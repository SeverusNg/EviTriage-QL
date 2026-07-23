from __future__ import annotations

import json
import logging
import os
import stat
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner

import evitriage.cli as cli_module
import evitriage.credentials as credentials_module
from evitriage.cli import app
from evitriage.credentials import (
    CredentialAvailability,
    CredentialProviderId,
    CredentialResolver,
    EnvironmentCredentialProvider,
    PassCredentialProvider,
    ResolvedCredential,
    SubprocessCommandRunner,
    SystemdCredentialProvider,
    deepseek_credential_is_present,
    load_deepseek_credential,
    store_deepseek_credential,
)
from evitriage.errors import ConfigurationError
from evitriage.observability import configure_logging

runner = CliRunner()


@dataclass
class FakeCommandRunner:
    completed: subprocess.CompletedProcess[bytes] | None = None
    error: BaseException | None = None
    calls: list[dict[str, object]] = field(default_factory=list)

    def run(
        self,
        argv: tuple[str, ...],
        *,
        input_bytes: bytes,
        timeout_seconds: int,
        environment: Mapping[str, str],
    ) -> subprocess.CompletedProcess[bytes]:
        self.calls.append(
            {
                "argv": argv,
                "environment": dict(environment),
                "input_bytes": input_bytes,
                "timeout_seconds": timeout_seconds,
            }
        )
        if self.error is not None:
            raise self.error
        assert self.completed is not None
        return self.completed


@dataclass
class StubProvider:
    provider_id: CredentialProviderId
    available: bool
    value: str = "test-only-provider-value"
    availability_error: ConfigurationError | None = None
    load_error: ConfigurationError | None = None
    availability_calls: int = 0
    load_calls: int = 0

    def availability(self) -> CredentialAvailability:
        self.availability_calls += 1
        if self.availability_error is not None:
            raise self.availability_error
        return CredentialAvailability(
            self.provider_id,
            self.available,
            "available" if self.available else "credential_missing",
        )

    def load_secret(self) -> str:
        self.load_calls += 1
        if self.load_error is not None:
            raise self.load_error
        return self.value


def _patch_credential_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    path = tmp_path / "private" / "evitriage-deepseek-api-key.cred"
    monkeypatch.setattr(credentials_module, "deepseek_credential_path", lambda: path)
    monkeypatch.setattr(
        credentials_module,
        "_validated_systemd_creds",
        lambda: Path("/usr/bin/systemd-creds"),
    )
    return path


def _executable(tmp_path: Path, name: str = "pass") -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    executable = tmp_path / name
    executable.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    executable.chmod(0o700)
    return executable


def _pass_provider(
    tmp_path: Path,
    command_runner: FakeCommandRunner,
    *,
    entry_exists: bool = True,
    parent_environment: dict[str, str] | None = None,
) -> tuple[PassCredentialProvider, Path, Path]:
    executable = _executable(tmp_path)
    home = tmp_path / "home"
    entry = home / ".password-store" / "evitriage" / "deepseek-api-key.gpg"
    if entry_exists:
        entry.parent.mkdir(parents=True)
        entry.write_bytes(b"fake-gpg-ciphertext")
    else:
        home.mkdir()
    provider = PassCredentialProvider(
        executable_resolver=lambda: executable,
        home_resolver=lambda: home,
        command_runner=command_runner,
        parent_environment=parent_environment or {},
    )
    return provider, executable, entry


def _resolver(
    environment: StubProvider,
    systemd: StubProvider,
    password_store: StubProvider,
) -> CredentialResolver:
    return CredentialResolver((password_store, systemd, environment))


def test_environment_provider_success_missing_and_malformed() -> None:
    api_key = "test-only-environment-value"
    success = EnvironmentCredentialProvider({"DEEPSEEK_API_KEY": api_key})
    assert success.availability().available is True
    assert success.load_secret() == api_key

    missing = EnvironmentCredentialProvider({})
    assert missing.availability() == CredentialAvailability("environment", False, "secret_missing")
    with pytest.raises(ConfigurationError) as missing_error:
        missing.load_secret()
    assert missing_error.value.details["error_type"] == "secret_missing"

    malformed = EnvironmentCredentialProvider({"DEEPSEEK_API_KEY": " invalid\n"})
    with pytest.raises(ConfigurationError) as malformed_error:
        malformed.availability()
    assert malformed_error.value.details == {
        "provider": "environment",
        "error_type": "environment_invalid",
    }
    assert api_key not in str(malformed_error.value)


def test_tpm_credential_round_trip_never_writes_plaintext(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = _patch_credential_path(monkeypatch, tmp_path)
    api_key = "test-only-key-material"
    ciphertext = b"encrypted-systemd-credential"
    calls: list[tuple[tuple[str, ...], bytes]] = []

    def fake_run(
        executable: Path,
        arguments: tuple[str, ...],
        *,
        input_bytes: bytes,
    ) -> subprocess.CompletedProcess[bytes]:
        calls.append((arguments, input_bytes))
        if "encrypt" in arguments:
            return subprocess.CompletedProcess((str(executable),), 0, ciphertext, b"")
        assert input_bytes == ciphertext
        return subprocess.CompletedProcess((str(executable),), 0, api_key.encode(), b"")

    monkeypatch.setattr(credentials_module, "_run_systemd_creds", fake_run)

    assert store_deepseek_credential(api_key) == path
    assert path.read_bytes() == ciphertext
    assert api_key.encode() not in path.read_bytes()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert deepseek_credential_is_present() is True
    assert load_deepseek_credential() == api_key
    assert calls[0][1] == api_key.encode()


def test_credential_store_rejects_overwrite_and_unsafe_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = _patch_credential_path(monkeypatch, tmp_path)
    path.parent.mkdir(mode=0o700)
    path.write_bytes(b"ciphertext")
    path.chmod(0o600)

    with pytest.raises(ConfigurationError, match="--replace"):
        store_deepseek_credential("test-only-key")

    path.chmod(0o644)
    with pytest.raises(ConfigurationError, match="owner-only"):
        load_deepseek_credential()


def test_systemd_provider_success_uses_injected_runner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    api_key = "test-only-systemd-value"
    executable = _executable(tmp_path, "systemd-creds")
    ciphertext = tmp_path / "credential.cred"
    ciphertext.write_bytes(b"encrypted")
    ciphertext.chmod(0o600)
    fake = FakeCommandRunner(
        subprocess.CompletedProcess((str(executable),), 0, api_key.encode(), b"")
    )
    monkeypatch.setattr(
        credentials_module,
        "_validated_executable",
        lambda path, *, trusted_owner_ids: path,
    )
    provider = SystemdCredentialProvider(
        executable_path=executable,
        credential_path_resolver=lambda: ciphertext,
        command_runner=fake,
    )

    assert provider.availability().available is True
    assert provider.load_secret() == api_key
    assert fake.calls[0]["argv"] == (
        str(executable),
        "--newline=no",
        "--name=evitriage-deepseek-api-key",
        "decrypt",
        "-",
        "-",
    )
    assert fake.calls[0]["input_bytes"] == b"encrypted"
    assert fake.calls[0]["environment"] == {"LANG": "C.UTF-8"}


def test_systemd_provider_command_missing_is_unavailable(tmp_path: Path) -> None:
    provider = SystemdCredentialProvider(
        executable_path=tmp_path / "missing-systemd-creds",
        credential_path_resolver=lambda: tmp_path / "missing.cred",
        command_runner=FakeCommandRunner(),
    )

    assert provider.availability() == CredentialAvailability(
        "systemd-creds", False, "executable_missing"
    )


@pytest.mark.parametrize("mode", [0o644, 0o666])
def test_systemd_provider_rejects_credential_permissions(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mode: int,
) -> None:
    executable = _executable(tmp_path, "systemd-creds")
    ciphertext = tmp_path / "credential.cred"
    ciphertext.write_bytes(b"encrypted")
    ciphertext.chmod(mode)
    monkeypatch.setattr(
        credentials_module,
        "_validated_executable",
        lambda path, *, trusted_owner_ids: path,
    )
    provider = SystemdCredentialProvider(
        executable_path=executable,
        credential_path_resolver=lambda: ciphertext,
        command_runner=FakeCommandRunner(),
    )

    with pytest.raises(ConfigurationError) as raised:
        provider.availability()
    assert raised.value.details["error_type"] == "credential_invalid"


def test_systemd_provider_corrupt_ciphertext_fails_without_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sensitive_marker = "test-only-never-leak"
    executable = _executable(tmp_path, "systemd-creds")
    ciphertext = tmp_path / "credential.cred"
    ciphertext.write_bytes(b"damaged-ciphertext")
    ciphertext.chmod(0o600)
    fake = FakeCommandRunner(
        subprocess.CompletedProcess(
            (str(executable),),
            1,
            sensitive_marker.encode(),
            f"gpg diagnostic {sensitive_marker}".encode(),
        )
    )
    monkeypatch.setattr(
        credentials_module,
        "_validated_executable",
        lambda path, *, trusted_owner_ids: path,
    )
    provider = SystemdCredentialProvider(
        executable_path=executable,
        credential_path_resolver=lambda: ciphertext,
        command_runner=fake,
    )

    with pytest.raises(ConfigurationError) as raised:
        provider.load_secret()
    serialized = json.dumps(raised.value.as_dict())
    assert raised.value.details["error_type"] == "decrypt_failed"
    assert raised.value.details["exit_code"] == 1
    assert sensitive_marker not in serialized


def test_systemd_creds_failure_discards_stderr_and_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sensitive_value = "test-only-sensitive-value"

    def failed_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(("systemd-creds",), 1, b"", sensitive_value.encode())

    monkeypatch.setattr(subprocess, "run", failed_run)
    with pytest.raises(ConfigurationError) as raised:
        credentials_module._run_systemd_creds(
            Path("/usr/bin/systemd-creds"),
            ("decrypt", "-", "-"),
            input_bytes=b"ciphertext",
        )

    assert sensitive_value not in str(raised.value)
    assert raised.value.details == {"exit_code": 1}


def test_subprocess_command_runner_uses_argv_without_a_shell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(
        argv: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        os.write(cast(int, kwargs["stdout"]), b"bounded stdout")
        os.write(cast(int, kwargs["stderr"]), b"bounded stderr")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    completed = SubprocessCommandRunner().run(
        ("/usr/bin/pass", "show", "evitriage/deepseek-api-key"),
        input_bytes=b"",
        timeout_seconds=30,
        environment={"PATH": "/usr/bin:/bin"},
    )

    assert completed.returncode == 0
    assert captured["argv"] == (
        "/usr/bin/pass",
        "show",
        "evitriage/deepseek-api-key",
    )
    kwargs = cast(dict[str, object], captured["kwargs"])
    assert "capture_output" not in kwargs
    assert isinstance(kwargs["stdout"], int)
    assert isinstance(kwargs["stderr"], int)
    assert kwargs["shell"] is False
    assert completed.stdout == b"bounded stdout"
    assert completed.stderr == b"bounded stderr"


def test_subprocess_command_runner_retains_only_one_byte_beyond_output_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(
        argv: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        output = b"x" * (credentials_module._MAXIMUM_CAPTURED_OUTPUT_BYTES + 4096)
        os.write(cast(int, kwargs["stdout"]), output)
        os.write(cast(int, kwargs["stderr"]), output)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    completed = SubprocessCommandRunner().run(
        ("/usr/bin/pass", "show", "evitriage/deepseek-api-key"),
        input_bytes=b"",
        timeout_seconds=30,
        environment={"PATH": "/usr/bin:/bin"},
    )

    expected_length = credentials_module._MAXIMUM_CAPTURED_OUTPUT_BYTES + 1
    assert len(completed.stdout) == expected_length
    assert len(completed.stderr) == expected_length


@pytest.mark.security
def test_pass_provider_success_uses_fixed_argv_and_minimal_environment(tmp_path: Path) -> None:
    api_key = "test-only-pass-value"
    fake = FakeCommandRunner(
        subprocess.CompletedProcess(("pass",), 0, api_key.encode() + b"\n", b"ignored")
    )
    ambient = {
        "DEEPSEEK_API_KEY": "must-not-reach-child",
        "HTTPS_PROXY": "http://proxy.invalid",
        "PASSWORD_STORE_ENABLE_EXTENSIONS": "true",
        "GITHUB_TOKEN": "must-not-reach-child",
        "GPG_TTY": "/dev/pts/7",
        "TERM": "xterm-256color",
    }
    provider, executable, _entry = _pass_provider(
        tmp_path,
        fake,
        parent_environment=ambient,
    )

    assert provider.availability().available is True
    assert provider.load_secret() == api_key
    call = fake.calls[0]
    assert call["argv"] == (str(executable), "show", "evitriage/deepseek-api-key")
    environment = cast(dict[str, str], call["environment"])
    assert environment == {
        "GPG_TTY": "/dev/pts/7",
        "HOME": str(tmp_path / "home"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PASSWORD_STORE_DIR": str(tmp_path / "home" / ".password-store"),
        "PATH": "/usr/bin:/bin",
        "TERM": "xterm-256color",
    }
    assert api_key not in str(call["argv"])
    assert api_key not in str(call["environment"])


def test_pass_provider_command_and_entry_missing_are_distinct(tmp_path: Path) -> None:
    missing_command = PassCredentialProvider(
        executable_resolver=lambda: None,
        home_resolver=lambda: tmp_path,
        command_runner=FakeCommandRunner(),
        parent_environment={},
    )
    assert missing_command.availability() == CredentialAvailability(
        "pass", False, "executable_missing"
    )

    fake = FakeCommandRunner()
    missing_entry, _executable_path, _entry = _pass_provider(
        tmp_path / "entry-missing",
        fake,
        entry_exists=False,
    )
    assert missing_entry.availability() == CredentialAvailability(
        "pass", False, "credential_missing"
    )
    assert fake.calls == []


@pytest.mark.parametrize(
    ("completed", "expected_error"),
    [
        (subprocess.CompletedProcess(("pass",), 1, b"", b"gpg failed"), "decrypt_failed"),
        (subprocess.CompletedProcess(("pass",), 0, b"", b""), "empty_secret"),
        (
            subprocess.CompletedProcess(("pass",), 0, b"first-line\nsecond-line\n", b""),
            "malformed_secret",
        ),
        (
            subprocess.CompletedProcess(
                ("pass",),
                0,
                b"x" * (credentials_module._MAXIMUM_PASS_STDOUT_BYTES + 1),
                b"",
            ),
            "output_too_large",
        ),
        (
            subprocess.CompletedProcess(
                ("pass",),
                0,
                b"valid-looking",
                b"x" * (credentials_module._MAXIMUM_PASS_STDERR_BYTES + 1),
            ),
            "output_too_large",
        ),
    ],
)
def test_pass_provider_rejects_gpg_failure_empty_multiline_and_oversized_output(
    tmp_path: Path,
    completed: subprocess.CompletedProcess[bytes],
    expected_error: str,
) -> None:
    fake = FakeCommandRunner(completed)
    provider, _executable_path, _entry = _pass_provider(tmp_path, fake)

    with pytest.raises(ConfigurationError) as raised:
        provider.load_secret()
    assert raised.value.details["error_type"] == expected_error
    if completed.returncode:
        assert raised.value.details["exit_code"] == completed.returncode
    if completed.stdout:
        assert completed.stdout.decode("utf-8", errors="ignore") not in str(raised.value)
    if completed.stderr:
        assert completed.stderr.decode("utf-8", errors="ignore") not in str(raised.value)


def test_pass_provider_timeout_is_structured_and_non_secret(tmp_path: Path) -> None:
    sensitive_marker = "test-only-timeout-value"
    timeout = subprocess.TimeoutExpired(
        ("pass", "show", "evitriage/deepseek-api-key"),
        30,
        output=sensitive_marker.encode(),
        stderr=sensitive_marker.encode(),
    )
    fake = FakeCommandRunner(error=timeout)
    provider, _executable_path, _entry = _pass_provider(tmp_path, fake)

    with pytest.raises(ConfigurationError) as raised:
        provider.load_secret()
    assert raised.value.__cause__ is None
    assert raised.value.details["error_type"] == "timeout"
    assert sensitive_marker not in json.dumps(raised.value.as_dict())


def test_pass_store_failure_does_not_expose_stdin_or_command_output(tmp_path: Path) -> None:
    api_key = "test-only-store-failure-value"
    fake = FakeCommandRunner(
        subprocess.CompletedProcess(
            ("pass",),
            1,
            f"stdout {api_key}".encode(),
            f"stderr {api_key}".encode(),
        )
    )
    provider, _executable_path, _entry = _pass_provider(tmp_path, fake, entry_exists=False)

    with pytest.raises(ConfigurationError) as raised:
        provider.store_secret(api_key)

    serialized = json.dumps(raised.value.as_dict())
    assert raised.value.details["error_type"] == "store_failed"
    assert api_key not in serialized
    assert api_key not in str(fake.calls[0]["argv"])
    assert api_key not in str(fake.calls[0]["environment"])


@pytest.mark.parametrize(
    "entry",
    [
        "",
        "/absolute",
        "a//b",
        ".",
        "..",
        "a/.",
        "a/..",
        "-option",
        "a/-option",
        "../escape",
        "a;id",
        "a$(id)",
        "a`id`",
        "a b",
        "a\\b",
        "é",
        "a" * 256,
    ],
)
@pytest.mark.security
def test_pass_provider_rejects_malicious_entry_names(entry: str) -> None:
    with pytest.raises(ConfigurationError, match="entry is invalid"):
        PassCredentialProvider(entry=entry)


@pytest.mark.security
def test_pass_provider_rejects_symlink_and_writable_executable(tmp_path: Path) -> None:
    target = _executable(tmp_path)
    linked = tmp_path / "linked-pass"
    linked.symlink_to(target)
    symlink_provider = PassCredentialProvider(
        executable_resolver=lambda: linked,
        home_resolver=lambda: tmp_path,
        command_runner=FakeCommandRunner(),
        parent_environment={},
    )
    with pytest.raises(ConfigurationError) as symlink_error:
        symlink_provider.availability()
    assert symlink_error.value.details["error_type"] == "unsafe_executable"

    target.chmod(0o722)
    writable_provider = PassCredentialProvider(
        executable_resolver=lambda: target,
        home_resolver=lambda: tmp_path,
        command_runner=FakeCommandRunner(),
        parent_environment={},
    )
    with pytest.raises(ConfigurationError) as writable_error:
        writable_provider.availability()
    assert writable_error.value.details["error_type"] == "unsafe_executable"

    target.chmod(0o600)
    non_executable_provider = PassCredentialProvider(
        executable_resolver=lambda: target,
        home_resolver=lambda: tmp_path,
        command_runner=FakeCommandRunner(),
        parent_environment={},
    )
    with pytest.raises(ConfigurationError) as non_executable_error:
        non_executable_provider.availability()
    assert non_executable_error.value.details["error_type"] == "unsafe_executable"


def test_pass_provider_rejects_untrusted_executable_owner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    executable = _executable(tmp_path)
    original_stat = Path.stat
    metadata = executable.stat(follow_symlinks=False)

    def fake_stat(path: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        observed = original_stat(path, follow_symlinks=follow_symlinks)
        if path != executable:
            return observed
        values = list(observed)
        values[stat.ST_UID] = metadata.st_uid + 1000
        return os.stat_result(values)

    monkeypatch.setattr(Path, "stat", fake_stat)
    provider = PassCredentialProvider(
        executable_resolver=lambda: executable,
        home_resolver=lambda: tmp_path,
        command_runner=FakeCommandRunner(),
        parent_environment={},
    )

    with pytest.raises(ConfigurationError) as raised:
        provider.availability()
    assert raised.value.details["error_type"] == "unsafe_executable"


def test_credential_resolver_auto_priority_is_fixed() -> None:
    selected_value = "environment-value"
    environment = StubProvider("environment", True, value=selected_value)
    systemd = StubProvider("systemd-creds", True, value="systemd-value")
    password_store = StubProvider("pass", True, value="pass-value")

    resolved = _resolver(environment, systemd, password_store).resolve("auto")

    assert resolved.provider_id == "environment"
    assert resolved.secret == selected_value
    assert environment.load_calls == 1
    assert systemd.availability_calls == 0
    assert password_store.availability_calls == 0
    assert selected_value not in repr(resolved)
    assert selected_value not in repr(ResolvedCredential("environment", selected_value))


def test_credential_resolver_explicit_provider_never_falls_back() -> None:
    environment = StubProvider("environment", True)
    systemd = StubProvider("systemd-creds", True)
    password_store = StubProvider("pass", False)
    resolver = _resolver(environment, systemd, password_store)

    with pytest.raises(ConfigurationError) as raised:
        resolver.resolve("pass")

    assert raised.value.details["provider"] == "pass"
    assert environment.availability_calls == 0
    assert systemd.availability_calls == 0
    assert password_store.load_calls == 0


def test_credential_resolver_selected_load_failure_never_falls_back() -> None:
    environment = StubProvider("environment", False)
    systemd = StubProvider(
        "systemd-creds",
        True,
        load_error=ConfigurationError("simulated decrypt failure"),
    )
    password_store = StubProvider("pass", True)
    resolver = _resolver(environment, systemd, password_store)

    with pytest.raises(ConfigurationError, match="simulated decrypt failure"):
        resolver.resolve("auto")

    assert systemd.load_calls == 1
    assert password_store.availability_calls == 0
    assert password_store.load_calls == 0


def test_credential_resolver_discovery_error_never_falls_back() -> None:
    environment = StubProvider(
        "environment",
        False,
        availability_error=ConfigurationError(
            "credential provider environment failed: environment_invalid",
            details={"provider": "environment", "error_type": "environment_invalid"},
        ),
    )
    systemd = StubProvider("systemd-creds", True)
    password_store = StubProvider("pass", True)

    with pytest.raises(ConfigurationError) as raised:
        _resolver(environment, systemd, password_store).resolve("auto")

    assert raised.value.details["error_type"] == "environment_invalid"
    assert systemd.availability_calls == 0
    assert password_store.availability_calls == 0


def test_credentials_cli_hides_systemd_input(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    api_key = "test-only-hidden-input"
    installed = tmp_path / "encrypted.cred"
    captured: list[tuple[str, bool]] = []

    def fake_store(value: str, *, replace: bool) -> Path:
        captured.append((value, replace))
        return installed

    monkeypatch.setattr(cli_module, "store_deepseek_credential", fake_store)

    result = runner.invoke(
        app,
        ["credentials", "set-deepseek", "--replace"],
        input=f"{api_key}\n{api_key}\n",
    )

    assert result.exit_code == 0, result.output
    assert api_key not in result.output
    assert captured == [(api_key, True)]
    assert str(installed) in result.output


@pytest.mark.security
def test_credentials_cli_pass_set_uses_stdin_and_creates_no_plaintext_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    api_key = "test-only-pass-cli-value"
    fake = FakeCommandRunner(subprocess.CompletedProcess(("pass",), 0, b"", b""))
    provider, executable, _entry = _pass_provider(tmp_path, fake, entry_exists=False)
    before = {path.relative_to(tmp_path) for path in tmp_path.rglob("*")}
    monkeypatch.setattr(cli_module, "PassCredentialProvider", lambda: provider)

    result = runner.invoke(
        app,
        ["credentials", "set-deepseek", "--provider", "pass"],
        input=f"{api_key}\n{api_key}\n",
    )

    assert result.exit_code == 0, result.output
    assert api_key not in result.output
    assert fake.calls[0]["argv"] == (
        str(executable),
        "insert",
        "--echo",
        "evitriage/deepseek-api-key",
    )
    assert fake.calls[0]["input_bytes"] == api_key.encode() + b"\n"
    after = {path.relative_to(tmp_path) for path in tmp_path.rglob("*")}
    assert after == before
    assert all(
        api_key.encode() not in path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    )


@pytest.mark.security
def test_credentials_status_reports_all_providers_and_never_secret_material(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sensitive_marker = "test-only-status-value"
    environment = StubProvider("environment", False, value=sensitive_marker)
    systemd = StubProvider("systemd-creds", False, value=sensitive_marker)
    password_store = StubProvider("pass", True, value=sensitive_marker)
    resolver = _resolver(environment, systemd, password_store)
    monkeypatch.setattr(cli_module, "CredentialResolver", lambda: resolver)

    status = runner.invoke(app, ["credentials", "status", "--json"])

    assert status.exit_code == 0, status.output
    payload = json.loads(status.stdout)
    assert payload == {
        "deepseek": {
            "providers": {
                "environment": {
                    "available": False,
                    "reason": "credential_missing",
                    "state": "unavailable",
                },
                "pass": {
                    "available": True,
                    "reason": "available",
                    "state": "available",
                },
                "systemd-creds": {
                    "available": False,
                    "reason": "credential_missing",
                    "state": "unavailable",
                },
            },
            "selected_provider": "pass",
            "selection_status": "available",
        },
        "status": "ok",
    }
    assert sensitive_marker not in status.output
    assert "ciphertext" not in status.output
    assert "gpg diagnostic" not in status.output


def test_credential_errors_and_logs_never_contain_pass_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sensitive_marker = "test-only-log-value"
    fake = FakeCommandRunner(
        subprocess.CompletedProcess(
            ("pass",),
            2,
            f"stdout {sensitive_marker}".encode(),
            f"stderr {sensitive_marker}".encode(),
        )
    )
    provider, _executable_path, _entry = _pass_provider(tmp_path, fake)
    configure_logging(verbose=True)

    try:
        provider.load_secret()
    except ConfigurationError as error:
        raised = error
        logging.getLogger("evitriage").exception("credential load failed")
    else:  # pragma: no cover - the fake runner always fails
        raise AssertionError("credential load unexpectedly succeeded")

    captured = capsys.readouterr()
    serialized = json.dumps(raised.as_dict())
    assert sensitive_marker not in serialized
    assert sensitive_marker not in captured.out
    assert sensitive_marker not in captured.err
