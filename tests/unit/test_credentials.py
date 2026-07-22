from __future__ import annotations

import json
import stat
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

import evitriage.credentials as credentials_module
from evitriage.cli import app
from evitriage.credentials import (
    deepseek_credential_is_present,
    load_deepseek_credential,
    store_deepseek_credential,
)
from evitriage.errors import ConfigurationError

runner = CliRunner()


def _patch_credential_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    path = tmp_path / "private" / "evitriage-deepseek-api-key.cred"
    monkeypatch.setattr(credentials_module, "deepseek_credential_path", lambda: path)
    monkeypatch.setattr(
        credentials_module,
        "_validated_systemd_creds",
        lambda: Path("/usr/bin/systemd-creds"),
    )
    return path


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


def test_credentials_cli_hides_input_and_reports_presence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    api_key = "test-only-hidden-input"
    installed = tmp_path / "encrypted.cred"
    captured: list[tuple[str, bool]] = []

    def fake_store(value: str, *, replace: bool) -> Path:
        captured.append((value, replace))
        return installed

    monkeypatch.setattr("evitriage.cli.store_deepseek_credential", fake_store)

    result = runner.invoke(
        app,
        ["credentials", "set-deepseek", "--replace"],
        input=f"{api_key}\n{api_key}\n",
    )

    assert result.exit_code == 0, result.output
    assert api_key not in result.output
    assert captured == [(api_key, True)]
    assert str(installed) in result.output

    monkeypatch.setattr("evitriage.cli.deepseek_credential_is_present", lambda: True)
    monkeypatch.setattr("evitriage.cli.deepseek_credential_path", lambda: installed)
    status = runner.invoke(app, ["credentials", "status", "--json"])
    assert status.exit_code == 0
    assert json.loads(status.stdout) == {
        "deepseek": {
            "available": True,
            "path": str(installed),
        },
        "status": "ok",
    }
