"""Fail-closed DeepSeek credential providers outside the model adapter."""

from __future__ import annotations

import os
import re
import secrets
import shutil
import stat
import subprocess
import threading
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

from evitriage.errors import ConfigurationError

CredentialProviderId = Literal["environment", "systemd-creds", "pass"]
CredentialProviderSelection = Literal["environment", "systemd-creds", "pass", "auto"]

_DEEPSEEK_API_KEY_ENVIRONMENT = "DEEPSEEK_API_KEY"
_CREDENTIAL_NAME = "evitriage-deepseek-api-key"
_CREDENTIAL_FILENAME = f"{_CREDENTIAL_NAME}.cred"
_SYSTEMD_CREDS = Path("/usr/bin/systemd-creds")
_DEFAULT_PASS_ENTRY = "evitriage/deepseek-api-key"  # noqa: S105 - entry name, not a secret
_AUTO_PROVIDER_PRIORITY: tuple[CredentialProviderId, ...] = (
    "environment",
    "systemd-creds",
    "pass",
)
_MAXIMUM_API_KEY_CHARACTERS = 4096
_MAXIMUM_ENCODED_API_KEY_BYTES = _MAXIMUM_API_KEY_CHARACTERS * 4
_MAXIMUM_CIPHERTEXT_BYTES = 64 * 1024
_MAXIMUM_PASS_ENTRY_LENGTH = 255
_MAXIMUM_PASS_STDOUT_BYTES = _MAXIMUM_ENCODED_API_KEY_BYTES + 1
_MAXIMUM_PASS_STDERR_BYTES = 64 * 1024
_MAXIMUM_SYSTEMD_OUTPUT_BYTES = 64 * 1024
_MAXIMUM_CAPTURED_OUTPUT_BYTES = 64 * 1024
_SYSTEMD_CREDS_TIMEOUT_SECONDS = 30
_PASS_TIMEOUT_SECONDS = 30
_PASS_ENTRY_CHARACTERS = re.compile(r"^[A-Za-z0-9_.\-/]+$")
_PASS_PINENTRY_ENVIRONMENT = (
    "DBUS_SESSION_BUS_ADDRESS",
    "DISPLAY",
    "GPG_TTY",
    "TERM",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
)
_SAFE_AVAILABILITY_REASONS = frozenset(
    {
        "available",
        "credential_missing",
        "executable_missing",
        "secret_missing",
    }
)
_SAFE_PROVIDER_ERROR_TYPES = frozenset(
    {
        "credential_changed",
        "credential_exists",
        "credential_invalid",
        "credential_missing",
        "decrypt_failed",
        "empty_secret",
        "environment_invalid",
        "execution_failed",
        "executable_missing",
        "home_unavailable",
        "malformed_secret",
        "no_available_provider",
        "output_too_large",
        "provider_unavailable",
        "secret_missing",
        "store_failed",
        "timeout",
        "unsafe_entry",
        "unsafe_executable",
    }
)


class _BoundedPipeCapture:
    """Drain one child pipe while retaining at most ``maximum_bytes + 1``."""

    def __init__(self, maximum_bytes: int) -> None:
        self._maximum_bytes = maximum_bytes
        self._read_descriptor, self.write_descriptor = os.pipe2(os.O_CLOEXEC)
        os.set_blocking(self._read_descriptor, False)
        self._buffer = bytearray()
        self._subprocess_finished = threading.Event()
        self._thread = threading.Thread(target=self._drain, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def finish(self) -> bytes:
        with suppress(OSError):
            os.close(self.write_descriptor)
        self._subprocess_finished.set()
        self._thread.join()
        with suppress(OSError):
            os.close(self._read_descriptor)
        return bytes(self._buffer)

    def _drain(self) -> None:
        retained_limit = self._maximum_bytes + 1
        while True:
            try:
                chunk = os.read(self._read_descriptor, 64 * 1024)
            except BlockingIOError:
                if self._subprocess_finished.is_set():
                    return
                self._subprocess_finished.wait(0.01)
                continue
            except OSError:
                return
            if not chunk:
                return
            remaining = retained_limit - len(self._buffer)
            if remaining > 0:
                self._buffer.extend(chunk[:remaining])
            if self._subprocess_finished.is_set() and len(self._buffer) >= retained_limit:
                return


class CommandRunner(Protocol):
    """Injectable argument-vector subprocess boundary for credential tools."""

    def run(
        self,
        argv: tuple[str, ...],
        *,
        input_bytes: bytes,
        timeout_seconds: int,
        environment: Mapping[str, str],
    ) -> subprocess.CompletedProcess[bytes]:
        """Run one fixed credential-tool invocation for provider-side output checks."""
        ...


class SubprocessCommandRunner:
    """Production credential command runner using ``subprocess.run`` only."""

    def run(
        self,
        argv: tuple[str, ...],
        *,
        input_bytes: bytes,
        timeout_seconds: int,
        environment: Mapping[str, str],
    ) -> subprocess.CompletedProcess[bytes]:
        """Execute an already validated absolute executable without a shell."""

        stdout_capture = _BoundedPipeCapture(_MAXIMUM_CAPTURED_OUTPUT_BYTES)
        stderr_capture = _BoundedPipeCapture(_MAXIMUM_CAPTURED_OUTPUT_BYTES)
        stdout_capture.start()
        stderr_capture.start()
        try:
            completed = subprocess.run(  # noqa: S603 - provider-validated executable and argv
                argv,
                input=input_bytes,
                stdout=stdout_capture.write_descriptor,
                stderr=stderr_capture.write_descriptor,
                check=False,
                shell=False,
                timeout=timeout_seconds,
                env=dict(environment),
            )
        finally:
            stdout = stdout_capture.finish()
            stderr = stderr_capture.finish()
        return subprocess.CompletedProcess(
            completed.args,
            completed.returncode,
            stdout,
            stderr,
        )


@dataclass(frozen=True, slots=True)
class CredentialAvailability:
    """Non-secret provider discovery result."""

    provider_id: CredentialProviderId
    available: bool
    reason: str


@dataclass(frozen=True, slots=True)
class ResolvedCredential:
    """One validated in-memory secret and its selected provider identity."""

    provider_id: CredentialProviderId
    secret: str = field(repr=False)


class CredentialProvider(Protocol):
    """Provider-neutral boundary for discovering and loading one secret."""

    provider_id: CredentialProviderId

    def availability(self) -> CredentialAvailability:
        """Report non-secret availability without decrypting a credential."""
        ...

    def load_secret(self) -> str:
        """Return one validated secret or fail without exposing it."""
        ...


class EnvironmentCredentialProvider:
    """Read DeepSeek credentials only from the current process environment."""

    provider_id: CredentialProviderId = "environment"

    def __init__(self, environment: Mapping[str, str] | None = None) -> None:
        self._environment = os.environ if environment is None else environment

    def availability(self) -> CredentialAvailability:
        """Distinguish an absent variable from a present malformed secret."""

        api_key = self._environment.get(_DEEPSEEK_API_KEY_ENVIRONMENT)
        if api_key is None or api_key == "":
            return CredentialAvailability(self.provider_id, False, "secret_missing")
        try:
            _validated_api_key(api_key)
        except ConfigurationError:
            raise _provider_error(self.provider_id, "environment_invalid") from None
        return CredentialAvailability(self.provider_id, True, "available")

    def load_secret(self) -> str:
        """Load and validate the process-local DeepSeek key."""

        api_key = self._environment.get(_DEEPSEEK_API_KEY_ENVIRONMENT)
        if api_key is None or api_key == "":
            raise _provider_error(self.provider_id, "secret_missing")
        try:
            return _validated_api_key(api_key)
        except ConfigurationError:
            raise _provider_error(self.provider_id, "environment_invalid") from None


class SystemdCredentialProvider:
    """Load the existing fixed TPM2/systemd encrypted credential."""

    provider_id: CredentialProviderId = "systemd-creds"

    def __init__(
        self,
        *,
        executable_path: Path = _SYSTEMD_CREDS,
        credential_path_resolver: Callable[[], Path] | None = None,
        command_runner: CommandRunner | None = None,
    ) -> None:
        self._executable_path = executable_path
        self._credential_path_resolver = credential_path_resolver or deepseek_credential_path
        self._command_runner = command_runner or SubprocessCommandRunner()

    def availability(self) -> CredentialAvailability:
        """Check executable and ciphertext presence without decrypting."""

        try:
            _validated_executable(self._executable_path, trusted_owner_ids=frozenset({0}))
        except FileNotFoundError:
            return CredentialAvailability(self.provider_id, False, "executable_missing")
        except ConfigurationError:
            raise _provider_error(self.provider_id, "unsafe_executable") from None
        path = self._credential_path()
        try:
            path.stat(follow_symlinks=False)
        except FileNotFoundError:
            return CredentialAvailability(self.provider_id, False, "credential_missing")
        except OSError:
            raise _provider_error(self.provider_id, "credential_invalid") from None
        try:
            _read_ciphertext(path)
        except ConfigurationError:
            raise _provider_error(self.provider_id, "credential_invalid") from None
        return CredentialAvailability(self.provider_id, True, "available")

    def load_secret(self) -> str:
        """Decrypt through an in-memory pipe and fail closed on any error."""

        availability = self.availability()
        if not availability.available:
            raise _provider_error(self.provider_id, availability.reason)
        try:
            executable = _validated_executable(
                self._executable_path,
                trusted_owner_ids=frozenset({0}),
            )
            ciphertext = _read_ciphertext(self._credential_path())
            completed = _run_systemd_creds(
                executable,
                (
                    "--newline=no",
                    f"--name={_CREDENTIAL_NAME}",
                    "decrypt",
                    "-",
                    "-",
                ),
                input_bytes=ciphertext,
                runner=self._command_runner,
            )
        except FileNotFoundError:
            raise _provider_error(self.provider_id, "executable_missing") from None
        except ConfigurationError as error:
            exit_code = error.details.get("exit_code")
            raise _provider_error(
                self.provider_id,
                "decrypt_failed",
                exit_code=exit_code if isinstance(exit_code, int) else None,
            ) from None
        try:
            api_key = completed.stdout.decode("utf-8")
            return _validated_api_key(api_key)
        except (UnicodeDecodeError, ConfigurationError):
            raise _provider_error(self.provider_id, "malformed_secret") from None

    def _credential_path(self) -> Path:
        try:
            return self._credential_path_resolver()
        except ConfigurationError:
            raise _provider_error(self.provider_id, "home_unavailable") from None


class PassCredentialProvider:
    """Load or store the fixed DeepSeek entry through validated ``pass``."""

    provider_id: CredentialProviderId = "pass"

    def __init__(
        self,
        *,
        entry: str = _DEFAULT_PASS_ENTRY,
        executable_resolver: Callable[[], Path | None] | None = None,
        home_resolver: Callable[[], Path] | None = None,
        command_runner: CommandRunner | None = None,
        parent_environment: Mapping[str, str] | None = None,
    ) -> None:
        self._entry = _validated_pass_entry(entry)
        self._executable_resolver = executable_resolver or _discover_pass_executable
        self._home_resolver = home_resolver or _operator_home_directory
        self._command_runner = command_runner or SubprocessCommandRunner()
        self._parent_environment = os.environ if parent_environment is None else parent_environment

    @property
    def entry(self) -> str:
        """Return the validated, non-secret fixed password-store entry name."""

        return self._entry

    def availability(self) -> CredentialAvailability:
        """Check the executable and encrypted entry without invoking GPG."""

        executable = self._resolve_executable()
        if executable is None:
            return CredentialAvailability(self.provider_id, False, "executable_missing")
        self._validate_resolved_executable(executable)
        home = self._resolve_home()
        try:
            metadata = self._entry_path(home).stat(follow_symlinks=False)
        except FileNotFoundError:
            return CredentialAvailability(self.provider_id, False, "credential_missing")
        except OSError:
            raise _provider_error(self.provider_id, "credential_invalid") from None
        if not stat.S_ISREG(metadata.st_mode):
            raise _provider_error(self.provider_id, "unsafe_entry")
        return CredentialAvailability(self.provider_id, True, "available")

    def load_secret(self) -> str:
        """Run exactly ``pass show <entry>`` and validate its bounded output."""

        availability = self.availability()
        if not availability.available:
            raise _provider_error(self.provider_id, availability.reason)
        executable = self._required_executable()
        home = self._resolve_home()
        completed = self._run_pass(
            (str(executable), "show", self._entry),
            input_bytes=b"",
            home=home,
            failure_type="decrypt_failed",
        )
        raw = completed.stdout
        if not raw:
            raise _provider_error(self.provider_id, "empty_secret")
        without_expected_newline = raw[:-1] if raw.endswith(b"\n") else raw
        if not without_expected_newline:
            raise _provider_error(self.provider_id, "empty_secret")
        try:
            api_key = without_expected_newline.decode("utf-8")
            return _validated_api_key(api_key)
        except (UnicodeDecodeError, ConfigurationError):
            raise _provider_error(self.provider_id, "malformed_secret") from None

    def store_secret(self, api_key: str, *, replace: bool = False) -> str:
        """Pipe a confirmed key to ``pass insert`` without a plaintext file."""

        try:
            validated = _validated_api_key(api_key)
        except ConfigurationError:
            raise _provider_error(self.provider_id, "malformed_secret") from None
        executable = self._required_executable()
        home = self._resolve_home()
        entry_path = self._entry_path(home)
        try:
            metadata = entry_path.stat(follow_symlinks=False)
        except FileNotFoundError:
            metadata = None
        except OSError:
            raise _provider_error(self.provider_id, "credential_invalid") from None
        if metadata is not None:
            if not stat.S_ISREG(metadata.st_mode):
                raise _provider_error(self.provider_id, "unsafe_entry")
            if not replace:
                raise _provider_error(self.provider_id, "credential_exists")
        arguments = (
            ("insert", "--force", "--echo", self._entry)
            if replace
            else ("insert", "--echo", self._entry)
        )
        self._run_pass(
            (str(executable), *arguments),
            input_bytes=validated.encode("utf-8") + b"\n",
            home=home,
            failure_type="store_failed",
        )
        return self._entry

    def _run_pass(
        self,
        argv: tuple[str, ...],
        *,
        input_bytes: bytes,
        home: Path,
        failure_type: str,
    ) -> subprocess.CompletedProcess[bytes]:
        try:
            completed = self._command_runner.run(
                argv,
                input_bytes=input_bytes,
                timeout_seconds=_PASS_TIMEOUT_SECONDS,
                environment=_pass_environment(home, self._parent_environment),
            )
        except subprocess.TimeoutExpired:
            raise _provider_error(self.provider_id, "timeout") from None
        except (OSError, subprocess.SubprocessError):
            raise _provider_error(self.provider_id, "execution_failed") from None
        if (
            len(completed.stdout) > _MAXIMUM_PASS_STDOUT_BYTES
            or len(completed.stderr) > _MAXIMUM_PASS_STDERR_BYTES
        ):
            raise _provider_error(self.provider_id, "output_too_large")
        if completed.returncode != 0:
            raise _provider_error(
                self.provider_id,
                failure_type,
                exit_code=completed.returncode,
            )
        return completed

    def _resolve_executable(self) -> Path | None:
        try:
            return self._executable_resolver()
        except OSError:
            raise _provider_error(self.provider_id, "execution_failed") from None

    def _required_executable(self) -> Path:
        executable = self._resolve_executable()
        if executable is None:
            raise _provider_error(self.provider_id, "executable_missing")
        return self._validate_resolved_executable(executable)

    def _validate_resolved_executable(self, executable: Path) -> Path:
        try:
            return _validated_executable(
                executable,
                trusted_owner_ids=frozenset({0, os.getuid()}),
            )
        except FileNotFoundError:
            raise _provider_error(self.provider_id, "executable_missing") from None
        except ConfigurationError:
            raise _provider_error(self.provider_id, "unsafe_executable") from None

    def _resolve_home(self) -> Path:
        try:
            return self._home_resolver()
        except (ConfigurationError, OSError, RuntimeError):
            raise _provider_error(self.provider_id, "home_unavailable") from None

    def _entry_path(self, home: Path) -> Path:
        return home / ".password-store" / f"{self._entry}.gpg"


class CredentialResolver:
    """Select one provider without fallback after discovery or load failure."""

    def __init__(self, providers: Sequence[CredentialProvider] | None = None) -> None:
        configured = (
            tuple(providers)
            if providers is not None
            else (
                EnvironmentCredentialProvider(),
                SystemdCredentialProvider(),
                PassCredentialProvider(),
            )
        )
        provider_map: dict[CredentialProviderId, CredentialProvider] = {}
        for provider in configured:
            if provider.provider_id in provider_map:
                raise ConfigurationError("duplicate credential provider id")
            provider_map[provider.provider_id] = provider
        missing = [
            provider_id
            for provider_id in _AUTO_PROVIDER_PRIORITY
            if provider_id not in provider_map
        ]
        if missing:
            raise ConfigurationError(
                "credential resolver is missing required providers",
                details={"providers": missing},
            )
        self._providers = provider_map

    def resolve(self, selection: CredentialProviderSelection) -> ResolvedCredential:
        """Resolve explicit or fixed-priority auto selection and load once."""

        if selection == "auto":
            for provider_id in _AUTO_PROVIDER_PRIORITY:
                provider = self._providers[provider_id]
                availability = provider.availability()
                if not availability.available:
                    continue
                return ResolvedCredential(provider_id, provider.load_secret())
            raise _provider_error("auto", "no_available_provider")
        if selection not in _AUTO_PROVIDER_PRIORITY:
            raise ConfigurationError("unsupported credential provider selection")
        provider = self._providers[selection]
        availability = provider.availability()
        if not availability.available:
            raise _provider_error(provider.provider_id, availability.reason)
        return ResolvedCredential(provider.provider_id, provider.load_secret())

    def status(self) -> dict[str, object]:
        """Return non-secret provider state and the auto-mode final selection."""

        providers: dict[str, object] = {}
        selected_provider: CredentialProviderId | None = None
        selection_status = "unavailable"
        for provider_id in _AUTO_PROVIDER_PRIORITY:
            provider = self._providers[provider_id]
            try:
                availability = provider.availability()
            except ConfigurationError as error:
                error_type = _safe_provider_error_type(error)
                providers[provider_id] = {
                    "available": False,
                    "error_type": error_type,
                    "state": "error",
                }
                if selected_provider is None:
                    selected_provider = provider_id
                    selection_status = "error"
                continue
            reason = (
                availability.reason
                if availability.reason in _SAFE_AVAILABILITY_REASONS
                else "provider_unavailable"
            )
            providers[provider_id] = {
                "available": availability.available,
                "reason": reason,
                "state": "available" if availability.available else "unavailable",
            }
            if selected_provider is None and availability.available:
                selected_provider = provider_id
                selection_status = "available"
        return {
            "providers": providers,
            "selected_provider": selected_provider,
            "selection_status": selection_status,
        }


def deepseek_credential_path() -> Path:
    """Return the fixed, repository-external systemd credential path."""

    return (
        _operator_home_directory()
        / ".local"
        / "share"
        / "evitriage"
        / "credentials"
        / _CREDENTIAL_FILENAME
    )


def deepseek_credential_is_present() -> bool:
    """Report whether a secure-looking encrypted systemd credential is present."""

    path = deepseek_credential_path()
    if not path.exists():
        return False
    _read_ciphertext(path)
    return True


def store_deepseek_credential(api_key: str, *, replace: bool = False) -> Path:
    """Encrypt one API key with TPM2 and atomically store only its ciphertext."""

    encoded = _validated_api_key(api_key).encode("utf-8")
    executable = _validated_systemd_creds()
    path = deepseek_credential_path()
    directory = path.parent
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    _validate_private_directory(directory)
    if path.exists() and not replace:
        raise ConfigurationError(
            "an encrypted DeepSeek credential already exists; use --replace only for rotation"
        )
    if path.is_symlink():
        raise ConfigurationError("refusing to replace a symlinked DeepSeek credential")

    completed = _run_systemd_creds(
        executable,
        (
            "--newline=no",
            f"--name={_CREDENTIAL_NAME}",
            "--with-key=tpm2",
            "encrypt",
            "-",
            "-",
        ),
        input_bytes=encoded,
    )
    ciphertext = completed.stdout
    if not ciphertext or len(ciphertext) > _MAXIMUM_CIPHERTEXT_BYTES:
        raise ConfigurationError("systemd-creds returned an invalid encrypted credential")
    _atomic_private_write(path, ciphertext)
    return path


def load_deepseek_credential() -> str:
    """Decrypt the fixed TPM2 credential without creating a plaintext file."""

    executable = _validated_systemd_creds()
    ciphertext = _read_ciphertext(deepseek_credential_path())
    completed = _run_systemd_creds(
        executable,
        (
            "--newline=no",
            f"--name={_CREDENTIAL_NAME}",
            "decrypt",
            "-",
            "-",
        ),
        input_bytes=ciphertext,
    )
    try:
        api_key = completed.stdout.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigurationError("decrypted DeepSeek credential is not UTF-8") from None
    return _validated_api_key(api_key)


def _operator_home_directory() -> Path:
    try:
        import pwd

        home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
    except (ImportError, KeyError, OSError, RuntimeError) as error:
        raise ConfigurationError("cannot resolve the operator home directory") from error
    if not home.is_dir():
        raise ConfigurationError("operator home directory is not a directory")
    return home


def _validated_api_key(api_key: str) -> str:
    if (
        not api_key
        or len(api_key) > _MAXIMUM_API_KEY_CHARACTERS
        or api_key.strip() != api_key
        or any(ord(character) < 33 or ord(character) == 127 for character in api_key)
    ):
        raise ConfigurationError("DeepSeek API key is missing or malformed")
    return api_key


def _validated_pass_entry(entry: str) -> str:
    if (
        not entry
        or len(entry) > _MAXIMUM_PASS_ENTRY_LENGTH
        or entry.startswith("/")
        or not entry.isascii()
        or _PASS_ENTRY_CHARACTERS.fullmatch(entry) is None
    ):
        raise ConfigurationError("pass credential entry is invalid")
    segments = entry.split("/")
    if any(
        not segment or segment in {".", ".."} or segment.startswith("-") for segment in segments
    ):
        raise ConfigurationError("pass credential entry is invalid")
    return entry


def _discover_pass_executable() -> Path | None:
    discovered = shutil.which("pass")
    if discovered is None:
        return None
    return Path(os.path.abspath(discovered))


def _validated_systemd_creds(path: Path = _SYSTEMD_CREDS) -> Path:
    try:
        return _validated_executable(path, trusted_owner_ids=frozenset({0}))
    except FileNotFoundError as error:
        raise ConfigurationError("/usr/bin/systemd-creds is unavailable") from error


def _validated_executable(path: Path, *, trusted_owner_ids: frozenset[int]) -> Path:
    try:
        metadata = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        raise
    except OSError as error:
        raise ConfigurationError("cannot inspect credential executable") from error
    if (
        not path.is_absolute()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in trusted_owner_ids
        or metadata.st_mode & 0o022
        or not os.access(path, os.X_OK)
    ):
        raise ConfigurationError("credential executable failed integrity checks")
    return path


def _validate_private_directory(directory: Path) -> None:
    try:
        metadata = directory.stat(follow_symlinks=False)
    except OSError as error:
        raise ConfigurationError("cannot inspect the credential directory") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ConfigurationError(
            "credential directory must be owned by the operator with mode 0700"
        )


def _read_ciphertext(path: Path) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except FileNotFoundError as error:
        raise ConfigurationError("no DeepSeek systemd credential is installed") from error
    except OSError as error:
        raise ConfigurationError("cannot safely open the encrypted DeepSeek credential") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > _MAXIMUM_CIPHERTEXT_BYTES
        ):
            raise ConfigurationError(
                "encrypted DeepSeek credential must be a private, owner-only regular file"
            )
        ciphertext = os.read(descriptor, _MAXIMUM_CIPHERTEXT_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(ciphertext) != metadata.st_size:
        raise ConfigurationError("encrypted DeepSeek credential changed while being read")
    return ciphertext


def _pass_environment(home: Path, parent: Mapping[str, str]) -> dict[str, str]:
    environment = {
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PASSWORD_STORE_DIR": str(home / ".password-store"),
        "PATH": "/usr/bin:/bin",
    }
    for name in _PASS_PINENTRY_ENVIRONMENT:
        value = parent.get(name)
        if (
            value is not None
            and value
            and len(value) <= 4096
            and all(ord(character) >= 32 and ord(character) != 127 for character in value)
        ):
            environment[name] = value
    return environment


def _run_systemd_creds(
    executable: Path,
    arguments: tuple[str, ...],
    *,
    input_bytes: bytes,
    runner: CommandRunner | None = None,
) -> subprocess.CompletedProcess[bytes]:
    active_runner = runner or SubprocessCommandRunner()
    try:
        completed = active_runner.run(
            (str(executable), *arguments),
            input_bytes=input_bytes,
            timeout_seconds=_SYSTEMD_CREDS_TIMEOUT_SECONDS,
            environment={"LANG": "C.UTF-8"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ConfigurationError(
            "systemd-creds could not process the TPM2 credential",
            details={"reason": type(error).__name__},
        ) from None
    if (
        len(completed.stdout) > _MAXIMUM_SYSTEMD_OUTPUT_BYTES
        or len(completed.stderr) > _MAXIMUM_SYSTEMD_OUTPUT_BYTES
    ):
        raise ConfigurationError(
            "systemd-creds returned excessive output",
            details={"reason": "output_too_large"},
        )
    if completed.returncode != 0:
        raise ConfigurationError(
            "TPM2 credential operation failed; ensure the operator belongs to the tss group "
            "and has started a new login session",
            details={"exit_code": completed.returncode},
        )
    return completed


def _provider_error(
    provider_id: CredentialProviderId | Literal["auto"],
    error_type: str,
    *,
    exit_code: int | None = None,
) -> ConfigurationError:
    safe_error_type = (
        error_type if error_type in _SAFE_PROVIDER_ERROR_TYPES else "provider_unavailable"
    )
    details: dict[str, object] = {
        "provider": provider_id,
        "error_type": safe_error_type,
    }
    if exit_code is not None:
        details["exit_code"] = exit_code if -255 <= exit_code <= 255 else "outside_allowed_range"
    return ConfigurationError(
        f"credential provider {provider_id} failed: {safe_error_type}",
        details=details,
    )


def _safe_provider_error_type(error: ConfigurationError) -> str:
    error_type = error.details.get("error_type")
    if isinstance(error_type, str) and error_type in _SAFE_PROVIDER_ERROR_TYPES:
        return error_type
    return "provider_unavailable"


def _atomic_private_write(path: Path, content: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(12)}.tmp")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as error:
        raise ConfigurationError(
            "cannot atomically store the encrypted DeepSeek credential"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(OSError):
            temporary.unlink(missing_ok=True)


__all__ = [
    "CommandRunner",
    "CredentialAvailability",
    "CredentialProvider",
    "CredentialProviderId",
    "CredentialProviderSelection",
    "CredentialResolver",
    "EnvironmentCredentialProvider",
    "PassCredentialProvider",
    "ResolvedCredential",
    "SubprocessCommandRunner",
    "SystemdCredentialProvider",
    "deepseek_credential_is_present",
    "deepseek_credential_path",
    "load_deepseek_credential",
    "store_deepseek_credential",
]
