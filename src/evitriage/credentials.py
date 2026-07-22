"""TPM2-bound operator credential storage outside the repository."""

from __future__ import annotations

import os
import secrets
import stat
import subprocess
from contextlib import suppress
from pathlib import Path

from evitriage.errors import ConfigurationError

_CREDENTIAL_NAME = "evitriage-deepseek-api-key"
_CREDENTIAL_FILENAME = f"{_CREDENTIAL_NAME}.cred"
_SYSTEMD_CREDS = Path("/usr/bin/systemd-creds")
_MAXIMUM_CIPHERTEXT_BYTES = 64 * 1024
_SYSTEMD_CREDS_TIMEOUT_SECONDS = 30


def deepseek_credential_path() -> Path:
    """Return the fixed, repository-external DeepSeek credential path."""

    try:
        import pwd

        home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
    except (ImportError, KeyError, OSError, RuntimeError) as error:
        raise ConfigurationError("cannot resolve the operator home directory") from error
    return home / ".local" / "share" / "evitriage" / "credentials" / _CREDENTIAL_FILENAME


def deepseek_credential_is_present() -> bool:
    """Report whether a secure-looking encrypted credential file is present."""

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
    except UnicodeDecodeError as error:
        raise ConfigurationError("decrypted DeepSeek credential is not UTF-8") from error
    return _validated_api_key(api_key)


def _validated_api_key(api_key: str) -> str:
    if (
        not api_key
        or len(api_key) > 4096
        or api_key.strip() != api_key
        or any(ord(character) < 33 or ord(character) == 127 for character in api_key)
    ):
        raise ConfigurationError("DeepSeek API key is missing or malformed")
    return api_key


def _validated_systemd_creds() -> Path:
    try:
        metadata = _SYSTEMD_CREDS.stat(follow_symlinks=False)
    except OSError as error:
        raise ConfigurationError("/usr/bin/systemd-creds is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
        or not os.access(_SYSTEMD_CREDS, os.X_OK)
    ):
        raise ConfigurationError("/usr/bin/systemd-creds failed executable integrity checks")
    return _SYSTEMD_CREDS


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
        raise ConfigurationError(
            "no DeepSeek credential is installed; set DEEPSEEK_API_KEY for one process or run "
            "`evitriage credentials set-deepseek` for TPM2 storage"
        ) from error
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


def _run_systemd_creds(
    executable: Path,
    arguments: tuple[str, ...],
    *,
    input_bytes: bytes,
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed root-owned executable and literal argv
            (str(executable), *arguments),
            input=input_bytes,
            capture_output=True,
            check=False,
            timeout=_SYSTEMD_CREDS_TIMEOUT_SECONDS,
            env={"LANG": "C.UTF-8"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ConfigurationError(
            "systemd-creds could not process the TPM2 credential",
            details={"reason": type(error).__name__},
        ) from error
    if completed.returncode != 0:
        raise ConfigurationError(
            "TPM2 credential operation failed; ensure the operator belongs to the tss group "
            "and has started a new login session",
            details={"exit_code": completed.returncode},
        )
    return completed


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
    "deepseek_credential_is_present",
    "deepseek_credential_path",
    "load_deepseek_credential",
    "store_deepseek_credential",
]
