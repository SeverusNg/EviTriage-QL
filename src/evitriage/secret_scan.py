"""Fail CI when commit-eligible files appear to contain private credentials."""

from __future__ import annotations

import re
import shutil
import stat
import subprocess
import tomllib
from os import walk
from pathlib import Path

from evitriage.errors import ConfigurationError

_MAXIMUM_SCANNED_FILE_BYTES = 16 * 1024 * 1024
_SOURCE_DISTRIBUTION_IGNORED_DIRECTORIES = frozenset(
    {
        ".evitriage",
        ".git",
        ".hypothesis",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "artifacts",
        "build",
        "dist",
        "htmlcov",
        "model-responses",
        "replay-cache",
        "test-results",
        "workspaces",
    }
)
_RULES: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    (
        "deepseek-environment-assignment",
        re.compile(
            rb"(?i)(?<![A-Z0-9_])DEEPSEEK_API_KEY\s*=\s*['\"]?"
            rb"(?!\s*(?:$|<|\$|REPLACE|YOUR_|EXAMPLE|CHANGEME))[A-Za-z0-9._~+/=-]{12,}"
        ),
    ),
    ("api-key-shaped-token", re.compile(rb"(?<![A-Za-z0-9])sk-[A-Za-z0-9]{20,}")),
    ("private-key-block", re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
)


def detect_secret_rules(content: bytes) -> tuple[str, ...]:
    """Return rule names only, never matched credential material."""

    return tuple(name for name, pattern in _RULES if pattern.search(content) is not None)


def commit_eligible_paths(repository_root: Path) -> tuple[Path, ...]:
    """List tracked and untracked non-ignored files using Git's own policy."""

    git = shutil.which("git")
    if git is None:
        raise ConfigurationError("git is required for the commit-eligible secret scan")
    completed = subprocess.run(  # noqa: S603 - absolute executable and fixed argv
        [git, "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=repository_root,
        check=False,
        capture_output=True,
        timeout=30,
    )
    if completed.returncode != 0:
        raise ConfigurationError("git could not list commit-eligible files")
    paths: list[Path] = []
    for raw_path in completed.stdout.split(b"\0"):
        if not raw_path:
            continue
        try:
            relative = Path(raw_path.decode("utf-8"))
        except UnicodeError as error:
            raise ConfigurationError("git returned a non-UTF-8 repository path") from error
        unresolved = repository_root / relative
        try:
            metadata = unresolved.lstat()
        except FileNotFoundError:
            # Git keeps a deleted tracked path in --cached output until the
            # deletion is staged or committed. There are no remaining bytes to scan.
            continue
        if not stat.S_ISREG(metadata.st_mode) or unresolved.is_symlink():
            raise ConfigurationError("git returned an unsafe commit-eligible path")
        candidate = unresolved.resolve(strict=True)
        if not candidate.is_relative_to(repository_root) or not candidate.is_file():
            raise ConfigurationError("git returned an unsafe commit-eligible path")
        paths.append(candidate)
    return tuple(paths)


def source_distribution_paths(source_root: Path) -> tuple[Path, ...]:
    """List bounded release-source files when Git metadata is intentionally absent."""

    package_metadata = source_root / "PKG-INFO"
    required = (package_metadata, source_root / "pyproject.toml", source_root / "uv.lock")
    if any(path.is_symlink() or not path.is_file() for path in required):
        raise ConfigurationError(
            "secret scan requires a Git checkout or an EviTriage source distribution"
        )
    pyproject = tomllib.loads((source_root / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject.get("project")
    expected_version = project.get("version") if isinstance(project, dict) else None
    metadata = package_metadata.read_text(encoding="utf-8")
    if (
        not isinstance(expected_version, str)
        or "\nName: evitriage-ql\n" not in metadata
        or f"\nVersion: {expected_version}\n" not in metadata
    ):
        raise ConfigurationError("PKG-INFO does not identify the expected source distribution")

    paths: list[Path] = []
    for directory, directory_names, file_names in walk(
        source_root, topdown=True, followlinks=False
    ):
        current = Path(directory)
        retained_directories: list[str] = []
        for name in sorted(directory_names):
            candidate = current / name
            if name == "__pycache__" or (
                current == source_root and name in _SOURCE_DISTRIBUTION_IGNORED_DIRECTORIES
            ):
                continue
            if candidate.is_symlink():
                raise ConfigurationError(
                    "source distribution contains a symlink",
                    details={"path": candidate.relative_to(source_root).as_posix()},
                )
            retained_directories.append(name)
        directory_names[:] = retained_directories
        for name in sorted(file_names):
            candidate = current / name
            if candidate.is_symlink() or not candidate.is_file():
                raise ConfigurationError(
                    "source distribution contains a non-regular file",
                    details={"path": candidate.relative_to(source_root).as_posix()},
                )
            paths.append(candidate)
    return tuple(sorted(paths))


def secret_scan_paths(repository_root: Path) -> tuple[Path, ...]:
    """Select Git commit candidates or the closed source-distribution tree."""

    git_marker = repository_root / ".git"
    if git_marker.exists() or git_marker.is_symlink():
        return commit_eligible_paths(repository_root)
    return source_distribution_paths(repository_root)


def scan_repository(repository_root: Path) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Scan bounded releasable files and return path/rule findings."""

    canonical_root = repository_root.resolve(strict=True)
    findings: list[tuple[str, tuple[str, ...]]] = []
    for path in secret_scan_paths(canonical_root):
        if path.stat().st_size > _MAXIMUM_SCANNED_FILE_BYTES:
            raise ConfigurationError(
                "releasable file exceeds the secret-scan size limit",
                details={"path": path.relative_to(canonical_root).as_posix()},
            )
        content = path.read_bytes()
        matched = detect_secret_rules(content)
        if matched:
            findings.append((path.relative_to(canonical_root).as_posix(), matched))
    return tuple(findings)


def main() -> int:
    """Scan the current checkout without printing matched credential values."""

    findings = scan_repository(Path.cwd())
    if not findings:
        print("No credential patterns found in releasable files")
        return 0
    print("Potential credentials found in releasable files:")
    for relative_path, rules in findings:
        print(f"- {relative_path}: {', '.join(rules)}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
