"""Fail CI when commit-eligible files appear to contain private credentials."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from evitriage.errors import ConfigurationError

_MAXIMUM_SCANNED_FILE_BYTES = 16 * 1024 * 1024
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
        candidate = (repository_root / relative).resolve(strict=True)
        if not candidate.is_relative_to(repository_root) or not candidate.is_file():
            raise ConfigurationError("git returned an unsafe commit-eligible path")
        paths.append(candidate)
    return tuple(paths)


def scan_repository(repository_root: Path) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Scan commit-eligible bounded files and return path/rule findings."""

    canonical_root = repository_root.resolve(strict=True)
    findings: list[tuple[str, tuple[str, ...]]] = []
    for path in commit_eligible_paths(canonical_root):
        if path.stat().st_size > _MAXIMUM_SCANNED_FILE_BYTES:
            raise ConfigurationError(
                "commit-eligible file exceeds the secret-scan size limit",
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
        print("No credential patterns found in commit-eligible files")
        return 0
    print("Potential credentials found in commit-eligible files:")
    for relative_path, rules in findings:
        print(f"- {relative_path}: {', '.join(rules)}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
