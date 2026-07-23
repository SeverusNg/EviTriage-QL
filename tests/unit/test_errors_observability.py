from __future__ import annotations

import json
import logging
import shutil
import subprocess
from io import StringIO
from pathlib import Path

import pytest

from evitriage.errors import ConfigurationError
from evitriage.observability import configure_logging, redact
from evitriage.secret_scan import (
    commit_eligible_paths,
    detect_secret_rules,
    scan_repository,
    source_distribution_paths,
)


def test_typed_error_has_stable_machine_representation() -> None:
    error = ConfigurationError("bad project", details={"field": "source.path"})

    assert error.exit_code == 2
    assert error.as_dict() == {
        "error": {
            "code": "CONFIGURATION_ERROR",
            "message": "bad project",
            "details": {"field": "source.path"},
        }
    }


@pytest.mark.security
def test_redaction_handles_nested_secrets_and_bearer_values() -> None:
    value = {
        "api_key": "top-secret",
        "nested": [
            {"password": "hidden"},
            "Bearer abc.def",
            "password=hunter2 token:secret-value",
            "https://user:token@example.invalid/repository.git",
        ],
        "safe": "visible",
    }

    assert redact(value) == {
        "api_key": "[REDACTED]",
        "nested": [
            {"password": "[REDACTED]"},
            "Bearer [REDACTED]",
            "password=[REDACTED] token:[REDACTED]",
            "https://[REDACTED]@example.invalid/repository.git",
        ],
        "safe": "visible",
    }


def test_json_logger_redacts_structured_fields() -> None:
    stream = StringIO()
    configure_logging(stream=stream)

    logging.getLogger("evitriage.test").info(
        "configured",
        extra={"structured_fields": {"token": "secret", "project": "demo"}},
    )

    event = json.loads(stream.getvalue())
    assert event["message"] == "configured"
    assert event["fields"] == {"project": "demo", "token": "[REDACTED]"}


def test_secret_scan_detects_values_without_flagging_environment_references(
    repository_root: Path,
) -> None:
    assignment = b"DEEPSEEK_API_" + b"KEY=" + b"sk-" + (b"x" * 24)
    private_key = b"-----BEGIN " + b"PRIVATE KEY-----"

    assert set(detect_secret_rules(assignment)) == {
        "api-key-shaped-token",
        "deepseek-environment-assignment",
    }
    assert detect_secret_rules(private_key) == ("private-key-block",)
    assert detect_secret_rules(b"read -s DEEPSEEK_API_KEY; export DEEPSEEK_API_KEY") == ()
    assert scan_repository(repository_root) == ()


def test_secret_scan_supports_a_gitless_source_distribution(tmp_path: Path) -> None:
    (tmp_path / "PKG-INFO").write_text(
        "Metadata-Version: 2.4\nName: evitriage-ql\nVersion: 0.1.0\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='evitriage-ql'\nversion='0.1.0'\n", encoding="utf-8"
    )
    (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (tmp_path / "safe.py").write_text("print('safe')\n", encoding="utf-8")
    ignored = tmp_path / ".venv"
    ignored.mkdir()
    (ignored / "credential.txt").write_bytes(b"sk-" + b"x" * 24)

    assert {
        path.relative_to(tmp_path).as_posix() for path in source_distribution_paths(tmp_path)
    } == {
        "PKG-INFO",
        "pyproject.toml",
        "safe.py",
        "uv.lock",
    }
    assert scan_repository(tmp_path) == ()

    (tmp_path / "unsafe.txt").write_bytes(b"sk-" + b"x" * 24)
    assert scan_repository(tmp_path) == (("unsafe.txt", ("api-key-shaped-token",)),)


def test_git_secret_scan_ignores_deleted_tracked_paths(tmp_path: Path) -> None:
    git = shutil.which("git")
    assert git is not None
    initialized = subprocess.run(
        [git, "init", "--quiet", str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert initialized.returncode == 0, initialized.stderr
    tracked = tmp_path / "tracked.txt"
    tracked.write_text("tracked\n", encoding="utf-8")
    added = subprocess.run(
        [git, "add", "tracked.txt"],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert added.returncode == 0, added.stderr
    tracked.unlink()
    untracked = tmp_path / "untracked.txt"
    untracked.write_text("untracked\n", encoding="utf-8")

    assert commit_eligible_paths(tmp_path) == (untracked,)


@pytest.mark.security
def test_gitless_secret_scan_rejects_unidentified_archives_and_symlinks(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="Git checkout or an EviTriage source"):
        source_distribution_paths(tmp_path)

    (tmp_path / "PKG-INFO").write_text(
        "Metadata-Version: 2.4\nName: evitriage-ql\nVersion: 0.1.0\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='evitriage-ql'\nversion='0.1.0'\n", encoding="utf-8"
    )
    (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    outside = tmp_path.parent / f"{tmp_path.name}-outside-secret-scan.txt"
    outside.write_text("outside", encoding="utf-8")
    (tmp_path / "linked.txt").symlink_to(outside)

    with pytest.raises(ConfigurationError, match="non-regular file"):
        source_distribution_paths(tmp_path)
