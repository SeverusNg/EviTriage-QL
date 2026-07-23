from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol, cast

import pytest


class _TerminalReporter(Protocol):
    stats: dict[str, list[object]]


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register the opt-in Gate G machine-readable summary output."""

    group = parser.getgroup("evitriage-release")
    group.addoption(
        "--release-summary",
        action="store",
        default=None,
        help="write a strict machine-readable Gate G pytest summary",
    )
    group.addoption(
        "--release-suite",
        action="store",
        choices=("full", "security"),
        default="full",
        help="identify the acceptance suite represented by --release-summary",
    )


def pytest_sessionfinish(session: pytest.Session, exitstatus: int | pytest.ExitCode) -> None:
    """Write actual pytest outcome counts when release evidence was requested."""

    raw_path = cast(str | None, session.config.getoption("release_summary"))
    if raw_path is None:
        return
    output = Path(raw_path)
    if output.is_symlink() or not output.parent.is_dir() or output.parent.is_symlink():
        raise pytest.UsageError(
            "release summary path must be a regular file in an existing directory"
        )
    reporter_value = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter_value is None or not hasattr(reporter_value, "stats"):
        raise pytest.UsageError("terminal reporter is required for a release summary")
    reporter = cast(_TerminalReporter, reporter_value)
    counts = {
        "passed": len(reporter.stats.get("passed", [])),
        "failed": len(reporter.stats.get("failed", [])),
        "errors": len(reporter.stats.get("error", [])),
        "skipped": len(reporter.stats.get("skipped", [])),
        "xfailed": len(reporter.stats.get("xfailed", [])),
        "xpassed": len(reporter.stats.get("xpassed", [])),
        "deselected": len(reporter.stats.get("deselected", [])),
    }
    numeric_exit = int(exitstatus)
    summary = {
        "schema_version": "1.0",
        "suite": cast(str, session.config.getoption("release_suite")),
        "command": "pytest",
        "outcome": "passed" if numeric_exit == 0 else "failed",
        "exit_code": numeric_exit,
        "tests_collected": session.testscollected,
        "counts": counts,
        "coverage_gate_enforced": cast(str, session.config.getoption("release_suite")) == "full",
    }
    output.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )


@pytest.fixture
def repository_root() -> Path:
    """Return the checkout root used by checked-in integration fixtures."""
    return Path(__file__).resolve().parents[1]
