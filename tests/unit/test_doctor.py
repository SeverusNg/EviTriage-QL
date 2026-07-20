from __future__ import annotations

import shutil
from pathlib import Path
from typing import cast

from evitriage.doctor import run_doctor


def test_doctor_reports_managed_roots_and_optional_codeql(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='test'\n", encoding="utf-8")
    config_dir = tmp_path / "configs" / "system"
    config_dir.mkdir(parents=True)
    repository_root = Path(__file__).resolve().parents[2]
    shutil.copy2(repository_root / "configs/system/v0.1.yaml", config_dir / "v0.1.yaml")

    report = run_doctor(tmp_path)

    check_items = cast(list[dict[str, object]], report["checks"])
    checks = {str(item["name"]): item for item in check_items}
    assert checks["workspace_root"]["status"] == "ok"
    assert checks["artifact_root"]["status"] == "ok"
    assert checks["system_config"]["status"] == "ok"
    assert checks["codeql"]["required"] is False
    assert (tmp_path / "workspaces").is_dir()
    assert (tmp_path / "artifacts").is_dir()
