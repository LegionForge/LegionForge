"""
tests/testlab_suite/novel_findings.py
──────────────────────────────────────
Read/write helpers for the novel_findings.json file.

Each finding:
  {
    "id":            str (uuid),
    "ts":            str (ISO 8601 UTC),
    "category":      "general" | "security" | "cve",
    "test_name":     str,
    "source_code":   str,
    "failure_reason": str,
    "promoted":      bool,
  }

Used by:
  - test_novel_llm.py       — appends findings when generated tests fail
  - test_novel_security.py  — appends security findings
  - test_cve.py             — appends CVE findings
  - src/testlab/app.py      — serves /novel endpoints
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_FINDINGS_FILE = Path(__file__).parent / "novel_findings.json"


def load_findings() -> list[dict[str, Any]]:
    """Load all findings from disk. Returns [] if file missing or corrupt."""
    if not _FINDINGS_FILE.exists():
        return []
    try:
        return json.loads(_FINDINGS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def save_findings(findings: list[dict[str, Any]]) -> None:
    """Overwrite findings file with the given list."""
    _FINDINGS_FILE.write_text(
        json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def append_finding(
    *,
    category: str,
    test_name: str,
    source_code: str,
    failure_reason: str,
) -> str:
    """Append a new finding and return its id."""
    findings = load_findings()
    finding_id = str(uuid.uuid4())
    findings.append(
        {
            "id": finding_id,
            "ts": datetime.now(timezone.utc).isoformat(),
            "category": category,
            "test_name": test_name,
            "source_code": source_code,
            "failure_reason": failure_reason,
            "promoted": False,
        }
    )
    save_findings(findings)
    return finding_id


def promote_finding(finding_id: str, target_file: Path) -> bool:
    """
    Copy a finding's source_code into target_file (appended).
    Marks the finding as promoted=True.
    Returns True on success.
    """
    findings = load_findings()
    for f in findings:
        if f["id"] == finding_id:
            if not f.get("promoted"):
                existing = (
                    target_file.read_text(encoding="utf-8")
                    if target_file.exists()
                    else ""
                )
                separator = f"\n\n\n# ── Promoted novel finding: {f['test_name']} ({f['ts']}) ──\n\n"
                target_file.write_text(
                    existing + separator + f["source_code"] + "\n", encoding="utf-8"
                )
                f["promoted"] = True
                save_findings(findings)
            return True
    return False
