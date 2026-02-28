"""
tests/gateway_client/report.py
────────────────────────────────
Test result types and output reporters.

TestResult  — outcome of a single test case
SuiteResult — aggregated results for one suite
Reporter    — renders to terminal (ANSI) or JSON
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"


@dataclass
class TestResult:
    name: str
    status: Status
    message: str = ""
    duration_ms: float = 0.0
    detail: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def passed(cls, name: str, duration_ms: float = 0.0, **detail: Any) -> "TestResult":
        return cls(
            name=name, status=Status.PASS, duration_ms=duration_ms, detail=detail
        )

    @classmethod
    def failed(
        cls, name: str, message: str, duration_ms: float = 0.0, **detail: Any
    ) -> "TestResult":
        return cls(
            name=name,
            status=Status.FAIL,
            message=message,
            duration_ms=duration_ms,
            detail=detail,
        )

    @classmethod
    def skipped(cls, name: str, reason: str) -> "TestResult":
        return cls(name=name, status=Status.SKIP, message=reason)

    @classmethod
    def error(cls, name: str, exc: Exception) -> "TestResult":
        return cls(
            name=name, status=Status.ERROR, message=f"{type(exc).__name__}: {exc}"
        )


@dataclass
class SuiteResult:
    name: str
    results: list[TestResult] = field(default_factory=list)
    started_at: float = field(default_factory=time.monotonic)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.status == Status.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if r.status == Status.FAIL)

    @property
    def skipped(self) -> int:
        return sum(1 for r in self.results if r.status == Status.SKIP)

    @property
    def errors(self) -> int:
        return sum(1 for r in self.results if r.status == Status.ERROR)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def duration_s(self) -> float:
        return time.monotonic() - self.started_at

    @property
    def ok(self) -> bool:
        return self.failed == 0 and self.errors == 0


# ── ANSI helpers ──────────────────────────────────────────────────────────────

_RESET = "\033[0m"
_BOLD = "\033[1m"
_GREEN = "\033[32m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_DIM = "\033[2m"


def _color(text: str, *codes: str) -> str:
    return "".join(codes) + text + _RESET


# ── Reporters ─────────────────────────────────────────────────────────────────


def print_suite_header(name: str) -> None:
    bar = "─" * 60
    print(f"\n{_color(bar, _CYAN)}")
    print(f"  {_color('Suite: ' + name.upper(), _BOLD, _CYAN)}")
    print(f"{_color(bar, _CYAN)}")


def print_result(result: TestResult) -> None:
    icon = {
        Status.PASS: _color("✔", _GREEN),
        Status.FAIL: _color("✘", _RED),
        Status.SKIP: _color("·", _YELLOW),
        Status.ERROR: _color("!", _RED, _BOLD),
    }[result.status]

    dur = f"{_color(f'{result.duration_ms:.0f}ms', _DIM)}" if result.duration_ms else ""
    name = f"{result.name:<55}"
    line = f"  {icon}  {name} {dur}"

    if result.status in (Status.FAIL, Status.ERROR) and result.message:
        print(line)
        print(f"     {_color(result.message, _RED)}")
        for k, v in result.detail.items():
            print(f"     {_color(k + ':', _DIM)} {v}")
    elif result.status == Status.SKIP:
        print(f"  {icon}  {_color(result.name, _DIM)}: {result.message}")
    else:
        print(line)


def print_suite_summary(suite: SuiteResult) -> None:
    total = suite.total
    color = _GREEN if suite.ok else _RED
    status_str = _color("PASS" if suite.ok else "FAIL", _BOLD, color)
    print(
        f"\n  {status_str}  {suite.passed}/{total} passed"
        f"  {suite.skipped} skipped"
        f"  {suite.errors} errors"
        f"  ({suite.duration_s:.1f}s)\n"
    )


def print_grand_summary(suites: list[SuiteResult]) -> None:
    bar = "═" * 60
    print(f"\n{_color(bar, _BOLD)}")
    print(f"  {_color('GRAND SUMMARY', _BOLD)}")
    print(f"{_color(bar, _BOLD)}")

    total_pass = sum(s.passed for s in suites)
    total_fail = sum(s.failed for s in suites)
    total_skip = sum(s.skipped for s in suites)
    total_err = sum(s.errors for s in suites)
    total_all = sum(s.total for s in suites)
    all_ok = all(s.ok for s in suites)

    for suite in suites:
        icon = _color("✔", _GREEN) if suite.ok else _color("✘", _RED)
        print(f"  {icon}  {suite.name:<20}  {suite.passed}/{suite.total} passed")

    color = _GREEN if all_ok else _RED
    overall = _color("ALL PASSED" if all_ok else "FAILURES DETECTED", _BOLD, color)
    print(f"\n  {overall}")
    print(
        f"  {total_pass}/{total_all} passed  "
        f"{total_skip} skipped  "
        f"{total_err} errors  "
        f"{total_fail} failures\n"
    )


def dump_json(suites: list[SuiteResult]) -> str:
    """Serialize all suite results to a JSON string."""

    def result_to_dict(r: TestResult) -> dict:
        return {
            "name": r.name,
            "status": r.status.value,
            "message": r.message,
            "duration_ms": round(r.duration_ms, 1),
            "detail": r.detail,
        }

    data = []
    for suite in suites:
        data.append(
            {
                "suite": suite.name,
                "passed": suite.passed,
                "failed": suite.failed,
                "skipped": suite.skipped,
                "errors": suite.errors,
                "total": suite.total,
                "duration_s": round(suite.duration_s, 2),
                "ok": suite.ok,
                "results": [result_to_dict(r) for r in suite.results],
            }
        )
    return json.dumps({"suites": data}, indent=2)
