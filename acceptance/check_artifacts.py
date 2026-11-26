#!/usr/bin/env python3
"""Validate the acceptance artifacts emitted by the Rust test suite.

The `writes_acceptance_artifacts_when_requested` test writes
`artifacts/redaction-acceptance-report.json` and
`artifacts/redaction-audit.jsonl` when `REDACT_ACCEPTANCE_ARTIFACTS=1`.
This checker independently verifies the acceptance contract from disk.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    artifacts = Path(__file__).resolve().parent.parent / "artifacts"
    report_path = artifacts / "redaction-acceptance-report.json"
    audit_path = artifacts / "redaction-audit.jsonl"

    failures: list[str] = []

    if not report_path.exists():
        print(f"missing {report_path}", file=sys.stderr)
        return 1

    report = json.loads(report_path.read_text(encoding="utf-8"))
    cases = report.get("cases", [])
    if len(cases) != 3:
        failures.append(f"expected 3 nested-structure cases, got {len(cases)}")

    names = {case.get("name") for case in cases}
    expected = {"deep_object", "object_array", "nested_arrays"}
    if names != expected:
        failures.append(f"case names {names} != {expected}")

    for case in cases:
        name = case.get("name")
        if case.get("leaks") != 0:
            failures.append(f"{name}: {case.get('leaks')} PII leaks")
        if case.get("consistent") is not True:
            failures.append(f"{name}: consistency check did not pass")
        if case.get("fingerprints_match") is not True:
            failures.append(f"{name}: non-PII fingerprints differ")
        if not case.get("pii_locations"):
            failures.append(f"{name}: no PII locations processed")
        if not case.get("audit_records"):
            failures.append(f"{name}: no audit records")

    if not audit_path.exists():
        failures.append(f"missing audit file {audit_path}")
        records = []
    else:
        records = [
            json.loads(line)
            for line in audit_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    if len(records) < 11:
        failures.append(f"expected at least 11 audit records, got {len(records)}")

    for record in records:
        if record.get("status") != "redacted":
            failures.append(f"unexpected audit status {record.get('status')!r}")
            continue
        if not record.get("timestamp"):
            failures.append("audit record without timestamp")
        if not record.get("path"):
            failures.append("audit record without path")
        if not record.get("original_digest"):
            failures.append(f"audit record {record.get('path')} without digest")

    audited_paths = {record.get("path") for record in records}
    for required in (
        ".request.user.profile.email",
        ".accounts[0].owner.email",
        ".batches[0][0].card",
        ".meta.deep.card",
    ):
        if required not in audited_paths:
            failures.append(f"audit missing representative path {required}")

    if failures:
        print("ARTIFACT CHECK FAILED:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print(f"[ok] report covers 3 nested structures: {sorted(names)}")
    print("[ok] every case: 0 leaks, consistent, fingerprints match")
    print(f"[ok] {len(records)} audited redaction operations with digests")
    print("ACCEPTANCE ARTIFACTS VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
