#!/usr/bin/env python3
"""Independent end-to-end checks for the path based PII redaction transform.

Reads the console sink output (newline delimited JSON) and the redaction audit
JSON Lines file produced by ``acceptance/vector-redact-acceptance.yaml`` and
verifies:

* every known PII secret is gone from the entire output,
* PII paths carry the redaction token,
* non PII fields keep exactly their original values,
* upstream/downstream ``remap`` transforms still work,
* every redaction is audited with a path, timestamp and value digest,
* the before/after consistency check reported no violations.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SECRETS = [
    "Jane Doe",
    "jane.doe@example.com",
    "123-45-6789",
    "alice@example.com",
    "bob@example.com",
    "tok-alpha",
    "tok-beta",
    "4111-1111-1111-1111",
    "5555-5555-5555-4444",
    "3782-822463-10005",
    "6011-1111-1111-1117",
]

REPLACEMENT = "[REDACTED]"


def dig(node, *path):
    for key in path:
        node = node[key]
    return node


def load_events(stdout_path: Path):
    raw = stdout_path.read_text(encoding="utf-8", errors="replace")
    events = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return raw, events


def check_outputs(raw: str, events: list) -> list[str]:
    failures: list[str] = []

    for secret in SECRETS:
        if secret in raw:
            failures.append(f"raw PII {secret!r} still present in console output")

    if len(events) != 3:
        failures.append(f"expected 3 output events, got {len(events)}: {events!r}")
        return failures

    by_marker = {}
    for event in events:
        if event.get("event_id") == "evt-1":
            by_marker["deep"] = event
        elif event.get("region") == "cn-north":
            by_marker["array"] = event
        elif event.get("batch_id") == "b-9":
            by_marker["nested"] = event

    if set(by_marker) != {"deep", "array", "nested"}:
        failures.append(f"could not classify all three events: {list(by_marker)}")
        return failures

    deep = by_marker["deep"]
    try:
        assert dig(deep, "request", "user", "profile", "email") == REPLACEMENT
        assert dig(deep, "request", "user", "profile", "ssn") == REPLACEMENT
        assert dig(deep, "request", "user", "profile", "name") == REPLACEMENT
        # Non PII fields unchanged.
        assert deep["event_id"] == "evt-1"
        assert dig(deep, "request", "id") == "req-42"
        assert dig(deep, "request", "user", "id") == "u-7"
    except (KeyError, AssertionError) as exc:
        failures.append(f"deep-object case mismatch: {exc}")

    array = by_marker["array"]
    try:
        assert dig(array, "accounts", 0, "owner", "email") == REPLACEMENT
        assert dig(array, "accounts", 1, "owner", "email") == REPLACEMENT
        assert dig(array, "accounts", 0, "token") == REPLACEMENT
        assert dig(array, "accounts", 1, "token") == REPLACEMENT
        assert array["region"] == "cn-north"
        assert dig(array, "accounts", 0, "score") == 10
        assert dig(array, "accounts", 1, "score") == 20
        assert len(array["accounts"]) == 2
    except (KeyError, IndexError, AssertionError) as exc:
        failures.append(f"object-array case mismatch: {exc}")

    nested = by_marker["nested"]
    try:
        assert dig(nested, "batches", 0, 0, "card") == REPLACEMENT
        assert dig(nested, "batches", 0, 1, "card") == REPLACEMENT
        assert dig(nested, "batches", 1, 0, "card") == REPLACEMENT
        assert dig(nested, "meta", "deep", "card") == REPLACEMENT
        assert nested["batch_id"] == "b-9"
        assert dig(nested, "batches", 0, 0, "ok") is True
        assert dig(nested, "batches", 0, 1, "ok") is False
    except (KeyError, IndexError, AssertionError) as exc:
        failures.append(f"nested-array case mismatch: {exc}")

    # Compatibility with the remap transforms before and after redact.
    for name, event in by_marker.items():
        if event.get("pipeline") != "pii-acceptance":
            failures.append(f"{name}: upstream remap marker missing")
        if event.get("redaction_verified") is not True:
            failures.append(f"{name}: downstream remap marker missing")

    return failures


def check_audit(audit_path: Path) -> list[str]:
    failures: list[str] = []
    if not audit_path.exists():
        return [f"audit file not created: {audit_path}"]

    records = []
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))

    redacted = [r for r in records if r.get("status") == "redacted"]
    violations = [r for r in records if r.get("status") == "consistency_violation"]

    if violations:
        failures.append(f"consistency violations audited: {violations}")
    if len(redacted) != 11:
        failures.append(f"expected 11 redaction audit records, got {len(redacted)}")

    required_paths = {
        ".request.user.profile.email",
        ".request.user.profile.ssn",
        ".request.user.profile.name",
        ".accounts[0].owner.email",
        ".accounts[1].owner.email",
        ".accounts[0].token",
        ".accounts[1].token",
        ".batches[0][0].card",
        ".batches[0][1].card",
        ".batches[1][0].card",
        ".meta.deep.card",
    }
    seen_paths = {r.get("path") for r in redacted}
    missing = required_paths - seen_paths
    if missing:
        failures.append(f"audit missing paths: {sorted(missing)}")

    for record in redacted:
        for key in ("timestamp", "path", "strategy", "status", "original_digest"):
            if not record.get(key):
                failures.append(f"audit record {record.get('path')} missing {key}")
                break

    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--audit", required=True, type=Path)
    args = parser.parse_args()

    raw, events = load_events(args.output)
    failures = check_outputs(raw, events)
    failures.extend(check_audit(args.audit))

    if failures:
        print("E2E CHECK FAILED:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print(f"[ok] no PII survives across {len(events)} nested events")
    print("[ok] all targeted paths redacted; non-PII fields unchanged")
    print("[ok] remap -> redact -> remap chain works")
    print("[ok] audit trail complete and consistency check clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
