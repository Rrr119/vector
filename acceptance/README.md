# Nested PII redaction — acceptance

One command verifies the full contract:

```bash
bash acceptance/run_acceptance.sh
```

`--unit-only` skips the binary end-to-end phase.

## What is verified

Three nested JSON structures cover the acceptance criteria:

1. `deep_object` — deeply nested object fields
   (`request.user.profile.{name,email,ssn}`).
2. `object_array` — arrays of nested objects
   (`accounts[*].owner.email`, `accounts[*].token`).
3. `nested_arrays` — arrays of arrays plus recursive key matching
   (`batches[*][*].card`, `..card` / `meta.deep.card`).

For every structure the suite asserts:

- **All PII is processed** — every configured location is redacted and a
  whole-document scan finds none of the original secret fragments.
- **Non-PII fields are unchanged** — exact value assertions plus a
  SHA-256 fingerprint over the document ignoring targeted paths.
- **Consistency verification** — `verify_redaction` / `verify_consistency`
  proves the above and detects both tampered non-PII fields and missed PII.
- **Auditable operations** — one structured `AuditRecord` per operation with
  timestamp, concrete path, rule, strategy and original/final value digests
  (raw PII is never recorded). Records are retained in memory, appended as
  JSON Lines, and emitted on the `vector::transforms::redact::audit` target.
- **Compatibility** — `redact` is a normal Vector `FunctionTransform`
  (topology test) and the binary phase runs
  `remap -> redact -> remap -> console` over stdin JSON.

## Entry points

- Transform type: `redact` (also registered as `redact_pii` and
  `pii_redaction`).
- Rust module: `vector::transforms::redact` (and the `vector::redaction`
  re-export).
- Key APIs: `parse_path`, `PathPattern`, `enumerate_paths`, `Redactor`,
  `RedactionStrategy`, `apply_patterns`, `redact_nested_fields`,
  `redact_json`, `verify_redaction` / `verify_consistency` / `verify_json`,
  `scan_secrets`, `AuditSink`, `AuditRecord`.

## Evidence files

- `fixtures/nested_pii.jsonl` — the three input events.
- `vector-redact-acceptance.yaml` — the chained transform config.
- `check_artifacts.py` — validates the Rust-generated report/audit artifacts.
- `check_e2e.py` — validates binary console output and e2e audit log.

Generated evidence lands in `artifacts/`.
