#!/usr/bin/env bash
# End-to-end acceptance for path based nested PII redaction.
#
# Verifies the contract from the task:
#   1. PII is fully processed under three different nested structures
#      (deep objects, arrays of objects, nested arrays + recursion).
#   2. Non-PII fields are byte-for-byte / value-for-value unchanged.
#   3. A before/after consistency check proves (1)+(2) and detects tampering.
#   4. Every redaction is auditable (structured records + JSONL file).
#   5. The feature is a normal Vector transform compatible with existing
#      transforms (topology test + remap -> redact -> remap binary run).
#
# Usage:
#   bash acceptance/run_acceptance.sh [--unit-only]
#
# Environment:
#   CARGO_JOBS          cargo parallelism (default: min(4, nproc))
#   ACCEPTANCE_NO_E2E=1 skip building/running the vector binary phase

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# Ensure the per-user cargo/rustup shims (and any protoc shim) are reachable.
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

mkdir -p artifacts

# --- protoc: vector-core's build script requires it -------------------------
if ! command -v protoc >/dev/null 2>&1; then
  VENDORED_PROTOC="$(find "${CARGO_HOME:-$HOME/.cargo}/registry/src" \
      -path '*protoc-bin-vendored-linux-*/bin/protoc' -type f 2>/dev/null | head -1 || true)"
  if [[ -n "${VENDORED_PROTOC:-}" ]]; then
    export PROTOC="$VENDORED_PROTOC"
  fi
fi
# Some setups keep the registry under /home/dev/.cargo even when HOME differs.
if ! command -v protoc >/dev/null 2>&1 && [[ -z "${PROTOC:-}" ]]; then
  VENDORED_PROTOC="$(find /home/dev/.cargo/registry/src /root/.cargo/registry/src \
      -path '*protoc-bin-vendored-linux-*/bin/protoc' -type f 2>/dev/null | head -1 || true)"
  [[ -n "${VENDORED_PROTOC:-}" ]] && export PROTOC="$VENDORED_PROTOC"
fi
if ! command -v protoc >/dev/null 2>&1 && [[ -z "${PROTOC:-}" ]]; then
  echo "ERROR: protoc is required to build Vector. Install protobuf-compiler or set PROTOC." >&2
  exit 2
fi

JOBS="${CARGO_JOBS:-$( (nproc 2>/dev/null || echo 4) | awk '{ if ($1 > 4) print 4; else print $1 }')}"
FEATURES="transforms-redact"

echo "==> [1/4] Rust unit + topology tests (3 nested structures, consistency, audit)"
REDACT_ACCEPTANCE_ARTIFACTS=1 \
CARGO_BUILD_JOBS="$JOBS" \
  cargo test -p vector --lib --no-default-features --features "$FEATURES" \
  transforms::redact -- --nocapture

echo
echo "==> [2/4] Independent artifact verification"
python3 acceptance/check_artifacts.py

if [[ "${1:-}" == "--unit-only" || "${ACCEPTANCE_NO_E2E:-0}" == "1" ]]; then
  echo
  echo "ACCEPTANCE PASSED (unit + artifacts; binary e2e skipped)."
  exit 0
fi

echo
echo "==> [3/4] Build vector binary with stdin + remap + redact + console"
E2E_FEATURES="sources-stdin,sinks-console,transforms-remap,transforms-redact"
CARGO_BUILD_JOBS="$JOBS" \
  cargo build --bin vector --no-default-features --features "$E2E_FEATURES"

VECTOR_BIN="$REPO_ROOT/target/debug/vector"
AUDIT_FILE="$REPO_ROOT/artifacts/e2e-audit.jsonl"
OUT_FILE="$REPO_ROOT/artifacts/e2e-console.jsonl"
ERR_FILE="$REPO_ROOT/artifacts/e2e-vector.err.log"
: >"$AUDIT_FILE"
: >"$OUT_FILE"
: >"$ERR_FILE"
mkdir -p "$REPO_ROOT/artifacts/vector-data"

echo
echo "==> [4/4] Run remap -> redact -> remap over the three nested structures"
"$VECTOR_BIN" validate acceptance/vector-redact-acceptance.yaml >/dev/null

set +e
timeout --signal=TERM 90 "$VECTOR_BIN" \
  --config acceptance/vector-redact-acceptance.yaml \
  < acceptance/fixtures/nested_pii.jsonl \
  >"$OUT_FILE" 2>"$ERR_FILE"
RUN_RC=$?
set -e

# stdin EOF normally makes vector exit 0; 124 means timeout but the output may
# already be complete, so let the Python checker be the source of truth.
if [[ "$RUN_RC" -ne 0 && "$RUN_RC" -ne 124 ]]; then
  echo "vector run failed with exit code $RUN_RC" >&2
  tail -40 "$ERR_FILE" >&2 || true
  exit 1
fi

python3 acceptance/check_e2e.py --output "$OUT_FILE" --audit "$AUDIT_FILE"

echo
echo "ACCEPTANCE PASSED. Evidence:"
echo "  - $REPO_ROOT/artifacts/redaction-acceptance-report.json"
echo "  - $REPO_ROOT/artifacts/redaction-audit.jsonl"
echo "  - $AUDIT_FILE"
echo "  - $OUT_FILE"
