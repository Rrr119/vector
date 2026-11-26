#!/usr/bin/env bash
# Convenience entry point; the full suite lives in acceptance/run_acceptance.sh.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/acceptance/run_acceptance.sh" "$@"
