#!/usr/bin/env bash
# Simulate a scanner POSTing a finding to the orchestrator.
#
# Usage:
#   ./scripts/simulate.sh                # post all demo findings
#   ./scripts/simulate.sh sast           # post just the SAST demo finding
#   ./scripts/simulate.sh cve            # post just the dep-CVE demo finding
#   ORCHESTRATOR_URL=http://localhost:8080 INGEST_SHARED_SECRET=xxx ./scripts/simulate.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
URL="${ORCHESTRATOR_URL:-http://localhost:8080}"
SECRET="${INGEST_SHARED_SECRET:-change-me-to-a-long-random-string}"
WHICH="${1:-all}"

case "$WHICH" in
  cve)  FILES=("$ROOT/examples/finding-dep-cve.json") ;;
  sast) FILES=("$ROOT/examples/finding-sast.json") ;;
  all)  FILES=("$ROOT/examples/finding-dep-cve.json" "$ROOT/examples/finding-sast.json") ;;
  *) echo "unknown argument: $WHICH (use: cve | sast | all)" >&2; exit 2 ;;
esac

for f in "${FILES[@]}"; do
  echo ">>> POST $URL/ingest  <- $(basename "$f")"
  curl -sS -X POST "$URL/ingest" \
    -H "Content-Type: application/json" \
    -H "X-Ingest-Secret: $SECRET" \
    --data-binary "@$f" | python3 -m json.tool
  echo
done

echo "Dashboard: $URL/dashboard"
echo "Stats:     $URL/stats"
