#!/usr/bin/env bash
set -euo pipefail

PROJ_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CRADAR_BIN="${CRADAR_BIN:-/tmp/cradar-benchmark}"
RESULTS_DIR="$PROJ_DIR/results"
mkdir -p "$RESULTS_DIR"

echo "=== CipherRadar Benchmark Scan ==="
echo "Project: $PROJ_DIR"
echo ""

# Pass 1 only (fair comparison with CBOMkit)
echo "--- Pass 1 Only (tree-sitter) ---"
START=$(python3 -c "import time; print(int(time.time()*1000))")
$CRADAR_BIN scan "$PROJ_DIR" \
  --format cyclonedx-json \
  --output "$RESULTS_DIR/cradar-pass1.json" \
  --passes 1
END=$(python3 -c "import time; print(int(time.time()*1000))")
PASS1_MS=$((END - START))
echo "$PASS1_MS" > "$RESULTS_DIR/cradar-pass1-time.txt"
echo "Pass 1 scan time: ${PASS1_MS}ms"

# Full scan (all 3 passes)
echo ""
echo "--- Full Scan (Pass 1+2+3) ---"
START=$(python3 -c "import time; print(int(time.time()*1000))")
$CRADAR_BIN scan "$PROJ_DIR" \
  --format cyclonedx-json \
  --output "$RESULTS_DIR/cradar-full.json" \
  --passes 1,2,3
END=$(python3 -c "import time; print(int(time.time()*1000))")
FULL_MS=$((END - START))
echo "$FULL_MS" > "$RESULTS_DIR/cradar-full-time.txt"
echo "Full scan time: ${FULL_MS}ms"

# Text summary
$CRADAR_BIN scan "$PROJ_DIR" \
  --format text \
  --output "$RESULTS_DIR/cradar-summary.txt" \
  --passes 1

echo ""
echo "=== Timing Summary ==="
echo "Pass 1 only: ${PASS1_MS}ms"
echo "Full (1+2+3): ${FULL_MS}ms"
echo "Results saved to: $RESULTS_DIR/"
