#!/usr/bin/env bash
set -euo pipefail

PROJ_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SONAR_URL="${SONAR_URL:-http://localhost:9000}"
SONAR_TOKEN="${SONAR_TOKEN:-squ_73c2bb4beeb17a4a90cd6e2fc669b7d6aac723f1}"
RESULTS_DIR="$PROJ_DIR/results"
mkdir -p "$RESULTS_DIR"

echo "=== CBOMkit SonarQube Scan ==="
echo "Project: $PROJ_DIR"
echo "SonarQube: $SONAR_URL"
echo ""

# Run sonar-scanner with timing
START=$(python3 -c "import time; print(int(time.time()*1000))")
cd "$PROJ_DIR"
sonar-scanner \
  -Dsonar.host.url="$SONAR_URL" \
  -Dsonar.token="$SONAR_TOKEN" \
  -Dsonar.projectKey=CipherRadarTestProj
END=$(python3 -c "import time; print(int(time.time()*1000))")
SCAN_MS=$((END - START))
echo "$SCAN_MS" > "$RESULTS_DIR/cbomkit-time.txt"
echo "SonarQube scan time: ${SCAN_MS}ms"

# Wait for analysis
echo "Waiting for analysis to complete..."
if [ -f "$PROJ_DIR/.scannerwork/report-task.txt" ]; then
  TASK_ID=$(grep "ceTaskId=" "$PROJ_DIR/.scannerwork/report-task.txt" | cut -d= -f2)
  for i in $(seq 1 30); do
    TASK_STATUS=$(curl -s -u "$SONAR_TOKEN:" "$SONAR_URL/api/ce/task?id=$TASK_ID" | python3 -c "import sys,json; print(json.load(sys.stdin).get('task',{}).get('status',''))" 2>/dev/null)
    echo "  Status: $TASK_STATUS ($i/30)"
    if [ "$TASK_STATUS" = "SUCCESS" ]; then break; fi
    if [ "$TASK_STATUS" = "FAILED" ]; then echo "ERROR: Analysis failed"; break; fi
    sleep 5
  done
fi

# Extract CBOM
if [ -f "$PROJ_DIR/.scannerwork/cbom.json" ]; then
  cp "$PROJ_DIR/.scannerwork/cbom.json" "$RESULTS_DIR/cbomkit-cbom.json"
  echo "CBOM copied to results/"
fi

# Extract issues via API
curl -s -u "$SONAR_TOKEN:" \
  "$SONAR_URL/api/issues/search?componentKeys=CipherRadarTestProj&ps=500" \
  > "$RESULTS_DIR/cbomkit-issues.json"

TOTAL=$(python3 -c "import json; print(json.load(open('$RESULTS_DIR/cbomkit-issues.json')).get('total',0))" 2>/dev/null || echo "N/A")
echo "Total CBOMkit issues: $TOTAL"
echo ""
echo "=== Timing Summary ==="
echo "SonarQube scan: ${SCAN_MS}ms"
echo "Results saved to: $RESULTS_DIR/"
