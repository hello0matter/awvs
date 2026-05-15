#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"
if ! command -v sqlmap >/dev/null 2>&1; then
  echo "[ERROR] sqlmap was not found in PATH."
  echo "[HINT] Install sqlmap or add it to PATH, then rerun this script."
  exit 1
fi
echo "[INFO] SQLMap Baseline Collection Mode"
echo "[INFO] WorkDir: $(pwd)"
echo
echo "[INFO] Baseline collection mode, 1 command."
sqlmap -m "08_sqlmap_urls_baseline.txt" --batch --random-agent --level 5 --risk 3 --drop-set-cookie --skip-static --results-file "sqlmap_collection_results.csv" --output-dir "sqlmap_output_baseline/collection"
