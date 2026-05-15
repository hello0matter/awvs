#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"
if ! command -v sqlmap >/dev/null 2>&1; then
  echo "[ERROR] sqlmap was not found in PATH."
  echo "[HINT] Install sqlmap or add it to PATH, then rerun this script."
  exit 1
fi
echo "[INFO] SQLMap Hit Filter"
echo "[INFO] WorkDir: $(pwd)"
echo
python3 "13_filter_sqlmap_hits.py"
echo "[DONE] Filter finished, ExitCode=$?"
