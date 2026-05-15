@echo off
setlocal enableextensions
title SQLMap Baseline Request Mode
pushd "%~dp0"
where sqlmap >nul 2>&1
if errorlevel 1 (
  echo [ERROR] sqlmap was not found in PATH.
  echo [HINT] Confirm sqlmap can run directly in cmd.exe.
  pause
  exit /b 1
)
echo [INFO] WorkDir: %CD%
echo.
set "FAIL_COUNT=0"
echo [INFO] Baseline request mode, 1 unique requests.
echo.
echo [RUN 1/1] sqlmap -r "sqlmap_requests_baseline\001_sql_injection_tid_3888037214562551033.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output_baseline\001_3888037214562551033" --force-ssl -p "tid" --technique=B
sqlmap -r "sqlmap_requests_baseline\001_sql_injection_tid_3888037214562551033.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output_baseline\001_3888037214562551033" --force-ssl -p "tid" --technique=B
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [DONE] Baseline request mode finished, FailCount=%FAIL_COUNT%
pause
exit /b %FAIL_COUNT%
