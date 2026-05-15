@echo off
setlocal enableextensions
title SQLMap Baseline Collection Mode
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
echo [INFO] Baseline collection mode, 25 unique URLs.
sqlmap -m "08_sqlmap_urls_baseline.txt" --batch --random-agent --level 5 --risk 3 --drop-set-cookie --skip-static --results-file "sqlmap_collection_results.csv" --output-dir "sqlmap_output_baseline\collection"
set "RC=%ERRORLEVEL%"
echo.
echo [DONE] Baseline collection mode finished, ExitCode=%RC%
pause
exit /b %RC%
