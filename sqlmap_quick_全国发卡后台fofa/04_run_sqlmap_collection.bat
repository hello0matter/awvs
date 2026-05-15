@echo off
setlocal enableextensions
title SQLMap Collection Mode
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
echo [INFO] Collection mode, 15 unique URLs.
sqlmap -m "03_sqlmap_urls.txt" --batch --smart --random-agent --results-file "sqlmap_collection_results.csv" --output-dir "sqlmap_output_collection"
set "RC=%ERRORLEVEL%"
echo.
echo [DONE] Collection mode finished, ExitCode=%RC%
pause
exit /b %RC%
