@echo off
setlocal enableextensions
title SQLMap Hit Filter
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
python "13_filter_sqlmap_hits.py"
set "RC=%ERRORLEVEL%"
echo.
echo [DONE] Filter finished, ExitCode=%RC%
pause
exit /b %RC%
