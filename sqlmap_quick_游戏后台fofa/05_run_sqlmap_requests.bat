@echo off
setlocal enableextensions
title SQLMap Request Mode
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
echo [INFO] Request mode, 0 unique requests.
echo.
echo [DONE] Request mode finished, FailCount=%FAIL_COUNT%
pause
exit /b %FAIL_COUNT%
