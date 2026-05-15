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
echo [INFO] Request mode, 1 unique requests.
echo.
echo [RUN 1/1] sqlmap -r "sqlmap_requests\001_SQL_Injection_tid_3888037214562551033.txt" --batch --smart --random-agent --output-dir "sqlmap_output\001_3888037214562551033" --force-ssl -p "tid"
sqlmap -r "sqlmap_requests\001_SQL_Injection_tid_3888037214562551033.txt" --batch --smart --random-agent --output-dir "sqlmap_output\001_3888037214562551033" --force-ssl -p "tid"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [DONE] Request mode finished, FailCount=%FAIL_COUNT%
pause
exit /b %FAIL_COUNT%
