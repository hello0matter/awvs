@echo off
setlocal enableextensions
chcp 65001 >nul
title SQLMap Quick Wizard
pushd "%~dp0"
:MENU
cls
type "00_MENU.txt"
echo.
set /p CHOICE=Choose: 
if "%CHOICE%"=="1" call "05_run_sqlmap_requests.bat" & goto MENU
if "%CHOICE%"=="2" call "10_run_sqlmap_requests_baseline.bat" & goto MENU
if "%CHOICE%"=="3" call "04_run_sqlmap_collection.bat" & goto MENU
if "%CHOICE%"=="4" call "09_run_sqlmap_collection_baseline.bat" & goto MENU
if "%CHOICE%"=="5" call "14_run_filter_sqlmap_hits.bat" & goto MENU
if "%CHOICE%"=="6" type "16_sqlmap_request_commands_powershell.txt" & echo. & pause & goto MENU
if "%CHOICE%"=="7" type "17_sqlmap_request_commands_cmd.txt" & echo. & pause & goto MENU
if "%CHOICE%"=="8" type "20_sqlmap_string_hint.txt" & echo. & pause & goto MENU
if "%CHOICE%"=="9" type "21_sqlmap_followup_commands_powershell.txt" & echo. & pause & goto MENU
if "%CHOICE%"=="10" type "README.txt" & echo. & pause & goto MENU
if "%CHOICE%"=="0" exit /b 0
echo Invalid choice.
pause
goto MENU
