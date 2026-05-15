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
echo [INFO] Baseline request mode, 16 unique requests.
echo.
echo [RUN 1/16] sqlmap -r "sqlmap_requests_baseline\001_SQL_Injection_q_3883157333253031595.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\001_3883157333253031595" -p "q"
sqlmap -r "sqlmap_requests_baseline\001_SQL_Injection_q_3883157333253031595.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\001_3883157333253031595" -p "q"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 2/16] sqlmap -r "sqlmap_requests_baseline\002_SQL_Injection_scene_3883157333370472110.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\002_3883157333370472110" -p "scene"
sqlmap -r "sqlmap_requests_baseline\002_SQL_Injection_scene_3883157333370472110.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\002_3883157333370472110" -p "scene"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 3/16] sqlmap -r "sqlmap_requests_baseline\003_SQL_Injection_s_s_[_]_3883163174542771913.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\003_3883163174542771913" -p "/<s>/<s>/[*]"
sqlmap -r "sqlmap_requests_baseline\003_SQL_Injection_s_s_[_]_3883163174542771913.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\003_3883163174542771913" -p "/<s>/<s>/[*]"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 4/16] sqlmap -r "sqlmap_requests_baseline\004_SQL_Injection_good_3883164188171830991.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\004_3883164188171830991" -p "good"
sqlmap -r "sqlmap_requests_baseline\004_SQL_Injection_good_3883164188171830991.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\004_3883164188171830991" -p "good"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 5/16] sqlmap -r "sqlmap_requests_baseline\005_SQL_Injection_data_d_3883165606534448850.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\005_3883165606534448850" -p "data_d"
sqlmap -r "sqlmap_requests_baseline\005_SQL_Injection_data_d_3883165606534448850.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\005_3883165606534448850" -p "data_d"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 6/16] sqlmap -r "sqlmap_requests_baseline\006_SQL_Injection_bh_3883167794493130465.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\006_3883167794493130465" -p "bh"
sqlmap -r "sqlmap_requests_baseline\006_SQL_Injection_bh_3883167794493130465.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\006_3883167794493130465" -p "bh"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 7/16] sqlmap -r "sqlmap_requests_baseline\007_SQL_Injection_filter_3883167794660902628.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\007_3883167794660902628" -p "filter"
sqlmap -r "sqlmap_requests_baseline\007_SQL_Injection_filter_3883167794660902628.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\007_3883167794660902628" -p "filter"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 8/16] sqlmap -r "sqlmap_requests_baseline\008_SQL_Injection_s_[_]_s_s_s_3883176859667531549.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\008_3883176859667531549" -p "/<s>/[*]/<s>/<s>/<s>"
sqlmap -r "sqlmap_requests_baseline\008_SQL_Injection_s_[_]_s_s_s_3883176859667531549.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\008_3883176859667531549" -p "/<s>/[*]/<s>/<s>/<s>"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 9/16] sqlmap -r "sqlmap_requests_baseline\009_SQL_Injection_{GENERIC}_3883540746938091449.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\009_3883540746938091449" -p "{GENERIC}"
sqlmap -r "sqlmap_requests_baseline\009_SQL_Injection_{GENERIC}_3883540746938091449.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\009_3883540746938091449" -p "{GENERIC}"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 10/16] sqlmap -r "sqlmap_requests_baseline\010_SQL_Injection_{GENERIC}_3883541567813715917.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\010_3883541567813715917" -p "{GENERIC}"
sqlmap -r "sqlmap_requests_baseline\010_SQL_Injection_{GENERIC}_3883541567813715917.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\010_3883541567813715917" -p "{GENERIC}"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 11/16] sqlmap -r "sqlmap_requests_baseline\011_SQL_Injection_{GENERIC}_3883543136944785404.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\011_3883543136944785404" -p "{GENERIC}"
sqlmap -r "sqlmap_requests_baseline\011_SQL_Injection_{GENERIC}_3883543136944785404.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\011_3883543136944785404" -p "{GENERIC}"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 12/16] sqlmap -r "sqlmap_requests_baseline\012_SQL_Injection_{GENERIC}_3883543277940507653.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\012_3883543277940507653" -p "{GENERIC}"
sqlmap -r "sqlmap_requests_baseline\012_SQL_Injection_{GENERIC}_3883543277940507653.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\012_3883543277940507653" -p "{GENERIC}"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 13/16] sqlmap -r "sqlmap_requests_baseline\013_SQL_Injection_s_[_]_3883544415016322098.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\013_3883544415016322098" -p "/<s>/[*]"
sqlmap -r "sqlmap_requests_baseline\013_SQL_Injection_s_[_]_3883544415016322098.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\013_3883544415016322098" -p "/<s>/[*]"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 14/16] sqlmap -r "sqlmap_requests_baseline\014_SQL_Injection_s_[_]_3885468190293100424.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\014_3885468190293100424" -p "/<s>/[*]"
sqlmap -r "sqlmap_requests_baseline\014_SQL_Injection_s_[_]_3885468190293100424.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\014_3885468190293100424" -p "/<s>/[*]"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 15/16] sqlmap -r "sqlmap_requests_baseline\015_SQL_Injection_keyword_3885515566584170300.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\015_3885515566584170300" -p "keyword"
sqlmap -r "sqlmap_requests_baseline\015_SQL_Injection_keyword_3885515566584170300.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\015_3885515566584170300" -p "keyword"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 16/16] sqlmap -r "sqlmap_requests_baseline\016_SQL_Injection_path_3885561309093168626.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\016_3885561309093168626"
sqlmap -r "sqlmap_requests_baseline\016_SQL_Injection_path_3885561309093168626.txt" --batch --smart --random-agent --output-dir "sqlmap_output_baseline\016_3885561309093168626"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [DONE] Baseline request mode finished, FailCount=%FAIL_COUNT%
pause
exit /b %FAIL_COUNT%
