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
echo [INFO] Request mode, 15 unique requests.
echo.
echo [RUN 1/15] sqlmap -r "sqlmap_requests\001_SQL_Injection_sort_3883645565363291921.txt" --batch --smart --random-agent --output-dir "sqlmap_output\001_3883645565363291921" -p "sort"
sqlmap -r "sqlmap_requests\001_SQL_Injection_sort_3883645565363291921.txt" --batch --smart --random-agent --output-dir "sqlmap_output\001_3883645565363291921" -p "sort"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 2/15] sqlmap -r "sqlmap_requests\002_SQL_Injection_order_id_3883650099934397475.txt" --batch --smart --random-agent --output-dir "sqlmap_output\002_3883650099934397475" -p "order_id"
sqlmap -r "sqlmap_requests\002_SQL_Injection_order_id_3883650099934397475.txt" --batch --smart --random-agent --output-dir "sqlmap_output\002_3883650099934397475" -p "order_id"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 3/15] sqlmap -r "sqlmap_requests\003_SQL_Injection_email_3883698983062734454.txt" --batch --smart --random-agent --output-dir "sqlmap_output\003_3883698983062734454" -p "email"
sqlmap -r "sqlmap_requests\003_SQL_Injection_email_3883698983062734454.txt" --batch --smart --random-agent --output-dir "sqlmap_output\003_3883698983062734454" -p "email"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 4/15] sqlmap -r "sqlmap_requests\004_SQL_Injection_ispersis_3883698983188563577.txt" --batch --smart --random-agent --output-dir "sqlmap_output\004_3883698983188563577" -p "ispersis"
sqlmap -r "sqlmap_requests\004_SQL_Injection_ispersis_3883698983188563577.txt" --batch --smart --random-agent --output-dir "sqlmap_output\004_3883698983188563577" -p "ispersis"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 5/15] sqlmap -r "sqlmap_requests\005_SQL_Injection_mail_code_3883698983373112956.txt" --batch --smart --random-agent --output-dir "sqlmap_output\005_3883698983373112956" -p "mail_code"
sqlmap -r "sqlmap_requests\005_SQL_Injection_mail_code_3883698983373112956.txt" --batch --smart --random-agent --output-dir "sqlmap_output\005_3883698983373112956" -p "mail_code"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 6/15] sqlmap -r "sqlmap_requests\006_SQL_Injection_paynumber_3883883625518729183.txt" --batch --smart --random-agent --output-dir "sqlmap_output\006_3883883625518729183" -p "paynumber"
sqlmap -r "sqlmap_requests\006_SQL_Injection_paynumber_3883883625518729183.txt" --batch --smart --random-agent --output-dir "sqlmap_output\006_3883883625518729183" -p "paynumber"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 7/15] sqlmap -r "sqlmap_requests\007_SQL_Injection_path_3884135652538714102.txt" --batch --smart --random-agent --output-dir "sqlmap_output\007_3884135652538714102"
sqlmap -r "sqlmap_requests\007_SQL_Injection_path_3884135652538714102.txt" --batch --smart --random-agent --output-dir "sqlmap_output\007_3884135652538714102"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 8/15] sqlmap -r "sqlmap_requests\008_SQL_Injection_log_id_3884137629314188306.txt" --batch --smart --random-agent --output-dir "sqlmap_output\008_3884137629314188306" -p "log_id"
sqlmap -r "sqlmap_requests\008_SQL_Injection_log_id_3884137629314188306.txt" --batch --smart --random-agent --output-dir "sqlmap_output\008_3884137629314188306" -p "log_id"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 9/15] sqlmap -r "sqlmap_requests\009_SQL_Injection_log_id_3884146621516088726.txt" --batch --smart --random-agent --output-dir "sqlmap_output\009_3884146621516088726" -p "log_id"
sqlmap -r "sqlmap_requests\009_SQL_Injection_log_id_3884146621516088726.txt" --batch --smart --random-agent --output-dir "sqlmap_output\009_3884146621516088726" -p "log_id"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 10/15] sqlmap -r "sqlmap_requests\010_SQL_Injection_author_3884149438041556404.txt" --batch --smart --random-agent --output-dir "sqlmap_output\010_3884149438041556404" -p "author"
sqlmap -r "sqlmap_requests\010_SQL_Injection_author_3884149438041556404.txt" --batch --smart --random-agent --output-dir "sqlmap_output\010_3884149438041556404" -p "author"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 11/15] sqlmap -r "sqlmap_requests\011_SQL_Injection_keyword_3884149438133831095.txt" --batch --smart --random-agent --output-dir "sqlmap_output\011_3884149438133831095" -p "keyword"
sqlmap -r "sqlmap_requests\011_SQL_Injection_keyword_3884149438133831095.txt" --batch --smart --random-agent --output-dir "sqlmap_output\011_3884149438133831095" -p "keyword"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 12/15] sqlmap -r "sqlmap_requests\012_SQL_Injection_type_3884149438293214650.txt" --batch --smart --random-agent --output-dir "sqlmap_output\012_3884149438293214650" -p "type"
sqlmap -r "sqlmap_requests\012_SQL_Injection_type_3884149438293214650.txt" --batch --smart --random-agent --output-dir "sqlmap_output\012_3884149438293214650" -p "type"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 13/15] sqlmap -r "sqlmap_requests\013_SQL_Injection_page_3884290611896911055.txt" --batch --smart --random-agent --output-dir "sqlmap_output\013_3884290611896911055" -p "page"
sqlmap -r "sqlmap_requests\013_SQL_Injection_page_3884290611896911055.txt" --batch --smart --random-agent --output-dir "sqlmap_output\013_3884290611896911055" -p "page"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 14/15] sqlmap -r "sqlmap_requests\014_SQL_Injection_page_3884372510942168483.txt" --batch --smart --random-agent --output-dir "sqlmap_output\014_3884372510942168483" -p "page"
sqlmap -r "sqlmap_requests\014_SQL_Injection_page_3884372510942168483.txt" --batch --smart --random-agent --output-dir "sqlmap_output\014_3884372510942168483" -p "page"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 15/15] sqlmap -r "sqlmap_requests\015_SQL_Injection_page_3884374429802694164.txt" --batch --smart --random-agent --output-dir "sqlmap_output\015_3884374429802694164" -p "page"
sqlmap -r "sqlmap_requests\015_SQL_Injection_page_3884374429802694164.txt" --batch --smart --random-agent --output-dir "sqlmap_output\015_3884374429802694164" -p "page"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [DONE] Request mode finished, FailCount=%FAIL_COUNT%
pause
exit /b %FAIL_COUNT%
