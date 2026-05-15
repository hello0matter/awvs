group_name=论文辅导
group_id=8fcf0ae7-e0dc-40e7-8b04-e42cf68e714a
severity_filter=critical
status_filter=open
sqlmap_proxy_mode=inherit-precheck
sqlmap_proxy=-
sqlmap_force_ssl=auto
sqlmap_force_ssl_note=auto adds --force-ssl for HTTPS request-mode exports; HTTP requests stay unchanged
sqlmap_check_cache=D:\tmp\anjian\pj\st\tmp\tmp\awvs\_awvs_precheck_cache
precheck_sources=25
collection_proxy=-
total_vulnerabilities=34
sql_injection_count=31
direct_exploitable_count=31
auto_string_count=10
auto_not_string_count=0

Start here:
  double-click 00_START_HERE.bat

Files:
  00_START_HERE.bat              interactive Windows menu
  00_vulnerability_summary.csv   all findings in scope
  01_direct_exploitable.csv      findings suitable for direct follow-up
  02_manual_review.csv           findings that should be reviewed manually
  03_sqlmap_urls.txt             original URLs for sqlmap -m
  04_run_sqlmap_collection.bat   collection mode, single sqlmap -m run
  05_run_sqlmap_requests.bat     secondary request mode, one normalized request at a time
  06_sqlmap_collection_command.txt  collection command in plain text
  07_sqlmap_request_commands.txt    request commands in plain text
  sqlmap_requests\*.txt         one normalized raw request per SQLi (no * replacement)
  08_sqlmap_urls_baseline.txt    baseline URLs for sqlmap -m
  09_run_sqlmap_collection_baseline.bat  baseline collection mode
  10_run_sqlmap_requests_baseline.bat    recommended baseline request mode
  11_sqlmap_collection_baseline_command.txt baseline collection command
  12_sqlmap_request_baseline_commands.txt baseline request commands
  sqlmap_requests_baseline\*.txt baseline raw requests
  sqlmap_output_baseline\       baseline output root
  13_filter_sqlmap_hits.py      filter script for non-empty sqlmap log files
  14_run_filter_sqlmap_hits.bat run the filter script
  15_sqlmap_hit_candidates.txt  filtered candidates: host / source / command
  16_sqlmap_request_commands_powershell.txt  secondary PowerShell request commands
  17_sqlmap_request_commands_cmd.txt         secondary CMD request commands
  18_sqlmap_request_baseline_commands_powershell.txt  recommended PowerShell baseline commands
  19_sqlmap_request_baseline_commands_cmd.txt         recommended CMD baseline commands
  20_sqlmap_string_hint.txt          boolean SQLi --string/--not-string guidance
  21_sqlmap_followup_commands_powershell.txt  follow-up enumeration commands
  22_sqlmap_followup_commands_cmd.txt         CMD follow-up enumeration commands
  linux\                    Linux runnable copy with .sh scripts and '/' paths

Suggested usage:
  double-click 09_run_sqlmap_collection_baseline.bat
  double-click 10_run_sqlmap_requests_baseline.bat
  double-click 05_run_sqlmap_requests.bat
  double-click 04_run_sqlmap_collection.bat
  double-click 14_run_filter_sqlmap_hits.bat
  prefer 2 first; use 1 when baseline is noisy or unavailable
  use 21/22 after sqlmap confirms injection and you know the DB name
  use 20 when sqlmap needs a stable TRUE/FALSE discriminator
  use --tables for table listing; -T needs a table name
