group_name=全国发卡后台fofa
group_id=3f4773c3-fdb4-4a39-b3e2-b742f97abb69
severity_filter=critical
status_filter=open
sqlmap_proxy_mode=inherit-precheck
sqlmap_proxy=-
sqlmap_force_ssl=off
sqlmap_check_cache=D:\tmp\anjian\pj\st\tmp\tmp\awvs\_awvs_precheck_cache
precheck_sources=0
collection_proxy=-
total_vulnerabilities=24
sql_injection_count=15
direct_exploitable_count=15

Files:
  00_vulnerability_summary.csv   all findings in scope
  01_direct_exploitable.csv      findings suitable for direct follow-up
  02_manual_review.csv           findings that should be reviewed manually
  03_sqlmap_urls.txt             original URLs for sqlmap -m
  04_run_sqlmap_collection.bat   collection mode, single sqlmap -m run
  05_run_sqlmap_requests.bat     request mode, one normalized request at a time
  06_sqlmap_collection_command.txt  collection command in plain text
  07_sqlmap_request_commands.txt    request commands in plain text
  sqlmap_requests\*.txt         one normalized raw request per SQLi (no * replacement)
  08_sqlmap_urls_baseline.txt    baseline URLs for sqlmap -m
  09_run_sqlmap_collection_baseline.bat  baseline collection mode
  10_run_sqlmap_requests_baseline.bat    baseline request mode
  11_sqlmap_collection_baseline_command.txt baseline collection command
  12_sqlmap_request_baseline_commands.txt baseline request commands
  sqlmap_requests_baseline\*.txt baseline raw requests
  sqlmap_output_baseline\       baseline output root
  13_filter_sqlmap_hits.py      filter script for non-empty sqlmap log files
  14_run_filter_sqlmap_hits.bat run the filter script
  15_sqlmap_hit_candidates.txt  filtered candidates: host / source / command

Suggested usage:
  double-click 04_run_sqlmap_collection.bat
  double-click 05_run_sqlmap_requests.bat
  double-click 09_run_sqlmap_collection_baseline.bat
  double-click 10_run_sqlmap_requests_baseline.bat
  double-click 14_run_filter_sqlmap_hits.bat
