group_name=预约按摩fofa
group_id=27b1809f-97eb-495a-8133-7a778d2af94a
severity_filter=critical
status_filter=open
sqlmap_proxy_mode=inherit-precheck
sqlmap_proxy=-
sqlmap_force_ssl=off
sqlmap_check_cache=D:\tmp\anjian\pj\st\tmp\tmp\awvs\_awvs_precheck_cache
precheck_sources=0
collection_proxy=-
total_vulnerabilities=0
sql_injection_count=0
direct_exploitable_count=0

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

Suggested usage:
  double-click 04_run_sqlmap_collection.bat
  double-click 05_run_sqlmap_requests.bat
