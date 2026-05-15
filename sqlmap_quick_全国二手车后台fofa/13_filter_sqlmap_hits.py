import csv
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SUMMARY_CSV = ROOT / "00_vulnerability_summary.csv"
OUTPUT_TXT = ROOT / "15_sqlmap_hit_candidates.txt"
BOOLEAN_TXT = ROOT / "16_sqlmap_hit_boolean.txt"
ERROR_TXT = ROOT / "17_sqlmap_hit_error.txt"
TIME_TXT = ROOT / "18_sqlmap_hit_time.txt"
TECHNIQUE_NOTES_TXT = ROOT / "19_sqlmap_technique_notes.txt"
COLLECTION_CMD = (ROOT / "06_sqlmap_collection_command.txt").read_text(encoding="utf-8", errors="ignore").strip() if (ROOT / "06_sqlmap_collection_command.txt").exists() else ""
BASELINE_COLLECTION_CMD = (ROOT / "11_sqlmap_collection_baseline_command.txt").read_text(encoding="utf-8", errors="ignore").strip() if (ROOT / "11_sqlmap_collection_baseline_command.txt").exists() else ""


def file_has_content(path: Path) -> bool:
    if not path.exists() or not path.is_file():
        return False
    try:
        content = path.read_text(encoding="utf-8", errors="ignore").strip()
    except Exception:
        return False
    return bool(content)


def dir_has_signal(host_dir: Path) -> bool:
    log_path = host_dir / "log"
    if not file_has_content(log_path):
        return False
    try:
        lowered = log_path.read_text(encoding="utf-8", errors="ignore").lower()
    except Exception:
        return False
    success_keywords = [
        "identified the following injection point",
        "back-end dbms",
        "web application technology",
    ]
    return any(keyword in lowered for keyword in success_keywords)


def detect_techniques(host_dir: Path):
    log_path = host_dir / "log"
    try:
        lowered = log_path.read_text(encoding="utf-8", errors="ignore").lower()
    except Exception:
        return []
    techniques = []
    if "boolean-based" in lowered:
        techniques.append("boolean")
    if "error-based" in lowered:
        techniques.append("error")
    if "time-based" in lowered:
        techniques.append("time")
    return techniques


def load_summary_rows():
    rows = []
    if not SUMMARY_CSV.exists():
        return rows
    with SUMMARY_CSV.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        rows.extend(reader)
    return rows


def build_request_maps(rows):
    req_map = {}
    baseline_req_map = {}
    for row in rows:
        sqlmap_command = row.get("sqlmap_command") or ""
        baseline_sqlmap_command = row.get("baseline_sqlmap_command") or ""
        match = re.search(r'--output-dir\s+"([^"]+)"', sqlmap_command)
        if match:
            key = Path(match.group(1).replace("/", "\\")).name
            req_map[key] = row
        match = re.search(r'--output-dir\s+"([^"]+)"', baseline_sqlmap_command)
        if match:
            key = Path(match.group(1).replace("/", "\\")).name
            baseline_req_map[key] = row
    return req_map, baseline_req_map


def append_hit(lines, host, source, command):
    lines.append(str(host))
    lines.append(source)
    lines.append(command or "")
    lines.append("")


def append_hit_with_classification(all_lines, categorized, host, source, command, techniques):
    append_hit(all_lines, host, source, command)
    for tech in techniques:
        categorized.setdefault(tech, [])
        append_hit(categorized[tech], host, source, command)


def scan_request_side(root_name, request_map, command_field, source_name, all_lines, categorized):
    output_root = ROOT / root_name
    if not output_root.exists():
        return
    for bundle_dir in sorted(output_root.iterdir()):
        if not bundle_dir.is_dir():
            continue
        row = request_map.get(bundle_dir.name)
        if not row:
            continue
        for host_dir in sorted(bundle_dir.iterdir()):
            if not host_dir.is_dir():
                continue
            if dir_has_signal(host_dir):
                techniques = detect_techniques(host_dir)
                append_hit_with_classification(all_lines, categorized, host_dir.name, source_name, row.get(command_field, ""), techniques)


def scan_collection_side(root_name, source_name, command_text, all_lines, categorized):
    output_root = ROOT / root_name
    if not output_root.exists():
        return
    for host_dir in sorted(output_root.iterdir()):
        if not host_dir.is_dir():
            continue
        if dir_has_signal(host_dir):
            techniques = detect_techniques(host_dir)
            append_hit_with_classification(all_lines, categorized, host_dir.name, source_name, command_text, techniques)


def write_text(path: Path, lines):
    path.write_text("\n".join(lines).rstrip() + ("\n" if lines else ""), encoding="utf-8")


def main():
    rows = load_summary_rows()
    req_map, baseline_req_map = build_request_maps(rows)
    all_lines = []
    categorized = {}
    scan_request_side("sqlmap_output", req_map, "sqlmap_command", "request", all_lines, categorized)
    scan_request_side("sqlmap_output_baseline", baseline_req_map, "baseline_sqlmap_command", "request-baseline", all_lines, categorized)
    scan_collection_side("sqlmap_output_collection", "collection", COLLECTION_CMD, all_lines, categorized)
    scan_collection_side(os.path.join("sqlmap_output_baseline", "collection"), "collection-baseline", BASELINE_COLLECTION_CMD, all_lines, categorized)
    write_text(OUTPUT_TXT, all_lines)
    write_text(BOOLEAN_TXT, categorized.get("boolean", []))
    write_text(ERROR_TXT, categorized.get("error", []))
    write_text(TIME_TXT, categorized.get("time", []))
    notes = [
        "技术分类说明",
        "",
        "boolean: 布尔/逻辑盲注。通过真假条件让页面表现不同，再据此判断注入是否成立。",
        "error: 报错注入。通过数据库报错信息直接回显数据、结构或可控表达式结果。",
        "time: 时间盲注。通过 sleep/延时函数观察响应时间变化来判断真假。",
        "",
        "来源说明",
        "",
        "request: 原始 request 模式跑出来的结果。",
        "request-baseline: 基线值 request 模式跑出来的结果。",
        "collection: URL collection 模式跑出来的结果。",
        "collection-baseline: 基线值 URL collection 模式跑出来的结果。",
    ]
    write_text(TECHNIQUE_NOTES_TXT, notes)
    print(f"[DONE] wrote {OUTPUT_TXT}")
    print(f"[DONE] wrote {BOOLEAN_TXT}")
    print(f"[DONE] wrote {ERROR_TXT}")
    print(f"[DONE] wrote {TIME_TXT}")
    print(f"[DONE] wrote {TECHNIQUE_NOTES_TXT}")


if __name__ == "__main__":
    main()
