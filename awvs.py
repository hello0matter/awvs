import argparse
import csv
import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import warnings
from collections import deque
from datetime import datetime
from html import unescape
from urllib.parse import urlparse, urlsplit, urlunsplit

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

warnings.filterwarnings("ignore", message="urllib3 .* doesn't match a supported version!")

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_API_KEY = "1986ad8c0a5b3df4d7028d5f3c06e936cb4217b974a8b4f40b1086d31d7e8869e"
DEFAULT_BASE_URL = "https://localhost:3443/api/v1"
DEFAULT_PROFILE_ID = "12"
LOCAL_CONFIG_FILENAME = "awvs.local.json"
TOOL_VERSION = "2026.05.05-sqlmap-followup"
SQLMAP_DEFAULT_THREADS = 5
DEFAULT_WEAK_LOGIN_USERNAME = "admin"
DEFAULT_WEAK_LOGIN_PASSWORD = "123456"
ACTIVE_STATUSES = {"processing", "starting", "queued"}
RUNNING_ONLY_STATUSES = {"processing", "starting"}
FINISHED_STATUSES = {"completed", "aborted", "failed"}
RETRYABLE_ERROR_KEYWORDS = (
    "concurrent",
    "limit",
    "queue",
    "worker",
    "busy",
    "engine",
    "temporary",
    "timeout",
    "503",
    "502",
    "500",
    "429",
)
COMMON_HTTPS_PORTS = {443, 444, 563, 636, 651, 832, 843, 844, 853, 989, 990, 992, 993, 994, 995, 1443, 2443, 3333, 3443, 4433, 4443, 5443, 6443, 7443, 8443, 9443, 10443}
COMMON_HTTP_PORTS = {80, 81, 88, 631, 3000, 3128, 5080, 5601, 6080, 7001, 7002, 7070, 7080, 7088, 8000, 8001, 8008, 8010, 8080, 8081, 8082, 8088, 8090, 8091, 8180, 8181, 8200, 8800, 8880, 8888, 8889, 9000, 9001, 9043, 9060, 9080, 9090, 9091, 9099}
HOST_PORT_RE = re.compile(r"^(?P<host>[A-Za-z0-9._-]+):(?P<port>\d{1,5})$")
HOST_RE = re.compile(r"^(?=.{1,253}\.?$)[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?)*\.?$")
PROFILE_ID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
ROUTE_POLICIES = {"auto", "direct", "http-proxy"}
DEFAULT_SCAN_HTTP_PROXY = ""
DEFAULT_SCAN_HTTP_PROXY_VALUE = "127.0.0.1:7890"
DEFAULT_PRECHECK_SOCKS5 = ""
PRECHECK_CSV_HEADERS = [
    "url",
    "description",
    "selected_route",
    "selected_reason",
    "risk_level",
    "risk_tag",
    "direct_ok",
    "http_proxy_ok",
    "socks5_ok",
    "http_attempts",
    "details",
]
SEVERITY_NAME_TO_VALUE = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
SEVERITY_VALUE_TO_NAME = {value: key for key, value in SEVERITY_NAME_TO_VALUE.items()}
SQLMAP_REQUEST_DROP_HEADERS = {
    "accept-encoding",
    "connection",
    "content-encoding",
    "content-length",
    "transfer-encoding",
}
DIRECT_EXPLOIT_KEYWORDS = {
    "SQL Injection": ("sql injection", "sql_injection"),
    "Command Execution": ("command execution", "os command injection", "code execution", "remote code execution"),
    "File Read": ("path traversal", "arbitrary file read", "local file inclusion", "file inclusion"),
    "File Write": ("arbitrary file upload", "arbitrary file write"),
    "SSRF": ("server side request forgery", "ssrf"),
    "XXE": ("xml external entity", "xxe"),
    "SSTI": ("server side template injection", "template injection"),
    "Deserialization": ("deserialization", "object injection"),
    "Auth Bypass": ("authentication bypass", "authorization bypass"),
}
GROUP_SYNC_ATTEMPTS = 5
GROUP_SYNC_DELAY_SECONDS = 2.0

task_tracker = {}
def setup_logger(log_path, verbose=False):
    os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
    logger = logging.getLogger("awvs_scheduler")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False

    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger
def write_dict_csv(path, fieldnames, rows):
    with open(path, "w", encoding="utf-8-sig", newline="") as file_obj:
        writer = csv.DictWriter(file_obj, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def normalize_address(address):
    return address.strip().lstrip("\ufeff").rstrip("/")


def format_duration_compact(seconds):
    seconds = max(0, int(seconds))
    minutes, sec = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours > 0:
        return f"{hours}h{minutes:02d}m{sec:02d}s"
    if minutes > 0:
        return f"{minutes}m{sec:02d}s"
    return f"{sec}s"


def build_progress_snapshot(index, total, started_at):
    total = max(total, 1)
    index = max(0, min(index, total))
    percent = (index / total) * 100
    elapsed_seconds = max(0.0, time.time() - started_at)
    avg_seconds = (elapsed_seconds / index) if index > 0 else 0.0
    remaining_seconds = avg_seconds * max(0, total - index)
    return {
        "index": index,
        "total": total,
        "percent": percent,
        "elapsed_text": format_duration_compact(elapsed_seconds),
        "avg_text": format_duration_compact(avg_seconds),
        "eta_text": format_duration_compact(remaining_seconds),
    }


def chunked(items, size):
    for index in range(0, len(items), size):
        yield items[index : index + size]


def looks_like_ip_or_hostport(value):
    if not value:
        return False

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass

    return bool(HOST_PORT_RE.match(value))


def looks_like_host(value):
    if not value:
        return False

    host = value.strip().strip("[]").rstrip(".")
    if not host or "/" in host or "\\" in host or " " in host:
        return False

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    return bool(HOST_RE.match(host)) and ("." in host or host.lower() == "localhost")


def infer_scheme_from_port(port, default_scheme):
    if default_scheme in {"http", "https"}:
        return default_scheme
    if port in COMMON_HTTPS_PORTS:
        return "https"
    if port in COMMON_HTTP_PORTS:
        return "http"
    return "https"


def split_host_port(value):
    value = (value or "").strip()
    match = HOST_PORT_RE.match(value)
    if match:
        return match.group("host"), int(match.group("port"))
    return value, None


def build_url_for_host(value, scheme, default_scheme="auto"):
    host, port = split_host_port(value)
    if port is not None and not 1 <= port <= 65535:
        return None
    if port is not None:
        selected_scheme = scheme or infer_scheme_from_port(port, default_scheme)
        return f"{selected_scheme}://{host}:{port}"
    selected_scheme = scheme or ("https" if default_scheme == "auto" else default_scheme)
    return f"{selected_scheme}://{host}"


def normalize_input_target(raw_value, default_scheme):
    value = normalize_address(raw_value)
    if not value:
        return None, "empty"

    lowered = value.lower()
    if lowered in {"url", "urls", "target", "targets", "address", "domain", "host"}:
        return None, "header"

    if value.startswith(("http://", "https://")):
        return value, None

    match = HOST_PORT_RE.match(value)
    if match:
        port = int(match.group("port"))
        if not 1 <= port <= 65535:
            return None, "invalid_port"
        scheme = infer_scheme_from_port(port, default_scheme)
        return f"{scheme}://{value}", None

    try:
        ipaddress.ip_address(value)
        scheme = "https" if default_scheme == "auto" else default_scheme
        return f"{scheme}://{value}", None
    except ValueError:
        pass

    if looks_like_host(value):
        return build_url_for_host(value, None, default_scheme), None

    return None, "unsupported"


def parse_proxy_endpoint(proxy_value):
    if not proxy_value:
        return None

    value = proxy_value.strip()
    if "://" in value:
        parsed = urlparse(value)
        host = parsed.hostname
        port = parsed.port
    else:
        if ":" not in value:
            raise RuntimeError(f"代理地址格式无效: {proxy_value}")
        host, port_text = value.rsplit(":", 1)
        host = host.strip()
        port = int(port_text)

    if not host or not port:
        raise RuntimeError(f"代理地址格式无效: {proxy_value}")
    return {"host": host, "port": int(port), "raw": proxy_value}


def parse_target_endpoint(address):
    parsed = urlparse(address)
    scheme = (parsed.scheme or "https").lower()
    host = parsed.hostname
    if not host:
        raise RuntimeError(f"目标地址无法解析: {address}")
    port = parsed.port or (443 if scheme == "https" else 80)
    return {"scheme": scheme, "host": host, "port": port, "address": address}


def build_default_description(input_path, line_no, address):
    base_name = os.path.splitext(os.path.basename(input_path))[0]
    return f"{base_name}-{line_no:04d} {address}"


def build_precheck_cache_root():
    return os.path.join(os.getcwd(), "_awvs_precheck_cache")


def build_precheck_cache_name(input_path, suffix="_precheck"):
    normalized = os.path.abspath(input_path).lower()
    digest = hashlib.sha1(normalized.encode("utf-8", errors="ignore")).hexdigest()[:10]
    base_name = safe_filename(os.path.splitext(os.path.basename(input_path))[0] or "targets", max_length=48)
    return f"{base_name}{suffix}_{digest}"


def build_default_precheck_dir(input_path, suffix="_precheck"):
    return os.path.join(build_precheck_cache_root(), build_precheck_cache_name(input_path, suffix=suffix))


def build_default_precheck_file(input_path):
    return os.path.join(build_default_precheck_dir(input_path), "00_全部结果.csv")


def parse_json_safe(response):
    try:
        return response.json()
    except ValueError:
        return {}


def format_response_error(response):
    data = parse_json_safe(response)
    pieces = [f"HTTP {response.status_code}"]

    for key in ("code", "reason", "message", "details"):
        value = data.get(key)
        if value:
            if isinstance(value, (dict, list)):
                value = json.dumps(value, ensure_ascii=False)
            pieces.append(str(value))

    if len(pieces) == 1:
        text = response.text.strip()
        pieces.append(text[:300] if text else "empty response")

    return " | ".join(pieces)


def is_retryable_error(message):
    lowered = (message or "").lower()
    return any(keyword in lowered for keyword in RETRYABLE_ERROR_KEYWORDS)


def resolve_local_config_path():
    return os.path.join(os.getcwd(), LOCAL_CONFIG_FILENAME)


def load_local_config():
    config_path = resolve_local_config_path()
    if not os.path.exists(config_path):
        return {}, config_path, None

    try:
        with open(config_path, "r", encoding="utf-8-sig") as file_obj:
            data = json.load(file_obj)
    except Exception as exc:
        return {}, config_path, f"读取本地配置失败: {exc}"

    if not isinstance(data, dict):
        return {}, config_path, "读取本地配置失败: 顶层结构不是 JSON 对象"
    return data, config_path, None


def apply_local_config(args):
    config, config_path, load_error = load_local_config()
    explicit = {
        "key": args.key is not None,
        "url": args.url is not None,
        "profile_id": args.profile_id is not None,
        "login_url": args.login_url is not None,
        "login_username": args.login_username is not None,
        "login_password": args.login_password is not None,
        "login_sequence": args.login_sequence is not None,
    }

    if args.key is None:
        args.key = config.get("key") or DEFAULT_API_KEY
    if args.url is None:
        args.url = config.get("url") or DEFAULT_BASE_URL
    if args.profile_id is None:
        args.profile_id = config.get("profile_id") or DEFAULT_PROFILE_ID
    if args.login_url is None:
        args.login_url = config.get("login_url") or ""
    if args.login_username is None:
        args.login_username = config.get("login_username") or ""
    if args.login_password is None:
        args.login_password = config.get("login_password") or ""
    if args.login_sequence is None:
        args.login_sequence = config.get("login_sequence") or ""

    return config, config_path, explicit, load_error


def save_local_config(current_config, config_path, args, explicit):
    updated = dict(current_config or {})
    changed = False

    if explicit.get("key") and args.key and updated.get("key") != args.key:
        updated["key"] = args.key
        changed = True
    if explicit.get("url") and args.url and updated.get("url") != args.url:
        updated["url"] = args.url
        changed = True
    if explicit.get("profile_id") and args.profile_id and updated.get("profile_id") != args.profile_id:
        updated["profile_id"] = args.profile_id
        changed = True
    if explicit.get("login_url") and updated.get("login_url") != (args.login_url or ""):
        updated["login_url"] = args.login_url or ""
        changed = True
    if explicit.get("login_username") and updated.get("login_username") != (args.login_username or ""):
        updated["login_username"] = args.login_username or ""
        changed = True
    if explicit.get("login_password") and updated.get("login_password") != (args.login_password or ""):
        updated["login_password"] = args.login_password or ""
        changed = True
    if explicit.get("login_sequence") and updated.get("login_sequence") != (args.login_sequence or ""):
        updated["login_sequence"] = args.login_sequence or ""
        changed = True

    if not changed:
        return False

    with open(config_path, "w", encoding="utf-8") as file_obj:
        json.dump(updated, file_obj, ensure_ascii=False, indent=2, sort_keys=True)
    if isinstance(current_config, dict):
        current_config.clear()
        current_config.update(updated)
    return True


def save_resolved_profile_id(current_config, config_path, resolved_profile_id):
    if not resolved_profile_id:
        return False

    updated = dict(current_config or {})
    if updated.get("profile_id") == resolved_profile_id:
        return False

    updated["profile_id"] = resolved_profile_id
    with open(config_path, "w", encoding="utf-8") as file_obj:
        json.dump(updated, file_obj, ensure_ascii=False, indent=2, sort_keys=True)
    if isinstance(current_config, dict):
        current_config.clear()
        current_config.update(updated)
    return True


class AwvsClient:
    def __init__(self, base_url, api_key, request_timeout):
        self.base_url = base_url.rstrip("/")
        self.request_timeout = request_timeout
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update(
            {
                "X-Auth": api_key,
                "Content-Type": "application/json",
            }
        )
        self.session.verify = False

        retry = Retry(
            total=3,
            connect=3,
            read=3,
            backoff_factor=1,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "HEAD", "OPTIONS"}),
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def request(self, method, path, **kwargs):
        url = f"{self.base_url}{path}"
        kwargs.setdefault("timeout", self.request_timeout)
        try:
            return self.session.request(method, url, **kwargs)
        except requests.RequestException as exc:
            raise RuntimeError(f"{method} {path} 请求失败: {exc}") from exc

    def iter_paginated(self, path, key, page_size=100):
        cursor = 0
        while True:
            response = self.request("GET", path, params={"l": page_size, "c": cursor})
            if response.status_code != 200:
                raise RuntimeError(f"{path} 拉取失败: {format_response_error(response)}")
            data = parse_json_safe(response)
            items = data.get(key, [])
            if not items:
                break
            for item in items:
                yield item
            if len(items) < page_size:
                break
            cursor += page_size

    def list_targets(self):
        return list(self.iter_paginated("/targets", "targets"))

    def list_scans(self):
        return list(self.iter_paginated("/scans", "scans"))

    def list_groups(self):
        return list(self.iter_paginated("/target_groups", "groups"))

    def iter_cursor_paginated(self, path, key, params=None, page_size=100):
        query_params = dict(params or {})
        query_params.setdefault("l", page_size)
        cursor = None
        seen_cursors = set()

        while True:
            request_params = dict(query_params)
            if cursor:
                request_params["c"] = cursor
            response = self.request("GET", path, params=request_params)
            if response.status_code != 200:
                raise RuntimeError(f"{path} pull failed: {format_response_error(response)}")
            data = parse_json_safe(response)
            items = data.get(key, [])
            if not items:
                break
            for item in items:
                yield item

            pagination = data.get("pagination") or {}
            cursors = pagination.get("cursors") or []
            next_cursor = cursors[1] if len(cursors) > 1 else None
            if not next_cursor or next_cursor in seen_cursors:
                break
            seen_cursors.add(next_cursor)
            cursor = next_cursor

    def list_profiles(self):
        response = self.request("GET", "/scanning_profiles")
        if response.status_code != 200:
            raise RuntimeError(f"/scanning_profiles 拉取失败: {format_response_error(response)}")
        data = parse_json_safe(response)
        for key in ("profiles", "scanning_profiles"):
            items = data.get(key)
            if isinstance(items, list):
                return items
        return []

    def get_profile(self, profile_ref):
        profiles = self.list_profiles()
        exact_id = next((p for p in profiles if p.get("profile_id") == profile_ref), None)
        if exact_id:
            return exact_id

        lowered = profile_ref.lower()
        exact_name = [p for p in profiles if (p.get("name") or "").lower() == lowered]
        if len(exact_name) == 1:
            return exact_name[0]
        if len(exact_name) > 1:
            raise RuntimeError(f"发现多个同名扫描方案: {profile_ref}，请改用 profile UUID")

        fuzzy_name = [p for p in profiles if lowered in (p.get("name") or "").lower()]
        if len(fuzzy_name) == 1:
            return fuzzy_name[0]
        if len(fuzzy_name) > 1:
            names = ", ".join(sorted({p.get('name') or '-' for p in fuzzy_name}))
            raise RuntimeError(f"扫描方案匹配到多个名称: {names}，请改用更精确的名称或 UUID")
        return None

    def create_target(self, address, description=""):
        payload = {
            "address": address,
            "description": description,
            "criticality": "10",
            "type": "default",
        }
        response = self.request("POST", "/targets", json=payload)
        if response.status_code not in (200, 201):
            return None, format_response_error(response)

        data = parse_json_safe(response)
        target_id = data.get("target_id")
        if not target_id:
            location = response.headers.get("Location", "")
            target_id = location.rstrip("/").split("/")[-1] if location else None
        if not target_id:
            return None, "创建成功但未返回 target_id"
        return target_id, None

    def create_targets_bulk(self, targets, group_ids=None):
        payload = {"targets": targets}
        if group_ids:
            payload["groups"] = group_ids
        response = self.request("POST", "/targets/add", json=payload)
        if response.status_code not in (200, 201, 204):
            return False, format_response_error(response)
        return True, None

    def update_target_address(self, target_id, address, description=None):
        payload = {"address": address}
        if description is not None:
            payload["description"] = description
        response = self.request("PATCH", f"/targets/{target_id}", json=payload)
        if response.status_code not in (200, 204):
            raise RuntimeError(f"更新 Target 地址失败: {format_response_error(response)}")

    def delete_target(self, target_id):
        response = self.request("DELETE", f"/targets/{target_id}")
        if response.status_code not in (200, 202, 204, 404):
            raise RuntimeError(f"删除 Target 失败: {format_response_error(response)}")

    def get_target_configuration(self, target_id):
        response = self.request("GET", f"/targets/{target_id}/configuration")
        if response.status_code != 200:
            raise RuntimeError(f"读取 Target 配置失败: {format_response_error(response)}")
        return parse_json_safe(response)

    def configure_target_proxy(self, target_id, enabled, proxy_host=None, proxy_port=None, username=None, password=None):
        configuration = self.get_target_configuration(target_id)
        if enabled:
            configuration["proxy"] = {
                "enabled": True,
                "protocol": "http",
                "address": proxy_host,
                "port": int(proxy_port),
                "username": username or "",
                "password": password or "",
            }
        else:
            # AWVS 在 disabled 状态下只接受 {"enabled": false}，
            # 继续携带空 address/port 会触发 configuration.proxy.address 格式校验。
            configuration["proxy"] = {"enabled": False}
        response = self.request("PATCH", f"/targets/{target_id}/configuration", json=configuration)
        if response.status_code not in (200, 204):
            raise RuntimeError(f"更新 Target 代理配置失败: {format_response_error(response)}")

    def configure_target_auto_login(self, target_id, login_url, username, password):
        configuration = self.get_target_configuration(target_id)
        login_config = configuration.get("login") or {}
        login_config["kind"] = "automatic"
        login_config["credentials"] = {
            "enabled": True,
            "url": login_url,
            "username": username,
            "password": password,
        }
        configuration["login"] = login_config
        response = self.request("PATCH", f"/targets/{target_id}/configuration", json=configuration)
        if response.status_code not in (200, 204):
            raise RuntimeError(f"更新 Target 自动登录配置失败: {format_response_error(response)}")

    def upload_target_login_sequence(self, target_id, lsr_path):
        file_size = os.path.getsize(lsr_path)
        descriptor = {
            "name": os.path.basename(lsr_path),
            "size": file_size,
        }
        response = self.request("POST", f"/targets/{target_id}/configuration/login_sequence", json=descriptor)
        if response.status_code != 200:
            raise RuntimeError(f"创建 Login Sequence 上传会话失败: {format_response_error(response)}")
        upload_url = (parse_json_safe(response) or {}).get("upload_url")
        if not upload_url:
            raise RuntimeError("创建 Login Sequence 上传会话失败: response missing upload_url")

        headers = {"Content-Type": "application/octet-stream"}
        with open(lsr_path, "rb") as file_obj:
            upload_response = self.session.post(upload_url, data=file_obj, headers=headers, timeout=self.request_timeout)
        if upload_response.status_code not in (200, 201, 204):
            raise RuntimeError(f"上传 Login Sequence 失败: {format_response_error(upload_response)}")

        configuration = self.get_target_configuration(target_id)
        login_config = configuration.get("login") or {}
        login_config["kind"] = "sequence"
        configuration["login"] = login_config
        apply_response = self.request("PATCH", f"/targets/{target_id}/configuration", json=configuration)
        if apply_response.status_code not in (200, 204):
            raise RuntimeError(f"启用 Login Sequence 失败: {format_response_error(apply_response)}")

    def start_scan(self, target_id, profile_id):
        payload = {
            "target_id": target_id,
            "profile_id": profile_id,
            "schedule": {"disable": False, "start_date": None, "time_sensitive": False},
        }
        response = self.request("POST", "/scans", json=payload)
        if response.status_code == 201:
            location = response.headers.get("Location", "")
            scan_id = location.rstrip("/").split("/")[-1] if location else None
            if scan_id:
                return scan_id, None
            data = parse_json_safe(response)
            return data.get("scan_id"), None
        return None, format_response_error(response)

    def abort_scan(self, scan_id):
        response = self.request("POST", f"/scans/{scan_id}/abort")
        return response.status_code in (200, 204)

    def get_group(self, group_ref):
        groups = self.list_groups()
        exact_id = next((g for g in groups if g.get("group_id") == group_ref), None)
        if exact_id:
            return exact_id

        lowered = group_ref.lower()
        exact_name = [g for g in groups if (g.get("name") or "").lower() == lowered]
        if len(exact_name) == 1:
            return exact_name[0]
        if len(exact_name) > 1:
            raise RuntimeError(f"发现多个同名分组: {group_ref}，请直接传 group_id")
        return None

    def create_group(self, group_name):
        payload = {"name": group_name, "description": f"Created by awvs.py at {datetime.now():%F %T}"}
        response = self.request("POST", "/target_groups", json=payload)
        if response.status_code not in (200, 201):
            raise RuntimeError(f"创建分组失败: {format_response_error(response)}")
        data = parse_json_safe(response)
        group_id = data.get("group_id")
        if not group_id:
            location = response.headers.get("Location", "")
            group_id = location.rstrip("/").split("/")[-1] if location else None
        if not group_id:
            raise RuntimeError("分组创建成功但未返回 group_id")
        return {"group_id": group_id, "name": group_name}

    def list_group_target_ids(self, group_id):
        response = self.request("GET", f"/target_groups/{group_id}/targets")
        if response.status_code != 200:
            raise RuntimeError(f"读取分组目标失败: {format_response_error(response)}")
        data = parse_json_safe(response)
        target_ids = data.get("target_id_list")
        if isinstance(target_ids, list):
            return target_ids

        targets = data.get("targets")
        if isinstance(targets, list):
            return [item.get("target_id") for item in targets if item.get("target_id")]
        return []

    def add_targets_to_group(self, group_id, target_ids):
        if not target_ids:
            return
        seen = set()
        deduped_target_ids = []
        for target_id in target_ids:
            if target_id and target_id not in seen:
                seen.add(target_id)
                deduped_target_ids.append(target_id)

        existing_target_ids = set(self.list_group_target_ids(group_id))
        pending_target_ids = [target_id for target_id in deduped_target_ids if target_id not in existing_target_ids]
        if not pending_target_ids:
            return

        failures = []
        for index in range(0, len(pending_target_ids), 200):
            chunk = pending_target_ids[index : index + 200]
            payload = {"target_id_list": chunk}
            response = self.request("POST", f"/target_groups/{group_id}/targets", json=payload)
            if response.status_code in (200, 201, 204):
                continue

            chunk_error = format_response_error(response)
            for target_id in chunk:
                single_payload = {"target_id_list": [target_id]}
                single_response = self.request("POST", f"/target_groups/{group_id}/targets", json=single_payload)
                if single_response.status_code not in (200, 201, 204):
                    failures.append((target_id, format_response_error(single_response)))

            if failures and len(failures) == len(chunk):
                raise RuntimeError(f"写入分组失败: chunk_error={chunk_error} | failed={failures[:5]}")

        if failures:
            raise RuntimeError(f"部分目标写入分组失败: {failures[:5]}")

    def list_vulnerabilities(self, query=None, page_size=100):
        params = {}
        if query:
            params["q"] = query
        return list(self.iter_cursor_paginated("/vulnerabilities", "vulnerabilities", params=params, page_size=page_size))

    def get_vulnerability(self, vuln_id):
        response = self.request("GET", f"/vulnerabilities/{vuln_id}")
        if response.status_code != 200:
            raise RuntimeError(f"读取漏洞详情失败: {format_response_error(response)}")
        return parse_json_safe(response)


def load_urls_from_file(input_file, default_scheme):
    rows = load_raw_input_rows(input_file)
    clean_entries = []
    seen = set()
    skipped = []

    for line_no, raw_target, raw_description in rows:
        raw_value = normalize_address(raw_target)
        if not raw_value:
            skipped.append((line_no, raw_value, "empty"))
            continue
        if raw_value.lower() in {"url", "urls", "target", "targets", "address", "domain", "host"}:
            skipped.append((line_no, raw_value, "header"))
            continue

        normalized, reason = normalize_input_target(raw_value, default_scheme)
        if not normalized:
            skipped.append((line_no, raw_value, reason))
            continue

        dedupe_key = normalized.lower()
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        clean_entries.append(
            {
                "address": normalized,
                "description": raw_description or build_default_description(input_file, line_no, normalized),
                "line_no": line_no,
                "raw": raw_target,
                "raw_target": raw_value,
                "source_file": input_file,
            }
        )

    return clean_entries, skipped


def extract_httpx_probe_host(raw_value):
    value = normalize_address(raw_value)
    if not value:
        return None
    lowered = value.lower()
    if lowered in {"url", "urls", "target", "targets", "address", "domain", "host"}:
        return None
    if value.startswith(("http://", "https://")):
        try:
            endpoint = parse_target_endpoint(value)
            if endpoint["explicit_port"]:
                return f"{endpoint['host']}:{endpoint['port']}"
            return endpoint["host"]
        except Exception:
            return None
    if HOST_PORT_RE.match(value):
        return value
    if looks_like_host(value):
        return value
    return None


def load_raw_input_rows(input_file):
    ext = os.path.splitext(input_file)[1].lower()
    rows = []
    if ext == ".txt":
        with open(input_file, "r", encoding="utf-8") as file_obj:
            for line_no, line in enumerate(file_obj, start=1):
                raw = line.strip()
                if raw:
                    rows.append((line_no, raw, ""))
    elif ext == ".csv":
        with open(input_file, "r", encoding="utf-8-sig", newline="") as file_obj:
            reader = csv.reader(file_obj)
            for line_no, row in enumerate(reader, start=1):
                if not row:
                    continue
                target_cell = (row[0] or "").strip()
                description_cell = (row[1] or "").strip() if len(row) > 1 else ""
                if target_cell:
                    rows.append((line_no, target_cell, description_cell))
    elif ext in (".xlsx", ".xls"):
        try:
            import pandas as pd
        except ImportError as exc:
            raise RuntimeError("读取 xlsx 需要安装 pandas") from exc

        dataframe = pd.read_excel(input_file, header=None)
        for row_index, row in dataframe.iterrows():
            target_cell = str(row.iloc[0]).strip() if len(row) > 0 and not pd.isna(row.iloc[0]) else ""
            description_cell = str(row.iloc[1]).strip() if len(row) > 1 and not pd.isna(row.iloc[1]) else ""
            if target_cell:
                rows.append((row_index + 1, target_cell, description_cell))
    else:
        raise RuntimeError("不支持的输入格式，仅支持 .txt / .csv / .xlsx / .xls")
    return rows


def export_awvs_csv(entries, output_dir, chunk_size):
    if chunk_size <= 0:
        raise RuntimeError("chunk_size 必须大于 0")

    os.makedirs(output_dir, exist_ok=True)
    source_file = entries[0]["source_file"] if entries else "targets"
    base_name = os.path.splitext(os.path.basename(source_file))[0]
    generated_files = []

    for index, chunk in enumerate(chunked(entries, chunk_size), start=1):
        output_file = os.path.join(output_dir, f"{base_name}_awvs_part{index}.csv")
        with open(output_file, "w", encoding="utf-8", newline="") as file_obj:
            writer = csv.writer(file_obj)
            for item in chunk:
                writer.writerow([item["address"], item["description"]])
        generated_files.append(output_file)

    return generated_files


def safe_filename(value, fallback="item", max_length=80):
    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", (value or "").strip())
    cleaned = re.sub(r"\s+", "_", cleaned).strip("._ ")
    if not cleaned:
        cleaned = fallback
    return cleaned[:max_length].rstrip("._ ") or fallback


def default_sqlmap_quick_dir(group_ref):
    return os.path.abspath(f"sqlmap_quick_{safe_filename(group_ref or 'group')}")


def severity_to_query_value(severity_name):
    if not severity_name or severity_name == "all":
        return None
    return SEVERITY_NAME_TO_VALUE[severity_name]


def severity_to_name(severity_value):
    return SEVERITY_VALUE_TO_NAME.get(severity_value, str(severity_value))


def strip_html_text(text):
    normalized = (text or "").replace("<br/>", "\n").replace("<br />", "\n").replace("<br>", "\n")
    normalized = re.sub(r"</li\s*>", "\n", normalized, flags=re.I)
    normalized = re.sub(r"<li[^>]*>", "- ", normalized, flags=re.I)
    normalized = re.sub(r"</p\s*>", "\n", normalized, flags=re.I)
    normalized = re.sub(r"<[^>]+>", "", normalized)
    normalized = unescape(normalized)
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")
    normalized = re.sub(r"\n{3,}", "\n\n", normalized)
    return normalized.strip()


def build_vulnerability_query(group_id, severity_name=None, status_name=None):
    query_parts = [f"group_id:{group_id}"]
    severity_value = severity_to_query_value(severity_name)
    if severity_value is not None:
        query_parts.append(f"severity:{severity_value}")
    if status_name and status_name != "all":
        query_parts.append(f"status:{status_name}")
    return ";".join(query_parts)


def is_sqli_vulnerability(vuln):
    name = (vuln.get("vt_name") or "").strip().lower()
    tags = {str(tag).strip().lower() for tag in (vuln.get("tags") or [])}
    return name == "sql injection" or "sql_injection" in tags


def detect_sqli_techniques(details_text):
    lowered = (details_text or "").lower()
    techniques = []
    if any(token in lowered for token in ("error message found", "sql syntax", "mysql error", "odbc", "jdbc", "ora-", "postgresql query failed")):
        techniques.append("error-based")
    if "tests performed" in lowered or ("=> true" in lowered and "=> false" in lowered) or (" true" in lowered and " false" in lowered):
        techniques.append("boolean-based")
    if any(token in lowered for token in ("sleep(", "benchmark(", "pg_sleep", "waitfor delay", "dbms_pipe", "sysdate()", "time delay")):
        techniques.append("time-based")
    if any(token in lowered for token in ("union select", "union-based", "union query", "union all select")):
        techniques.append("union-based")
    return techniques


def sqlmap_technique_letters(techniques):
    letters = []
    mapping = {
        "boolean-based": "B",
        "error-based": "E",
        "time-based": "T",
        "union-based": "U",
    }
    for technique in techniques or []:
        letter = mapping.get(technique)
        if letter and letter not in letters:
            letters.append(letter)
    return "".join(letters)


def detect_sqli_dbms(details_text):
    lowered = (details_text or "").lower()
    dbms_tokens = [
        ("mysql", ("mysql", "mariadb")),
        ("postgresql", ("postgresql", "postgres", "pg_sleep")),
        ("mssql", ("microsoft sql server", "sql server", "mssql", "waitfor delay")),
        ("oracle", ("oracle", "ora-", "dbms_pipe")),
        ("sqlite", ("sqlite",)),
        ("access", ("microsoft access", "ms access")),
    ]
    for dbms_name, tokens in dbms_tokens:
        if any(token in lowered for token in tokens):
            return dbms_name
    return ""


def classify_direct_exploitability(vuln):
    title = (vuln.get("vt_name") or "").strip()
    title_lower = title.lower()
    tags = {str(tag).strip().lower() for tag in (vuln.get("tags") or [])}
    description_blob = " ".join(
        [
            title_lower,
            (vuln.get("description") or "").lower(),
            (vuln.get("details") or "").lower(),
            " ".join(sorted(tags)),
        ]
    )

    if is_sqli_vulnerability(vuln):
        return True, "sqlmap", "SQL Injection with request evidence"

    for label, keywords in DIRECT_EXPLOIT_KEYWORDS.items():
        if any(keyword in description_blob for keyword in keywords):
            return True, "manual", label

    return False, "review", "likely component/CVE finding or needs manual validation"


def looks_like_injected_header_value(value):
    lowered = (value or "").lower()
    suspicious_tokens = (
        "sleep(",
        "benchmark(",
        "waitfor delay",
        "sysdate()",
        " xor",
        "' or ",
        "\" or ",
        "' and ",
        "\" and ",
        "'\"",
        "\"'",
    )
    return any(token in lowered for token in suspicious_tokens)


def replace_named_parameter(serialized_text, name):
    if not serialized_text or not name:
        return serialized_text, False
    pattern = re.compile(rf"(^|[?&])({re.escape(name)})=([^&]*)")
    replaced, count = pattern.subn(lambda match: f"{match.group(1)}{match.group(2)}=*", serialized_text, count=1)
    return replaced, count > 0


def replace_named_parameter_value(serialized_text, name, replacement="1"):
    if not serialized_text or not name:
        return serialized_text, False
    pattern = re.compile(rf"(^|[?&])({re.escape(name)})=([^&]*)")
    replaced, count = pattern.subn(lambda match: f"{match.group(1)}{match.group(2)}={replacement}", serialized_text, count=1)
    return replaced, count > 0


def replace_json_parameter(serialized_text, name):
    if not serialized_text or not name:
        return serialized_text, False
    string_pattern = re.compile(rf'("{re.escape(name)}"\s*:\s*")([^"]*)(")')
    replaced, count = string_pattern.subn(r'\1*\3', serialized_text, count=1)
    if count > 0:
        return replaced, True
    numeric_pattern = re.compile(rf'("{re.escape(name)}"\s*:\s*)(-?\d+(?:\.\d+)?)')
    replaced, count = numeric_pattern.subn(r"\1*", serialized_text, count=1)
    return replaced, count > 0


def replace_json_parameter_value(serialized_text, name, replacement="1"):
    if not serialized_text or not name:
        return serialized_text, False
    string_pattern = re.compile(rf'("{re.escape(name)}"\s*:\s*")([^"]*)(")')
    replaced, count = string_pattern.subn(rf'\g<1>{replacement}\3', serialized_text, count=1)
    if count > 0:
        return replaced, True
    numeric_pattern = re.compile(rf'("{re.escape(name)}"\s*:\s*)(-?\d+(?:\.\d+)?)')
    replaced, count = numeric_pattern.subn(rf"\g<1>{replacement}", serialized_text, count=1)
    return replaced, count > 0


def replace_path_tail_with_marker(path, affects_url):
    current_path = path or "/"
    base_path = urlparse(affects_url).path or "/"
    if current_path == base_path:
        return current_path, False
    if base_path.endswith("/") and current_path.startswith(base_path) and current_path[len(base_path) :]:
        return f"{base_path}*", True
    if current_path.startswith(f"{base_path}/") and current_path[len(base_path) + 1 :]:
        return f"{base_path}/*", True
    head, sep, tail = current_path.rpartition("/")
    if sep and tail:
        return f"{head}{sep}*", True
    return current_path, False


def replace_path_tail_with_value(path, affects_url, replacement="1"):
    current_path = path or "/"
    base_path = urlparse(affects_url).path or "/"
    if current_path == base_path:
        return current_path, False
    if base_path.endswith("/") and current_path.startswith(base_path) and current_path[len(base_path) :]:
        return f"{base_path}{replacement}", True
    if current_path.startswith(f"{base_path}/") and current_path[len(base_path) + 1 :]:
        return f"{base_path}/{replacement}", True
    head, sep, tail = current_path.rpartition("/")
    if sep and tail:
        return f"{head}{sep}{replacement}", True
    return current_path, False


def sanitize_form_encoded_values(serialized_text):
    if not serialized_text or "=" not in serialized_text:
        return serialized_text
    parts = []
    for chunk in serialized_text.split("&"):
        if "=" not in chunk:
            parts.append(chunk)
            continue
        name, value = chunk.split("=", 1)
        if value in {"", "*"}:
            value = "1"
        parts.append(f"{name}={value}")
    return "&".join(parts)


def sanitize_json_marker_values(serialized_text):
    if not serialized_text:
        return serialized_text
    serialized_text = re.sub(r'(:\s*")\*(")', r'\g<1>1\2', serialized_text)
    serialized_text = re.sub(r'(:\s*)\*([,\}\]])', r'\g<1>1\2', serialized_text)
    return serialized_text


def sanitize_query_string_values(query_text):
    if not query_text:
        return query_text
    return sanitize_form_encoded_values(query_text)


def sanitize_path_marker(path_text):
    if not path_text:
        return path_text
    return path_text.replace("/*", "/1").replace("*", "1")


def normalize_request_for_sqlmap(raw_request, affects_url, affected_param, baseline_value=None):
    parsed_url = urlparse(affects_url)
    scheme = (parsed_url.scheme or "http").lower()
    normalized = (raw_request or "").replace("\r\n", "\n").replace("\r", "\n")
    header_blob, _, body = normalized.partition("\n\n")
    header_lines = [line for line in header_blob.split("\n") if line]
    request_line = header_lines[0].strip() if header_lines else ""
    header_pairs = []
    for line in header_lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        header_pairs.append((name.strip(), value.strip()))

    if request_line:
        request_parts = request_line.split()
        method = request_parts[0].upper()
        target = request_parts[1] if len(request_parts) > 1 else (parsed_url.path or "/")
        version = request_parts[2] if len(request_parts) > 2 else "HTTP/1.1"
    else:
        method = "GET"
        target = urlunsplit(("", "", parsed_url.path or "/", parsed_url.query, ""))
        version = "HTTP/1.1"

    target_parts = urlsplit(target if "://" in target else f"http://placeholder{target}")
    target_path = target_parts.path or "/"
    target_query = target_parts.query
    body_text = body or ""
    marker_mode = "as-is"

    target_path = sanitize_path_marker(target_path)
    target_query = sanitize_query_string_values(target_query)
    if body_text:
        content_type = next((value for name, value in header_pairs if name.lower() == "content-type"), "")
        lowered_content_type = (content_type or "").lower()
        if "application/json" in lowered_content_type:
            body_text = sanitize_json_marker_values(body_text)
        else:
            body_text = sanitize_form_encoded_values(body_text)

    if baseline_value is not None:
        target_query, query_changed = replace_named_parameter_value(target_query, affected_param, baseline_value)
        if query_changed:
            marker_mode = "baseline-query"
        elif method in {"POST", "PUT", "PATCH"} and body_text:
            body_text, form_changed = replace_named_parameter_value(body_text, affected_param, baseline_value)
            if form_changed:
                marker_mode = "baseline-body-form"
            else:
                body_text, json_changed = replace_json_parameter_value(body_text, affected_param, baseline_value)
                if json_changed:
                    marker_mode = "baseline-body-json"
        else:
            target_path, path_changed = replace_path_tail_with_value(target_path, affects_url, baseline_value)
            if path_changed:
                marker_mode = "baseline-path"

    request_target = urlunsplit(("", "", target_path, target_query, ""))

    host_header = parsed_url.netloc
    normalized_headers = []
    seen_headers = set()
    for name, value in header_pairs:
        lowered = name.lower()
        if lowered in SQLMAP_REQUEST_DROP_HEADERS or lowered in seen_headers:
            continue
        if lowered == "host":
            host_header = value
            continue
        if lowered not in {"user-agent", "referer", "cookie", "authorization", "content-type", "x-requested-with", "accept", "origin"}:
            continue
        seen_headers.add(lowered)

        safe_value = value
        if lowered == "user-agent" and looks_like_injected_header_value(value):
            safe_value = "Mozilla/5.0"
        elif lowered == "referer" and looks_like_injected_header_value(value):
            safe_value = f"{scheme}://{host_header}{parsed_url.path or '/'}"
        elif lowered == "origin" and looks_like_injected_header_value(value):
            safe_value = f"{scheme}://{host_header}"
        elif lowered == "x-requested-with" and looks_like_injected_header_value(value):
            safe_value = "XMLHttpRequest"
        elif lowered == "accept" and looks_like_injected_header_value(value):
            safe_value = "*/*"

        normalized_headers.append((name, safe_value))

    if "user-agent" not in seen_headers:
        normalized_headers.insert(0, ("User-Agent", "Mozilla/5.0"))

    request_lines = [f"{method} {request_target or '/'} {version}", f"Host: {host_header}"]
    for name, value in normalized_headers:
        request_lines.append(f"{name}: {value}")
    request_text = "\r\n".join(request_lines) + "\r\n\r\n"
    if body_text:
        request_text += body_text

    full_url = f"{scheme}://{host_header}{request_target or '/'}"
    return {
        "method": method,
        "scheme": scheme,
        "request_target": request_target or "/",
        "request_text": request_text,
        "full_url": full_url,
        "marker_mode": marker_mode,
    }


def build_sqlmap_command(
    request_file,
    vuln,
    sqlmap_output_dir,
    proxy=None,
    force_ssl_mode="off",
    baseline_value=None,
    string_hint=None,
    not_string_hint=None,
    dbms_hint=None,
    threads=None,
    extra_options=None,
):
    normalized = normalize_request_for_sqlmap(
        vuln.get("request") or "",
        vuln.get("affects_url") or "",
        vuln.get("affects_detail") or "",
        baseline_value=baseline_value,
    )
    details_text = strip_html_text(vuln.get("details") or "")
    techniques = detect_sqli_techniques(details_text)
    options = [
        "--batch",
        "--random-agent",
        "--level 5",
        "--risk 3",
        "--flush-session",
        "--drop-set-cookie",
        "--skip-static",
        f'--output-dir "{sqlmap_output_dir}"',
    ]
    if normalized["scheme"] == "https" and force_ssl_mode == "on":
        options.append("--force-ssl")
    elif normalized["scheme"] == "https" and force_ssl_mode == "auto":
        options.append("--force-ssl")
    if vuln.get("affects_detail"):
        options.append(f'-p "{vuln["affects_detail"]}"')
    technique_letters = sqlmap_technique_letters(techniques)
    if technique_letters:
        options.append(f"--technique={technique_letters}")
    effective_dbms = dbms_hint or detect_sqli_dbms(details_text)
    if effective_dbms:
        options.append(f"--dbms={effective_dbms}")
    if string_hint:
        options.append(f"--string {quote_sqlmap_option_value(string_hint)}")
    elif not_string_hint:
        options.append(f"--not-string {quote_sqlmap_option_value(not_string_hint)}")
    if threads:
        options.append(f"--threads {threads}")
    if extra_options:
        options.extend(extra_options)
    if proxy:
        options.append(f'--proxy "{proxy}"')
    command = f'sqlmap -r "{request_file}" ' + " ".join(options)
    return command, normalized


def build_sqlmap_followup_commands(base_command):
    commands = []
    if not base_command:
        return commands
    current_db_command = (
        f"{base_command} --current-db --threads {SQLMAP_DEFAULT_THREADS} "
        "--fresh-queries"
    )
    dbs_command = (
        f"{base_command} --dbs --threads {SQLMAP_DEFAULT_THREADS} "
        "--fresh-queries"
    )
    tables_template = (
        f"{base_command} -D DB_NAME_HERE --tables --threads {SQLMAP_DEFAULT_THREADS} "
        "--fresh-queries"
    )
    tables_hardening_template = (
        f"{base_command} -D DB_NAME_HERE --tables --threads {SQLMAP_DEFAULT_THREADS} "
        "--fresh-queries --no-cast --hex"
    )
    commands.extend(
        [
            current_db_command,
            dbs_command,
            tables_template,
            tables_hardening_template,
        ]
    )
    return commands


def quote_sqlmap_option_value(value):
    return '"' + (value or "").replace('"', r'\"') + '"'


def parse_normalized_request_text(request_text):
    normalized = (request_text or "").replace("\r\n", "\n").replace("\r", "\n")
    header_blob, _, body = normalized.partition("\n\n")
    lines = [line for line in header_blob.split("\n") if line]
    if not lines:
        raise RuntimeError("empty request")
    request_parts = lines[0].split()
    if len(request_parts) < 2:
        raise RuntimeError("invalid request line")
    method = request_parts[0].upper()
    target = request_parts[1]
    headers = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip()] = value.strip()
    return method, target, headers, body


def request_normalized_http(normalized, timeout=8, proxy=None):
    method, target, headers, body = parse_normalized_request_text(normalized.get("request_text", ""))
    url = normalized.get("full_url") or target
    request_headers = {name: value for name, value in headers.items() if name.lower() != "host"}
    proxies = None
    if proxy:
        proxy_value = proxy if "://" in proxy else f"http://{proxy}"
        proxies = {"http": proxy_value, "https": proxy_value}
    response = requests.request(
        method,
        url,
        headers=request_headers,
        data=body.encode("utf-8", errors="ignore") if body else None,
        timeout=timeout,
        verify=False,
        allow_redirects=True,
        proxies=proxies,
    )
    response.encoding = response.encoding or response.apparent_encoding or "utf-8"
    return response


def extract_visible_text_candidates(html_text):
    text = strip_html_text(html_text or "")
    candidates = []
    for token in re.findall(r"[\u4e00-\u9fffA-Za-z0-9][\u4e00-\u9fffA-Za-z0-9 _\-\u3002\uff0c\uff1a\uff1b\uff08\uff09]{2,40}", text):
        candidate = re.sub(r"\s+", " ", token).strip(" _-")
        if len(candidate) < 3 or len(candidate) > 40:
            continue
        if re.fullmatch(r"\d+", candidate):
            continue
        lowered = candidate.lower()
        if lowered in {"html", "head", "body", "script", "style", "true", "false"}:
            continue
        if any(token in candidate for token in ("对不起", "系统繁忙", "错误", "失败", "异常", "联系管理员", "重试", "不存在", "未找到")):
            continue
        candidates.append(candidate)
    seen = set()
    deduped = []
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            deduped.append(candidate)
    return deduped


def choose_sqlmap_string(true_text, false_text):
    false_text = false_text or ""
    preferred_tokens = ("线上查询", "网站首页", "快件业务", "发货指南", "新闻资讯", "联系我们", "关于我们")
    candidates = extract_visible_text_candidates(true_text)
    for token in preferred_tokens:
        if token in candidates and token not in false_text:
            return token
    for candidate in extract_visible_text_candidates(true_text):
        if candidate not in false_text:
            return candidate
    return ""


def choose_sqlmap_not_string(true_text, false_text):
    true_text = true_text or ""
    false_text = false_text or ""
    preferred_tokens = (
        "对不起，系统繁忙",
        "系统繁忙",
        "请联系管理员",
        "请稍后重试",
        "请重试",
        "error",
        "exception",
        "warning",
        "failed",
    )
    for token in preferred_tokens:
        if token and token in false_text and token not in true_text:
            return token
    return ""



def resolve_auto_sqlmap_string(vuln, normal_normalized, probe_normalized, proxy=None, logger=None):
    details_text = strip_html_text(vuln.get("details") or "")
    if "boolean-based" not in detect_sqli_techniques(details_text):
        return "", "not-boolean"
    try:
        true_response = request_normalized_http(normal_normalized, proxy=proxy)
        false_response = request_normalized_http(probe_normalized, proxy=proxy)
    except Exception as exc:
        if logger:
            logger.info("[SQLMAP-STRING] 自动获取 --string 失败: %s | %s", vuln.get("affects_url", ""), exc)
        return "", f"request-failed:{exc}"
    if true_response.status_code >= 500:
        return "", f"true-http-{true_response.status_code}"
    candidate = choose_sqlmap_string(true_response.text, false_response.text)
    if candidate:
        return candidate, "auto"
    return "", "no-stable-token"


def resolve_auto_sqlmap_response_hint(vuln, normal_normalized, probe_normalized, proxy=None, logger=None):
    details_text = strip_html_text(vuln.get("details") or "")
    if "boolean-based" not in detect_sqli_techniques(details_text):
        return "", "", "not-boolean"
    try:
        true_response = request_normalized_http(normal_normalized, proxy=proxy)
        false_response = request_normalized_http(probe_normalized, proxy=proxy)
    except Exception as exc:
        if logger:
            logger.info("[SQLMAP-STRING] 自动获取响应特征失败: %s | %s", vuln.get("affects_url", ""), exc)
        return "", "", f"request-failed:{exc}"
    if true_response.status_code >= 500:
        not_string = choose_sqlmap_not_string(true_response.text, false_response.text)
        if not_string:
            return "", not_string, f"auto-not-string:true-http-{true_response.status_code}"
        return "", "", f"true-http-{true_response.status_code}"
    string_hint = choose_sqlmap_string(true_response.text, false_response.text)
    if string_hint:
        return string_hint, "", "auto-string"
    not_string = choose_sqlmap_not_string(true_response.text, false_response.text)
    if not_string:
        return "", not_string, "auto-not-string"
    return "", "", "no-stable-token"


def build_sqlmap_url_command(url_file, output_dir, proxy=None):
    command = f'sqlmap -m "{url_file}" --batch --random-agent --level 5 --risk 3 --drop-set-cookie --skip-static --results-file "sqlmap_collection_results.csv" --output-dir "{output_dir}"'
    if proxy:
        command += f' --proxy "{proxy}"'
    return command


def build_batch_header(title_text):
    return [
        "@echo off",
        "setlocal enableextensions",
        f'title {title_text}',
        'pushd "%~dp0"',
        "where sqlmap >nul 2>&1",
        "if errorlevel 1 (",
        '  echo [ERROR] sqlmap was not found in PATH.',
        '  echo [HINT] Confirm sqlmap can run directly in cmd.exe.',
        "  pause",
        "  exit /b 1",
        ")",
        "echo [INFO] WorkDir: %CD%",
        "echo.",
    ]


def build_sqlmap_wizard_batch():
    return [
        "@echo off",
        "setlocal enableextensions",
        "chcp 65001 >nul",
        "title SQLMap Quick Wizard",
        'pushd "%~dp0"',
        ":MENU",
        "cls",
        'type "00_MENU.txt"',
        "echo.",
        "set /p CHOICE=Choose: ",
        'if "%CHOICE%"=="1" call "05_run_sqlmap_requests.bat" & goto MENU',
        'if "%CHOICE%"=="2" call "10_run_sqlmap_requests_baseline.bat" & goto MENU',
        'if "%CHOICE%"=="3" call "04_run_sqlmap_collection.bat" & goto MENU',
        'if "%CHOICE%"=="4" call "09_run_sqlmap_collection_baseline.bat" & goto MENU',
        'if "%CHOICE%"=="5" call "14_run_filter_sqlmap_hits.bat" & goto MENU',
        'if "%CHOICE%"=="6" type "16_sqlmap_request_commands_powershell.txt" & echo. & pause & goto MENU',
        'if "%CHOICE%"=="7" type "17_sqlmap_request_commands_cmd.txt" & echo. & pause & goto MENU',
        'if "%CHOICE%"=="8" type "20_sqlmap_string_hint.txt" & echo. & pause & goto MENU',
        'if "%CHOICE%"=="9" type "21_sqlmap_followup_commands_powershell.txt" & echo. & pause & goto MENU',
        'if "%CHOICE%"=="10" type "README.txt" & echo. & pause & goto MENU',
        'if "%CHOICE%"=="0" exit /b 0',
        "echo Invalid choice.",
        "pause",
        "goto MENU",
    ]


def split_command_args(command):
    args = []
    current = []
    quote_char = None
    escaped = False
    for char in command or "":
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\" and quote_char != "'":
            current.append(char)
            continue
        if char in {'"', "'"}:
            quote_char = None if quote_char == char else (char if quote_char is None else quote_char)
            current.append(char)
            continue
        if char.isspace() and quote_char is None:
            if current:
                args.append("".join(current))
                current = []
            continue
        current.append(char)
    if current:
        args.append("".join(current))
    return args


def format_powershell_command(command):
    parts = split_command_args(command)
    if len(parts) <= 1:
        return command or ""
    first_line_count = 3 if len(parts) >= 3 and parts[0].lower() == "sqlmap" and parts[1] == "-r" else 1
    lines = [" ".join(parts[:first_line_count])]
    for part in parts[first_line_count:]:
        lines[-1] += " `"
        lines.append(f"    {part}")
    return "\n".join(lines)


SQLMAP_STRING_HINT_TEXT = (
    f"sqlmap quick export guidance ({TOOL_VERSION})\n"
    "\n"
    "This exporter now does three things for boolean-based blind SQLi:\n"
    "  1. Tries to add a TRUE-only --string automatically.\n"
    "  2. If TRUE text is not stable, tries a FALSE-only --not-string automatically.\n"
    "  3. Exports follow-up enumeration commands in 21/22 after a hit is confirmed.\n"
    "\n"
    "Recommended flow after sqlmap confirms an injection:\n"
    "  1. Run --current-db first; do not assume the database name from FOFA/domain text.\n"
    "  2. Run --dbs if --current-db is empty or suspicious.\n"
    "  3. Replace DB_NAME_HERE in 21/22 with the confirmed database name, then run --tables.\n"
    "  4. If table count/name retrieval fails, retry the hardened command with --no-cast --hex.\n"
    "  5. Keep --threads 5 for blind retrieval; increase carefully only if responses are stable.\n"
    "\n"
    "Important sqlmap options:\n"
    "  --tables lists all tables for a database.\n"
    "  -T requires one table name, e.g. -T admin; do not use bare -T for listing tables.\n"
    "  --string must appear only in TRUE/normal responses.\n"
    "  --not-string should be text that appears only in FALSE/error responses.\n"
)


def sqlmap_command_to_linux(command):
    return (command or "").replace("\\", "/")


def shell_single_quote(value):
    return "'" + (value or "").replace("'", "'\"'\"'") + "'"


def build_shell_header(title_text):
    return [
        "#!/usr/bin/env bash",
        "set -u",
        'cd "$(dirname "$0")"',
        'if ! command -v sqlmap >/dev/null 2>&1; then',
        '  echo "[ERROR] sqlmap was not found in PATH."',
        '  echo "[HINT] Install sqlmap or add it to PATH, then rerun this script."',
        "  exit 1",
        "fi",
        f'echo "[INFO] {title_text}"',
        'echo "[INFO] WorkDir: $(pwd)"',
        "echo",
    ]


def write_shell_script(path, lines):
    with open(path, "w", encoding="utf-8", newline="\n") as file_obj:
        file_obj.write("\n".join(lines) + "\n")
    try:
        os.chmod(path, 0o755)
    except OSError:
        pass


def copy_file_if_exists(source, destination):
    if os.path.exists(source):
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        shutil.copy2(source, destination)


def copy_tree_contents(source_dir, destination_dir):
    if not os.path.isdir(source_dir):
        return
    if os.path.exists(destination_dir):
        shutil.rmtree(destination_dir)
    shutil.copytree(source_dir, destination_dir)


def build_linux_sqlmap_bundle(
    output_dir,
    summary_file,
    direct_file,
    manual_file,
    sqlmap_url_file,
    sqlmap_baseline_url_file,
    sqlmap_filter_hits_script_file,
    extra_text_files,
    scatter_commands,
    baseline_scatter_commands,
    collection_command,
    baseline_collection_command,
    request_dir,
    baseline_request_dir,
):
    linux_dir = os.path.join(output_dir, "linux")
    os.makedirs(linux_dir, exist_ok=True)

    for source_file in (summary_file, direct_file, manual_file, sqlmap_url_file, sqlmap_baseline_url_file, sqlmap_filter_hits_script_file, *(extra_text_files or [])):
        copy_file_if_exists(source_file, os.path.join(linux_dir, os.path.basename(source_file)))
    copy_tree_contents(request_dir, os.path.join(linux_dir, os.path.basename(request_dir)))
    copy_tree_contents(baseline_request_dir, os.path.join(linux_dir, os.path.basename(baseline_request_dir)))

    linux_collection_command = sqlmap_command_to_linux(collection_command)
    linux_baseline_collection_command = sqlmap_command_to_linux(baseline_collection_command)
    linux_scatter_commands = [sqlmap_command_to_linux(command) for command in scatter_commands]
    linux_baseline_scatter_commands = [sqlmap_command_to_linux(command) for command in baseline_scatter_commands]

    linux_command_files = {
        "06_sqlmap_collection_command.txt": [linux_collection_command],
        "07_sqlmap_request_commands.txt": linux_scatter_commands,
        "11_sqlmap_collection_baseline_command.txt": [linux_baseline_collection_command],
        "12_sqlmap_request_baseline_commands.txt": linux_baseline_scatter_commands,
    }
    for filename, commands in linux_command_files.items():
        with open(os.path.join(linux_dir, filename), "w", encoding="utf-8", newline="\n") as file_obj:
            file_obj.write("\n".join(command for command in commands if command) + "\n")

    collection_lines = build_shell_header("SQLMap Collection Mode")
    collection_lines.extend(
        [
            f'echo "[INFO] Collection mode, {1 if linux_collection_command else 0} command."',
            linux_collection_command,
        ]
    )
    write_shell_script(os.path.join(linux_dir, "04_run_sqlmap_collection.sh"), collection_lines)

    request_lines = build_shell_header("SQLMap Request Mode")
    request_lines.extend(
        [
            "FAIL_COUNT=0",
            f'echo "[INFO] Request mode, {len(linux_scatter_commands)} unique requests."',
            "echo",
        ]
    )
    for index, command in enumerate(linux_scatter_commands, start=1):
        request_lines.append(f"printf '%s\\n' {shell_single_quote(f'[RUN {index}/{len(linux_scatter_commands)}] {command}')}")
        request_lines.append(f"{command} || FAIL_COUNT=$((FAIL_COUNT+1))")
        request_lines.append("echo")
    request_lines.extend(
        [
            'echo "[DONE] Request mode finished, FailCount=$FAIL_COUNT"',
            "exit $FAIL_COUNT",
        ]
    )
    write_shell_script(os.path.join(linux_dir, "05_run_sqlmap_requests.sh"), request_lines)

    baseline_collection_lines = build_shell_header("SQLMap Baseline Collection Mode")
    baseline_collection_lines.extend(
        [
            f'echo "[INFO] Baseline collection mode, {1 if linux_baseline_collection_command else 0} command."',
            linux_baseline_collection_command,
        ]
    )
    write_shell_script(os.path.join(linux_dir, "09_run_sqlmap_collection_baseline.sh"), baseline_collection_lines)

    baseline_request_lines = build_shell_header("SQLMap Baseline Request Mode")
    baseline_request_lines.extend(
        [
            "FAIL_COUNT=0",
            f'echo "[INFO] Baseline request mode, {len(linux_baseline_scatter_commands)} unique requests."',
            "echo",
        ]
    )
    for index, command in enumerate(linux_baseline_scatter_commands, start=1):
        baseline_request_lines.append(f"printf '%s\\n' {shell_single_quote(f'[RUN {index}/{len(linux_baseline_scatter_commands)}] {command}')}")
        baseline_request_lines.append(f"{command} || FAIL_COUNT=$((FAIL_COUNT+1))")
        baseline_request_lines.append("echo")
    baseline_request_lines.extend(
        [
            'echo "[DONE] Baseline request mode finished, FailCount=$FAIL_COUNT"',
            "exit $FAIL_COUNT",
        ]
    )
    write_shell_script(os.path.join(linux_dir, "10_run_sqlmap_requests_baseline.sh"), baseline_request_lines)

    filter_lines = build_shell_header("SQLMap Hit Filter")
    filter_lines.extend(
        [
            'python3 "13_filter_sqlmap_hits.py"',
            'echo "[DONE] Filter finished, ExitCode=$?"',
        ]
    )
    write_shell_script(os.path.join(linux_dir, "14_run_filter_sqlmap_hits.sh"), filter_lines)

    with open(os.path.join(linux_dir, "README_LINUX.txt"), "w", encoding="utf-8", newline="\n") as file_obj:
        file_obj.write(
            "\n".join(
                [
                    "Linux sqlmap bundle",
                    "",
                    "Usage:",
                    "  cd linux",
                    "  ./05_run_sqlmap_requests.sh",
                    "  ./10_run_sqlmap_requests_baseline.sh",
                    "  ./14_run_filter_sqlmap_hits.sh",
                    "",
                    "Notes:",
                    "  Paths use Linux '/' separators.",
                    "  HTTPS request-mode commands keep --force-ssl when exported by auto mode.",
                    "  Install sqlmap and python3 before running these scripts.",
                ]
            )
            + "\n"
        )

    return linux_dir


def build_review_row(group, detail):
    detail_text = strip_html_text(detail.get("details") or "")
    evidence = detail_text.splitlines()[0] if detail_text else strip_html_text(detail.get("description") or "")
    url = detail.get("affects_url", "") or ""
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path or ""
    path = parsed.path or "/"
    return {
        "group_name": group.get("name", ""),
        "group_id": group.get("group_id", ""),
        "severity": severity_to_name(detail.get("severity")),
        "status": detail.get("status", ""),
        "confidence": detail.get("confidence", ""),
        "vuln_id": detail.get("vuln_id", ""),
        "vuln_name": detail.get("vt_name", ""),
        "url": url,
        "host": host,
        "path": path,
        "parameter": detail.get("affects_detail", ""),
        "is_sqli": "yes" if is_sqli_vulnerability(detail) else "no",
        "techniques": ",".join(detect_sqli_techniques(detail_text)) if is_sqli_vulnerability(detail) else "",
        "evidence": evidence,
        "dedupe_key": "",
        "repeat_count": 0,
        "priority": "normal",
    }


def export_group_review_bundle(client, group, output_dir, severity_name="all", status_name="open", sqli_only=True):
    query = build_vulnerability_query(group["group_id"], severity_name=severity_name, status_name=status_name)
    vulnerabilities = client.list_vulnerabilities(query=query, page_size=100)

    rows = []
    repeat_counter = {}
    for vuln in vulnerabilities:
        detail = client.get_vulnerability(vuln["vuln_id"])
        if sqli_only and not is_sqli_vulnerability(detail):
            continue
        row = build_review_row(group, detail)
        dedupe_key = (
            row["vuln_name"].strip().lower(),
            row["host"].strip().lower(),
            row["path"].strip().lower(),
            row["parameter"].strip().lower(),
        )
        row["dedupe_key"] = "|".join(dedupe_key)
        repeat_counter[dedupe_key] = repeat_counter.get(dedupe_key, 0) + 1
        rows.append(row)

    for row in rows:
        dedupe_key = tuple(row["dedupe_key"].split("|"))
        row["repeat_count"] = repeat_counter.get(dedupe_key, 1)
        confidence_value = int(str(row.get("confidence", "0") or "0").strip() or "0")
        if row["repeat_count"] >= 2 and confidence_value >= 90:
            row["priority"] = "high"
        elif confidence_value >= 90:
            row["priority"] = "medium"
        elif row["repeat_count"] >= 2:
            row["priority"] = "medium"

    rows.sort(key=lambda item: (item["priority"] != "high", item["host"], item["path"], item["parameter"], item["vuln_name"]))
    os.makedirs(output_dir, exist_ok=True)

    fieldnames = [
        "group_name",
        "group_id",
        "severity",
        "status",
        "confidence",
        "vuln_id",
        "vuln_name",
        "url",
        "host",
        "path",
        "parameter",
        "is_sqli",
        "techniques",
        "repeat_count",
        "priority",
        "evidence",
        "dedupe_key",
    ]

    summary_file = os.path.join(output_dir, "00_review_summary.csv")
    high_confidence_file = os.path.join(output_dir, "01_high_confidence.csv")
    deduped_file = os.path.join(output_dir, "02_deduped_by_url_param.csv")
    repeated_file = os.path.join(output_dir, "03_repeated_candidates.csv")
    host_counts_file = os.path.join(output_dir, "04_host_counts.csv")
    manual_first_file = os.path.join(output_dir, "05_优先人工看.csv")
    noisy_file = os.path.join(output_dir, "06_疑似噪音.csv")
    host_multi_param_file = os.path.join(output_dir, "07_同主机多参数集中.csv")
    readme_file = os.path.join(output_dir, "README.txt")

    write_dict_csv(summary_file, fieldnames, [{name: row.get(name, "") for name in fieldnames} for row in rows])
    write_dict_csv(
        high_confidence_file,
        fieldnames,
        [{name: row.get(name, "") for name in fieldnames} for row in rows if int(str(row.get("confidence", "0") or "0").strip() or "0") >= 90],
    )

    deduped_rows = []
    seen_keys = set()
    for row in rows:
        if row["dedupe_key"] in seen_keys:
            continue
        deduped_rows.append(row)
        seen_keys.add(row["dedupe_key"])
    write_dict_csv(deduped_file, fieldnames, [{name: row.get(name, "") for name in fieldnames} for row in deduped_rows])
    write_dict_csv(
        repeated_file,
        fieldnames,
        [{name: row.get(name, "") for name in fieldnames} for row in deduped_rows if int(row.get("repeat_count", 0) or 0) >= 2],
    )

    write_dict_csv(
        manual_first_file,
        fieldnames,
        [
            {name: row.get(name, "") for name in fieldnames}
            for row in deduped_rows
            if row.get("priority") == "high"
            or int(str(row.get("confidence", "0") or "0").strip() or "0") >= 95
            or int(row.get("repeat_count", 0) or 0) >= 2
        ],
    )
    write_dict_csv(
        noisy_file,
        fieldnames,
        [
            {name: row.get(name, "") for name in fieldnames}
            for row in deduped_rows
            if int(str(row.get("confidence", "0") or "0").strip() or "0") < 90
            and int(row.get("repeat_count", 0) or 0) <= 1
        ],
    )

    host_counts = {}
    for row in rows:
        host = row["host"] or "-"
        entry = host_counts.setdefault(
            host,
            {
                "host": host,
                "total": 0,
                "high_priority": 0,
                "high_confidence": 0,
                "unique_paths": set(),
                "unique_parameters": set(),
            },
        )
        entry["total"] += 1
        if row.get("priority") == "high":
            entry["high_priority"] += 1
        if int(str(row.get("confidence", "0") or "0").strip() or "0") >= 90:
            entry["high_confidence"] += 1
        if row.get("path"):
            entry["unique_paths"].add(row["path"])
        if row.get("parameter"):
            entry["unique_parameters"].add(row["parameter"])
    host_rows = []
    for entry in host_counts.values():
        host_rows.append(
            {
                "host": entry["host"],
                "total": entry["total"],
                "high_priority": entry["high_priority"],
                "high_confidence": entry["high_confidence"],
                "unique_paths": len(entry["unique_paths"]),
                "unique_parameters": len(entry["unique_parameters"]),
            }
        )
    host_rows = sorted(host_rows, key=lambda item: (-item["high_priority"], -item["high_confidence"], -item["total"], item["host"]))
    write_dict_csv(host_counts_file, ["host", "total", "high_priority", "high_confidence", "unique_paths", "unique_parameters"], host_rows)
    write_dict_csv(
        host_multi_param_file,
        ["host", "total", "high_priority", "high_confidence", "unique_paths", "unique_parameters"],
        [
            row
            for row in host_rows
            if int(row.get("unique_parameters", 0) or 0) >= 2 or int(row.get("total", 0) or 0) >= 3
        ],
    )

    with open(readme_file, "w", encoding="utf-8-sig", newline="\n") as file_obj:
        file_obj.write(
            "\n".join(
                [
                    f"group_name={group.get('name', '')}",
                    f"group_id={group.get('group_id', '')}",
                    f"severity_filter={severity_name}",
                    f"status_filter={status_name}",
                    f"sqli_only={'yes' if sqli_only else 'no'}",
                    f"total_rows={len(rows)}",
                    f"deduped_rows={len(deduped_rows)}",
                    f"repeated_candidates={sum(1 for row in deduped_rows if int(row.get('repeat_count', 0) or 0) >= 2)}",
                    "",
                    "Files:",
                    "  00_review_summary.csv        all matching findings",
                    "  01_high_confidence.csv       confidence >= 90",
                    "  02_deduped_by_url_param.csv  one row per host/path/parameter finding",
                    "  03_repeated_candidates.csv   repeated same host/path/parameter findings",
                    "  04_host_counts.csv           host-level concentration view",
                    "  05_优先人工看.csv           high priority / high confidence / repeated first",
                    "  06_疑似噪音.csv             confidence < 90 and not repeated",
                    "  07_同主机多参数集中.csv     hosts worth clustering review first",
                ]
            )
            + "\n"
        )

    return {
        "query": query,
        "summary_file": summary_file,
        "high_confidence_file": high_confidence_file,
        "deduped_file": deduped_file,
        "repeated_file": repeated_file,
        "host_counts_file": host_counts_file,
        "manual_first_file": manual_first_file,
        "noisy_file": noisy_file,
        "host_multi_param_file": host_multi_param_file,
        "readme_file": readme_file,
        "total_count": len(rows),
        "deduped_count": len(deduped_rows),
    }


def export_precheck_csv(rows, output_file):
    os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
    with open(output_file, "w", encoding="utf-8-sig", newline="") as file_obj:
        writer = csv.writer(file_obj)
        writer.writerow(PRECHECK_CSV_HEADERS)
        for row in rows:
            writer.writerow(serialize_precheck_row(row))


def serialize_precheck_row(row):
    return [
        row.get("url", ""),
        row.get("description", ""),
        row.get("selected_route", ""),
        row.get("selected_reason", ""),
        row.get("risk_level", ""),
        row.get("risk_tag", ""),
        row.get("direct_ok", ""),
        row.get("http_proxy_ok", ""),
        row.get("socks5_ok", ""),
        row.get("http_attempts", ""),
        row.get("details", ""),
    ]


def resolve_precheck_csv_path(output_path):
    if output_path.lower().endswith(".csv"):
        return output_path
    return os.path.join(output_path, "00_全部结果.csv")


def resolve_precheck_sidecar_csv_path(output_file):
    root, ext = os.path.splitext(output_file)
    return f"{root}.增量{ext or '.csv'}"


def resolve_precheck_runtime_dir(output_path):
    root, _ = os.path.splitext(resolve_precheck_csv_path(output_path))
    return f"{root}.runtime"


def list_precheck_runtime_csv_files(output_path):
    runtime_dir = resolve_precheck_runtime_dir(output_path)
    if not os.path.isdir(runtime_dir):
        return []

    files = []
    for name in sorted(os.listdir(runtime_dir)):
        path = os.path.join(runtime_dir, name)
        if os.path.isfile(path) and name.lower().endswith(".csv"):
            files.append(path)
    return files


def create_precheck_runtime_writer(output_path):
    runtime_dir = resolve_precheck_runtime_dir(output_path)
    os.makedirs(runtime_dir, exist_ok=True)
    run_id = f"{datetime.now():%Y%m%d_%H%M%S_%f}_{os.getpid()}"
    return {
        "runtime_dir": runtime_dir,
        "run_id": run_id,
        "part_index": 0,
        "active_file": "",
    }


def allocate_precheck_runtime_file(runtime_writer):
    runtime_writer["part_index"] += 1
    runtime_writer["active_file"] = os.path.join(
        runtime_writer["runtime_dir"],
        f"session_{runtime_writer['run_id']}_{runtime_writer['part_index']:03d}.csv",
    )
    return runtime_writer["active_file"]


def append_precheck_runtime_row(row, runtime_writer, logger=None):
    if not runtime_writer:
        raise RuntimeError("runtime_writer 未初始化")

    last_error = None
    for _ in range(50):
        candidate = runtime_writer.get("active_file") or allocate_precheck_runtime_file(runtime_writer)
        try:
            need_header = not os.path.exists(candidate) or os.path.getsize(candidate) == 0
            with open(candidate, "a", encoding="utf-8-sig", newline="") as file_obj:
                writer = csv.writer(file_obj)
                if need_header:
                    writer.writerow(PRECHECK_CSV_HEADERS)
                writer.writerow(serialize_precheck_row(row))
            return candidate
        except PermissionError as exc:
            last_error = exc
            if logger:
                logger.warning("[CHECK-SAVE] 运行时结果文件被占用，自动切换新文件: %s", os.path.abspath(candidate))
            runtime_writer["active_file"] = ""
            continue

    raise last_error or RuntimeError("运行时结果文件连续被占用，无法写入预检结果")


def build_precheck_row(target, result):
    return {
        "url": target.get("url", ""),
        "description": target.get("description", ""),
        "selected_route": result.get("selected_route", ""),
        "selected_reason": result.get("selected_reason", ""),
        "risk_level": result.get("risk_level", ""),
        "risk_tag": result.get("risk_tag", ""),
        "direct_ok": result.get("direct_ok", ""),
        "http_proxy_ok": result.get("http_proxy_ok", ""),
        "socks5_ok": result.get("socks5_ok", ""),
        "http_attempts": ",".join("ok" if item else "fail" for item in result.get("http_attempts", [])),
        "details": " | ".join(result.get("details", [])),
    }


def persist_target_precheck_result(target, result, logger=None):
    runtime_writer = target.get("precheck_runtime_writer")
    if not runtime_writer or target.get("precheck_persisted"):
        return None
    row = build_precheck_row(target, result)
    path = append_precheck_runtime_row(row, runtime_writer, logger)
    target["precheck_persisted"] = True
    return path


def export_precheck_bundle(rows, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    all_file = os.path.join(output_dir, "00_全部结果.csv")
    export_precheck_csv(rows, all_file)

    def write_subset(filename, predicate):
        subset = [row for row in rows if predicate(row)]
        export_precheck_csv(subset, os.path.join(output_dir, filename))

    write_subset("01_HTTP代理优先.csv", lambda row: row.get("selected_route") == "http-proxy")
    write_subset("02_直连回退.csv", lambda row: row.get("selected_route") == "direct")
    write_subset("03_风险标记.csv", lambda row: row.get("risk_level") in {"medium", "high"})
    write_subset(
        "04_都不通.csv",
        lambda row: row.get("direct_ok") is not True and row.get("http_proxy_ok") is not True,
    )
    write_subset(
        "05_HTTP波动.csv",
        lambda row: row.get("risk_tag") == "http_proxy_flaky",
    )
    return [
        os.path.join(output_dir, "00_全部结果.csv"),
        os.path.join(output_dir, "01_HTTP代理优先.csv"),
        os.path.join(output_dir, "02_直连回退.csv"),
        os.path.join(output_dir, "03_风险标记.csv"),
        os.path.join(output_dir, "04_都不通.csv"),
        os.path.join(output_dir, "05_HTTP波动.csv"),
    ]


def export_precheck_results(rows, output_path):
    if output_path.lower().endswith(".csv"):
        try:
            export_precheck_csv(rows, output_path)
            return [os.path.abspath(output_path)]
        except PermissionError:
            root, ext = os.path.splitext(output_path)
            fallback_file = f"{root}.final_{datetime.now():%Y%m%d_%H%M%S}{ext or '.csv'}"
            export_precheck_csv(rows, fallback_file)
            return [os.path.abspath(fallback_file)]
    try:
        return [os.path.abspath(path) for path in export_precheck_bundle(rows, output_path)]
    except PermissionError:
        fallback_dir = f"{output_path}_final_{datetime.now():%Y%m%d_%H%M%S}"
        return [os.path.abspath(path) for path in export_precheck_bundle(rows, fallback_dir)]


def parse_csv_bool(value):
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"true", "1", "yes", "ok"}:
        return True
    if text in {"false", "0", "no", ""}:
        return False
    return None


def load_precheck_cache(cache_file):
    if not os.path.exists(cache_file):
        return {}

    cache_map = {}
    with open(cache_file, "r", encoding="utf-8-sig", newline="") as file_obj:
        reader = csv.DictReader(file_obj)
        for row in reader:
            url = normalize_address(row.get("url", ""))
            if not url:
                continue
            cache_map[url.lower()] = {
                "url": url,
                "description": row.get("description", ""),
                "selected_route": row.get("selected_route", "") or "direct",
                "selected_reason": row.get("selected_reason", "") or "命中预检缓存",
                "risk_level": row.get("risk_level", "") or "low",
                "risk_tag": row.get("risk_tag", ""),
                "direct_ok": parse_csv_bool(row.get("direct_ok", "")),
                "http_proxy_ok": parse_csv_bool(row.get("http_proxy_ok", "")),
                "socks5_ok": parse_csv_bool(row.get("socks5_ok", "")),
                "http_attempts": [item.strip() == "ok" for item in (row.get("http_attempts", "") or "").split(",") if item.strip()],
                "details": [part.strip() for part in (row.get("details", "") or "").split("|") if part.strip()],
            }
    return cache_map


def load_precheck_cache_bundle(output_path, logger=None):
    cache_map = {}
    source_files = []
    primary_csv = resolve_precheck_csv_path(output_path)
    legacy_sidecar = resolve_precheck_sidecar_csv_path(primary_csv)

    for candidate in [primary_csv, legacy_sidecar, *list_precheck_runtime_csv_files(output_path)]:
        if os.path.exists(candidate):
            try:
                cache_map.update(load_precheck_cache(candidate))
                source_files.append(candidate)
            except PermissionError as exc:
                if logger:
                    logger.warning("[CHECK-LOAD] 缓存文件正在被占用，已跳过: %s | %s", os.path.abspath(candidate), exc)
    return cache_map, source_files


def load_precheck_cache_tree(cache_root, logger=None):
    cache_map = {}
    source_files = []
    if not cache_root or not os.path.isdir(cache_root):
        return cache_map, source_files

    for current_root, _, files in os.walk(cache_root):
        for name in sorted(files):
            if not name.lower().endswith(".csv"):
                continue
            candidate = os.path.join(current_root, name)
            try:
                cache_map.update(load_precheck_cache(candidate))
                source_files.append(candidate)
            except PermissionError as exc:
                if logger:
                    logger.warning("[CHECK-LOAD] 缓存文件正在被占用，已跳过: %s | %s", os.path.abspath(candidate), exc)
    return cache_map, source_files


def resolve_sqlmap_proxy_for_url(url, sqlmap_proxy_mode, sqlmap_proxy, precheck_map):
    if sqlmap_proxy_mode == "off":
        return None, "proxy-mode=off"

    if sqlmap_proxy_mode == "inherit-precheck":
        cached = (precheck_map or {}).get(normalize_address(url).lower())
        if cached:
            selected_route = (cached.get("selected_route") or "direct").strip().lower()
            if selected_route == "http-proxy":
                return (sqlmap_proxy or None), "precheck:http-proxy"
            return None, "precheck:direct"

    if sqlmap_proxy:
        return sqlmap_proxy, "fixed"
    return None, "direct"


def precheck_cache_map_to_rows(cache_map):
    rows = []
    for item in cache_map.values():
        rows.append(
            {
                "url": item.get("url", ""),
                "description": item.get("description", ""),
                "selected_route": item.get("selected_route", ""),
                "selected_reason": item.get("selected_reason", ""),
                "risk_level": item.get("risk_level", ""),
                "risk_tag": item.get("risk_tag", ""),
                "direct_ok": item.get("direct_ok", ""),
                "http_proxy_ok": item.get("http_proxy_ok", ""),
                "socks5_ok": item.get("socks5_ok", ""),
                "http_attempts": ",".join("ok" if flag else "fail" for flag in item.get("http_attempts", [])),
                "details": " | ".join(item.get("details", [])),
            }
        )
    return rows


def should_use_cached_precheck(cached, args):
    if not cached:
        return False
    if args.scan_route == "http-proxy":
        return True
    selected_route = (cached.get("selected_route") or "direct").strip().lower()
    direct_ok = cached.get("direct_ok")
    if selected_route == "http-proxy" and direct_ok is True and not args.scan_http_proxy:
        return False
    return True


def resolve_group(client, group_ref, create_if_missing=False):
    if not group_ref:
        return None

    group = client.get_group(group_ref)
    if group:
        return group

    if create_if_missing:
        return client.create_group(group_ref)

    raise RuntimeError(f"未找到目标组: {group_ref}")


def parse_group_target_count(group):
    if not group:
        return 0

    for key in ("targets_count", "target_count"):
        value = group.get(key)
        if isinstance(value, int):
            return max(0, value)
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return 0


def wait_for_group_target_ids(client, group, logger=None, attempts=GROUP_SYNC_ATTEMPTS, delay_seconds=GROUP_SYNC_DELAY_SECONDS):
    group_id = group["group_id"]
    expected_count = parse_group_target_count(group)
    target_ids = client.list_group_target_ids(group_id)
    if expected_count <= 0 or len(target_ids) >= expected_count:
        return target_ids

    for attempt in range(2, max(1, attempts) + 1):
        if logger:
            logger.info(
                "[GROUP] 目标组成员尚未稳定: %s | current=%s expected=%s attempt=%s/%s",
                group.get("name"),
                len(target_ids),
                expected_count,
                attempt,
                attempts,
            )
        time.sleep(delay_seconds)
        target_ids = client.list_group_target_ids(group_id)
        if len(target_ids) >= expected_count:
            break

    return target_ids


def sync_group_targets(client, group, target_ids, logger=None, attempts=GROUP_SYNC_ATTEMPTS, delay_seconds=GROUP_SYNC_DELAY_SECONDS):
    if not group or not target_ids:
        return set()

    group_id = group["group_id"]
    desired_ids = list(dict.fromkeys(target_id for target_id in target_ids if target_id))
    current_ids = set()

    for attempt in range(1, max(1, attempts) + 1):
        current_ids = set(client.list_group_target_ids(group_id))
        missing_ids = [target_id for target_id in desired_ids if target_id not in current_ids]
        if not missing_ids:
            return current_ids

        if logger:
            logger.info(
                "[GROUP] 同步目标组成员: %s | expected=%s current=%s missing=%s attempt=%s/%s",
                group.get("name"),
                len(desired_ids),
                len(current_ids),
                len(missing_ids),
                attempt,
                attempts,
            )
        client.add_targets_to_group(group_id, missing_ids)
        if attempt < attempts:
            time.sleep(delay_seconds)

    return set(client.list_group_target_ids(group_id))


def export_group_sqlmap_bundle(
    client,
    group,
    output_dir,
    severity_name="critical",
    status_name="open",
    sqlmap_proxy="",
    sqlmap_proxy_mode="inherit-precheck",
    sqlmap_check_cache=None,
    sqlmap_force_ssl="off",
):
    query = build_vulnerability_query(group["group_id"], severity_name=severity_name, status_name=status_name)
    vulnerabilities = client.list_vulnerabilities(query=query, page_size=100)
    if sqlmap_check_cache:
        precheck_map, precheck_sources = load_precheck_cache_bundle(sqlmap_check_cache)
    else:
        sqlmap_check_cache = build_precheck_cache_root()
        precheck_map, precheck_sources = load_precheck_cache_tree(sqlmap_check_cache)

    os.makedirs(output_dir, exist_ok=True)
    request_dir = os.path.join(output_dir, "sqlmap_requests")
    sqlmap_output_dir = os.path.join(output_dir, "sqlmap_output")
    baseline_request_dir = os.path.join(output_dir, "sqlmap_requests_baseline")
    baseline_output_dir = os.path.join(output_dir, "sqlmap_output_baseline")
    os.makedirs(request_dir, exist_ok=True)
    os.makedirs(sqlmap_output_dir, exist_ok=True)
    os.makedirs(baseline_request_dir, exist_ok=True)
    os.makedirs(baseline_output_dir, exist_ok=True)
    for existing_name in os.listdir(request_dir):
        existing_path = os.path.join(request_dir, existing_name)
        if os.path.isfile(existing_path):
            os.remove(existing_path)
    for existing_name in os.listdir(baseline_request_dir):
        existing_path = os.path.join(baseline_request_dir, existing_name)
        if os.path.isfile(existing_path):
            os.remove(existing_path)

    summary_rows = []
    direct_rows = []
    manual_rows = []
    sqlmap_urls = []
    scatter_commands = []
    sqlmap_target_cache = {}
    seen_direct_keys = set()
    seen_manual_keys = set()
    seen_sqlmap_urls = set()

    sql_index = 0
    for vuln in vulnerabilities:
        detail = client.get_vulnerability(vuln["vuln_id"])
        severity_label = severity_to_name(detail.get("severity"))
        direct_ok, exploit_mode, reason = classify_direct_exploitability(detail)
        detail_text = strip_html_text(detail.get("details") or "")
        evidence = detail_text.splitlines()[0] if detail_text else strip_html_text(detail.get("description") or "")
        techniques = ",".join(detect_sqli_techniques(detail_text)) if is_sqli_vulnerability(detail) else ""

        row = {
            "group_name": group.get("name", ""),
            "group_id": group.get("group_id", ""),
            "severity": severity_label,
            "status": detail.get("status", ""),
            "confidence": detail.get("confidence", ""),
            "vuln_id": detail.get("vuln_id", ""),
            "vuln_name": detail.get("vt_name", ""),
            "url": detail.get("affects_url", ""),
            "parameter": detail.get("affects_detail", ""),
            "techniques": techniques,
            "direct_exploitable": "yes" if direct_ok else "no",
            "exploit_mode": exploit_mode,
            "reason": reason,
            "evidence": evidence,
            "request_file": "",
            "sqlmap_url": "",
            "sqlmap_command": "",
            "baseline_request_file": "",
            "baseline_sqlmap_url": "",
            "baseline_sqlmap_command": "",
            "effective_proxy": "",
            "proxy_source": "",
            "auto_string": "",
            "auto_not_string": "",
            "auto_string_source": "",
        }

        if is_sqli_vulnerability(detail):
            effective_proxy, proxy_source = resolve_sqlmap_proxy_for_url(
                detail.get("affects_url", ""),
                sqlmap_proxy_mode,
                sqlmap_proxy,
                precheck_map,
            )
            row["effective_proxy"] = effective_proxy or ""
            row["proxy_source"] = proxy_source
            _, normalized = build_sqlmap_command(
                "__REQUEST_FILE__",
                detail,
                "__OUTPUT_DIR__",
                proxy=effective_proxy,
                force_ssl_mode=sqlmap_force_ssl,
            )
            dedupe_key = (normalized["method"], normalized["full_url"], detail.get("affects_detail", ""))
            cached_sqlmap = sqlmap_target_cache.get(dedupe_key)

            if not cached_sqlmap:
                sql_index += 1
                request_name = f"{sql_index:03d}_{safe_filename(detail.get('vt_name') or 'sqli').lower()}_{safe_filename(detail.get('affects_detail') or 'path').lower()}_{detail.get('vuln_id')}.txt"
                request_file = os.path.join(request_dir, request_name)
                baseline_request_file = os.path.join(baseline_request_dir, request_name)
                output_name = f"{sql_index:03d}_{detail.get('vuln_id')}"
                output_path = os.path.join(sqlmap_output_dir, output_name)
                baseline_output_path = os.path.join(baseline_output_dir, output_name)
                request_file_rel = os.path.relpath(request_file, output_dir).replace("/", "\\")
                baseline_request_file_rel = os.path.relpath(baseline_request_file, output_dir).replace("/", "\\")
                output_path_rel = os.path.relpath(output_path, output_dir).replace("/", "\\")
                baseline_output_path_rel = os.path.relpath(baseline_output_path, output_dir).replace("/", "\\")
                sqlmap_command, normalized = build_sqlmap_command(
                    request_file_rel,
                    detail,
                    output_path_rel,
                    proxy=effective_proxy,
                    force_ssl_mode=sqlmap_force_ssl,
                )
                baseline_sqlmap_command, baseline_normalized = build_sqlmap_command(
                    baseline_request_file_rel,
                    detail,
                    baseline_output_path_rel,
                    proxy=effective_proxy,
                    force_ssl_mode=sqlmap_force_ssl,
                    baseline_value="1",
                )
                auto_string, auto_not_string, auto_string_source = resolve_auto_sqlmap_response_hint(
                    detail,
                    baseline_normalized,
                    normalized,
                    proxy=effective_proxy,
                )
                if auto_string or auto_not_string:
                    sqlmap_command, normalized = build_sqlmap_command(
                        request_file_rel,
                        detail,
                        output_path_rel,
                        proxy=effective_proxy,
                        force_ssl_mode=sqlmap_force_ssl,
                        string_hint=auto_string,
                        not_string_hint=auto_not_string,
                    )
                    baseline_sqlmap_command, baseline_normalized = build_sqlmap_command(
                        baseline_request_file_rel,
                        detail,
                        baseline_output_path_rel,
                        proxy=effective_proxy,
                        force_ssl_mode=sqlmap_force_ssl,
                        baseline_value="1",
                        string_hint=auto_string,
                        not_string_hint=auto_not_string,
                    )
                with open(request_file, "w", encoding="utf-8", newline="") as file_obj:
                    file_obj.write(normalized["request_text"])
                with open(baseline_request_file, "w", encoding="utf-8", newline="") as file_obj:
                    file_obj.write(baseline_normalized["request_text"])
                cached_sqlmap = {
                    "request_file": request_file_rel,
                    "sqlmap_url": normalized["full_url"],
                    "sqlmap_command": sqlmap_command,
                    "baseline_request_file": baseline_request_file_rel,
                    "baseline_sqlmap_url": baseline_normalized["full_url"],
                    "baseline_sqlmap_command": baseline_sqlmap_command,
                    "effective_proxy": effective_proxy or "",
                    "proxy_source": proxy_source,
                    "auto_string": auto_string or "",
                    "auto_not_string": auto_not_string or "",
                    "auto_string_source": auto_string_source,
                }
                sqlmap_target_cache[dedupe_key] = cached_sqlmap
                if normalized["full_url"] not in seen_sqlmap_urls:
                    sqlmap_urls.append(normalized["full_url"])
                    seen_sqlmap_urls.add(normalized["full_url"])
                scatter_commands.append(sqlmap_command)

            row["request_file"] = cached_sqlmap["request_file"]
            row["sqlmap_url"] = cached_sqlmap["sqlmap_url"]
            row["sqlmap_command"] = cached_sqlmap["sqlmap_command"]
            row["baseline_request_file"] = cached_sqlmap.get("baseline_request_file", "")
            row["baseline_sqlmap_url"] = cached_sqlmap.get("baseline_sqlmap_url", "")
            row["baseline_sqlmap_command"] = cached_sqlmap.get("baseline_sqlmap_command", "")
            row["effective_proxy"] = cached_sqlmap.get("effective_proxy", "")
            row["proxy_source"] = cached_sqlmap.get("proxy_source", "")
            row["auto_string"] = cached_sqlmap.get("auto_string", "")
            row["auto_not_string"] = cached_sqlmap.get("auto_not_string", "")
            row["auto_string_source"] = cached_sqlmap.get("auto_string_source", "")

        summary_rows.append(row)
        if direct_ok:
            direct_key = (row["vuln_name"], row["sqlmap_url"] or row["url"], row["parameter"], row["reason"])
            if direct_key not in seen_direct_keys:
                direct_rows.append(dict(row))
                seen_direct_keys.add(direct_key)
        else:
            manual_key = (row["vuln_name"], row["url"], row["parameter"], row["reason"])
            if manual_key not in seen_manual_keys:
                manual_rows.append(dict(row))
                seen_manual_keys.add(manual_key)

    fieldnames = [
        "group_name",
        "group_id",
        "severity",
        "status",
        "confidence",
        "vuln_id",
        "vuln_name",
        "url",
        "parameter",
        "techniques",
        "direct_exploitable",
        "exploit_mode",
        "reason",
        "evidence",
        "request_file",
        "sqlmap_url",
        "sqlmap_command",
        "baseline_request_file",
        "baseline_sqlmap_url",
        "baseline_sqlmap_command",
        "effective_proxy",
        "proxy_source",
        "auto_string",
        "auto_not_string",
        "auto_string_source",
    ]

    def write_csv(path, rows):
        with open(path, "w", encoding="utf-8-sig", newline="") as file_obj:
            writer = csv.DictWriter(file_obj, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    wizard_bat_file = os.path.join(output_dir, "00_START_HERE.bat")
    wizard_menu_file = os.path.join(output_dir, "00_MENU.txt")
    summary_file = os.path.join(output_dir, "00_vulnerability_summary.csv")
    direct_file = os.path.join(output_dir, "01_direct_exploitable.csv")
    manual_file = os.path.join(output_dir, "02_manual_review.csv")
    sqlmap_url_file = os.path.join(output_dir, "03_sqlmap_urls.txt")
    sqlmap_collection_bat_file = os.path.join(output_dir, "04_run_sqlmap_collection.bat")
    sqlmap_requests_bat_file = os.path.join(output_dir, "05_run_sqlmap_requests.bat")
    sqlmap_collection_txt_file = os.path.join(output_dir, "06_sqlmap_collection_command.txt")
    sqlmap_requests_txt_file = os.path.join(output_dir, "07_sqlmap_request_commands.txt")
    sqlmap_baseline_url_file = os.path.join(output_dir, "08_sqlmap_urls_baseline.txt")
    sqlmap_baseline_collection_bat_file = os.path.join(output_dir, "09_run_sqlmap_collection_baseline.bat")
    sqlmap_baseline_requests_bat_file = os.path.join(output_dir, "10_run_sqlmap_requests_baseline.bat")
    sqlmap_baseline_collection_txt_file = os.path.join(output_dir, "11_sqlmap_collection_baseline_command.txt")
    sqlmap_baseline_requests_txt_file = os.path.join(output_dir, "12_sqlmap_request_baseline_commands.txt")
    sqlmap_filter_hits_script_file = os.path.join(output_dir, "13_filter_sqlmap_hits.py")
    sqlmap_filter_hits_bat_file = os.path.join(output_dir, "14_run_filter_sqlmap_hits.bat")
    sqlmap_filter_hits_output_file = os.path.join(output_dir, "15_sqlmap_hit_candidates.txt")
    sqlmap_powershell_commands_file = os.path.join(output_dir, "16_sqlmap_request_commands_powershell.txt")
    sqlmap_cmd_commands_file = os.path.join(output_dir, "17_sqlmap_request_commands_cmd.txt")
    sqlmap_baseline_powershell_commands_file = os.path.join(output_dir, "18_sqlmap_request_baseline_commands_powershell.txt")
    sqlmap_baseline_cmd_commands_file = os.path.join(output_dir, "19_sqlmap_request_baseline_commands_cmd.txt")
    sqlmap_string_hint_file = os.path.join(output_dir, "20_sqlmap_string_hint.txt")
    sqlmap_followup_powershell_commands_file = os.path.join(output_dir, "21_sqlmap_followup_commands_powershell.txt")
    sqlmap_followup_cmd_commands_file = os.path.join(output_dir, "22_sqlmap_followup_commands_cmd.txt")
    readme_file = os.path.join(output_dir, "README.txt")

    write_csv(summary_file, summary_rows)
    write_csv(direct_file, direct_rows)
    write_csv(manual_file, manual_rows)
    with open(wizard_bat_file, "w", encoding="ascii", newline="") as file_obj:
        file_obj.write("\r\n".join(build_sqlmap_wizard_batch()) + "\r\n")
    with open(wizard_menu_file, "w", encoding="utf-8-sig", newline="\n") as file_obj:
        menu_lines = [
            "============================================================",
            "SQLMap " + "\u5feb\u901f\u5411\u5bfc",
            "============================================================",
            f"\u5de5\u4f5c\u76ee\u5f55: {os.path.abspath(output_dir)}",
            "",
            "  1. " + "\u8fd0\u884c\u8bf7\u6c42\u6a21\u5f0f\uff08\u6b21\u9009\uff09",
            "  2. " + "\u8fd0\u884c\u57fa\u7ebf\u8bf7\u6c42\u6a21\u5f0f\uff08\u63a8\u8350\uff09",
            "  3. " + "\u8fd0\u884c URL \u96c6\u5408\u6a21\u5f0f",
            "  4. " + "\u8fd0\u884c\u57fa\u7ebf URL \u96c6\u5408\u6a21\u5f0f",
            "  5. " + "\u8fc7\u6ee4 sqlmap \u547d\u4e2d\u7ed3\u679c",
            "  6. " + "\u663e\u793a PowerShell \u8bf7\u6c42\u547d\u4ee4",
            "  7. " + "\u663e\u793a CMD \u8bf7\u6c42\u547d\u4ee4",
            "  8. " + "\u663e\u793a --string \u4f7f\u7528\u8bf4\u660e",
            "  9. " + "\u663e\u793a sqlmap \u540e\u7eed\u679a\u4e3e\u547d\u4ee4",
            " 10. " + "\u67e5\u770b README",
            "  0. " + "\u9000\u51fa",
            "",
        ]
        file_obj.write("\n".join(menu_lines) + "\n")

    with open(sqlmap_url_file, "w", encoding="utf-8", newline="\n") as file_obj:
        for url in sqlmap_urls:
            file_obj.write(url + "\n")
    baseline_sqlmap_urls = []
    for item in sqlmap_target_cache.values():
        url = item.get("baseline_sqlmap_url", "")
        if url and url not in baseline_sqlmap_urls:
            baseline_sqlmap_urls.append(url)
    with open(sqlmap_baseline_url_file, "w", encoding="utf-8", newline="\n") as file_obj:
        for url in baseline_sqlmap_urls:
            file_obj.write(url + "\n")

    unique_effective_proxies = sorted({item.get("effective_proxy", "") for item in sqlmap_target_cache.values()})
    if len(unique_effective_proxies) == 1:
        collection_proxy = unique_effective_proxies[0] or None
    elif sqlmap_proxy_mode == "inherit-precheck":
        collection_proxy = None
    else:
        collection_proxy = sqlmap_proxy or None

    collection_command = build_sqlmap_url_command("03_sqlmap_urls.txt", "sqlmap_output_collection", proxy=collection_proxy)
    baseline_collection_command = build_sqlmap_url_command("08_sqlmap_urls_baseline.txt", r"sqlmap_output_baseline\collection", proxy=collection_proxy)
    collection_batch_lines = build_batch_header("SQLMap Collection Mode")
    collection_batch_lines.extend(
        [
            f"echo [INFO] Collection mode, {len(sqlmap_urls)} unique URLs.",
            collection_command,
            'set "RC=%ERRORLEVEL%"',
            "echo.",
            'echo [DONE] Collection mode finished, ExitCode=%RC%',
            "pause",
            "exit /b %RC%",
        ]
    )

    scatter_batch_lines = build_batch_header("SQLMap Request Mode")
    scatter_batch_lines.extend(
        [
            'set "FAIL_COUNT=0"',
            f"echo [INFO] Request mode, {len(scatter_commands)} unique requests.",
            "echo.",
        ]
    )
    for index, command in enumerate(scatter_commands, start=1):
        scatter_batch_lines.append(f"echo [RUN {index}/{len(scatter_commands)}] {command}")
        scatter_batch_lines.append(command)
        scatter_batch_lines.append("if errorlevel 1 set /a FAIL_COUNT+=1")
        scatter_batch_lines.append("echo.")
    scatter_batch_lines.extend(
        [
            'echo [DONE] Request mode finished, FailCount=%FAIL_COUNT%',
            "pause",
            "exit /b %FAIL_COUNT%",
        ]
    )
    baseline_scatter_commands = [item.get("baseline_sqlmap_command", "") for item in sqlmap_target_cache.values() if item.get("baseline_sqlmap_command")]
    followup_commands = []
    for item in sqlmap_target_cache.values():
        base_command = item.get("baseline_sqlmap_command") or item.get("sqlmap_command") or ""
        followup_commands.extend(build_sqlmap_followup_commands(base_command))
    baseline_scatter_batch_lines = build_batch_header("SQLMap Baseline Request Mode")
    baseline_scatter_batch_lines.extend(
        [
            'set "FAIL_COUNT=0"',
            f"echo [INFO] Baseline request mode, {len(baseline_scatter_commands)} unique requests.",
            "echo.",
        ]
    )
    for index, command in enumerate(baseline_scatter_commands, start=1):
        baseline_scatter_batch_lines.append(f"echo [RUN {index}/{len(baseline_scatter_commands)}] {command}")
        baseline_scatter_batch_lines.append(command)
        baseline_scatter_batch_lines.append("if errorlevel 1 set /a FAIL_COUNT+=1")
        baseline_scatter_batch_lines.append("echo.")
    baseline_scatter_batch_lines.extend(
        [
            'echo [DONE] Baseline request mode finished, FailCount=%FAIL_COUNT%',
            "pause",
            "exit /b %FAIL_COUNT%",
        ]
    )
    baseline_collection_batch_lines = build_batch_header("SQLMap Baseline Collection Mode")
    baseline_collection_batch_lines.extend(
        [
            f"echo [INFO] Baseline collection mode, {len(baseline_sqlmap_urls)} unique URLs.",
            baseline_collection_command,
            'set "RC=%ERRORLEVEL%"',
            "echo.",
            'echo [DONE] Baseline collection mode finished, ExitCode=%RC%',
            "pause",
            "exit /b %RC%",
        ]
    )

    with open(sqlmap_collection_bat_file, "w", encoding="utf-8", newline="") as file_obj:
        file_obj.write("\r\n".join(collection_batch_lines) + "\r\n")
    with open(sqlmap_requests_bat_file, "w", encoding="utf-8", newline="") as file_obj:
        file_obj.write("\r\n".join(scatter_batch_lines) + "\r\n")
    with open(sqlmap_baseline_collection_bat_file, "w", encoding="utf-8", newline="") as file_obj:
        file_obj.write("\r\n".join(baseline_collection_batch_lines) + "\r\n")
    with open(sqlmap_baseline_requests_bat_file, "w", encoding="utf-8", newline="") as file_obj:
        file_obj.write("\r\n".join(baseline_scatter_batch_lines) + "\r\n")
    with open(sqlmap_collection_txt_file, "w", encoding="utf-8-sig", newline="\n") as file_obj:
        file_obj.write(collection_command + "\n")
    with open(sqlmap_requests_txt_file, "w", encoding="utf-8-sig", newline="\n") as file_obj:
        file_obj.write("\n".join(scatter_commands) + "\n")
    with open(sqlmap_baseline_collection_txt_file, "w", encoding="utf-8-sig", newline="\n") as file_obj:
        file_obj.write(baseline_collection_command + "\n")
    with open(sqlmap_baseline_requests_txt_file, "w", encoding="utf-8-sig", newline="\n") as file_obj:
        file_obj.write("\n".join(baseline_scatter_commands) + "\n")
    with open(sqlmap_powershell_commands_file, "w", encoding="utf-8-sig", newline="\n") as file_obj:
        file_obj.write("\n\n".join(format_powershell_command(command) for command in scatter_commands) + "\n")
    with open(sqlmap_cmd_commands_file, "w", encoding="utf-8-sig", newline="\n") as file_obj:
        file_obj.write("\n".join(scatter_commands) + "\n")
    with open(sqlmap_baseline_powershell_commands_file, "w", encoding="utf-8-sig", newline="\n") as file_obj:
        file_obj.write("\n\n".join(format_powershell_command(command) for command in baseline_scatter_commands) + "\n")
    with open(sqlmap_baseline_cmd_commands_file, "w", encoding="utf-8-sig", newline="\n") as file_obj:
        file_obj.write("\n".join(baseline_scatter_commands) + "\n")
    with open(sqlmap_followup_powershell_commands_file, "w", encoding="utf-8-sig", newline="\n") as file_obj:
        file_obj.write("\n\n".join(format_powershell_command(command) for command in followup_commands) + "\n")
    with open(sqlmap_followup_cmd_commands_file, "w", encoding="utf-8-sig", newline="\n") as file_obj:
        file_obj.write("\n".join(followup_commands) + "\n")
    with open(sqlmap_string_hint_file, "w", encoding="utf-8-sig", newline="\n") as file_obj:
        file_obj.write(SQLMAP_STRING_HINT_TEXT)

    filter_script = f'''import csv
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SUMMARY_CSV = ROOT / "00_vulnerability_summary.csv"
OUTPUT_TXT = ROOT / "15_sqlmap_hit_candidates.txt"
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


def load_summary_rows():
    rows = []
    if not SUMMARY_CSV.exists():
        return rows
    with SUMMARY_CSV.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        rows.extend(reader)
    return rows


def build_request_maps(rows):
    req_map = {{}}
    baseline_req_map = {{}}
    for row in rows:
        sqlmap_command = row.get("sqlmap_command") or ""
        baseline_sqlmap_command = row.get("baseline_sqlmap_command") or ""
        match = re.search(r'--output-dir\\s+"([^"]+)"', sqlmap_command)
        if match:
            key = Path(match.group(1).replace("/", "\\\\")).name
            req_map[key] = row
        match = re.search(r'--output-dir\\s+"([^"]+)"', baseline_sqlmap_command)
        if match:
            key = Path(match.group(1).replace("/", "\\\\")).name
            baseline_req_map[key] = row
    return req_map, baseline_req_map


def append_hit(lines, host, source, command):
    lines.append(str(host))
    lines.append(source)
    lines.append(command or "")
    lines.append("")


def scan_request_side(root_name, request_map, command_field, source_name, lines):
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
                append_hit(lines, host_dir.name, source_name, row.get(command_field, ""))


def scan_collection_side(root_name, source_name, command_text, lines):
    output_root = ROOT / root_name
    if not output_root.exists():
        return
    for host_dir in sorted(output_root.iterdir()):
        if not host_dir.is_dir():
            continue
        if dir_has_signal(host_dir):
            append_hit(lines, host_dir.name, source_name, command_text)


def main():
    rows = load_summary_rows()
    req_map, baseline_req_map = build_request_maps(rows)
    lines = []
    scan_request_side("sqlmap_output", req_map, "sqlmap_command", "request", lines)
    scan_request_side("sqlmap_output_baseline", baseline_req_map, "baseline_sqlmap_command", "request-baseline", lines)
    scan_collection_side("sqlmap_output_collection", "collection", COLLECTION_CMD, lines)
    scan_collection_side(os.path.join("sqlmap_output_baseline", "collection"), "collection-baseline", BASELINE_COLLECTION_CMD, lines)
    OUTPUT_TXT.write_text("\\n".join(lines).rstrip() + ("\\n" if lines else ""), encoding="utf-8")
    print(f"[DONE] wrote {{OUTPUT_TXT}}")


if __name__ == "__main__":
    main()
'''
    with open(sqlmap_filter_hits_script_file, "w", encoding="utf-8", newline="\n") as file_obj:
        file_obj.write(filter_script)
    with open(sqlmap_filter_hits_bat_file, "w", encoding="ascii", newline="") as file_obj:
        file_obj.write(
            "\r\n".join(
                build_batch_header("SQLMap Hit Filter")
                + [
                    'python "13_filter_sqlmap_hits.py"',
                    'set "RC=%ERRORLEVEL%"',
                    "echo.",
                    'echo [DONE] Filter finished, ExitCode=%RC%',
                    "pause",
                    "exit /b %RC%",
                ]
            )
            + "\r\n"
        )

    with open(sqlmap_string_hint_file, "w", encoding="utf-8-sig", newline="\n") as file_obj:
        file_obj.write(SQLMAP_STRING_HINT_TEXT)

    linux_dir = build_linux_sqlmap_bundle(
        output_dir,
        summary_file,
        direct_file,
        manual_file,
        sqlmap_url_file,
        sqlmap_baseline_url_file,
        sqlmap_filter_hits_script_file,
        [
            sqlmap_powershell_commands_file,
            sqlmap_cmd_commands_file,
            sqlmap_baseline_powershell_commands_file,
            sqlmap_baseline_cmd_commands_file,
            sqlmap_string_hint_file,
            sqlmap_followup_powershell_commands_file,
            sqlmap_followup_cmd_commands_file,
        ],
        scatter_commands,
        baseline_scatter_commands,
        collection_command,
        baseline_collection_command,
        request_dir,
        baseline_request_dir,
    )

    with open(readme_file, "w", encoding="utf-8-sig", newline="\n") as file_obj:
        file_obj.write(
            "\n".join(
                [
                    f"group_name={group.get('name', '')}",
                    f"group_id={group.get('group_id', '')}",
                    f"severity_filter={severity_name}",
                    f"status_filter={status_name}",
                    f"sqlmap_proxy_mode={sqlmap_proxy_mode}",
                    f"sqlmap_proxy={sqlmap_proxy or '-'}",
                    f"sqlmap_force_ssl={sqlmap_force_ssl}",
                    "sqlmap_force_ssl_note=auto adds --force-ssl for HTTPS request-mode exports; HTTP requests stay unchanged",
                    f"sqlmap_check_cache={sqlmap_check_cache or '-'}",
                    f"precheck_sources={len(precheck_sources)}",
                    f"collection_proxy={collection_proxy or '-'}",
                    f"total_vulnerabilities={len(summary_rows)}",
                    f"sql_injection_count={len(sqlmap_target_cache)}",
                    f"direct_exploitable_count={len(direct_rows)}",
                    f"auto_string_count={sum(1 for item in sqlmap_target_cache.values() if item.get('auto_string'))}",
                    f"auto_not_string_count={sum(1 for item in sqlmap_target_cache.values() if item.get('auto_not_string'))}",
                    "",
                    "Start here:",
                    "  double-click 00_START_HERE.bat",
                    "",
                    "Files:",
                    "  00_START_HERE.bat              interactive Windows menu",
                    "  00_vulnerability_summary.csv   all findings in scope",
                    "  01_direct_exploitable.csv      findings suitable for direct follow-up",
                    "  02_manual_review.csv           findings that should be reviewed manually",
                    "  03_sqlmap_urls.txt             original URLs for sqlmap -m",
                    "  04_run_sqlmap_collection.bat   collection mode, single sqlmap -m run",
                    "  05_run_sqlmap_requests.bat     secondary request mode, one normalized request at a time",
                    "  06_sqlmap_collection_command.txt  collection command in plain text",
                    "  07_sqlmap_request_commands.txt    request commands in plain text",
                    "  sqlmap_requests\\*.txt         one normalized raw request per SQLi (no * replacement)",
                    "  08_sqlmap_urls_baseline.txt    baseline URLs for sqlmap -m",
                    "  09_run_sqlmap_collection_baseline.bat  baseline collection mode",
                    "  10_run_sqlmap_requests_baseline.bat    recommended baseline request mode",
                    "  11_sqlmap_collection_baseline_command.txt baseline collection command",
                    "  12_sqlmap_request_baseline_commands.txt baseline request commands",
                    "  sqlmap_requests_baseline\\*.txt baseline raw requests",
                    "  sqlmap_output_baseline\\       baseline output root",
                    "  13_filter_sqlmap_hits.py      filter script for non-empty sqlmap log files",
                    "  14_run_filter_sqlmap_hits.bat run the filter script",
                    "  15_sqlmap_hit_candidates.txt  filtered candidates: host / source / command",
                    "  16_sqlmap_request_commands_powershell.txt  secondary PowerShell request commands",
                    "  17_sqlmap_request_commands_cmd.txt         secondary CMD request commands",
                    "  18_sqlmap_request_baseline_commands_powershell.txt  recommended PowerShell baseline commands",
                    "  19_sqlmap_request_baseline_commands_cmd.txt         recommended CMD baseline commands",
                    "  20_sqlmap_string_hint.txt          boolean SQLi --string/--not-string guidance",
                    "  21_sqlmap_followup_commands_powershell.txt  follow-up enumeration commands",
                    "  22_sqlmap_followup_commands_cmd.txt         CMD follow-up enumeration commands",
                    "  linux\\                    Linux runnable copy with .sh scripts and '/' paths",
                    "",
                    "Suggested usage:",
                    '  double-click 09_run_sqlmap_collection_baseline.bat',
                    '  double-click 10_run_sqlmap_requests_baseline.bat',
                    '  double-click 05_run_sqlmap_requests.bat',
                    '  double-click 04_run_sqlmap_collection.bat',
                    '  double-click 14_run_filter_sqlmap_hits.bat',
                    '  prefer 2 first; use 1 when baseline is noisy or unavailable',
                    '  use 21/22 after sqlmap confirms injection and you know the DB name',
                    '  use 20 when sqlmap needs a stable TRUE/FALSE discriminator',
                    '  use --tables for table listing; -T needs a table name',
                ]
            )
            + "\n"
        )

    return {
        "query": query,
        "wizard_bat_file": wizard_bat_file,
        "summary_file": summary_file,
        "direct_file": direct_file,
        "manual_file": manual_file,
        "sqlmap_url_file": sqlmap_url_file,
        "sqlmap_collection_bat_file": sqlmap_collection_bat_file,
        "sqlmap_requests_bat_file": sqlmap_requests_bat_file,
        "sqlmap_collection_txt_file": sqlmap_collection_txt_file,
        "sqlmap_requests_txt_file": sqlmap_requests_txt_file,
        "request_dir": request_dir,
        "baseline_request_dir": baseline_request_dir,
        "baseline_output_dir": baseline_output_dir,
        "sqlmap_baseline_url_file": sqlmap_baseline_url_file,
        "sqlmap_baseline_collection_bat_file": sqlmap_baseline_collection_bat_file,
        "sqlmap_baseline_requests_bat_file": sqlmap_baseline_requests_bat_file,
        "sqlmap_baseline_collection_txt_file": sqlmap_baseline_collection_txt_file,
        "sqlmap_baseline_requests_txt_file": sqlmap_baseline_requests_txt_file,
        "sqlmap_filter_hits_script_file": sqlmap_filter_hits_script_file,
        "sqlmap_filter_hits_bat_file": sqlmap_filter_hits_bat_file,
        "sqlmap_filter_hits_output_file": sqlmap_filter_hits_output_file,
        "sqlmap_powershell_commands_file": sqlmap_powershell_commands_file,
        "sqlmap_cmd_commands_file": sqlmap_cmd_commands_file,
        "sqlmap_baseline_powershell_commands_file": sqlmap_baseline_powershell_commands_file,
        "sqlmap_baseline_cmd_commands_file": sqlmap_baseline_cmd_commands_file,
        "sqlmap_string_hint_file": sqlmap_string_hint_file,
        "sqlmap_followup_powershell_commands_file": sqlmap_followup_powershell_commands_file,
        "sqlmap_followup_cmd_commands_file": sqlmap_followup_cmd_commands_file,
        "linux_dir": linux_dir,
        "readme_file": readme_file,
        "sql_request_count": len(sqlmap_target_cache),
        "total_count": len(summary_rows),
        "direct_count": len(direct_rows),
        "manual_count": len(manual_rows),
    }


def tcp_connect_test(host, port, timeout):
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.close()


def direct_http_response_test(target, timeout):
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*",
        "Connection": "close",
    }
    last_error = None
    for method in ("HEAD", "GET"):
        try:
            response = requests.request(
                method,
                target["address"],
                headers=headers,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            if response.status_code:
                return
        except requests.RequestException as exc:
            last_error = exc
    raise RuntimeError(f"http response failed: {last_error}")


def run_projectdiscovery_httpx(hosts, timeout, logger=None):
    executable = shutil.which("httpx") or shutil.which("httpx.exe")
    if not executable:
        return {}, "httpx executable not found"

    try:
        help_result = subprocess.run(
            [executable, "-h"],
            capture_output=True,
            text=True,
            timeout=8,
            encoding="utf-8",
            errors="replace",
        )
    except Exception as exc:
        return {}, f"httpx help failed: {exc}"
    help_text = (help_result.stdout or "") + (help_result.stderr or "")
    if "projectdiscovery" not in help_text.lower() and "-silent" not in help_text:
        return {}, "httpx executable is not ProjectDiscovery httpx"

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".txt") as file_obj:
        input_path = file_obj.name
        for host in hosts:
            file_obj.write(host + "\n")

    command = [
        executable,
        "-l",
        input_path,
        "-silent",
        "-no-color",
        "-timeout",
        str(max(1, int(timeout))),
        "-retries",
        "1",
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=max(15, int(timeout * max(4, len(hosts))) + 10),
            encoding="utf-8",
            errors="replace",
        )
    except Exception as exc:
        return {}, f"httpx run failed: {exc}"
    finally:
        try:
            os.unlink(input_path)
        except OSError:
            pass

    if logger and completed.stderr.strip():
        logger.info("[HTTPX] stderr=%s", completed.stderr.strip()[:500])

    results = {}
    for line in (completed.stdout or "").splitlines():
        url = normalize_address(line.split()[0] if line.split() else "")
        if not url.startswith(("http://", "https://")):
            continue
        endpoint = parse_target_endpoint(url)
        key = endpoint["host"].lower()
        results.setdefault(key, url)
        host_port_key = f"{endpoint['host'].lower()}:{endpoint['port']}"
        results.setdefault(host_port_key, url)
    return results, ""


def fallback_httpx_probe_host(host_value, timeout):
    candidates = []
    host, port = split_host_port(host_value)
    if port is not None:
        for scheme in ("https", "http"):
            candidates.append(f"{scheme}://{host}:{port}")
    else:
        candidates.extend([f"https://{host}", f"http://{host}"])

    for candidate in candidates:
        try:
            endpoint = parse_target_endpoint(candidate)
            direct_http_response_test(endpoint, timeout)
            return candidate
        except Exception:
            continue
    return None


def httpx_probe_hosts(hosts, timeout, logger=None):
    clean_hosts = []
    seen = set()
    for host in hosts:
        host = normalize_address(host)
        if not host:
            continue
        key = host.lower()
        if key in seen:
            continue
        seen.add(key)
        clean_hosts.append(host)

    if not clean_hosts:
        return {}, "empty host list"

    results, reason = run_projectdiscovery_httpx(clean_hosts, timeout, logger)
    missing_hosts = [host for host in clean_hosts if host.lower() not in results]
    for host in missing_hosts:
        fallback_url = fallback_httpx_probe_host(host, timeout)
        if fallback_url:
            results[host.lower()] = fallback_url
            endpoint = parse_target_endpoint(fallback_url)
            results.setdefault(endpoint["host"].lower(), fallback_url)
            results.setdefault(f"{endpoint['host'].lower()}:{endpoint['port']}", fallback_url)

    return results, reason


def should_probe_asset_before_create(raw_target, normalized_url):
    raw_value = normalize_address(raw_target)
    if not raw_value:
        return False
    if not raw_value.startswith(("http://", "https://")):
        return True
    try:
        raw_endpoint = parse_target_endpoint(raw_value)
        normalized_endpoint = parse_target_endpoint(normalized_url)
        return raw_endpoint["scheme"] != normalized_endpoint["scheme"]
    except Exception:
        return True


def resolve_asset_before_create(entry, args, logger):
    original_url = entry["address"]
    raw_target = entry.get("raw_target") or entry.get("raw") or original_url
    resolved = {
        "url": original_url,
        "status": "as_is",
        "reason": "normalized",
        "details": [],
    }

    if not args.asset_resolve:
        return resolved

    probe_host = extract_httpx_probe_host(raw_target) or extract_httpx_probe_host(original_url)
    if not probe_host:
        return resolved

    endpoint = parse_target_endpoint(original_url)
    as_is_ok = False
    if raw_target.startswith(("http://", "https://")) or not should_probe_asset_before_create(raw_target, original_url):
        try:
            direct_http_response_test(endpoint, args.precheck_timeout)
            as_is_ok = True
            resolved["reason"] = "as-is reachable"
            resolved["details"].append("as-is=ok")
        except Exception as exc:
            resolved["details"].append(f"as-is=fail:{exc}")

    if as_is_ok:
        return resolved

    httpx_results, httpx_reason = httpx_probe_hosts([probe_host], args.httpx_timeout, logger)
    if httpx_reason:
        resolved["details"].append(f"httpx-note:{httpx_reason}")
    httpx_url = httpx_results.get(probe_host.lower())
    if not httpx_url:
        lookup_keys = [endpoint["host"].lower(), f"{endpoint['host'].lower()}:{endpoint['port']}"]
        httpx_url = next((httpx_results.get(key) for key in lookup_keys if httpx_results.get(key)), None)

    if httpx_url:
        resolved["url"] = httpx_url
        resolved["status"] = "rewritten" if normalize_address(httpx_url).lower() != normalize_address(original_url).lower() else "confirmed"
        resolved["reason"] = "httpx reachable"
        resolved["details"].append(f"httpx=ok:{httpx_url}")
        return resolved

    resolved["status"] = "dead"
    resolved["reason"] = "httpx no alive url"
    resolved["details"].append(f"httpx=fail:{resolved['reason']}")
    return resolved


def http_proxy_connect_test(proxy_host, proxy_port, target, timeout):
    with socket.create_connection((proxy_host, proxy_port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        if target["scheme"] == "https":
            request = (
                f"CONNECT {target['host']}:{target['port']} HTTP/1.1\r\n"
                f"Host: {target['host']}:{target['port']}\r\n"
                "Proxy-Connection: Keep-Alive\r\n\r\n"
            )
        else:
            request = (
                f"HEAD {target['address']} HTTP/1.1\r\n"
                f"Host: {target['host']}:{target['port']}\r\n"
                "Connection: close\r\n\r\n"
            )
        sock.sendall(request.encode("ascii", errors="ignore"))
        response = sock.recv(1024).decode("latin1", errors="ignore")

    if " 200 " not in response and " 301 " not in response and " 302 " not in response and "HTTP/" not in response:
        raise RuntimeError(f"http proxy 返回异常: {response[:120]}")


def socks5_connect_test(proxy_host, proxy_port, target, timeout):
    host_bytes = target["host"].encode("idna")
    if len(host_bytes) > 255:
        raise RuntimeError("目标主机名过长，无法通过 socks5 探测")

    with socket.create_connection((proxy_host, proxy_port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        greeting = sock.recv(2)
        if greeting != b"\x05\x00":
            raise RuntimeError(f"socks5 握手失败: {greeting!r}")

        request = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + target["port"].to_bytes(2, "big")
        sock.sendall(request)
        reply = sock.recv(10)
        if len(reply) < 2 or reply[1] != 0x00:
            code = reply[1] if len(reply) > 1 else None
            raise RuntimeError(f"socks5 CONNECT 失败: code={code}")


def run_precheck(target, args, logger):
    endpoint = parse_target_endpoint(target["url"])
    result = {
        "selected_route": args.scan_route,
        "selected_reason": "",
        "risk_level": "low",
        "risk_tag": "",
        "direct_ok": None,
        "http_proxy_ok": None,
        "socks5_ok": None,
        "http_attempts": [],
        "details": [],
    }
    progress = target.get("precheck_progress") or {}
    progress_prefix = ""
    if progress:
        progress_prefix = (
            f"[{progress.get('index', 0)}/{progress.get('total', 0)} "
            f"{progress.get('percent', 0.0):.1f}% "
            f"elapsed={progress.get('elapsed_text', '0s')} "
            f"avg={progress.get('avg_text', '0s')} "
            f"eta={progress.get('eta_text', '0s')}] "
        )

    logger.info(
        "[PRECHECK-START] %sURL=%s target=%s:%s route=%s timeout=%.2fs http_attempts=%s socks5=%s",
        progress_prefix,
        target["url"],
        endpoint["host"],
        endpoint["port"],
        args.scan_route,
        args.precheck_timeout,
        args.precheck_http_attempts if args.scan_http_proxy else 0,
        args.precheck_socks5 or "-",
    )

    def probe(name, fn):
        started = time.time()
        try:
            fn()
            cost = time.time() - started
            detail = f"{name}=ok({cost:.2f}s)"
            result["details"].append(detail)
            logger.info("[PRECHECK-STEP] URL=%s %s", target["url"], detail)
            return True
        except Exception as exc:
            cost = time.time() - started
            detail = f"{name}=fail({cost:.2f}s:{exc})"
            result["details"].append(detail)
            logger.info("[PRECHECK-STEP] URL=%s %s", target["url"], detail)
            return False

    def probe_many(name_prefix, fn, attempts):
        outcomes = []
        for index in range(1, attempts + 1):
            started = time.time()
            try:
                fn()
                cost = time.time() - started
                detail = f"{name_prefix}#{index}=ok({cost:.2f}s)"
                result["details"].append(detail)
                logger.info("[PRECHECK-STEP] URL=%s %s", target["url"], detail)
                outcomes.append(True)
            except Exception as exc:
                cost = time.time() - started
                detail = f"{name_prefix}#{index}=fail({cost:.2f}s:{exc})"
                result["details"].append(detail)
                logger.info("[PRECHECK-STEP] URL=%s %s", target["url"], detail)
                outcomes.append(False)
        return outcomes

    if args.precheck:
        result["direct_ok"] = probe("direct-http", lambda: direct_http_response_test(endpoint, args.precheck_timeout))
        if args.scan_http_proxy:
            http_proxy = parse_proxy_endpoint(args.scan_http_proxy)
            result["http_attempts"] = probe_many(
                f"http-proxy:{http_proxy['raw']}",
                lambda: http_proxy_connect_test(http_proxy["host"], http_proxy["port"], endpoint, args.precheck_timeout),
                args.precheck_http_attempts,
            )
            result["http_proxy_ok"] = any(result["http_attempts"])

        if args.precheck_socks5:
            socks5_proxy = parse_proxy_endpoint(args.precheck_socks5)
            result["socks5_ok"] = probe(
                f"socks5:{socks5_proxy['raw']}",
                lambda: socks5_connect_test(socks5_proxy["host"], socks5_proxy["port"], endpoint, args.precheck_timeout),
            )

        if args.httpx_precheck_fallback and result["direct_ok"] is not True and result["http_proxy_ok"] is not True:
            probe_host = f"{endpoint['host']}:{endpoint['port']}" if endpoint.get("explicit_port") else endpoint["host"]
            httpx_results, httpx_reason = httpx_probe_hosts([probe_host], args.httpx_timeout, logger)
            httpx_url = httpx_results.get(probe_host.lower()) or httpx_results.get(endpoint["host"].lower())
            if httpx_url:
                result["details"].append(f"httpx-fallback=ok:{httpx_url}")
                logger.info("[HTTPX] precheck fallback URL=%s -> %s", target["url"], httpx_url)
                if normalize_address(target["url"]).lower() != httpx_url.lower():
                    old_url = target["url"]
                    target["url"] = httpx_url
                    endpoint = parse_target_endpoint(target["url"])
                    result["details"].append(f"httpx-rewrite={old_url}->{httpx_url}")
                result["direct_ok"] = probe("direct-http-after-httpx", lambda: direct_http_response_test(endpoint, args.precheck_timeout))
            else:
                result["details"].append(f"httpx-fallback=fail:{httpx_reason or 'no alive url'}")
                logger.info("[HTTPX] precheck fallback failed URL=%s reason=%s", target["url"], httpx_reason or "no alive url")

    if result["http_attempts"]:
        has_success = any(result["http_attempts"])
        has_fail = any(not item for item in result["http_attempts"])
        if has_success and has_fail:
            result["risk_level"] = "high"
            result["risk_tag"] = "http_proxy_flaky"
        elif not has_success and result["socks5_ok"] is True:
            result["risk_level"] = "medium"
            result["risk_tag"] = "http_proxy_failed_but_socks_ok"

    if args.scan_route == "direct":
        result["selected_route"] = "direct"
        result["selected_reason"] = "用户指定直连"
    elif args.scan_route == "http-proxy":
        result["selected_route"] = "http-proxy"
        result["selected_reason"] = "用户指定 HTTP 代理"
    else:
        if args.scan_http_proxy and result["http_proxy_ok"] is True:
            result["selected_route"] = "http-proxy"
            if result["risk_tag"] == "http_proxy_flaky":
                if result["direct_ok"] is True:
                    result["selected_reason"] = "直连和 HTTP 代理都可用，--aproxy 指定代理优先；代理不稳定，标记高风控"
                else:
                    result["selected_reason"] = "直连失败，HTTP 代理有成功但不稳定，标记高风控"
            else:
                if result["direct_ok"] is True:
                    result["selected_reason"] = "直连和 HTTP 代理都可用，--aproxy 指定代理优先"
                else:
                    result["selected_reason"] = "直连失败，HTTP 代理可用"
        elif result["direct_ok"] is True:
            result["selected_route"] = "direct"
            if args.scan_http_proxy:
                result["selected_reason"] = "HTTP 代理不可用，回退直连"
            else:
                result["selected_reason"] = "直连可用，未启用代理探测"
        elif result["http_proxy_ok"] is False:
            result["selected_route"] = "direct"
            result["selected_reason"] = "直连和 HTTP 代理都不可用，auto 保守回退直连"
        else:
            result["selected_route"] = "direct"
            result["selected_reason"] = "预检结果不完整，保守回退直连"

    if args.precheck and (args.enforce_precheck or not args.allow_unreachable_scan):
        allowed = []
        if result["selected_route"] == "http-proxy":
            allowed.append(result["http_proxy_ok"] is True)
        else:
            allowed.append(result["direct_ok"] is True)
        if not any(allowed):
            return False, result

    logger.info(
        "[PRECHECK] %sURL=%s route=%s reason=%s risk=%s/%s details=%s",
        progress_prefix,
        target["url"],
        result["selected_route"],
        result["selected_reason"] or "-",
        result["risk_level"],
        result["risk_tag"] or "-",
        "; ".join(result["details"]) if result["details"] else "disabled",
    )
    return True, result


def has_auto_login_config(args):
    return bool((args.login_url or "").strip() and (args.login_username or "").strip() and (args.login_password or "").strip())


def resolve_login_url(args, target):
    login_url = (args.login_url or "").strip()
    if login_url:
        return login_url
    return (target.get("url") or "").strip()


def ensure_target_login(client, args, logger, target):
    if target.get("login_ready"):
        return True

    if args.login_sequence:
        try:
            client.upload_target_login_sequence(target["id"], args.login_sequence)
            logger.info("[LOGIN] 已配置 Target Login Sequence: %s | lsr=%s", target["url"], os.path.abspath(args.login_sequence))
            target["login_error"] = ""
            target["login_ready"] = True
            return True
        except Exception as exc:
            target["login_error"] = str(exc)
            logger.error("[LOGIN] 配置 Target Login Sequence 失败: %s | %s", target["url"], exc)
            return False

    if not has_auto_login_config(args):
        target["login_error"] = ""
        target["login_ready"] = True
        return True

    try:
        login_url = resolve_login_url(args, target)
        client.configure_target_auto_login(
            target["id"],
            login_url=login_url,
            username=args.login_username.strip(),
            password=args.login_password,
        )
        logger.info("[LOGIN] 已配置 Target 自动登录: %s | login_url=%s | username=%s", target["url"], login_url, args.login_username.strip())
        target["login_error"] = ""
        target["login_ready"] = True
        return True
    except Exception as exc:
        target["login_error"] = str(exc)
        logger.error("[LOGIN] 配置 Target 自动登录失败: %s | %s", target["url"], exc)
        return False


def ensure_target_route(client, args, logger, target):
    if target.get("route_ready"):
        return True

    original_url = target.get("url")
    if not args.route_by_target:
        target["selected_route"] = args.scan_route
        target["precheck"] = {
            "selected_route": args.scan_route,
            "selected_reason": "关闭 route-by-target，整次任务按固定路由执行",
            "details": ["route-by-target=disabled"],
        }
        logger.info("[ROUTE] route-by-target=off URL=%s fixed_route=%s", target["url"], args.scan_route)
    else:
        cached = target.get("cached_precheck")
        if args.use_check_cache and should_use_cached_precheck(cached, args):
            target["precheck"] = cached
            target["selected_route"] = cached.get("selected_route", "direct")
            logger.info(
                "[CHECK-CACHE] URL=%s route=%s reason=%s",
                target["url"],
                target["selected_route"],
                cached.get("selected_reason", "命中预检缓存"),
            )
            if args.precheck and not args.allow_unreachable_scan:
                cached_ok = cached.get("http_proxy_ok") is True if target["selected_route"] == "http-proxy" else cached.get("direct_ok") is True
                if not cached_ok:
                    logger.error("[ROUTE] cached precheck is unreachable, skip target: %s | route=%s | details=%s", target["url"], target["selected_route"], "; ".join(cached.get("details") or []))
                    return False
        else:
            if args.use_check_cache and cached:
                logger.info(
                    "[CHECK-CACHE] 忽略旧代理优先缓存，重新预检直连优先策略: URL=%s cached_route=%s",
                    target["url"],
                    cached.get("selected_route", "-"),
                )
            ok, result = run_precheck(target, args, logger)
            target["precheck"] = result
            target["selected_route"] = result["selected_route"]
            persisted_path = persist_target_precheck_result(target, result, logger)
            if persisted_path:
                logger.info("[CHECK-SAVE] 已保存实时预检结果: %s", os.path.abspath(persisted_path))

            if not ok:
                logger.error("[ROUTE] precheck failed, skip unreachable target: %s | reason=%s | details=%s", target["url"], result.get("selected_reason", "-"), "; ".join(result.get("details") or []))
                return False

    if original_url and target.get("url") and normalize_address(original_url).lower() != normalize_address(target["url"]).lower():
        try:
            client.update_target_address(target["id"], target["url"], target.get("description", ""))
            logger.info("[HTTPX] 已同步 AWVS Target 地址: %s -> %s", original_url, target["url"])
        except Exception as exc:
            target["route_error"] = str(exc)
            logger.error("[HTTPX] 同步 AWVS Target 地址失败: %s -> %s | %s", original_url, target["url"], exc)
            return False

    if target["selected_route"] == "http-proxy":
        if not args.scan_http_proxy:
            target["route_error"] = "选择了 HTTP 代理，但未提供 --scan-http-proxy"
            logger.error("[ROUTE] 目标 %s 选择了 HTTP 代理，但未提供 --scan-http-proxy", target["url"])
            return False
        proxy = parse_proxy_endpoint(args.scan_http_proxy)
        try:
            client.configure_target_proxy(
                target["id"],
                enabled=True,
                proxy_host=proxy["host"],
                proxy_port=proxy["port"],
                username=args.scan_proxy_username,
                password=args.scan_proxy_password,
            )
            logger.info(
                "[ROUTE] 已配置 Target 走 HTTP 代理: %s -> %s | reason=%s",
                target["url"],
                proxy["raw"],
                target["precheck"].get("selected_reason", "-"),
            )
            target["route_error"] = ""
        except Exception as exc:
            target["route_error"] = str(exc)
            logger.error("[ROUTE] 配置 HTTP 代理失败: %s | %s", target["url"], exc)
            return False
    else:
        try:
            client.configure_target_proxy(target["id"], enabled=False)
            logger.info(
                "[ROUTE] 已配置 Target 直连: %s | reason=%s",
                target["url"],
                target["precheck"].get("selected_reason", "-"),
            )
            target["route_error"] = ""
        except Exception as exc:
            target["route_error"] = str(exc)
            logger.error("[ROUTE] 清理 Target 代理失败: %s | %s", target["url"], exc)
            return False

    target["route_ready"] = True
    return True


def prepare_targets_from_file(client, args, logger):
    entries, skipped = load_and_log_input_entries(args, logger)
    cache_file = args.check_cache or build_default_precheck_file(args.input)
    precheck_runtime_writer = create_precheck_runtime_writer(cache_file) if args.precheck else None
    cache_map = {}
    cache_sources = []
    if args.use_check_cache:
        cache_map, cache_sources = load_precheck_cache_bundle(cache_file, logger)
    cache_hits = sum(1 for entry in entries if entry["address"].lower() in cache_map)
    logger.info(
        "[CHECK-CACHE] 统一缓存目录: root=%s target=%s",
        os.path.abspath(build_precheck_cache_root()),
        os.path.abspath(resolve_precheck_csv_path(cache_file)),
    )
    if args.use_check_cache:
        if cache_map:
            logger.info(
                "[CHECK-CACHE] 已加载缓存: primary=%s runtime_dir=%s sources=%s | 命中 %s/%s",
                os.path.abspath(resolve_precheck_csv_path(cache_file)),
                os.path.abspath(resolve_precheck_runtime_dir(cache_file)),
                len(cache_sources),
                cache_hits,
                len(entries),
            )
            if cache_hits == len(entries):
                logger.info("[CHECK-CACHE] 全量命中，正式扫描将默认复用预检结果")
        else:
            logger.info("[CHECK-CACHE] 未找到可用预检缓存，将实时预检")

    existing_targets = {
        normalize_address(target.get("address", "")).lower(): target
        for target in client.list_targets()
        if target.get("address")
    }

    auto_create_group = bool(args.group)
    group = resolve_group(client, args.group, create_if_missing=auto_create_group) if args.group else None
    prepared_targets = []
    group_attach_target_ids = []
    created_count = 0
    reused_count = 0
    recreated_count = 0
    skipped_existing_count = 0
    asset_resolved_count = 0
    asset_rewritten_count = 0
    asset_dead_count = 0
    bulk_create_candidates = []
    candidate_by_address = {}
    prepared_address_keys = set()

    for entry in entries:
        asset_resolution = resolve_asset_before_create(entry, args, logger)
        if asset_resolution["status"] == "dead":
            asset_dead_count += 1
            logger.warning(
                "[ASSET] dead after httpx, skip create: line=%s raw=%s normalized=%s reason=%s details=%s",
                entry.get("line_no"),
                entry.get("raw_target") or entry.get("raw"),
                entry["address"],
                asset_resolution["reason"],
                "; ".join(asset_resolution["details"]),
            )
            continue
        if asset_resolution["status"] in {"rewritten", "confirmed"}:
            asset_resolved_count += 1
            logger.info(
                "[ASSET] resolved line=%s raw=%s normalized=%s final=%s status=%s details=%s",
                entry.get("line_no"),
                entry.get("raw_target") or entry.get("raw"),
                entry["address"],
                asset_resolution["url"],
                asset_resolution["status"],
                "; ".join(asset_resolution["details"]),
            )
        if asset_resolution["status"] == "rewritten":
            asset_rewritten_count += 1
            entry = dict(entry)
            entry["address"] = asset_resolution["url"]

        address = entry["address"]
        key = address.lower()
        if key in prepared_address_keys:
            logger.info("[ASSET] duplicate after resolve, skip: line=%s url=%s", entry.get("line_no"), address)
            continue
        prepared_address_keys.add(key)
        current = existing_targets.get(key)
        if current:
            target_id = current.get("target_id")
            if args.skip_existing_targets:
                skipped_existing_count += 1
                logger.info("[TARGET] 已有目标，按 --skip-existing-targets 跳过: %s | %s", address, target_id)
                continue
            if args.recreate_targets:
                try:
                    client.delete_target(target_id)
                    existing_targets.pop(key, None)
                    recreated_count += 1
                    logger.info("[TARGET] 已删除已有目标，准备重建: %s | old_id=%s", address, target_id)
                except Exception as exc:
                    logger.error("[TARGET] 删除已有目标失败，跳过重建: %s | %s | %s", address, target_id, exc)
                    continue
                bulk_create_candidates.append(
                    {
                        "address": address,
                        "description": entry["description"],
                        "criticality": "10",
                        "type": "default",
                    }
                )
                candidate_by_address[address.lower()] = entry
                continue
            reused_count += 1
            logger.info("[TARGET] 复用已有目标: %s | %s | desc=%s", address, target_id, entry["description"])
            prepared_targets.append(
                {
                    "id": target_id,
                    "url": address,
                    "description": entry["description"],
                    "cached_precheck": cache_map.get(address.lower()),
                    "source": "file",
                    "attempts": 0,
                    "route_ready": False,
                    "login_ready": False,
                    "precheck_cache_target": cache_file,
                    "precheck_runtime_writer": precheck_runtime_writer,
                    "precheck_persisted": False,
                }
            )
            group_attach_target_ids.append(target_id)
        else:
            bulk_create_candidates.append(
                {
                    "address": address,
                    "description": entry["description"],
                    "criticality": "10",
                    "type": "default",
                }
            )
            candidate_by_address[address.lower()] = entry

    for chunk_index, chunk in enumerate(chunked(bulk_create_candidates, args.create_batch_size), start=1):
        logger.info("[TARGET] 批量创建 chunk=%s size=%s", chunk_index, len(chunk))
        success, error = client.create_targets_bulk(
            chunk,
            group_ids=[group["group_id"]] if group else None,
        )
        if not success:
            logger.warning("[TARGET] 批量创建失败，回退逐个创建: chunk=%s error=%s", chunk_index, error)
            for item in chunk:
                target_id, single_error = client.create_target(item["address"], item["description"])
                if not target_id:
                    logger.error("[TARGET] 创建失败: %s | %s", item["address"], single_error)
                    continue
                created_count += 1
                existing_targets[item["address"].lower()] = {"target_id": target_id, "address": item["address"]}
                entry = candidate_by_address[item["address"].lower()]
                prepared_targets.append(
                    {
                        "id": target_id,
                        "url": item["address"],
                        "description": item["description"],
                        "cached_precheck": cache_map.get(item["address"].lower()),
                        "source": "file",
                        "attempts": 0,
                        "route_ready": False,
                        "login_ready": False,
                        "precheck_cache_target": cache_file,
                        "precheck_runtime_writer": precheck_runtime_writer,
                        "precheck_persisted": False,
                    }
                )
                group_attach_target_ids.append(target_id)
                logger.info("[TARGET] 创建成功: %s | %s | desc=%s", item["address"], target_id, item["description"])
            continue

        refreshed_targets = {
            normalize_address(target.get("address", "")).lower(): target
            for target in client.list_targets()
            if target.get("address")
        }
        for item in chunk:
            current = refreshed_targets.get(item["address"].lower())
            if not current:
                logger.error("[TARGET] 批量创建后未找到目标: %s", item["address"])
                continue
            target_id = current.get("target_id")
            created_count += 1
            existing_targets[item["address"].lower()] = current
            prepared_targets.append(
                {
                    "id": target_id,
                    "url": item["address"],
                    "description": item["description"],
                    "cached_precheck": cache_map.get(item["address"].lower()),
                    "source": "file",
                    "attempts": 0,
                    "route_ready": False,
                    "login_ready": False,
                    "precheck_cache_target": cache_file,
                    "precheck_runtime_writer": precheck_runtime_writer,
                    "precheck_persisted": False,
                }
            )
            group_attach_target_ids.append(target_id)
            logger.info("[TARGET] 批量创建成功: %s | %s | desc=%s", item["address"], target_id, item["description"])

    if group and group_attach_target_ids:
        existing_group_target_ids = set(client.list_group_target_ids(group["group_id"]))
        pending_group_target_ids = [target_id for target_id in group_attach_target_ids if target_id not in existing_group_target_ids]
        logger.info(
            "[GROUP] 准备写入目标组: %s | total=%s existing=%s pending=%s",
            group.get("name"),
            len(group_attach_target_ids),
            len(existing_group_target_ids),
            len(pending_group_target_ids),
        )
        try:
            synced_group_target_ids = sync_group_targets(client, group, group_attach_target_ids, logger=logger)
            logger.info(
                "[GROUP] 已写入目标组: %s | desired=%s actual=%s",
                group.get("name"),
                len(set(group_attach_target_ids)),
                len(synced_group_target_ids),
            )
        except Exception as exc:
            logger.warning("[GROUP] 写入目标组失败，但继续扫描: %s | %s", group.get("name"), exc)

    logger.info(
        "[*] 文件模式准备完成: created=%s reused=%s recreated=%s skipped_existing=%s pending=%s skipped=%s asset_resolved=%s asset_rewritten=%s asset_dead=%s batch_size=%s",
        created_count,
        reused_count,
        recreated_count,
        skipped_existing_count,
        len(prepared_targets),
        len(skipped),
        asset_resolved_count,
        asset_rewritten_count,
        asset_dead_count,
        args.create_batch_size,
    )
    return prepared_targets


def load_and_log_input_entries(args, logger):
    if not os.path.exists(args.input):
        raise RuntimeError(f"输入文件不存在: {args.input}")

    logger.info("[*] 本地文件模式: 读取 %s", args.input)
    entries, skipped = load_urls_from_file(args.input, args.default_scheme)
    for line_no, item, reason in skipped:
        logger.warning("[SKIP] 无法识别的目标，已跳过: line=%s target=%s reason=%s", line_no, item, reason)

    if not entries:
        raise RuntimeError("输入文件中没有可用 URL")

    logger.info("[*] 输入文件有效 URL: %s 个", len(entries))
    return entries, skipped


def prepare_targets_from_awvs(client, args, logger):
    logger.info("[*] AWVS 接管模式: 正在读取目标列表")
    targets = client.list_targets()
    group = resolve_group(client, args.group) if args.group else None

    if group:
        group_target_ids = set(wait_for_group_target_ids(client, group, logger=logger))
        targets = [target for target in targets if target.get("target_id") in group_target_ids]
        logger.info("[GROUP] 仅接管目标组: %s | 命中 %s 个目标", group.get("name"), len(targets))

    pending_targets = []
    skipped_completed = 0
    skipped_active = 0
    pending_retryable = 0
    pending_never_scanned = 0

    for target in targets:
        last_status = (target.get("last_scan_session_status") or "").strip().lower()
        if last_status in ACTIVE_STATUSES:
            skipped_active += 1
            continue

        if last_status == "completed" and not args.include_scanned:
            skipped_completed += 1
            continue

        if last_status in {"aborted", "failed"}:
            pending_retryable += 1
        elif not last_status:
            pending_never_scanned += 1

        pending_targets.append(
            {
                "id": target.get("target_id"),
                "url": target.get("address"),
                "description": target.get("description") or "",
                "source": "awvs",
                "attempts": 0,
                "route_ready": False,
                "login_ready": False,
            }
        )

    logger.info(
        "[*] AWVS 模式准备完成: pending=%s never_scanned=%s retryable=%s skipped_completed=%s skipped_active=%s include_scanned=%s",
        len(pending_targets),
        pending_never_scanned,
        pending_retryable,
        skipped_completed,
        skipped_active,
        args.include_scanned,
    )
    return pending_targets


def refresh_active_scans(client, args, logger):
    try:
        scans = client.list_scans()
    except Exception as exc:
        logger.warning("[SCAN] 读取运行中任务失败: %s", exc)
        return None

    active_count = 0
    count_statuses = RUNNING_ONLY_STATUSES if args.concurrent_count_mode == "running" else ACTIVE_STATUSES
    now = time.time()

    for scan in scans:
        scan_id = scan.get("scan_id")
        status = scan.get("status") or scan.get("current_session", {}).get("status")
        target_info = scan.get("target_info") or scan.get("target") or {}
        url = target_info.get("address") or task_tracker.get(scan_id, {}).get("url") or "AWVS内部资产"

        if status in ACTIVE_STATUSES:
            counted = status in count_statuses
            if counted:
                active_count += 1
            record = task_tracker.setdefault(
                scan_id,
                {"url": url, "start_time": now, "source": "awvs", "status": status},
            )
            record["url"] = url
            record["status"] = status

            elapsed_minutes = (now - record["start_time"]) / 60
            if args.timeout > 0 and elapsed_minutes > args.timeout:
                logger.warning(
                    "[TIMEOUT] ScanID=%s URL=%s 已运行 %.1f 分钟，执行熔断",
                    scan_id,
                    url,
                    elapsed_minutes,
                )
                if client.abort_scan(scan_id):
                    logger.warning("[ABORT] ScanID=%s URL=%s 强制终止成功", scan_id, url)
                else:
                    logger.error("[ABORT] ScanID=%s URL=%s 强制终止失败", scan_id, url)
                task_tracker.pop(scan_id, None)
                if counted:
                    active_count -= 1

        elif status in FINISHED_STATUSES and scan_id in task_tracker:
            record = task_tracker.pop(scan_id)
            duration = (now - record["start_time"]) / 60
            logger.info(
                "[DONE] status=%s ScanID=%s URL=%s route=%s duration=%.1fm",
                status.upper(),
                scan_id,
                record["url"],
                record.get("route", "unknown"),
                duration,
            )

    return active_count


def schedule_scans(client, args, logger, pending_targets):
    queue = deque(pending_targets)
    summary = {
        "started": 0,
        "dropped": 0,
        "route_dropped": 0,
        "route_resolved": 0,
        "route_cache_hit": 0,
        "route_live_checked": 0,
    }
    route_total = len(pending_targets)
    route_started_at = time.time()

    if not queue:
        logger.warning("[!] 没有可调度的目标。")
        return summary

    logger.info(
        "[*] 调度开始: pending=%s concurrent=%s profile_id=%s timeout=%sm",
        len(queue),
        args.concurrent,
        args.profile_id,
        args.timeout,
    )

    while queue:
        active_count = refresh_active_scans(client, args, logger)
        if active_count is None:
            logger.warning("[WAIT] 本轮无法确认运行中任务数量，%s 秒后重试", args.interval)
            time.sleep(args.interval)
            continue

        logger.info(
            "[QUEUE] counted_%s=%s/%s remaining=%s",
            args.concurrent_count_mode,
            active_count,
            args.concurrent,
            len(queue),
        )

        if active_count >= args.concurrent:
            time.sleep(args.interval)
            continue

        dispatch_blocked = False
        while active_count < args.concurrent and queue:
            target = queue.popleft()
            logger.info("[START] 尝试启动: %s", target["url"])
            route_resolution_pending = args.route_by_target and not target.get("route_ready")
            cached_route_available = bool(args.use_check_cache and target.get("cached_precheck"))
            if route_resolution_pending:
                progress = build_progress_snapshot(summary["route_resolved"] + 1, route_total, route_started_at)
                target["precheck_progress"] = progress
                logger.info(
                    "[ROUTE-PROGRESS] %s/%s %.1f%% elapsed=%s avg=%s eta=%s mode=%s URL=%s",
                    progress["index"],
                    progress["total"],
                    progress["percent"],
                    progress["elapsed_text"],
                    progress["avg_text"],
                    progress["eta_text"],
                    "cache" if cached_route_available else "live",
                    target["url"],
                )

            if not ensure_target_login(client, args, logger, target):
                summary["route_dropped"] += 1
                continue

            if not ensure_target_route(client, args, logger, target):
                if route_resolution_pending and target.get("precheck") is not None:
                    summary["route_resolved"] += 1
                    if cached_route_available:
                        summary["route_cache_hit"] += 1
                    else:
                        summary["route_live_checked"] += 1
                summary["route_dropped"] += 1
                continue

            if route_resolution_pending:
                summary["route_resolved"] += 1
                if cached_route_available:
                    summary["route_cache_hit"] += 1
                else:
                    summary["route_live_checked"] += 1

            try:
                scan_id, error = client.start_scan(target["id"], args.profile_id)
            except Exception as exc:
                scan_id, error = None, str(exc)

            if scan_id:
                task_tracker[scan_id] = {
                    "url": target["url"],
                    "start_time": time.time(),
                    "source": target.get("source", "unknown"),
                    "status": "starting",
                    "route": target.get("selected_route", "unknown"),
                }
                summary["started"] += 1
                active_count += 1
                logger.info(
                    "[STARTED] ScanID=%s URL=%s route=%s reason=%s",
                    scan_id,
                    target["url"],
                    target.get("selected_route", "unknown"),
                    target.get("precheck", {}).get("selected_reason", "-"),
                )
                continue

            target["attempts"] += 1
            logger.error(
                "[FAILED] URL=%s attempt=%s error=%s",
                target["url"],
                target["attempts"],
                error,
            )

            if is_retryable_error(error):
                queue.appendleft(target)
                dispatch_blocked = True
                logger.warning("[RETRY] 临时性失败，保持原顺序等待下一轮: %s", target["url"])
                break

            if args.max_start_retries <= 0 or target["attempts"] < args.max_start_retries:
                queue.append(target)
                logger.warning("[RETRY] 非临时失败，移到队尾稍后再试: %s", target["url"])
                continue

            summary["dropped"] += 1
            logger.error("[DROP] 超过最大启动失败次数，放弃目标: %s", target["url"])

        if queue or dispatch_blocked:
            time.sleep(args.interval)

    logger.info("[*] 目标队列已投递完毕，开始等待存量扫描结束")
    while True:
        active_count = refresh_active_scans(client, args, logger)
        if active_count is None:
            logger.warning("[WAIT] 状态读取失败，%s 秒后继续等待", args.interval)
            time.sleep(args.interval)
            continue
        if active_count == 0:
            break
        logger.info("[WAIT] 仍有 %s 个扫描运行中", active_count)
        time.sleep(args.interval)

    return summary


def check_targets_only(args, logger, targets):
    summary = {
        "total": 0,
        "direct_ok": 0,
        "http_proxy_ok": 0,
        "socks5_ok": 0,
        "direct_route": 0,
        "proxy_route": 0,
        "cache_hit": 0,
        "fresh_checked": 0,
    }
    export_target = args.check_export or build_default_precheck_dir(args.input)
    export_csv = resolve_precheck_csv_path(export_target)
    runtime_writer = create_precheck_runtime_writer(export_target)
    logger.info(
        "[CHECK-CACHE] 统一缓存目录: root=%s target=%s",
        os.path.abspath(build_precheck_cache_root()),
        os.path.abspath(export_csv),
    )

    if args.check_limit > 0:
        targets = targets[: args.check_limit]

    if args.use_check_cache:
        cache_map, cache_sources = load_precheck_cache_bundle(export_target, logger)
    else:
        cache_map, cache_sources = {}, []
    cache_hits = sum(1 for target in targets if target["url"].lower() in cache_map)
    rows_by_url = {row["url"].lower(): row for row in precheck_cache_map_to_rows(cache_map)}
    if not args.use_check_cache:
        logger.info(
            "[CHECK-RESUME] --no-check-cache 已启用，本次不读取历史预检缓存: main=%s runtime_dir=%s",
            os.path.abspath(export_csv),
            os.path.abspath(resolve_precheck_runtime_dir(export_target)),
        )
    elif cache_map:
        logger.info(
            "[CHECK-RESUME] 已加载已有预检结果: main=%s runtime_dir=%s sources=%s | 命中 %s/%s",
            os.path.abspath(export_csv),
            os.path.abspath(resolve_precheck_runtime_dir(export_target)),
            len(cache_sources),
            cache_hits,
            len(targets),
        )
    else:
        logger.info(
            "[CHECK-RESUME] 未发现历史预检结果，将从头开始: main=%s runtime_dir=%s",
            os.path.abspath(export_csv),
            os.path.abspath(resolve_precheck_runtime_dir(export_target)),
        )

    total_targets = len(targets)
    progress_started_at = time.time()
    for index, target in enumerate(targets, start=1):
        progress = build_progress_snapshot(index, total_targets, progress_started_at)
        cached = cache_map.get(target["url"].lower())
        if cached:
            result = cached
            summary["cache_hit"] += 1
            logger.info(
                "[CHECK-PROGRESS] %s/%s %.1f%% elapsed=%s avg=%s eta=%s cache-hit URL=%s route=%s reason=%s",
                progress["index"],
                progress["total"],
                progress["percent"],
                progress["elapsed_text"],
                progress["avg_text"],
                progress["eta_text"],
                target["url"],
                cached.get("selected_route", "direct"),
                cached.get("selected_reason", "命中预检缓存"),
            )
        else:
            logger.info(
                "[CHECK-PROGRESS] %s/%s %.1f%% elapsed=%s avg=%s eta=%s live URL=%s",
                progress["index"],
                progress["total"],
                progress["percent"],
                progress["elapsed_text"],
                progress["avg_text"],
                progress["eta_text"],
                target["url"],
            )
            target["precheck_progress"] = progress
            _, result = run_precheck(target, args, logger)
            row = build_precheck_row(target, result)
            rows_by_url[target["url"].lower()] = row
            append_precheck_runtime_row(row, runtime_writer, logger)
            summary["fresh_checked"] += 1

        summary["total"] += 1
        if result["direct_ok"] is True:
            summary["direct_ok"] += 1
        if result["http_proxy_ok"] is True:
            summary["http_proxy_ok"] += 1
        if result["socks5_ok"] is True:
            summary["socks5_ok"] += 1
        if result["selected_route"] == "http-proxy":
            summary["proxy_route"] += 1
        else:
            summary["direct_route"] += 1

    logger.info(
        "[CHECK] total=%s direct_ok=%s http_proxy_ok=%s socks5_ok=%s route_direct=%s route_proxy=%s cache_hit=%s fresh_checked=%s",
        summary["total"],
        summary["direct_ok"],
        summary["http_proxy_ok"],
        summary["socks5_ok"],
        summary["direct_route"],
        summary["proxy_route"],
        summary["cache_hit"],
        summary["fresh_checked"],
    )
    rows = [rows_by_url[target["url"].lower()] for target in targets if target["url"].lower() in rows_by_url]
    return summary, rows, export_target


class AwvsHelpFormatter(argparse.RawTextHelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=36, width=118)


def build_parser():
    usage_guide = """
════════════════════════════════════ Quick Start ════════════════════════════════════

  profile = 扫描模板 = AWVS 左侧 "Scan Profiles"
  group   = 目标组   = Targets -> Target Groups

  `-k/-u/-p` 显式传入后会写入当前目录的 `awvs.local.json`
  之后同目录再次运行会自动复用。

════════════════════════════════════ Common Flows ════════════════════════════════════

  [1] 首次绑定 Key / 看模板 / 看分组
      python awvs.py --profiles -k <key>
      python awvs.py --groups

  [2] 只做预检查，不开扫
      python awvs.py -i targets.txt --check-only

  [3] 正式扫描本地文件，默认复用统一预检缓存
      python awvs.py -i targets.txt -p 1

  [4] 固定整次走直连，不按目标切路由
      python awvs.py -i targets.txt -p 1 --route direct --no-route-by-target

  [5] 新建组并导入文件里的目标后开扫
      python awvs.py -i targets.txt -g 医疗测试 -p 1

  [6] sqlmap 快捷导出
      python awvs.py -g his --sqlmap-quick
      python awvs.py -g his --sqlmap-quick outdir --sqlmap-proxy-mode inherit-precheck --sqlmap-force-ssl off
      python awvs.py -g his --sql
      python awvs.py -g his --sql-direct
      python awvs.py -g his --sql-inherit

════════════════════════════════════ Precheck Cache ═══════════════════════════════════

  预检结果现在默认统一存放在:
    `_awvs_precheck_cache/`

  手动 `--check-only` 和正式扫描时实时产生的预检结果会写到同一套缓存。
  正式扫描默认优先复用缓存，不再把手动预检和自动运行拆成两套目录。

════════════════════════════════════ sqlmap Notes ═════════════════════════════════════

  `--sqlmap-quick`:
    按组直接生成 sqlmap 包目录。

  `--sqlmap-proxy-mode`:
    `inherit-precheck`  按预检的 `selected_route` 决定是否走代理
    `fixed`             全部使用 `--sqlmap-proxy`
    `off`               全部直连

  `--sqlmap-check-cache`:
    现在默认自动读取统一预检缓存；通常不用手填。

  `--sqlmap-force-ssl`:
    默认 `off`。只在你明确确认目标必须强制 HTTPS 时再开。

  推荐优先运行:
    `05_run_sqlmap_requests.bat`
  不建议先跑:
    `04_run_sqlmap_collection.bat`

════════════════════════════════════ Tips ══════════════════════════════════════════════

  想先看组名:
    python awvs.py --groups

  想最省事地导出并按预检同步 sqlmap 代理:
    python awvs.py -g his --sqlmap-quick --sqlmap-proxy-mode inherit-precheck --sqlmap-force-ssl off
    python awvs.py -g his --sql
"""
    parser = argparse.ArgumentParser(
        prog="awvs.py",
        usage="%(prog)s [核心参数] [模式参数] [路由/预检参数] [输出参数]",
        description="AWVS 双模式调度器\n支持: 文件导入扫描 / AWVS 目标接管 / 预检查缓存复用 / 逐目标动态路由",
        epilog=usage_guide,
        formatter_class=AwvsHelpFormatter,
    )

    connection_group = parser.add_argument_group("连接与身份")
    connection_group.add_argument("-k", "--key", default=None, help=f"AWVS Key；显式传入后写入 `{LOCAL_CONFIG_FILENAME}`")
    connection_group.add_argument("-u", "--url", default=None, help=f"API 地址；显式传入后写入 `{LOCAL_CONFIG_FILENAME}`")
    connection_group.add_argument("--request-timeout", type=int, default=30, help="API 请求超时秒；默认 30")
    connection_group.add_argument("--list-profiles", "--profiles", action="store_true", help="列出扫描模板（支持后续 `-p 序号`）")
    connection_group.add_argument("--list-groups", "--groups", action="store_true", help="列出目标组")

    target_group = parser.add_argument_group("目标来源与扫描对象")
    target_group.add_argument("-i", "--input", help="输入文件；支持 `.txt/.csv/.xlsx`")
    target_group.add_argument("--default-scheme", choices=("auto", "http", "https"), default="auto", help="裸 `host:port` 自动补协议；默认 auto")
    target_group.add_argument("-p", "--profile-id", "--profile", dest="profile_id", default=None, help=f"扫描模板 UUID / 名字 / 序号；显式传入后写入 `{LOCAL_CONFIG_FILENAME}`")
    target_group.add_argument("-g", "--group", help="目标组名或 group_id")
    target_group.add_argument("--create-group", action="store_true", help="兼容旧参数；文件模式传 `-g` 时现在默认就会自动创建")
    target_group.add_argument(
        "--include-scanned",
        "--rescan",
        "--force-rescan",
        dest="include_scanned",
        action="store_true",
        help="AWVS 接管模式下，包含已扫目标（覆盖重扫）",
    )
    target_group.add_argument("--login-url", default=None, help=f"自动登录页 URL；与账号密码配套使用，显式传入后写入 `{LOCAL_CONFIG_FILENAME}`")
    target_group.add_argument("--login-user", dest="login_username", default=None, help=f"自动登录用户名；显式传入后写入 `{LOCAL_CONFIG_FILENAME}`")
    target_group.add_argument("--login-pass", dest="login_password", default=None, help=f"自动登录密码（明文保存在 `{LOCAL_CONFIG_FILENAME}`）")
    target_group.add_argument("--login-default-weak", action="store_true", help="使用默认弱口令自动登录：admin / 123456；未提供 --login-url 时按每个 target URL 自动填写")
    target_group.add_argument("--login-sequence", "--lsr", default=None, help=f"导入 Acunetix Login Sequence Recorder `.lsr` 文件；显式传入后写入 `{LOCAL_CONFIG_FILENAME}`")
    target_group.add_argument("--recreate-targets", action="store_true", help="文件模式下发现 AWVS 已有同地址 Target 时，先删除再重新创建（会影响该 Target 历史记录）")
    target_group.add_argument("--skip-existing-targets", action="store_true", help="文件模式下发现 AWVS 已有同地址 Target 时直接跳过，不复用、不扫描")

    mode_group = parser.add_argument_group("模式与运行控制")
    mode_group.add_argument("-c", "--concurrent", type=int, default=60, help="同时运行的扫描数；默认 60")
    mode_group.add_argument("-t", "--timeout", type=int, default=60, help="单任务超时分钟；默认 60")
    mode_group.add_argument("-I", "--interval", type=int, default=30, help="状态轮询秒数；默认 30")
    mode_group.add_argument("--concurrent-count-mode", choices=("active", "running"), default="running", help="并发计数口径；running=只按 AWVS 正在跑/启动中的任务计数，active=queued 也计入；默认 running")
    mode_group.add_argument("--max-start-retries", type=int, default=3, help="启动失败最大重试次数；默认 3")
    mode_group.add_argument("--check-only", action="store_true", help="只做预检查，不创建 target、不启动扫描")

    precheck_group = parser.add_argument_group("预检查与路由")
    precheck_group.add_argument("--scan-route", "--route", choices=sorted(ROUTE_POLICIES), default="auto", help="出站策略；默认 auto=直连优先，直连失败且配置代理时才走代理")
    precheck_group.add_argument("--route-by-target", dest="route_by_target", action="store_true", help="每个 target 启动前按预检结果切路由；默认开启")
    precheck_group.add_argument("--no-route-by-target", dest="route_by_target", action="store_false", help="整次任务固定走同一路由")
    precheck_group.add_argument("--scan-http-proxy", "--aproxy", dest="scan_http_proxy", nargs="?", const=DEFAULT_SCAN_HTTP_PROXY_VALUE, default=DEFAULT_SCAN_HTTP_PROXY, help="启用 AWVS HTTP 代理探测；单独传 --aproxy 默认 127.0.0.1:7890；直连/代理都可用时优先代理")
    precheck_group.add_argument("--scan-proxy-username", default="", help="HTTP 代理用户名")
    precheck_group.add_argument("--scan-proxy-password", default="", help="HTTP 代理密码")
    precheck_group.add_argument("--precheck-socks5", "--socks", dest="precheck_socks5", default=DEFAULT_PRECHECK_SOCKS5, help="Socks5 探针地址；默认不启用，常用 Clash: 127.0.0.1:7891")
    precheck_group.add_argument("--no-socks-probe", action="store_true", help="关闭 socks5 探针")
    precheck_group.add_argument("--precheck-timeout", type=float, default=3.0, help="单次预检超时秒；默认 3.0")
    precheck_group.add_argument("--precheck-http-attempts", type=int, default=3, help="HTTP 代理探测次数；默认 3")
    precheck_group.add_argument("--no-precheck", dest="precheck", action="store_false", help="关闭预检查")
    precheck_group.add_argument("--enforce-precheck", action="store_true", help="预检失败时直接跳过目标")
    precheck_group.add_argument("--allow-unreachable-scan", action="store_true", help="allow starting AWVS scans even when precheck cannot connect; default skips unreachable targets")
    precheck_group.add_argument("--check-limit", type=int, default=0, help="`--check-only` 时只处理前 N 条；0=全部")
    precheck_group.add_argument("--check-export", help="预检汇总输出位置；默认 `输入文件名_precheck/`")
    precheck_group.add_argument("--check-cache", help="正式扫描时指定预检缓存 CSV/目录；默认自动读统一缓存目录 `_awvs_precheck_cache/`")
    precheck_group.add_argument("--no-check-cache", dest="use_check_cache", action="store_false", help="正式扫描时不复用预检缓存")
    precheck_group.add_argument("--httpx-precheck-fallback", dest="httpx_precheck_fallback", action="store_true", help="预检查直连/代理都失败时，用 httpx/内置探测尝试纠正 URL 后再判定是否跳过")
    precheck_group.add_argument("--no-httpx-precheck-fallback", dest="httpx_precheck_fallback", action="store_false", help="关闭预检查失败时的 httpx 兜底")
    precheck_group.add_argument("--httpx-timeout", type=float, default=5.0, help="httpx/内置探测超时秒；默认 5.0")
    precheck_group.add_argument("--asset-resolve", dest="asset_resolve", action="store_true", help="录入 AWVS 前逐条用预检/httpx 纠正协议；失败才拒绝录入")
    precheck_group.add_argument("--no-asset-resolve", dest="asset_resolve", action="store_false", help="关闭录入前逐条协议纠偏")

    output_group = parser.add_argument_group("导出与日志")
    output_group.add_argument("--create-batch-size", type=int, default=500, help="批量创建 target 的分片大小；默认 500")
    output_group.add_argument("--export-awvs-csv", "--export", dest="export_awvs_csv", help="只导出 AWVS 导入 CSV，不启动扫描")
    output_group.add_argument("--export-sqlmap", dest="export_sqlmap", help="按组导出 SQL 注入漏洞为 sqlmap 可直接使用的文件目录")
    output_group.add_argument("--export-group-review", dest="export_group_review", help="按组导出 SQL 审查包（分组、去重、优先级、主机汇总）")
    output_group.add_argument("--vuln-severity", choices=("all", "info", "low", "medium", "high", "critical"), default="critical", help="漏洞导出筛选级别；默认 critical")
    output_group.add_argument("--vuln-status", choices=("all", "open", "fixed", "ignored"), default="open", help="漏洞导出筛选状态；默认 open")
    output_group.add_argument("--sqlmap-proxy", default="", help="sqlmap 固定代理地址；默认空=直连，只有 proxy-mode=fixed 或 inherit-precheck 命中代理时才使用")
    output_group.add_argument("--export-chunk-size", type=int, default=500, help="导出 AWVS CSV 的分片大小；默认 500")
    output_group.add_argument("-o", "--output", default="awvs_run.log", help="运行日志文件；默认 `awvs_run.log`")
    output_group.add_argument("-v", "--verbose", action="store_true", help="输出更详细的日志")

    output_group.add_argument("--sqlmap-quick", nargs="?", const="", help="sqlmap quick export; if omitted path, uses sqlmap_quick_<group>")
    output_group.add_argument("--sql", dest="sql_alias", action="store_true", help="等价于 --sqlmap-quick --sqlmap-proxy-mode inherit-precheck --sqlmap-force-ssl auto")
    output_group.add_argument("--sql-direct", dest="sql_direct_alias", action="store_true", help="等价于 --sqlmap-quick --sqlmap-proxy-mode off --sqlmap-force-ssl auto")
    output_group.add_argument("--sql-inherit", dest="sql_inherit_alias", action="store_true", help="等价于 --sqlmap-quick --sqlmap-proxy-mode inherit-precheck --sqlmap-force-ssl auto")
    output_group.add_argument("--sqlmap-proxy-mode", choices=("fixed", "inherit-precheck", "off"), default="inherit-precheck", help="sqlmap proxy mode")
    output_group.add_argument("--sqlmap-check-cache", help="sqlmap 导出时读取预检 CSV/目录并按 selected_route 判断是否走代理；默认自动读取统一缓存")
    output_group.add_argument("--sqlmap-force-ssl", choices=("off", "auto", "on"), default="auto", help="sqlmap force ssl mode")
    parser.set_defaults(precheck=True, route_by_target=True, use_check_cache=True, httpx_precheck_fallback=True, asset_resolve=True)
    return parser


def validate_args(args):
    if args.login_default_weak:
        if not (args.login_username or "").strip():
            args.login_username = DEFAULT_WEAK_LOGIN_USERNAME
        if not args.login_password:
            args.login_password = DEFAULT_WEAK_LOGIN_PASSWORD

    if args.list_profiles or args.list_groups:
        return
    if args.export_awvs_csv and not args.input:
        raise RuntimeError("使用 --export-awvs-csv 时必须提供 -i/--input")
    if args.export_sqlmap and not args.group:
        raise RuntimeError("使用 --export-sqlmap 时必须提供 -g/--group")
    if args.export_group_review and not args.group:
        raise RuntimeError("使用 --export-group-review 时必须提供 -g/--group")
    if args.check_only and not args.input:
        raise RuntimeError("使用 --check-only 时必须提供 -i/--input")
    if args.check_export and not args.check_only:
        raise RuntimeError("使用 --check-export 时必须同时开启 --check-only")
    if args.sqlmap_quick is not None and not args.group:
        raise RuntimeError("use --sqlmap-quick requires -g/--group")
    if args.recreate_targets and args.skip_existing_targets:
        raise RuntimeError("--recreate-targets 和 --skip-existing-targets 不能同时使用")
    if (args.login_sequence or "").strip():
        args.login_sequence = os.path.abspath(os.path.expanduser(args.login_sequence.strip()))
        if not os.path.isfile(args.login_sequence):
            raise RuntimeError(f"Login Sequence 文件不存在: {args.login_sequence}")
    if (args.login_sequence or "").strip() and has_auto_login_config(args):
        raise RuntimeError("--login-sequence/--lsr 不能和 --login-url/--login-user/--login-pass 同时使用")
    login_fields = [bool((args.login_url or "").strip()), bool((args.login_username or "").strip()), bool(args.login_password or "")]
    if any(login_fields) and not (bool((args.login_username or "").strip()) and bool(args.login_password or "")):
        raise RuntimeError("启用自动登录时，必须提供 --login-user / --login-pass；--login-url 可省略并按 target URL 自动填写")
    if args.concurrent <= 0:
        raise RuntimeError("并发数必须大于 0")
    if args.interval <= 0:
        raise RuntimeError("轮询间隔必须大于 0")
    if args.request_timeout <= 0:
        raise RuntimeError("请求超时必须大于 0")
    if args.create_batch_size <= 0:
        raise RuntimeError("create_batch_size 必须大于 0")
    if args.export_chunk_size <= 0:
        raise RuntimeError("export_chunk_size 必须大于 0")
    if args.precheck_timeout <= 0:
        raise RuntimeError("precheck_timeout 必须大于 0")
    if args.precheck_http_attempts <= 0:
        raise RuntimeError("precheck_http_attempts 必须大于 0")
    if args.httpx_timeout <= 0:
        raise RuntimeError("httpx_timeout 必须大于 0")
    if args.check_limit < 0:
        raise RuntimeError("check_limit 不能小于 0")
    if args.scan_route == "http-proxy" and not args.scan_http_proxy:
        raise RuntimeError("scan_route=http-proxy 时必须提供 --scan-http-proxy")
    if not args.route_by_target and args.scan_route == "auto":
        raise RuntimeError("关闭 route-by-target 时，--route 不能用 auto，请显式指定 direct 或 http-proxy")
    if args.check_only or args.export_sqlmap or args.sqlmap_quick is not None or args.export_group_review:
        return
    if not PROFILE_ID_RE.match(args.profile_id) and re.fullmatch(r"[0-9a-fA-F]{32,128}", args.profile_id):
        raise RuntimeError("你传给 -p/--profile-id 的值看起来像 API Key，不是 AWVS 扫描模板 UUID")


def print_profiles(client):
    profiles = client.list_profiles()
    print("Available scan profiles:")
    if not profiles:
        print("(empty)")
        return
    sorted_profiles = sort_profiles_for_display(profiles)
    name_width = max(len(profile.get("name") or "-") for profile in sorted_profiles)
    for index, profile in enumerate(sorted_profiles, start=1):
        profile_id = profile.get("profile_id") or "-"
        name = profile.get("name") or "-"
        custom = "custom" if profile.get("custom") else "builtin"
        print(f"{index:02d}. {name.ljust(name_width)}  {profile_id}  {custom}")
    print("")
    print("Use:")
    print("  python awvs.py -p 1")
    print("  python awvs.py -p \"Full Scan\"")
    print("  python awvs.py -p 11111111-1111-1111-1111-111111111111")


def print_groups(client):
    groups = client.list_groups()
    print("Available target groups:")
    if not groups:
        print("(empty)")
        return
    sorted_groups = sorted(groups, key=lambda group: ((group.get("name") or "").lower(), group.get("group_id") or ""))
    name_width = max(len(group.get("name") or "-") for group in sorted_groups)
    for index, group in enumerate(sorted_groups, start=1):
        group_id = group.get("group_id") or "-"
        name = group.get("name") or "-"
        description = group.get("description") or "-"
        targets_count = group.get("targets_count") or group.get("target_count") or "-"
        print(f"{index:02d}. {name.ljust(name_width)}  {group_id}  targets={targets_count}  desc={description}")
    print("")
    print("Use:")
    print("  python awvs.py -g his -p 1")
    print("  python awvs.py -g <group_id> -p 1")


def sort_profiles_for_display(profiles):
    return sorted(
        profiles,
        key=lambda profile: (
            profile.get("sort_order", 10**9),
            (profile.get("name") or "").lower(),
            profile.get("profile_id") or "",
        ),
    )


def resolve_profile_reference(client, profile_ref):
    if PROFILE_ID_RE.match(profile_ref):
        return profile_ref, None

    normalized_ref = (profile_ref or "").strip()
    if normalized_ref.isdigit():
        sorted_profiles = sort_profiles_for_display(client.list_profiles())
        index = int(normalized_ref)
        if not 1 <= index <= len(sorted_profiles):
            raise RuntimeError(f"扫描方案序号越界: {profile_ref}，当前可选范围 1-{len(sorted_profiles)}")
        profile = sorted_profiles[index - 1]
        return profile.get("profile_id"), profile.get("name") or profile_ref

    try:
        profile = client.get_profile(profile_ref)
    except Exception as exc:
        raise RuntimeError(f"按名称/序号查扫描方案失败，请检查 -k 是否有效，或直接改用 profile UUID。原始错误: {exc}") from exc
    if not profile:
        raise RuntimeError(f"未找到扫描方案: {profile_ref}")
    return profile.get("profile_id"), profile.get("name") or profile_ref


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.sql_alias or args.sql_direct_alias or args.sql_inherit_alias:
        if not args.export_sqlmap and args.sqlmap_quick is None:
            args.sqlmap_quick = ""
        if args.sql_direct_alias:
            args.sqlmap_proxy_mode = "off"
            args.sqlmap_force_ssl = "auto"
        else:
            args.sqlmap_proxy_mode = "inherit-precheck"
            args.sqlmap_force_ssl = "auto"
    if args.sqlmap_quick is not None and not args.export_sqlmap:
        args.export_sqlmap = (args.sqlmap_quick or "").strip() or default_sqlmap_quick_dir(args.group)
    local_config, local_config_path, explicit_config, local_config_error = apply_local_config(args)
    if local_config_error:
        print(f"[CONFIG] {local_config_error}", file=sys.stderr)
    try:
        config_saved = save_local_config(local_config, local_config_path, args, explicit_config)
    except Exception as exc:
        print(f"[CONFIG] 保存本地配置失败: {exc}", file=sys.stderr)
        config_saved = False
    else:
        if config_saved:
            print(f"[CONFIG] 已写入本地默认值: {os.path.abspath(local_config_path)}")
    if args.no_socks_probe:
        args.precheck_socks5 = ""
    validate_args(args)

    client = AwvsClient(args.url, args.key, args.request_timeout)

    if args.list_profiles:
        print_profiles(client)
        return

    if args.list_groups:
        print_groups(client)
        return

    resolved_profile_name = None
    if not args.check_only and not args.export_sqlmap and args.sqlmap_quick is None and not args.export_group_review:
        args.profile_id, resolved_profile_name = resolve_profile_reference(client, args.profile_id)
        try:
            save_resolved_profile_id(local_config, local_config_path, args.profile_id)
        except Exception as exc:
            print(f"[CONFIG] 保存解析后的 profile_id 失败: {exc}", file=sys.stderr)

    logger = setup_logger(args.output, args.verbose)

    logger.info("=" * 68)
    logger.info("AWVS 双模式扫描调度器启动")
    mode_name = "sqlmap-quick" if args.sqlmap_quick is not None else ("export-group-review" if args.export_group_review else ("export-sqlmap" if args.export_sqlmap else ("check-only" if args.check_only else ("file" if args.input else "awvs"))))
    logger.info("mode=%s base_url=%s", mode_name, args.url)
    logger.info(
        "profile_id=%s profile_name=%s group=%s output=%s",
        args.profile_id,
        resolved_profile_name or "-",
        args.group or "-",
        os.path.abspath(args.output),
    )
    logger.info(
        "scan_route=%s route_by_target=%s check_cache=%s http_proxy=%s precheck=%s allow_unreachable=%s http_attempts=%s socks5_probe=%s asset_resolve=%s httpx_fallback=%s concurrent_mode=%s batch_size=%s timeout=%sm auto_login=%s login_sequence=%s",
        args.scan_route,
        args.route_by_target,
        args.use_check_cache,
        args.scan_http_proxy or "-",
        args.precheck,
        args.allow_unreachable_scan,
        args.precheck_http_attempts,
        args.precheck_socks5 or "-",
        args.asset_resolve,
        args.httpx_precheck_fallback,
        args.concurrent_count_mode,
        args.create_batch_size,
        args.timeout,
        has_auto_login_config(args),
        args.login_sequence or "-",
    )
    logger.info("=" * 68)

    try:
        if args.export_awvs_csv:
            entries, _ = load_and_log_input_entries(args, logger)
            generated_files = export_awvs_csv(entries, args.export_awvs_csv, args.export_chunk_size)
            for file_path in generated_files:
                logger.info("[EXPORT] 已生成: %s", file_path)
            logger.info("[DONE] 导出完成: files=%s dir=%s", len(generated_files), os.path.abspath(args.export_awvs_csv))
            return

        if args.export_sqlmap:
            group = resolve_group(client, args.group)
            export_result = export_group_sqlmap_bundle(
                client,
                group,
                args.export_sqlmap,
                severity_name=args.vuln_severity,
                status_name=args.vuln_status,
                sqlmap_proxy=args.sqlmap_proxy,
                sqlmap_proxy_mode=args.sqlmap_proxy_mode,
                sqlmap_check_cache=args.sqlmap_check_cache,
                sqlmap_force_ssl=args.sqlmap_force_ssl,
            )
            logger.info("[SQLMAP] query=%s", export_result["query"])
            logger.info("[SQLMAP] summary=%s", os.path.abspath(export_result["summary_file"]))
            logger.info("[SQLMAP] direct=%s", os.path.abspath(export_result["direct_file"]))
            logger.info("[SQLMAP] manual=%s", os.path.abspath(export_result["manual_file"]))
            logger.info("[SQLMAP] urls=%s", os.path.abspath(export_result["sqlmap_url_file"]))
            logger.info("[SQLMAP] collection_bat=%s", os.path.abspath(export_result["sqlmap_collection_bat_file"]))
            logger.info("[SQLMAP] requests_bat=%s", os.path.abspath(export_result["sqlmap_requests_bat_file"]))
            logger.info(
                "[DONE] SQLMap bundle ready: total=%s sql_requests=%s direct=%s dir=%s",
                export_result["total_count"],
                export_result["sql_request_count"],
                export_result["direct_count"],
                os.path.abspath(args.export_sqlmap),
            )
            return

        if args.export_group_review:
            group = resolve_group(client, args.group)
            export_result = export_group_review_bundle(
                client,
                group,
                args.export_group_review,
                severity_name=args.vuln_severity,
                status_name=args.vuln_status,
                sqli_only=True,
            )
            logger.info("[REVIEW] query=%s", export_result["query"])
            logger.info("[REVIEW] summary=%s", os.path.abspath(export_result["summary_file"]))
            logger.info("[REVIEW] high_confidence=%s", os.path.abspath(export_result["high_confidence_file"]))
            logger.info("[REVIEW] deduped=%s", os.path.abspath(export_result["deduped_file"]))
            logger.info("[REVIEW] repeated=%s", os.path.abspath(export_result["repeated_file"]))
            logger.info("[REVIEW] host_counts=%s", os.path.abspath(export_result["host_counts_file"]))
            logger.info(
                "[DONE] Group review bundle ready: total=%s deduped=%s dir=%s",
                export_result["total_count"],
                export_result["deduped_count"],
                os.path.abspath(args.export_group_review),
            )
            return

        if args.check_only:
            entries, _ = load_and_log_input_entries(args, logger)
            check_targets = [
                {
                    "url": item["address"],
                    "description": item["description"],
                    "source": "check-only",
                }
                for item in entries
            ]
            summary, rows, export_target = check_targets_only(args, logger, check_targets)
            exported_paths = export_precheck_results(rows, export_target)
            for path in exported_paths:
                logger.info("[CHECK-EXPORT] 已生成: %s", path)
            logger.info(
                "[DONE] 预检查完成 total=%s cache_hit=%s fresh_checked=%s",
                summary["total"],
                summary["cache_hit"],
                summary["fresh_checked"],
            )
            return

        if args.input:
            pending_targets = prepare_targets_from_file(client, args, logger)
        else:
            pending_targets = prepare_targets_from_awvs(client, args, logger)

        if not pending_targets:
            active_count = refresh_active_scans(client, args, logger)
            if not active_count:
                logger.warning("[!] 没有可启动的目标，也没有存量扫描任务。")
                return

        summary = schedule_scans(client, args, logger, pending_targets)
        logger.info(
            "[SUMMARY] started=%s dropped=%s route_dropped=%s route_resolved=%s route_cache_hit=%s route_live_checked=%s",
            summary["started"],
            summary["dropped"],
            summary["route_dropped"],
            summary["route_resolved"],
            summary["route_cache_hit"],
            summary["route_live_checked"],
        )
        logger.info("[DONE] 全部处理结束，日志文件: %s", os.path.abspath(args.output))
    except KeyboardInterrupt:
        logger.warning("[STOP] 用户手动中断。")
    except Exception as exc:
        logger.exception("[FATAL] 脚本执行失败: %s", exc)
        raise


if __name__ == "__main__":
    main()
