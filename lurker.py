import argparse
import concurrent.futures
import datetime
import importlib.util
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import errno

if importlib.util.find_spec("colorama") is not None:
    colorama_init = importlib.import_module("colorama").init
else: 
    colorama_init = None

if importlib.util.find_spec("tqdm") is not None:
    tqdm = importlib.import_module("tqdm").tqdm
else:
    def tqdm(iterable, **_kw):
        return iterable


DEFAULT_CONFIG = {
    "max_threads": 8,
    "webhook_url": "",
    "output_dir": "output",
}
STATE_FILENAME = "state.json"

HEADERS_TO_STORE = {
    "server",
    "x-powered-by",
    "content-security-policy",
    "x-frame-options",
    "strict-transport-security",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
}

ANSI_RESET = "\033[0m"
ANSI_GREEN = "\033[32m"
ANSI_YELLOW = "\033[33m"
ANSI_RED = "\033[31m"
ANSI_CYAN = "\033[36m"


REQUIRED_SECURITY_HEADERS = {
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
}
REQUIRED_SECURITY_HEADERS_LOWER = {
    header.lower() for header in REQUIRED_SECURITY_HEADERS
}
HEADER_VALUE_POLICIES = {
    "x-frame-options": {
        "type": "allowlist",
        "safe_values": {"deny", "sameorigin"},
        "reason": "must be DENY or SAMEORIGIN",
    },
    "strict-transport-security": {
        "type": "max-age",
        "min_max_age": 31536000,
        "reason": "max-age must be at least 31536000",
    },
    "x-content-type-options": {
        "type": "exact",
        "safe_value": "nosniff",
        "reason": "must be nosniff",
    },
    "content-security-policy": {
        "type": "csp",
        "reason": "must not be empty, *, unsafe-inline, or unsafe-eval",
    },
    "referrer-policy": {
        "type": "denylist",
        "unsafe_values": {"", "unsafe-url", "no-referrer-when-downgrade"},
        "reason": "must not be empty, unsafe-url, or no-referrer-when-downgrade",
    },
    "permissions-policy": {
        "type": "presence_only",
    },
}
# Global flag to disable ANSI coloring when requested via CLI
NO_COLOR = False

def _color_text(text, color_code):
    if NO_COLOR:
        return text
    return f"{color_code}{text}{ANSI_RESET}"
def print_info(message):
    print(_color_text(f"[INFO] {message}", ANSI_CYAN))

def print_success(message):
    print(_color_text(f"[SUCCESS] {message}", ANSI_GREEN))

def print_warning(message):
    print(_color_text(f"[WARNING] {message}", ANSI_YELLOW))

def print_error(message):
    print(_color_text(f"[ERROR] {message}", ANSI_RED))

def _resolve_path(path_value, base_dir=None):
    if not path_value:
        return path_value
    candidate = os.path.expanduser(path_value)
    if os.path.isabs(candidate):
        return os.path.normpath(candidate)

    if base_dir is None:
        base_dir = os.getcwd()
    return os.path.normpath(os.path.join(base_dir, candidate))


def load_config(config_path=None):
    base_dir = os.getcwd()
    config_file_path = None
    if config_path:
        config_file_path = _resolve_path(config_path, base_dir)
        if not os.path.exists(config_file_path):
            raise FileNotFoundError(f"Config file not found: {config_file_path}")
        base_dir = os.path.dirname(config_file_path)
    else:
        default_path = os.path.join(base_dir, "config.json")
        if os.path.exists(default_path):
            config_file_path = default_path

    config = dict(DEFAULT_CONFIG)
    if config_file_path:
        with open(config_file_path, "r", encoding="utf-8") as config_file:
            loaded_config = json.load(config_file)

        if not isinstance(loaded_config, dict):
            raise ValueError("Configuration file must contain a JSON object.")
        config.update({key: value for key, value in loaded_config.items() if value is not None})

    config["output_dir"] = _resolve_path(config.get("output_dir"), base_dir)
    return config


def apply_cli_overrides(config, args):
    resolved = dict(config)

    if getattr(args, "max_threads", None) is not None:
        resolved["max_threads"] = args.max_threads
    if getattr(args, "webhook_url", None) is not None:
        resolved["webhook_url"] = args.webhook_url

    if getattr(args, "output_dir", None):
        resolved["output_dir"] = _resolve_path(args.output_dir)

    return resolved


def validate_url(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")
    return url

def _is_connection_refused_error(error):
    reason = getattr(error, "reason", error)

    try:
        if isinstance(reason, OSError):
            return getattr(reason, "errno", None) in (
                errno.ECONNREFUSED,
                errno.ENETUNREACH,
                errno.EHOSTUNREACH,
            )
    except Exception:
        pass
    reason_text = str(reason)
    return "Connection refused" in reason_text or "No route to host" in reason_text


def _sanitize_hostname(target_url):
    parsed = urllib.parse.urlparse(target_url)
    hostname = parsed.hostname or parsed.netloc
    if not hostname:
        raise ValueError(f"Invalid URL: {target_url}")
    if parsed.port:
        hostname = f"{hostname}_{parsed.port}"
    return hostname.replace(".", "_").replace(":", "_").replace("[", "_").replace("]", "_")
def _get_state_file_path(target_url, output_dir):
    hostname = _sanitize_hostname(target_url)
    return os.path.join(output_dir, hostname, STATE_FILENAME)


def _get_history_file_path(target_url, output_dir):
    hostname = _sanitize_hostname(target_url)
    history_dir = os.path.join(output_dir, hostname, "history")
    os.makedirs(history_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M")
    return os.path.join(history_dir, f"{timestamp}.json")


def _filter_stored_headers(headers_dict):
    return {
        header.lower(): value
        for header, value in headers_dict.items()
        if header.lower() in HEADERS_TO_STORE
        }


def validate_header_values(headers_dict):
    unsafe_headers = []

    for header, value in headers_dict.items():
        policy = HEADER_VALUE_POLICIES.get(header.lower())
        if policy is None:
            continue

        normalized_value = "" if value is None else str(value)
        stripped_value = normalized_value.strip()
        lower_value = stripped_value.lower()
        reason = None

        policy_type = policy["type"]
        if policy_type == "presence_only":
            continue
        if policy_type == "allowlist":
            safe_values = {safe_value.lower() for safe_value in policy["safe_values"]}
            if lower_value not in safe_values:
                reason = policy["reason"]
        elif policy_type == "max-age":
            match = re.search(r"(?i)\bmax-age\s*=\s*([^;]+)", normalized_value)
            if not match:
                reason = "missing max-age"
            else:
                max_age_value = match.group(1).strip().strip("\"'")
                try:
                    max_age = int(max_age_value)
                except ValueError:
                    reason = "invalid max-age"
                else:
                    if max_age < policy["min_max_age"]:
                        reason = policy["reason"]
        elif policy_type == "exact":
            if lower_value != policy["safe_value"]:
                reason = policy["reason"]
        elif policy_type == "csp":
            tokens = re.split(r"[\s;]+", stripped_value) if stripped_value else []
            if (
                not stripped_value
                or "*" in tokens
                or "unsafe-inline" in lower_value
                or "unsafe-eval" in lower_value
            ):
                reason = policy["reason"]
        elif policy_type == "denylist":
            if lower_value in policy["unsafe_values"]:
                reason = policy["reason"]

        if reason:
            unsafe_headers.append({"header": header.lower(), "value": value, "reason": reason})

    return unsafe_headers

def load_wordlist(wordlist_path):
    with open(wordlist_path, "r", encoding="utf-8") as wordlist_file:
        return [
            line.strip()
            for line in wordlist_file
            if line.strip() and not line.lstrip().startswith("#")
        ]

def save_state(data, filename):
    os.makedirs(os.path.dirname(filename) or ".", exist_ok=True)
    with open(filename, "w", encoding="utf-8") as state_file:
        json.dump(data, state_file, indent=2, sort_keys=True)

def load_state(filename, missing_ok=True):
    try:
        with open(filename, "r", encoding="utf-8") as state_file:
            return json.load(state_file)
    except FileNotFoundError:
        if missing_ok: return {}
        raise

def probe_endpoint(target_url, path):
    base_url = target_url.rstrip("/")
    endpoint_path = path.lstrip("/")
    url = f"{base_url}/{endpoint_path}"
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            status_code = response.getcode()
            if status_code in (200, 403):
                return status_code, _filter_stored_headers(dict(response.headers))
            return None
    except urllib.error.HTTPError as error:
        if error.code == 403:
            return 403, _filter_stored_headers(dict(error.headers or {}))
        if error.code == 404:
            return None
        return None
def analyze_headers(headers_dict):
    present_headers = {header.lower() for header in headers_dict}
    missing_headers = REQUIRED_SECURITY_HEADERS_LOWER - present_headers
    return sorted(
        header
        for header in REQUIRED_SECURITY_HEADERS
        if header.lower() in missing_headers
    )

def scan_target(target_url, wordlist, max_threads, show_progress=False, collect_errors=False):
    paths = list(wordlist)
    results = {}
    failures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        def _worker(path):
            try:
                return path, probe_endpoint(target_url, path), None
            except urllib.error.URLError as error:
                reason = getattr(error, "reason", None)
                if reason is None:
                    reason = str(error)
                return path, None, str(reason)
        probe_results = executor.map(_worker, paths)
        if show_progress:
            probe_results = tqdm(
                probe_results,
                total=len(paths),
                desc="Scanning",
                unit="path",
            )
        for path, probe_result, error_message in probe_results:
            if probe_result is not None:
                status_code, headers_dict = probe_result
                results[path] = {
                    "status": status_code,
                    "headers": headers_dict,
                }
                continue

            if collect_errors and error_message:
                failures.append({"path": path, "error": error_message})
    if collect_errors:
        return results, failures
    return results
def detect_changes(old_state, new_state):
    new_paths = sorted(path for path in new_state if path not in old_state)
    removed_paths = sorted(path for path in old_state if path not in new_state)
    regressions = []

    for path in old_state:
        if path not in new_state:
            continue

        old_entry = old_state[path]
        new_entry = new_state[path]

        regression_reasons = []
        if old_entry.get("status") != new_entry.get("status"):
            regression_reasons.append(
                {
                    "type": "status_change",
                    "old": old_entry.get("status"),
                    "new": new_entry.get("status"),
                }
            )
        old_headers = old_entry.get("headers", {})
        new_headers = new_entry.get("headers", {})
        old_header_keys = set(old_headers.keys())
        new_header_keys = set(new_headers.keys())
        missing_security_headers = (
            (REQUIRED_SECURITY_HEADERS_LOWER & old_header_keys) - new_header_keys
        )
        if missing_security_headers:
            regression_reasons.append(
                {
                    "type": "missing_security_headers",
                    "missing": sorted(
                        header
                        for header in REQUIRED_SECURITY_HEADERS
                        if header.lower() in missing_security_headers
                    ),
                }
            )

        old_value_issues = {
            issue["header"]: issue for issue in validate_header_values(old_headers)
        }
        new_value_issues = {
            issue["header"]: issue for issue in validate_header_values(new_headers)
        }
        for header, issue in new_value_issues.items():
            if header not in old_headers:
                continue
            if header in old_value_issues:
                continue
            regression_reasons.append(
                {
                    "type": "unsafe_header_value",
                    "header": header,
                    "old_value": old_headers.get(header),
                    "new_value": issue.get("value"),
                    "reason": issue.get("reason"),
                }
            )

        if regression_reasons:
            regressions.append({"path": path, "reasons": regression_reasons})
    return {
        "new": new_paths,
        "regressions": sorted(regressions, key=lambda item: item["path"]),
        "removed": removed_paths,
    }


def audit_first_scan(scan_results):
    regressions = []

    for path, entry in scan_results.items():
        missing_headers = analyze_headers(entry.get("headers", {}))
        if missing_headers:
            regressions.append(
                {
                    "path": path,
                    "reasons": [
                        {
                            "type": "missing_security_headers",
                            "missing": missing_headers,
                        }
                    ],
                }
            )

    return sorted(regressions, key=lambda item: item["path"])

def send_discord_alert(webhook_url, message):
    if not message:
        return
    payload = json.dumps({"content": message}).encode("utf-8")
    request = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10):
        return


def _describe_regression_reason(reason):
    reason_type = reason.get("type", "unknown")
    if reason_type == "status_change":
        return f"status {reason.get('old')} -> {reason.get('new')}"
    if reason_type == "missing_security_headers":
        missing = ", ".join(reason.get("missing", [])) or "none"
        return f"missing headers: {missing}"
    if reason_type == "unsafe_header_value":
        return (
            f"unsafe value: {reason.get('header')} changed to '{reason.get('new_value')}' "
            f"({reason.get('reason')})"
        )
    return reason_type

def format_alert_message(diff_results):
    new_paths = diff_results.get("new", [])
    regressions = diff_results.get("regressions", [])
    removed_paths = diff_results.get("removed", [])

    if not new_paths and not regressions and not removed_paths:
        return None

    new_summary = ", ".join(new_paths) if new_paths else "None"
    removed_summary = ", ".join(removed_paths) if removed_paths else "None"
    regression_summaries = []
    for regression in regressions:
        path = regression.get("path", "<unknown>")
        reason_summaries = []
        for reason in regression.get("reasons", []):
            reason_summaries.append(_describe_regression_reason(reason))
        details = "; ".join(reason_summaries) if reason_summaries else "unspecified"
        regression_summaries.append(f"{path} ({details})")

    regressions_summary = "; ".join(regression_summaries) if regression_summaries else "None"
    return (
        "Lurker Alert!\n"
        f"New: {new_summary}\n"
        f"Regressions: {regressions_summary}\n"
        f"Removed: {removed_summary}"
    )

def render_diff_summary(diff_results):
    lines = []
    new_paths = diff_results.get("new", [])
    regressions = diff_results.get("regressions", [])
    removed_paths = diff_results.get("removed", [])

    if not new_paths and not regressions and not removed_paths:
        return _color_text("No changes detected.", ANSI_GREEN)
    if new_paths:
        lines.append(_color_text("New endpoints:", ANSI_GREEN))
        lines.extend(f"  + {path}" for path in new_paths)

    if regressions:
        lines.append(_color_text("Regressions detected:", ANSI_YELLOW))
        for regression in regressions:
            path = regression.get("path", "<unknown>")
            reason_summaries = []
            for reason in regression.get("reasons", []):
                reason_summaries.append(_describe_regression_reason(reason))
            details = "; ".join(reason_summaries) if reason_summaries else "unspecified"
            lines.append(f"  ! {path}: {details}")
    if removed_paths:
        lines.append(_color_text("Removed endpoints:", ANSI_RED))
        lines.extend(f"  - {path}" for path in removed_paths)

    return "\n".join(lines)

def _build_parser():
    parser = argparse.ArgumentParser(
        prog="lurker",
        description="Scan endpoints, compare results, and notify on changes.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colored output.",
    )
    parser.add_argument(
        "--config",
        help="Path to a config.json file. Defaults to ./config.json when present.",
    )
    subparsers = parser.add_subparsers(dest="command")
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a target URL with a wordlist.",
    )
    scan_parser.add_argument("--url", required=True, help="Target URL to scan.")
    scan_parser.add_argument("--wordlist", required=True, help="Wordlist file path.")
    scan_parser.add_argument(
        "--max-threads",
        type=int,
        help="Maximum concurrent scan threads.",
    )
    scan_parser.add_argument(
        "--webhook-url",
        help="Discord webhook URL for alerts.",
    )
    scan_parser.add_argument(
        "--output-dir",
        help="Directory where scan state is stored.",
    )
    diff_parser = subparsers.add_parser(
        "diff",
        help="Compare two saved scan files.",
    )
    diff_parser.add_argument("old_file", help="Older scan state file.")
    diff_parser.add_argument("new_file", help="Newer scan state file.")
    diff_parser.add_argument(
        "--webhook-url",
        help="Discord webhook URL for alerts.",
    )
    return parser

def _run_scan(args, config):
    target_url = validate_url(args.url)
    wordlist = load_wordlist(args.wordlist)
    resolved_config = apply_cli_overrides(config, args)
    max_threads = resolved_config["max_threads"]
    output_dir = resolved_config["output_dir"]
    webhook_url = resolved_config.get("webhook_url", "")
    try:
        probe_endpoint(target_url, "/")
    except urllib.error.URLError as error:
        if _is_connection_refused_error(error) and len(wordlist) > 1:
            print_warning(
                f"Could not reach {target_url}. The server may be offline. Continue anyway? [y/N]"
            )
            response = input().strip().lower()
            if response != "y":
                return 1
        else:
            pass
    state_file = _get_state_file_path(target_url, output_dir)
    os.makedirs(os.path.dirname(state_file), exist_ok=True)
    previous_state = load_state(state_file)

    print_info(f"Scanning {target_url} with {len(wordlist)} paths.")
    scan_results, failures = scan_target(
        target_url,
        wordlist,
        max_threads=max_threads,
        show_progress=True,
        collect_errors=True,
    )

    diff_results = detect_changes(previous_state, scan_results)
    if not previous_state:
        first_scan_regressions = audit_first_scan(scan_results)
        if first_scan_regressions:
            diff_results = dict(diff_results)
            diff_results["regressions"] = sorted(
                diff_results["regressions"] + first_scan_regressions,
                key=lambda item: item["path"],
            )
    summary = render_diff_summary(diff_results)
    print(summary)
    if failures:
        for failure in failures:
            print_error(f"Failed to reach endpoint {failure['path']}: {failure['error']}")

    save_state(scan_results, state_file)
    history_file = _get_history_file_path(target_url, output_dir)
    save_state(scan_results, history_file)
    print_info(f"History snapshot saved to {history_file}.")
    print_success(f"Scan complete. Results saved to {state_file}.")
    alert_message = format_alert_message(diff_results)
    if alert_message:
        if webhook_url:
            try:
                send_discord_alert(webhook_url, alert_message)
                print_success("Discord alert sent.")
            except urllib.error.URLError as error:
                print_error(f"Failed to send Discord alert: {error}")
        else:
            print_info("Changes detected:")
            print(alert_message)

    return 0

def _run_diff(args, config):
    old_state = load_state(args.old_file, missing_ok=False)
    new_state = load_state(args.new_file, missing_ok=False)
    diff_results = detect_changes(old_state, new_state)
    
    resolved_config = apply_cli_overrides(config, args)
    webhook_url = resolved_config.get("webhook_url", "")
    print_info(f"Comparing {args.old_file} to {args.new_file}.")
    print(render_diff_summary(diff_results))

    alert_message = format_alert_message(diff_results)
    if alert_message:
        if webhook_url:
            try:
                send_discord_alert(webhook_url, alert_message)
                print_success("Discord alert sent.")
            except urllib.error.URLError as error:
                print_error(f"Failed to send Discord alert: {error}")
        else:
            print_info("Changes detected:")
            print(alert_message)
            
    return 0

def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = _build_parser()
    if not argv:
        parser.print_help()
        return 0

    # Parse known args first so we can read the --no-color flag before
    # initializing colorama. Then parse the full args for the command.
    pre_args, _ = parser.parse_known_args(argv)
    global NO_COLOR
    NO_COLOR = getattr(pre_args, "no_color", False)

    if colorama_init is not None and not NO_COLOR:
        colorama_init()

    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    try:
        config = load_config(args.config)
        if args.command == "scan":
            return _run_scan(args, config)

        if args.command == "diff":
            return _run_diff(args, config)
        parser.print_help()
        return 0
    except FileNotFoundError as error:
        print_error(str(error))
        return 1
    except ValueError as error:
        print_error(str(error))
        return 2
    except KeyboardInterrupt:
        print_warning("Operation cancelled by user.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())