import json
import os
import tempfile
import urllib.error
import unittest
from unittest.mock import MagicMock, patch
import lurker

class TestProbeEndpoint(unittest.TestCase):
    @patch("lurker.urllib.request.urlopen")
    def test_probe_endpoint_returns_200_when_endpoint_exists(self, mock_urlopen):
        response = MagicMock()
        response.getcode.return_value = 200
        response.headers = {"Content-Type": "text/html"}
        response.__enter__.return_value = response
        mock_urlopen.return_value = response

        result = lurker.probe_endpoint("https://example.com", "/admin")

        # probe_endpoint now filters stored headers to security-relevant ones
        self.assertEqual(result, (200, {}))

    @patch("lurker.urllib.request.urlopen")
    def test_probe_endpoint_retains_new_security_headers(self, mock_urlopen):
        response = MagicMock()
        response.getcode.return_value = 200
        response.headers = {
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "geolocation=()",
            "Content-Type": "text/html",
        }
        response.__enter__.return_value = response
        mock_urlopen.return_value = response

        result = lurker.probe_endpoint("https://example.com", "/admin")

        self.assertEqual(
            result,
            (
                200,
                {
                    "x-content-type-options": "nosniff",
                    "referrer-policy": "strict-origin",
                    "permissions-policy": "geolocation=()",
                },
            ),
        )

    @patch("lurker.urllib.request.urlopen")
    def test_probe_endpoint_returns_403_when_endpoint_exists(self, mock_urlopen):
        response = MagicMock()
        response.getcode.return_value = 403
        response.headers = {"Content-Type": "text/html"}
        response.__enter__.return_value = response
        mock_urlopen.return_value = response

        result = lurker.probe_endpoint("https://example.com", "/private")

        # 403 returns filtered headers
        self.assertEqual(result, (403, {}))

    @patch("lurker.urllib.request.urlopen")
    def test_probe_endpoint_returns_none_on_404(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://example.com/missing",
            code=404,
            msg="Not Found",
            hdrs=None,
            fp=None,
        )

        result = lurker.probe_endpoint("https://example.com", "/missing")

        self.assertIsNone(result)

    @patch("lurker.urllib.request.urlopen")
    def test_probe_endpoint_handles_timeout(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("timed out")
        with self.assertRaises(urllib.error.URLError):
            lurker.probe_endpoint("https://example.com", "/slow")

    @patch("lurker.urllib.request.urlopen")
    def test_probe_endpoint_returns_none_on_connection_refused(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
        with self.assertRaises(urllib.error.URLError):
            lurker.probe_endpoint("https://example.com", "/")



class TestSanitizeHostname(unittest.TestCase):
    def test_sanitizes_regular_hostname(self):
        self.assertEqual(lurker._sanitize_hostname("http://example.com"), "example_com")

    def test_sanitizes_ipv4_with_port(self):
        self.assertEqual(lurker._sanitize_hostname("http://127.0.0.1:8000"), "127_0_0_1_8000")

    def test_sanitizes_ipv6_with_brackets_and_port(self):
        # [::1]:8000 -> ::1_8000 -> underscores
        self.assertEqual(lurker._sanitize_hostname("http://[::1]:8000"), "__1_8000")


class TestScanTarget(unittest.TestCase):
    @patch("lurker.probe_endpoint")
    @patch("lurker.concurrent.futures.ThreadPoolExecutor")
    def test_scan_target_maps_wordlist_concurrently(self, mock_executor_cls, mock_probe_endpoint):
        wordlist = ["/.env", "/admin", "/missing"]
        expected = {
            "/.env": {
                "status": 200,
                "headers": {
                    "Server": "nginx",
                    "X-Powered-By": "php/8.2",
                },
            },
            "/admin": {
                "status": 403,
                "headers": {
                    "X-Frame-Options": "DENY",
                    "Strict-Transport-Security": "max-age=31536000",
                },
            },
        }
        raw_headers = {
            "/.env": {
                "Server": "nginx",
                "X-Powered-By": "php/8.2",
                "Set-Cookie": "session=abc123",
            },
            "/admin": {
                "X-Frame-Options": "DENY",
                "Strict-Transport-Security": "max-age=31536000",
                "Set-Cookie": "session=abc123",
            },
        }

        def side_effect(target_url, path):
            if path in expected:
                # simulate probe_endpoint filtering headers
                allowed = set(k for k in raw_headers[path] if k.lower() in {h.lower() for h in expected[path]["headers"]})
                return expected[path]["status"], {k: v for k, v in raw_headers[path].items() if k in allowed}
            return None

        mock_probe_endpoint.side_effect = side_effect

        executor = MagicMock()
        executor.__enter__.return_value = executor
        executor.__exit__.return_value = None
        executor.map.side_effect = lambda func, iterable: [func(item) for item in iterable]
        mock_executor_cls.return_value = executor

        result = lurker.scan_target("https://example.com", wordlist, max_threads=8)

        mock_executor_cls.assert_called_once_with(max_workers=8)
        executor.map.assert_called_once()
        self.assertEqual(result, expected)

    @patch("lurker.probe_endpoint")
    @patch("lurker.concurrent.futures.ThreadPoolExecutor")
    def test_scan_target_collects_errors(self, mock_executor_cls, mock_probe_endpoint):
        wordlist = ["/good", "/bad"]

        def side_effect(target_url, path):
            if path == "/good":
                return 200, {"Server": "nginx"}
            raise urllib.error.URLError("Connection refused")

        mock_probe_endpoint.side_effect = side_effect

        executor = MagicMock()
        executor.__enter__.return_value = executor
        executor.__exit__.return_value = None
        executor.map.side_effect = lambda func, iterable: [func(item) for item in iterable]
        mock_executor_cls.return_value = executor

        results, failures = lurker.scan_target("https://example.com", wordlist, max_threads=4, collect_errors=True)

        self.assertIn("/good", results)
        self.assertEqual(results["/good"]["status"], 200)
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["path"], "/bad")
        self.assertIn("Connection refused", failures[0]["error"])

class TestHeaderAuditor(unittest.TestCase):
    def test_analyze_headers_returns_empty_list_when_all_headers_present(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000",
        }

        result = lurker.analyze_headers(headers)

        self.assertEqual(result, [])

    def test_analyze_headers_returns_all_missing_headers(self):
        headers = {"Server": "nginx"}

        result = lurker.analyze_headers(headers)

        self.assertEqual(set(result), lurker.REQUIRED_SECURITY_HEADERS)


class TestHeaderValueValidator(unittest.TestCase):
    def test_xfo_deny_is_safe(self):
        result = lurker.validate_header_values({"x-frame-options": "DENY"})
        self.assertEqual(result, [])

    def test_xfo_allowall_is_unsafe(self):
        result = lurker.validate_header_values({"x-frame-options": "ALLOWALL"})
        self.assertEqual(
            result,
            [
                {
                    "header": "x-frame-options",
                    "value": "ALLOWALL",
                    "reason": "must be DENY or SAMEORIGIN",
                }
            ],
        )

    def test_hsts_sufficient_max_age_is_safe(self):
        result = lurker.validate_header_values(
            {"strict-transport-security": "max-age=31536000; includeSubDomains"}
        )
        self.assertEqual(result, [])

    def test_hsts_insufficient_max_age_is_unsafe(self):
        result = lurker.validate_header_values(
            {"strict-transport-security": "max-age=100"}
        )
        self.assertEqual(
            result,
            [
                {
                    "header": "strict-transport-security",
                    "value": "max-age=100",
                    "reason": "max-age must be at least 31536000",
                }
            ],
        )

    def test_hsts_missing_max_age_is_unsafe(self):
        result = lurker.validate_header_values(
            {"strict-transport-security": "includeSubDomains"}
        )
        self.assertEqual(
            result,
            [
                {
                    "header": "strict-transport-security",
                    "value": "includeSubDomains",
                    "reason": "missing max-age",
                }
            ],
        )

    def test_hsts_non_integer_max_age_is_unsafe(self):
        result = lurker.validate_header_values(
            {"strict-transport-security": "max-age=abc"}
        )
        self.assertEqual(
            result,
            [
                {
                    "header": "strict-transport-security",
                    "value": "max-age=abc",
                    "reason": "invalid max-age",
                }
            ],
        )

    def test_hsts_value_without_max_age_directive_is_unsafe(self):
        result = lurker.validate_header_values({"strict-transport-security": "abc"})
        self.assertEqual(
            result,
            [
                {
                    "header": "strict-transport-security",
                    "value": "abc",
                    "reason": "missing max-age",
                }
            ],
        )

    def test_xcto_nosniff_is_safe(self):
        result = lurker.validate_header_values({"x-content-type-options": "nosniff"})
        self.assertEqual(result, [])

    def test_xcto_wrong_value_is_unsafe(self):
        result = lurker.validate_header_values({"x-content-type-options": "allow"})
        self.assertEqual(
            result,
            [
                {
                    "header": "x-content-type-options",
                    "value": "allow",
                    "reason": "must be nosniff",
                }
            ],
        )

    def test_csp_unsafe_inline_is_unsafe(self):
        result = lurker.validate_header_values(
            {"content-security-policy": "default-src 'self'; script-src 'unsafe-inline'"}
        )
        self.assertEqual(
            result,
            [
                {
                    "header": "content-security-policy",
                    "value": "default-src 'self'; script-src 'unsafe-inline'",
                    "reason": "must not be empty, *, unsafe-inline, or unsafe-eval",
                }
            ],
        )

    def test_csp_wildcard_directive_is_unsafe(self):
        result = lurker.validate_header_values(
            {"content-security-policy": "default-src *; script-src 'self'"}
        )
        self.assertEqual(
            result,
            [
                {
                    "header": "content-security-policy",
                    "value": "default-src *; script-src 'self'",
                    "reason": "must not be empty, *, unsafe-inline, or unsafe-eval",
                }
            ],
        )

    def test_referrer_unsafe_url_is_unsafe(self):
        result = lurker.validate_header_values({"referrer-policy": "unsafe-url"})
        self.assertEqual(
            result,
            [
                {
                    "header": "referrer-policy",
                    "value": "unsafe-url",
                    "reason": "must not be empty, unsafe-url, or no-referrer-when-downgrade",
                }
            ],
        )

    def test_referrer_strict_origin_is_safe(self):
        result = lurker.validate_header_values({"referrer-policy": "strict-origin"})
        self.assertEqual(result, [])

    def test_referrer_empty_value_is_unsafe(self):
        result = lurker.validate_header_values({"referrer-policy": ""})
        self.assertEqual(
            result,
            [
                {
                    "header": "referrer-policy",
                    "value": "",
                    "reason": "must not be empty, unsafe-url, or no-referrer-when-downgrade",
                }
            ],
        )


class TestDiffEngine(unittest.TestCase):
    def test_detect_changes_flags_missing_header_and_removed_path(self):
        old_state = {
            "/admin": {
                "status": 200,
                "headers": {
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "strict-transport-security": "max-age=31536000",
                },
            },
            "/legacy": {
                "status": 403,
                "headers": {"x-frame-options": "DENY"},
            },
        }
        new_state = {
            "/admin": {
                "status": 200,
                "headers": {
                    "x-frame-options": "DENY",
                    "strict-transport-security": "max-age=31536000",
                },
            }
        }

        result = lurker.detect_changes(old_state, new_state)

        self.assertEqual(result["new"], [])
        self.assertEqual(result["removed"], ["/legacy"])
        self.assertEqual(len(result["regressions"]), 1)
        self.assertEqual(result["regressions"][0]["path"], "/admin")
        self.assertIn(
            {
                "type": "missing_security_headers",
                "missing": ["Content-Security-Policy"],
            },
            result["regressions"][0]["reasons"],
        )

    def test_detect_changes_flags_new_endpoint(self):
        old_state = {}
        new_state = {
            "/api": {
                "status": 200,
                "headers": {"x-frame-options": "DENY"},
            }
        }

        result = lurker.detect_changes(old_state, new_state)

        self.assertEqual(result["new"], ["/api"])
        self.assertEqual(result["regressions"], [])
        self.assertEqual(result["removed"], [])

    def test_detect_changes_flags_safe_to_unsafe_value_as_regression(self):
        old_state = {
            "/admin": {
                "status": 200,
                "headers": {"x-frame-options": "DENY"},
            }
        }
        new_state = {
            "/admin": {
                "status": 200,
                "headers": {"x-frame-options": "ALLOWALL"},
            }
        }

        result = lurker.detect_changes(old_state, new_state)

        self.assertEqual(result["new"], [])
        self.assertEqual(result["removed"], [])
        self.assertEqual(len(result["regressions"]), 1)
        reasons = result["regressions"][0]["reasons"]
        self.assertIn(
            {
                "type": "unsafe_header_value",
                "header": "x-frame-options",
                "old_value": "DENY",
                "new_value": "ALLOWALL",
                "reason": "must be DENY or SAMEORIGIN",
            },
            reasons,
        )

    def test_detect_changes_does_not_flag_already_unsafe_value(self):
        old_state = {
            "/admin": {
                "status": 200,
                "headers": {"x-frame-options": "ALLOWALL"},
            }
        }
        new_state = {
            "/admin": {
                "status": 200,
                "headers": {"x-frame-options": "DENY"},
            }
        }

        result = lurker.detect_changes(old_state, new_state)

        self.assertEqual(result["regressions"], [])

    def test_detect_changes_flags_referrer_policy_empty_value_as_regression(self):
        old_state = {
            "/admin": {
                "status": 200,
                "headers": {"referrer-policy": "strict-origin"},
            }
        }
        new_state = {
            "/admin": {
                "status": 200,
                "headers": {"referrer-policy": ""},
            }
        }

        result = lurker.detect_changes(old_state, new_state)

        self.assertEqual(result["new"], [])
        self.assertEqual(result["removed"], [])
        self.assertEqual(len(result["regressions"]), 1)
        reasons = result["regressions"][0]["reasons"]
        self.assertIn(
            {
                "type": "unsafe_header_value",
                "header": "referrer-policy",
                "old_value": "strict-origin",
                "new_value": "",
                "reason": "must not be empty, unsafe-url, or no-referrer-when-downgrade",
            },
            reasons,
        )

    def test_detect_changes_ignores_permissions_policy_value_changes(self):
        old_state = {
            "/admin": {
                "status": 200,
                "headers": {"permissions-policy": "geolocation=()"},
            }
        }
        new_state = {
            "/admin": {
                "status": 200,
                "headers": {"permissions-policy": "camera=()"},
            }
        }

        result = lurker.detect_changes(old_state, new_state)

        self.assertEqual(result["new"], [])
        self.assertEqual(result["removed"], [])
        self.assertEqual(result["regressions"], [])

    def test_render_diff_summary_includes_unsafe_header_value(self):
        previous_no_color = lurker.NO_COLOR
        lurker.NO_COLOR = True
        try:
            summary = lurker.render_diff_summary(
                {
                    "new": [],
                    "regressions": [
                        {
                            "path": "/admin",
                            "reasons": [
                                {
                                    "type": "unsafe_header_value",
                                    "header": "x-frame-options",
                                    "old_value": "DENY",
                                    "new_value": "ALLOWALL",
                                    "reason": "must be DENY or SAMEORIGIN",
                                }
                            ],
                        }
                    ],
                    "removed": [],
                }
            )
        finally:
            lurker.NO_COLOR = previous_no_color

        self.assertIn(
            "unsafe value: x-frame-options changed to 'ALLOWALL' (must be DENY or SAMEORIGIN)",
            summary,
        )

    def test_detect_changes_flags_status_change(self):
        old_state = {
            "/admin": {"status": 200, "headers": {"x-frame-options": "DENY"}}
        }
        new_state = {
            "/admin": {"status": 500, "headers": {"x-frame-options": "DENY"}}
        }

        result = lurker.detect_changes(old_state, new_state)

        self.assertEqual(result["new"], [])
        self.assertEqual(result["removed"], [])
        self.assertEqual(len(result["regressions"]), 1)
        reasons = result["regressions"][0]["reasons"]
        self.assertIn({"type": "status_change", "old": 200, "new": 500}, reasons)


class TestDiscordNotifier(unittest.TestCase):
    @patch("lurker.urllib.request.urlopen")
    def test_send_discord_alert_posts_json_payload(self, mock_urlopen):
        response = MagicMock()
        response.__enter__.return_value = response
        response.__exit__.return_value = None
        mock_urlopen.return_value = response

        webhook_url = "https://discord.com/api/webhooks/123/abc"
        message = "Scan complete"

        lurker.send_discord_alert(webhook_url, message)

        mock_urlopen.assert_called_once()
        request = mock_urlopen.call_args.args[0]
        headers = {key.lower(): value for key, value in request.header_items()}

        self.assertEqual(request.full_url, webhook_url)
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(
            request.data,
            json.dumps({"content": message}).encode("utf-8"),
        )
        self.assertEqual(headers.get("content-type"), "application/json")

    def test_format_alert_message_summarizes_findings(self):
        diff_results = {
            "new": ["/new-admin"],
            "regressions": [
                {
                    "path": "/admin",
                    "reasons": [
                        {
                            "type": "missing_security_headers",
                            "missing": ["Content-Security-Policy"],
                        }
                    ],
                }
            ],
            "removed": ["/legacy"],
        }

        message = lurker.format_alert_message(diff_results)

        self.assertIn("Lurker Alert!", message)
        self.assertIn("New: /new-admin", message)
        self.assertIn("Regressions: /admin (missing headers: Content-Security-Policy)", message)
        self.assertIn("Removed: /legacy", message)

    def test_format_alert_message_describes_unsafe_header_values(self):
        message = lurker.format_alert_message(
            {
                "new": [],
                "regressions": [
                    {
                        "path": "/admin",
                        "reasons": [
                            {
                                "type": "unsafe_header_value",
                                "header": "x-frame-options",
                                "old_value": "DENY",
                                "new_value": "ALLOWALL",
                                "reason": "must be DENY or SAMEORIGIN",
                            }
                        ],
                    }
                ],
                "removed": [],
            }
        )

        self.assertIn(
            "unsafe value: x-frame-options changed to 'ALLOWALL' (must be DENY or SAMEORIGIN)",
            message,
        )

    def test_format_alert_message_returns_none_when_no_changes(self):
        result = lurker.format_alert_message({"new": [], "regressions": [], "removed": []})
        self.assertIsNone(result)

class TestCliAndConfig(unittest.TestCase):
    def setUp(self):
        self.parser = lurker._build_parser()

    def test_scan_args_optional_webhook(self):
        args = self.parser.parse_args(["scan", "--url", "http://a.com", "--wordlist", "w.txt"])
        self.assertIsNone(args.webhook_url)

    def test_diff_args_optional_webhook(self):
        args = self.parser.parse_args(["diff", "old.json", "new.json"])
        self.assertIsNone(args.webhook_url)

    @patch("lurker.scan_target")
    @patch("builtins.input", return_value="n")
    @patch("builtins.print")
    @patch("lurker.probe_endpoint")
    def test_scan_aborts_when_preflight_fails_and_user_declines(
        self,
        mock_probe_endpoint,
        mock_print,
        mock_input,
        mock_scan_target,
    ):
        mock_probe_endpoint.side_effect = urllib.error.URLError("Connection refused")
        with tempfile.TemporaryDirectory() as temp_dir:
            wordlist_path = os.path.join(temp_dir, "wordlist.txt")
            with open(wordlist_path, "w", encoding="utf-8") as wordlist_file:
                wordlist_file.write("/one\n/two\n")

            return_code = lurker.main([
                "scan",
                "--url", "http://example.com",
                "--wordlist", wordlist_path,
                "--output-dir", temp_dir,
            ])

        self.assertEqual(return_code, 1)
        mock_probe_endpoint.assert_called_once_with("http://example.com", "/")
        mock_input.assert_called_once()
        mock_scan_target.assert_not_called()

    @patch("builtins.print")
    @patch("lurker.scan_target")
    def test_preflight_404_does_not_prompt_and_scans(self, mock_scan_target, mock_print):
        # If probe_endpoint returns None (404), do not prompt; proceed to scan
        with tempfile.TemporaryDirectory() as temp_dir:
            wordlist_path = os.path.join(temp_dir, "wordlist.txt")
            with open(wordlist_path, "w", encoding="utf-8") as wordlist_file:
                wordlist_file.write("/one\n/two\n")

            with patch("lurker.probe_endpoint", return_value=None):
                lurker.main([
                    "scan",
                    "--url", "http://example.com",
                    "--wordlist", wordlist_path,
                    "--output-dir", temp_dir,
                ])

        mock_scan_target.assert_called()

    @patch("builtins.print")
    @patch("lurker.scan_target")
    def test_single_path_should_not_prompt_on_preflight_failure(self, mock_scan_target, mock_print):
        # Single-path wordlists should not trigger the preflight prompt even on URLError
        with tempfile.TemporaryDirectory() as temp_dir:
            wordlist_path = os.path.join(temp_dir, "wordlist.txt")
            with open(wordlist_path, "w", encoding="utf-8") as wordlist_file:
                wordlist_file.write("/only\n")

            with patch("lurker.probe_endpoint", side_effect=urllib.error.URLError("Connection refused")):
                lurker.main([
                    "scan",
                    "--url", "http://example.com",
                    "--wordlist", wordlist_path,
                    "--output-dir", temp_dir,
                ])

        mock_scan_target.assert_called()

    @patch("builtins.print")
    @patch("lurker.send_discord_alert")
    def test_scan_calls_webhook(self, mock_send_alert, mock_print):
        with tempfile.TemporaryDirectory() as temp_dir:
            wordlist_path = os.path.join(temp_dir, "wordlist.txt")
            with open(wordlist_path, "w", encoding="utf-8") as wordlist_file:
                wordlist_file.write("/found\n")

            with patch("lurker.probe_endpoint", return_value=(200, {})):
                lurker.main([
                    "scan",
                    "--url", "http://example.com",
                    "--wordlist", wordlist_path,
                    "--webhook-url", "http://fake.hook",
                    "--output-dir", temp_dir,
                ])

            state_path = os.path.join(temp_dir, "example_com", "state.json")
            self.assertTrue(os.path.exists(state_path))
            with open(state_path, "r", encoding="utf-8") as state_file:
                stored_state = json.load(state_file)
            self.assertIn("/found", stored_state)
            self.assertEqual(stored_state["/found"]["headers"], {})

            history_dir = os.path.join(temp_dir, "example_com", "history")
            self.assertTrue(os.path.isdir(history_dir))
            history_files = [name for name in os.listdir(history_dir) if name.endswith(".json")]
            self.assertTrue(history_files)
        
        mock_send_alert.assert_called_once()

    @patch("builtins.print")
    @patch("lurker.send_discord_alert")
    def test_scan_handles_webhook_error(self, mock_send_alert, mock_print):
        mock_send_alert.side_effect = urllib.error.URLError("Failed to connect")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            wordlist_path = os.path.join(temp_dir, "wordlist.txt")
            with open(wordlist_path, "w", encoding="utf-8") as wordlist_file:
                wordlist_file.write("/found\n")

            with patch("lurker.probe_endpoint", return_value=(200, {})):
                lurker.main([
                    "scan",
                    "--url", "http://example.com",
                    "--wordlist", wordlist_path,
                    "--webhook-url", "http://fake.hook",
                    "--output-dir", temp_dir,
                ])

            state_path = os.path.join(temp_dir, "example_com", "state.json")
            self.assertTrue(os.path.exists(state_path))
        
        printed_messages = [call.args[0] for call in mock_print.call_args_list if call.args]
        self.assertTrue(
            any("Failed to send Discord alert" in message for message in printed_messages)
        )

    @patch("builtins.print")
    def test_first_scan_reports_missing_security_headers(self, mock_print):
        with tempfile.TemporaryDirectory() as temp_dir:
            wordlist_path = os.path.join(temp_dir, "wordlist.txt")
            with open(wordlist_path, "w", encoding="utf-8") as wordlist_file:
                wordlist_file.write("/admin\n")

            with patch("lurker.probe_endpoint", return_value=(200, {})):
                with patch(
                    "lurker.scan_target",
                    return_value=(
                        {
                            "/admin": {
                                "status": 200,
                                "headers": {"x-frame-options": "DENY"},
                            }
                        },
                        [],
                    ),
                ):
                    lurker.main([
                        "scan",
                        "--url",
                        "http://example.com",
                        "--wordlist",
                        wordlist_path,
                        "--output-dir",
                        temp_dir,
                    ])

        printed_messages = [call.args[0] for call in mock_print.call_args_list if call.args]
        self.assertTrue(
            any("missing headers: Content-Security-Policy" in message for message in printed_messages)
        )

    @patch("builtins.print")
    def test_first_scan_does_not_report_missing_headers_when_complete(self, mock_print):
        with tempfile.TemporaryDirectory() as temp_dir:
            wordlist_path = os.path.join(temp_dir, "wordlist.txt")
            with open(wordlist_path, "w", encoding="utf-8") as wordlist_file:
                wordlist_file.write("/admin\n")

            complete_headers = {
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "Strict-Transport-Security": "max-age=31536000",
            }

            with patch("lurker.probe_endpoint", return_value=(200, {})):
                with patch(
                    "lurker.scan_target",
                    return_value=(
                        {
                            "/admin": {
                                "status": 200,
                                "headers": complete_headers,
                            }
                        },
                        [],
                    ),
                ):
                    lurker.main([
                        "scan",
                        "--url",
                        "http://example.com",
                        "--wordlist",
                        wordlist_path,
                        "--output-dir",
                        temp_dir,
                    ])

        printed_messages = [call.args[0] for call in mock_print.call_args_list if call.args]
        self.assertFalse(any("missing headers:" in message for message in printed_messages))

    def test_load_config_overrides(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "config.json")
            with open(config_path, "w", encoding="utf-8") as config_file:
                json.dump({"max_threads": 99, "output_dir": "test_output"}, config_file)

            config = lurker.load_config(config_path)
            self.assertEqual(config["max_threads"], 99)
            self.assertTrue(config["output_dir"].endswith("test_output"))

            # Test CLI override
            args = MagicMock(max_threads=101)
            resolved = lurker.apply_cli_overrides(config, args)
            self.assertEqual(resolved["max_threads"], 101)


class TestValidateUrl(unittest.TestCase):
    def test_valid_http_url(self):
        self.assertEqual(lurker.validate_url("http://example.com"), "http://example.com")

    def test_valid_https_url(self):
        self.assertEqual(lurker.validate_url("https://example.com"), "https://example.com")

    def test_missing_scheme_raises(self):
        with self.assertRaises(ValueError):
            lurker.validate_url("example.com")

    def test_missing_netloc_raises(self):
        with self.assertRaises(ValueError):
            lurker.validate_url("http://")

    def test_unsupported_scheme_raises(self):
        with self.assertRaises(ValueError):
            lurker.validate_url("ftp://example.com")

if __name__ == "__main__":
    unittest.main()
