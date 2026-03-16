#dast/sqli.py
from typing import Any
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

import requests


SQLI_TEST_CASES = [
    {
        "payload": "'",
        "kind": "error",
    },
    {
        "payload": "' OR '1'='1",
        "kind": "boolean_true",
    },
    {
        "payload": "' OR '1'='2",
        "kind": "boolean_false",
    },
    {
        "payload": "' OR 1=1 --",
        "kind": "boolean_true",
    },
]


SQL_ERROR_KEYWORDS = [
    "sql syntax",
    "warning: mysql",
    "mysql error",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlite error",
    "sqlite3.operationalerror",
    "psycopg2.errors",
    "syntax error",
    "database error",
    "odbc",
    "postgresql",
]


def build_url_with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)

    updated = []
    found = False

    for key, old_value in query_pairs:
        if key == param:
            updated.append((key, value))
            found = True
        else:
            updated.append((key, old_value))

    if not found:
        updated.append((param, value))

    new_query = urlencode(updated, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def build_post_data(target: dict[str, Any], payload_param: str, payload_value: str) -> dict[str, str]:
    data = {}

    current_param = target.get("param", "")
    if current_param:
        data[current_param] = "1"

    data[payload_param] = payload_value
    return data


def has_sql_error(text: str) -> str | None:
    lowered = text.lower()
    for keyword in SQL_ERROR_KEYWORDS:
        if keyword in lowered:
            return keyword
    return None


class SQLiScanner:
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.session = requests.Session()

    def scan(self, target: dict[str, Any]) -> list[dict[str, Any]]:
        findings = []

        method = target.get("method", "GET").upper()
        url = target.get("url", "")
        param = target.get("param", "")

        if not url or not param:
            return findings

        baseline_response = self._send_payload(target, "1")
        baseline_text = baseline_response.text
        baseline_len = len(baseline_text)

        responses = []
        for case in SQLI_TEST_CASES:
            try:
                response = self._send_payload(target, case["payload"])
            except requests.RequestException:
                continue

            responses.append({
                "payload": case["payload"],
                "kind": case["kind"],
                "status_code": response.status_code,
                "text": response.text,
                "length": len(response.text),
            })

        # 1. 报错型判断
        for item in responses:
            error_keyword = has_sql_error(item["text"])
            if error_keyword:
                findings.append({
                    "type": "sqli",
                    "url": url,
                    "param": param,
                    "payload": item["payload"],
                    "evidence": f"SQL error keyword detected: {error_keyword}",
                    "severity": "high",
                    "verified": True,
                    "suggestion": "use parameterized queries / prepared statements instead of string concatenation"
                })
                return findings

        # 2. 布尔型基础对比
        true_case = next((r for r in responses if r["kind"] == "boolean_true"), None)
        false_case = next((r for r in responses if r["kind"] == "boolean_false"), None)

        if true_case and false_case:
            length_gap = abs(true_case["length"] - false_case["length"])
            baseline_gap_true = abs(true_case["length"] - baseline_len)
            baseline_gap_false = abs(false_case["length"] - baseline_len)

            # 简化判断：true/false 响应差异明显
            if length_gap > 20 and baseline_gap_true != baseline_gap_false:
                findings.append({
                    "type": "sqli",
                    "url": url,
                    "param": param,
                    "payload": true_case["payload"],
                    "evidence": (
                        f"response length changed after SQLi payloads; "
                        f"baseline={baseline_len}, true={true_case['length']}, false={false_case['length']}"
                    ),
                    "severity": "high",
                    "verified": True,
                    "suggestion": "use parameterized queries / prepared statements instead of string concatenation"
                })

        return findings

    def _send_payload(self, target: dict[str, Any], payload: str) -> requests.Response:
        method = target.get("method", "GET").upper()
        url = target.get("url", "")
        param = target.get("param", "")

        if method == "GET":
            test_url = build_url_with_param(url, param, payload)
            return self.session.get(test_url, timeout=self.timeout)

        if method == "POST":
            data = build_post_data(target, param, payload)
            return self.session.post(url, data=data, timeout=self.timeout)

        raise requests.RequestException(f"Unsupported method: {method}")
