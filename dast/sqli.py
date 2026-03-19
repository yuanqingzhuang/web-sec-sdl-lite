from typing import Any
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

import requests


SQLI_TEST_CASES = [
    {"payload": "1'", "kind": "error"},
    {"payload": "1' OR '1'='1", "kind": "boolean_true"},
    {"payload": "1' OR '1'='2", "kind": "boolean_false"},
    {"payload": "1' OR 1=1 -- -", "kind": "boolean_true"},
]


SQL_ERROR_KEYWORDS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql error",
    "mysql_fetch",
    "mysqli_sql_exception",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlite error",
    "sqlite3.operationalerror",
    "psycopg2.errors",
    "odbc",
    "postgresql",
    "ora-01756",
]


def has_sql_error(text: str) -> str | None:
    lowered = text.lower()
    for keyword in SQL_ERROR_KEYWORDS:
        if keyword in lowered:
            return keyword
    return None


def build_url_with_params(url: str, new_params: dict[str, str]) -> str:
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)

    merged = dict(query_pairs)
    merged.update(new_params)

    new_query = urlencode(list(merged.items()), doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def build_form_request_data(
    target: dict[str, Any],
    payload_param: str,
    payload_value: str,
    default_value: str = "1",
) -> dict[str, str]:
    data: dict[str, str] = {}

    for field in target.get("form_inputs", []):
        name = field.get("name")
        if not name:
            continue

        field_type = (field.get("type") or "text").lower()
        field_value = field.get("value", "")

        if name == payload_param:
            data[name] = payload_value
            continue

        if field_type == "submit":
            data[name] = field_value or "Submit"
            continue

        if field_type == "hidden":
            data[name] = field_value
            continue

        if field_type == "file":
            continue

        data[name] = field_value or default_value

    # 兜底，避免 form_inputs 缺失时没带 payload 参数
    if payload_param not in data:
        data[payload_param] = payload_value

    return data


class SQLiScanner:
    def __init__(self, timeout: int = 5, session: requests.Session | None = None):
        self.timeout = timeout
        self.session = session or requests.Session()

    def scan(self, target: dict[str, Any]) -> list[dict[str, Any]]:
        findings = []

        url = target.get("url", "")
        param = target.get("param", "")

        if not url or not param:
            return findings

        try:
            baseline_response = self._send_payload(target, "1")
        except requests.RequestException:
            return findings

        baseline_text = baseline_response.text
        baseline_len = len(baseline_text)

        if "/vulnerabilities/sqli/" in url and param == "id":
            print(
                f"[DEBUG][SQLI] baseline='1' "
                f"status={baseline_response.status_code} "
                f"len={baseline_len} "
                f"url={baseline_response.url}"
            )

        responses = []
        for case in SQLI_TEST_CASES:
            try:
                response = self._send_payload(target, case["payload"])
            except requests.RequestException:
                continue

            item = {
                "payload": case["payload"],
                "kind": case["kind"],
                "status_code": response.status_code,
                "text": response.text,
                "length": len(response.text),
                "final_url": str(response.url),
            }
            responses.append(item)

            if "/vulnerabilities/sqli/" in url and param == "id":
                print(
                    f"[DEBUG][SQLI] payload={case['payload']!r} "
                    f"status={response.status_code} "
                    f"len={len(response.text)} "
                    f"url={response.url}"
                )

        # 1. 报错型：payload 响应出现 SQL 报错，baseline 不出现
        baseline_error = has_sql_error(baseline_text)

        for item in responses:
            error_keyword = has_sql_error(item["text"])
            if error_keyword and not baseline_error:
                findings.append({
                    "type": "sqli",
                    "url": url,
                    "param": param,
                    "payload": item["payload"],
                    "evidence": f"SQL error keyword detected only after payload: {error_keyword}",
                    "severity": "high",
                    "verified": True,
                    "suggestion": "use parameterized queries / prepared statements instead of string concatenation"
                })
                return findings

        # 2. 布尔型：true/false 页面内容不同，且长度有差异
        true_case = next((r for r in responses if r["kind"] == "boolean_true"), None)
        false_case = next((r for r in responses if r["kind"] == "boolean_false"), None)

        if true_case and false_case:
            length_gap = abs(true_case["length"] - false_case["length"])
            texts_differ = true_case["text"] != false_case["text"]

            if texts_differ and length_gap > 5:
                findings.append({
                    "type": "sqli",
                    "url": url,
                    "param": param,
                    "payload": true_case["payload"],
                    "evidence": (
                        f"boolean-based difference detected; "
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
        location = target.get("location", "")

        # GET + form：重放整张表单，保留 Submit=Submit
        if method == "GET" and location == "form":
            params = build_form_request_data(target, param, payload)
            test_url = build_url_with_params(url, params)
            return self.session.get(test_url, timeout=self.timeout)

        # GET + query：只替换 query 参数
        if method == "GET":
            test_url = build_url_with_params(url, {param: payload})
            return self.session.get(test_url, timeout=self.timeout)

        # POST + form：重放整张表单
        if method == "POST":
            data = build_form_request_data(target, param, payload)
            return self.session.post(url, data=data, timeout=self.timeout)

        raise requests.RequestException(f"Unsupported method: {method}")
