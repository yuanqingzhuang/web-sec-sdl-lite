# dast/xss.py
import html
from typing import Any
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

import requests


DEFAULT_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
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
        data[current_param] = "test"

    data[payload_param] = payload_value
    return data


def get_evidence_snippet(text: str, payload: str, radius: int = 40) -> tuple[str, int]:
    index = text.find(payload)
    if index == -1:
        return "", -1

    start = max(0, index - radius)
    end = min(len(text), index + len(payload) + radius)
    snippet = text[start:end]
    return snippet, index


def looks_like_html_response(response: requests.Response) -> bool:
    content_type = response.headers.get("Content-Type", "").lower()
    return "html" in content_type or "<html" in response.text.lower()


def is_payload_in_html_context(body: str, payload: str) -> bool:
    lowered = body.lower()
    payload_lower = payload.lower()

    if payload_lower not in lowered:
        return False

    html_indicators = [
        "<script",
        "<input",
        "<div",
        "<span",
        "<a ",
        "<body",
        "<html",
        "value=",
        "href=",
    ]

    return any(indicator in lowered for indicator in html_indicators)


class XSSScanner:
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.session = requests.Session()

    def scan(self, target: dict[str, Any]) -> list[dict[str, Any]]:
        findings = []

        method = target.get("method", "GET").upper()
        url = target.get("url", "")
        param = target.get("param", "")
        location = target.get("location", "")

        if not url or not param:
            return findings

        for payload in DEFAULT_XSS_PAYLOADS:
            try:
                response = self._send_payload(target, payload)
            except requests.RequestException:
                continue

            if not response:
                continue

            body = response.text

            # Day 9: 原样反射判断
            raw_reflected = payload in body

            # Day 10: 基础降误报
            escaped_reflected = html.escape(payload) in body
            html_context = is_payload_in_html_context(body, payload)

            if raw_reflected and looks_like_html_response(response) and html_context:
                snippet, index = get_evidence_snippet(body, payload)

                findings.append({
                    "type": "xss",
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "evidence": f"payload reflected in HTML response at offset {index}: {snippet}",
                    "severity": "medium",
                    "verified": True,
                    "suggestion": "escape untrusted output before rendering HTML; use template autoescaping and input validation"
                })
                break

            # 只做提示，不判真
            if raw_reflected and not html_context:
                snippet, index = get_evidence_snippet(body, payload)

                findings.append({
                    "type": "xss",
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "evidence": f"payload reflected, but HTML execution context is unclear at offset {index}: {snippet}",
                    "severity": "low",
                    "verified": False,
                    "suggestion": "manually verify reflection context and ensure output encoding is applied"
                })
                break

            if escaped_reflected:
                # 有反射但已被转义，不报漏洞
                continue

        return findings

    def _send_payload(self, target: dict[str, Any], payload: str) -> requests.Response:
        method = target.get("method", "GET").upper()
        url = target.get("url", "")
        param = target.get("param", "")
        location = target.get("location", "")

        if method == "GET":
            test_url = build_url_with_param(url, param, payload)
            return self.session.get(test_url, timeout=self.timeout)

        if method == "POST":
            data = build_post_data(target, param, payload)
            return self.session.post(url, data=data, timeout=self.timeout)

        # 其他方法暂不处理
        raise requests.RequestException(f"Unsupported method: {method}")
