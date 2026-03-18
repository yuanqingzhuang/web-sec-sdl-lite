import json
from pathlib import Path
from typing import List, Dict, Any

import requests

from .xss import XSSScanner
from .sqli import SQLiScanner
from .traversal import TraversalScanner


class DASTEngine:
    """
    Core DAST scanning engine
    """

    def __init__(self, targets: List[Dict[str, Any]], session: requests.Session | None = None):
        self.targets = targets
        self.results: List[Dict[str, Any]] = []
        self.session = session or requests.Session()
        self.xss_scanner = XSSScanner(session=self.session)
        self.sqli_scanner = SQLiScanner(session=self.session)
        self.traversal_scanner = TraversalScanner(session=self.session)

    def run(self) -> List[Dict[str, Any]]:
        print(f"[+] Starting DAST scan: {len(self.targets)} targets")

        for target in self.targets:
            self.scan_target(target)

        print(f"[+] Scan finished: {len(self.results)} findings")
        return self.results

    def scan_target(self, target: Dict[str, Any]) -> None:
        url = target["url"]
        param = target["param"]

        print(f"[SCAN] {url} -> {param}")

        xss_results = self.xss_scanner.scan(target)
        sqli_results = self.sqli_scanner.scan(target)
        traversal_results = self.traversal_scanner.scan(target)

        self.results.extend(xss_results)
        self.results.extend(sqli_results)
        self.results.extend(traversal_results)

    @staticmethod
    def build_finding(
        vuln_type: str,
        url: str,
        param: str,
        payload: str,
        evidence: str,
        severity: str,
        verified: bool,
        suggestion: str
    ) -> Dict[str, Any]:
        return {
            "type": vuln_type,
            "url": url,
            "param": param,
            "payload": payload,
            "evidence": evidence,
            "severity": severity,
            "verified": verified,
            "suggestion": suggestion
        }


def load_targets(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_results(results: List[Dict[str, Any]], path: str) -> None:
    Path(path).parent.mkdir(exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
