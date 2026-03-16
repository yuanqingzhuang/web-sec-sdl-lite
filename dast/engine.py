# dast/engine.py
import json
from pathlib import Path
from typing import List, Dict, Any
from .xss import XSSScanner
from .sqli import SQLiScanner
from .traversal import TraversalScanner

class DASTEngine:
    """
    Core DAST scanning engine
    """

    def __init__(self, targets: List[Dict[str, Any]]):
        self.targets = targets
        self.results: List[Dict[str, Any]] = []
        self.xss_scanner = XSSScanner()
        self.sqli_scanner = SQLiScanner()
        self.traversal_scanner = TraversalScanner()

    def run(self) -> List[Dict[str, Any]]:
        """
        Run all scanners
        """
        print(f"[+] Starting DAST scan: {len(self.targets)} targets")

        for target in self.targets:
            self.scan_target(target)

        print(f"[+] Scan finished: {len(self.results)} findings")
        return self.results

    def scan_target(self, target: Dict[str, Any]) -> None:
        """
        Scan a single parameter target
        """
        url = target["url"]
        param = target["param"]

        print(f"[SCAN] {url} -> {param}")

        # Placeholder for scanners
        xss_results = self.xss_scanner.scan(target)
        sqli_results = self.sqli_scanner.scan(target)
        traversal_results = self.traversal_scanner.scan(target)
        # Future modules: XSS / SQLi / Traversal

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
        """
        Unified vulnerability structure
        """

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
