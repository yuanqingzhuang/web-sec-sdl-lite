#main.py
import argparse
import json
import os
from pathlib import Path

from crawler.engine import BasicCrawler
from crawler.target_builder import build_target_pool, save_target_pool
from dast.engine import DASTEngine, load_targets, save_results

RESULTS_DIR = Path("results")
CRAWL_OUTPUT_PATH = RESULTS_DIR / "crawl_output.json"
TARGETS_OUTPUT_PATH = RESULTS_DIR / "targets.json"
DAST_OUTPUT_PATH = RESULTS_DIR / "dast_output.json"
SAST_OUTPUT_PATH = RESULTS_DIR / "sast_output.json"
REPORT_OUTPUT_PATH = RESULTS_DIR / "report.md"


def ensure_results_dir() -> None:
    RESULTS_DIR.mkdir(exist_ok=True)


def run_crawler(target_url: str, max_pages: int = 10) -> dict:
    print(f"[+] Crawling target: {target_url}")
    crawler = BasicCrawler(start_url=target_url, max_pages=max_pages)
    crawl_data = crawler.crawl()
    crawler.save_results(crawl_data, str(CRAWL_OUTPUT_PATH))
    print(f"[+] Crawl result saved to {CRAWL_OUTPUT_PATH}")
    return crawl_data


def run_target_builder(crawl_data: dict | None = None) -> list[dict]:
    print("[+] Building target pool")

    if crawl_data is None:
        if not CRAWL_OUTPUT_PATH.exists():
            raise FileNotFoundError("crawl_output.json not found. Please run crawl first.")

        with open(CRAWL_OUTPUT_PATH, "r", encoding="utf-8") as f:
            crawl_data = json.load(f)

    targets = build_target_pool(crawl_data)
    save_target_pool(targets, str(TARGETS_OUTPUT_PATH))

    print(f"[+] Target pool saved to {TARGETS_OUTPUT_PATH}")
    print(f"[+] Total targets: {len(targets)}")
    return targets


def run_dast(target_url: str | None = None) -> list[dict]:

    """
    运行DAST扫描
    """
    print("[+] Running DAST")

    if not TARGETS_OUTPUT_PATH.exists():
        raise FileNotFoundError("targets.json not found. Please run crawl/build_targets first.")
     # 加载目标
    targets = load_targets(str(TARGETS_OUTPUT_PATH))

    engine = DASTEngine(targets)
    results = engine.run()
    save_results(results, str(DAST_OUTPUT_PATH))
    print(f"[+] DAST result saved to {DAST_OUTPUT_PATH}")
    return results


def run_sast(source_path: str | None = None) -> list[dict]:
    print("[+] Running SAST (placeholder)")

    results = [
        {
            "type": "placeholder",
            "file": source_path or "",
            "line": 0,
            "evidence": "SAST module not implemented yet",
            "severity": "info",
            "suggestion": "Implement SAST modules in Day 15-19"
        }
    ]

    with open(SAST_OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print(f"[+] SAST result saved to {SAST_OUTPUT_PATH}")
    return results


def run_report() -> str:
    print("[+] Generating report (placeholder)")

    report_lines = [
        "# Scan Report",
        "",
        "## Overview",
        "- This is a placeholder report.",
        "- Report module will be completed in Day 21.",
        "",
        "## Files",
        f"- Crawl output: `{CRAWL_OUTPUT_PATH}`",
        f"- Targets output: `{TARGETS_OUTPUT_PATH}`",
        f"- DAST output: `{DAST_OUTPUT_PATH}`",
        f"- SAST output: `{SAST_OUTPUT_PATH}`",
    ]

    report_text = "\n".join(report_lines)

    with open(REPORT_OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write(report_text)

    print(f"[+] Report saved to {REPORT_OUTPUT_PATH}")
    return report_text


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="web-sec-sdl-lite main dispatcher"
    )

    parser.add_argument(
        "--target",
        help="Target URL for crawl/DAST, e.g. http://127.0.0.1:5000"
    )
    parser.add_argument(
        "--source",
        help="Source code directory for SAST, e.g. ./targets/demo_flask_app"
    )
    parser.add_argument(
        "--mode",
        required=True,
        choices=["crawl", "build_targets", "dast", "sast", "report", "all"],
        help="Execution mode"
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=10,
        help="Maximum number of pages to crawl"
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ensure_results_dir()

    if args.mode == "crawl":
        if not args.target:
            raise ValueError("--target is required for crawl mode")
        run_crawler(args.target, args.max_pages)

    elif args.mode == "build_targets":
        run_target_builder()

    elif args.mode == "dast":
        run_dast(args.target)

    elif args.mode == "sast":
        run_sast(args.source)

    elif args.mode == "report":
        run_report()

    elif args.mode == "all":
        if not args.target:
            raise ValueError("--target is required for all mode")

        crawl_data = run_crawler(args.target, args.max_pages)
        run_target_builder(crawl_data)
        run_dast(args.target)

        if args.source:
            run_sast(args.source)
        else:
            print("[!] --source not provided, skipping SAST")

        run_report()


if __name__ == "__main__":
    main()
