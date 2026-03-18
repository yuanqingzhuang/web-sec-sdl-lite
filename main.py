from __future__ import annotations

import argparse
import inspect
import json
from pathlib import Path

try:
    from auth.session import build_session, build_dvwa_session
except Exception:  # pragma: no cover
    build_session = None
    build_dvwa_session = None

from crawler.engine import BasicCrawler
from crawler.target_builder import build_target_pool, save_target_pool
from dast.engine import DASTEngine, load_targets, save_results
from report.aggregator import aggregate_from_files
from report.reporter import write_report
from sast.scanner import scan_directory, save_results as save_sast_results, build_stats as build_sast_stats

RESULTS_DIR = Path('results')
CRAWL_OUTPUT_PATH = RESULTS_DIR / 'crawl_output.json'
TARGETS_OUTPUT_PATH = RESULTS_DIR / 'targets.json'
DAST_OUTPUT_PATH = RESULTS_DIR / 'dast_output.json'
SAST_OUTPUT_PATH = RESULTS_DIR / 'sast_output.json'
AGGREGATED_OUTPUT_PATH = RESULTS_DIR / 'aggregated_output.json'
REPORT_OUTPUT_PATH = RESULTS_DIR / 'report.md'


def ensure_results_dir() -> None:
    RESULTS_DIR.mkdir(exist_ok=True)


def _supports_argument(callable_obj, arg_name: str) -> bool:
    try:
        signature = inspect.signature(callable_obj)
    except (TypeError, ValueError):
        return False
    return arg_name in signature.parameters


def resolve_session(
    target_url: str | None = None,
    cookie_str: str = '',
    use_dvwa_login: bool = False,
    username: str = 'admin',
    password: str = 'password',
):
    if use_dvwa_login:
        if build_dvwa_session is None:
            raise RuntimeError('DVWA login module is unavailable')
        if not target_url:
            raise ValueError('--target is required when --dvwa-login is enabled')
        return build_dvwa_session(
            base_url=target_url,
            username=username,
            password=password,
        )

    if build_session is None:
        return None

    if not cookie_str:
        return None

    return build_session(cookie_str)


def run_crawler(
    target_url: str,
    max_pages: int = 1000,
    cookie_str: str = '',
    use_dvwa_login: bool = False,
    username: str = 'admin',
    password: str = 'password',
) -> dict:
    print(f'[+] Crawling target: {target_url}')

    session = resolve_session(
        target_url=target_url,
        cookie_str=cookie_str,
        use_dvwa_login=use_dvwa_login,
        username=username,
        password=password,
    )

    crawler_kwargs = {
        'start_url': target_url,
        'max_pages': max_pages,
    }
    if session is not None and _supports_argument(BasicCrawler, 'session'):
        crawler_kwargs['session'] = session

    crawler = BasicCrawler(**crawler_kwargs)
    crawl_data = crawler.crawl()
    crawler.save_results(crawl_data, str(CRAWL_OUTPUT_PATH))
    print(f'[+] Crawl result saved to {CRAWL_OUTPUT_PATH}')
    return crawl_data


def run_target_builder(crawl_data: dict | None = None) -> list[dict]:
    print('[+] Building target pool')
    if crawl_data is None:
        if not CRAWL_OUTPUT_PATH.exists():
            raise FileNotFoundError('crawl_output.json not found. Please run crawl first.')
        with open(CRAWL_OUTPUT_PATH, 'r', encoding='utf-8') as handle:
            crawl_data = json.load(handle)

    targets = build_target_pool(crawl_data)
    save_target_pool(targets, str(TARGETS_OUTPUT_PATH))
    print(f'[+] Target pool saved to {TARGETS_OUTPUT_PATH}')
    print(f'[+] Total targets: {len(targets)}')
    return targets


def run_dast(
    target_url: str | None = None,
    cookie_str: str = '',
    use_dvwa_login: bool = False,
    username: str = 'admin',
    password: str = 'password',
) -> list[dict]:
    print('[+] Running DAST')
    if not TARGETS_OUTPUT_PATH.exists():
        raise FileNotFoundError('targets.json not found. Please run crawl/build_targets first.')

    targets = load_targets(str(TARGETS_OUTPUT_PATH))

    session = resolve_session(
        target_url=target_url,
        cookie_str=cookie_str,
        use_dvwa_login=use_dvwa_login,
        username=username,
        password=password,
    )

    engine_kwargs = {'targets': targets}
    if session is not None and _supports_argument(DASTEngine, 'session'):
        engine_kwargs['session'] = session

    engine = DASTEngine(**engine_kwargs)
    results = engine.run()
    save_results(results, str(DAST_OUTPUT_PATH))
    print(f'[+] DAST result saved to {DAST_OUTPUT_PATH}')
    return results


def run_sast(source_path: str | None = None) -> list[dict]:
    if not source_path:
        raise ValueError('--source is required for sast mode')
    print(f'[+] Running SAST on: {source_path}')
    results = scan_directory(source_path)
    save_sast_results(results, str(SAST_OUTPUT_PATH))
    stats = build_sast_stats(results)
    print(f"[+] SAST result saved to {SAST_OUTPUT_PATH}")
    print(f"[+] SAST stats: total={stats['total_findings']} by_type={stats['by_type']} by_severity={stats['by_severity']}")
    return results


def run_report(target_url: str | None = None, source_path: str | None = None) -> str:
    print('[+] Aggregating results and generating report')
    aggregate = aggregate_from_files(
        dast_path=DAST_OUTPUT_PATH,
        sast_path=SAST_OUTPUT_PATH,
        output_path=AGGREGATED_OUTPUT_PATH,
    )
    report_text = write_report(
        aggregate,
        REPORT_OUTPUT_PATH,
        metadata={
            'target': target_url or 'N/A',
            'source': source_path or 'N/A',
        },
    )
    print(f'[+] Aggregated result saved to {AGGREGATED_OUTPUT_PATH}')
    print(f'[+] Report saved to {REPORT_OUTPUT_PATH}')
    return report_text


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='web-sec-sdl-lite main dispatcher')
    parser.add_argument('--target', help='Target URL for crawl/DAST, e.g. http://127.0.0.1:5000')
    parser.add_argument('--source', help='Source code directory for SAST, e.g. ./targets/demo_flask_app')
    parser.add_argument('--mode', required=True, choices=['crawl', 'build_targets', 'dast', 'sast', 'report', 'all'], help='Execution mode')
    parser.add_argument('--max-pages', type=int, default=1000, help='Maximum number of pages to crawl')

    parser.add_argument('--cookie', default='', help='Cookie string for authenticated scan, e.g. "PHPSESSID=xxx; security=low"')

    parser.add_argument('--dvwa-login', action='store_true', help='Use automatic DVWA login instead of manual cookie')
    parser.add_argument('--username', default='admin', help='Username for DVWA login')
    parser.add_argument('--password', default='password', help='Password for DVWA login')

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ensure_results_dir()

    if args.mode == 'crawl':
        if not args.target:
            raise ValueError('--target is required for crawl mode')
        run_crawler(
            args.target,
            args.max_pages,
            args.cookie,
            args.dvwa_login,
            args.username,
            args.password,
        )

    elif args.mode == 'build_targets':
        run_target_builder()

    elif args.mode == 'dast':
        run_dast(
            args.target,
            args.cookie,
            args.dvwa_login,
            args.username,
            args.password,
        )

    elif args.mode == 'sast':
        run_sast(args.source)

    elif args.mode == 'report':
        run_report(args.target, args.source)

    elif args.mode == 'all':
        if not args.target and not args.source:
            raise ValueError('--all requires at least --target or --source')

        if args.target:
            crawl_data = run_crawler(
                args.target,
                args.max_pages,
                args.cookie,
                args.dvwa_login,
                args.username,
                args.password,
            )
            run_target_builder(crawl_data)
            run_dast(
                args.target,
                args.cookie,
                args.dvwa_login,
                args.username,
                args.password,
            )
        else:
            print('[!] --target not provided, skipping crawl/build_targets/dast')

        if args.source:
            run_sast(args.source)
        else:
            print('[!] --source not provided, skipping SAST')

        run_report(args.target, args.source)


if __name__ == '__main__':
    main()
