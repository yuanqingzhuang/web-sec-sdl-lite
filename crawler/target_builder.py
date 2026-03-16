# crawler/target_builder.py
import json
from urllib.parse import urlparse, parse_qs
from typing import Any


def extract_query_params(url: str) -> list[str]:
    parsed = urlparse(url)
    query_dict = parse_qs(parsed.query, keep_blank_values=True)
    return list(query_dict.keys())


def build_target_pool(crawl_data: dict[str, Any]) -> list[dict[str, str]]:
    targets = []
    seen = set()

    for page in crawl_data.get("pages", []):
        source_page = page.get("url", "")

        # 1. 提取页面自身 URL 中的 query 参数
        page_url = page.get("url", "")
        for param_name in extract_query_params(page_url):
            item = {
                "url": page_url,
                "method": "GET",
                "param": param_name,
                "location": "query",
                "source_page": source_page
            }

            dedup_key = (
                item["url"],
                item["method"],
                item["param"],
                item["location"],
                item["source_page"]
            )

            if dedup_key not in seen:
                seen.add(dedup_key)
                targets.append(item)

        # 2. 提取 form 中的参数
        for form in page.get("forms", []):
            action_url = form.get("action", source_page)
            method = form.get("method", "GET").upper()

            for input_item in form.get("inputs", []):
                param_name = input_item.get("name")

                # 跳过没有 name 的 input
                if not param_name:
                    continue

                item = {
                    "url": action_url,
                    "method": method,
                    "param": param_name,
                    "location": "form",
                    "source_page": source_page
                }

                dedup_key = (
                    item["url"],
                    item["method"],
                    item["param"],
                    item["location"],
                    item["source_page"]
                )

                if dedup_key not in seen:
                    seen.add(dedup_key)
                    targets.append(item)

    return targets


def save_target_pool(targets: list[dict[str, str]], output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(targets, f, ensure_ascii=False, indent=2)
