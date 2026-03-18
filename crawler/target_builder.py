import json
from urllib.parse import urlparse, parse_qs
from typing import Any

IGNORE_INPUT_TYPES = {"submit", "button", "reset", "image", "hidden", "file"}
IGNORE_INPUT_NAMES = {"user_token", "MAX_FILE_SIZE", "PHPSESSID"}

def extract_query_params(url: str) -> list[str]:
    parsed = urlparse(url)
    query_dict = parse_qs(parsed.query, keep_blank_values=True)
    return list(query_dict.keys())

def build_target_pool(crawl_data: dict[str, Any]) -> list[dict[str, Any]]:
    targets = []
    seen = set()

    for page in crawl_data.get("pages", []):
        source_page = page.get("url", "")

        # 1. 页面自身 query 参数
        page_url = page.get("url", "")
        for param_name in extract_query_params(page_url):
            if not param_name:
                continue

            item = {
                "url": page_url,
                "method": "GET",
                "param": param_name,
                "location": "query",
                "source_page": source_page,
            }

            dedup_key = (
                item["url"],
                item["method"],
                item["param"],
                item["location"],
            )

            if dedup_key not in seen:
                seen.add(dedup_key)
                targets.append(item)

        # 2. form 参数
        for form in page.get("forms", []):
            action_url = form.get("action", source_page)
            method = form.get("method", "GET").upper()
            form_inputs = form.get("inputs", [])

            for input_item in form_inputs:
                param_name = input_item.get("name")
                input_type = (input_item.get("type") or "text").lower()

                if not param_name:
                    continue
                if param_name in IGNORE_INPUT_NAMES:
                    continue
                if input_type in IGNORE_INPUT_TYPES:
                    continue

                item = {
                    "url": action_url,
                    "method": method,
                    "param": param_name,
                    "location": "form",
                    "source_page": source_page,
                    "form_inputs": form_inputs,
                }

                dedup_key = (
                    item["url"],
                    item["method"],
                    item["param"],
                    item["location"],
                )

                if dedup_key not in seen:
                    seen.add(dedup_key)
                    targets.append(item)

    return targets

def save_target_pool(targets: list[dict[str, Any]], output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(targets, f, ensure_ascii=False, indent=2)
