# crawler/engine.py
import json
from collections import deque
from urllib.parse import urlparse

import requests

from .parser import extract_links, extract_forms


class BasicCrawler:
    def __init__(self, start_url: str, max_pages: int = 10, timeout: int = 5):
        self.start_url = start_url
        self.max_pages = max_pages
        self.timeout = timeout
        self.visited = set()
        self.results = []

    def is_same_domain(self, url: str) -> bool:
        start_netloc = urlparse(self.start_url).netloc
        target_netloc = urlparse(url).netloc
        return start_netloc == target_netloc

    def fetch_page(self, url: str) -> str | None:
        try:
            response = requests.get(url, timeout=self.timeout)
            response.raise_for_status()

            content_type = response.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                return None

            return response.text
        except requests.RequestException:
            return None

    def crawl(self) -> dict:
        queue = deque([self.start_url])

        while queue and len(self.visited) < self.max_pages:
            current_url = queue.popleft()

            if current_url in self.visited:
                continue

            self.visited.add(current_url)

            html = self.fetch_page(current_url)
            if not html:
                continue

            links = extract_links(html, current_url)
            forms = extract_forms(html, current_url)

            self.results.append({
                "url": current_url,
                "links": links,
                "forms": forms
            })

            for link in links:
                if self.is_same_domain(link) and link not in self.visited:
                    queue.append(link)

        return {
            "start_url": self.start_url,
            "pages": self.results
        }

    @staticmethod
    def save_results(data: dict, output_path: str) -> None:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
