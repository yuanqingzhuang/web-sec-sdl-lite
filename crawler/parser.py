# crawler/parser.py
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    cleaned = parsed._replace(fragment="")
    return cleaned.geturl()


def extract_links(html: str, base_url: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    links = []

    for a_tag in soup.find_all("a", href=True):
        href = a_tag.get("href", "").strip()
        if not href:
            continue
        if href.startswith("javascript:") or href.startswith("mailto:"):
            continue

        full_url = urljoin(base_url, href)
        full_url = normalize_url(full_url)
        links.append(full_url)

    return list(dict.fromkeys(links))


def extract_forms(html: str, base_url: str) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")
    forms = []

    for form in soup.find_all("form"):
        method = form.get("method", "GET").upper()
        action = form.get("action", "").strip()
        action_url = urljoin(base_url, action) if action else base_url

        inputs = []
        for input_tag in form.find_all("input"):
            inputs.append({
                "name": input_tag.get("name"),
                "type": input_tag.get("type", "text"),
                "value": input_tag.get("value", "")
            })

        forms.append({
            "method": method,
            "action": action_url,
            "inputs": inputs
        })

    return forms
