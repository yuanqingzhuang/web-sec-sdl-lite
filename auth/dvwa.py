import re
from urllib.parse import urljoin

import requests


def extract_user_token(html: str) -> str:
    patterns = [
        r'name=["\']user_token["\']\s+value=["\']([^"\']+)["\']',
        r'value=["\']([^"\']+)["\']\s+name=["\']user_token["\']',
    ]

    for pattern in patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return match.group(1)

    raise ValueError("user_token not found in page")


def looks_like_login_page(html: str) -> bool:
    text = html.lower()
    return (
        "user_token" in text
        and "password" in text
        and "login" in text
        and "username" in text
    )


def login_dvwa(
    base_url: str,
    username: str = "admin",
    password: str = "password",
    timeout: int = 10,
    security_level: str = "low",
) -> requests.Session:
    session = requests.Session()
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        )
    })

    normalized_base = base_url.rstrip("/") + "/"
    login_url = urljoin(normalized_base, "login.php")
    index_url = urljoin(normalized_base, "index.php")
    security_url = urljoin(normalized_base, "security.php")

    # 1. GET login page and extract token
    resp = session.get(login_url, timeout=timeout)
    resp.raise_for_status()

    token = extract_user_token(resp.text)

    # 2. POST login form
    login_data = {
        "username": username,
        "password": password,
        "Login": "Login",
        "user_token": token,
    }

    resp = session.post(
        login_url,
        data=login_data,
        timeout=timeout,
        allow_redirects=True,
    )
    resp.raise_for_status()

    # 3. Verify login
    check = session.get(index_url, timeout=timeout, allow_redirects=True)
    check.raise_for_status()

    if "login.php" in check.url.lower() or looks_like_login_page(check.text):
        raise RuntimeError("DVWA login failed: still redirected to login.php")

    # 4.Set security level
    try:
        sec_page = session.get(security_url, timeout=timeout, allow_redirects=True)
        sec_page.raise_for_status()

        sec_token = extract_user_token(sec_page.text)
        sec_data = {
            "security": security_level,
            "seclev_submit": "Submit",
            "user_token": sec_token,
        }

        sec_resp = session.post(
            security_url,
            data=sec_data,
            timeout=timeout,
            allow_redirects=True,
        )
        sec_resp.raise_for_status()
    except Exception:

        pass

    return session
