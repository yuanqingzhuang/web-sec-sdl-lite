import requests

from .dvwa import login_dvwa


def parse_cookie_string(cookie_str: str) -> dict[str, str]:
    cookies: dict[str, str] = {}

    if not cookie_str:
        return cookies

    for part in cookie_str.split(";"):
        item = part.strip()
        if not item or "=" not in item:
            continue

        key, value = item.split("=", 1)
        key = key.strip()
        value = value.strip()

        if key:
            cookies[key] = value

    return cookies


def build_session(cookie_str: str = "") -> requests.Session:
    session = requests.Session()

    cookies = parse_cookie_string(cookie_str)
    for key, value in cookies.items():
        session.cookies.set(key, value)

    return session


def build_dvwa_session(
    base_url: str,
    username: str = "admin",
    password: str = "password",
    timeout: int = 10,
    security_level: str = "low",
) -> requests.Session:
    return login_dvwa(
        base_url=base_url,
        username=username,
        password=password,
        timeout=timeout,
        security_level=security_level,
    )
