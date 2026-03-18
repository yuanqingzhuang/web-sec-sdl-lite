import re
import sys
from urllib.parse import urljoin

import requests


def extract_user_token(html: str) -> str:
    """
    从 DVWA 登录页提取 user_token
    """
    patterns = [
        r'name=["\']user_token["\']\s+value=["\']([^"\']+)["\']',
        r'value=["\']([^"\']+)["\']\s+name=["\']user_token["\']',
    ]

    for pattern in patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return match.group(1)

    raise ValueError("user_token not found in login page")


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
) -> requests.Session:
    """
    登录 DVWA，返回已登录的 Session
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    })

    login_url = urljoin(base_url.rstrip("/") + "/", "login.php")
    index_url = urljoin(base_url.rstrip("/") + "/", "index.php")
    security_url = urljoin(base_url.rstrip("/") + "/", "security.php")

    print(f"[1] GET login page: {login_url}")
    resp = session.get(login_url, timeout=timeout)
    resp.raise_for_status()

    print(f"    status={resp.status_code} final_url={resp.url}")
    token = extract_user_token(resp.text)
    print(f"    user_token={token}")

    print("[2] POST login form")
    login_data = {
        "username": username,
        "password": password,
        "Login": "Login",
        "user_token": token,
    }

    resp = session.post(login_url, data=login_data, timeout=timeout, allow_redirects=True)
    resp.raise_for_status()

    print(f"    status={resp.status_code} final_url={resp.url}")
    print(f"    cookies={session.cookies.get_dict()}")

    print("[3] Verify login by visiting index.php")
    check = session.get(index_url, timeout=timeout, allow_redirects=True)
    check.raise_for_status()

    print(f"    status={check.status_code} final_url={check.url}")

    if "login.php" in check.url.lower() or looks_like_login_page(check.text):
        raise RuntimeError("Login failed: still redirected to login page")

    print("    login ok")

    # 尝试把 security 固定成 low
    print("[4] Try setting security level to low")
    try:
        sec_page = session.get(security_url, timeout=timeout)
        sec_page.raise_for_status()

        sec_token = extract_user_token(sec_page.text)
        sec_data = {
            "security": "low",
            "seclev_submit": "Submit",
            "user_token": sec_token,
        }

        sec_resp = session.post(security_url, data=sec_data, timeout=timeout, allow_redirects=True)
        sec_resp.raise_for_status()

        print(f"    status={sec_resp.status_code} final_url={sec_resp.url}")
    except Exception as e:
        print(f"    warning: failed to set security=low automatically: {e}")

    return session


def test_sqli_page(session: requests.Session, base_url: str, timeout: int = 10) -> None:
    """
    验证是否能带登录态访问 SQLi 页面
    """
    sqli_url = urljoin(base_url.rstrip("/") + "/", "vulnerabilities/sqli/")
    print(f"[5] Visit SQLi page: {sqli_url}")

    resp = session.get(sqli_url, timeout=timeout, allow_redirects=True)
    resp.raise_for_status()

    print(f"    status={resp.status_code} final_url={resp.url}")

    if "login.php" in resp.url.lower() or looks_like_login_page(resp.text):
        raise RuntimeError("Not authenticated on SQLi page: redirected to login.php")

    if "Vulnerability: SQL Injection" not in resp.text:
        print("    warning: SQLi marker text not found, but page is not login page")
    else:
        print("    SQLi page access ok")

    test_url = sqli_url + "?id=1%27or%20%271=1&Submit=Submit"
    print(f"[6] Visit known-working test URL: {test_url}")

    resp2 = session.get(test_url, timeout=timeout, allow_redirects=True)
    resp2.raise_for_status()

    print(f"    status={resp2.status_code} final_url={resp2.url}")

    if "login.php" in resp2.url.lower() or looks_like_login_page(resp2.text):
        raise RuntimeError("Known-working SQLi URL still redirected to login.php")

    print("    known-working SQLi URL reachable with current session")

    # 打印一点关键片段，方便肉眼确认不是登录页
    preview = resp2.text[:500].replace("\n", " ")
    print("    response preview:")
    print(f"    {preview}")


def main():
    # 可按需改成你的地址
    base_url = "http://192.168.23.132/dvwa"

    # 允许命令行传 base_url username password
    if len(sys.argv) >= 2:
        base_url = sys.argv[1]
    username = sys.argv[2] if len(sys.argv) >= 3 else "admin"
    password = sys.argv[3] if len(sys.argv) >= 4 else "password"

    print(f"base_url={base_url}")
    print(f"username={username}")

    session = login_dvwa(base_url, username=username, password=password)
    test_sqli_page(session, base_url)

    print("[DONE] DVWA login/session test passed")


if __name__ == "__main__":
    main()
