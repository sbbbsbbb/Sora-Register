"""
协议版 ChatGPT 注册（严格按 protocol_keygen 一套）
入口：register_one_protocol(email, password, jwt_token, get_otp_fn, user_info, **kwargs)。
流程（keygen 单流程）：GET /oauth/authorize(screen_hint=signup) -> POST authorize/continue(sentinel) -> GET create-account/password -> POST user/register(sentinel) -> send_otp -> 邮局取验证码 -> validate_otp -> create_account -> callback -> 取 code 换 AT/RT 或 8.6 登录取 code 换 RT -> 返回 tokens 供 runner 写入账号列表。
邮箱/代理/OAuth Client ID 等均从配置（Web 系统设置）获取。
"""

import base64
import hashlib
import json
import os
import random
import re
import secrets
import time
import uuid
from urllib.parse import urlparse, parse_qs, urlencode
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import (
    cfg,
    HTTP_TIMEOUT,
    get_proxy_url_for_session,
)
from utils import get_user_agent

try:
    from curl_cffi import requests as curl_requests
    CURL_CFFI_AVAILABLE = True
except ImportError:
    curl_requests = None
    CURL_CFFI_AVAILABLE = False

try:
    from protocol_sentinel import build_sentinel_token, build_sentinel_token_pow_only
except Exception:
    try:
        from protocol.protocol_sentinel import build_sentinel_token, build_sentinel_token_pow_only
    except Exception:
        build_sentinel_token = None
        build_sentinel_token_pow_only = None

CHATGPT_ORIGIN = "https://chatgpt.com"
AUTH_ORIGIN = "https://auth.openai.com"

# OAuth Code 换 Token（Codex / ChatGPT），运行时从 cfg.oauth 读（Web 下为系统设置）
OAUTH_ISSUER = AUTH_ORIGIN


def _get_oauth_client_id() -> str:
    return (getattr(getattr(cfg, "oauth", None), "client_id", None) or "").strip()


def _get_oauth_redirect_uri() -> str:
    return (getattr(getattr(cfg, "oauth", None), "redirect_uri", None) or "").strip() or f"{CHATGPT_ORIGIN}/"


def _has_cookie(session, name: str) -> bool:
    """兼容 requests 与 curl_cffi：判断 session 是否含有名为 name 的 cookie。"""
    try:
        if getattr(session.cookies, "get", None):
            if session.cookies.get(name):
                return True
        for c in getattr(session, "cookies", []):
            if getattr(c, "name", None) == name:
                return True
    except Exception:
        pass
    return False

# 密码规则：OpenAI 要求最少 12 位
PASSWORD_MIN_LENGTH = 12


class RetryException(Exception):
    """需换 IP/会话重试时抛出；主循环捕获后重新开始。"""
    pass


class RegistrationCancelled(Exception):
    """用户请求停止注册时抛出。"""
    pass


# Chrome 指纹：与参考 chatgpt_register.py 对齐，impersonate 与 sec-ch-ua 匹配
_CHROME_PROFILES = [
    {"major": 131, "impersonate": "chrome131", "build": 6778, "patch_range": (69, 205),
     "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"'},
    {"major": 136, "impersonate": "chrome136", "build": 7103, "patch_range": (48, 175),
     "sec_ch_ua": '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"'},
    {"major": 124, "impersonate": "chrome124", "build": 6367, "patch_range": (50, 120),
     "sec_ch_ua": '"Chromium";v="124", "Google Chrome";v="124", "Not_A Brand";v="24"'},
]


def _random_chrome_version():
    profile = random.choice(_CHROME_PROFILES)
    major, build = profile["major"], profile["build"]
    patch = random.randint(*profile["patch_range"])
    full_ver = f"{major}.0.{build}.{patch}"
    ua = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{full_ver} Safari/537.36"
    return profile["impersonate"], full_ver, ua, profile["sec_ch_ua"]


def _reorder_headers_chrome(session):
    order = ["Accept", "Accept-Language", "Accept-Encoding", "User-Agent", "Referer", "Origin", "Content-Type", "Authorization"]
    h = dict(session.headers)
    session.headers.clear()
    for k in order:
        if k in h:
            session.headers[k] = h.pop(k)
    for k, v in h.items():
        session.headers[k] = v


def _make_trace_headers():
    """与参考 chatgpt_register.py 一致：traceparent + datadog 头。"""
    trace_id = random.randint(10**17, 10**18 - 1)
    parent_id = random.randint(10**17, 10**18 - 1)
    tp = f"00-{uuid.uuid4().hex}-{format(parent_id, '016x')}-01"
    return {
        "traceparent": tp, "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum", "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": str(trace_id), "x-datadog-parent-id": str(parent_id),
    }


def _make_session(device_id: str = None):
    """创建 Session：与参考对齐。device_id 与 signin 的 ext-oai-did 一致，并写入 oai-did cookie。"""
    proxy = get_proxy_url_for_session()
    proxies = {"http": proxy, "https": proxy} if proxy else None
    if device_id is None:
        device_id = str(uuid.uuid4())

    if CURL_CFFI_AVAILABLE:
        impersonate, full_ver, ua, sec_ch_ua = _random_chrome_version()
        print(f"[*] Using curl_cffi impersonate={impersonate}", flush=True)
        session = curl_requests.Session(impersonate=impersonate)
        if proxies:
            session.proxies = proxies
        session.headers.update({
            "User-Agent": ua,
            "Accept-Language": random.choice([
                "en-US,en;q=0.9", "en-US,en;q=0.9,zh-CN;q=0.8",
                "en,en-US;q=0.9", "en-US,en;q=0.8",
            ]),
            "sec-ch-ua": sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-ch-ua-arch": '"x86"',
            "sec-ch-ua-bitness": '"64"',
            "sec-ch-ua-full-version": f'"{full_ver}"',
            "sec-ch-ua-platform-version": f'"{random.randint(10, 15)}.0.0"',
            "Accept": "application/json, text/plain, */*",
            "Referer": CHATGPT_ORIGIN + "/",
        })
        try:
            session.cookies.set("oai-did", device_id, domain="chatgpt.com")
        except Exception:
            pass
        _reorder_headers_chrome(session)
        return session

    session = requests.Session()
    retry = Retry(
        total=getattr(cfg.retry, "http_max_retries", 5),
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "POST", "OPTIONS"],
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://", HTTPAdapter(max_retries=retry))
    ua = get_user_agent() or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    session.headers.update({
        "User-Agent": ua,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": CHATGPT_ORIGIN + "/",
        "Origin": CHATGPT_ORIGIN,
    })
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})
    return session


# -------------------- 注册流程步骤（keygen 单流程） --------------------

def _ensure_password_page(session, state: str = None) -> None:
    """Authorize 后 GET create-account/password，确保会话处于密码页步骤（与参考中 final_path 含 create-account/password 等价）。"""
    url = f"{AUTH_ORIGIN}/create-account/password"
    if state:
        url = f"{url}?state={state}"
    r = session.get(url, headers={
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Referer": f"{CHATGPT_ORIGIN}/",
        "Upgrade-Insecure-Requests": "1",
    }, timeout=HTTP_TIMEOUT, allow_redirects=True)


def _keygen_step0_oauth_and_continue(session, email: str, device_id: str, code_verifier: str, code_challenge: str, _step) -> bool:
    """
    keygen 可注册方案：GET /oauth/authorize (screen_hint=signup) + POST authorize/continue 带 sentinel。
    代理从 config 的 get_proxy_url_for_session 已注入到 session。
    """
    client_id = _get_oauth_client_id()
    if not client_id:
        _step("[*] keygen 需配置 OAuth Client ID，跳过 Sentinel 流程")
        return False
    redirect_uri = _get_oauth_redirect_uri()
    state = secrets.token_urlsafe(32)
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid profile email offline_access",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
        "screen_hint": "signup",
        "prompt": "login",
    }
    authorize_url = f"{AUTH_ORIGIN}/oauth/authorize?{urlencode(params)}"
    _step("[*] keygen 0a GET /oauth/authorize (screen_hint=signup)")
    # 从 chatgpt 点注册进入 auth 时，需 Referer + sec-fetch-site: cross-site 才能拿到 login_session
    nav_headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": f"{CHATGPT_ORIGIN}/",
        "Upgrade-Insecure-Requests": "1",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "cross-site",
        "sec-fetch-user": "?1",
    }
    try:
        r = session.get(authorize_url, headers=nav_headers, timeout=HTTP_TIMEOUT, allow_redirects=True)
    except Exception as e:
        print(f"[x] keygen 0a 失败: {e}", flush=True)
        return False
    if not _has_cookie(session, "login_session"):
        status = getattr(r, "status_code", None)
        final_url = getattr(r, "url", "") or ""
        _step(f"[*] keygen 0a 未获得 login_session (HTTP {status} -> {final_url[:90]}...)")
        if status == 403:
            print("[x] 0a 返回 403，多为当前 IP/代理被风控，请更换代理或网络后重试", flush=True)
        return False
    if not build_sentinel_token:
        _step("[*] keygen 需 protocol_sentinel，跳过 Sentinel 流程")
        return False
    sentinel_token = build_sentinel_token(session, device_id, flow="authorize_continue")
    if not sentinel_token:
        _step("[*] keygen 获取 sentinel token 失败")
        return False
    _step("[*] keygen 0b POST authorize/continue + sentinel")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Referer": f"{AUTH_ORIGIN}/create-account",
        "Origin": AUTH_ORIGIN,
        "oai-device-id": device_id,
        "openai-sentinel-token": sentinel_token,
    }
    headers.update(_make_trace_headers())
    try:
        r = session.post(
            f"{AUTH_ORIGIN}/api/accounts/authorize/continue",
            json={"username": {"kind": "email", "value": email}, "screen_hint": "signup"},
            headers=headers,
            timeout=HTTP_TIMEOUT,
        )
    except Exception as e:
        print(f"[x] keygen 0b 失败: {e}", flush=True)
        return False
    if r.status_code != 200:
        _step(f"[*] keygen 0b 返回 {r.status_code}")
        return False
    return True


def _register_with_sentinel(session, email: str, password: str, device_id: str, _step) -> tuple:
    """keygen 方案：POST user/register 带 openai-sentinel-token（keygen 用 PoW 字符串）。"""
    url = f"{AUTH_ORIGIN}/api/accounts/user/register"
    referer = f"{AUTH_ORIGIN}/create-account/password"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Referer": referer,
        "Origin": AUTH_ORIGIN,
        "oai-device-id": device_id,
    }
    headers.update(_make_trace_headers())
    if build_sentinel_token_pow_only:
        headers["openai-sentinel-token"] = build_sentinel_token_pow_only(device_id)
    r = session.post(url, json={"username": email, "password": password}, headers=headers, timeout=HTTP_TIMEOUT)
    try:
        data = r.json()
    except Exception:
        data = {"text": (r.text or "")[:500]}
    if r.status_code == 409:
        err = data.get("error") or {}
        err_code = err.get("code") if isinstance(err, dict) else None
        if err_code == "invalid_state" or (isinstance(err, dict) and "invalid" in str(err).lower()):
            raise RetryException("Step register returned 409 invalid_state")
    return r.status_code, data


def _send_otp(session):
    url = f"{AUTH_ORIGIN}/api/accounts/email-otp/send"
    r = session.get(url, headers={
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Referer": f"{AUTH_ORIGIN}/create-account/password",
        "Upgrade-Insecure-Requests": "1",
    }, timeout=HTTP_TIMEOUT, allow_redirects=True)
    try:
        data = r.json()
    except Exception:
        data = {"final_url": str(r.url), "status": r.status_code}
    return r.status_code, data


def _validate_otp(session, code: str):
    url = f"{AUTH_ORIGIN}/api/accounts/email-otp/validate"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Referer": f"{AUTH_ORIGIN}/email-verification",
        "Origin": AUTH_ORIGIN,
    }
    headers.update(_make_trace_headers())
    r = session.post(url, json={"code": code}, headers=headers, timeout=HTTP_TIMEOUT)
    try:
        data = r.json()
    except Exception:
        data = {"text": (r.text or "")[:500]}
    return r.status_code, data


def _create_account(session, name: str, birthdate: str):
    url = f"{AUTH_ORIGIN}/api/accounts/create_account"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Referer": f"{AUTH_ORIGIN}/about-you",
        "Origin": AUTH_ORIGIN,
    }
    headers.update(_make_trace_headers())
    r = session.post(url, json={"name": name, "birthdate": birthdate}, headers=headers, timeout=HTTP_TIMEOUT)
    try:
        data = r.json()
    except Exception:
        data = {"text": (r.text or "")[:500]}
    return r.status_code, data


def _callback(session, url: str):
    if not url or not url.startswith("http"):
        return None, None
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Upgrade-Insecure-Requests": "1",
    }
    r_first = session.get(url, headers=headers, timeout=HTTP_TIMEOUT, allow_redirects=False)
    body_first = (r_first.text or "")[:50000]
    location = r_first.headers.get("Location") or r_first.headers.get("location") or ""
    if r_first.status_code in (301, 302, 303, 307, 308) and location:
        r = session.get(location, headers=headers, timeout=HTTP_TIMEOUT, allow_redirects=True)
        body = (r.text or "")[:50000]
        final_url = str(r.url)
    else:
        r = r_first
        body = body_first
        final_url = str(r.url)
    if not body and body_first:
        body = body_first
    return r.status_code, {"final_url": final_url, "body": body, "first_location": location}


def _generate_code_verifier() -> str:
    """PKCE code_verifier，43~128 字符。"""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def _generate_code_challenge(verifier: str) -> str:
    """PKCE S256 code_challenge。"""
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _parse_code_from_url(final_url: str) -> str:
    """从 callback 最终 URL 的 query 或 fragment 中解析 OAuth code。"""
    if not final_url or not isinstance(final_url, str):
        return ""
    try:
        parsed = urlparse(final_url)
        for part in (parsed.query, parsed.fragment):
            if not part:
                continue
            params = parse_qs(part, keep_blank_values=False)
            for key in ("code",):
                vals = params.get(key)
                if vals and isinstance(vals[0], str) and vals[0].strip():
                    return vals[0].strip()
    except Exception:
        pass
    return ""


def _parse_code_from_body(body: str) -> str:
    """从 callback 响应体（HTML/JSON）中解析 OAuth code。"""
    if not body or not isinstance(body, str):
        return ""
    try:
        stripped = body.strip()
        if stripped.startswith("{"):
            data = json.loads(body)
            if isinstance(data, dict):
                c = data.get("code") or data.get("authorization_code")
                if isinstance(c, str) and len(c.strip()) > 5:
                    return c.strip()
        m = re.search(r"[\?&]code=([^&\s\"'<>]+)", body)
        if m and m.group(1) and len(m.group(1).strip()) > 5:
            return m.group(1).strip()
        m = re.search(r"[\"']code[\"']\s*:\s*[\"']([^\"']{10,})[\"']", body, re.I)
        if m:
            return m.group(1).strip()
    except Exception:
        pass
    return ""


def _parse_tokens_from_body(body: str) -> dict:
    """从 callback 响应体（HTML/JSON）中解析 refresh_token、access_token。"""
    out = {"refresh_token": "", "access_token": ""}
    if not body or not isinstance(body, str):
        return out
    try:
        stripped = body.strip()
        if stripped.startswith("{"):
            data = json.loads(body)
            if isinstance(data, dict):
                for key in ("refresh_token", "refresh_token_secret"):
                    v = data.get(key)
                    if isinstance(v, str) and len(v.strip()) > 10:
                        out["refresh_token"] = v.strip()
                        break
                for key in ("access_token", "token"):
                    v = data.get(key)
                    if isinstance(v, str) and len(v.strip()) > 10:
                        out["access_token"] = v.strip()
                        break
                for nest in ("session", "credentials", "auth"):
                    obj = data.get(nest)
                    if isinstance(obj, dict):
                        if not out["refresh_token"]:
                            v = obj.get("refresh_token") or obj.get("refresh_token_secret")
                            if isinstance(v, str) and len(v.strip()) > 10:
                                out["refresh_token"] = v.strip()
                        if not out["access_token"]:
                            v = obj.get("access_token") or obj.get("token")
                            if isinstance(v, str) and len(v.strip()) > 10:
                                out["access_token"] = v.strip()
        for key_rt in ("refresh_token", "refresh_token_secret"):
            m = re.search(r"[\"']" + re.escape(key_rt) + r"[\"']\s*:\s*[\"']([^\"']{15,})[\"']", body, re.I)
            if m and not out["refresh_token"]:
                out["refresh_token"] = m.group(1).strip()
                break
        for key_at in ("access_token", "token"):
            m = re.search(r"[\"']" + re.escape(key_at) + r"[\"']\s*:\s*[\"']([^\"']{15,})[\"']", body, re.I)
            if m and not out["access_token"]:
                out["access_token"] = m.group(1).strip()
                break
    except Exception:
        pass
    return out


# 注册后「登录取 code」专用 redirect_uri：服务端会 302 到此 URL 并带 code=，从 Location 头解析即可，无需起本地服务
LOGIN_REDIRECT_URI_FOR_CODE = "http://localhost:1455/auth/callback"


def codex_exchange_code(session, code: str, code_verifier: str, redirect_uri: str = None):
    """
    用 authorization code 换取 Codex/ChatGPT tokens。
    POST https://auth.openai.com/oauth/token
    redirect_uri 需与拿 code 时一致；不传则用系统设置或 chatgpt.com/。
    返回含 access_token、refresh_token 等的 dict，失败返回 None。
    """
    client_id = _get_oauth_client_id()
    if not client_id:
        return None
    uri = (redirect_uri or "").strip() or _get_oauth_redirect_uri()
    try:
        resp = session.post(
            f"{OAUTH_ISSUER}/oauth/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": uri,
                "client_id": client_id,
                "code_verifier": code_verifier,
            },
            timeout=60,
        )
    except Exception as e:
        print(f"  Token 交换失败: {e}", flush=True)
        return None
    if resp.status_code == 200:
        data = resp.json()
        return data
    try:
        err_text = (resp.text or "")[:300]
        print(f"  Token 交换失败: HTTP {resp.status_code} - {err_text}", flush=True)
    except Exception:
        print(f"  Token 交换失败: HTTP {resp.status_code}", flush=True)
    return None


def _decode_oai_session_cookie(session) -> dict:
    """从 oai-client-auth-session cookie 解码 JSON（尝试各 segment）。"""
    val = ""
    try:
        val = (session.cookies.get("oai-client-auth-session") or "") if hasattr(session, "cookies") else ""
    except Exception:
        pass
    if not val:
        for c in getattr(session, "cookies", []):
            if getattr(c, "name", None) == "oai-client-auth-session":
                val = getattr(c, "value", "") or ""
                break
    if not val:
        return {}
    for i, part in enumerate(val.split(".")[:3]):
        if not part:
            continue
        pad = 4 - len(part) % 4
        if pad != 4:
            part = part + ("=" * pad)
        try:
            raw = base64.urlsafe_b64decode(part)
            return json.loads(raw.decode("utf-8"))
        except Exception:
            continue
    return {}


def _follow_consent_to_code(session, start_url: str, _step, max_depth: int = 15) -> str:
    """跟随 consent 重定向链，从 302 Location 中解析 code（redirect_uri 为 localhost 时 Location 会带 code=）。"""
    url = start_url
    if not url or not url.startswith("http"):
        url = f"{AUTH_ORIGIN}{start_url}" if start_url.startswith("/") else ""
    if not url:
        return ""
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Referer": f"{AUTH_ORIGIN}/",
        "Upgrade-Insecure-Requests": "1",
    }
    for _ in range(max_depth):
        try:
            r = session.get(url, headers=headers, timeout=HTTP_TIMEOUT, allow_redirects=False)
        except Exception as e:
            if "localhost" in str(e) or "1455" in str(e):
                m = re.search(r"(https?://localhost[^\s\'\"<>]+)", str(e))
                if m:
                    return _parse_code_from_url(m.group(1))
            return ""
        if r.status_code in (301, 302, 303, 307, 308):
            loc = (r.headers.get("Location") or r.headers.get("location") or "").strip()
            if not loc:
                return ""
            code = _parse_code_from_url(loc)
            if code:
                return code
            url = loc if loc.startswith("http") else f"{AUTH_ORIGIN}{loc}"
            continue
        if r.status_code == 200:
            code = _parse_code_from_url(r.url)
            if code:
                return code
        return ""
    return ""


def _oauth_login_get_tokens(session, email: str, password: str, get_otp_fn, _step) -> dict:
    """
    注册成功后用「邮箱+密码」再走一遍 OAuth 登录，从 consent 重定向到 localhost 的 Location 中拿 code，再换 AT/RT。
    确保能拿到 token；若服务端要求 sentinel 等可能 403，则返回空 dict。
    """
    client_id = _get_oauth_client_id()
    if not client_id:
        return {}
    _step("[*] 8.6 注册后登录取 code 换 AT/RT...")
    device_id = str(uuid.uuid4())
    try:
        session.cookies.set("oai-did", device_id, domain=".auth.openai.com")
        session.cookies.set("oai-did", device_id, domain="auth.openai.com")
    except Exception:
        pass
    code_verifier = _generate_code_verifier()
    code_challenge = _generate_code_challenge(code_verifier)
    state = secrets.token_urlsafe(32)
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": LOGIN_REDIRECT_URI_FOR_CODE,
        "scope": "openid profile email offline_access",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    authorize_url = f"{AUTH_ORIGIN}/oauth/authorize?{urlencode(params)}"
    nav_headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Referer": f"{AUTH_ORIGIN}/",
        "Upgrade-Insecure-Requests": "1",
    }
    try:
        r = session.get(authorize_url, headers=nav_headers, timeout=HTTP_TIMEOUT, allow_redirects=True)
    except Exception as e:
        _step(f"[*] 8.6 authorize 请求失败: {e}")
        return {}
    if not _has_cookie(session, "login_session"):
        _step("[*] 8.6 未获得 login_session，可能需 sentinel")
    api_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Referer": f"{AUTH_ORIGIN}/log-in",
        "Origin": AUTH_ORIGIN,
        "oai-device-id": device_id,
    }
    api_headers.update(_make_trace_headers())
    if build_sentinel_token:
        sentinel_ac = build_sentinel_token(session, device_id, flow="authorize_continue")
        if sentinel_ac:
            api_headers["openai-sentinel-token"] = sentinel_ac
    try:
        r = session.post(
            f"{AUTH_ORIGIN}/api/accounts/authorize/continue",
            json={"username": {"kind": "email", "value": email}},
            headers=api_headers,
            timeout=HTTP_TIMEOUT,
        )
    except Exception as e:
        _step(f"[*] 8.6 authorize/continue 失败: {e}")
        return {}
    if r.status_code != 200:
        _step(f"[*] 8.6 authorize/continue {r.status_code}（若 403 可能需 sentinel）")
        try:
            _step(f"[*] 8.6 响应: {(r.text or '')[:200]}")
        except Exception:
            pass
        return {}
    api_headers["Referer"] = f"{AUTH_ORIGIN}/log-in/password"
    api_headers.update(_make_trace_headers())
    if build_sentinel_token:
        sentinel_pw = build_sentinel_token(session, device_id, flow="password_verify")
        if sentinel_pw:
            api_headers["openai-sentinel-token"] = sentinel_pw
    try:
        r = session.post(
            f"{AUTH_ORIGIN}/api/accounts/password/verify",
            json={"password": password},
            headers=api_headers,
            timeout=HTTP_TIMEOUT,
            allow_redirects=False,
        )
    except Exception as e:
        _step(f"[*] 8.6 password/verify 失败: {e}")
        return {}
    if r.status_code != 200:
        _step(f"[*] 8.6 password/verify {r.status_code}（若 403 可能需 sentinel）")
        try:
            _step(f"[*] 8.6 响应: {(r.text or '')[:200]}")
        except Exception:
            pass
        return {}
    try:
        data = r.json()
        continue_url = (data.get("continue_url") or "").strip()
        page_type = (data.get("page") or {}).get("type", "")
    except Exception:
        continue_url = ""
        page_type = ""
    if not continue_url:
        _step("[*] 8.6 password/verify 200 但无 continue_url")
        return {}
    _step(f"[*] 8.6 continue_url: {continue_url[:80]}...")
    if page_type == "email_otp_verification" or "email-verification" in continue_url:
        code_otp = get_otp_fn() if get_otp_fn else None
        if not code_otp:
            _step("[*] 8.6 需要邮箱验证码但未提供 get_otp_fn 或未取到")
            return {}
        code_otp = re.sub(r"\D", "", str(code_otp).strip())[:6]
        api_headers["Referer"] = f"{AUTH_ORIGIN}/email-verification"
        api_headers.update(_make_trace_headers())
        try:
            r = session.post(
                f"{AUTH_ORIGIN}/api/accounts/email-otp/validate",
                json={"code": code_otp},
                headers=api_headers,
                timeout=HTTP_TIMEOUT,
            )
        except Exception:
            return {}
        if r.status_code != 200:
            _step(f"[*] 8.6 email-otp/validate {r.status_code}")
            return {}
        try:
            data = r.json()
            continue_url = (data.get("continue_url") or "").strip()
        except Exception:
            pass
    if not continue_url:
        return {}
    consent_url = continue_url if continue_url.startswith("http") else f"{AUTH_ORIGIN}{continue_url}"
    auth_code = _follow_consent_to_code(session, consent_url, _step)
    if not auth_code:
        _step("[*] 8.6 直接 GET consent 未拿到 code，尝试 workspace/select...")
        session_data = _decode_oai_session_cookie(session)
        workspaces = (session_data or {}).get("workspaces") or []
        workspace_id = workspaces[0].get("id") if workspaces else None
        if workspace_id:
            api_headers["Referer"] = consent_url
            api_headers.update(_make_trace_headers())
            try:
                r = session.post(
                    f"{AUTH_ORIGIN}/api/accounts/workspace/select",
                    json={"workspace_id": workspace_id},
                    headers=api_headers,
                    timeout=HTTP_TIMEOUT,
                    allow_redirects=False,
                )
                if r.status_code in (301, 302, 303, 307, 308):
                    loc = (r.headers.get("Location") or r.headers.get("location") or "").strip()
                    auth_code = _parse_code_from_url(loc)
                    if not auth_code and loc:
                        auth_code = _follow_consent_to_code(
                            session, loc if loc.startswith("http") else f"{AUTH_ORIGIN}{loc}", _step
                        )
                elif r.status_code == 200:
                    try:
                        ws_data = r.json()
                        ws_next = (ws_data.get("continue_url") or "").strip()
                        if ws_next:
                            auth_code = _follow_consent_to_code(
                                session,
                                ws_next if ws_next.startswith("http") else f"{AUTH_ORIGIN}{ws_next}",
                                _step,
                            )
                        if not auth_code:
                            orgs = (ws_data.get("data") or {}).get("orgs") or []
                            if orgs:
                                org_id = orgs[0].get("id")
                                proj = (orgs[0].get("projects") or [{}])[0].get("id") if orgs[0].get("projects") else None
                                body = {"org_id": org_id}
                                if proj:
                                    body["project_id"] = proj
                                api_headers["Referer"] = consent_url
                                api_headers.update(_make_trace_headers())
                                r2 = session.post(
                                    f"{AUTH_ORIGIN}/api/accounts/organization/select",
                                    json=body,
                                    headers=api_headers,
                                    timeout=HTTP_TIMEOUT,
                                    allow_redirects=False,
                                )
                                if r2.status_code in (301, 302, 303, 307, 308):
                                    loc2 = (r2.headers.get("Location") or r2.headers.get("location") or "").strip()
                                    auth_code = _parse_code_from_url(loc2) or _follow_consent_to_code(
                                        session, loc2 if loc2.startswith("http") else f"{AUTH_ORIGIN}{loc2}", _step
                                    )
                                elif r2.status_code == 200:
                                    try:
                                        next_url = (r2.json().get("continue_url") or "").strip()
                                        if next_url:
                                            auth_code = _follow_consent_to_code(
                                                session,
                                                next_url if next_url.startswith("http") else f"{AUTH_ORIGIN}{next_url}",
                                                _step,
                                            )
                                    except Exception:
                                        pass
                    except Exception as e:
                        _step(f"[*] 8.6 workspace 响应解析异常: {e}")
            except Exception as e:
                _step(f"[*] 8.6 workspace/select 请求异常: {e}")
        else:
            _step("[*] 8.6 无 workspace_id（cookie 无 workspaces）")
    if not auth_code:
        _step("[*] 8.6 跟随 consent 未解析到 code")
        return {}
    _step("[*] 8.6 已从 consent 拿到 code，换取 token...")
    exchange = codex_exchange_code(session, auth_code, code_verifier, redirect_uri=LOGIN_REDIRECT_URI_FOR_CODE)
    if not exchange:
        _step("[*] 8.6 code 换 token 失败，请确认 OAuth 应用已添加 redirect_uri: http://localhost:1455/auth/callback")
        return {}
    if not exchange.get("refresh_token"):
        _step("[*] 8.6 换 token 成功但响应无 refresh_token")
    return dict(exchange)


def decode_jwt_payload(token: str) -> dict:
    """解析 JWT token 的 payload 部分。"""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return {}


def _parse_tokens_from_url(final_url: str) -> dict:
    """从 callback 最终 URL 的 query 或 fragment 中解析 refresh_token、access_token。返回 {\"refresh_token\": \"\", \"access_token\": \"\"}。"""
    out = {"refresh_token": "", "access_token": ""}
    if not final_url or not isinstance(final_url, str):
        return out
    try:
        parsed = urlparse(final_url)
        for part in (parsed.query, parsed.fragment):
            if not part:
                continue
            params = parse_qs(part, keep_blank_values=False)
            for key_rt in ("refresh_token", "refresh_token_secret"):
                vals = params.get(key_rt) or params.get(key_rt.replace("_", "."))
                if vals and isinstance(vals[0], str) and len(vals[0].strip()) > 10:
                    out["refresh_token"] = vals[0].strip()
                    break
            for key_at in ("access_token", "token"):
                vals = params.get(key_at) or params.get(key_at.replace("_", "."))
                if vals and isinstance(vals[0], str) and len(vals[0].strip()) > 10:
                    out["access_token"] = vals[0].strip()
                    break
    except Exception:
        pass
    return out


def _parse_refresh_token_from_url(final_url: str) -> str:
    """从 callback 最终 URL 的 query 或 fragment 中解析 refresh_token（兼容旧逻辑）。"""
    return _parse_tokens_from_url(final_url).get("refresh_token", "") or ""


def _get_access_token_from_response(data: dict) -> str:
    """从 create_account 等接口的 JSON 响应中提取 access_token。"""
    if not data or not isinstance(data, dict):
        return ""
    for key in ("access_token", "token"):
        v = data.get(key)
        if isinstance(v, str) and len(v.strip()) > 10:
            return v.strip()
    for nest in ("session", "credentials", "auth", "token"):
        obj = data.get(nest)
        if isinstance(obj, dict):
            v = obj.get("access_token") or obj.get("token")
            if isinstance(v, str) and len(v.strip()) > 10:
                return v.strip()
    return ""


def _get_refresh_token_from_response(data: dict) -> str:
    """从 create_account 等接口的 JSON 响应中提取 refresh_token。"""
    if not data or not isinstance(data, dict):
        return ""
    for key in ("refresh_token", "refresh_token_secret"):
        v = data.get(key)
        if isinstance(v, str) and len(v.strip()) > 10:
            return v.strip()
    for nest in ("session", "credentials", "auth", "token"):
        obj = data.get(nest)
        if isinstance(obj, dict):
            v = obj.get("refresh_token") or obj.get("refresh_token_secret")
            if isinstance(v, str) and len(v.strip()) > 10:
                return v.strip()
    return ""


# -------------------- 入口 --------------------

def register_one_protocol(email: str, password: str, jwt_token: str, get_otp_fn, user_info: dict, **kwargs):
    """
    协议注册入口。
    入参：email, password, jwt_token, get_otp_fn(), user_info(name/year/month/day), step_log_fn, stop_check 等。
    返回：(email, password, success: bool[, status_extra[, tokens]])。
    """
    step_log_fn = kwargs.pop("step_log_fn", None)
    stop_check = kwargs.pop("stop_check", None)

    def _step(msg: str):
        if stop_check and callable(stop_check) and stop_check():
            raise RegistrationCancelled()
        if msg:
            print(msg, flush=True)
            if step_log_fn:
                try:
                    step_log_fn(msg.strip())
                except Exception:
                    pass

    _step(f"[*] register_one_protocol start {email}")
    pwd = (password or "").strip()
    if len(pwd) < PASSWORD_MIN_LENGTH:
        raise ValueError(f"Password length must be >= {PASSWORD_MIN_LENGTH}, got {len(pwd)}. Set password in email row or use runner which auto-generates.")
    password = pwd
    name = user_info.get("name", "User")
    year = user_info.get("year", "1990")
    month = user_info.get("month", "01")
    day = user_info.get("day", "01")
    birthdate = f"{year}-{month}-{day}"

    device_id = str(uuid.uuid4())
    session = _make_session(device_id)
    code_verifier = _generate_code_verifier()
    code_challenge = _generate_code_challenge(code_verifier)
    if not _get_oauth_client_id():
        _step("[*] 未配置 OAuth Client ID，请在系统设置中填写")
        return email, password, False
    if not build_sentinel_token:
        _step("[*] Sentinel 未加载，请确保 protocol_sentinel 可用")
        return email, password, False
    try:
        _step("[*] 0. GET authorize + POST authorize/continue (sentinel)")
        try:
            session.cookies.set("oai-did", device_id, domain=".auth.openai.com")
            session.cookies.set("oai-did", device_id, domain="auth.openai.com")
        except Exception:
            pass
        time.sleep(random.uniform(0.2, 0.5))
        if not _keygen_step0_oauth_and_continue(session, email, device_id, code_verifier, code_challenge, _step):
            return email, password, False
        time.sleep(random.uniform(0.5, 1.0))
        _step("[*] 1. GET create-account/password")
        _ensure_password_page(session, None)
        time.sleep(random.uniform(0.5, 1.0))
        _step("[*] 2. Register (user/register + sentinel)")
        status_reg, data_reg = _register_with_sentinel(session, email, password, device_id, _step)
        if status_reg not in (200, 201, 204):
            print(f"[x] 4. Register failed: status={status_reg} data={data_reg}", flush=True)
            return email, password, False
        print("[ok] 4. Register OK", flush=True)
        _step("[*] 3. Send OTP")
        status_otp, data_otp = _send_otp(session)
        if status_otp not in (200, 201, 204) and (not isinstance(data_otp, dict) or data_otp.get("error")):
            print(f"[x] 5. Send OTP failed: status={status_otp} data={data_otp}", flush=True)
            return email, password, False

        _step("[*] Waiting for email OTP...")
        if stop_check and callable(stop_check) and stop_check():
            return email, password, False
        code = get_otp_fn()
        if not code or len(str(code).strip()) < 4:
            print("[x] No OTP received or invalid", flush=True)
            return email, password, False
        # 规范为纯 6 位数字，避免空格/换行导致 wrong_email_otp_code
        code = re.sub(r"\D", "", str(code).strip())
        if len(code) < 6:
            print("[x] OTP too short after normalizing", flush=True)
            return email, password, False
        code = code[:6]

        _step("[*] 6. Validate OTP")
        status_val, data_val = _validate_otp(session, code)
        if status_val not in (200, 201, 204):
            err = (data_val.get("error") or {}) if isinstance(data_val, dict) else {}
            print(f"[x] 6. Validate OTP failed: status={status_val} data={data_val}", flush=True)
            return email, password, False

        _step("[*] 7. Create account")
        status_create, data_create = _create_account(session, name, birthdate)
        if status_create not in (200, 201, 204):
            print(f"[x] 7. Create account failed: status={status_create} data={data_create}", flush=True)
            return email, password, False

        callback_url = None
        if isinstance(data_create, dict):
            callback_url = data_create.get("continue_url") or data_create.get("url") or data_create.get("redirect_url")

        _step("[*] 8. Callback")
        callback_data = None
        if callback_url:
            _, callback_data = _callback(session, callback_url)

        print("[ok] Protocol registration success", flush=True)
        tokens = dict(data_create) if isinstance(data_create, dict) else {}

        final_url = (callback_data or {}).get("final_url") if isinstance(callback_data, dict) else ""
        callback_body = (callback_data or {}).get("body") if isinstance(callback_data, dict) else ""
        first_location = (callback_data or {}).get("first_location") if isinstance(callback_data, dict) else ""
        oauth_code = _parse_code_from_url(final_url) if final_url else ""
        if not oauth_code and first_location:
            oauth_code = _parse_code_from_url(first_location)
        if not oauth_code and callback_body:
            oauth_code = _parse_code_from_body(callback_body)
        has_client_id = bool(_get_oauth_client_id())
        if not has_client_id:
            _step("[*] 未配置 OAuth Client ID，跳过 code 换 token；请在系统设置中填写以获取 AT/RT")
        elif not oauth_code:
            _step("[*] Callback URL 中无 code 参数，无法换 token（可能未走 PKCE 或服务端未返回 code）")
        if oauth_code and code_verifier and has_client_id:
            _step("[*] 8.5 用 code 换取 AT/RT...")
            exchange = codex_exchange_code(session, oauth_code, code_verifier)
            if exchange:
                if exchange.get("access_token"):
                    tokens["access_token"] = exchange["access_token"]
                if exchange.get("refresh_token"):
                    tokens["refresh_token"] = exchange["refresh_token"]
                if exchange.get("id_token"):
                    tokens["id_token"] = exchange["id_token"]
                _step("[*] 8.5 AT/RT 已从 code 交换获取")
            else:
                _step("[*] 8.5 code 换 token 请求失败，请检查 Client ID / Redirect URI")

        rt = tokens.get("refresh_token") or _get_refresh_token_from_response(tokens)
        at = tokens.get("access_token") or _get_access_token_from_response(tokens)
        if final_url:
            url_tokens = _parse_tokens_from_url(final_url)
            if url_tokens.get("refresh_token") and not rt:
                rt = url_tokens["refresh_token"]
            if url_tokens.get("access_token") and not at:
                at = url_tokens["access_token"]
        if first_location and (not rt or not at):
            loc_tokens = _parse_tokens_from_url(first_location)
            if loc_tokens.get("refresh_token") and not rt:
                rt = loc_tokens["refresh_token"]
            if loc_tokens.get("access_token") and not at:
                at = loc_tokens["access_token"]
        if callback_body and (not rt or not at):
            body_tokens = _parse_tokens_from_body(callback_body)
            if body_tokens.get("refresh_token") and not rt:
                rt = body_tokens["refresh_token"]
            if body_tokens.get("access_token") and not at:
                at = body_tokens["access_token"]
        if rt:
            tokens["refresh_token"] = rt
        if at:
            tokens["access_token"] = at
        if not rt:
            rt = _get_refresh_token_from_response(data_create) if isinstance(data_create, dict) else ""
            if rt:
                tokens["refresh_token"] = rt
        if not at and isinstance(data_create, dict):
            at = _get_access_token_from_response(data_create)
            if at:
                tokens["access_token"] = at

        if (not tokens.get("refresh_token") or not tokens.get("access_token")) and has_client_id:
            login_tokens = _oauth_login_get_tokens(session, email, password, get_otp_fn, _step)
            if login_tokens:
                if login_tokens.get("access_token"):
                    tokens["access_token"] = login_tokens["access_token"]
                if login_tokens.get("refresh_token"):
                    tokens["refresh_token"] = login_tokens["refresh_token"]
                if login_tokens.get("id_token"):
                    tokens["id_token"] = login_tokens["id_token"]
                _step("[*] 8.6 登录取 code 已拿到 AT/RT")

        if not tokens.get("refresh_token"):
            _step("[*] 8. Callback 完成，未解析到 refresh_token（可能需登录页再取）")
            if isinstance(data_create, dict) and data_create:
                _step(f"[*] create_account 响应键: {list(data_create.keys())}")
        if tokens.get("refresh_token") or tokens.get("access_token"):
            _step(f"[*] 最终: RT={'有' if tokens.get('refresh_token') else '无'}, AT={'有' if tokens.get('access_token') else '无'}")
        return email, password, True, None, (tokens if tokens else None)
    except RegistrationCancelled:
        print("[*] 注册已停止", flush=True)
        return email, password, False
    except RetryException:
        raise
    except (requests.RequestException, ValueError) as e:
        print(f"[x] {e}", flush=True)
        return email, password, False
    except Exception as e:
        print(f"[x] Unexpected error: {e}", flush=True)
        return email, password, False
    finally:
        try:
            session.close()
        except Exception:
            pass


def activate_sora(tokens, email: str, **kwargs):
    """Sora 激活（注册成功后可调）。当前为桩，返回 False。"""
    return False
