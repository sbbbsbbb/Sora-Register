"""
单条注册任务运行器：从 DB 取未注册邮箱与配置，调 protocol_register，落库 accounts/run_logs，更新 last_run_success/fail。
不实现 8 步协议，仅「取配置 → 调 register_one_protocol / activate_sora → 落库」。
环境变量：PRINT_STEP_LOGS=1 时步骤日志同时输出到 stdout，便于终端跑测。
"""
import os
import random
from datetime import datetime
from typing import Optional, Tuple

from app.database import get_db, init_db
from app.registration_env import inject_registration_modules, set_task_config, clear_task_config
from app.registration_state import is_stop_requested
from app.services.otp_resolver import get_otp_for_email

# 首次执行注册前注入 config/utils，再懒加载 protocol_register，避免未注入时导入
_injected = False


def _ensure_injected():
    global _injected
    if not _injected:
        inject_registration_modules()
        _injected = True


def _get_registration_settings() -> dict:
    """从 system_settings 读取注册所需配置。"""
    init_db()
    with get_db() as conn:
        c = conn.cursor()
        c.execute(
            """SELECT key, value FROM system_settings WHERE key IN (
            'thread_count', 'retry_count', 'proxy_url', 'email_api_url', 'email_api_key',
            'oauth_client_id', 'oauth_redirect_uri'
            )"""
        )
        rows = c.fetchall()
    out = {}
    for k, v in rows:
        out[k] = (v or "").strip()
    out.setdefault("retry_count", "2")
    out.setdefault("thread_count", "1")
    return out


def fetch_one_unregistered_email(conn, order_random: bool = False) -> Optional[Tuple]:
    """取一条未注册邮箱。返回 (id, email, password, uuid, token) 或 None。order_random=True 时随机取一条便于轮换邮箱。"""
    c = conn.cursor()
    order = "ORDER BY RANDOM()" if order_random else ""
    c.execute(
        f"""SELECT e.id, e.email, e.password, e.uuid, e.token
           FROM emails e
           LEFT JOIN accounts a ON LOWER(TRIM(e.email)) = LOWER(TRIM(a.email))
           WHERE a.email IS NULL AND e.email IS NOT NULL AND TRIM(e.email) != ''
           {order}
           LIMIT 1"""
    )
    row = c.fetchone()
    return tuple(row) if row else None


def fetch_unregistered_emails(limit: int = 10):
    """取最多 limit 条未注册邮箱，用于多线程分配。返回 [(id, email, password, uuid, token), ...]。"""
    init_db()
    with get_db() as conn:
        c = conn.cursor()
        c.execute(
            """SELECT e.id, e.email, e.password, e.uuid, e.token
               FROM emails e
               LEFT JOIN accounts a ON LOWER(TRIM(e.email)) = LOWER(TRIM(a.email))
               WHERE a.email IS NULL AND e.email IS NOT NULL AND TRIM(e.email) != ''
               LIMIT ?""",
            (max(1, limit),),
        )
        rows = c.fetchall()
    return [tuple(r) for r in rows]


def _default_user_info() -> dict:
    """协议需要的 name, year, month, day（字符串）。"""
    y = random.randint(1985, 2000)
    m = random.randint(1, 12)
    d = random.randint(1, 28)
    return {
        "name": "User",
        "year": str(y),
        "month": str(m).zfill(2),
        "day": str(d).zfill(2),
    }


def _run_one_registration(
    email_id: int,
    email: str,
    password: str,
    uuid_val: str,
    token: str,
    settings: dict,
    task_id: str,
) -> Tuple[bool, Optional[str], Optional[dict]]:
    """
    执行单条注册（不重试）。返回 (success, status_extra, tokens)。
    """
    _ensure_injected()
    import protocol_register as pr  # 注入后导入

    base = (settings.get("email_api_url") or "https://gapi.hotmail007.com").rstrip("/")
    key = settings.get("email_api_key") or ""
    # 支持多行 proxy_url：每行一个代理，随机选用其一
    proxy_raw = (settings.get("proxy_url") or "").strip()
    proxy_lines = [p.strip() for p in proxy_raw.splitlines() if p.strip()]
    proxy_url = random.choice(proxy_lines) if proxy_lines else None

    account_str = f"{email}:{password or ''}:{token or ''}:{uuid_val or ''}"
    otp_timeout = 120
    otp_interval = 5

    def get_otp_fn():
        return get_otp_for_email(
            base, key, account_str,
            timeout_sec=otp_timeout, interval_sec=otp_interval,
            stop_check=is_stop_requested,
        )

    _print_steps = os.environ.get("PRINT_STEP_LOGS", "").strip().lower() in ("1", "true", "yes")

    def _step_log(msg: str) -> None:
        try:
            with get_db() as conn:
                c = conn.cursor()
                created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                c.execute(
                    "INSERT INTO run_logs (task_id, level, message, created_at) VALUES (?, ?, ?, ?)",
                    (task_id, "info", (msg or "")[:500], created),
                )
        except Exception:
            pass
        if _print_steps and msg:
            print(f"  [step] {msg}", flush=True)

    set_task_config(
        proxy_url=proxy_url,
        timeout=60,
        http_max_retries=5,
        oauth_client_id=settings.get("oauth_client_id") or "",
        oauth_redirect_uri=settings.get("oauth_redirect_uri") or "",
    )
    try:
        result = pr.register_one_protocol(
            email,
            password,
            token or "",
            get_otp_fn,
            _default_user_info(),
            proxy_url=proxy_url,
            step_log_fn=_step_log,
            stop_check=is_stop_requested,
        )
    except pr.RetryException as e:
        with get_db() as conn:
            c = conn.cursor()
            created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute(
                "INSERT INTO run_logs (task_id, level, message, created_at) VALUES (?, ?, ?, ?)",
                (task_id, "info", f"409 会话已清理，将重试 {email}: {e!s}", created),
            )
        return False, str(e), None
    except Exception as e:
        with get_db() as conn:
            c = conn.cursor()
            created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute(
                "INSERT INTO run_logs (task_id, level, message, created_at) VALUES (?, ?, ?, ?)",
                (task_id, "error", f"注册异常 {email}: {e!s}", created),
            )
        return False, str(e), None
    finally:
        clear_task_config()

    # result: (email, password, success[, status_extra[, tokens]])
    success = bool(result[2]) if len(result) > 2 else False
    status_extra = result[3] if len(result) > 3 else None
    tokens = result[4] if len(result) > 4 else None
    if isinstance(tokens, dict):
        pass
    else:
        tokens = None
    return success, status_extra, tokens


# 密码规则：与 protocol_register.PASSWORD_MIN_LENGTH 一致，OpenAI 要求最少 12 位，建议含大小写+数字+符号
PASSWORD_MIN_LENGTH = 12


def _random_password() -> str:
    """生成随机密码：至少 12 位，含大小写、数字、符号，满足 OpenAI 协议要求。"""
    import string
    upper = random.choices(string.ascii_uppercase, k=2)
    lower = random.choices(string.ascii_lowercase, k=2)
    digit = random.choices(string.digits, k=2)
    symbol = random.choices("!@#$%&*", k=2)
    rest = random.choices(string.ascii_letters + string.digits + "!@#$%&*", k=PASSWORD_MIN_LENGTH - 8)
    parts = upper + lower + digit + symbol + rest
    random.shuffle(parts)
    return "".join(parts)


def run_one_with_retry(
    email_id: int,
    email: str,
    password: str,
    uuid_val: str,
    token: str,
    settings: dict,
    task_id: str,
) -> bool:
    """
    单条任务带重试（1～5 次），成功写 accounts、run_logs、last_run_success，失败写 run_logs、last_run_fail。
    返回是否最终成功。
    """
    pwd = (password or "").strip() or _random_password()
    if len(pwd) < PASSWORD_MIN_LENGTH:
        pwd = _random_password()
    retry_count = max(1, min(5, int(settings.get("retry_count") or "2")))
    last_error = None
    _now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        c = conn.cursor()
        c.execute(
            "INSERT INTO run_logs (task_id, level, message, created_at) VALUES (?, ?, ?, ?)",
            (task_id, "info", f"正在注册账号 {email}", _now),
        )
    if is_stop_requested():
        with get_db() as conn:
            c = conn.cursor()
            created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute(
                "INSERT INTO run_logs (task_id, level, message, created_at) VALUES (?, ?, ?, ?)",
                (task_id, "info", f"任务已停止，跳过 {email}", created),
            )
        return False
    for attempt in range(retry_count):
        if is_stop_requested():
            with get_db() as conn:
                c = conn.cursor()
                created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                c.execute(
                    "INSERT INTO run_logs (task_id, level, message, created_at) VALUES (?, ?, ?, ?)",
                    (task_id, "info", f"任务已停止，跳过 {email}", created),
                )
            return False
        use_settings = settings
        _restore_direct_auth = None
        err = str(last_error or "").lower()
        retry_no_proxy = (
            attempt == 1
            and last_error
            and (
                "409" in str(last_error)
                or "invalid_state" in err
                or "tls" in err
                or "connection timed out" in err
                or "curl: (28)" in str(last_error)
                or "curl: (35)" in str(last_error)
            )
        )
        if retry_no_proxy:
            use_settings = {**settings, "proxy_url": ""}
            _restore_direct_auth = os.environ.get("USE_DIRECT_AUTH")
            os.environ["USE_DIRECT_AUTH"] = "1"
            print("[*] retry: no proxy + USE_DIRECT_AUTH=1", flush=True)
            with get_db() as conn:
                c = conn.cursor()
                created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                c.execute(
                    "INSERT INTO run_logs (task_id, level, message, created_at) VALUES (?, ?, ?, ?)",
                    (task_id, "info", "重试：无代理 + 直连 auth", created),
                )
        try:
            success, status_extra, tokens = _run_one_registration(
                email_id, email, pwd, uuid_val, token, use_settings, task_id
            )
        finally:
            if _restore_direct_auth is not None:
                if _restore_direct_auth:
                    os.environ["USE_DIRECT_AUTH"] = _restore_direct_auth
                else:
                    os.environ.pop("USE_DIRECT_AUTH", None)
        if success:
            _ensure_injected()
            import protocol_register as pr
            proxy_raw = (settings.get("proxy_url") or "").strip()
            proxy_lines = [p.strip() for p in proxy_raw.splitlines() if p.strip()]
            same_proxy = random.choice(proxy_lines) if proxy_lines else None
            if tokens:
                try:
                    pr.activate_sora(tokens, email, proxy_url=same_proxy)
                except Exception:
                    pass
            try:
                rt = ""
                at = ""
                if isinstance(tokens, dict):
                    rt = tokens.get("refresh_token") or ""
                    if not rt and isinstance(tokens.get("session"), dict):
                        rt = (tokens.get("session") or {}).get("refresh_token") or ""
                    rt = (rt or "").strip() if rt else ""
                    at = (tokens.get("access_token") or "").strip() or None
                with get_db() as conn:
                    c = conn.cursor()
                    c.execute(
                        """INSERT OR REPLACE INTO accounts (email, password, status, registered_at, has_sora, has_plus, phone_bound, proxy, refresh_token, access_token)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            email,
                            pwd,
                            "Registered+Sora" if tokens else "Registered",
                            datetime.now().strftime("%Y-%m-%d %H:%M"),
                            1 if tokens else 0,
                            0,
                            0,
                            (same_proxy or ""),
                            rt or None,
                            at,
                        ),
                    )
                    created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    c.execute(
                        "INSERT INTO run_logs (task_id, level, message, created_at) VALUES (?, ?, ?, ?)",
                        (task_id, "info", f"注册成功 {email}", created),
                    )
                    try:
                        from app.database import DB_PATH
                        c.execute("SELECT COUNT(*) FROM accounts")
                        n = c.fetchone()[0]
                        created2 = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        c.execute(
                            "INSERT INTO run_logs (task_id, level, message, created_at) VALUES (?, ?, ?, ?)",
                            (task_id, "info", f"账号已写入 accounts 表，数据文件: {DB_PATH}，当前共 {n} 条", created2),
                        )
                    except Exception:
                        pass
                    c.execute("SELECT value FROM system_settings WHERE key = 'last_run_success'")
                    r2 = c.fetchone()
                    prev_ok = int((r2[0] or "0")) if r2 else 0
                    c.execute(
                        "INSERT OR REPLACE INTO system_settings (key, value) VALUES ('last_run_success', ?)",
                        (str(prev_ok + 1),),
                    )
            except Exception as e:
                created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with get_db() as conn:
                    c = conn.cursor()
                    c.execute(
                        "INSERT INTO run_logs (task_id, level, message, created_at) VALUES (?, ?, ?, ?)",
                        (task_id, "error", f"注册成功但写入账号列表失败 {email}: {e!s}", created),
                    )
                return False
            return True
        last_error = status_extra or "注册失败"
        with get_db() as conn:
            c = conn.cursor()
            created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute(
                "INSERT INTO run_logs (task_id, level, message, created_at) VALUES (?, ?, ?, ?)",
                (task_id, "error", f"尝试 {attempt + 1}/{retry_count} 失败 {email}: {last_error}", created),
            )

    with get_db() as conn:
        c = conn.cursor()
        created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute(
            "INSERT INTO run_logs (task_id, level, message, created_at) VALUES (?, ?, ?, ?)",
            (task_id, "error", f"注册失败 {email} (已重试 {retry_count} 次)", created),
        )
        c.execute("SELECT value FROM system_settings WHERE key = 'last_run_fail'")
        row = c.fetchone()
        prev = int((row[0] or "0")) if row else 0
        c.execute(
            "INSERT OR REPLACE INTO system_settings (key, value) VALUES ('last_run_fail', ?)",
            (str(prev + 1),),
        )
    return False


def run_one_task(
    task_id: str,
    settings: Optional[dict] = None,
    email_row: Optional[Tuple] = None,
) -> bool:
    """
    执行单条注册任务。若传 email_row 则用该行；否则从 DB 取一条未注册邮箱。
    返回是否执行并成功（无任务可执行时返回 False）。
    """
    init_db()
    if settings is None:
        settings = _get_registration_settings()
    if email_row is not None:
        row = email_row
    else:
        with get_db() as conn:
            row = fetch_one_unregistered_email(conn)
    if not row:
        return False
    if is_stop_requested():
        return False
    email_id, email, password, uuid_val, token = row
    return run_one_with_retry(email_id, email, password or "", uuid_val or "", token or "", settings, task_id)
