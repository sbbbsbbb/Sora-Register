"""
Web 端调用 protocol_register 前的 config/utils 注入。
在首次 import protocol_register 之前调用 inject_registration_modules()，
并在每任务开始前调用 set_task_config() 设置当前线程的 proxy/timeout 等。
"""
import sys
import threading
import types
from pathlib import Path

# 线程局部：当前注册任务的 proxy、timeout 等，由 runner 在每任务开始前写入
_reg_task = threading.local()

# 默认超时与 UA（与 protocol_register 内默认一致）
DEFAULT_HTTP_TIMEOUT = 60
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


def set_task_config(
    *,
    proxy_url=None,
    timeout=DEFAULT_HTTP_TIMEOUT,
    user_agent=None,
    http_max_retries=5,
    oauth_client_id=None,
    oauth_redirect_uri=None,
):
    """由 registration_runner 在每任务开始前调用，设置当前线程的注册配置。"""
    _reg_task.proxy_url = proxy_url
    _reg_task.timeout = timeout
    _reg_task.user_agent = user_agent
    _reg_task.http_max_retries = http_max_retries
    _reg_task.oauth_client_id = oauth_client_id if oauth_client_id is not None else getattr(_reg_task, "oauth_client_id", "")
    _reg_task.oauth_redirect_uri = oauth_redirect_uri if oauth_redirect_uri is not None else getattr(_reg_task, "oauth_redirect_uri", "")


def clear_task_config():
    """任务结束后可调用，清理当前线程配置（可选）。"""
    for key in ("proxy_url", "timeout", "user_agent", "http_max_retries"):
        if hasattr(_reg_task, key):
            delattr(_reg_task, key)


def get_proxy_url_random():
    """供注入的 config 使用；优先返回当前任务线程的 proxy。"""
    return getattr(_reg_task, "proxy_url", None)


def get_proxy_url_for_session():
    """供注入的 config 使用。"""
    return getattr(_reg_task, "proxy_url", None)


def get_http_timeout():
    return getattr(_reg_task, "timeout", DEFAULT_HTTP_TIMEOUT)


def get_user_agent():
    return getattr(_reg_task, "user_agent", None) or DEFAULT_USER_AGENT


def _make_cfg():
    """最小 cfg：protocol_register 用到的 retry、oauth（按线程动态，oauth 来自系统设置）。"""

    class _Retry:
        @property
        def http_max_retries(self):
            return getattr(_reg_task, "http_max_retries", 5)

    class _OAuth:
        @property
        def client_id(self):
            return getattr(_reg_task, "oauth_client_id", None) or ""

        @property
        def redirect_uri(self):
            return getattr(_reg_task, "oauth_redirect_uri", None) or ""

    cfg = types.SimpleNamespace()
    cfg.retry = _Retry()
    cfg.oauth = _OAuth()
    return cfg


def inject_registration_modules():
    """
    在首次 import protocol_register 之前调用。
    向 sys.modules 注入 config 与 utils，并确保协议包根目录在 sys.path 中。
    """
    root = Path(__file__).resolve().parent.parent.parent.parent  # app -> backend -> web -> protocol
    root_str = str(root)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)

    # 仅在首次执行注册前注入，保证 protocol_register 的 from config/utils 使用桩
    _config = types.ModuleType("config")
    _config.__registration_stub__ = True
    _config.HTTP_TIMEOUT = DEFAULT_HTTP_TIMEOUT
    _config.get_proxy_url_random = get_proxy_url_random
    _config.get_proxy_url_for_session = get_proxy_url_for_session
    _config.cfg = _make_cfg()
    sys.modules["config"] = _config

    _utils = types.ModuleType("utils")
    _utils.__registration_stub__ = True
    _utils.get_user_agent = get_user_agent
    sys.modules["utils"] = _utils
