"""
Sentinel Token 生成（从 protocol_keygen 可注册方案移植）。
用于 authorize/continue、user/register 等步骤的 openai-sentinel-token 头。
"""
import base64
import json
import random
import time
import uuid
from datetime import datetime, timezone

# 与 keygen 一致，需与 sec-ch-ua 版本匹配
SENTINEL_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36"
)


class SentinelTokenGenerator:
    """Sentinel PoW 纯 Python 生成器（逆向 sentinel SDK）。"""

    MAX_ATTEMPTS = 500000
    ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

    def __init__(self, device_id=None):
        self.device_id = device_id or str(uuid.uuid4())
        self.requirements_seed = str(random.random())
        self.sid = str(uuid.uuid4())

    @staticmethod
    def _fnv1a_32(text):
        h = 2166136261
        for ch in text:
            h ^= ord(ch)
            h = ((h * 16777619) & 0xFFFFFFFF)
        h ^= (h >> 16)
        h = ((h * 2246822507) & 0xFFFFFFFF)
        h ^= (h >> 13)
        h = ((h * 3266489909) & 0xFFFFFFFF)
        h ^= (h >> 16)
        return format(h & 0xFFFFFFFF, '08x')

    def _get_config(self):
        screen_info = "1920x1080"
        now = datetime.now(timezone.utc)
        date_str = now.strftime("%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)")
        config = [
            screen_info, date_str, 4294705152, random.random(),
            SENTINEL_USER_AGENT, "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js",
            None, None, "en-US", "en-US,en", random.random(),
            random.choice(["vendorSub", "productSub", "vendor", "maxTouchPoints"]) + "\u2212undefined",
            random.choice(["location", "implementation", "URL", "documentURI", "compatMode"]),
            random.choice(["Object", "Function", "Array", "Number", "parseFloat", "undefined"]),
            random.uniform(1000, 50000), self.sid, "",
            random.choice([4, 8, 12, 16]), time.time() * 1000 - random.uniform(1000, 50000),
        ]
        return config

    @staticmethod
    def _base64_encode(data):
        return base64.b64encode(json.dumps(data, separators=(',', ':'), ensure_ascii=False).encode()).decode()

    def _run_check(self, start_time, seed, difficulty, config, nonce):
        config = list(config)
        config[3] = nonce
        config[9] = round((time.time() - start_time) * 1000)
        data = self._base64_encode(config)
        hash_hex = self._fnv1a_32(seed + data)
        diff_len = len(difficulty)
        if hash_hex[:diff_len] <= difficulty:
            return data + "~S"
        return None

    def generate_token(self, seed=None, difficulty=None):
        if seed is None:
            seed = self.requirements_seed
            difficulty = difficulty or "0"
        start_time = time.time()
        config = self._get_config()
        for i in range(self.MAX_ATTEMPTS):
            result = self._run_check(start_time, seed, difficulty, config, i)
            if result:
                return "gAAAAAB" + result
        return "gAAAAAB" + self.ERROR_PREFIX + self._base64_encode(str(None))

    def generate_requirements_token(self):
        config = self._get_config()
        config[3] = 1
        config[9] = round(random.uniform(5, 50))
        return "gAAAAAC" + self._base64_encode(config)


def fetch_sentinel_challenge(session, device_id, flow="authorize_continue"):
    """调用 sentinel 后端获取 challenge（含 c 与 proofofwork）。"""
    gen = SentinelTokenGenerator(device_id=device_id)
    p_token = gen.generate_requirements_token()
    req_body = {"p": p_token, "id": device_id, "flow": flow}
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html",
        "User-Agent": SENTINEL_USER_AGENT,
        "Origin": "https://sentinel.openai.com",
        "sec-ch-ua": '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }
    try:
        resp = session.post(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            data=json.dumps(req_body), headers=headers, timeout=15, verify=False,
        )
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None


def build_sentinel_token(session, device_id, flow="authorize_continue"):
    """构建 openai-sentinel-token 头值（JSON 字符串，含 p/t/c/id/flow）。"""
    challenge = fetch_sentinel_challenge(session, device_id, flow)
    if not challenge:
        return None
    c_value = challenge.get("token", "")
    pow_data = challenge.get("proofofwork", {}) or {}
    gen = SentinelTokenGenerator(device_id=device_id)
    if pow_data.get("required") and pow_data.get("seed"):
        p_value = gen.generate_token(seed=pow_data["seed"], difficulty=pow_data.get("difficulty", "0"))
    else:
        p_value = gen.generate_requirements_token()
    return json.dumps({"p": p_value, "t": "", "c": c_value, "id": device_id, "flow": flow})


def build_sentinel_token_pow_only(device_id):
    """仅 PoW 字符串（keygen 的 register 步骤用）。"""
    gen = SentinelTokenGenerator(device_id=device_id)
    return gen.generate_token()
