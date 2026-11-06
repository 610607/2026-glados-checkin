#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
2026 GLaDOS 自动签到 (积分增强版)

功能：
- 全自动签到
- 精准获取当前积分 (Points)
- 积分达标自动兑换会员天数（默认 500 分兑换 100 天，可配置/关闭）
- PushPlus / Server酱 微信推送（包含积分、剩余天数、签到结果、兑换结果）
- 智能多域名切换 (优先 glados.cloud)
- 支持 Cookie-Editor 导出格式
"""

import hashlib
import html
import http.cookiejar
import json
import math
import os
import random
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Fix Windows Unicode Output
if sys.platform.startswith('win'):
    sys.stdout.reconfigure(encoding='utf-8')

# ================= 配置 =================

# 域名优先级：Cloud 第一
DOMAINS = [
    "https://glados.cloud",
    "https://glados.rocks", 
    "https://glados.network",
]

DEFAULT_USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/120.0.0.0 Safari/537.36'
)

HEADERS = {
    'Content-Type': 'application/json;charset=UTF-8',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
}

NORMAL_CHECKIN_MESSAGES = (
    "checkin! got",
    "checkin repeats! please try tomorrow",
    "today's observation logged",
)

# The current official console obtains a fresh challenge, waits at least 2.5 s,
# and sends SHA-256(nonce + ".glados-observe-v1") with the check-in request.
# Stay strictly above that floor and add a short human-like jitter.
CHECKIN_CHALLENGE_DELAY = 2.5
CHECKIN_OBSERVE_MIN = 2.8
CHECKIN_OBSERVE_MAX = 4.0
CHECKIN_PROOF_SUFFIX = '.glados-observe-v1'
SCHEDULE_JITTER_MIN = 5
SCHEDULE_JITTER_MAX = 45

# Official console map: 0/10 Free, 11 Education, 21 Basic, 31 Pro, 41 Team, 51 Enterprise.
VIP_LABELS = {
    0: 'Free',
    10: 'Free',
    11: 'Edu',
    21: 'Basic',
    31: 'Pro',
    41: 'Team',
    51: 'Enterprise',
}
VIP_NAMES = {
    'free': 'Free',
    'edu': 'Edu',
    'education': 'Edu',
    'basic': 'Basic',
    'pro': 'Pro',
    'team': 'Team',
    'enterprise': 'Enterprise',
}

# 积分兑换计划 (#11)：消耗 points 积分兑换 days 天会员。
# 通过环境变量 EXCHANGE_PLAN 选择，默认 plan500（500 分兑换 100 天），
# 设为 off 关闭自动兑换。
EXCHANGE_PLANS = {
    "plan100": {"points": 100, "days": 10},
    "plan200": {"points": 200, "days": 30},
    "plan500": {"points": 500, "days": 100},
}

EXCHANGE_DISABLED_VALUES = ("", "off", "no", "none", "false", "0", "disabled")

CURRENT_SESSION_COOKIES = ('gld:sess', 'gld:sess.sig')
LEGACY_SESSION_COOKIES = ('koa:sess', 'koa:sess.sig')

# ================= 工具函数 =================

def get_beijing_time():
    """Timezone-aware Beijing time (UTC+8)."""
    return datetime.now(timezone(timedelta(hours=8)))


def beijing_time():
    return get_beijing_time().strftime("%Y-%m-%d %H:%M:%S")


def log(msg):
    print(f"[{beijing_time()} 北京时间] {msg}")

def sanitize_cookie(raw):
    """Drop copied wrappers. Return None when the value cannot be a header."""
    if not isinstance(raw, str):
        return None
    # Requests encodes headers as latin-1; non-ASCII here crashes the run.
    if any(ord(char) > 127 for char in raw):
        return None
    value = raw.strip()
    if not value:
        return None
    value = re.sub(r'^(?i:cookie)\s*:\s*', '', value).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
        inner = value[1:-1].strip()
        if inner:
            value = re.sub(r'^(?i:cookie)\s*:\s*', '', inner).strip()
    if not value or any(ord(char) > 127 for char in value):
        return None
    # JSON exports may contain newlines. A Cookie header must not.
    if not value.lstrip().startswith(('{', '[')) and any(ord(char) < 32 for char in value):
        return None
    return value


def extract_cookie(raw: str):
    """提取 Cookie，支持请求头及 Cookie-Editor JSON 导出格式。"""
    raw = sanitize_cookie(raw)
    if not raw:
        return None
    
    # GLaDOS 2026 新会话与旧 Koa 会话的 Cookie 请求头格式。
    if any(f'{name}=' in raw for name in CURRENT_SESSION_COOKIES + LEGACY_SESSION_COOKIES):
        return raw
        
    # Cookie-Editor 的 JSON 数组导出，或旧版 {"token": "..."} 格式。
    if raw.startswith(('{', '[')):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                pairs = []
                for item in parsed:
                    if not isinstance(item, dict):
                        continue
                    name = item.get('name')
                    value = item.get('value')
                    if name and value is not None:
                        pairs.append(f'{name}={value}')
                cookie = '; '.join(pairs)
                return cookie if cookie and get_session_cookie_kind(cookie) else None

            token = parsed.get('token') if isinstance(parsed, dict) else None
            return f'koa:sess={token}' if token else None
        except (json.JSONDecodeError, AttributeError, TypeError):
            return None
        
    # JWT Token
    if raw.count('.') == 2 and '=' not in raw and len(raw) > 50:
        return 'koa:sess=' + raw
        
    # Standard
    return raw


def get_cookie_names(cookie_header):
    """Return Cookie names only; values are deliberately never logged."""
    names = set()
    for item in cookie_header.split(';'):
        name, separator, _ = item.strip().partition('=')
        if separator and name:
            names.add(name)
    return names


def get_session_cookie_kind(cookie_header):
    """Identify a complete current or legacy signed session Cookie pair."""
    names = get_cookie_names(cookie_header)
    if set(CURRENT_SESSION_COOKIES).issubset(names):
        return 'gld'
    if set(LEGACY_SESSION_COOKIES).issubset(names):
        return 'koa'
    return None

def get_cookies():
    raw = os.environ.get("GLADOS_COOKIE", "")
    if not raw:
        log("❌ 未配置 GLADOS_COOKIE")
        return []

    # A Cookie-Editor export is one JSON document. Its formatting newlines
    # and ampersands inside values are not account separators.
    if raw.lstrip().startswith(('{', '[')):
        cookie = extract_cookie(raw)
        if cookie is None and any(ord(char) > 127 for char in raw):
            log("❌ Cookie 含有非 ASCII 字符，已跳过该账号")
        return [cookie] if cookie else []

    # Split by enter or &
    sep = '\n' if '\n' in raw else '&'
    cookies = []
    skipped_non_ascii = False
    for item in raw.split(sep):
        if any(ord(char) > 127 for char in item):
            skipped_non_ascii = True
        cookie = extract_cookie(item)
        if cookie:
            cookies.append(cookie)
    if skipped_non_ascii:
        log("❌ Cookie 含有非 ASCII 字符，已跳过对应账号")
    return cookies


class UserAgentConfigurationError(ValueError):
    """Invalid local User-Agent input; messages never contain the supplied value."""


def normalize_user_agent(raw):
    """Remove common copy/paste wrappers without altering the browser value."""
    if any((ord(char) < 32 and char not in '\t\r\n') or ord(char) == 127 for char in raw):
        raise UserAgentConfigurationError('含有无效控制字符，请重新复制浏览器的 User-Agent')
    value = raw.strip()
    if not value:
        return '', False
    if '\r' in value or '\n' in value:
        raise UserAgentConfigurationError('含有换行，请粘贴完整单行 User-Agent')
    try:
        value.encode('latin-1')
    except UnicodeEncodeError:
        raise UserAgentConfigurationError(
            '含有不支持的字符，请重新复制浏览器的 User-Agent，不要加入说明文字或中文引号'
        ) from None

    original = value
    prefix_removed = False
    if value.lower().startswith('user-agent:'):
        value = value[len('user-agent:'):].strip()
        prefix_removed = True
    if len(value) >= 2 and value[0] == value[-1]:
        inner = value[1:-1]
        # Apostrophes can be legal product-token characters. Preserve a quoted
        # single token; only unwrap full, space-containing browser strings or
        # an explicitly copied header name. Double quotes are not token chars.
        single_quote_wrapper = value[0] == "'" and (
            not inner or any(char in ' \t' for char in inner)
            or inner.lower().startswith('user-agent:')
        )
        if value[0] == '"' or single_quote_wrapper:
            value = inner.strip()
    if not prefix_removed and value.lower().startswith('user-agent:'):
        value = value[len('user-agent:'):].strip()
    if not value:
        raise UserAgentConfigurationError('只有请求头名称或引号，没有 User-Agent 值')
    if value[0] == '"' or value[-1] == '"':
        raise UserAgentConfigurationError('外层双引号不成对或重复，请只保留 User-Agent 值')
    if len(value) >= 2 and value[0] == value[-1] == "'" and any(char in ' \t' for char in value):
        raise UserAgentConfigurationError('包裹 User-Agent 的单引号重复，请只保留 User-Agent 值')
    if value.lower().startswith('user-agent:'):
        raise UserAgentConfigurationError('请求头名称重复，请只保留 User-Agent 值')
    return value, value != original


def get_browser_headers(user_agent_raw=None):
    """Build headers matching the browser that created the login session."""
    if user_agent_raw is None:
        user_agent_raw = os.environ.get("GLADOS_USER_AGENT", "")
    user_agent, _ = normalize_user_agent(user_agent_raw)
    user_agent = user_agent or DEFAULT_USER_AGENT
    headers = {'User-Agent': user_agent}

    chrome = re.search(r'(?:Chrome|Chromium)/(\d+)', user_agent)
    if chrome:
        major = chrome.group(1)
        if 'Macintosh' in user_agent:
            platform = 'macOS'
        elif 'Windows' in user_agent:
            platform = 'Windows'
        elif 'Android' in user_agent:
            platform = 'Android'
        elif 'Linux' in user_agent:
            platform = 'Linux'
        else:
            platform = 'Unknown'

        headers.update({
            'Sec-CH-UA': (
                f'"Chromium";v="{major}", '
                f'"Google Chrome";v="{major}", '
                '"Not_A Brand";v="99"'
            ),
            'Sec-CH-UA-Mobile': '?1' if 'Mobile' in user_agent else '?0',
            'Sec-CH-UA-Platform': f'"{platform}"',
        })

    return headers


def is_non_retryable_checkin_result(result):
    """Return True for authentication/device failures that waiting cannot fix."""
    if not isinstance(result, dict):
        return False
    code = result.get('code')
    reason = str(result.get('reason', '')).strip().lower()
    message = str(result.get('message', '')).strip().lower()
    return (
        code == -2
        or code == 4
        or result.get('http_status') in (401, 403)
        or reason == 'device-mismatch'
        or '没有权限' in message
        or 'permission' in message
        or 'unauthorized' in message
        or 'automated check-in detected' in message
    )


def is_missing_api_response(result):
    return not isinstance(result, dict) or result.get('request_failed') is True


def summarize_checkin_failure(result):
    """Describe failures using fixed labels and allowlisted, non-secret metadata."""
    if not isinstance(result, dict):
        return '未收到有效 API 响应；本次请求失败，今日签到状态未知'

    reason = str(result.get('reason', '')).strip().lower()
    message = str(result.get('message', '')).strip().lower()
    code = result.get('code')
    if reason == 'checkin-challenge-unavailable':
        label = '未获取有效签到验证，本次未提交签到，请稍后重试'
    elif reason == 'checkin-challenge-expired':
        label = '签到验证已过期，本次未提交签到，请稍后重试'
    elif result.get('request_failed') is True:
        if result.get('invalid_headers') is True:
            label = '请求头格式无效，请检查 Cookie 和 User-Agent 格式'
        elif result.get('invalid_response') is True:
            label = '服务响应格式异常，未收到有效 API 响应'
        else:
            label = '网络或服务暂时异常，未收到有效 API 响应'
        label += '；本次请求失败，今日签到状态未知'
    elif reason == 'device-mismatch':
        label = '服务端拒绝设备校验；请核对会话和 User-Agent 配置'
    elif 'automated check-in detected' in message:
        label = '服务端拒绝自动签到；请核对会话配置，仍失败时联系服务方'
    elif code == 4:
        label = '服务端拒绝设备校验；请核对会话和 User-Agent 配置'
    elif is_non_retryable_checkin_result(result):
        label = '服务端拒绝会话认证或访问'
    else:
        label = '签到失败'

    details = []
    if type(code) is int and -999 <= code <= 999:
        details.append(f'code={code}')
    status = result.get('http_status')
    if type(status) is int and 100 <= status <= 599:
        details.append(f'http_status={status}')
    if result.get('request_failed') is True and result.get('timed_out') is True:
        details.append('timeout=true')
    if reason in ('device-mismatch', 'http-auth-rejected'):
        details.append(f'reason={reason}')
    return label + (f" [{', '.join(details)}]" if details else '')


def log_user_agent_configuration():
    try:
        user_agent, normalized = normalize_user_agent(os.environ.get('GLADOS_USER_AGENT', ''))
    except UserAgentConfigurationError as error:
        log(f'❌ User-Agent 配置错误: {error}')
        return False
    status = '已配置' if user_agent else '未配置，使用默认值'
    if normalized:
        status += '（已自动去除外层引号或请求头名称）'
    log('浏览器 User-Agent: ' + status)
    return True


def is_normal_checkin_result(result):
    """Return True for a new check-in or a harmless already-checked-in response."""
    if is_missing_api_response(result):
        return False
    if is_non_retryable_checkin_result(result):
        return False

    message = str(result.get('message', '')).strip().lower()
    if any(marker in message for marker in NORMAL_CHECKIN_MESSAGES):
        return True

    # GLaDOS has historically used code=0 for successful check-ins. Newer
    # duplicate/observation responses can use code=1 and are handled above.
    return result.get('code') == 0


def checkin_with_retry(client, attempts=3, delay_seconds=60):
    """Retry transient/unknown check-in failures without sending duplicate alerts."""
    attempts = max(1, attempts)
    last_result = None

    for attempt in range(1, attempts + 1):
        last_result = client.checkin()
        if is_normal_checkin_result(last_result):
            return last_result, True

        if is_non_retryable_checkin_result(last_result):
            log(f"❌ 签到认证失败，不再重试: {summarize_checkin_failure(last_result)}")
            return last_result, False

        if attempt < attempts:
            log(f"⚠️ 签到第 {attempt}/{attempts} 次失败，{delay_seconds} 秒后重试")
            time.sleep(max(0, delay_seconds))

    return last_result, False


def format_points(value):
    """Format a points value, keeping a single decimal for Team .5 awards."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number):
        return None
    scaled = round(number * 10) / 10
    if abs(scaled - round(scaled)) < 1e-9:
        return str(int(round(scaled)))
    return f'{scaled:.1f}'


def format_streak(value):
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number) or number < 0:
        return None
    return str(int(number))


def vip_label(vip, level=None):
    """Map official vip/level fields to Free/Edu/Basic/Pro/Team/Enterprise."""
    for candidate in (level, vip):
        if isinstance(candidate, str):
            mapped = VIP_NAMES.get(candidate.strip().lower())
            if mapped:
                return mapped
    if isinstance(vip, str) and vip.strip().lstrip('-').isdigit():
        try:
            vip = int(vip.strip())
        except ValueError:
            return '?'
    if isinstance(vip, float) and math.isfinite(vip) and vip.is_integer():
        vip = int(vip)
    if type(vip) is int:
        return VIP_LABELS.get(vip, '?')
    return '?'


def is_expired_status(result, data=None):
    """Official /api/user/status uses code -101, and some payloads use leftDays -101."""
    if isinstance(result, dict) and result.get('code') == -101:
        return True
    days = data.get('leftDays') if isinstance(data, dict) else None
    if isinstance(days, str):
        days = days.strip()
    try:
        return float(days) == -101
    except (TypeError, ValueError):
        return False


def compute_checkin_proof(nonce):
    return hashlib.sha256((nonce + CHECKIN_PROOF_SUFFIX).encode('utf-8')).hexdigest()


def checkin_observe_delay():
    """Random wait in [2.8, 4.0], always above the official 2.5s floor."""
    delay = random.uniform(CHECKIN_OBSERVE_MIN, CHECKIN_OBSERVE_MAX)
    return min(CHECKIN_OBSERVE_MAX, max(CHECKIN_OBSERVE_MIN, delay))


def maybe_sleep_schedule_jitter():
    """Spread GitHub Actions schedule runs. Manual and external dispatches do not wait."""
    if os.environ.get('GITHUB_EVENT_NAME', '').strip() != 'schedule':
        return 0.0
    delay = random.uniform(SCHEDULE_JITTER_MIN, SCHEDULE_JITTER_MAX)
    delay = min(SCHEDULE_JITTER_MAX, max(SCHEDULE_JITTER_MIN, delay))
    log(f'定时触发随机延迟 {delay:.0f} 秒')
    time.sleep(delay)
    return delay


def prepare_account_user_agent(index):
    """Return (raw_override_or_None, error_or_None) for GLADOS_USER_AGENT_N."""
    raw = os.environ.get(f'GLADOS_USER_AGENT_{index}', '')
    if not str(raw).strip():
        return None, None
    try:
        value, normalized = normalize_user_agent(raw)
    except UserAgentConfigurationError as error:
        return None, str(error)
    if not value:
        return None, None
    note = '已配置独立值'
    if normalized:
        note += '（已自动去除外层引号或请求头名称）'
    log(f'账号 {index} 浏览器 User-Agent: {note}')
    return raw, None


class _RejectCookies(http.cookiejar.DefaultCookiePolicy):
    """Keep the account Cookie on the explicit header, not the shared cookie jar."""

    def set_ok(self, cookie, request):
        return False


def create_session():
    """Reuse TCP/TLS for one account. Retry idempotent GETs once; never retry POST."""
    session = requests.Session()
    session.cookies.set_policy(_RejectCookies())
    retry = Retry(
        total=1,
        connect=1,
        read=1,
        status=0,
        redirect=0,
        raise_on_status=False,
        allowed_methods=frozenset(['GET', 'HEAD', 'OPTIONS']),
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=4, pool_maxsize=4)
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    return session


def known_text(value):
    """Return a real display string. Ignore missing fields on test doubles."""
    if isinstance(value, str) and value != '?':
        return value
    return None


def apply_checkin_details(client, result):
    """Read earned points, streak and balance from a check-in payload."""
    if not isinstance(result, dict):
        return
    earned = format_points(result.get('points'))
    if earned is not None:
        client.points_earned = earned
    streak = format_streak(result.get('streak'))
    if streak is not None:
        client.streak = streak
    listing = result.get('list')
    if isinstance(listing, list) and listing and isinstance(listing[0], dict):
        balance = format_points(listing[0].get('balance'))
        if balance is not None:
            client.points = balance


def _post_timed_out(result):
    return (
        isinstance(result, dict)
        and result.get('request_failed') is True
        and result.get('timed_out') is True
        and result.get('method') == 'POST'
    )

# ================= 核心逻辑 =================

class GLaDOS:
    def __init__(self, cookie, user_agent=None):
        self.cookie = cookie
        self.user_agent_raw = user_agent
        self.domain = DOMAINS[0]
        self.email = "?"
        self.left_days = "?"
        self.points = "?"
        self.points_change = "?"
        self.points_earned = "?"
        self.streak = "?"
        self.exchange_info = ""
        self.exchange_result = ""
        self.plan = "?"
        self.expired = False
        self.session = create_session()
        self.session_cookie_kind = get_session_cookie_kind(cookie)
        if self.session_cookie_kind != 'gld':
            log(
                "⚠️ Cookie 未包含完整的 gld:sess 与 gld:sess.sig；"
                "2026-09 新版接口可能返回“没有权限”"
            )

    def req(self, method, path, data=None, form=False, domains=None):
        """带自动域名切换的请求；form=True 时以表单提交（兑换接口要求）"""
        # Validate local configuration before the retry loop or any network request.
        browser_headers = get_browser_headers(self.user_agent_raw)
        # Keep only fixed, non-secret failure metadata after all domains fail.
        failure = {'request_failed': True, 'reason': 'request-failed', 'method': method}
        for d in DOMAINS if domains is None else domains:
            try:
                url = f"{d}{path}"
                h = HEADERS.copy()
                h.update(browser_headers)
                h['Cookie'] = self.cookie
                h['Origin'] = d
                h['Referer'] = f"{d}/console/checkin"

                if form:
                    # 表单提交交给 requests 自动设置 Content-Type，
                    # 手动预设 JSON 头会被兑换接口拒绝。
                    h.pop('Content-Type', None)
                    resp = self.session.post(url, headers=h, data=data, timeout=10)
                elif method == 'GET':
                    # GET does not need a JSON Content-Type; omit it.
                    h.pop('Content-Type', None)
                    resp = self.session.get(url, headers=h, timeout=10)
                else:
                    resp = self.session.post(url, headers=h, json=data, timeout=10)

                if resp.status_code == 200:
                    payload = resp.json()
                    if isinstance(payload, dict):
                        self.domain = d # Remember working domain
                        return payload
                    failure['invalid_response'] = True
                    log(f"⚠️ {d} 响应格式异常")
                    continue
                if resp.status_code in (401, 403):
                    # A rejected request must not be replayed on alternate domains.
                    # The response can be HTML or contain private details; do not echo it.
                    return {
                        'http_status': resp.status_code,
                        'reason': 'http-auth-rejected',
                    }
                failure['http_status'] = resp.status_code
                log(f"⚠️ {d} 返回 HTTP {resp.status_code}")
            except (requests.RequestException, ValueError) as e:
                # InvalidHeader and other request errors may embed Cookie values.
                if isinstance(e, requests.Timeout):
                    failure['timed_out'] = True
                elif isinstance(e, requests.exceptions.InvalidHeader):
                    failure['invalid_headers'] = True
                elif isinstance(e, ValueError):
                    failure['invalid_response'] = True
                log(f"⚠️ {d} 请求失败: {type(e).__name__}")
                continue
        return failure

    def get_status(self):
        """获取状态：天数、邮箱、套餐。code/-101 或 leftDays=-101 视为已过期。"""
        res = self.req('GET', '/api/user/status')
        if not isinstance(res, dict):
            return False
        data = res.get('data') if isinstance(res.get('data'), dict) else None
        if data is not None:
            self.email = data.get('email', 'Unknown')
            self.plan = vip_label(data.get('vip'), data.get('level'))
        if is_expired_status(res, data):
            self.expired = True
            self.left_days = '已过期'
            return True
        if data is not None:
            self.left_days = str(data.get('leftDays', '?')).split('.')[0]
            return True
        return False

    def get_points(self):
        """获取积分、变化历史、连签与兑换计划。保留 Team 套餐的 .5 分。"""
        res = self.req('GET', '/api/user/points')
        if res and 'points' in res:
            formatted = format_points(res.get('points'))
            self.points = formatted if formatted is not None else str(res.get('points', '0')).split('.')[0]

            streak = format_streak(res.get('streak'))
            if streak is not None:
                self.streak = streak

            # 最近一次积分变化
            history = res.get('history', [])
            if history and isinstance(history[0], dict):
                last = history[0]
                change = format_points(last.get('change'))
                if change is None:
                    change = str(last.get('change', '0')).split('.')[0]
                if not str(change).startswith('-'):
                    change = '+' + str(change)
                self.points_change = change

            # 兑换计划
            plans = res.get('plans', {})
            try:
                balance = float(self.points)
            except (TypeError, ValueError):
                balance = 0.0
            exchange_lines = []
            for plan_data in plans.values():
                need = int(plan_data.get('points', 0))
                days = plan_data.get('days', '?')
                if balance >= need:
                    exchange_lines.append(f"✅ {need}分→{days}天 (可兑换)")
                else:
                    gap = format_points(need - balance) or str(need - int(balance))
                    exchange_lines.append(f"❌ {need}分→{days}天 (差{gap}分)")
            self.exchange_info = "<br>".join(exchange_lines)
            return True
        return False

    def _checkin_once(self):
        """One challenge → observe → proof submission. Never logs nonce or proof."""
        challenge = self.req('GET', '/api/user/checkin/challenge')
        # Cookie expired (code -2) and device-mismatch (code 4) fail before the wait.
        if is_non_retryable_checkin_result(challenge) or is_missing_api_response(challenge):
            return challenge
        nonce = challenge.get('nonce')
        ttl = challenge.get('ttl', 300000)
        if (
            challenge.get('code') != 0
            or not isinstance(nonce, str) or not 0 < len(nonce) <= 4096
            or type(ttl) not in (int, float)
            or (type(ttl) is float and not math.isfinite(ttl))
            or ttl <= CHECKIN_CHALLENGE_DELAY * 1000
        ):
            return {'request_failed': True, 'reason': 'checkin-challenge-unavailable'}

        # A nonce belongs to the origin which issued it. Do not replay the POST
        # on another domain; the outer retry obtains a fresh challenge instead.
        domain = self.domain
        received_at = time.monotonic()
        proof = compute_checkin_proof(nonce)
        time.sleep(checkin_observe_delay())
        if (time.monotonic() - received_at) * 1000 >= ttl:
            return {'request_failed': True, 'reason': 'checkin-challenge-expired'}
        return self.req('POST', '/api/user/checkin', {
            'token': urlsplit(domain).hostname,
            'nonce': nonce,
            'proof': proof,
        }, domains=(domain,))

    def checkin(self):
        """执行签到。POST 超时则重新申请 nonce 并立即再试一次。"""
        result = self._checkin_once()
        if _post_timed_out(result):
            log('⚠️ 签到提交超时，重新获取验证后重试一次')
            result = self._checkin_once()
        return result

    def exchange(self, plan):
        """兑换会员天数：表单提交 planType (plan100/plan200/plan500)"""
        return self.req('POST', '/api/user/exchange', {'planType': plan}, form=True)

# ================= 自动兑换 (#11) =================

def get_exchange_plan():
    """读取自动兑换配置，返回计划 ID；关闭或无效时返回 None"""
    raw = os.environ.get("EXCHANGE_PLAN", "plan500").strip().lower()
    if raw in EXCHANGE_DISABLED_VALUES:
        return None
    if raw in EXCHANGE_PLANS:
        return raw
    log(f"⚠️ EXCHANGE_PLAN 值 '{raw}' 无效 (可选: {'/'.join(EXCHANGE_PLANS)}/off)，本次跳过兑换")
    return None


def auto_exchange(g, plan_id):
    """积分达标时自动兑换会员天数，返回用于推送的兑换说明"""
    info = EXCHANGE_PLANS[plan_id]
    need, days = info["points"], info["days"]

    try:
        pts = int(float(g.points))
    except (TypeError, ValueError):
        log("⚠️ 积分查询失败，跳过兑换")
        return "⚠️ 兑换跳过(积分查询失败)"

    if pts < need:
        return f"⏭️ 积分不足({pts}/{need})，攒够自动兑换{days}天"

    res = g.exchange(plan_id)
    if res and res.get('code') == 0:
        log(f"🎁 自动兑换成功: {need}分 → +{days}天")
        # 兑换消耗积分、增加天数，刷新后推送里才是最新数据
        g.get_status()
        g.get_points()
        return f"🎁 兑换成功 +{days}天 (消耗{need}分)"

    err = res.get('message', 'Failure') if res else "Network Error"
    log(f"⚠️ 自动兑换失败: {err}")
    return f"⚠️ 兑换失败({err})"

# ================= 主程序 =================

def pushplus(token, title, content):
    if not token:
        return False
    try:
        url = "https://www.pushplus.plus/send"
        response = requests.post(
            url,
            json={'token': token, 'title': title, 'content': content, 'template': 'html'},
            timeout=10,
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get('code') not in (None, 0, 200):
            raise RuntimeError(payload.get('msg', f"PushPlus code={payload.get('code')}"))
        log("✅ PushPlus 推送成功")
        return True
    except (requests.RequestException, ValueError, RuntimeError) as e:
        log(f"❌ PushPlus 推送失败: {e}")
        return False

def serverchan_push(sendkey, title, content):
    """发送 Server酱通知，兼容 Turbo 与 Server酱³ SendKey。"""
    sendkey = (sendkey or "").strip()
    if not sendkey:
        return False

    # 与官方 SDK 保持相同的 SendKey 路由，无需增加依赖。
    # https://sct.ftqq.com/docs/integrations/python/
    if sendkey.startswith("sctp"):
        match = re.match(r"sctp([0-9]+)t", sendkey)
        if not match:
            log("❌ Server酱 推送失败: Server酱³ SendKey 格式无效")
            return False
        url = f"https://{match.group(1)}.push.ft07.com/send/{sendkey}.send"
    else:
        url = f"https://sctapi.ftqq.com/{sendkey}.send"

    # 复用完整的多账号报告；先去标签再解码，保留正文里的 HTML 转义字符。
    text = re.sub(r"<br\s*/?>", "\n", content, flags=re.IGNORECASE)
    text = re.sub(r"</(?:h[1-6]|p|div)\s*>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)
    lines = [line.strip() for line in html.unescape(text).splitlines()]
    desp = "  \n".join(line for line in lines if line)

    try:
        response = requests.post(url, json={'title': title, 'desp': desp}, timeout=10)
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict) or payload.get('code') != 0:
            code = payload.get('code') if isinstance(payload, dict) else None
            detail = f"code={code}" if type(code) is int else "接口返回无效响应"
            log(f"❌ Server酱 推送失败: {detail}")
            return False
        log("✅ Server酱 推送成功")
        return True
    except (requests.RequestException, ValueError) as e:
        # HTTP 异常可能包含带 SendKey 的请求 URL，不输出原始异常或响应正文。
        log(f"❌ Server酱 推送失败: {type(e).__name__}")
        return False


def telegram_push(token, chat_id, title, content):
    if not token or not chat_id: return
    try:
        import re
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        # Convert HTML to be Telegram-compatible
        text = f"<b>{title}</b>\n\n{content}"
        
        # 1. Block elements replacements (handle tags with attributes)
        text = text.replace("<br>", "\n")
        # Handle H3 tags
        text = re.sub(r"<h3[^>]*>", "<b>", text)
        text = text.replace("</h3>", "</b>\n")
        
        # 2. Paragraph and Div tags
        text = re.sub(r"<(div|p)[^>]*>", "", text)
        text = re.sub(r"</(div|p)>", "\n", text)
        
        # 3. Span and small tags
        text = re.sub(r"<(span|small)[^>]*>", "", text)
        text = re.sub(r"</(span|small)>", "", text)
        
        # 4. Final cleaning: Strip all HTML tags EXCEPT the ones supported by Telegram: b, i, u, s, a, code, pre
        text = re.sub(r"<(?!\/?(b|i|u|s|a|code|pre)\b)[^>]+>", "", text)
        
        # 5. Dedent each line to fix alignment issues caused by HTML template indentation
        lines = [line.strip() for line in text.split('\n')]
        text = "\n".join(lines)
        
        # 6. Collapse multiple newlines
        text = re.sub(r"\n\s*\n", "\n\n", text).strip()
        
        data = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML"
        }
        resp = requests.post(url, json=data, timeout=10)
        if resp.status_code != 200:
            log(f"❌ Telegram 推送失败: HTTP {resp.status_code}")
            return False
        log("✅ Telegram 推送成功")
        return True
    except (requests.RequestException, ValueError) as e:
        log(f"❌ Telegram 推送失败: {e}")
        return False

def diagnose_accounts(cookies):
    """Read authentication status without check-in, redemption or notifications."""
    success_cnt = 0
    log('🔎 只读诊断：仅查询登录状态，不签到、不兑换、不推送')
    if not log_user_agent_configuration():
        return 1
    for i, cookie in enumerate(cookies, 1):
        user_agent, error = prepare_account_user_agent(i)
        if error:
            log(f'❌ 账号 {i} User-Agent 配置错误: {error}')
            continue
        client = GLaDOS(cookie, user_agent=user_agent)
        result = client.req('GET', '/api/user/status')
        authenticated = (
            isinstance(result, dict)
            and result.get('code') == 0
            and isinstance(result.get('data'), dict)
            and bool(result['data'])
        )
        # Never print response bodies: they may contain email or account data.
        if authenticated:
            success_cnt += 1
            log(f'✅ 账号 {i}: 登录状态查询成功')
        elif is_non_retryable_checkin_result(result):
            log(f'❌ 账号 {i}: 会话认证被拒绝；{summarize_checkin_failure(result)}')
        elif is_missing_api_response(result):
            log(f'❌ 账号 {i}: 登录状态查询失败；{summarize_checkin_failure(result)}')
        else:
            log(f'❌ 账号 {i}: 登录状态查询失败，请检查 API 返回分类和会话配置')
    log('只读查询通过不代表签到设备校验通过；实际签到仍需匹配浏览器 User-Agent')
    return 0 if success_cnt == len(cookies) else 1


def main():
    log("🚀 2026 GLaDOS Checkin Starting...")
    cookies = get_cookies()
    if not cookies:
        return 1

    maybe_sleep_schedule_jitter()

    if os.environ.get('CHECKIN_DIAGNOSTIC_ONLY', '').strip().lower() in ('1', 'true', 'yes'):
        return diagnose_accounts(cookies)

    if not log_user_agent_configuration():
        return 1
    exchange_plan = get_exchange_plan()
    if exchange_plan:
        plan = EXCHANGE_PLANS[exchange_plan]
        log(f"🎁 自动兑换已启用: {plan['points']}分 → {plan['days']}天 (EXCHANGE_PLAN={exchange_plan})")
    else:
        log("⏭️ 自动兑换未启用")

    results = []
    success_cnt = 0
    exchange_events = 0

    for i, cookie in enumerate(cookies, 1):
        user_agent, ua_error = prepare_account_user_agent(i)
        if ua_error:
            log(f'❌ 账号 {i} User-Agent 配置错误: {ua_error}')
            results.append(f"""
<div style="border:2px solid #333; padding:15px; margin-bottom:15px; border-radius:10px; background:#fff;">
    <h3 style="margin:0 0 15px 0; color:#333; border-bottom:2px solid #333; padding-bottom:8px;">👤 账号 {i}</h3>
    <p style="margin:8px 0; color:#000; font-size:16px;"><b>签到结果:</b> {html.escape('User-Agent 配置错误: ' + ua_error)}</p>
</div>
""")
            continue
        g = GLaDOS(cookie, user_agent=user_agent)

        # 1. Checkin
        attempts = int(os.environ.get("CHECKIN_MAX_ATTEMPTS", "3"))
        delay_seconds = int(os.environ.get("CHECKIN_RETRY_DELAY_SECONDS", "60"))
        res, is_success = checkin_with_retry(g, attempts, delay_seconds)
        msg = res.get('message', 'Success') if is_success else summarize_checkin_failure(res)

        if is_non_retryable_checkin_result(res):
            # Stop all follow-up requests for this account after an explicit denial.
            g.exchange_result = '⏭️ 认证被拒绝，跳过兑换'
        elif is_missing_api_response(res):
            # Do not add more reads or attempt redemption during a transport outage.
            g.exchange_result = '⏭️ 本次请求失败，跳过积分查询和兑换'
        else:
            # 2. Check-in payload first, then /api/user/points fills balance and streak
            # when a repeat response omits them.
            apply_checkin_details(g, res)
            g.get_status()
            g.get_points()

            # 2.5 Auto exchange (issue #11): runs after check-in so the
            # just-earned points count toward the threshold.
            if exchange_plan:
                g.exchange_result = auto_exchange(g, exchange_plan)
                if not g.exchange_result.startswith("⏭️"):
                    exchange_events += 1

        # 3. Log
        status_icon = "✅" if is_success else "❌"
        # Actions logs are public in a public repository. Keep account details
        # inside the private notification instead of exposing the email here.
        earned = ''
        earned_value = known_text(getattr(g, 'points_earned', None))
        if earned_value:
            earned_text = earned_value if earned_value.startswith(('+', '-')) else f'+{earned_value}'
            earned = f' | 本次: {earned_text}'
        plan_text = known_text(getattr(g, 'plan', None)) or '?'
        streak_text = known_text(getattr(g, 'streak', None)) or '?'
        log(
            f"{status_icon} 账号 {i} | 套餐: {plan_text} | 积分: {g.points} | "
            f"连签: {streak_text} | 天数: {g.left_days}{earned} | 结果: {msg}"
        )

        if is_success:
            success_cnt += 1

        # 4. Result Formatting
        account_label = str(g.email) if g.email != '?' else f'账号 {i}'
        points_label = str(g.points) if g.points != '?' else '未获取'
        change_label = f'({g.points_change})' if g.points_change != '?' else ''
        if getattr(g, 'expired', False) is True or g.left_days == '已过期':
            days_label = '已过期'
        elif isinstance(g.left_days, str) and g.left_days != '?':
            days_label = f'{g.left_days} 天'
        else:
            days_label = '未获取'
        plan_label = known_text(getattr(g, 'plan', None)) or '未获取'
        streak_value = known_text(getattr(g, 'streak', None))
        streak_label = f'{streak_value} 天' if streak_value else '未获取'
        earned_line = ''
        if earned_value:
            earned_line = f"""
    <p style="margin:8px 0; color:#000; font-size:16px;"><b>本次积分:</b> {html.escape(earned_text)}</p>"""
        exchange_line = ""
        if exchange_plan:
            exchange_line = f"""
    <p style="margin:8px 0; color:#000; font-size:16px;"><b>自动兑换:</b> {html.escape(g.exchange_result)}</p>"""
        results.append(f"""
<div style="border:2px solid #333; padding:15px; margin-bottom:15px; border-radius:10px; background:#fff;">
    <h3 style="margin:0 0 15px 0; color:#333; border-bottom:2px solid #333; padding-bottom:8px;">👤 {html.escape(account_label)}</h3>
    <p style="margin:8px 0; color:#000; font-size:16px;"><b>套餐:</b> {html.escape(plan_label)}</p>
    <p style="margin:8px 0; color:#000; font-size:16px;"><b>当前积分:</b> <span style="color:#e74c3c; font-size:22px; font-weight:bold;">{html.escape(points_label)}</span> <span style="color:#27ae60; font-weight:bold;">{html.escape(change_label)}</span></p>
    <p style="margin:8px 0; color:#000; font-size:16px;"><b>连签:</b> {html.escape(streak_label)}</p>
    <p style="margin:8px 0; color:#000; font-size:16px;"><b>剩余天数:</b> <span style="font-weight:bold;">{html.escape(days_label)}</span></p>{earned_line}
    <p style="margin:8px 0; color:#000; font-size:16px;"><b>签到结果:</b> {html.escape(str(msg))}</p>{exchange_line}
    <div style="margin-top:15px; padding:12px; background:#f0f0f0; border-radius:8px; border:1px solid #ccc;">
        <p style="margin:0 0 8px 0; color:#333; font-weight:bold; font-size:15px;">🎁 兑换选项:</p>
        <p style="margin:0; color:#000; font-size:14px; line-height:1.8;">
{g.exchange_info}</p>
    </div>
</div>
""")

    # Push
    push_level = os.environ.get("PUSH_LEVEL", "fail_only").lower()

    # Exchange outcomes (success or failure) are worth notifying even when
    # PUSH_LEVEL=fail_only, otherwise an always-failing exchange stays silent.
    if push_level == "fail_only" and success_cnt == len(cookies) and exchange_events == 0:
        log("⏭️ 根据 PUSH_LEVEL=fail_only 设置，所有账号签到成功，跳过推送")
        return 0

    ptoken = os.environ.get("PUSHPLUS_TOKEN")
    serverchan_sendkey = os.environ.get("SERVERCHAN_SENDKEY", "").strip()
    tg_token = os.environ.get("TELEGRAM_BOT_TOKEN")
    tg_chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    
    if ptoken or serverchan_sendkey or (tg_token and tg_chat_id):
        outcome = '本次运行成功' if success_cnt == len(cookies) else '本次运行失败'
        title = f"GLaDOS签到: {outcome} {success_cnt}/{len(cookies)}"
        content = "".join(results)
        if success_cnt < len(cookies):
            content += '<p>以上仅反映本次运行。失败账号的今日签到状态未知，请结合当天其他成功运行或官网签到日历核对。</p>'
        content += f"<br><small>时间（北京时间 UTC+8）: {beijing_time()}</small>"
        
        if ptoken:
            pushplus(ptoken, title, content)
        if serverchan_sendkey:
            serverchan_push(serverchan_sendkey, title, content)
        if tg_token and tg_chat_id:
            telegram_push(tg_token, tg_chat_id, title, content)

    return 0 if success_cnt == len(cookies) else 1

if __name__ == '__main__':
    sys.exit(main())
