#!/usr/bin/env python3

import asyncio
import socket
import urllib.parse
import urllib.request
import collections
import time
import datetime
import hmac
import base64
import hashlib
import random
import binascii
import sys
import re
import runpy
import signal
import os
import stat
import traceback
import sqlite3
from typing import Any, Dict
import secrets
import json


from dotenv import load_dotenv

load_dotenv()

try:
    from utils.email_sender import EmailSender
    from utils.telegram_bot import TelegramBotApi, parse_start_payload, backoff_sleep
except Exception:  # pragma: no cover
    EmailSender = None
    TelegramBotApi = None
    parse_start_payload = None
    backoff_sleep = None

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field


TG_DATACENTER_PORT = 443

ERROR_UNKNOWN_PLAN = "unknown plan"

SECONDS_IN_HOUR = 3600
HOURS_IN_DAY = 24
DAYS_IN_WEEK = 7
DAYS_IN_MONTH = 30
DAYS_IN_YEAR = 365

TG_DATACENTERS_V4 = [
    "149.154.175.50", "149.154.167.51", "149.154.175.100",
    "149.154.167.91", "149.154.171.5"
]

TG_DATACENTERS_V6 = [
    "2001:b28:f23d:f001::a", "2001:67c:04e8:f002::a", "2001:b28:f23d:f003::a",
    "2001:67c:04e8:f004::a", "2001:b28:f23f:f005::a"
]

# This list will be updated in the runtime
TG_MIDDLE_PROXIES_V4 = {
    1: [("149.154.175.50", 8888)], -1: [("149.154.175.50", 8888)],
    2: [("149.154.161.144", 8888)], -2: [("149.154.161.144", 8888)],
    3: [("149.154.175.100", 8888)], -3: [("149.154.175.100", 8888)],
    4: [("91.108.4.136", 8888)], -4: [("149.154.165.109", 8888)],
    5: [("91.108.56.183", 8888)], -5: [("91.108.56.183", 8888)]
}

TG_MIDDLE_PROXIES_V6 = {
    1: [("2001:b28:f23d:f001::d", 8888)], -1: [("2001:b28:f23d:f001::d", 8888)],
    2: [("2001:67c:04e8:f002::d", 80)], -2: [("2001:67c:04e8:f002::d", 80)],
    3: [("2001:b28:f23d:f003::d", 8888)], -3: [("2001:b28:f23d:f003::d", 8888)],
    4: [("2001:67c:04e8:f004::d", 8888)], -4: [("2001:67c:04e8:f004::d", 8888)],
    5: [("2001:b28:f23f:f005::d", 8888)], -5: [("2001:b28:f23f:f005::d", 8888)]
}

PROXY_SECRET = bytes.fromhex(
    "c4f9faca9678e6bb48ad6c7e2ce5c0d24430645d554addeb55419e034da62721" +
    "d046eaab6e52ab14a95a443ecfb3463e79a05a66612adf9caeda8be9a80da698" +
    "6fb0a6ff387af84d88ef3a6413713e5c3377f6e1a3d47d99f5e0c56eece8f05c" +
    "54c490b079e31bef82ff0ee8f2b0a32756d249c5f21269816cb7061b265db212"
)

TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "").strip()
TG_BOT_USERNAME = os.environ.get("TG_BOT_USERNAME", "").strip()
TG_BOT_POLL = os.environ.get("TG_BOT_POLL", "").strip().lower() in ("1", "true", "yes", "on")

SKIP_LEN = 8
PREKEY_LEN = 32
KEY_LEN = 32
IV_LEN = 16
HANDSHAKE_LEN = 64
PROTO_TAG_POS = 56
DC_IDX_POS = 60

MIN_CERT_LEN = 1024

PROTO_TAG_ABRIDGED = b"\xef\xef\xef\xef"
PROTO_TAG_INTERMEDIATE = b"\xee\xee\xee\xee"
PROTO_TAG_SECURE = b"\xdd\xdd\xdd\xdd"

CBC_PADDING = 16
PADDING_FILLER = b"\x04\x00\x00\x00"

MIN_MSG_LEN = 12
MAX_MSG_LEN = 2 ** 24

STAT_DURATION_BUCKETS = [0.1, 0.5, 1, 2, 5, 15, 60, 300, 600, 1800, 2**31 - 1]

my_ip_info = {"ipv4": None, "ipv6": None}
used_handshakes = collections.OrderedDict()
client_ips = collections.OrderedDict()
last_client_ips = {}
disable_middle_proxy = False
is_time_skewed = False
fake_cert_len = random.randrange(1024, 4096)
mask_host_cached_ip = None
last_clients_with_time_skew = {}
last_clients_with_same_handshake = collections.Counter()
proxy_start_time = 0
proxy_links = []

stats = collections.Counter()
user_stats = collections.defaultdict(collections.Counter)

config = {}
config_source = os.environ.get("CONFIG_SOURCE", "db")

CONFIG_DB_PATH = os.environ.get("CONFIG_DB", "./config.db")
API_LISTEN_HOST = os.environ.get("API_HOST", "127.0.0.1")
API_LISTEN_PORT = int(os.environ.get("API_PORT", "8080"))

CLIENT_PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").strip()
CLIENT_DEV_ISSUE_LINKS = os.environ.get("DEV_ISSUE_LINKS", "").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)

YOOKASSA_SHOP_ID = os.environ.get("YOOKASSA_SHOP_ID", "").strip()
YOOKASSA_SECRET_KEY = os.environ.get("YOOKASSA_SECRET_KEY", "").strip()
YOOKASSA_API_BASE = "https://api.yookassa.ru/v3"
YOOKASSA_CURRENCY = "RUB"

QUIET = os.environ.get("QUIET", "").strip().lower() in ("1", "true", "yes", "on")

STATS_SAMPLE_PERIOD = int(os.environ.get("STATS_SAMPLE_PERIOD", "10"))
STATS_RETENTION_HOURS = int(os.environ.get("STATS_RETENTION_HOURS", "168"))

ADMIN_USER_ENV = os.environ.get("ADMIN_USER")
ADMIN_PASS_ENV = os.environ.get("ADMIN_PASS")

_config_db_inited = False
_proxy_listen_port_at_start: int = 0
_api_server = None


def _connect_config_db() -> sqlite3.Connection:
    conn = sqlite3.connect(CONFIG_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_config_db() -> None:
    global _config_db_inited
    if _config_db_inited:
        return

    with _connect_config_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS kv (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS client_tg_link_tokens (
                token_hash TEXT PRIMARY KEY,
                client_id INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                name TEXT PRIMARY KEY,
                secret TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT,
                tg_username TEXT,
                tg_chat_id TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_email ON clients(email)")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_tg_username ON clients(tg_username)")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS client_sessions (
                token_hash TEXT PRIMARY KEY,
                client_id INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS client_login_tokens (
                token_hash TEXT PRIMARY KEY,
                client_id INTEGER NOT NULL,
                channel TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS client_login_tg_messages (
                token_hash TEXT PRIMARY KEY,
                chat_id TEXT NOT NULL,
                message_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS proxy_subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER NOT NULL,
                account_id INTEGER,
                plan TEXT NOT NULL,
                status TEXT NOT NULL,
                starts_at INTEGER,
                ends_at INTEGER,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_proxy_subscriptions_client ON proxy_subscriptions(client_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_proxy_subscriptions_account ON proxy_subscriptions(account_id)")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS yookassa_payments (
                payment_id TEXT PRIMARY KEY,
                subscription_id INTEGER NOT NULL,
                client_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                amount TEXT NOT NULL,
                currency TEXT NOT NULL,
                idempotence_key TEXT NOT NULL,
                processed INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_yookassa_payments_sub ON yookassa_payments(subscription_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_yookassa_payments_client ON yookassa_payments(client_id)")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS client_proxy_accounts2 (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER NOT NULL,
                proxy_user TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_client_proxy_accounts2_client ON client_proxy_accounts2(client_id)")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                token_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS stats_samples (
                ts INTEGER PRIMARY KEY,
                uptime INTEGER NOT NULL,
                connects_all INTEGER NOT NULL,
                connects_bad INTEGER NOT NULL,
                handshake_timeouts INTEGER NOT NULL,
                curr_connects INTEGER NOT NULL,
                octets_total INTEGER NOT NULL,
                msgs_total INTEGER NOT NULL
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS user_stats_samples (
                ts INTEGER NOT NULL,
                user TEXT NOT NULL,
                connects INTEGER NOT NULL,
                curr_connects INTEGER NOT NULL,
                octets_total INTEGER NOT NULL,
                msgs_total INTEGER NOT NULL,
                PRIMARY KEY (ts, user)
            )
            """
        )

        now = int(time.time())
        defaults = [
            ("port", "443"),
            ("tls_domain", "yandex.ru"),
            ("ad_tag", ""),
            ("modes_classic", "0"),
            ("modes_secure", "1"),
            ("modes_tls", "1"),
            ("user_max_tcp_conns_default", "5"),
            ("admin_user", "admin"),
            ("yookassa_price_week", "100.00"),
            ("yookassa_price_month", "250.00"),
            ("yookassa_price_year", "2000.00"),
        ]
        for key, default in defaults:
            conn.execute(
                "INSERT OR IGNORE INTO kv(key, value, updated_at) VALUES(?, ?, ?)",
                (key, default, now),
            )

        # Admin credentials
        row_user = conn.execute("SELECT value FROM kv WHERE key = ?", ("admin_user",)).fetchone()
        row_hash = conn.execute("SELECT value FROM kv WHERE key = ?", ("admin_pass_hash",)).fetchone()
        if ADMIN_USER_ENV:
            conn.execute(
                "INSERT INTO kv(key, value, updated_at) VALUES(?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                ("admin_user", ADMIN_USER_ENV, now),
            )
        if ADMIN_PASS_ENV:
            pass_hash = _hash_password(ADMIN_PASS_ENV)
            conn.execute(
                "INSERT INTO kv(key, value, updated_at) VALUES(?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                ("admin_pass_hash", pass_hash, now),
            )
        elif not row_hash:
            generated = secrets.token_urlsafe(12)
            pass_hash = _hash_password(generated)
            conn.execute(
                "INSERT INTO kv(key, value, updated_at) VALUES(?, ?, ?)",
                ("admin_pass_hash", pass_hash, now),
            )
            print_err("Generated admin password (set ADMIN_PASS to override): %s" % generated)

        # ensure at least one user exists
        has_user = conn.execute("SELECT 1 FROM users LIMIT 1").fetchone()
        if not has_user:
            conn.execute(
                "INSERT OR IGNORE INTO users(name, secret, updated_at) VALUES(?, ?, ?)",
                ("tg", "00000000000000000000000000000000", now),
            )
        conn.commit()

    _config_db_inited = True


def _stats_snapshot_now(ts: int) -> tuple[dict, list[dict]]:
    global stats
    global user_stats
    global proxy_start_time

    total_octets = 0
    total_msgs = 0
    total_curr = 0
    users_out: list[dict] = []
    for user, s in user_stats.items():
        octets = int(s.get("octets_from_client", 0)) + int(s.get("octets_to_client", 0))
        msgs = int(s.get("msgs_from_client", 0)) + int(s.get("msgs_to_client", 0))
        curr = int(s.get("curr_connects", 0))
        total_octets += octets
        total_msgs += msgs
        total_curr += curr
        users_out.append(
            {
                "user": user,
                "connects": int(s.get("connects", 0)),
                "curr_connects": curr,
                "octets_total": octets,
                "msgs_total": msgs,
            }
        )

    users_out.sort(key=lambda r: (r["octets_total"], r["connects"]), reverse=True)

    agg = {
        "ts": ts,
        "uptime": int(max(0, time.time() - proxy_start_time)),
        "connects_all": int(stats.get("connects_all", 0)),
        "connects_bad": int(stats.get("connects_bad", 0)),
        "handshake_timeouts": int(stats.get("handshake_timeouts", 0)),
        "curr_connects": total_curr,
        "octets_total": total_octets,
        "msgs_total": total_msgs,
    }
    return agg, users_out


async def stats_sampler():
    global proxy_start_time

    _init_config_db()
    cleanup_every = max(1, int(60 / max(1, STATS_SAMPLE_PERIOD)))
    i = 0

    while True:
        await asyncio.sleep(max(1, STATS_SAMPLE_PERIOD))
        ts = int(time.time())
        agg, users_out = _stats_snapshot_now(ts)

        try:
            with _connect_config_db() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO stats_samples(ts, uptime, connects_all, connects_bad, handshake_timeouts, curr_connects, octets_total, msgs_total) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        agg["ts"],
                        agg["uptime"],
                        agg["connects_all"],
                        agg["connects_bad"],
                        agg["handshake_timeouts"],
                        agg["curr_connects"],
                        agg["octets_total"],
                        agg["msgs_total"],
                    ),
                )
                for u in users_out:
                    conn.execute(
                        "INSERT OR REPLACE INTO user_stats_samples(ts, user, connects, curr_connects, octets_total, msgs_total) VALUES(?, ?, ?, ?, ?, ?)",
                        (
                            ts,
                            u["user"],
                            u["connects"],
                            u["curr_connects"],
                            u["octets_total"],
                            u["msgs_total"],
                        ),
                    )

                if i % cleanup_every == 0 and STATS_RETENTION_HOURS > 0:
                    cutoff = ts - STATS_RETENTION_HOURS * 3600
                    conn.execute("DELETE FROM user_stats_samples WHERE ts < ?", (cutoff,))
                    conn.execute("DELETE FROM stats_samples WHERE ts < ?", (cutoff,))

                conn.commit()
        except Exception:
            pass


async def telegram_bot_poller():
    if not TG_BOT_TOKEN or TelegramBotApi is None:
        return
    bot = TelegramBotApi(TG_BOT_TOKEN)
    offset = None
    backoff = 1.0

    def _bot_base_url() -> str:
        if CLIENT_PUBLIC_BASE_URL:
            return CLIENT_PUBLIC_BASE_URL.rstrip("/")
        return f"http://{API_LISTEN_HOST}:{API_LISTEN_PORT}"

    def _issue_login_token_db(conn: sqlite3.Connection, client_id: int) -> str:
        token = secrets.token_urlsafe(32)
        token_hash = _hash_token(token)
        now = _now_ts()
        exp = now + 15 * 60
        conn.execute(
            "INSERT OR REPLACE INTO client_login_tokens(token_hash, client_id, channel, expires_at, created_at) VALUES(?, ?, ?, ?, ?)",
            (token_hash, int(client_id), "telegram", exp, now),
        )
        return token

    def _reply_markup_new_link(client_id: int) -> dict:
        return {
            "inline_keyboard": [
                [
                    {
                        "text": "Получить новую ссылку для входа",
                        "callback_data": f"new_login:{int(client_id)}",
                    }
                ]
            ]
        }

    def _send_login_link_and_track(chat_id: str, client_id: int) -> None:
        _init_config_db()
        with _connect_config_db() as conn:
            token = _issue_login_token_db(conn, client_id)
            link = f"{_bot_base_url()}/client/auth/confirm?token={urllib.parse.quote(token)}"
            msg_id = bot.send_message(
                chat_id,
                f"Ссылка для входа (одноразовая):\n{link}",
                reply_markup=_reply_markup_new_link(client_id),
            )
            if msg_id:
                conn.execute(
                    "INSERT OR REPLACE INTO client_login_tg_messages(token_hash, chat_id, message_id, created_at) VALUES(?, ?, ?, ?)",
                    (_hash_token(token), str(chat_id), int(msg_id), _now_ts()),
                )
            conn.commit()

    async def _to_thread(func, *args, **kwargs):
        return await asyncio.to_thread(func, *args, **kwargs)

    while True:
        try:
            updates = await _to_thread(bot.get_updates, offset=offset, timeout=25)
            if updates:
                backoff = 1.0
            for u in updates:
                try:
                    upd_id = int(u.get("update_id"))
                    offset = upd_id + 1
                    if u.get("message"):
                        msg = u.get("message") or {}
                        text = msg.get("text") or ""
                        payload = parse_start_payload(text) if parse_start_payload else ""
                        if not payload:
                            continue
                        chat = msg.get("chat") or {}
                        chat_id = str(chat.get("id") or "")
                        if not chat_id:
                            continue
                        token_hash = _hash_token(payload)
                        now = _now_ts()
                        _init_config_db()
                        with _connect_config_db() as conn:
                            row = conn.execute(
                                "SELECT client_id, expires_at FROM client_tg_link_tokens WHERE token_hash = ?",
                                (token_hash,),
                            ).fetchone()
                            if not row:
                                continue
                            if int(row["expires_at"]) <= now:
                                conn.execute("DELETE FROM client_tg_link_tokens WHERE token_hash = ?", (token_hash,))
                                conn.commit()
                                continue
                            client_id = int(row["client_id"])
                            conn.execute("DELETE FROM client_tg_link_tokens WHERE token_hash = ?", (token_hash,))
                            conn.execute(
                                "UPDATE clients SET tg_chat_id = ?, updated_at = ? WHERE id = ?",
                                (chat_id, now, client_id),
                            )
                            conn.commit()
                            try:
                                await _to_thread(
                                    bot.send_message,
                                    chat_id,
                                    "Telegram привязан. Сейчас пришлю ссылку для входа.",
                                    True,
                                    _tg_reply_markup_new_login(client_id),
                                )
                            except Exception:
                                pass
                            try:
                                await _to_thread(_send_login_link_and_track, chat_id, client_id)
                            except Exception:
                                pass

                    if u.get("callback_query"):
                        cq = u.get("callback_query") or {}
                        cq_id = str(cq.get("id") or "")
                        data = str(cq.get("data") or "")
                        msg = cq.get("message") or {}
                        chat = msg.get("chat") or {}
                        chat_id = str(chat.get("id") or "")
                        if not cq_id or not chat_id or not data:
                            continue
                        if data.startswith("new_login:"):
                            try:
                                client_id = int(data.split(":", 1)[1])
                            except Exception:
                                client_id = 0
                            if client_id <= 0:
                                continue
                            _init_config_db()
                            with _connect_config_db() as conn:
                                row = conn.execute(
                                    "SELECT COALESCE(tg_chat_id, '') AS tg_chat_id FROM clients WHERE id = ?",
                                    (int(client_id),),
                                ).fetchone()
                                if not row or str(row["tg_chat_id"]) != str(chat_id):
                                    try:
                                        await _to_thread(bot.answer_callback_query, cq_id, "Недоступно")
                                    except Exception:
                                        pass
                                    continue
                                try:
                                    await _to_thread(_send_login_link_and_track, chat_id, client_id)
                                    await _to_thread(bot.answer_callback_query, cq_id, "Отправил")
                                except Exception:
                                    try:
                                        await _to_thread(bot.answer_callback_query, cq_id, "Ошибка")
                                    except Exception:
                                        pass
                except Exception:
                    continue
        except Exception:
            await asyncio.sleep(backoff)
            backoff = min(30.0, backoff * 2.0)


async def client_subscription_watcher():
    while True:
        await asyncio.sleep(60)
        try:
            _init_config_db()
            now = _now_ts()
            with _connect_config_db() as conn:
                rows = conn.execute(
                    "SELECT id, client_id, account_id FROM proxy_subscriptions WHERE status = 'active' AND ends_at IS NOT NULL AND ends_at <= ?",
                    (now,),
                ).fetchall()
                for r in rows:
                    sub_id = int(r["id"])
                    account_id = int(r["account_id"]) if r["account_id"] is not None else 0
                    conn.execute(
                        "UPDATE proxy_subscriptions SET status = 'expired', updated_at = ? WHERE id = ?",
                        (now, sub_id),
                    )

                    if account_id > 0:
                        row_acc = conn.execute(
                            "SELECT proxy_user FROM client_proxy_accounts2 WHERE id = ?",
                            (account_id,),
                        ).fetchone()
                        if row_acc:
                            conn.execute("DELETE FROM users WHERE name = ?", (str(row_acc["proxy_user"]),))
                        conn.execute("DELETE FROM client_proxy_accounts2 WHERE id = ?", (account_id,))

                if rows:
                    conn.commit()

            if rows:
                reload_config_internal()
                _ensure_port_is_static()
        except Exception:
            pass


def _hash_password(password: str, iterations: int = 200_000) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256$%d$%s$%s" % (
        iterations,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(dk).decode("ascii"),
    )


def _verify_password(password: str, encoded: str) -> bool:
    try:
        algo, iter_s, salt_b64, hash_b64 = encoded.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iter_s)
        salt = base64.b64decode(salt_b64.encode("ascii"))
        expected = base64.b64decode(hash_b64.encode("ascii"))
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def _issue_token(conn: sqlite3.Connection, ttl_seconds: int = 24 * 60 * 60) -> str:
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    exp = now + ttl_seconds
    _set_kv(conn, "api_token", token)
    _set_kv(conn, "api_token_exp", str(exp))
    conn.commit()
    return token


def _get_active_token(conn: sqlite3.Connection) -> str:
    try:
        token = _get_kv(conn, "api_token")
        exp_s = _get_kv(conn, "api_token_exp")
        exp = int(exp_s)
        if int(time.time()) >= exp:
            return ""
        return token
    except Exception:
        return ""


def _client_issue_tg_link_token(conn: sqlite3.Connection, client_id: int) -> str:
    token = secrets.token_urlsafe(16)
    token_hash = _hash_token(token)
    now = _now_ts()
    exp = now + 30 * 60
    conn.execute(
        "INSERT OR REPLACE INTO client_tg_link_tokens(token_hash, client_id, expires_at, created_at) VALUES(?, ?, ?, ?)",
        (token_hash, client_id, exp, now),
    )
    return token


def _get_email_sender() -> Any:
    if EmailSender is None:
        return None
    try:
        return EmailSender.from_env()
    except Exception:
        return None


def _get_tg_bot() -> Any:
    if not TG_BOT_TOKEN or TelegramBotApi is None:
        return None
    try:
        return TelegramBotApi(TG_BOT_TOKEN)
    except Exception:
        return None


def _format_proxy_message(links: list[dict]) -> str:
    if not links:
        return ""
    lines = ["Твой прокси:"]
    for l in links:
        mode = l.get("mode")
        link = l.get("link")
        if mode and link:
            lines.append(f"{mode}: {link}")
    return "\n".join(lines)


def _tg_reply_markup_new_login(client_id: int) -> dict:
    return {
        "inline_keyboard": [
            [
                {
                    "text": "Получить новую ссылку для входа",
                    "callback_data": f"new_login:{int(client_id)}",
                }
            ]
        ]
    }


def _client_notify_login_link(conn: sqlite3.Connection, client_id: int, link: str) -> dict:
    info = {"email": "", "telegram": ""}
    row = conn.execute(
        "SELECT COALESCE(email, '') AS email, COALESCE(tg_chat_id, '') AS tg_chat_id FROM clients WHERE id = ?",
        (client_id,),
    ).fetchone()
    if not row:
        return info

    email = str(row["email"])
    tg_chat_id = str(row["tg_chat_id"])
    if email:
        sender = _get_email_sender()
        if sender and link:
            try:
                sender.send_text(email, "Вход в прокси", f"Ссылка для входа:\n{link}\n")
                info["email"] = "sent"
            except Exception:
                info["email"] = "failed"
    if tg_chat_id:
        bot = _get_tg_bot()
        if bot and link:
            try:
                msg_id = bot.send_message(
                    tg_chat_id,
                    f"Ссылка для входа (одноразовая):\n{link}",
                    reply_markup=_tg_reply_markup_new_login(client_id),
                )
                if msg_id:
                    try:
                        token_hash = _hash_token(urllib.parse.parse_qs(urllib.parse.urlparse(link).query).get("token", [""])[0])
                    except Exception:
                        token_hash = ""
                    if token_hash:
                        conn.execute(
                            "INSERT OR REPLACE INTO client_login_tg_messages(token_hash, chat_id, message_id, created_at) VALUES(?, ?, ?, ?)",
                            (token_hash, str(tg_chat_id), int(msg_id), _now_ts()),
                        )
                info["telegram"] = "sent"
            except Exception:
                info["telegram"] = "failed"
    return info


def _client_notify_proxy(conn: sqlite3.Connection, client_id: int, links: list[dict]) -> dict:
    info = {"email": "", "telegram": ""}
    text = _format_proxy_message(links)
    if not text:
        return info
    row = conn.execute(
        "SELECT COALESCE(email, '') AS email, COALESCE(tg_chat_id, '') AS tg_chat_id FROM clients WHERE id = ?",
        (client_id,),
    ).fetchone()
    if not row:
        return info
    email = str(row["email"])
    tg_chat_id = str(row["tg_chat_id"])
    if email:
        sender = _get_email_sender()
        if sender:
            try:
                sender.send_text(email, "Данные прокси", text)
                info["email"] = "sent"
            except Exception:
                info["email"] = "failed"
    if tg_chat_id:
        bot = _get_tg_bot()
        if bot and text:
            try:
                bot.send_message(tg_chat_id, text, reply_markup=_tg_reply_markup_new_login(client_id))
                info["telegram"] = "sent"
            except Exception:
                info["telegram"] = "failed"
    return info


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _now_ts() -> int:
    return int(time.time())


def _get_client_base_url(request: "Request") -> str:
    if CLIENT_PUBLIC_BASE_URL:
        return CLIENT_PUBLIC_BASE_URL.rstrip("/")
    try:
        return str(request.base_url).rstrip("/")
    except Exception:
        return ""


def _random_secret_hex32() -> str:
    return secrets.token_hex(16)


def _sanitize_email(email: str) -> str:
    return (email or "").strip().lower()


def _sanitize_tg_username(username: str) -> str:
    u = (username or "").strip()
    if u.startswith("@"):  # user may input @name
        u = u[1:]
    return u.lower()


def _tg_username_clean(u: str) -> str:
    s = (u or "").strip()
    if s.startswith("@"): 
        s = s[1:]
    return s


def _tg_start_link(token: str) -> str:
    bot = _tg_username_clean(TG_BOT_USERNAME)
    if not bot:
        return ""
    return f"https://t.me/{bot}?start={urllib.parse.quote(str(token))}"


def _format_token_prefix(token_hash: str) -> str:
    return token_hash[:12]


def _is_valid_api_key(conn: sqlite3.Connection, token: str) -> bool:
    token_hash = _hash_token(token)
    row = conn.execute(
        "SELECT 1 FROM api_keys WHERE token_hash = ? AND revoked = 0",
        (token_hash,),
    ).fetchone()
    return bool(row)


def _get_kv(conn: sqlite3.Connection, key: str) -> str:
    row = conn.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
    if not row:
        raise KeyError(key)
    return str(row["value"])


def _set_kv(conn: sqlite3.Connection, key: str, value: str) -> None:
    now = int(time.time())
    conn.execute(
        "INSERT INTO kv(key, value, updated_at) VALUES(?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (key, value, now),
    )


def _load_conf_dict_from_db() -> Dict[str, Any]:
    _init_config_db()
    with _connect_config_db() as conn:
        conf_dict: Dict[str, Any] = {}
        conf_dict["PORT"] = int(_get_kv(conn, "port"))
        conf_dict["TLS_DOMAIN"] = _get_kv(conn, "tls_domain")
        conf_dict["AD_TAG"] = _get_kv(conn, "ad_tag")
        try:
            default_max_tcp = int(_get_kv(conn, "user_max_tcp_conns_default"))
        except Exception:
            default_max_tcp = 0
        conf_dict["MODES"] = {
            "classic": _get_kv(conn, "modes_classic") not in ("0", "false", "False", ""),
            "secure": _get_kv(conn, "modes_secure") not in ("0", "false", "False", ""),
            "tls": _get_kv(conn, "modes_tls") not in ("0", "false", "False", ""),
        }

        rows = conn.execute("SELECT name, secret FROM users ORDER BY name").fetchall()
        conf_dict["USERS"] = {str(r["name"]): str(r["secret"]) for r in rows}

        # Default per-user concurrent TCP connections limit.
        # If set (>0), apply same limit to all users.
        if default_max_tcp and default_max_tcp > 0:
            conf_dict["USER_MAX_TCP_CONNS"] = {u: int(default_max_tcp) for u in conf_dict["USERS"].keys()}

    return conf_dict


def init_config():
    global config
    # we use conf_dict to protect the original config from exceptions when reloading
    if len(sys.argv) < 2:
        if config_source == "db":
            conf_dict = _load_conf_dict_from_db()
        else:
            conf_dict = runpy.run_module("config")
    elif len(sys.argv) == 2:
        # launch with own config
        conf_dict = runpy.run_path(sys.argv[1])
    else:
        # undocumented way of launching
        conf_dict = {}
        conf_dict["PORT"] = int(sys.argv[1])
        secrets = sys.argv[2].split(",")
        conf_dict["USERS"] = {"user%d" % i: secrets[i].zfill(32) for i in range(len(secrets))}
        conf_dict["MODES"] = {"classic": False, "secure": True, "tls": True}
        if len(sys.argv) > 3:
            conf_dict["AD_TAG"] = sys.argv[3]
        if len(sys.argv) > 4:
            conf_dict["TLS_DOMAIN"] = sys.argv[4]
            conf_dict["MODES"] = {"classic": False, "secure": False, "tls": True}

    conf_dict = {k: v for k, v in conf_dict.items() if k.isupper()}

    conf_dict.setdefault("PORT", 3256)
    conf_dict.setdefault("USERS", {"tg":  "00000000000000000000000000000000"})
    conf_dict["AD_TAG"] = bytes.fromhex(conf_dict.get("AD_TAG", ""))

    for user, secret in conf_dict["USERS"].items():
        if not re.fullmatch("[0-9a-fA-F]{32}", secret):
            fixed_secret = re.sub(r"[^0-9a-fA-F]", "", secret).zfill(32)[:32]

            print_err("Bad secret for user %s, should be 32 hex chars, got %s. " % (user, secret))
            print_err("Changing it to %s" % fixed_secret)

            conf_dict["USERS"][user] = fixed_secret

    # load advanced settings

    # use middle proxy, necessary to show ad
    conf_dict.setdefault("USE_MIDDLE_PROXY", len(conf_dict["AD_TAG"]) == 16)

    # if IPv6 avaliable, use it by default
    conf_dict.setdefault("PREFER_IPV6", socket.has_ipv6)

    # disables tg->client trafic reencryption, faster but less secure
    conf_dict.setdefault("FAST_MODE", True)

    # enables some working modes
    modes = conf_dict.get("MODES", {})

    if "MODES" not in conf_dict:
        modes.setdefault("classic", True)
        modes.setdefault("secure", True)
        modes.setdefault("tls", True)
    else:
        modes.setdefault("classic", False)
        modes.setdefault("secure", False)
        modes.setdefault("tls", False)

    legacy_warning = False
    if "SECURE_ONLY" in conf_dict:
        legacy_warning = True
        modes["classic"] = not bool(conf_dict["SECURE_ONLY"])

    if "TLS_ONLY" in conf_dict:
        legacy_warning = True
        if conf_dict["TLS_ONLY"]:
            modes["classic"] = False
            modes["secure"] = False

    if not modes["classic"] and not modes["secure"] and not modes["tls"]:
        print_err("No known modes enabled, enabling tls-only mode")
        modes["tls"] = True

    if legacy_warning:
        print_err("Legacy options SECURE_ONLY or TLS_ONLY detected")
        print_err("Please use MODES in your config instead:")
        print_err("MODES = {")
        print_err('    "classic": %s,' % modes["classic"])
        print_err('    "secure": %s,' % modes["secure"])
        print_err('    "tls": %s' % modes["tls"])
        print_err("}")

    conf_dict["MODES"] = modes

    # accept incoming connections only with proxy protocol v1/v2, useful for nginx and haproxy
    conf_dict.setdefault("PROXY_PROTOCOL", False)

    # set the tls domain for the proxy, has an influence only on starting message
    conf_dict.setdefault("TLS_DOMAIN", "www.google.com")

    # enable proxying bad clients to some host
    conf_dict.setdefault("MASK", True)

    # the next host to forward bad clients
    conf_dict.setdefault("MASK_HOST", conf_dict["TLS_DOMAIN"])

    # set the home domain for the proxy, has an influence only on the log message
    conf_dict.setdefault("MY_DOMAIN", False)

    # the next host's port to forward bad clients
    conf_dict.setdefault("MASK_PORT", 443)

    # use upstream SOCKS5 proxy
    conf_dict.setdefault("SOCKS5_HOST", None)
    conf_dict.setdefault("SOCKS5_PORT", None)
    conf_dict.setdefault("SOCKS5_USER", None)
    conf_dict.setdefault("SOCKS5_PASS", None)

    if conf_dict["SOCKS5_HOST"] and conf_dict["SOCKS5_PORT"]:
        # Disable the middle proxy if using socks, they are not compatible
        conf_dict["USE_MIDDLE_PROXY"] = False

    # user tcp connection limits, the mapping from name to the integer limit
    # one client can create many tcp connections, up to 8
    conf_dict.setdefault("USER_MAX_TCP_CONNS", {})

    # expiration date for users in format of day/month/year
    conf_dict.setdefault("USER_EXPIRATIONS", {})
    for user in conf_dict["USER_EXPIRATIONS"]:
        expiration = datetime.datetime.strptime(conf_dict["USER_EXPIRATIONS"][user], "%d/%m/%Y")
        conf_dict["USER_EXPIRATIONS"][user] = expiration

    # the data quota for user
    conf_dict.setdefault("USER_DATA_QUOTA", {})

    # length of used handshake randoms for active fingerprinting protection, zero to disable
    conf_dict.setdefault("REPLAY_CHECK_LEN", 65536)

    # accept clients with bad clocks. This reduces the protection against replay attacks
    conf_dict.setdefault("IGNORE_TIME_SKEW", False)

    # length of last client ip addresses for logging
    conf_dict.setdefault("CLIENT_IPS_LEN", 131072)

    # delay in seconds between stats printing
    conf_dict.setdefault("STATS_PRINT_PERIOD", 600)

    # delay in seconds between middle proxy info updates
    conf_dict.setdefault("PROXY_INFO_UPDATE_PERIOD", 24*60*60)

    # delay in seconds between time getting, zero means disabled
    conf_dict.setdefault("GET_TIME_PERIOD", 10*60)

    # delay in seconds between getting the length of certificate on the mask host
    conf_dict.setdefault("GET_CERT_LEN_PERIOD", random.randrange(4*60*60, 6*60*60))

    # max socket buffer size to the client direction, the more the faster, but more RAM hungry
    # can be the tuple (low, users_margin, high) for the adaptive case. If no much users, use high
    conf_dict.setdefault("TO_CLT_BUFSIZE", (16384, 100, 131072))

    # max socket buffer size to the telegram servers direction, also can be the tuple
    conf_dict.setdefault("TO_TG_BUFSIZE", 65536)

    # keepalive period for clients in secs
    conf_dict.setdefault("CLIENT_KEEPALIVE", 10*60)

    # drop client after this timeout if the handshake fail
    conf_dict.setdefault("CLIENT_HANDSHAKE_TIMEOUT", random.randrange(5, 15))

    # if client doesn't confirm data for this number of seconds, it is dropped
    conf_dict.setdefault("CLIENT_ACK_TIMEOUT", 5*60)

    # telegram servers connect timeout in seconds
    conf_dict.setdefault("TG_CONNECT_TIMEOUT", 10)

    # listen address for IPv4
    conf_dict.setdefault("LISTEN_ADDR_IPV4", "0.0.0.0")

    # listen address for IPv6
    conf_dict.setdefault("LISTEN_ADDR_IPV6", "::")

    # listen unix socket
    conf_dict.setdefault("LISTEN_UNIX_SOCK", "")

    # prometheus exporter listen port, use some random port here
    conf_dict.setdefault("METRICS_PORT", None)

    # prometheus listen addr ipv4
    conf_dict.setdefault("METRICS_LISTEN_ADDR_IPV4", "0.0.0.0")

    # prometheus listen addr ipv6
    conf_dict.setdefault("METRICS_LISTEN_ADDR_IPV6", None)

    # prometheus scrapers whitelist
    conf_dict.setdefault("METRICS_WHITELIST", ["127.0.0.1", "::1"])

    # export proxy link to prometheus
    conf_dict.setdefault("METRICS_EXPORT_LINKS", False)

    # default prefix for metrics
    conf_dict.setdefault("METRICS_PREFIX", "mtprotoproxy_")

    # allow access to config by attributes
    config = type("config", (dict,), conf_dict)(conf_dict)


def reload_config_internal() -> None:
    init_config()
    ensure_users_in_user_stats()
    apply_upstream_proxy_settings()
    print("Config reloaded", flush=True, file=sys.stderr)
    print_tg_info()


def _ensure_port_is_static() -> None:
    global _proxy_listen_port_at_start
    if not _proxy_listen_port_at_start:
        _proxy_listen_port_at_start = int(config.PORT)
        return
    if int(config.PORT) != _proxy_listen_port_at_start:
        raise ValueError("PORT change requires proxy restart")


def apply_upstream_proxy_settings():
    # apply socks settings in place
    if config.SOCKS5_HOST and config.SOCKS5_PORT:
        import socks
        print_err("Socket-proxy mode activated, it is incompatible with advertising and uvloop")
        socks.set_default_proxy(socks.PROXY_TYPE_SOCKS5, config.SOCKS5_HOST, config.SOCKS5_PORT,
                                username=config.SOCKS5_USER, password=config.SOCKS5_PASS)
        if not hasattr(socket, "origsocket"):
            socket.origsocket = socket.socket
            socket.socket = socks.socksocket
    elif hasattr(socket, "origsocket"):
        socket.socket = socket.origsocket
        del socket.origsocket


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class CryptographyEncryptorAdapter:
    __slots__ = ('encryptor', 'decryptor')

    def __init__(self, cipher):
        self.encryptor = cipher.encryptor()
        self.decryptor = cipher.decryptor()

    def encrypt(self, data):
        return self.encryptor.update(data)

    def decrypt(self, data):
        return self.decryptor.update(data)


def create_aes_ctr(key, iv):
    iv_bytes = int.to_bytes(iv, 16, "big")
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv_bytes), default_backend())
    return CryptographyEncryptorAdapter(cipher)


def create_aes_cbc(key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    return CryptographyEncryptorAdapter(cipher)


def print_err(*params):
    print(*params, file=sys.stderr, flush=True)


def ensure_users_in_user_stats():
    global user_stats

    for user in config.USERS:
        user_stats[user].update()


def init_proxy_start_time():
    global proxy_start_time
    proxy_start_time = time.time()


def update_stats(**kw_stats):
    global stats
    stats.update(**kw_stats)


def update_user_stats(user, **kw_stats):
    global user_stats
    user_stats[user].update(**kw_stats)


def update_durations(duration):
    global stats

    for bucket in STAT_DURATION_BUCKETS:
        if duration <= bucket:
            break

    update_stats(**{"connects_with_duration_le_%s" % str(bucket): 1})


def get_curr_connects_count():
    global user_stats

    all_connects = 0
    for user, stat in user_stats.items():
        all_connects += stat["curr_connects"]
    return all_connects


def get_to_tg_bufsize():
    if isinstance(config.TO_TG_BUFSIZE, int):
        return config.TO_TG_BUFSIZE

    low, margin, high = config.TO_TG_BUFSIZE
    return high if get_curr_connects_count() < margin else low


def get_to_clt_bufsize():
    if isinstance(config.TO_CLT_BUFSIZE, int):
        return config.TO_CLT_BUFSIZE

    low, margin, high = config.TO_CLT_BUFSIZE
    return high if get_curr_connects_count() < margin else low


class MyRandom(random.Random):
    def __init__(self):
        super().__init__()
        key = bytes([random.randrange(256) for i in range(32)])
        iv = random.randrange(256**16)

        self.encryptor = create_aes_ctr(key, iv)
        self.buffer = bytearray()

    def getrandbits(self, k):
        numbytes = (k + 7) // 8
        return int.from_bytes(self.getrandbytes(numbytes), 'big') >> (numbytes * 8 - k)

    def getrandbytes(self, n):
        CHUNK_SIZE = 512

        while n > len(self.buffer):
            data = int.to_bytes(super().getrandbits(CHUNK_SIZE*8), CHUNK_SIZE, "big")
            self.buffer += self.encryptor.encrypt(data)

        result = self.buffer[:n]
        self.buffer = self.buffer[n:]
        return bytes(result)


myrandom = MyRandom()


class TgConnectionPool:
    MAX_CONNS_IN_POOL = 64

    def __init__(self):
        self.pools = {}

    async def open_tg_connection(self, host, port, init_func=None):
        task = asyncio.open_connection(host, port, limit=get_to_clt_bufsize())
        reader_tgt, writer_tgt = await asyncio.wait_for(task, timeout=config.TG_CONNECT_TIMEOUT)

        set_keepalive(writer_tgt.get_extra_info("socket"))
        set_bufsizes(writer_tgt.get_extra_info("socket"), get_to_clt_bufsize(), get_to_tg_bufsize())

        if init_func:
            return await asyncio.wait_for(init_func(host, port, reader_tgt, writer_tgt),
                                          timeout=config.TG_CONNECT_TIMEOUT)
        return reader_tgt, writer_tgt

    def register_host_port(self, host, port, init_func):
        if (host, port, init_func) not in self.pools:
            self.pools[(host, port, init_func)] = []

        while len(self.pools[(host, port, init_func)]) < TgConnectionPool.MAX_CONNS_IN_POOL:
            connect_task = asyncio.ensure_future(self.open_tg_connection(host, port, init_func))
            self.pools[(host, port, init_func)].append(connect_task)

    async def get_connection(self, host, port, init_func=None):
        self.register_host_port(host, port, init_func)

        ret = None
        for task in self.pools[(host, port, init_func)][::]:
            if task.done():
                if task.exception():
                    self.pools[(host, port, init_func)].remove(task)
                    continue

                reader, writer, *other = task.result()
                if writer.transport.is_closing():
                    self.pools[(host, port, init_func)].remove(task)
                    continue

                if not ret:
                    self.pools[(host, port, init_func)].remove(task)
                    ret = (reader, writer, *other)

        self.register_host_port(host, port, init_func)
        if ret:
            return ret
        return await self.open_tg_connection(host, port, init_func)


tg_connection_pool = TgConnectionPool()


class LayeredStreamReaderBase:
    __slots__ = ("upstream", )

    def __init__(self, upstream):
        self.upstream = upstream

    async def read(self, n):
        return await self.upstream.read(n)

    async def readexactly(self, n):
        return await self.upstream.readexactly(n)


class LayeredStreamWriterBase:
    __slots__ = ("upstream", )

    def __init__(self, upstream):
        self.upstream = upstream

    def write(self, data, extra={}):
        return self.upstream.write(data)

    def write_eof(self):
        return self.upstream.write_eof()

    async def drain(self):
        return await self.upstream.drain()

    def close(self):
        return self.upstream.close()

    def abort(self):
        return self.upstream.transport.abort()

    def get_extra_info(self, name):
        return self.upstream.get_extra_info(name)

    @property
    def transport(self):
        return self.upstream.transport


class FakeTLSStreamReader(LayeredStreamReaderBase):
    __slots__ = ('buf', )

    def __init__(self, upstream):
        self.upstream = upstream
        self.buf = bytearray()

    async def read(self, n, ignore_buf=False):
        if self.buf and not ignore_buf:
            data = self.buf
            self.buf = bytearray()
            return bytes(data)

        while True:
            tls_rec_type = await self.upstream.readexactly(1)
            if not tls_rec_type:
                return b""

            if tls_rec_type not in [b"\x14", b"\x17"]:
                print_err("BUG: bad tls type %s in FakeTLSStreamReader" % tls_rec_type)
                return b""

            version = await self.upstream.readexactly(2)
            if version != b"\x03\x03":
                print_err("BUG: unknown version %s in FakeTLSStreamReader" % version)
                return b""

            data_len = int.from_bytes(await self.upstream.readexactly(2), "big")
            data = await self.upstream.readexactly(data_len)
            if tls_rec_type == b"\x14":
                continue
            return data

    async def readexactly(self, n):
        while len(self.buf) < n:
            tls_data = await self.read(1, ignore_buf=True)
            if not tls_data:
                return b""
            self.buf += tls_data
        data, self.buf = self.buf[:n], self.buf[n:]
        return bytes(data)


class FakeTLSStreamWriter(LayeredStreamWriterBase):
    __slots__ = ()

    def __init__(self, upstream):
        self.upstream = upstream

    def write(self, data, extra={}):
        MAX_CHUNK_SIZE = 16384 + 24
        for start in range(0, len(data), MAX_CHUNK_SIZE):
            end = min(start+MAX_CHUNK_SIZE, len(data))
            self.upstream.write(b"\x17\x03\x03" + int.to_bytes(end-start, 2, "big"))
            self.upstream.write(data[start: end])
        return len(data)


class CryptoWrappedStreamReader(LayeredStreamReaderBase):
    __slots__ = ('decryptor', 'block_size', 'buf')

    def __init__(self, upstream, decryptor, block_size=1):
        self.upstream = upstream
        self.decryptor = decryptor
        self.block_size = block_size
        self.buf = bytearray()

    async def read(self, n):
        if self.buf:
            ret = bytes(self.buf)
            self.buf.clear()
            return ret
        else:
            data = await self.upstream.read(n)
            if not data:
                return b""

            needed_till_full_block = -len(data) % self.block_size
            if needed_till_full_block > 0:
                data += await self.upstream.readexactly(needed_till_full_block)
            return self.decryptor.decrypt(data)

    async def readexactly(self, n):
        if n > len(self.buf):
            to_read = n - len(self.buf)
            needed_till_full_block = -to_read % self.block_size

            to_read_block_aligned = to_read + needed_till_full_block
            data = await self.upstream.readexactly(to_read_block_aligned)
            self.buf += self.decryptor.decrypt(data)

        ret = bytes(self.buf[:n])
        self.buf = self.buf[n:]
        return ret


class CryptoWrappedStreamWriter(LayeredStreamWriterBase):
    __slots__ = ('encryptor', 'block_size')

    def __init__(self, upstream, encryptor, block_size=1):
        self.upstream = upstream
        self.encryptor = encryptor
        self.block_size = block_size

    def write(self, data, extra={}):
        if len(data) % self.block_size != 0:
            print_err("BUG: writing %d bytes not aligned to block size %d" % (
                      len(data), self.block_size))
            return 0
        q = self.encryptor.encrypt(data)
        return self.upstream.write(q)


class MTProtoFrameStreamReader(LayeredStreamReaderBase):
    __slots__ = ('seq_no', )

    def __init__(self, upstream, seq_no=0):
        self.upstream = upstream
        self.seq_no = seq_no

    async def read(self, buf_size):
        msg_len_bytes = await self.upstream.readexactly(4)
        msg_len = int.from_bytes(msg_len_bytes, "little")
        # skip paddings
        while msg_len == 4:
            msg_len_bytes = await self.upstream.readexactly(4)
            msg_len = int.from_bytes(msg_len_bytes, "little")

        len_is_bad = (msg_len % len(PADDING_FILLER) != 0)
        if not MIN_MSG_LEN <= msg_len <= MAX_MSG_LEN or len_is_bad:
            print_err("msg_len is bad, closing connection", msg_len)
            return b""

        msg_seq_bytes = await self.upstream.readexactly(4)
        msg_seq = int.from_bytes(msg_seq_bytes, "little", signed=True)
        if msg_seq != self.seq_no:
            print_err("unexpected seq_no")
            return b""

        self.seq_no += 1

        data = await self.upstream.readexactly(msg_len - 4 - 4 - 4)
        checksum_bytes = await self.upstream.readexactly(4)
        checksum = int.from_bytes(checksum_bytes, "little")

        computed_checksum = binascii.crc32(msg_len_bytes + msg_seq_bytes + data)
        if computed_checksum != checksum:
            return b""
        return data


class MTProtoFrameStreamWriter(LayeredStreamWriterBase):
    __slots__ = ('seq_no', )

    def __init__(self, upstream, seq_no=0):
        self.upstream = upstream
        self.seq_no = seq_no

    def write(self, msg, extra={}):
        len_bytes = int.to_bytes(len(msg) + 4 + 4 + 4, 4, "little")
        seq_bytes = int.to_bytes(self.seq_no, 4, "little", signed=True)
        self.seq_no += 1

        msg_without_checksum = len_bytes + seq_bytes + msg
        checksum = int.to_bytes(binascii.crc32(msg_without_checksum), 4, "little")

        full_msg = msg_without_checksum + checksum
        padding = PADDING_FILLER * ((-len(full_msg) % CBC_PADDING) // len(PADDING_FILLER))

        return self.upstream.write(full_msg + padding)


class MTProtoCompactFrameStreamReader(LayeredStreamReaderBase):
    __slots__ = ()

    async def read(self, buf_size):
        msg_len_bytes = await self.upstream.readexactly(1)
        msg_len = int.from_bytes(msg_len_bytes, "little")

        extra = {"QUICKACK_FLAG": False}
        if msg_len >= 0x80:
            extra["QUICKACK_FLAG"] = True
            msg_len -= 0x80

        if msg_len == 0x7f:
            msg_len_bytes = await self.upstream.readexactly(3)
            msg_len = int.from_bytes(msg_len_bytes, "little")

        msg_len *= 4

        data = await self.upstream.readexactly(msg_len)

        return data, extra


class MTProtoCompactFrameStreamWriter(LayeredStreamWriterBase):
    __slots__ = ()

    def write(self, data, extra={}):
        SMALL_PKT_BORDER = 0x7f
        LARGE_PKT_BORGER = 256 ** 3

        if len(data) % 4 != 0:
            print_err("BUG: MTProtoFrameStreamWriter attempted to send msg with len", len(data))
            return 0

        if extra.get("SIMPLE_ACK"):
            return self.upstream.write(data[::-1])

        len_div_four = len(data) // 4

        if len_div_four < SMALL_PKT_BORDER:
            return self.upstream.write(bytes([len_div_four]) + data)
        elif len_div_four < LARGE_PKT_BORGER:
            return self.upstream.write(b'\x7f' + int.to_bytes(len_div_four, 3, 'little') + data)
        else:
            print_err("Attempted to send too large pkt len =", len(data))
            return 0


class MTProtoIntermediateFrameStreamReader(LayeredStreamReaderBase):
    __slots__ = ()

    async def read(self, buf_size):
        msg_len_bytes = await self.upstream.readexactly(4)
        msg_len = int.from_bytes(msg_len_bytes, "little")

        extra = {}
        if msg_len > 0x80000000:
            extra["QUICKACK_FLAG"] = True
            msg_len -= 0x80000000

        data = await self.upstream.readexactly(msg_len)
        return data, extra


class MTProtoIntermediateFrameStreamWriter(LayeredStreamWriterBase):
    __slots__ = ()

    def write(self, data, extra={}):
        if extra.get("SIMPLE_ACK"):
            return self.upstream.write(data)
        else:
            return self.upstream.write(int.to_bytes(len(data), 4, 'little') + data)


class MTProtoSecureIntermediateFrameStreamReader(LayeredStreamReaderBase):
    __slots__ = ()

    async def read(self, buf_size):
        msg_len_bytes = await self.upstream.readexactly(4)
        msg_len = int.from_bytes(msg_len_bytes, "little")

        extra = {}
        if msg_len > 0x80000000:
            extra["QUICKACK_FLAG"] = True
            msg_len -= 0x80000000

        data = await self.upstream.readexactly(msg_len)

        if msg_len % 4 != 0:
            cut_border = msg_len - (msg_len % 4)
            data = data[:cut_border]

        return data, extra


class MTProtoSecureIntermediateFrameStreamWriter(LayeredStreamWriterBase):
    __slots__ = ()

    def write(self, data, extra={}):
        MAX_PADDING_LEN = 4
        if extra.get("SIMPLE_ACK"):
            # TODO: make this unpredictable
            return self.upstream.write(data)
        else:
            padding_len = myrandom.randrange(MAX_PADDING_LEN)
            padding = myrandom.getrandbytes(padding_len)
            padded_data_len_bytes = int.to_bytes(len(data) + padding_len, 4, 'little')
            return self.upstream.write(padded_data_len_bytes + data + padding)


class ProxyReqStreamReader(LayeredStreamReaderBase):
    __slots__ = ()

    async def read(self, msg):
        RPC_PROXY_ANS = b"\x0d\xda\x03\x44"
        RPC_CLOSE_EXT = b"\xa2\x34\xb6\x5e"
        RPC_SIMPLE_ACK = b"\x9b\x40\xac\x3b"
        RPC_UNKNOWN = b'\xdf\xa2\x30\x57'

        data = await self.upstream.read(1)

        if len(data) < 4:
            return b""

        ans_type = data[:4]
        if ans_type == RPC_CLOSE_EXT:
            return b""

        if ans_type == RPC_PROXY_ANS:
            ans_flags, conn_id, conn_data = data[4:8], data[8:16], data[16:]
            return conn_data

        if ans_type == RPC_SIMPLE_ACK:
            conn_id, confirm = data[4:12], data[12:16]
            return confirm, {"SIMPLE_ACK": True}

        if ans_type == RPC_UNKNOWN:
            return b"", {"SKIP_SEND": True}

        print_err("unknown rpc ans type:", ans_type)
        return b"", {"SKIP_SEND": True}


class ProxyReqStreamWriter(LayeredStreamWriterBase):
    __slots__ = ('remote_ip_port', 'our_ip_port', 'out_conn_id', 'proto_tag')

    def __init__(self, upstream, cl_ip, cl_port, my_ip, my_port, proto_tag):
        self.upstream = upstream

        if ":" not in cl_ip:
            self.remote_ip_port = b"\x00" * 10 + b"\xff\xff"
            self.remote_ip_port += socket.inet_pton(socket.AF_INET, cl_ip)
        else:
            self.remote_ip_port = socket.inet_pton(socket.AF_INET6, cl_ip)
        self.remote_ip_port += int.to_bytes(cl_port, 4, "little")

        if ":" not in my_ip:
            self.our_ip_port = b"\x00" * 10 + b"\xff\xff"
            self.our_ip_port += socket.inet_pton(socket.AF_INET, my_ip)
        else:
            self.our_ip_port = socket.inet_pton(socket.AF_INET6, my_ip)
        self.our_ip_port += int.to_bytes(my_port, 4, "little")
        self.out_conn_id = myrandom.getrandbytes(8)

        self.proto_tag = proto_tag

    def write(self, msg, extra={}):
        RPC_PROXY_REQ = b"\xee\xf1\xce\x36"
        EXTRA_SIZE = b"\x18\x00\x00\x00"
        PROXY_TAG = b"\xae\x26\x1e\xdb"
        FOUR_BYTES_ALIGNER = b"\x00\x00\x00"

        FLAG_NOT_ENCRYPTED = 0x2
        FLAG_HAS_AD_TAG = 0x8
        FLAG_MAGIC = 0x1000
        FLAG_EXTMODE2 = 0x20000
        FLAG_PAD = 0x8000000
        FLAG_INTERMEDIATE = 0x20000000
        FLAG_ABRIDGED = 0x40000000
        FLAG_QUICKACK = 0x80000000

        if len(msg) % 4 != 0:
            print_err("BUG: attempted to send msg with len %d" % len(msg))
            return 0

        flags = FLAG_HAS_AD_TAG | FLAG_MAGIC | FLAG_EXTMODE2

        if self.proto_tag == PROTO_TAG_ABRIDGED:
            flags |= FLAG_ABRIDGED
        elif self.proto_tag == PROTO_TAG_INTERMEDIATE:
            flags |= FLAG_INTERMEDIATE
        elif self.proto_tag == PROTO_TAG_SECURE:
            flags |= FLAG_INTERMEDIATE | FLAG_PAD

        if extra.get("QUICKACK_FLAG"):
            flags |= FLAG_QUICKACK

        if msg.startswith(b"\x00" * 8):
            flags |= FLAG_NOT_ENCRYPTED

        full_msg = bytearray()
        full_msg += RPC_PROXY_REQ + int.to_bytes(flags, 4, "little") + self.out_conn_id
        full_msg += self.remote_ip_port + self.our_ip_port + EXTRA_SIZE + PROXY_TAG
        full_msg += bytes([len(config.AD_TAG)]) + config.AD_TAG + FOUR_BYTES_ALIGNER
        full_msg += msg

        return self.upstream.write(full_msg)


def try_setsockopt(sock, level, option, value):
    try:
        sock.setsockopt(level, option, value)
    except OSError as E:
        pass


def set_keepalive(sock, interval=40, attempts=5):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if hasattr(socket, "TCP_KEEPIDLE"):
        try_setsockopt(sock, socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, interval)
    if hasattr(socket, "TCP_KEEPINTVL"):
        try_setsockopt(sock, socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval)
    if hasattr(socket, "TCP_KEEPCNT"):
        try_setsockopt(sock, socket.IPPROTO_TCP, socket.TCP_KEEPCNT, attempts)


def set_ack_timeout(sock, timeout):
    if hasattr(socket, "TCP_USER_TIMEOUT"):
        try_setsockopt(sock, socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, timeout*1000)


def set_bufsizes(sock, recv_buf, send_buf):
    try_setsockopt(sock, socket.SOL_SOCKET, socket.SO_RCVBUF, recv_buf)
    try_setsockopt(sock, socket.SOL_SOCKET, socket.SO_SNDBUF, send_buf)


def set_instant_rst(sock):
    INSTANT_RST = b"\x01\x00\x00\x00\x00\x00\x00\x00"
    if hasattr(socket, "SO_LINGER"):
        try_setsockopt(sock, socket.SOL_SOCKET, socket.SO_LINGER, INSTANT_RST)


def gen_x25519_public_key():
    # generates some number which has square root by modulo P
    P = 2**255 - 19
    n = myrandom.randrange(P)
    return int.to_bytes((n*n) % P, length=32, byteorder="little")


async def connect_reader_to_writer(reader, writer):
    BUF_SIZE = 8192
    try:
        while True:
            data = await reader.read(BUF_SIZE)

            if not data:
                if not writer.transport.is_closing():
                    writer.write_eof()
                    await writer.drain()
                return

            writer.write(data)
            await writer.drain()
    except (OSError, asyncio.IncompleteReadError) as e:
        pass


async def handle_bad_client(reader_clt, writer_clt, handshake):
    BUF_SIZE = 8192
    CONNECT_TIMEOUT = 5

    global mask_host_cached_ip

    update_stats(connects_bad=1)

    if writer_clt.transport.is_closing():
        return

    set_bufsizes(writer_clt.get_extra_info("socket"), BUF_SIZE, BUF_SIZE)

    if not config.MASK or handshake is None:
        while await reader_clt.read(BUF_SIZE):
            # just consume all the data
            pass
        return

    writer_srv = None
    try:
        host = mask_host_cached_ip or config.MASK_HOST
        task = asyncio.open_connection(host, config.MASK_PORT, limit=BUF_SIZE)
        reader_srv, writer_srv = await asyncio.wait_for(task, timeout=CONNECT_TIMEOUT)
        if not mask_host_cached_ip:
            mask_host_cached_ip = writer_srv.get_extra_info("peername")[0]
        writer_srv.write(handshake)
        await writer_srv.drain()

        srv_to_clt = connect_reader_to_writer(reader_srv, writer_clt)
        clt_to_srv = connect_reader_to_writer(reader_clt, writer_srv)
        task_srv_to_clt = asyncio.ensure_future(srv_to_clt)
        task_clt_to_srv = asyncio.ensure_future(clt_to_srv)

        await asyncio.wait([task_srv_to_clt, task_clt_to_srv], return_when=asyncio.FIRST_COMPLETED)

        task_srv_to_clt.cancel()
        task_clt_to_srv.cancel()

        if writer_clt.transport.is_closing():
            return

        # if the server closed the connection with RST or FIN-RST, copy them to the client
        if not writer_srv.transport.is_closing():
            # workaround for uvloop, it doesn't fire exceptions on write_eof
            sock = writer_srv.get_extra_info('socket')
            raw_sock = socket.socket(sock.family, sock.type, sock.proto, sock.fileno())
            try:
                raw_sock.shutdown(socket.SHUT_WR)
            except OSError as E:
                set_instant_rst(writer_clt.get_extra_info("socket"))
            finally:
                raw_sock.detach()
        else:
            set_instant_rst(writer_clt.get_extra_info("socket"))
    except ConnectionRefusedError as E:
        return
    except (OSError, asyncio.TimeoutError) as E:
        return
    finally:
        if writer_srv is not None:
            writer_srv.transport.abort()


async def handle_fake_tls_handshake(handshake, reader, writer, peer):
    global used_handshakes
    global client_ips
    global last_client_ips
    global last_clients_with_time_skew
    global last_clients_with_same_handshake
    global fake_cert_len

    TIME_SKEW_MIN = -20 * 60
    TIME_SKEW_MAX = 10 * 60

    TLS_VERS = b"\x03\x03"
    TLS_CIPHERSUITE = b"\x13\x01"
    TLS_CHANGE_CIPHER = b"\x14" + TLS_VERS + b"\x00\x01\x01"
    TLS_APP_HTTP2_HDR = b"\x17" + TLS_VERS

    DIGEST_LEN = 32
    DIGEST_HALFLEN = 16
    DIGEST_POS = 11

    SESSION_ID_LEN_POS = DIGEST_POS + DIGEST_LEN
    SESSION_ID_POS = SESSION_ID_LEN_POS + 1

    tls_extensions = b"\x00\x2e" + b"\x00\x33\x00\x24" + b"\x00\x1d\x00\x20"
    tls_extensions += gen_x25519_public_key() + b"\x00\x2b\x00\x02\x03\x04"

    digest = handshake[DIGEST_POS:DIGEST_POS+DIGEST_LEN]

    if digest[:DIGEST_HALFLEN] in used_handshakes:
        last_clients_with_same_handshake[peer[0]] += 1
        return False

    sess_id_len = handshake[SESSION_ID_LEN_POS]
    sess_id = handshake[SESSION_ID_POS:SESSION_ID_POS+sess_id_len]

    for user in config.USERS:
        secret = bytes.fromhex(config.USERS[user])

        msg = handshake[:DIGEST_POS] + b"\x00"*DIGEST_LEN + handshake[DIGEST_POS+DIGEST_LEN:]
        computed_digest = hmac.new(secret, msg, digestmod=hashlib.sha256).digest()

        xored_digest = bytes(digest[i] ^ computed_digest[i] for i in range(DIGEST_LEN))
        digest_good = xored_digest.startswith(b"\x00" * (DIGEST_LEN-4))

        if not digest_good:
            continue

        timestamp = int.from_bytes(xored_digest[-4:], "little")
        client_time_is_ok = TIME_SKEW_MIN < time.time() - timestamp < TIME_SKEW_MAX

        # some clients fail to read unix time and send the time since boot instead
        client_time_is_small = timestamp < 60*60*24*1000
        accept_bad_time = config.IGNORE_TIME_SKEW or is_time_skewed or client_time_is_small

        if not client_time_is_ok and not accept_bad_time:
            last_clients_with_time_skew[peer[0]] = (time.time() - timestamp) // 60
            continue

        http_data = myrandom.getrandbytes(fake_cert_len)

        srv_hello = TLS_VERS + b"\x00"*DIGEST_LEN + bytes([sess_id_len]) + sess_id
        srv_hello += TLS_CIPHERSUITE + b"\x00" + tls_extensions

        hello_pkt = b"\x16" + TLS_VERS + int.to_bytes(len(srv_hello) + 4, 2, "big")
        hello_pkt += b"\x02" + int.to_bytes(len(srv_hello), 3, "big") + srv_hello
        hello_pkt += TLS_CHANGE_CIPHER + TLS_APP_HTTP2_HDR
        hello_pkt += int.to_bytes(len(http_data), 2, "big") + http_data

        computed_digest = hmac.new(secret, msg=digest+hello_pkt, digestmod=hashlib.sha256).digest()
        hello_pkt = hello_pkt[:DIGEST_POS] + computed_digest + hello_pkt[DIGEST_POS+DIGEST_LEN:]

        writer.write(hello_pkt)
        await writer.drain()

        if config.REPLAY_CHECK_LEN > 0:
            while len(used_handshakes) >= config.REPLAY_CHECK_LEN:
                used_handshakes.popitem(last=False)
            used_handshakes[digest[:DIGEST_HALFLEN]] = True

        if config.CLIENT_IPS_LEN > 0:
            while len(client_ips) >= config.CLIENT_IPS_LEN:
                client_ips.popitem(last=False)
            if peer[0] not in client_ips:
                client_ips[peer[0]] = True
                last_client_ips[peer[0]] = True

        reader = FakeTLSStreamReader(reader)
        writer = FakeTLSStreamWriter(writer)
        return reader, writer

    return False


async def handle_proxy_protocol(reader, peer=None):
    PROXY_SIGNATURE = b"PROXY "
    PROXY_MIN_LEN = 6
    PROXY_TCP4 = b"TCP4"
    PROXY_TCP6 = b"TCP6"
    PROXY_UNKNOWN = b"UNKNOWN"

    PROXY2_SIGNATURE = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"
    PROXY2_MIN_LEN = 16
    PROXY2_AF_UNSPEC = 0x0
    PROXY2_AF_INET = 0x1
    PROXY2_AF_INET6 = 0x2

    header = await reader.readexactly(PROXY_MIN_LEN)
    if header.startswith(PROXY_SIGNATURE):
        # proxy header v1
        header += await reader.readuntil(b"\r\n")
        _, proxy_fam, *proxy_addr = header[:-2].split(b" ")
        if proxy_fam in (PROXY_TCP4, PROXY_TCP6):
            if len(proxy_addr) == 4:
                src_addr = proxy_addr[0].decode('ascii')
                src_port = int(proxy_addr[2].decode('ascii'))
                return (src_addr, src_port)
        elif proxy_fam == PROXY_UNKNOWN:
            return peer
        return False

    header += await reader.readexactly(PROXY2_MIN_LEN - PROXY_MIN_LEN)
    if header.startswith(PROXY2_SIGNATURE):
        # proxy header v2
        proxy_ver = header[12]
        if proxy_ver & 0xf0 != 0x20:
            return False
        proxy_len = int.from_bytes(header[14:16], "big")
        proxy_addr = await reader.readexactly(proxy_len)
        if proxy_ver == 0x21:
            proxy_fam = header[13] >> 4
            if proxy_fam == PROXY2_AF_INET:
                if proxy_len >= (4 + 2)*2:
                    src_addr = socket.inet_ntop(socket.AF_INET, proxy_addr[:4])
                    src_port = int.from_bytes(proxy_addr[8:10], "big")
                    return (src_addr, src_port)
            elif proxy_fam == PROXY2_AF_INET6:
                if proxy_len >= (16 + 2)*2:
                    src_addr = socket.inet_ntop(socket.AF_INET6, proxy_addr[:16])
                    src_port = int.from_bytes(proxy_addr[32:34], "big")
                    return (src_addr, src_port)
            elif proxy_fam == PROXY2_AF_UNSPEC:
                return peer
        elif proxy_ver == 0x20:
            return peer

    return False


async def handle_handshake(reader, writer):
    global used_handshakes
    global client_ips
    global last_client_ips
    global last_clients_with_same_handshake

    TLS_START_BYTES = b"\x16\x03\x01"

    if writer.transport.is_closing() or writer.get_extra_info("peername") is None:
        return False

    peer = writer.get_extra_info("peername")[:2]
    if not peer:
        peer = ("unknown ip", 0)

    if config.PROXY_PROTOCOL:
        ip = peer[0] if peer else "unknown ip"
        peer = await handle_proxy_protocol(reader, peer)
        if not peer:
            print_err("Client from %s sent bad proxy protocol headers" % ip)
            await handle_bad_client(reader, writer, None)
            return False

    is_tls_handshake = True
    handshake = b""
    for expected_byte in TLS_START_BYTES:
        handshake += await reader.readexactly(1)
        if handshake[-1] != expected_byte:
            is_tls_handshake = False
            break

    if is_tls_handshake:
        handshake += await reader.readexactly(2)
        tls_handshake_len = int.from_bytes(handshake[-2:], "big")
        if tls_handshake_len < 512:
            is_tls_handshake = False

    if is_tls_handshake:
        handshake += await reader.readexactly(tls_handshake_len)
        tls_handshake_result = await handle_fake_tls_handshake(handshake, reader, writer, peer)

        if not tls_handshake_result:
            await handle_bad_client(reader, writer, handshake)
            return False
        reader, writer = tls_handshake_result
        handshake = await reader.readexactly(HANDSHAKE_LEN)
    else:
        if not config.MODES["classic"] and not config.MODES["secure"]:
            await handle_bad_client(reader, writer, handshake)
            return False
        handshake += await reader.readexactly(HANDSHAKE_LEN - len(handshake))

    dec_prekey_and_iv = handshake[SKIP_LEN:SKIP_LEN+PREKEY_LEN+IV_LEN]
    dec_prekey, dec_iv = dec_prekey_and_iv[:PREKEY_LEN], dec_prekey_and_iv[PREKEY_LEN:]
    enc_prekey_and_iv = handshake[SKIP_LEN:SKIP_LEN+PREKEY_LEN+IV_LEN][::-1]
    enc_prekey, enc_iv = enc_prekey_and_iv[:PREKEY_LEN], enc_prekey_and_iv[PREKEY_LEN:]

    if dec_prekey_and_iv in used_handshakes:
        last_clients_with_same_handshake[peer[0]] += 1
        await handle_bad_client(reader, writer, handshake)
        return False

    for user in config.USERS:
        secret = bytes.fromhex(config.USERS[user])

        dec_key = hashlib.sha256(dec_prekey + secret).digest()
        decryptor = create_aes_ctr(key=dec_key, iv=int.from_bytes(dec_iv, "big"))

        enc_key = hashlib.sha256(enc_prekey + secret).digest()
        encryptor = create_aes_ctr(key=enc_key, iv=int.from_bytes(enc_iv, "big"))

        decrypted = decryptor.decrypt(handshake)

        proto_tag = decrypted[PROTO_TAG_POS:PROTO_TAG_POS+4]
        if proto_tag not in (PROTO_TAG_ABRIDGED, PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE):
            continue

        if proto_tag == PROTO_TAG_SECURE:
            if is_tls_handshake and not config.MODES["tls"]:
                continue
            if not is_tls_handshake and not config.MODES["secure"]:
                continue
        else:
            if not config.MODES["classic"]:
                continue

        dc_idx = int.from_bytes(decrypted[DC_IDX_POS:DC_IDX_POS+2], "little", signed=True)

        if config.REPLAY_CHECK_LEN > 0:
            while len(used_handshakes) >= config.REPLAY_CHECK_LEN:
                used_handshakes.popitem(last=False)
            used_handshakes[dec_prekey_and_iv] = True

        if config.CLIENT_IPS_LEN > 0:
            while len(client_ips) >= config.CLIENT_IPS_LEN:
                client_ips.popitem(last=False)
            if peer[0] not in client_ips:
                client_ips[peer[0]] = True
                last_client_ips[peer[0]] = True

        reader = CryptoWrappedStreamReader(reader, decryptor)
        writer = CryptoWrappedStreamWriter(writer, encryptor)
        return reader, writer, proto_tag, user, dc_idx, enc_key + enc_iv, peer

    await handle_bad_client(reader, writer, handshake)
    return False


async def do_direct_handshake(proto_tag, dc_idx, dec_key_and_iv=None):
    RESERVED_NONCE_FIRST_CHARS = [b"\xef"]
    RESERVED_NONCE_BEGININGS = [b"\x48\x45\x41\x44", b"\x50\x4F\x53\x54",
                                b"\x47\x45\x54\x20", b"\xee\xee\xee\xee",
                                b"\xdd\xdd\xdd\xdd", b"\x16\x03\x01\x02"]
    RESERVED_NONCE_CONTINUES = [b"\x00\x00\x00\x00"]

    global my_ip_info
    global tg_connection_pool

    dc_idx = abs(dc_idx) - 1

    if my_ip_info["ipv6"] and (config.PREFER_IPV6 or not my_ip_info["ipv4"]):
        if not 0 <= dc_idx < len(TG_DATACENTERS_V6):
            return False
        dc = TG_DATACENTERS_V6[dc_idx]
    else:
        if not 0 <= dc_idx < len(TG_DATACENTERS_V4):
            return False
        dc = TG_DATACENTERS_V4[dc_idx]

    try:
        reader_tgt, writer_tgt = await tg_connection_pool.get_connection(dc, TG_DATACENTER_PORT)
    except ConnectionRefusedError as E:
        print_err("Got connection refused while trying to connect to", dc, TG_DATACENTER_PORT)
        return False
    except ConnectionAbortedError as E:
        print_err("The Telegram server connection is bad: %d (%s %s) %s" % (dc_idx, dc, TG_DATACENTER_PORT, E))
        return False
    except (OSError, asyncio.TimeoutError) as E:
        print_err("Unable to connect to", dc, TG_DATACENTER_PORT)
        return False

    while True:
        rnd = bytearray(myrandom.getrandbytes(HANDSHAKE_LEN))
        if rnd[:1] in RESERVED_NONCE_FIRST_CHARS:
            continue
        if rnd[:4] in RESERVED_NONCE_BEGININGS:
            continue
        if rnd[4:8] in RESERVED_NONCE_CONTINUES:
            continue
        break

    rnd[PROTO_TAG_POS:PROTO_TAG_POS+4] = proto_tag

    if dec_key_and_iv:
        rnd[SKIP_LEN:SKIP_LEN+KEY_LEN+IV_LEN] = dec_key_and_iv[::-1]

    rnd = bytes(rnd)

    dec_key_and_iv = rnd[SKIP_LEN:SKIP_LEN+KEY_LEN+IV_LEN][::-1]
    dec_key, dec_iv = dec_key_and_iv[:KEY_LEN], dec_key_and_iv[KEY_LEN:]
    decryptor = create_aes_ctr(key=dec_key, iv=int.from_bytes(dec_iv, "big"))

    enc_key_and_iv = rnd[SKIP_LEN:SKIP_LEN+KEY_LEN+IV_LEN]
    enc_key, enc_iv = enc_key_and_iv[:KEY_LEN], enc_key_and_iv[KEY_LEN:]
    encryptor = create_aes_ctr(key=enc_key, iv=int.from_bytes(enc_iv, "big"))

    rnd_enc = rnd[:PROTO_TAG_POS] + encryptor.encrypt(rnd)[PROTO_TAG_POS:]

    writer_tgt.write(rnd_enc)
    await writer_tgt.drain()

    reader_tgt = CryptoWrappedStreamReader(reader_tgt, decryptor)
    writer_tgt = CryptoWrappedStreamWriter(writer_tgt, encryptor)

    return reader_tgt, writer_tgt


def get_middleproxy_aes_key_and_iv(nonce_srv, nonce_clt, clt_ts, srv_ip, clt_port, purpose,
                                   clt_ip, srv_port, middleproxy_secret, clt_ipv6=None,
                                   srv_ipv6=None):
    EMPTY_IP = b"\x00\x00\x00\x00"

    if not clt_ip or not srv_ip:
        clt_ip = EMPTY_IP
        srv_ip = EMPTY_IP

    s = bytearray()
    s += nonce_srv + nonce_clt + clt_ts + srv_ip + clt_port + purpose + clt_ip + srv_port
    s += middleproxy_secret + nonce_srv

    if clt_ipv6 and srv_ipv6:
        s += clt_ipv6 + srv_ipv6

    s += nonce_clt

    md5_sum = hashlib.md5(s[1:]).digest()
    sha1_sum = hashlib.sha1(s).digest()

    key = md5_sum[:12] + sha1_sum
    iv = hashlib.md5(s[2:]).digest()
    return key, iv


async def middleproxy_handshake(host, port, reader_tgt, writer_tgt):
    """ The most logic of middleproxy handshake, launched in pool """
    START_SEQ_NO = -2
    NONCE_LEN = 16

    RPC_HANDSHAKE = b"\xf5\xee\x82\x76"
    RPC_NONCE = b"\xaa\x87\xcb\x7a"
    # pass as consts to simplify code
    RPC_FLAGS = b"\x00\x00\x00\x00"
    CRYPTO_AES = b"\x01\x00\x00\x00"

    RPC_NONCE_ANS_LEN = 32
    RPC_HANDSHAKE_ANS_LEN = 32

    writer_tgt = MTProtoFrameStreamWriter(writer_tgt, START_SEQ_NO)
    key_selector = PROXY_SECRET[:4]
    crypto_ts = int.to_bytes(int(time.time()) % (256**4), 4, "little")

    nonce = myrandom.getrandbytes(NONCE_LEN)

    msg = RPC_NONCE + key_selector + CRYPTO_AES + crypto_ts + nonce

    writer_tgt.write(msg)
    await writer_tgt.drain()

    reader_tgt = MTProtoFrameStreamReader(reader_tgt, START_SEQ_NO)
    ans = await reader_tgt.read(get_to_clt_bufsize())

    if len(ans) != RPC_NONCE_ANS_LEN:
        raise ConnectionAbortedError("bad rpc answer length")

    rpc_type, rpc_key_selector, rpc_schema, rpc_crypto_ts, rpc_nonce = (
        ans[:4], ans[4:8], ans[8:12], ans[12:16], ans[16:32]
    )

    if rpc_type != RPC_NONCE or rpc_key_selector != key_selector or rpc_schema != CRYPTO_AES:
        raise ConnectionAbortedError("bad rpc answer")

    # get keys
    tg_ip, tg_port = writer_tgt.upstream.get_extra_info('peername')[:2]
    my_ip, my_port = writer_tgt.upstream.get_extra_info('sockname')[:2]

    use_ipv6_tg = (":" in tg_ip)

    if not use_ipv6_tg:
        if my_ip_info["ipv4"]:
            # prefer global ip settings to work behind NAT
            my_ip = my_ip_info["ipv4"]

        tg_ip_bytes = socket.inet_pton(socket.AF_INET, tg_ip)[::-1]
        my_ip_bytes = socket.inet_pton(socket.AF_INET, my_ip)[::-1]

        tg_ipv6_bytes = None
        my_ipv6_bytes = None
    else:
        if my_ip_info["ipv6"]:
            my_ip = my_ip_info["ipv6"]

        tg_ip_bytes = None
        my_ip_bytes = None

        tg_ipv6_bytes = socket.inet_pton(socket.AF_INET6, tg_ip)
        my_ipv6_bytes = socket.inet_pton(socket.AF_INET6, my_ip)

    tg_port_bytes = int.to_bytes(tg_port, 2, "little")
    my_port_bytes = int.to_bytes(my_port, 2, "little")

    enc_key, enc_iv = get_middleproxy_aes_key_and_iv(
        nonce_srv=rpc_nonce, nonce_clt=nonce, clt_ts=crypto_ts, srv_ip=tg_ip_bytes,
        clt_port=my_port_bytes, purpose=b"CLIENT", clt_ip=my_ip_bytes, srv_port=tg_port_bytes,
        middleproxy_secret=PROXY_SECRET, clt_ipv6=my_ipv6_bytes, srv_ipv6=tg_ipv6_bytes)

    dec_key, dec_iv = get_middleproxy_aes_key_and_iv(
        nonce_srv=rpc_nonce, nonce_clt=nonce, clt_ts=crypto_ts, srv_ip=tg_ip_bytes,
        clt_port=my_port_bytes, purpose=b"SERVER", clt_ip=my_ip_bytes, srv_port=tg_port_bytes,
        middleproxy_secret=PROXY_SECRET, clt_ipv6=my_ipv6_bytes, srv_ipv6=tg_ipv6_bytes)

    encryptor = create_aes_cbc(key=enc_key, iv=enc_iv)
    decryptor = create_aes_cbc(key=dec_key, iv=dec_iv)

    SENDER_PID = b"IPIPPRPDTIME"
    PEER_PID = b"IPIPPRPDTIME"

    # TODO: pass client ip and port here for statistics
    handshake = RPC_HANDSHAKE + RPC_FLAGS + SENDER_PID + PEER_PID

    writer_tgt.upstream = CryptoWrappedStreamWriter(writer_tgt.upstream, encryptor, block_size=16)
    writer_tgt.write(handshake)
    await writer_tgt.drain()

    reader_tgt.upstream = CryptoWrappedStreamReader(reader_tgt.upstream, decryptor, block_size=16)

    handshake_ans = await reader_tgt.read(1)
    if len(handshake_ans) != RPC_HANDSHAKE_ANS_LEN:
        raise ConnectionAbortedError("bad rpc handshake answer length")

    handshake_type, handshake_flags, handshake_sender_pid, handshake_peer_pid = (
        handshake_ans[:4], handshake_ans[4:8], handshake_ans[8:20], handshake_ans[20:32])
    if handshake_type != RPC_HANDSHAKE or handshake_peer_pid != SENDER_PID:
        raise ConnectionAbortedError("bad rpc handshake answer")

    return reader_tgt, writer_tgt, my_ip, my_port


async def do_middleproxy_handshake(proto_tag, dc_idx, cl_ip, cl_port):
    global my_ip_info
    global tg_connection_pool

    use_ipv6_tg = (my_ip_info["ipv6"] and (config.PREFER_IPV6 or not my_ip_info["ipv4"]))

    if use_ipv6_tg:
        if dc_idx not in TG_MIDDLE_PROXIES_V6:
            return False
        addr, port = myrandom.choice(TG_MIDDLE_PROXIES_V6[dc_idx])
    else:
        if dc_idx not in TG_MIDDLE_PROXIES_V4:
            return False
        addr, port = myrandom.choice(TG_MIDDLE_PROXIES_V4[dc_idx])

    try:
        ret = await tg_connection_pool.get_connection(addr, port, middleproxy_handshake)
        reader_tgt, writer_tgt, my_ip, my_port = ret
    except ConnectionRefusedError as E:
        print_err("The Telegram server %d (%s %s) is refusing connections" % (dc_idx, addr, port))
        return False
    except ConnectionAbortedError as E:
        print_err("The Telegram server connection is bad: %d (%s %s) %s" % (dc_idx, addr, port, E))
        return False
    except (OSError, asyncio.TimeoutError) as E:
        print_err("Unable to connect to the Telegram server %d (%s %s)" % (dc_idx, addr, port))
        return False

    writer_tgt = ProxyReqStreamWriter(writer_tgt, cl_ip, cl_port, my_ip, my_port, proto_tag)
    reader_tgt = ProxyReqStreamReader(reader_tgt)

    return reader_tgt, writer_tgt


async def tg_connect_reader_to_writer(rd, wr, user, rd_buf_size, is_upstream):
    try:
        while True:
            data = await rd.read(rd_buf_size)
            if isinstance(data, tuple):
                data, extra = data
            else:
                extra = {}

            if extra.get("SKIP_SEND"):
                continue

            if not data:
                wr.write_eof()
                await wr.drain()
                return
            else:
                if is_upstream:
                    update_user_stats(user, octets_from_client=len(data), msgs_from_client=1)
                else:
                    update_user_stats(user, octets_to_client=len(data), msgs_to_client=1)

                wr.write(data, extra)
                await wr.drain()
    except (OSError, asyncio.IncompleteReadError) as e:
        # print_err(e)
        pass


async def handle_client(reader_clt, writer_clt):
    set_keepalive(writer_clt.get_extra_info("socket"), config.CLIENT_KEEPALIVE, attempts=3)
    set_ack_timeout(writer_clt.get_extra_info("socket"), config.CLIENT_ACK_TIMEOUT)
    set_bufsizes(writer_clt.get_extra_info("socket"), get_to_tg_bufsize(), get_to_clt_bufsize())

    update_stats(connects_all=1)

    try:
        clt_data = await asyncio.wait_for(handle_handshake(reader_clt, writer_clt),
                                          timeout=config.CLIENT_HANDSHAKE_TIMEOUT)
    except asyncio.TimeoutError:
        update_stats(handshake_timeouts=1)
        return

    if not clt_data:
        return

    reader_clt, writer_clt, proto_tag, user, dc_idx, enc_key_and_iv, peer = clt_data
    cl_ip, cl_port = peer

    update_user_stats(user, connects=1)

    connect_directly = (not config.USE_MIDDLE_PROXY or disable_middle_proxy)

    if connect_directly:
        if config.FAST_MODE:
            tg_data = await do_direct_handshake(proto_tag, dc_idx, dec_key_and_iv=enc_key_and_iv)
        else:
            tg_data = await do_direct_handshake(proto_tag, dc_idx)
    else:
        tg_data = await do_middleproxy_handshake(proto_tag, dc_idx, cl_ip, cl_port)

    if not tg_data:
        return

    reader_tg, writer_tg = tg_data

    if connect_directly and config.FAST_MODE:
        class FakeEncryptor:
            def encrypt(self, data):
                return data

        class FakeDecryptor:
            def decrypt(self, data):
                return data

        reader_tg.decryptor = FakeDecryptor()
        writer_clt.encryptor = FakeEncryptor()

    if not connect_directly:
        if proto_tag == PROTO_TAG_ABRIDGED:
            reader_clt = MTProtoCompactFrameStreamReader(reader_clt)
            writer_clt = MTProtoCompactFrameStreamWriter(writer_clt)
        elif proto_tag == PROTO_TAG_INTERMEDIATE:
            reader_clt = MTProtoIntermediateFrameStreamReader(reader_clt)
            writer_clt = MTProtoIntermediateFrameStreamWriter(writer_clt)
        elif proto_tag == PROTO_TAG_SECURE:
            reader_clt = MTProtoSecureIntermediateFrameStreamReader(reader_clt)
            writer_clt = MTProtoSecureIntermediateFrameStreamWriter(writer_clt)
        else:
            return

    tg_to_clt = tg_connect_reader_to_writer(reader_tg, writer_clt, user,
                                            get_to_clt_bufsize(), False)
    clt_to_tg = tg_connect_reader_to_writer(reader_clt, writer_tg,
                                            user, get_to_tg_bufsize(), True)
    task_tg_to_clt = asyncio.ensure_future(tg_to_clt)
    task_clt_to_tg = asyncio.ensure_future(clt_to_tg)

    update_user_stats(user, curr_connects=1)

    tcp_limit_hit = (
        user in config.USER_MAX_TCP_CONNS and
        user_stats[user]["curr_connects"] > config.USER_MAX_TCP_CONNS[user]
    )

    user_expired = (
        user in config.USER_EXPIRATIONS and
        datetime.datetime.now() > config.USER_EXPIRATIONS[user]
    )

    user_data_quota_hit = (
        user in config.USER_DATA_QUOTA and
        (user_stats[user]["octets_to_client"] +
         user_stats[user]["octets_from_client"] > config.USER_DATA_QUOTA[user])
    )

    if (not tcp_limit_hit) and (not user_expired) and (not user_data_quota_hit):
        start = time.time()
        await asyncio.wait([task_tg_to_clt, task_clt_to_tg], return_when=asyncio.FIRST_COMPLETED)
        update_durations(time.time() - start)

    update_user_stats(user, curr_connects=-1)

    task_tg_to_clt.cancel()
    task_clt_to_tg.cancel()

    writer_tg.transport.abort()


async def handle_client_wrapper(reader, writer):
    try:
        await handle_client(reader, writer)
    except (asyncio.IncompleteReadError, asyncio.CancelledError):
        pass
    except (ConnectionResetError, TimeoutError, BrokenPipeError):
        pass
    except Exception:
        traceback.print_exc()
    finally:
        writer.transport.abort()


def make_metrics_pkt(metrics):
    pkt_body_list = []
    used_names = set()

    for name, m_type, desc, val in metrics:
        name = config.METRICS_PREFIX + name
        if name not in used_names:
            pkt_body_list.append("# HELP %s %s" % (name, desc))
            pkt_body_list.append("# TYPE %s %s" % (name, m_type))
            used_names.add(name)

        if isinstance(val, dict):
            tags = []
            for tag, tag_val in val.items():
                if tag == "val":
                    continue
                tag_val = tag_val.replace('"', r'\"')
                tags.append('%s="%s"' % (tag, tag_val))
            pkt_body_list.append("%s{%s} %s" % (name, ",".join(tags), val["val"]))
        else:
            pkt_body_list.append("%s %s" % (name, val))
    pkt_body = "\n".join(pkt_body_list) + "\n"

    pkt_header_list = []
    pkt_header_list.append("HTTP/1.1 200 OK")
    pkt_header_list.append("Connection: close")
    pkt_header_list.append("Content-Length: %d" % len(pkt_body))
    pkt_header_list.append("Content-Type: text/plain; version=0.0.4; charset=utf-8")
    pkt_header_list.append("Date: %s" % time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()))

    pkt_header = "\r\n".join(pkt_header_list)

    pkt = pkt_header + "\r\n\r\n" + pkt_body
    return pkt


async def handle_metrics(reader, writer):
    global stats
    global user_stats
    global my_ip_info
    global proxy_start_time
    global proxy_links
    global last_clients_with_time_skew
    global last_clients_with_same_handshake

    client_ip = writer.get_extra_info("peername")[0]
    if client_ip not in config.METRICS_WHITELIST:
        writer.close()
        return

    try:
        metrics = []
        metrics.append(["uptime", "counter", "proxy uptime", time.time() - proxy_start_time])
        metrics.append(["connects_bad", "counter", "connects with bad secret",
                       stats["connects_bad"]])
        metrics.append(["connects_all", "counter", "incoming connects", stats["connects_all"]])
        metrics.append(["handshake_timeouts", "counter", "number of timed out handshakes",
                       stats["handshake_timeouts"]])

        if config.METRICS_EXPORT_LINKS:
            for link in proxy_links:
                link_as_metric = link.copy()
                link_as_metric["val"] = 1
                metrics.append(["proxy_link_info", "counter",
                                "the proxy link info", link_as_metric])

        bucket_start = 0
        for bucket in STAT_DURATION_BUCKETS:
            bucket_end = bucket if bucket != STAT_DURATION_BUCKETS[-1] else "+Inf"
            metric = {
                "bucket": "%s-%s" % (bucket_start, bucket_end),
                "val": stats["connects_with_duration_le_%s" % str(bucket)]
            }
            metrics.append(["connects_by_duration", "counter", "connects by duration", metric])
            bucket_start = bucket_end

        user_metrics_desc = [
            ["user_connects", "counter", "user connects", "connects"],
            ["user_connects_curr", "gauge", "current user connects", "curr_connects"],
            ["user_octets", "counter", "octets proxied for user",
                "octets_from_client+octets_to_client"],
            ["user_msgs", "counter", "msgs proxied for user",
                "msgs_from_client+msgs_to_client"],
            ["user_octets_from", "counter", "octets proxied from user", "octets_from_client"],
            ["user_octets_to", "counter", "octets proxied to user", "octets_to_client"],
            ["user_msgs_from", "counter", "msgs proxied from user", "msgs_from_client"],
            ["user_msgs_to", "counter", "msgs proxied to user", "msgs_to_client"],
        ]

        for m_name, m_type, m_desc, stat_key in user_metrics_desc:
            for user, stat in user_stats.items():
                if "+" in stat_key:
                    val = 0
                    for key_part in stat_key.split("+"):
                        val += stat[key_part]
                else:
                    val = stat[stat_key]
                metric = {"user": user, "val": val}
                metrics.append([m_name, m_type, m_desc, metric])

        pkt = make_metrics_pkt(metrics)
        writer.write(pkt.encode())
        await writer.drain()

    except Exception:
        traceback.print_exc()
    finally:
        writer.close()


async def stats_printer():
    global user_stats
    global last_client_ips
    global last_clients_with_time_skew
    global last_clients_with_same_handshake

    while True:
        await asyncio.sleep(config.STATS_PRINT_PERIOD)

        print("Stats for", time.strftime("%d.%m.%Y %H:%M:%S"))
        for user, stat in user_stats.items():
            print("%s: %d connects (%d current), %.2f MB, %d msgs" % (
                user, stat["connects"], stat["curr_connects"],
                (stat["octets_from_client"] + stat["octets_to_client"]) / 1000000,
                stat["msgs_from_client"] + stat["msgs_to_client"]))
        print(flush=True)

        if last_client_ips:
            print("New IPs:")
            for ip in last_client_ips:
                print(ip)
            print(flush=True)
            last_client_ips.clear()

        if last_clients_with_time_skew:
            print("Clients with time skew (possible replay-attackers):")
            for ip, skew_minutes in last_clients_with_time_skew.items():
                print("%s, clocks were %d minutes behind" % (ip, skew_minutes))
            print(flush=True)
            last_clients_with_time_skew.clear()
        if last_clients_with_same_handshake:
            print("Clients with duplicate handshake (likely replay-attackers):")
            for ip, times in last_clients_with_same_handshake.items():
                print("%s, %d times" % (ip, times))
            print(flush=True)
            last_clients_with_same_handshake.clear()


async def make_https_req(url, host="core.telegram.org"):
    """ Make request, return resp body and headers. """
    SSL_PORT = 443
    url_data = urllib.parse.urlparse(url)

    HTTP_REQ_TEMPLATE = "\r\n".join(["GET %s HTTP/1.1", "Host: %s",
                                     "Connection: close"]) + "\r\n\r\n"
    reader, writer = await asyncio.open_connection(url_data.netloc, SSL_PORT, ssl=True)
    req = HTTP_REQ_TEMPLATE % (urllib.parse.quote(url_data.path), host)
    writer.write(req.encode("utf8"))
    data = await reader.read()
    writer.close()

    headers, body = data.split(b"\r\n\r\n", 1)
    return headers, body


def gen_tls_client_hello_msg(server_name):
    msg = bytearray()
    msg += b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" + myrandom.getrandbytes(32)
    msg += b"\x20" + myrandom.getrandbytes(32)
    msg += b"\x00\x22\x4a\x4a\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9"
    msg += b"\xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x00\x0a\x01\x00\x01\x91"
    msg += b"\xda\xda\x00\x00\x00\x00"
    msg += int.to_bytes(len(server_name) + 5, 2, "big")
    msg += int.to_bytes(len(server_name) + 3, 2, "big") + b"\x00"
    msg += int.to_bytes(len(server_name), 2, "big") + server_name.encode("ascii")
    msg += b"\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\x0a\x00\x0a\x00\x08\xaa\xaa\x00\x1d\x00"
    msg += b"\x17\x00\x18\x00\x0b\x00\x02\x01\x00\x00\x23\x00\x00\x00\x10\x00\x0e\x00\x0c\x02"
    msg += b"\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31\x00\x05\x00\x05\x01\x00\x00\x00\x00"
    msg += b"\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06"
    msg += b"\x06\x01\x02\x01\x00\x12\x00\x00\x00\x33\x00\x2b\x00\x29\xaa\xaa\x00\x01\x00\x00"
    msg += b"\x1d\x00\x20" + gen_x25519_public_key()
    msg += b"\x00\x2d\x00\x02\x01\x01\x00\x2b\x00\x0b\x0a\xba\xba\x03\x04\x03\x03\x03\x02\x03"
    msg += b"\x01\x00\x1b\x00\x03\x02\x00\x02\x3a\x3a\x00\x01\x00\x00\x15"
    msg += int.to_bytes(517 - len(msg) - 2, 2, "big")
    msg += b"\x00" * (517 - len(msg))
    return bytes(msg)


async def get_encrypted_cert(host, port, server_name):
    async def get_tls_record(reader):
        try:
            record_type = (await reader.readexactly(1))[0]
            tls_version = await reader.readexactly(2)
            if tls_version != b"\x03\x03":
                return 0, b""
            record_len = int.from_bytes(await reader.readexactly(2), "big")
            record = await reader.readexactly(record_len)

            return record_type, record
        except asyncio.IncompleteReadError:
            return 0, b""

    reader, writer = await asyncio.open_connection(host, port)
    writer.write(gen_tls_client_hello_msg(server_name))
    await writer.drain()

    record1_type, record1 = await get_tls_record(reader)
    if record1_type != 22:
        return b""

    record2_type, record2 = await get_tls_record(reader)
    if record2_type != 20:
        return b""

    record3_type, record3 = await get_tls_record(reader)
    if record3_type != 23:
        return b""

    if len(record3) < MIN_CERT_LEN:
        record4_type, record4 = await get_tls_record(reader)
        if record4_type != 23:
            return b""
        msg = ("The MASK_HOST %s sent some TLS record before certificate record, this makes the " +
               "proxy more detectable") % config.MASK_HOST
        print_err(msg)

        return record4

    return record3


async def get_mask_host_cert_len():
    global fake_cert_len

    GET_CERT_TIMEOUT = 10
    MASK_ENABLING_CHECK_PERIOD = 60

    while True:
        try:
            if not config.MASK:
                # do nothing
                await asyncio.sleep(MASK_ENABLING_CHECK_PERIOD)
                continue

            task = get_encrypted_cert(config.MASK_HOST, config.MASK_PORT, config.TLS_DOMAIN)
            cert = await asyncio.wait_for(task, timeout=GET_CERT_TIMEOUT)
            if cert:
                if len(cert) < MIN_CERT_LEN:
                    msg = ("The MASK_HOST %s returned several TLS records, this is not supported" %
                           config.MASK_HOST)
                    print_err(msg)
                elif len(cert) != fake_cert_len:
                    fake_cert_len = len(cert)
                    print_err("Got cert from the MASK_HOST %s, its length is %d" %
                              (config.MASK_HOST, fake_cert_len))
            else:
                print_err("The MASK_HOST %s is not TLS 1.3 host, this is not recommended" %
                          config.MASK_HOST)
        except ConnectionRefusedError:
            print_err("The MASK_HOST %s is refusing connections, this is not recommended" %
                      config.MASK_HOST)
        except (TimeoutError, asyncio.TimeoutError):
            print_err("Got timeout while getting TLS handshake from MASK_HOST %s" %
                      config.MASK_HOST)
        except Exception as E:
            print_err("Failed to connect to MASK_HOST %s: %s" % (
                      config.MASK_HOST, E))

        await asyncio.sleep(config.GET_CERT_LEN_PERIOD)


async def get_srv_time():
    TIME_SYNC_ADDR = "https://core.telegram.org/getProxySecret"
    MAX_TIME_SKEW = 30

    global disable_middle_proxy
    global is_time_skewed

    want_to_reenable_advertising = False
    while True:
        try:
            headers, secret = await make_https_req(TIME_SYNC_ADDR)

            for line in headers.split(b"\r\n"):
                if not line.startswith(b"Date: "):
                    continue
                line = line[len("Date: "):].decode()
                srv_time = datetime.datetime.strptime(line, "%a, %d %b %Y %H:%M:%S %Z")
                now_time = datetime.datetime.utcnow()
                is_time_skewed = (now_time-srv_time).total_seconds() > MAX_TIME_SKEW
                if is_time_skewed and config.USE_MIDDLE_PROXY and not disable_middle_proxy:
                    print_err("Time skew detected, please set the clock")
                    print_err("Server time:", srv_time, "your time:", now_time)
                    print_err("Disabling advertising to continue serving")
                    print_err("Putting down the shields against replay attacks")

                    disable_middle_proxy = True
                    want_to_reenable_advertising = True
                elif not is_time_skewed and want_to_reenable_advertising:
                    print_err("Time is ok, reenabling advertising")
                    disable_middle_proxy = False
                    want_to_reenable_advertising = False
        except Exception as E:
            print_err("Error getting server time", E)

        await asyncio.sleep(config.GET_TIME_PERIOD)


async def clear_ip_resolving_cache():
    global mask_host_cached_ip
    min_sleep = myrandom.randrange(60 - 10, 60 + 10)
    max_sleep = myrandom.randrange(120 - 10, 120 + 10)
    while True:
        mask_host_cached_ip = None
        await asyncio.sleep(myrandom.randrange(min_sleep, max_sleep))


async def update_middle_proxy_info():
    async def get_new_proxies(url):
        PROXY_REGEXP = re.compile(r"proxy_for\s+(-?\d+)\s+(.+):(\d+)\s*;")
        ans = {}
        headers, body = await make_https_req(url)

        fields = PROXY_REGEXP.findall(body.decode("utf8"))
        if fields:
            for dc_idx, host, port in fields:
                if host.startswith("[") and host.endswith("]"):
                    host = host[1:-1]
                dc_idx, port = int(dc_idx), int(port)
                if dc_idx not in ans:
                    ans[dc_idx] = [(host, port)]
                else:
                    ans[dc_idx].append((host, port))
        return ans

    PROXY_INFO_ADDR = "https://core.telegram.org/getProxyConfig"
    PROXY_INFO_ADDR_V6 = "https://core.telegram.org/getProxyConfigV6"
    PROXY_SECRET_ADDR = "https://core.telegram.org/getProxySecret"

    global TG_MIDDLE_PROXIES_V4
    global TG_MIDDLE_PROXIES_V6
    global PROXY_SECRET

    while True:
        try:
            v4_proxies = await get_new_proxies(PROXY_INFO_ADDR)
            if not v4_proxies:
                raise Exception("no proxy data")
            TG_MIDDLE_PROXIES_V4 = v4_proxies
        except Exception as E:
            print_err("Error updating middle proxy list:", E)

        try:
            v6_proxies = await get_new_proxies(PROXY_INFO_ADDR_V6)
            if not v6_proxies:
                raise Exception("no proxy data (ipv6)")
            TG_MIDDLE_PROXIES_V6 = v6_proxies
        except Exception as E:
            print_err("Error updating middle proxy list for IPv6:", E)

        try:
            headers, secret = await make_https_req(PROXY_SECRET_ADDR)
            if not secret:
                raise Exception("no secret")
            if secret != PROXY_SECRET:
                PROXY_SECRET = secret
                print_err("Middle proxy secret updated")
        except Exception as E:
            print_err("Error updating middle proxy secret, using old", E)

        await asyncio.sleep(config.PROXY_INFO_UPDATE_PERIOD)


def init_ip_info():
    global my_ip_info
    global disable_middle_proxy

    def get_ip_from_url(url):
        TIMEOUT = 5
        try:
            with urllib.request.urlopen(url, timeout=TIMEOUT) as f:
                if f.status != 200:
                    raise Exception("Invalid status code")
                return f.read().decode().strip()
        except Exception:
            return None

    IPV4_URL1 = "http://v4.ident.me/"
    IPV4_URL2 = "http://ipv4.icanhazip.com/"

    IPV6_URL1 = "http://v6.ident.me/"
    IPV6_URL2 = "http://ipv6.icanhazip.com/"

    my_ip_info["ipv4"] = get_ip_from_url(IPV4_URL1) or get_ip_from_url(IPV4_URL2)
    my_ip_info["ipv6"] = get_ip_from_url(IPV6_URL1) or get_ip_from_url(IPV6_URL2)

    # the server can return ipv4 address instead of ipv6
    if my_ip_info["ipv6"] and ":" not in my_ip_info["ipv6"]:
        my_ip_info["ipv6"] = None

    if my_ip_info["ipv6"] and (config.PREFER_IPV6 or not my_ip_info["ipv4"]):
        print_err("IPv6 found, using it for external communication")

    if config.USE_MIDDLE_PROXY:
        if not my_ip_info["ipv4"] and not my_ip_info["ipv6"]:
            print_err("Failed to determine your ip, advertising disabled")
            disable_middle_proxy = True


def print_tg_info():
    global my_ip_info
    global proxy_links

    print_default_warning = False

    if config.PORT == 3256:
        if not QUIET:
            print_err("The default port 3256 is used, this is not recommended")
            if not config.MODES["classic"] and not config.MODES["secure"]:
                print_err("Since you have TLS only mode enabled the best port is 443")
        print_default_warning = True

    if not config.MY_DOMAIN:
        ip_addrs = [ip for ip in my_ip_info.values() if ip]
        if not ip_addrs:
            ip_addrs = ["YOUR_IP"]
    else:
        ip_addrs = [config.MY_DOMAIN]

    proxy_links = []

    for user, secret in sorted(config.USERS.items(), key=lambda x: x[0]):
        for ip in ip_addrs:
            if config.MODES["classic"]:
                params = {"server": ip, "port": config.PORT, "secret": secret}
                params_encodeded = urllib.parse.urlencode(params, safe=':')
                classic_link = "tg://proxy?{}".format(params_encodeded)
                proxy_links.append({"user": user, "link": classic_link})

            if config.MODES["secure"]:
                params = {"server": ip, "port": config.PORT, "secret": "dd" + secret}
                params_encodeded = urllib.parse.urlencode(params, safe=':')
                dd_link = "tg://proxy?{}".format(params_encodeded)
                proxy_links.append({"user": user, "link": dd_link})

            if config.MODES["tls"]:
                tls_secret = "ee" + secret + config.TLS_DOMAIN.encode().hex()
                # the base64 links is buggy on ios
                # tls_secret = bytes.fromhex("ee" + secret) + config.TLS_DOMAIN.encode()
                # tls_secret_base64 = base64.urlsafe_b64encode(tls_secret)
                params = {"server": ip, "port": config.PORT, "secret": tls_secret}
                params_encodeded = urllib.parse.urlencode(params, safe=':')
                tls_link = "tg://proxy?{}".format(params_encodeded)
                proxy_links.append({"user": user, "link": tls_link})

        if secret in ["00000000000000000000000000000000", "0123456789abcdef0123456789abcdef",
                      "00000000000000000000000000000001"]:
            msg = "The default secret {} is used, this is not recommended".format(secret)
            random_secret = "".join(myrandom.choice("0123456789abcdef") for i in range(32))
            if not QUIET:
                print_err(msg)
                print_err("You can change it to this random secret: %s" % random_secret)
            print_default_warning = True

    if config.TLS_DOMAIN == "www.google.com":
        if not QUIET:
            print_err("The default TLS_DOMAIN www.google.com is used, this is not recommended")
        msg = "You should use random existing domain instead, bad clients are proxied there"
        if not QUIET:
            print_err(msg)
        print_default_warning = True

    if print_default_warning:
        print_err("Warning: one or more default settings detected")


def setup_files_limit():
    try:
        import resource
        soft_fd_limit, hard_fd_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard_fd_limit, hard_fd_limit))
    except (ValueError, OSError):
        print("Failed to increase the limit of opened files", flush=True, file=sys.stderr)
    except ImportError:
        pass


def setup_asyncio():
    # get rid of annoying "socket.send() raised exception" log messages
    asyncio.constants.LOG_THRESHOLD_FOR_CONNLOST_WRITES = 100


def setup_signals():
    if hasattr(signal, 'SIGUSR1'):
        def debug_signal(signum, frame):
            import pdb
            pdb.set_trace()

        signal.signal(signal.SIGUSR1, debug_signal)

    if hasattr(signal, 'SIGUSR2'):
        def reload_signal(signum, frame):
            reload_config_internal()

        signal.signal(signal.SIGUSR2, reload_signal)


def _create_api_app():
    if FastAPI is None:
        return None

    class ModesModel(BaseModel):
        classic: bool = False
        secure: bool = True
        tls: bool = True

    class ConfigModel(BaseModel):
        port: int = Field(ge=1, le=65535)
        users: Dict[str, str]
        modes: ModesModel
        tls_domain: str
        ad_tag: str = ""
        user_max_tcp_conns_default: int = Field(default=5, ge=0, le=1000)
        yookassa_prices: Dict[str, str] = Field(default_factory=dict)

    class UserCreateModel(BaseModel):
        name: str = Field(min_length=1, max_length=64)
        secret: str

    class UserUpdateModel(BaseModel):
        secret: str

    class LoginRequestModel(BaseModel):
        username: str
        password: str

    class LoginResponseModel(BaseModel):
        token: str

    class ChangePasswordRequestModel(BaseModel):
        old_password: str
        new_password: str = Field(min_length=8)

    class ApiKeyCreateRequestModel(BaseModel):
        name: str = ""

    class ApiKeyCreateResponseModel(BaseModel):
        id: int
        token: str
        prefix: str

    class ApiKeyListItemModel(BaseModel):
        id: int
        name: str
        prefix: str
        created_at: int

    app = FastAPI(title="mtprotoproxy")

    public_paths = {"/", "/ui", "/health", "/auth/login", "/favicon.ico", "/client", "/client/"}

    def _auth_error(status_code: int, detail: str):
        try:
            from fastapi.responses import JSONResponse
        except Exception:
            raise HTTPException(status_code=status_code, detail=detail)
        return JSONResponse(status_code=status_code, content={"detail": detail})

    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        path = request.url.path
        if path.startswith("/client"):
            return await call_next(request)
        if path in public_paths:
            return await call_next(request)

        auth = request.headers.get("authorization") or ""
        if not auth.lower().startswith("bearer "):
            return _auth_error(401, "missing bearer token")
        provided = auth.split(" ", 1)[1].strip()

        _init_config_db()
        with _connect_config_db() as conn:
            # Backward compatibility: single token stored in kv
            active = _get_active_token(conn)
            ok = bool(active and hmac.compare_digest(provided, active))
            if not ok:
                ok = _is_valid_api_key(conn, provided)

        if not ok:
            return _auth_error(401, "invalid bearer token")

        return await call_next(request)

    def _build_proxy_links() -> list[dict[str, str]]:
        # Similar to print_tg_info(), but without printing.
        if not config.MY_DOMAIN:
            ip_addrs = [ip for ip in my_ip_info.values() if ip]
            if not ip_addrs:
                ip_addrs = ["YOUR_IP"]
        else:
            ip_addrs = [config.MY_DOMAIN]

        links: list[dict[str, str]] = []
        for user, secret in sorted(config.USERS.items(), key=lambda x: x[0]):
            for ip in ip_addrs:
                if config.MODES["classic"]:
                    params = {"server": ip, "port": config.PORT, "secret": secret}
                    links.append({"user": user, "mode": "classic", "link": "tg://proxy?{}".format(urllib.parse.urlencode(params, safe=':'))})
                if config.MODES["secure"]:
                    params = {"server": ip, "port": config.PORT, "secret": "dd" + secret}
                    links.append({"user": user, "mode": "secure", "link": "tg://proxy?{}".format(urllib.parse.urlencode(params, safe=':'))})
                if config.MODES["tls"]:
                    tls_secret = "ee" + secret + config.TLS_DOMAIN.encode().hex()
                    params = {"server": ip, "port": config.PORT, "secret": tls_secret}
                    links.append({"user": user, "mode": "tls", "link": "tg://proxy?{}".format(urllib.parse.urlencode(params, safe=':'))})
        return links

    def _load_ui_html() -> str:
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            ui_path = os.path.join(base_dir, "ui.html")
            with open(ui_path, "r", encoding="utf-8") as f:
                return f.read()
        except OSError:
            raise HTTPException(status_code=404, detail="ui.html not found")

    def _load_client_html() -> str:
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            ui_path = os.path.join(base_dir, "client.html")
            with open(ui_path, "r", encoding="utf-8") as f:
                return f.read()
        except OSError:
            raise HTTPException(status_code=404, detail="client.html not found")

    @app.get("/")
    @app.get("/ui")
    def ui() -> Any:
        try:
            from fastapi.responses import HTMLResponse
        except Exception:
            raise HTTPException(status_code=500, detail="FastAPI HTMLResponse unavailable")
        return HTMLResponse(_load_ui_html())

    @app.get("/client")
    @app.get("/client/")
    def client_ui() -> Any:
        try:
            from fastapi.responses import HTMLResponse
        except Exception:
            raise HTTPException(status_code=500, detail="FastAPI HTMLResponse unavailable")
        return HTMLResponse(_load_client_html())

    class ClientAuthStartModel(BaseModel):
        plan: str
        email: str = ""
        tg_username: str = ""

    class ClientAuthStartResponseModel(BaseModel):
        status: str
        dev_link: str = ""
        tg_start_url: str = ""
        tg_bot: str = ""
        delivery: dict = {}

    class ClientMeResponseModel(BaseModel):
        status: str
        client: dict
        orders: list
        proxy: dict

    def _plan_to_seconds(plan: str) -> int:
        p = _plan_normalize(plan)
        seconds_map = {
            "week": DAYS_IN_WEEK * HOURS_IN_DAY * SECONDS_IN_HOUR,
            "month": DAYS_IN_MONTH * HOURS_IN_DAY * SECONDS_IN_HOUR,
            "year": DAYS_IN_YEAR * HOURS_IN_DAY * SECONDS_IN_HOUR
        }
        return seconds_map[p]

    def _plan_to_price_rub_db(conn: sqlite3.Connection, plan: str) -> str:
        p = _plan_normalize(plan)
        key_map = {
            "week": "yookassa_price_week",
            "month": "yookassa_price_month",
            "year": "yookassa_price_year"
        }
        
        if p not in key_map:
            raise HTTPException(status_code=400, detail=ERROR_UNKNOWN_PLAN)
        
        key = key_map[p]
        value = str(_get_kv(conn, key)).strip()
        
        try:
            price = float(value)
            if price <= 0:
                raise ValueError("Price must be positive")
        except (ValueError, TypeError):
            raise HTTPException(status_code=500, detail=f"Invalid price configuration for {plan}")
        
        return f"{price:.2f}"

    def _yookassa_api_request(method: str, path: str, body: dict | None, idempotence_key: str | None = None) -> dict:
        if not YOOKASSA_SHOP_ID or not YOOKASSA_SECRET_KEY:
            raise HTTPException(status_code=409, detail="yookassa not configured")
        url = YOOKASSA_API_BASE.rstrip("/") + "/" + path.lstrip("/")
        auth_b64 = base64.b64encode(f"{YOOKASSA_SHOP_ID}:{YOOKASSA_SECRET_KEY}".encode("utf-8")).decode("ascii")
        data_b = json.dumps(body or {}, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(url, data=data_b if method.upper() != "GET" else None)
        req.method = method.upper()
        req.add_header("Authorization", f"Basic {auth_b64}")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        if idempotence_key:
            req.add_header("Idempotence-Key", idempotence_key)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            try:
                raw = e.read().decode("utf-8")
            except Exception:
                raw = str(e)
            raise HTTPException(status_code=502, detail=f"yookassa error: {raw}")
        try:
            return json.loads(raw)
        except Exception:
            raise HTTPException(status_code=502, detail=f"yookassa bad response: {raw}")

    def _plan_normalize(plan: str) -> str:
        p = (plan or "").strip().lower()
        plan_map = {
            "week": ("week", "7d", "7", "неделя"),
            "month": ("month", "30d", "30", "месяц"),
            "year": ("year", "365d", "365", "год")
        }
        
        for normalized, variants in plan_map.items():
            if p in variants:
                return normalized
        
        raise HTTPException(status_code=400, detail=ERROR_UNKNOWN_PLAN)

    def _create_or_get_client(conn: sqlite3.Connection, email: str, tg_username: str) -> int:
        email_n = _sanitize_email(email)
        tg_n = _sanitize_tg_username(tg_username)
        if not email_n and not tg_n:
            raise HTTPException(status_code=400, detail="email or tg_username required")

        row = None
        if email_n:
            row = conn.execute("SELECT id FROM clients WHERE email = ?", (email_n,)).fetchone()
        if not row and tg_n:
            row = conn.execute("SELECT id FROM clients WHERE tg_username = ?", (tg_n,)).fetchone()
        now = _now_ts()
        if row:
            client_id = int(row["id"])
            conn.execute("UPDATE clients SET updated_at = ? WHERE id = ?", (now, client_id))
            if email_n:
                conn.execute("UPDATE clients SET email = ? WHERE id = ?", (email_n, client_id))
            if tg_n:
                conn.execute("UPDATE clients SET tg_username = ? WHERE id = ?", (tg_n, client_id))
            return client_id

        cur = conn.execute(
            "INSERT INTO clients(email, tg_username, tg_chat_id, created_at, updated_at) VALUES(?, ?, ?, ?, ?)",
            (email_n or None, tg_n or None, None, now, now),
        )
        return int(cur.lastrowid)

    def _client_issue_login_token(conn: sqlite3.Connection, client_id: int, channel: str) -> str:
        token = secrets.token_urlsafe(32)
        token_hash = _hash_token(token)
        now = _now_ts()
        exp = now + 15 * 60
        conn.execute(
            "INSERT OR REPLACE INTO client_login_tokens(token_hash, client_id, channel, expires_at, created_at) VALUES(?, ?, ?, ?, ?)",
            (token_hash, client_id, channel, exp, now),
        )
        return token

    def _client_create_session(conn: sqlite3.Connection, client_id: int) -> str:
        token = secrets.token_urlsafe(32)
        token_hash = _hash_token(token)
        now = _now_ts()
        exp = now + 7 * 24 * 3600
        conn.execute(
            "INSERT OR REPLACE INTO client_sessions(token_hash, client_id, expires_at, created_at) VALUES(?, ?, ?, ?)",
            (token_hash, client_id, exp, now),
        )
        return token

    def _client_from_session(conn: sqlite3.Connection, request: Request) -> int:
        token = request.cookies.get("mtclient") or ""
        if not token:
            raise HTTPException(status_code=401, detail="missing client session")
        token_hash = _hash_token(token)
        now = _now_ts()
        row = conn.execute(
            "SELECT client_id, expires_at FROM client_sessions WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="invalid client session")
        if int(row["expires_at"]) <= now:
            conn.execute("DELETE FROM client_sessions WHERE token_hash = ?", (token_hash,))
            raise HTTPException(status_code=401, detail="client session expired")
        return int(row["client_id"])

    def _subscription_for_account(conn: sqlite3.Connection, client_id: int, account_id: int) -> dict:
        row = conn.execute(
            "SELECT id, plan, status, starts_at, ends_at FROM proxy_subscriptions WHERE client_id = ? AND account_id = ? ORDER BY id DESC LIMIT 1",
            (int(client_id), int(account_id)),
        ).fetchone()
        if not row:
            return {"status": "none"}
        return {
            "id": int(row["id"]),
            "plan": str(row["plan"]),
            "status": str(row["status"]),
            "starts_at": int(row["starts_at"]) if row["starts_at"] is not None else None,
            "ends_at": int(row["ends_at"]) if row["ends_at"] is not None else None,
        }

    def _ensure_active_subscription(conn: sqlite3.Connection, client_id: int, account_id: int) -> dict:
        sub = _subscription_for_account(conn, client_id, account_id)
        if sub.get("status") != "active":
            raise HTTPException(status_code=402, detail="subscription not active")
        now = _now_ts()
        ends_at = sub.get("ends_at")
        if ends_at is not None and int(ends_at) <= now:
            raise HTTPException(status_code=402, detail="subscription expired")
        return sub

    def _create_proxy_account(conn: sqlite3.Connection, client_id: int) -> dict:
        now = _now_ts()
        suffix = secrets.token_hex(3)
        proxy_user = f"c{client_id}_{suffix}"
        secret_hex = _random_secret_hex32()
        conn.execute(
            "INSERT INTO users(name, secret, updated_at) VALUES(?, ?, ?)",
            (proxy_user, secret_hex, now),
        )
        cur = conn.execute(
            "INSERT INTO client_proxy_accounts2(client_id, proxy_user, created_at, updated_at) VALUES(?, ?, ?, ?)",
            (client_id, proxy_user, now, now),
        )
        acc_id = int(cur.lastrowid)
        conn.commit()
        reload_config_internal()
        _ensure_port_is_static()
        links = [l for l in _build_proxy_links() if l.get("user") == proxy_user]
        return {"id": acc_id, "proxy_user": proxy_user, "secret": secret_hex, "links": links}

    def _delete_proxy_account(conn: sqlite3.Connection, client_id: int, account_id: int) -> None:
        row = conn.execute(
            "SELECT proxy_user FROM client_proxy_accounts2 WHERE id = ? AND client_id = ?",
            (int(account_id), int(client_id)),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="proxy account not found")
        proxy_user = str(row["proxy_user"])
        conn.execute("DELETE FROM users WHERE name = ?", (proxy_user,))
        conn.execute("DELETE FROM client_proxy_accounts2 WHERE id = ? AND client_id = ?", (int(account_id), int(client_id)))
        conn.execute("DELETE FROM proxy_subscriptions WHERE account_id = ? AND client_id = ?", (int(account_id), int(client_id)))
        conn.commit()
        reload_config_internal()
        _ensure_port_is_static()

    def _recreate_proxy_account(conn: sqlite3.Connection, client_id: int, account_id: int) -> dict:
        row = conn.execute(
            "SELECT proxy_user FROM client_proxy_accounts2 WHERE id = ? AND client_id = ?",
            (int(account_id), int(client_id)),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="proxy account not found")
        proxy_user = str(row["proxy_user"])
        now = _now_ts()
        secret_hex = _random_secret_hex32()
        conn.execute(
            "UPDATE users SET secret = ?, updated_at = ? WHERE name = ?",
            (secret_hex, now, proxy_user),
        )
        conn.execute(
            "UPDATE client_proxy_accounts2 SET updated_at = ? WHERE id = ? AND client_id = ?",
            (now, int(account_id), int(client_id)),
        )
        conn.commit()
        reload_config_internal()
        _ensure_port_is_static()
        links = [l for l in _build_proxy_links() if l.get("user") == proxy_user]
        return {"id": int(account_id), "proxy_user": proxy_user, "secret": secret_hex, "links": links}

    def _list_proxy_accounts(conn: sqlite3.Connection, client_id: int) -> list[dict]:
        rows = conn.execute(
            "SELECT id, proxy_user FROM client_proxy_accounts2 WHERE client_id = ? ORDER BY id ASC",
            (int(client_id),),
        ).fetchall()
        out: list[dict] = []
        for r in rows:
            proxy_user = str(r["proxy_user"])
            links = [l for l in _build_proxy_links() if l.get("user") == proxy_user]
            sub = _subscription_for_account(conn, int(client_id), int(r["id"]))
            out.append({"id": int(r["id"]), "proxy_user": proxy_user, "links": links, "subscription": sub})
        return out

    def _list_pending_orders(conn: sqlite3.Connection, client_id: int) -> list[dict]:
        rows = conn.execute(
            "SELECT id, plan, status, created_at FROM proxy_subscriptions WHERE client_id = ? AND account_id IS NULL AND status = 'pending' ORDER BY id DESC",
            (int(client_id),),
        ).fetchall()
        out: list[dict] = []
        for r in rows:
            out.append({"id": int(r["id"]), "plan": str(r["plan"]), "status": str(r["status"]), "created_at": int(r["created_at"])})
        return out

    @app.post("/client/auth/start", response_model=ClientAuthStartResponseModel)
    def client_auth_start(body: ClientAuthStartModel, request: Request) -> Any:
        plan = _plan_normalize(body.plan)
        email = _sanitize_email(body.email)
        tg_username = _sanitize_tg_username(body.tg_username)
        channel = "email" if email else "telegram"

        _init_config_db()
        with _connect_config_db() as conn:
            client_id = _create_or_get_client(conn, email, tg_username)
            now = _now_ts()
            conn.execute(
                "INSERT INTO proxy_subscriptions(client_id, account_id, plan, status, starts_at, ends_at, created_at, updated_at) VALUES(?, NULL, ?, 'pending', NULL, NULL, ?, ?)",
                (client_id, plan, now, now),
            )
            token = _client_issue_login_token(conn, client_id, channel)
            conn.commit()

        base = _get_client_base_url(request)
        link = f"{base}/client/auth/confirm?token={urllib.parse.quote(token)}" if base else ""
        if link:
            print_err(f"Client login link for client_id={client_id} ({channel}): {link}")

        tg_start_url = ""
        tg_bot = TG_BOT_USERNAME
        delivery: dict = {"email": "", "telegram": ""}
        with _connect_config_db() as conn:
            notify_info = _client_notify_login_link(conn, client_id, link)
            delivery = dict(notify_info or {})
            try:
                conn.commit()
            except Exception:
                pass
            if channel == "telegram" and notify_info.get("telegram") != "sent":
                token_tg = _client_issue_tg_link_token(conn, client_id)
                tg_start_url = _tg_start_link(token_tg)
                conn.commit()

        if CLIENT_DEV_ISSUE_LINKS:
            return {"status": "ok", "dev_link": link, "tg_start_url": tg_start_url, "tg_bot": tg_bot, "delivery": delivery}
        return {"status": "ok", "dev_link": "", "tg_start_url": tg_start_url, "tg_bot": tg_bot, "delivery": delivery}

    @app.get("/client/auth/confirm")
    def client_auth_confirm(token: str, request: Request) -> Any:
        try:
            from fastapi.responses import RedirectResponse
        except Exception:
            raise HTTPException(status_code=500, detail="FastAPI RedirectResponse unavailable")

        provided = (token or "").strip()
        if not provided:
            raise HTTPException(status_code=400, detail="missing token")
        token_hash = _hash_token(provided)
        now = _now_ts()

        _init_config_db()
        with _connect_config_db() as conn:
            row = conn.execute(
                "SELECT client_id, expires_at FROM client_login_tokens WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
            if not row:
                raise HTTPException(status_code=400, detail="invalid token")
            if int(row["expires_at"]) <= now:
                conn.execute("DELETE FROM client_login_tokens WHERE token_hash = ?", (token_hash,))
                conn.commit()
                raise HTTPException(status_code=400, detail="token expired")
            client_id = int(row["client_id"])
            conn.execute("DELETE FROM client_login_tokens WHERE token_hash = ?", (token_hash,))
            session = _client_create_session(conn, client_id)
            try:
                msg_row = conn.execute(
                    "SELECT chat_id, message_id FROM client_login_tg_messages WHERE token_hash = ?",
                    (token_hash,),
                ).fetchone()
            except Exception:
                msg_row = None
            if msg_row:
                conn.execute("DELETE FROM client_login_tg_messages WHERE token_hash = ?", (token_hash,))
            conn.commit()

        if msg_row and TG_BOT_TOKEN and TelegramBotApi is not None:
            try:
                bot = TelegramBotApi(TG_BOT_TOKEN)
                bot.delete_message(str(msg_row["chat_id"]), int(msg_row["message_id"]))
            except Exception:
                pass

        resp = RedirectResponse(url="/client")
        resp.set_cookie(
            key="mtclient",
            value=session,
            httponly=True,
            samesite="lax",
            secure=False,
            max_age=7 * 24 * 3600,
        )
        return resp

    @app.post("/client/logout")
    def client_logout(request: Request) -> Any:
        try:
            from fastapi.responses import JSONResponse
        except Exception:
            raise HTTPException(status_code=500, detail="FastAPI JSONResponse unavailable")
        token = request.cookies.get("mtclient") or ""
        if token:
            _init_config_db()
            with _connect_config_db() as conn:
                conn.execute("DELETE FROM client_sessions WHERE token_hash = ?", (_hash_token(token),))
                conn.commit()
        resp = JSONResponse(content={"status": "ok"})
        resp.delete_cookie("mtclient")
        return resp

    @app.get("/client/me", response_model=ClientMeResponseModel)
    def client_me(request: Request) -> Any:
        _init_config_db()
        with _connect_config_db() as conn:
            client_id = _client_from_session(conn, request)
            row = conn.execute(
                "SELECT id, COALESCE(email, '') AS email, COALESCE(tg_username, '') AS tg_username FROM clients WHERE id = ?",
                (client_id,),
            ).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="client not found")
            orders = _list_pending_orders(conn, client_id)
            proxy_accounts = _list_proxy_accounts(conn, client_id)
        return {
            "status": "ok",
            "client": {"id": int(row["id"]), "email": str(row["email"]), "tg_username": str(row["tg_username"])},
            "orders": orders,
            "proxy": {"accounts": proxy_accounts},
        }

    class ClientPaymentConfirmModel(BaseModel):
        subscription_id: int

    class ClientPaymentCompleteModel(BaseModel):
        payment_id: str

    class ClientPaymentCreateResponseModel(BaseModel):
        status: str
        payment_id: str
        confirmation_token: str

    @app.post("/client/payment/create", response_model=ClientPaymentCreateResponseModel)
    def client_payment_create(body: ClientPaymentConfirmModel, request: Request) -> Any:
        _init_config_db()
        with _connect_config_db() as conn:
            client_id = _client_from_session(conn, request)
            row = conn.execute(
                "SELECT id, plan, status, account_id FROM proxy_subscriptions WHERE id = ? AND client_id = ?",
                (int(body.subscription_id), int(client_id)),
            ).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="order not found")
            if str(row["status"]) != "pending" or row["account_id"] is not None:
                raise HTTPException(status_code=409, detail="order not pending")

            plan = str(row["plan"])
            amount = _plan_to_price_rub_db(conn, plan)
            idem = secrets.token_hex(16)

        payload = {
            "amount": {"value": amount, "currency": YOOKASSA_CURRENCY},
            "capture": True,
            "confirmation": {"type": "embedded"},
            "description": f"mtprotoproxy {plan}",
            "metadata": {"subscription_id": int(body.subscription_id), "client_id": int(client_id)},
        }
        resp = _yookassa_api_request("POST", "/payments", payload, idempotence_key=idem)
        payment_id = str(resp.get("id") or "")
        token = str(((resp.get("confirmation") or {}).get("confirmation_token")) or "")
        status = str(resp.get("status") or "")
        if not payment_id or not token:
            raise HTTPException(status_code=502, detail="yookassa missing confirmation token")

        now = _now_ts()
        _init_config_db()
        with _connect_config_db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO yookassa_payments(payment_id, subscription_id, client_id, status, amount, currency, idempotence_key, processed, created_at, updated_at) "
                "VALUES(?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT processed FROM yookassa_payments WHERE payment_id = ?), 0), COALESCE((SELECT created_at FROM yookassa_payments WHERE payment_id = ?), ?), ?)",
                (
                    payment_id,
                    int(body.subscription_id),
                    int(client_id),
                    status or "pending",
                    amount,
                    YOOKASSA_CURRENCY,
                    idem,
                    payment_id,
                    payment_id,
                    now,
                    now,
                ),
            )
            conn.commit()

        return {"status": "ok", "payment_id": payment_id, "confirmation_token": token}

    @app.post("/client/payment/complete")
    def client_payment_complete(body: ClientPaymentCompleteModel, request: Request) -> Any:
        payment_id = (body.payment_id or "").strip()
        if not payment_id:
            raise HTTPException(status_code=400, detail="missing payment_id")

        _init_config_db()
        with _connect_config_db() as conn:
            client_id = _client_from_session(conn, request)
            row_pay = conn.execute(
                "SELECT payment_id, subscription_id, client_id, processed FROM yookassa_payments WHERE payment_id = ?",
                (payment_id,),
            ).fetchone()
            if not row_pay:
                raise HTTPException(status_code=404, detail="payment not found")
            if int(row_pay["client_id"]) != int(client_id):
                raise HTTPException(status_code=403, detail="payment not yours")
            if int(row_pay["processed"]) == 1:
                return {"status": "ok"}
            sub_id = int(row_pay["subscription_id"]) or 0

        resp = _yookassa_api_request("GET", f"/payments/{payment_id}", None)
        status = str(resp.get("status") or "")
        metadata = resp.get("metadata") or {}
        sub_id_api = int(metadata.get("subscription_id") or 0)
        if sub_id_api and sub_id_api != sub_id:
            sub_id = sub_id_api

        now = _now_ts()
        _init_config_db()
        with _connect_config_db() as conn:
            conn.execute(
                "UPDATE yookassa_payments SET status = ?, updated_at = ? WHERE payment_id = ?",
                (status or "", now, payment_id),
            )
            conn.commit()

        if status != "succeeded":
            raise HTTPException(status_code=409, detail=f"payment status: {status}")

        # Apply success idempotently
        _init_config_db()
        with _connect_config_db() as conn:
            row_pay2 = conn.execute(
                "SELECT processed, subscription_id, client_id FROM yookassa_payments WHERE payment_id = ?",
                (payment_id,),
            ).fetchone()
            if not row_pay2:
                raise HTTPException(status_code=404, detail="payment not found")
            if int(row_pay2["client_id"]) != int(client_id):
                raise HTTPException(status_code=403, detail="payment not yours")
            if int(row_pay2["processed"]) == 1:
                return {"status": "ok"}

            row_sub = conn.execute(
                "SELECT id, plan, status, account_id FROM proxy_subscriptions WHERE id = ? AND client_id = ?",
                (int(sub_id), int(client_id)),
            ).fetchone()
            if not row_sub:
                conn.execute("UPDATE yookassa_payments SET processed = 1, updated_at = ? WHERE payment_id = ?", (now, payment_id))
                conn.commit()
                return {"status": "ok"}
            if row_sub["account_id"] is not None:
                conn.execute("UPDATE yookassa_payments SET processed = 1, updated_at = ? WHERE payment_id = ?", (now, payment_id))
                conn.commit()
                return {"status": "ok"}

            plan = str(row_sub["plan"])
            seconds = _plan_to_seconds(plan)
            starts = _now_ts()
            ends = starts + seconds
            conn.execute(
                "UPDATE proxy_subscriptions SET status = 'active', starts_at = ?, ends_at = ?, updated_at = ? WHERE id = ? AND client_id = ?",
                (starts, ends, starts, int(sub_id), int(client_id)),
            )
            conn.commit()
            proxy = _create_proxy_account(conn, int(client_id))
            conn.execute(
                "UPDATE proxy_subscriptions SET account_id = ?, updated_at = ? WHERE id = ? AND client_id = ?",
                (int(proxy.get("id") or 0), starts, int(sub_id), int(client_id)),
            )
            conn.execute("UPDATE yookassa_payments SET processed = 1, updated_at = ? WHERE payment_id = ?", (starts, payment_id))
            conn.commit()
            try:
                _client_notify_proxy(conn, int(client_id), proxy.get("links") or [])
            except Exception:
                pass

        return {"status": "ok"}


    class ClientProxyCreateModel(BaseModel):
        plan: str

    @app.post("/client/proxy/create")
    def client_proxy_create(body: ClientProxyCreateModel, request: Request) -> Any:
        _init_config_db()
        with _connect_config_db() as conn:
            client_id = _client_from_session(conn, request)
            plan = _plan_normalize(body.plan)
            now = _now_ts()
            row = conn.execute(
                "SELECT id FROM proxy_subscriptions WHERE client_id = ? AND account_id IS NULL AND status = 'pending' ORDER BY id DESC LIMIT 1",
                (int(client_id),),
            ).fetchone()
            if row:
                sub_id = int(row["id"])
                conn.execute(
                    "UPDATE proxy_subscriptions SET plan = ?, updated_at = ? WHERE id = ? AND client_id = ?",
                    (plan, now, sub_id, int(client_id)),
                )
                conn.commit()
                return {"status": "ok", "subscription": {"id": sub_id, "plan": plan, "status": "pending"}}

            cur = conn.execute(
                "INSERT INTO proxy_subscriptions(client_id, account_id, plan, status, starts_at, ends_at, created_at, updated_at) VALUES(?, NULL, ?, 'pending', NULL, NULL, ?, ?)",
                (int(client_id), plan, now, now),
            )
            conn.commit()
            return {"status": "ok", "subscription": {"id": int(cur.lastrowid), "plan": plan, "status": "pending"}}

    @app.post("/client/order/cancel")
    def client_order_cancel(request: Request) -> Any:
        _init_config_db()
        with _connect_config_db() as conn:
            client_id = _client_from_session(conn, request)
            row = conn.execute(
                "SELECT id FROM proxy_subscriptions WHERE client_id = ? AND account_id IS NULL AND status = 'pending' ORDER BY id DESC LIMIT 1",
                (int(client_id),),
            ).fetchone()
            if not row:
                return {"status": "ok", "cancelled": False}
            sub_id = int(row["id"])
            conn.execute(
                "DELETE FROM proxy_subscriptions WHERE id = ? AND client_id = ? AND account_id IS NULL AND status = 'pending'",
                (sub_id, int(client_id)),
            )
            conn.commit()
        return {"status": "ok", "cancelled": True}

    class ClientProxyRecreateModel(BaseModel):
        account_id: int

    @app.post("/client/proxy/recreate")
    def client_proxy_recreate(body: ClientProxyRecreateModel, request: Request) -> Any:
        _init_config_db()
        with _connect_config_db() as conn:
            client_id = _client_from_session(conn, request)
            _ensure_active_subscription(conn, client_id, int(body.account_id))
            proxy = _recreate_proxy_account(conn, client_id, int(body.account_id))
            try:
                _client_notify_proxy(conn, client_id, proxy.get("links") or [])
            except Exception:
                pass
        return {"status": "ok", "proxy": proxy}

    @app.delete("/client/proxy/{account_id}")
    def client_proxy_delete(account_id: int, request: Request) -> Any:
        _init_config_db()
        with _connect_config_db() as conn:
            client_id = _client_from_session(conn, request)
            # allow deleting even if expired (cleanup), but ensure the account belongs to the client
            _delete_proxy_account(conn, client_id, int(account_id))
        return {"status": "ok"}

    @app.post("/client/tg/link/start")
    def client_tg_link_start(request: Request) -> Any:
        if not TG_BOT_TOKEN:
            raise HTTPException(status_code=409, detail="telegram bot not configured")
        _init_config_db()
        with _connect_config_db() as conn:
            client_id = _client_from_session(conn, request)
            token_tg = _client_issue_tg_link_token(conn, client_id)
            conn.commit()
        return {"status": "ok", "start_url": _tg_start_link(token_tg), "bot": TG_BOT_USERNAME}

    def _validate_secret(secret: str) -> str:
        if re.fullmatch(r"[0-9a-fA-F]{32}", secret):
            return secret.lower()
        raise HTTPException(status_code=400, detail="secret must be 32 hex chars")

    def _dump_config_from_db() -> Dict[str, Any]:
        conf = _load_conf_dict_from_db()
        try:
            with _connect_config_db() as conn:
                default_max_tcp = int(_get_kv(conn, "user_max_tcp_conns_default"))
                y_week = str(_get_kv(conn, "yookassa_price_week"))
                y_month = str(_get_kv(conn, "yookassa_price_month"))
                y_year = str(_get_kv(conn, "yookassa_price_year"))
        except Exception:
            default_max_tcp = 0
            y_week = "100.00"
            y_month = "250.00"
            y_year = "2000.00"
        return {
            "port": int(conf["PORT"]),
            "users": dict(conf["USERS"]),
            "modes": dict(conf["MODES"]),
            "tls_domain": str(conf["TLS_DOMAIN"]),
            "ad_tag": str(conf.get("AD_TAG", "")),
            "user_max_tcp_conns_default": int(default_max_tcp),
            "yookassa_prices": {"week": y_week, "month": y_month, "year": y_year},
        }

    @app.get("/health")
    def health() -> Dict[str, Any]:
        return {"status": "ok"}

    @app.get("/links")
    def get_links() -> Any:
        return {"links": _build_proxy_links()}

    @app.get("/stats/summary")
    def stats_summary(limit_users: int = 20) -> Any:
        ts = int(time.time())
        agg, users_out = _stats_snapshot_now(ts)
        if limit_users > 0:
            users_out = users_out[: min(int(limit_users), 200)]
        return {"now": agg, "users": users_out}

    @app.get("/stats/timeseries")
    def stats_timeseries(minutes: int = 60, step: int = 10) -> Any:
        minutes = max(1, int(minutes))
        step = max(1, int(step))
        ts_to = int(time.time())
        ts_from = ts_to - minutes * 60

        _init_config_db()
        with _connect_config_db() as conn:
            rows = conn.execute(
                "SELECT ts, connects_all, connects_bad, handshake_timeouts, curr_connects, octets_total, msgs_total FROM stats_samples WHERE ts >= ? AND ts <= ? ORDER BY ts ASC",
                (ts_from, ts_to),
            ).fetchall()

        series = []
        last_emit = None
        for r in rows:
            ts = int(r["ts"])
            if last_emit is None or ts - last_emit >= step:
                series.append(
                    {
                        "ts": ts,
                        "connects_all": int(r["connects_all"]),
                        "connects_bad": int(r["connects_bad"]),
                        "handshake_timeouts": int(r["handshake_timeouts"]),
                        "curr_connects": int(r["curr_connects"]),
                        "octets_total": int(r["octets_total"]),
                        "msgs_total": int(r["msgs_total"]),
                    }
                )
                last_emit = ts

        return {"from": ts_from, "to": ts_to, "step": step, "series": series}

    @app.post("/auth/login", response_model=LoginResponseModel)
    def login(body: LoginRequestModel) -> Dict[str, Any]:
        _init_config_db()
        with _connect_config_db() as conn:
            admin_user = _get_kv(conn, "admin_user")
            admin_hash = _get_kv(conn, "admin_pass_hash")
            if body.username != admin_user or not _verify_password(body.password, admin_hash):
                raise HTTPException(status_code=401, detail="bad credentials")
            token = _issue_token(conn)
        return {"token": token}

    @app.post("/auth/change-password")
    def change_password(body: ChangePasswordRequestModel) -> Dict[str, Any]:
        _init_config_db()
        with _connect_config_db() as conn:
            admin_hash = _get_kv(conn, "admin_pass_hash")
            if not _verify_password(body.old_password, admin_hash):
                raise HTTPException(status_code=401, detail="bad credentials")

            new_hash = _hash_password(body.new_password)
            _set_kv(conn, "admin_pass_hash", new_hash)
            conn.commit()

        return {"status": "ok"}

    @app.get("/auth/keys", response_model=list[ApiKeyListItemModel])
    def list_api_keys() -> Any:
        _init_config_db()
        with _connect_config_db() as conn:
            rows = conn.execute(
                "SELECT id, COALESCE(name, '') AS name, token_hash, created_at "
                "FROM api_keys WHERE revoked = 0 ORDER BY id DESC"
            ).fetchall()
        return [
            {
                "id": int(r["id"]),
                "name": str(r["name"]),
                "prefix": _format_token_prefix(str(r["token_hash"])),
                "created_at": int(r["created_at"]),
            }
            for r in rows
        ]

    @app.post("/auth/keys", response_model=ApiKeyCreateResponseModel)
    def create_api_key(body: ApiKeyCreateRequestModel) -> Any:
        _init_config_db()
        token = secrets.token_urlsafe(32)
        token_hash = _hash_token(token)
        now = int(time.time())
        with _connect_config_db() as conn:
            cur = conn.execute(
                "INSERT INTO api_keys(name, token_hash, created_at, revoked) VALUES(?, ?, ?, 0)",
                (body.name or "", token_hash, now),
            )
            conn.commit()
            key_id = int(cur.lastrowid)
        return {"id": key_id, "token": token, "prefix": _format_token_prefix(token_hash)}

    @app.delete("/auth/keys/{key_id}")
    def delete_api_key(key_id: int) -> Any:
        _init_config_db()
        with _connect_config_db() as conn:
            cur = conn.execute("UPDATE api_keys SET revoked = 1 WHERE id = ?", (key_id,))
            conn.commit()
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="key not found")
        return {"status": "ok"}

    @app.get("/config", response_model=ConfigModel)
    def get_config() -> Dict[str, Any]:
        return _dump_config_from_db()

    @app.put("/config", response_model=ConfigModel)
    def put_config(body: ConfigModel) -> Dict[str, Any]:
        desired = body.model_dump()

        if _proxy_listen_port_at_start and int(desired["port"]) != _proxy_listen_port_at_start:
            raise HTTPException(status_code=409, detail="changing port requires restart")

        _init_config_db()
        with _connect_config_db() as conn:
            _set_kv(conn, "port", str(int(desired["port"])))
            _set_kv(conn, "tls_domain", str(desired["tls_domain"]))
            _set_kv(conn, "ad_tag", str(desired.get("ad_tag", "")))
            _set_kv(conn, "modes_classic", "1" if desired["modes"]["classic"] else "0")
            _set_kv(conn, "modes_secure", "1" if desired["modes"]["secure"] else "0")
            _set_kv(conn, "modes_tls", "1" if desired["modes"]["tls"] else "0")
            _set_kv(conn, "user_max_tcp_conns_default", str(int(desired.get("user_max_tcp_conns_default", 0))))

            prices = desired.get("yookassa_prices") or {}
            if isinstance(prices, dict):
                if "week" in prices:
                    _set_kv(conn, "yookassa_price_week", str(prices.get("week") or ""))
                if "month" in prices:
                    _set_kv(conn, "yookassa_price_month", str(prices.get("month") or ""))
                if "year" in prices:
                    _set_kv(conn, "yookassa_price_year", str(prices.get("year") or ""))

            conn.execute("DELETE FROM users")
            now = int(time.time())
            for name, secret in desired["users"].items():
                conn.execute(
                    "INSERT INTO users(name, secret, updated_at) VALUES(?, ?, ?)",
                    (str(name), _validate_secret(str(secret)), now),
                )
            conn.commit()

        reload_config_internal()
        _ensure_port_is_static()
        return _dump_config_from_db()

    @app.get("/users")
    def list_users() -> Dict[str, Any]:
        return {"users": _dump_config_from_db()["users"]}

    @app.post("/users", status_code=201)
    def create_user(body: UserCreateModel) -> Dict[str, Any]:
        _init_config_db()
        with _connect_config_db() as conn:
            exists = conn.execute("SELECT 1 FROM users WHERE name = ?", (body.name,)).fetchone()
            if exists:
                raise HTTPException(status_code=409, detail="user already exists")
            now = int(time.time())
            conn.execute(
                "INSERT INTO users(name, secret, updated_at) VALUES(?, ?, ?)",
                (body.name, _validate_secret(body.secret), now),
            )
            conn.commit()

        reload_config_internal()
        _ensure_port_is_static()
        return {"name": body.name}

    @app.put("/users/{name}")
    def update_user(name: str, body: UserUpdateModel) -> Dict[str, Any]:
        _init_config_db()
        with _connect_config_db() as conn:
            row = conn.execute("SELECT 1 FROM users WHERE name = ?", (name,)).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="user not found")
            now = int(time.time())
            conn.execute(
                "UPDATE users SET secret = ?, updated_at = ? WHERE name = ?",
                (_validate_secret(body.secret), now, name),
            )
            conn.commit()

        reload_config_internal()
        _ensure_port_is_static()
        return {"name": name}

    @app.delete("/users/{name}", status_code=204)
    def delete_user(name: str) -> None:
        _init_config_db()
        with _connect_config_db() as conn:
            cur = conn.execute("DELETE FROM users WHERE name = ?", (name,))
            conn.commit()
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="user not found")

        reload_config_internal()
        _ensure_port_is_static()

    return app


def start_config_api(loop):
    if uvicorn is None:
        print_err("fastapi/uvicorn are not installed, config api is disabled")
        return

    app = _create_api_app()
    if app is None:
        return

    global _api_server
    config_uv = uvicorn.Config(
        app,
        host=API_LISTEN_HOST,
        port=API_LISTEN_PORT,
        log_level="warning",
        lifespan="off",
    )
    server = uvicorn.Server(config_uv)
    # Uvicorn installs SIGINT/SIGTERM handlers by default. This breaks Ctrl+C handling in our
    # own event loop, so disable it and manage shutdown ourselves.
    try:
        server.install_signal_handlers = lambda: None
    except Exception:
        pass
    _api_server = server
    loop.create_task(server.serve())


def setup_shutdown_signals(loop):
    def _request_exit():
        global _api_server
        try:
            if _api_server is not None:
                _api_server.should_exit = True
        except Exception:
            pass
        loop.stop()

    for sig_name in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, sig_name, None)
        if sig is None:
            continue
        try:
            if hasattr(loop, "add_signal_handler"):
                loop.add_signal_handler(sig, _request_exit)
            else:
                signal.signal(sig, lambda s, f: _request_exit())
        except NotImplementedError:
            signal.signal(sig, lambda s, f: _request_exit())


def try_setup_uvloop():
    if config.SOCKS5_HOST and config.SOCKS5_PORT:
        # socks mode is not compatible with uvloop
        return
    try:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        print_err("Found uvloop, using it for optimal performance")
    except ImportError:
        pass


def remove_unix_socket(path):
    try:
        if stat.S_ISSOCK(os.stat(path).st_mode):
            os.unlink(path)
    except (FileNotFoundError, NotADirectoryError):
        pass


def loop_exception_handler(loop, context):
    exception = context.get("exception")
    transport = context.get("transport")
    if exception:
        if isinstance(exception, TimeoutError):
            if transport:
                transport.abort()
                return
        if isinstance(exception, OSError):
            IGNORE_ERRNO = {
                10038,  # operation on non-socket on Windows, likely because fd == -1
                121,    # the semaphore timeout period has expired on Windows
            }

            FORCE_CLOSE_ERRNO = {
                113,    # no route to host

            }
            if exception.errno in IGNORE_ERRNO:
                return
            elif exception.errno in FORCE_CLOSE_ERRNO:
                if transport:
                    transport.abort()
                    return

    loop.default_exception_handler(context)


def create_servers(loop):
    servers = []

    reuse_port = hasattr(socket, "SO_REUSEPORT")
    has_unix = hasattr(socket, "AF_UNIX")

    if config.LISTEN_ADDR_IPV4:
        task = asyncio.start_server(handle_client_wrapper, config.LISTEN_ADDR_IPV4, config.PORT,
                                    limit=get_to_tg_bufsize(), reuse_port=reuse_port)
        servers.append(loop.run_until_complete(task))

    if config.LISTEN_ADDR_IPV6 and socket.has_ipv6:
        task = asyncio.start_server(handle_client_wrapper, config.LISTEN_ADDR_IPV6, config.PORT,
                                    limit=get_to_tg_bufsize(), reuse_port=reuse_port)
        servers.append(loop.run_until_complete(task))

    if config.LISTEN_UNIX_SOCK and has_unix:
        remove_unix_socket(config.LISTEN_UNIX_SOCK)
        task = asyncio.start_unix_server(handle_client_wrapper, config.LISTEN_UNIX_SOCK,
                                         limit=get_to_tg_bufsize())
        servers.append(loop.run_until_complete(task))
        os.chmod(config.LISTEN_UNIX_SOCK, 0o666)

    if config.METRICS_PORT is not None:
        if config.METRICS_LISTEN_ADDR_IPV4:
            task = asyncio.start_server(handle_metrics, config.METRICS_LISTEN_ADDR_IPV4,
                                        config.METRICS_PORT)
            servers.append(loop.run_until_complete(task))
        if config.METRICS_LISTEN_ADDR_IPV6 and socket.has_ipv6:
            task = asyncio.start_server(handle_metrics, config.METRICS_LISTEN_ADDR_IPV6,
                                        config.METRICS_PORT)
            servers.append(loop.run_until_complete(task))

    return servers


def create_utilitary_tasks(loop):
    tasks = []

    stats_printer_task = asyncio.Task(stats_printer(), loop=loop)
    tasks.append(stats_printer_task)

    stats_sampler_task = asyncio.Task(stats_sampler(), loop=loop)
    tasks.append(stats_sampler_task)

    client_watcher_task = asyncio.Task(client_subscription_watcher(), loop=loop)
    tasks.append(client_watcher_task)

    if TG_BOT_POLL and TG_BOT_TOKEN:
        tg_poller_task = asyncio.Task(telegram_bot_poller(), loop=loop)
        tasks.append(tg_poller_task)

    if config.USE_MIDDLE_PROXY:
        middle_proxy_updater_task = asyncio.Task(update_middle_proxy_info(), loop=loop)
        tasks.append(middle_proxy_updater_task)

        if config.GET_TIME_PERIOD:
            time_get_task = asyncio.Task(get_srv_time(), loop=loop)
            tasks.append(time_get_task)

    get_cert_len_task = asyncio.Task(get_mask_host_cert_len(), loop=loop)
    tasks.append(get_cert_len_task)

    clear_resolving_cache_task = asyncio.Task(clear_ip_resolving_cache(), loop=loop)
    tasks.append(clear_resolving_cache_task)

    return tasks


def main():
    init_config()
    _ensure_port_is_static()
    ensure_users_in_user_stats()
    apply_upstream_proxy_settings()
    init_ip_info()
    print_tg_info()

    setup_asyncio()
    setup_files_limit()
    setup_signals()
    try_setup_uvloop()

    init_proxy_start_time()

    if sys.platform == "win32":
        loop = asyncio.ProactorEventLoop()
    else:
        loop = asyncio.new_event_loop()

    asyncio.set_event_loop(loop)
    loop.set_exception_handler(loop_exception_handler)

    setup_shutdown_signals(loop)

    utilitary_tasks = create_utilitary_tasks(loop)
    for task in utilitary_tasks:
        asyncio.ensure_future(task)

    start_config_api(loop)

    servers = create_servers(loop)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    if hasattr(asyncio, "all_tasks"):
        tasks = asyncio.all_tasks(loop)
    else:
        # for compatibility with Python 3.6
        tasks = asyncio.Task.all_tasks(loop)

    for task in tasks:
        task.cancel()

    for server in servers:
        server.close()
        loop.run_until_complete(server.wait_closed())

    has_unix = hasattr(socket, "AF_UNIX")

    if config.LISTEN_UNIX_SOCK and has_unix:
        remove_unix_socket(config.LISTEN_UNIX_SOCK)

    loop.close()


if __name__ == "__main__":
    main()
