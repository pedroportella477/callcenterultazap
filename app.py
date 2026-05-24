import hashlib
import hmac
import json
import os
import base64
import csv
import io
import mimetypes
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections import deque
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "omnichannel.sqlite3"
STATIC_DIR = BASE_DIR / "static"
UPLOADS_DIR = BASE_DIR / "uploads"

def env_int(name, default, minimum=0, maximum=None):
    raw_value = os.environ.get(name)
    try:
        value = int(raw_value) if raw_value is not None else int(default)
    except (TypeError, ValueError):
        value = int(default)
    if value < minimum:
        value = minimum
    if maximum is not None and value > maximum:
        value = maximum
    return value


APP_SECRET = os.environ.get("APP_SECRET", "dev-secret-change-me")
EVOLUTION_BASE_URL = os.environ.get("EVOLUTION_BASE_URL", "").rstrip("/")
EVOLUTION_API_KEY = os.environ.get("EVOLUTION_API_KEY", "")
EVOLUTION_INSTANCE = os.environ.get("EVOLUTION_INSTANCE", "atendimento")
WEBHOOK_TOKEN = os.environ.get("WEBHOOK_TOKEN", "")
SESSION_TTL_SECONDS = env_int("SESSION_TTL_SECONDS", 86400, minimum=300, maximum=604800)
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"
MAX_JSON_BYTES = env_int("MAX_JSON_BYTES", 1048576, minimum=1024, maximum=10485760)
MAX_WEBHOOK_QUEUE_SIZE = env_int("MAX_WEBHOOK_QUEUE_SIZE", 2000, minimum=1, maximum=100000)
LOGIN_RATE_LIMIT_ATTEMPTS = env_int("LOGIN_RATE_LIMIT_ATTEMPTS", 8, minimum=2, maximum=100)
LOGIN_RATE_LIMIT_WINDOW_SECONDS = env_int("LOGIN_RATE_LIMIT_WINDOW_SECONDS", 300, minimum=30, maximum=3600)
WEBHOOK_PROCESSED_RETENTION_SECONDS = env_int(
    "WEBHOOK_PROCESSED_RETENTION_SECONDS", 604800, minimum=3600, maximum=31536000
)
WEBHOOK_MAX_ATTEMPTS = env_int("WEBHOOK_MAX_ATTEMPTS", 5, minimum=1, maximum=50)
DEFAULT_SLA_FIRST_RESPONSE_SECONDS = env_int(
    "DEFAULT_SLA_FIRST_RESPONSE_SECONDS", 900, minimum=60, maximum=86400
)
DEFAULT_TME_TARGET_SECONDS = env_int(
    "DEFAULT_TME_TARGET_SECONDS", 300, minimum=30, maximum=86400
)
DEFAULT_TMA_TARGET_SECONDS = env_int(
    "DEFAULT_TMA_TARGET_SECONDS", 1200, minimum=60, maximum=172800
)
SCHEDULE_WORKER_POLL_SECONDS = env_int(
    "SCHEDULE_WORKER_POLL_SECONDS", 2, minimum=1, maximum=60
)
MAX_UPLOAD_BYTES = env_int("MAX_UPLOAD_BYTES", 10485760, minimum=1024, maximum=52428800)
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-5-mini")
SSE_KEEPALIVE_SECONDS = env_int("SSE_KEEPALIVE_SECONDS", 15, minimum=5, maximum=120)
SSE_SUBSCRIBER_QUEUE_MAX = env_int("SSE_SUBSCRIBER_QUEUE_MAX", 200, minimum=10, maximum=5000)

SUPPORTED_CHANNELS = {
    "whatsapp",
    "telegram",
    "instagram",
    "facebook_messenger",
    "email",
    "webchat",
}
CHANNEL_ALIASES = {
    "wa": "whatsapp",
    "wpp": "whatsapp",
    "whats": "whatsapp",
    "whats_app": "whatsapp",
    "telegram": "telegram",
    "instagram": "instagram",
    "ig": "instagram",
    "facebook": "facebook_messenger",
    "facebook_messenger": "facebook_messenger",
    "facebook-messenger": "facebook_messenger",
    "messenger": "facebook_messenger",
    "fecebook_messenger": "facebook_messenger",
    "email": "email",
    "e-mail": "email",
    "mail": "email",
    "chat": "webchat",
    "site_chat": "webchat",
    "website_chat": "webchat",
    "webchat": "webchat",
}

SESSIONS = {}
SESSIONS_LOCK = threading.RLock()
LOGIN_ATTEMPTS = {}
LOGIN_ATTEMPTS_LOCK = threading.Lock()
WEBHOOK_QUEUE = deque()
WEBHOOK_COND = threading.Condition()
METRICS = {
    "http_requests_total": 0,
    "webhook_received_total": 0,
    "webhook_duplicate_total": 0,
    "webhook_queue_dropped_total": 0,
    "webhook_reprocessed_total": 0,
    "webhook_failed_total": 0,
    "webhook_dead_lettered_total": 0,
    "messages_processed_total": 0,
    "login_rate_limited_total": 0,
    "scheduled_processed_total": 0,
    "scheduled_failed_total": 0,
}
EVENT_SUBSCRIBERS = {}
EVENT_SUBSCRIBERS_LOCK = threading.Lock()
EVENT_SUBSCRIBER_SEQ = 0
EVENT_ID_SEQ = 0


class APIError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def now_ts():
    return int(time.time())


def json_dumps(payload):
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def prune_expired_sessions(reference_ts=None):
    ts = reference_ts or now_ts()
    with SESSIONS_LOCK:
        expired_tokens = [token for token, session in SESSIONS.items() if session["expires_at"] < ts]
        for token in expired_tokens:
            SESSIONS.pop(token, None)


def create_session(user_id):
    prune_expired_sessions()
    token = secrets.token_urlsafe(32)
    with SESSIONS_LOCK:
        SESSIONS[token] = {"user_id": user_id, "expires_at": now_ts() + SESSION_TTL_SECONDS}
    return token


def touch_session(token):
    with SESSIONS_LOCK:
        session = SESSIONS.get(token)
        if not session:
            return None
        if session["expires_at"] < now_ts():
            SESSIONS.pop(token, None)
            return None
        session["expires_at"] = now_ts() + SESSION_TTL_SECONDS
        return dict(session)


def session_cookie_value(token, max_age):
    secure_flag = "; Secure" if SESSION_COOKIE_SECURE else ""
    return f"session={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age}{secure_flag}"


def _login_attempt_key(login_value, client_ip):
    safe_login = (login_value or "<empty>").strip().lower() or "<empty>"
    safe_ip = (client_ip or "-").strip()
    return f"{safe_login}|{safe_ip}"


def register_login_failure(login_value, client_ip, ts=None):
    ref_ts = ts or now_ts()
    key = _login_attempt_key(login_value, client_ip)
    with LOGIN_ATTEMPTS_LOCK:
        attempts = LOGIN_ATTEMPTS.setdefault(key, deque())
        attempts.append(ref_ts)


def clear_login_failures(login_value, client_ip):
    key = _login_attempt_key(login_value, client_ip)
    with LOGIN_ATTEMPTS_LOCK:
        LOGIN_ATTEMPTS.pop(key, None)


def login_rate_limit_retry_after(login_value, client_ip, ts=None):
    ref_ts = ts or now_ts()
    key = _login_attempt_key(login_value, client_ip)
    with LOGIN_ATTEMPTS_LOCK:
        attempts = LOGIN_ATTEMPTS.get(key)
        if not attempts:
            return 0
        while attempts and attempts[0] <= ref_ts - LOGIN_RATE_LIMIT_WINDOW_SECONDS:
            attempts.popleft()
        if len(attempts) < LOGIN_RATE_LIMIT_ATTEMPTS:
            if not attempts:
                LOGIN_ATTEMPTS.pop(key, None)
            return 0
        retry_after = (attempts[0] + LOGIN_RATE_LIMIT_WINDOW_SECONDS) - ref_ts
        return max(1, retry_after)


def _next_event_id():
    global EVENT_ID_SEQ
    with EVENT_SUBSCRIBERS_LOCK:
        EVENT_ID_SEQ += 1
        return EVENT_ID_SEQ


def _register_event_subscriber(user):
    global EVENT_SUBSCRIBER_SEQ
    subscriber = {
        "id": None,
        "user_id": user["id"],
        "role": user["role"],
        "queue": deque(maxlen=SSE_SUBSCRIBER_QUEUE_MAX),
        "cond": threading.Condition(),
    }
    with EVENT_SUBSCRIBERS_LOCK:
        EVENT_SUBSCRIBER_SEQ += 1
        subscriber["id"] = EVENT_SUBSCRIBER_SEQ
        EVENT_SUBSCRIBERS[subscriber["id"]] = subscriber
    return subscriber


def _unregister_event_subscriber(subscriber):
    with EVENT_SUBSCRIBERS_LOCK:
        EVENT_SUBSCRIBERS.pop(subscriber["id"], None)
    with subscriber["cond"]:
        subscriber["cond"].notify_all()


def _customer_assigned_operator_id(customer_id):
    with db() as conn:
        row = conn.execute("select assigned_operator_id from customers where id = ?", (customer_id,)).fetchone()
    if not row:
        return None
    return row["assigned_operator_id"]


def publish_realtime_event(event_type, payload, customer_id=None):
    assigned_operator_id = None
    if customer_id is not None:
        assigned_operator_id = _customer_assigned_operator_id(customer_id)
    event = {
        "id": _next_event_id(),
        "event": event_type,
        "ts": now_ts(),
        "payload": payload,
    }
    with EVENT_SUBSCRIBERS_LOCK:
        subscribers = list(EVENT_SUBSCRIBERS.values())
    for subscriber in subscribers:
        if subscriber["role"] != "admin":
            if customer_id is None:
                continue
            if assigned_operator_id != subscriber["user_id"]:
                continue
        with subscriber["cond"]:
            subscriber["queue"].append(event)
            subscriber["cond"].notify()


def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("pragma foreign_keys = ON")
    conn.execute("pragma busy_timeout = 5000")
    return conn


def password_hash(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120000).hex()
    return f"{salt}:{digest}"


def verify_password(password, stored):
    try:
        salt, digest = stored.split(":", 1)
    except ValueError:
        return False
    attempt = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120000).hex()
    return hmac.compare_digest(attempt, digest)


def validate_password_strength(password):
    if len(password) < 8:
        return False, "Nova senha deve ter pelo menos 8 caracteres"
    if not any(ch.isalpha() for ch in password) or not any(ch.isdigit() for ch in password):
        return False, "Nova senha deve conter letras e números"
    return True, ""


def init_db():
    with db() as conn:
        conn.execute("pragma journal_mode = WAL")
        conn.execute("pragma synchronous = NORMAL")
        conn.executescript(
            """
            create table if not exists users (
                id integer primary key autoincrement,
                name text not null,
                email text not null unique,
                password_hash text not null,
                role text not null check(role in ('admin', 'operator')),
                permissions text not null default '[]',
                must_change_password integer not null default 0,
                active integer not null default 1,
                created_at integer not null
            );

            create table if not exists queues (
                id integer primary key autoincrement,
                name text not null unique,
                color text not null default '#2563eb'
            );

            create table if not exists customers (
                id integer primary key autoincrement,
                name text not null,
                phone text not null unique,
                channel text not null default 'whatsapp',
                contact_ref text,
                queue_id integer not null,
                assigned_operator_id integer,
                status text not null default 'open' check(status in ('open', 'pending', 'closed')),
                finalized integer not null default 0,
                tags text not null default '[]',
                erp_provider text,
                erp_client_code text,
                erp_financial_pending integer not null default 0,
                erp_connection_data text not null default '{}',
                last_message_at integer,
                first_response_at integer,
                closed_at integer,
                sla_due_at integer,
                created_at integer not null,
                foreign key(queue_id) references queues(id),
                foreign key(assigned_operator_id) references users(id)
            );

            create table if not exists messages (
                id integer primary key autoincrement,
                customer_id integer not null,
                direction text not null check(direction in ('inbound', 'outbound', 'system')),
                body text not null,
                status text not null default 'sent',
                external_id text,
                created_at integer not null,
                foreign key(customer_id) references customers(id)
            );

            create table if not exists audit_log (
                id integer primary key autoincrement,
                user_id integer,
                action text not null,
                details text not null,
                created_at integer not null,
                foreign key(user_id) references users(id)
            );

            create table if not exists webhook_events (
                id integer primary key autoincrement,
                event_key text not null unique,
                payload text not null,
                processed integer not null default 0,
                attempts integer not null default 0,
                last_error text,
                created_at integer not null,
                processed_at integer
            );

            create table if not exists quick_replies (
                id integer primary key autoincrement,
                shortcut text not null unique,
                body text not null,
                created_by_user_id integer,
                created_at integer not null,
                updated_at integer not null,
                foreign key(created_by_user_id) references users(id)
            );

            create table if not exists private_notes (
                id integer primary key autoincrement,
                customer_id integer not null,
                user_id integer not null,
                body text not null,
                created_at integer not null,
                foreign key(customer_id) references customers(id),
                foreign key(user_id) references users(id)
            );

            create table if not exists scheduled_messages (
                id integer primary key autoincrement,
                customer_id integer not null,
                body text not null,
                send_at integer not null,
                status text not null check(status in ('pending', 'sent', 'failed', 'cancelled')) default 'pending',
                created_by_user_id integer not null,
                external_id text,
                last_error text,
                created_at integer not null,
                sent_at integer,
                foreign key(customer_id) references customers(id),
                foreign key(created_by_user_id) references users(id)
            );

            create table if not exists media_attachments (
                id integer primary key autoincrement,
                customer_id integer not null,
                media_type text not null check(media_type in ('image', 'video', 'gif', 'sticker', 'file')),
                url text not null,
                caption text,
                direction text not null check(direction in ('inbound', 'outbound', 'system')),
                created_by_user_id integer,
                created_at integer not null,
                foreign key(customer_id) references customers(id),
                foreign key(created_by_user_id) references users(id)
            );

            create table if not exists team_messages (
                id integer primary key autoincrement,
                user_id integer not null,
                body text not null,
                created_at integer not null,
                foreign key(user_id) references users(id)
            );

            create table if not exists campaigns (
                id integer primary key autoincrement,
                name text not null,
                body text not null,
                status text not null check(status in ('pending', 'running', 'completed', 'failed')) default 'pending',
                created_by_user_id integer not null,
                scheduled_at integer,
                rate_per_minute integer not null default 120,
                created_at integer not null,
                started_at integer not null,
                finished_at integer,
                foreign key(created_by_user_id) references users(id)
            );

            create table if not exists campaign_targets (
                id integer primary key autoincrement,
                campaign_id integer not null,
                customer_id integer not null,
                status text not null check(status in ('queued', 'sent', 'failed')) default 'queued',
                last_error text,
                sent_at integer,
                foreign key(campaign_id) references campaigns(id),
                foreign key(customer_id) references customers(id)
            );

            create table if not exists customer_preferences (
                customer_id integer primary key,
                campaign_opt_out integer not null default 0,
                updated_at integer not null,
                foreign key(customer_id) references customers(id)
            );

            create table if not exists ai_suggestions (
                id integer primary key autoincrement,
                customer_id integer not null,
                user_id integer not null,
                model text not null,
                prompt text not null,
                suggestion text not null,
                latency_ms integer,
                created_at integer not null,
                foreign key(customer_id) references customers(id),
                foreign key(user_id) references users(id)
            );

            create table if not exists tma_tme_targets (
                queue_id integer primary key check(queue_id >= 0),
                tme_target_seconds integer not null,
                tma_target_seconds integer not null,
                updated_at integer not null
            );

            create index if not exists idx_customers_assigned_status
            on customers(assigned_operator_id, status);

            create index if not exists idx_customers_last_message
            on customers(last_message_at desc);

            create index if not exists idx_messages_customer_created
            on messages(customer_id, created_at, id);

            create index if not exists idx_webhook_events_processed
            on webhook_events(processed, created_at);

            create index if not exists idx_private_notes_customer_created
            on private_notes(customer_id, created_at desc, id desc);

            create index if not exists idx_scheduled_messages_due
            on scheduled_messages(status, send_at, id);

            create index if not exists idx_media_customer_created
            on media_attachments(customer_id, created_at desc, id desc);

            create index if not exists idx_team_messages_created
            on team_messages(created_at desc, id desc);

            create index if not exists idx_campaign_targets_campaign
            on campaign_targets(campaign_id, status, id);

            create index if not exists idx_ai_suggestions_customer_created
            on ai_suggestions(customer_id, created_at desc, id desc);
            """
        )

        user_cols = [row["name"] for row in conn.execute("pragma table_info(users)").fetchall()]
        if "permissions" not in user_cols:
            conn.execute("alter table users add column permissions text not null default '[]'")
        if "must_change_password" not in user_cols:
            conn.execute("alter table users add column must_change_password integer not null default 0")
        customer_cols = [row["name"] for row in conn.execute("pragma table_info(customers)").fetchall()]
        if "channel" not in customer_cols:
            conn.execute("alter table customers add column channel text not null default 'whatsapp'")
        if "contact_ref" not in customer_cols:
            conn.execute("alter table customers add column contact_ref text")
        if "finalized" not in customer_cols:
            conn.execute("alter table customers add column finalized integer not null default 0")
        if "erp_provider" not in customer_cols:
            conn.execute("alter table customers add column erp_provider text")
        if "erp_client_code" not in customer_cols:
            conn.execute("alter table customers add column erp_client_code text")
        if "erp_financial_pending" not in customer_cols:
            conn.execute("alter table customers add column erp_financial_pending integer not null default 0")
        if "erp_connection_data" not in customer_cols:
            conn.execute("alter table customers add column erp_connection_data text not null default '{}'")
        if "first_response_at" not in customer_cols:
            conn.execute("alter table customers add column first_response_at integer")
        if "closed_at" not in customer_cols:
            conn.execute("alter table customers add column closed_at integer")
        if "sla_due_at" not in customer_cols:
            conn.execute("alter table customers add column sla_due_at integer")
        webhook_cols = [row["name"] for row in conn.execute("pragma table_info(webhook_events)").fetchall()]
        if "attempts" not in webhook_cols:
            conn.execute("alter table webhook_events add column attempts integer not null default 0")
        if "last_error" not in webhook_cols:
            conn.execute("alter table webhook_events add column last_error text")
        campaign_cols = [row["name"] for row in conn.execute("pragma table_info(campaigns)").fetchall()]
        if "scheduled_at" not in campaign_cols:
            conn.execute("alter table campaigns add column scheduled_at integer")
        if "rate_per_minute" not in campaign_cols:
            conn.execute("alter table campaigns add column rate_per_minute integer not null default 120")
        campaign_targets_table = conn.execute(
            "select sql from sqlite_master where type = 'table' and name = 'campaign_targets'"
        ).fetchone()
        campaign_targets_sql = (campaign_targets_table["sql"] or "").lower() if campaign_targets_table else ""
        if campaign_targets_table and "queued" not in campaign_targets_sql:
            conn.execute("pragma foreign_keys = OFF")
            conn.executescript(
                """
                create table campaign_targets_migrated (
                    id integer primary key autoincrement,
                    campaign_id integer not null,
                    customer_id integer not null,
                    status text not null check(status in ('queued', 'sent', 'failed')) default 'queued',
                    last_error text,
                    sent_at integer,
                    foreign key(campaign_id) references campaigns(id),
                    foreign key(customer_id) references customers(id)
                );

                insert into campaign_targets_migrated (id, campaign_id, customer_id, status, last_error, sent_at)
                select
                    id,
                    campaign_id,
                    customer_id,
                    case
                        when lower(status) = 'sent' then 'sent'
                        when lower(status) = 'failed' then 'failed'
                        else 'failed'
                    end,
                    last_error,
                    sent_at
                from campaign_targets;

                drop table campaign_targets;
                alter table campaign_targets_migrated rename to campaign_targets;
                create index if not exists idx_campaign_targets_campaign
                on campaign_targets(campaign_id, status, id);
                """
            )
            conn.execute("pragma foreign_keys = ON")

        if not conn.execute("select 1 from users limit 1").fetchone():
            admin_hash = password_hash("admin123")
            ana_hash = password_hash("operador123")
            bruno_hash = password_hash("operador123")
            conn.execute(
                "insert into users (name, email, password_hash, role, permissions, must_change_password, created_at) values (?, ?, ?, ?, ?, ?, ?)",
                ("Master", "master", admin_hash, "admin", json.dumps(["billing:unlock"]), 1, now_ts()),
            )
            conn.execute(
                "insert into users (name, email, password_hash, role, permissions, must_change_password, created_at) values (?, ?, ?, ?, ?, ?, ?)",
                ("Ana Operadora", "ana@local", ana_hash, "operator", json.dumps([]), 0, now_ts()),
            )
            conn.execute(
                "insert into users (name, email, password_hash, role, permissions, must_change_password, created_at) values (?, ?, ?, ?, ?, ?, ?)",
                ("Bruno Operador", "bruno@local", bruno_hash, "operator", json.dumps(["billing:unlock"]), 0, now_ts()),
            )
            conn.executemany(
                "insert into queues (name, color) values (?, ?)",
                [("Comercial", "#0f766e"), ("Suporte", "#7c3aed"), ("Financeiro", "#b45309")],
            )
            ana_id = conn.execute("select id from users where email = 'ana@local'").fetchone()["id"]
            bruno_id = conn.execute("select id from users where email = 'bruno@local'").fetchone()["id"]
            comercial_id = conn.execute("select id from queues where name = 'Comercial'").fetchone()["id"]
            suporte_id = conn.execute("select id from queues where name = 'Suporte'").fetchone()["id"]
            customers = [
                ("Maria Souza", "5511999990001", comercial_id, ana_id, "open", '["novo"]'),
                ("Carlos Lima", "5511999990002", suporte_id, ana_id, "pending", '["vip"]'),
                ("Fernanda Rocha", "5511999990003", suporte_id, bruno_id, "open", '["urgente"]'),
            ]
            conn.executemany(
                """
                insert into customers
                (name, phone, queue_id, assigned_operator_id, status, tags, last_message_at, sla_due_at, created_at)
                values (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        c[0],
                        c[1],
                        c[2],
                        c[3],
                        c[4],
                        c[5],
                        now_ts(),
                        now_ts() + DEFAULT_SLA_FIRST_RESPONSE_SECONDS,
                        now_ts(),
                    )
                    for c in customers
                ],
            )
            for customer in conn.execute("select id, name from customers").fetchall():
                conn.execute(
                    "insert into messages (customer_id, direction, body, created_at) values (?, ?, ?, ?)",
                    (customer["id"], "inbound", f"Olá, preciso de atendimento. Cliente: {customer['name']}", now_ts()),
                )
            conn.execute(
                """
                update customers
                set erp_provider = 'ixcsoft',
                    erp_client_code = 'IXC-2001',
                    erp_financial_pending = 1,
                    erp_connection_data = ?
                where phone = '5511999990002'
                """,
                (json.dumps({"plan": "400MB", "onu_status": "online", "signal_dbm": -21}, ensure_ascii=False),),
            )
        else:
            master_row = conn.execute("select id from users where lower(email) = 'master'").fetchone()
            if not master_row:
                conn.execute(
                    "insert into users (name, email, password_hash, role, permissions, must_change_password, created_at) values (?, ?, ?, ?, ?, ?, ?)",
                    ("Master", "master", password_hash("admin123"), "admin", json.dumps(["billing:unlock"]), 1, now_ts()),
                )

        master_user = conn.execute(
            "select id, password_hash, must_change_password from users where lower(email) = 'master'"
        ).fetchone()
        if master_user and verify_password("admin123", master_user["password_hash"]):
            conn.execute("update users set must_change_password = 1 where id = ?", (master_user["id"],))

        baseline_operator_permissions = {
            "team:chat",
            "notes:write",
            "media:send",
            "schedule:manage",
            "quick_reply:send",
            "ai:suggest",
        }
        operator_rows = conn.execute(
            "select id, permissions from users where role = 'operator' and active = 1"
        ).fetchall()
        for row in operator_rows:
            merged_permissions = parse_permissions(row["permissions"] or "[]")
            merged_permissions.update(baseline_operator_permissions)
            conn.execute(
                "update users set permissions = ? where id = ?",
                (json.dumps(sorted(merged_permissions), ensure_ascii=False), row["id"]),
            )

        conn.execute(
            "update customers set sla_due_at = coalesce(sla_due_at, created_at + ?) where sla_due_at is null",
            (DEFAULT_SLA_FIRST_RESPONSE_SECONDS,),
        )
        conn.execute(
            "update customers set channel = coalesce(nullif(channel, ''), 'whatsapp')",
        )
        conn.execute(
            "update customers set contact_ref = coalesce(nullif(contact_ref, ''), phone)",
        )
        conn.execute(
            "update customers set closed_at = coalesce(closed_at, ?) where status = 'closed' and closed_at is null",
            (now_ts(),),
        )
        conn.execute(
            """
            insert into tma_tme_targets (queue_id, tme_target_seconds, tma_target_seconds, updated_at)
            values (0, ?, ?, ?)
            on conflict(queue_id) do nothing
            """,
            (DEFAULT_TME_TARGET_SECONDS, DEFAULT_TMA_TARGET_SECONDS, now_ts()),
        )


def log_action(user_id, action, details):
    with db() as conn:
        conn.execute(
            "insert into audit_log (user_id, action, details, created_at) values (?, ?, ?, ?)",
            (user_id, action, json.dumps(details, ensure_ascii=False), now_ts()),
        )


def cleanup_processed_webhooks():
    cutoff = now_ts() - WEBHOOK_PROCESSED_RETENTION_SECONDS
    with db() as conn:
        conn.execute(
            "delete from webhook_events where processed = 1 and coalesce(processed_at, created_at) < ?",
            (cutoff,),
        )


def parse_permissions(raw_value):
    try:
        parsed = json.loads(raw_value or "[]")
        if isinstance(parsed, list):
            return set(str(item) for item in parsed)
    except json.JSONDecodeError:
        pass
    return set()


def user_has_permission(user, permission):
    if not user:
        return False
    if user.get("role") == "admin":
        return True
    return permission in parse_permissions(user.get("permissions", "[]"))


def normalize_avg_seconds(value):
    if value is None:
        return 0
    return int(round(value))


def percentage(value, total):
    if not total:
        return 0.0
    return round((float(value) / float(total)) * 100.0, 2)


def load_tma_tme_targets(conn):
    rows = conn.execute(
        "select queue_id, tme_target_seconds, tma_target_seconds, updated_at from tma_tme_targets"
    ).fetchall()
    global_target = {
        "queue_id": 0,
        "tme_target_seconds": DEFAULT_TME_TARGET_SECONDS,
        "tma_target_seconds": DEFAULT_TMA_TARGET_SECONDS,
        "updated_at": None,
    }
    by_queue = {}
    for row in rows:
        queue_id = int(row["queue_id"])
        item = {
            "queue_id": queue_id,
            "tme_target_seconds": int(row["tme_target_seconds"]),
            "tma_target_seconds": int(row["tma_target_seconds"]),
            "updated_at": int(row["updated_at"]),
        }
        if queue_id == 0:
            global_target = item
        else:
            by_queue[queue_id] = item
    return global_target, by_queue


def log_structured(event, request_id, **fields):
    payload = {"event": event, "request_id": request_id, **fields}
    print(json.dumps(payload, ensure_ascii=True))


def metrics_payload():
    with WEBHOOK_COND:
        queue_depth = len(WEBHOOK_QUEUE)
    with SESSIONS_LOCK:
        active_sessions = len(SESSIONS)
    with EVENT_SUBSCRIBERS_LOCK:
        realtime_subscribers = len(EVENT_SUBSCRIBERS)
    lines = [
        "# HELP http_requests_total Total HTTP requests.",
        "# TYPE http_requests_total counter",
        f"http_requests_total {METRICS['http_requests_total']}",
        "# HELP webhook_received_total Total webhook events received.",
        "# TYPE webhook_received_total counter",
        f"webhook_received_total {METRICS['webhook_received_total']}",
        "# HELP webhook_duplicate_total Duplicate webhook events discarded.",
        "# TYPE webhook_duplicate_total counter",
        f"webhook_duplicate_total {METRICS['webhook_duplicate_total']}",
        "# HELP webhook_queue_dropped_total Webhook events dropped due to queue backpressure.",
        "# TYPE webhook_queue_dropped_total counter",
        f"webhook_queue_dropped_total {METRICS['webhook_queue_dropped_total']}",
        "# HELP webhook_reprocessed_total Webhook events reprocessed from queue.",
        "# TYPE webhook_reprocessed_total counter",
        f"webhook_reprocessed_total {METRICS['webhook_reprocessed_total']}",
        "# HELP webhook_failed_total Webhook events failed during processing.",
        "# TYPE webhook_failed_total counter",
        f"webhook_failed_total {METRICS['webhook_failed_total']}",
        "# HELP webhook_dead_lettered_total Webhook events moved out after max processing attempts.",
        "# TYPE webhook_dead_lettered_total counter",
        f"webhook_dead_lettered_total {METRICS['webhook_dead_lettered_total']}",
        "# HELP messages_processed_total Inbound messages processed by worker.",
        "# TYPE messages_processed_total counter",
        f"messages_processed_total {METRICS['messages_processed_total']}",
        "# HELP scheduled_processed_total Scheduled messages processed.",
        "# TYPE scheduled_processed_total counter",
        f"scheduled_processed_total {METRICS['scheduled_processed_total']}",
        "# HELP scheduled_failed_total Scheduled messages failed.",
        "# TYPE scheduled_failed_total counter",
        f"scheduled_failed_total {METRICS['scheduled_failed_total']}",
        "# HELP login_rate_limited_total Login requests rejected by rate limiting.",
        "# TYPE login_rate_limited_total counter",
        f"login_rate_limited_total {METRICS['login_rate_limited_total']}",
        "# HELP active_sessions Total active authenticated sessions.",
        "# TYPE active_sessions gauge",
        f"active_sessions {active_sessions}",
        "# HELP webhook_queue_depth Current in-memory webhook queue depth.",
        "# TYPE webhook_queue_depth gauge",
        f"webhook_queue_depth {queue_depth}",
        "# HELP realtime_subscribers Active SSE realtime subscribers.",
        "# TYPE realtime_subscribers gauge",
        f"realtime_subscribers {realtime_subscribers}",
    ]
    return "\n".join(lines) + "\n"


class EvolutionClient:
    def configured(self):
        return bool(EVOLUTION_BASE_URL and EVOLUTION_API_KEY)

    def request(self, method, path, payload=None):
        if not self.configured():
            raise RuntimeError("Evolution API não configurada. Defina EVOLUTION_BASE_URL e EVOLUTION_API_KEY.")
        url = f"{EVOLUTION_BASE_URL}{path}"
        body = None if payload is None else json_dumps(payload)
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("apikey", EVOLUTION_API_KEY)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                data = response.read().decode("utf-8")
                return json.loads(data) if data else {}
        except urllib.error.HTTPError as exc:
            message = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Evolution API retornou {exc.code}: {message}") from exc

    def create_instance(self):
        return self.request(
            "POST",
            "/instance/create",
            {"instanceName": EVOLUTION_INSTANCE, "qrcode": True, "integration": "WHATSAPP-BAILEYS"},
        )

    def set_webhook(self, public_url):
        return self.request(
            "POST",
            f"/webhook/set/{EVOLUTION_INSTANCE}",
            {
                "url": f"{public_url.rstrip('/')}/api/webhook/evolution",
                "webhook_by_events": False,
                "webhook_base64": False,
                "events": ["MESSAGES_UPSERT", "CONNECTION_UPDATE"],
            },
        )

    def send_text(self, phone, text):
        return self.request("POST", f"/message/sendText/{EVOLUTION_INSTANCE}", {"number": phone, "text": text})


evolution = EvolutionClient()


def extract_response_output_text(response_payload):
    text = str(response_payload.get("output_text") or "").strip()
    if text:
        return text
    output_items = response_payload.get("output") or []
    for output_item in output_items:
        if output_item.get("type") != "message":
            continue
        for content in output_item.get("content") or []:
            maybe_text = content.get("text")
            if isinstance(maybe_text, str) and maybe_text.strip():
                return maybe_text.strip()
            if isinstance(maybe_text, dict):
                value = maybe_text.get("value")
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return ""


def generate_ai_suggestion(customer_name, conversation_text):
    if not OPENAI_API_KEY:
        raise RuntimeError("OPENAI_API_KEY nÃ£o configurada")
    system_prompt = (
        "VocÃª Ã© assistente de suporte de um call center WhatsApp. "
        "Responda em portuguÃªs do Brasil, com objetividade, empatia e tom profissional. "
        "NÃ£o invente informaÃ§Ãµes; se faltar contexto, diga quais dados faltam. "
        "Retorne apenas o texto sugerido para o operador enviar ao cliente."
    )
    request_payload = {
        "model": OPENAI_MODEL,
        "input": [
            {
                "role": "system",
                "content": [{"type": "input_text", "text": system_prompt}],
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": f"Cliente: {customer_name}\n\nHistÃ³rico recente:\n{conversation_text}",
                    }
                ],
            },
        ],
        "max_output_tokens": 240,
    }
    req = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(request_payload, ensure_ascii=False).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
        },
    )
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=25) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Erro OpenAI HTTP {exc.code}: {detail[:240]}")
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Falha de rede OpenAI: {exc}")
    parsed = json.loads(raw)
    suggestion = extract_response_output_text(parsed)
    if not suggestion:
        raise RuntimeError("OpenAI retornou resposta sem texto utilizÃ¡vel")
    latency_ms = int((time.time() - started) * 1000)
    return suggestion, latency_ms


def store_uploaded_file(filename, content_bytes):
    if not content_bytes:
        raise ValueError("arquivo vazio")
    if len(content_bytes) > MAX_UPLOAD_BYTES:
        raise ValueError(f"arquivo excede limite de {MAX_UPLOAD_BYTES} bytes")
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    safe_ext = Path(str(filename or "")).suffix.lower()
    if safe_ext not in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".txt", ".mp4", ".webm", ".ogg"}:
        safe_ext = ".bin"
    file_name = f"{now_ts()}_{uuid.uuid4().hex}{safe_ext}"
    target = UPLOADS_DIR / file_name
    target.write_bytes(content_bytes)
    return f"/uploads/{file_name}"


def dispatch_outbound_text(channel, contact_ref, text):
    external_id = None
    if channel == "whatsapp":
        status = "sent"
        if evolution.configured():
            response = evolution.send_text(contact_ref, text)
            external_id = str(response.get("key", {}).get("id") or response.get("messageId") or "")
        return status, external_id
    status = f"local:{channel}_integration_pending"
    return status, external_id


def process_due_scheduled_messages(limit=50):
    now = now_ts()
    processed = 0
    with db() as conn:
        rows = conn.execute(
            """
            select id, customer_id, body, send_at
            from scheduled_messages
            where status = 'pending' and send_at <= ?
            order by send_at asc, id asc
            limit ?
            """,
            (now, limit),
        ).fetchall()
        for row in rows:
            customer = conn.execute(
                "select id, phone, channel, contact_ref, finalized from customers where id = ?",
                (row["customer_id"],),
            ).fetchone()
            if not customer:
                conn.execute(
                    "update scheduled_messages set status = 'failed', last_error = ?, sent_at = ? where id = ?",
                    ("customer_not_found", now, row["id"]),
                )
                METRICS["scheduled_failed_total"] += 1
                continue
            if customer["finalized"]:
                conn.execute(
                    "update scheduled_messages set status = 'cancelled', last_error = ?, sent_at = ? where id = ?",
                    ("customer_finalized", now, row["id"]),
                )
                continue
            try:
                channel = normalize_channel(customer["channel"] or "whatsapp") or "whatsapp"
                contact_ref = customer["contact_ref"] or customer["phone"]
                status, external_id = dispatch_outbound_text(channel, contact_ref, row["body"])
                send_ts = now_ts()
                conn.execute(
                    """
                    insert into messages (customer_id, direction, body, status, external_id, created_at)
                    values (?, 'outbound', ?, ?, ?, ?)
                    """,
                    (row["customer_id"], row["body"], status, external_id, send_ts),
                )
                conn.execute(
                    "update customers set last_message_at = ?, first_response_at = coalesce(first_response_at, ?) where id = ?",
                    (send_ts, send_ts, row["customer_id"]),
                )
                conn.execute(
                    "update scheduled_messages set status = 'sent', external_id = ?, sent_at = ?, last_error = null where id = ?",
                    (external_id, send_ts, row["id"]),
                )
                METRICS["scheduled_processed_total"] += 1
                processed += 1
                publish_realtime_event(
                    "ticket.updated",
                    {"customer_id": row["customer_id"], "kind": "scheduled_message_sent"},
                    customer_id=row["customer_id"],
                )
            except Exception as exc:
                conn.execute(
                    "update scheduled_messages set status = 'failed', last_error = ?, sent_at = ? where id = ?",
                    (str(exc), now_ts(), row["id"]),
                )
                METRICS["scheduled_failed_total"] += 1
                log_structured("scheduled.failed", "-", scheduled_id=row["id"], error=str(exc))
    return processed


def process_pending_campaign_dispatches(limit_campaigns=3):
    now = now_ts()
    dispatched = 0
    with db() as conn:
        campaigns = conn.execute(
            """
            select id, body, status, rate_per_minute
            from campaigns
            where status in ('pending', 'running')
              and (scheduled_at is null or scheduled_at <= ?)
            order by created_at asc, id asc
            limit ?
            """,
            (now, limit_campaigns),
        ).fetchall()
        for campaign in campaigns:
            campaign_id = int(campaign["id"])
            if campaign["status"] == "pending":
                conn.execute(
                    "update campaigns set status = 'running', started_at = ? where id = ? and status = 'pending'",
                    (now_ts(), campaign_id),
                )
            rate_per_minute = int(campaign["rate_per_minute"] or 120)
            rate_per_minute = max(1, min(rate_per_minute, 600))
            dispatch_window = max(1, int((rate_per_minute * SCHEDULE_WORKER_POLL_SECONDS) / 60))
            targets = conn.execute(
                """
                select ct.id, ct.customer_id
                from campaign_targets ct
                where ct.campaign_id = ? and ct.status = 'queued'
                order by ct.id asc
                limit ?
                """,
                (campaign_id, dispatch_window),
            ).fetchall()
            for target in targets:
                target_id = int(target["id"])
                customer_id = int(target["customer_id"])
                customer = conn.execute(
                    "select id, phone, channel, contact_ref, finalized from customers where id = ?",
                    (customer_id,),
                ).fetchone()
                pref = conn.execute(
                    "select campaign_opt_out from customer_preferences where customer_id = ?",
                    (customer_id,),
                ).fetchone()
                if not customer:
                    conn.execute(
                        "update campaign_targets set status = 'failed', last_error = ?, sent_at = ? where id = ?",
                        ("customer_not_found", now_ts(), target_id),
                    )
                    continue
                if customer["finalized"]:
                    conn.execute(
                        "update campaign_targets set status = 'failed', last_error = ?, sent_at = ? where id = ?",
                        ("customer_finalized", now_ts(), target_id),
                    )
                    continue
                if pref and int(pref["campaign_opt_out"] or 0) == 1:
                    conn.execute(
                        "update campaign_targets set status = 'failed', last_error = ?, sent_at = ? where id = ?",
                        ("campaign_opt_out", now_ts(), target_id),
                    )
                    continue
                try:
                    channel = normalize_channel(customer["channel"] or "whatsapp") or "whatsapp"
                    contact_ref = customer["contact_ref"] or customer["phone"]
                    status, external_id = dispatch_outbound_text(channel, contact_ref, campaign["body"])
                    send_ts = now_ts()
                    conn.execute(
                        """
                        insert into messages (customer_id, direction, body, status, external_id, created_at)
                        values (?, 'outbound', ?, ?, ?, ?)
                        """,
                        (customer_id, campaign["body"], status, external_id, send_ts),
                    )
                    conn.execute(
                        "update customers set last_message_at = ?, first_response_at = coalesce(first_response_at, ?) where id = ?",
                        (send_ts, send_ts, customer_id),
                    )
                    conn.execute(
                        "update campaign_targets set status = 'sent', last_error = null, sent_at = ? where id = ?",
                        (send_ts, target_id),
                    )
                    dispatched += 1
                    publish_realtime_event(
                        "ticket.updated",
                        {"customer_id": customer_id, "kind": "campaign_message_sent", "campaign_id": campaign_id},
                        customer_id=customer_id,
                    )
                except Exception as exc:
                    conn.execute(
                        "update campaign_targets set status = 'failed', last_error = ?, sent_at = ? where id = ?",
                        (str(exc), now_ts(), target_id),
                    )
            pending_left = conn.execute(
                "select count(*) total from campaign_targets where campaign_id = ? and status = 'queued'",
                (campaign_id,),
            ).fetchone()["total"]
            if int(pending_left or 0) == 0:
                stats = conn.execute(
                    """
                    select
                        sum(case when status = 'sent' then 1 else 0 end) sent_total,
                        sum(case when status = 'failed' then 1 else 0 end) failed_total
                    from campaign_targets
                    where campaign_id = ?
                    """,
                    (campaign_id,),
                ).fetchone()
                final_status = "completed" if int(stats["sent_total"] or 0) > 0 else "failed"
                conn.execute(
                    "update campaigns set status = ?, finished_at = ? where id = ?",
                    (final_status, now_ts(), campaign_id),
                )
    return dispatched


def process_inbound_payload(payload):
    data = payload.get("data", payload)
    message = data.get("message", {})
    key = data.get("key", {})
    remote = key.get("remoteJid") or data.get("remoteJid") or ""
    phone = only_digits(remote.split("@")[0])
    text = (
        message.get("conversation")
        or message.get("extendedTextMessage", {}).get("text")
        or data.get("text")
        or ""
    )
    if not phone or not text:
        return False
    with db() as conn:
        customer = conn.execute("select id from customers where phone = ?", (phone,)).fetchone()
        created_new_customer = False
        if not customer:
            queue_id = conn.execute("select id from queues order by id limit 1").fetchone()["id"]
            operator = conn.execute(
                """
                select u.id, count(c.id) load
                from users u
                left join customers c on c.assigned_operator_id = u.id and c.status != 'closed'
                where u.role = 'operator' and u.active = 1
                group by u.id
                order by load asc, u.id asc
                limit 1
                """
            ).fetchone()
            cursor = conn.execute(
                """
                insert into customers
                (name, phone, channel, contact_ref, queue_id, assigned_operator_id, status, last_message_at, sla_due_at, created_at)
                values (?, ?, 'whatsapp', ?, ?, ?, 'open', ?, ?, ?)
                """,
                (
                    phone,
                    phone,
                    phone,
                    queue_id,
                    operator["id"] if operator else None,
                    now_ts(),
                    now_ts() + DEFAULT_SLA_FIRST_RESPONSE_SECONDS,
                    now_ts(),
                ),
            )
            customer_id = cursor.lastrowid
            created_new_customer = True
        else:
            customer_id = customer["id"]
        conn.execute(
            "insert into messages (customer_id, direction, body, external_id, created_at) values (?, 'inbound', ?, ?, ?)",
            (customer_id, text, str(key.get("id") or ""), now_ts()),
        )
        conn.execute(
            """
            update customers
            set status = 'open',
                finalized = 0,
                closed_at = null,
                last_message_at = ?,
                sla_due_at = coalesce(sla_due_at, ?)
            where id = ?
            """,
            (now_ts(), now_ts() + DEFAULT_SLA_FIRST_RESPONSE_SECONDS, customer_id),
        )
    METRICS["messages_processed_total"] += 1
    publish_realtime_event(
        "ticket.updated",
        {
            "customer_id": customer_id,
            "source": "webhook",
            "kind": "inbound_message",
            "created_new_customer": created_new_customer,
        },
        customer_id=customer_id,
    )
    return True


def next_pending_webhook_event():
    with db() as conn:
        row = conn.execute(
            """
            select event_key, payload, attempts
            from webhook_events
            where processed = 0
            order by id asc
            limit 1
            """
        ).fetchone()
    if not row:
        return None
    try:
        payload = json.loads(row["payload"])
    except json.JSONDecodeError:
        with db() as conn:
            conn.execute(
                "update webhook_events set processed = 1, processed_at = ?, attempts = attempts + 1, last_error = ? where event_key = ?",
                (now_ts(), "invalid_json_payload", row["event_key"]),
            )
        METRICS["webhook_failed_total"] += 1
        log_structured("webhook.invalid_payload", "-", event_key=row["event_key"])
        return None
    return row["event_key"], payload, row["attempts"]


def webhook_worker():
    processed_since_cleanup = 0
    while True:
        event_key = None
        payload = None
        attempts = 0
        with WEBHOOK_COND:
            if not WEBHOOK_QUEUE:
                WEBHOOK_COND.wait(timeout=1)
            if WEBHOOK_QUEUE:
                event_key, payload = WEBHOOK_QUEUE.popleft()
        if not event_key:
            pending = next_pending_webhook_event()
            if not pending:
                continue
            event_key, payload, attempts = pending
        try:
            METRICS["webhook_reprocessed_total"] += 1
            ok = process_inbound_payload(payload)
            with db() as conn:
                conn.execute(
                    "update webhook_events set processed = 1, processed_at = ?, last_error = null where event_key = ?",
                    (now_ts(), event_key),
                )
            if ok:
                log_structured("webhook.processed", "-", event_key=event_key)
            else:
                log_structured("webhook.ignored", "-", event_key=event_key)
            processed_since_cleanup += 1
            if processed_since_cleanup >= 100:
                cleanup_processed_webhooks()
                processed_since_cleanup = 0
        except Exception as exc:
            METRICS["webhook_failed_total"] += 1
            with db() as conn:
                conn.execute(
                    "update webhook_events set attempts = attempts + 1, last_error = ? where event_key = ? and processed = 0",
                    (str(exc), event_key),
                )
                row = conn.execute(
                    "select attempts from webhook_events where event_key = ?",
                    (event_key,),
                ).fetchone()
                current_attempts = row["attempts"] if row else (attempts + 1)
                if current_attempts >= WEBHOOK_MAX_ATTEMPTS:
                    conn.execute(
                        "update webhook_events set processed = 1, processed_at = ? where event_key = ?",
                        (now_ts(), event_key),
                    )
                    METRICS["webhook_dead_lettered_total"] += 1
                    log_structured(
                        "webhook.dead_lettered",
                        "-",
                        event_key=event_key,
                        attempts=current_attempts,
                        max_attempts=WEBHOOK_MAX_ATTEMPTS,
                    )
            log_structured("webhook.failed", "-", event_key=event_key, error=str(exc))
            time.sleep(0.2)


def scheduled_messages_worker():
    while True:
        try:
            process_due_scheduled_messages(limit=50)
            process_pending_campaign_dispatches(limit_campaigns=3)
        except Exception as exc:
            log_structured("scheduled.worker_error", "-", error=str(exc))
        time.sleep(SCHEDULE_WORKER_POLL_SECONDS)


class Handler(BaseHTTPRequestHandler):
    server_version = "OmniChannel/1.0"

    def log_message(self, fmt, *args):
        return

    def send_json(self, payload, status=HTTPStatus.OK, extra_headers=None):
        body = json_dumps(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("X-Request-ID", self.request_id)
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, str(value))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, path):
        if not path.exists() or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        guessed_type, _ = mimetypes.guess_type(str(path))
        content_type = guessed_type or "application/octet-stream"
        if content_type.startswith("text/") or path.suffix in {".js", ".mjs", ".json"}:
            content_type = f"{content_type}; charset=utf-8"
        body = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Request-ID", self.request_id)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_metrics(self):
        body = metrics_payload().encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("X-Request-ID", self.request_id)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_sse_event(self, event_name, payload, event_id=None):
        lines = []
        if event_id is not None:
            lines.append(f"id: {event_id}\n")
        if event_name:
            lines.append(f"event: {event_name}\n")
        data = json.dumps(payload, ensure_ascii=False)
        for line in data.splitlines() or [""]:
            lines.append(f"data: {line}\n")
        lines.append("\n")
        self.wfile.write("".join(lines).encode("utf-8"))
        self.wfile.flush()

    def api_events_stream(self):
        user = self.current_user()
        if not user:
            self.send_json({"error": "Não autenticado"}, HTTPStatus.UNAUTHORIZED)
            return
        subscriber = _register_event_subscriber(user)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("X-Request-ID", self.request_id)
        self.end_headers()
        try:
            self.wfile.write(b"retry: 3000\n\n")
            self.wfile.flush()
            self.send_sse_event("ready", {"ok": True, "ts": now_ts()}, _next_event_id())
            while True:
                event = None
                with subscriber["cond"]:
                    if not subscriber["queue"]:
                        subscriber["cond"].wait(timeout=SSE_KEEPALIVE_SECONDS)
                    if subscriber["queue"]:
                        event = subscriber["queue"].popleft()
                if event:
                    self.send_sse_event(event["event"], event["payload"], event["id"])
                else:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
            pass
        finally:
            _unregister_event_subscriber(subscriber)

    def _extract_customer_id(self, path, action):
        parts = path.strip("/").split("/")
        if len(parts) != 4 or parts[0] != "api" or parts[1] != "customers" or parts[3] != action:
            return False, None
        try:
            customer_id = int(parts[2])
            if customer_id <= 0:
                raise ValueError
        except ValueError:
            self.send_json({"error": "ID de cliente inválido"}, HTTPStatus.BAD_REQUEST)
            return True, None
        return True, customer_id

    def _extract_scheduled_message_id(self, path, action):
        parts = path.strip("/").split("/")
        if len(parts) != 4 or parts[0] != "api" or parts[1] != "scheduled-messages" or parts[3] != action:
            return False, None
        try:
            scheduled_message_id = int(parts[2])
            if scheduled_message_id <= 0:
                raise ValueError
        except ValueError:
            self.send_json({"error": "ID de agendamento invÃ¡lido"}, HTTPStatus.BAD_REQUEST)
            return True, None
        return True, scheduled_message_id

    def _extract_campaign_id(self, path, action):
        parts = path.strip("/").split("/")
        if len(parts) != 4 or parts[0] != "api" or parts[1] != "campaigns" or parts[3] != action:
            return False, None
        try:
            campaign_id = int(parts[2])
            if campaign_id <= 0:
                raise ValueError
        except ValueError:
            self.send_json({"error": "ID de campanha invÃ¡lido"}, HTTPStatus.BAD_REQUEST)
            return True, None
        return True, campaign_id

    def client_ip(self):
        forwarded = self.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",", 1)[0].strip()
        return self.client_address[0]

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise APIError(HTTPStatus.BAD_REQUEST, "Content-Length inválido")
        if length < 0:
            raise APIError(HTTPStatus.BAD_REQUEST, "Content-Length inválido")
        if length > MAX_JSON_BYTES:
            raise APIError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Payload excede limite permitido")
        if length == 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            raise APIError(HTTPStatus.BAD_REQUEST, "JSON inválido")
        if not isinstance(payload, dict):
            raise APIError(HTTPStatus.BAD_REQUEST, "JSON precisa ser um objeto")
        return payload

    def current_user(self):
        cookie_header = self.headers.get("Cookie", "")
        cookie = SimpleCookie(cookie_header)
        token = cookie.get("session")
        if not token:
            return None
        session = touch_session(token.value)
        if not session:
            return None
        with db() as conn:
            user = conn.execute(
                "select id, name, email, role, permissions, must_change_password, active from users where id = ? and active = 1",
                (session["user_id"],),
            ).fetchone()
            if user:
                return dict(user)
        with SESSIONS_LOCK:
            SESSIONS.pop(token.value, None)
        return None

    def require_user(self):
        user = self.current_user()
        if not user:
            self.send_json({"error": "Não autenticado"}, HTTPStatus.UNAUTHORIZED)
            return None
        current_path = urlparse(self.path).path
        allow_while_pending = {"/api/change-password", "/api/logout", "/api/me"}
        if user.get("must_change_password") and current_path not in allow_while_pending:
            self.send_json(
                {
                    "error": "Senha padrão detectada. Altere a senha para continuar.",
                    "must_change_password": True,
                },
                HTTPStatus.PRECONDITION_REQUIRED,
            )
            return None
        return user

    def visible_customer_clause(self, user, alias="c"):
        if user["role"] == "admin":
            return "1 = 1", []
        return f"{alias}.assigned_operator_id = ?", [user["id"]]

    def require_customer_access(self, user, customer_id):
        with db() as conn:
            row = conn.execute(
                "select id, assigned_operator_id from customers where id = ?",
                (customer_id,),
            ).fetchone()
        if not row:
            self.send_json({"error": "Cliente não encontrado"}, HTTPStatus.NOT_FOUND)
            return None
        if user["role"] != "admin" and row["assigned_operator_id"] != user["id"]:
            self.send_json({"error": "Cliente fora da sua fila"}, HTTPStatus.FORBIDDEN)
            return None
        return dict(row)

    def do_GET(self):
        self.request_id = self.headers.get("X-Request-ID") or str(uuid.uuid4())
        prune_expired_sessions()
        METRICS["http_requests_total"] += 1
        log_structured("http.request", self.request_id, method="GET", path=self.path)
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/health":
                with db() as conn:
                    conn.execute("select 1").fetchone()
                    pending_webhooks = conn.execute(
                        "select count(*) total from webhook_events where processed = 0"
                    ).fetchone()["total"]
                    pending_scheduled = conn.execute(
                        "select count(*) total from scheduled_messages where status = 'pending'"
                    ).fetchone()["total"]
                with WEBHOOK_COND:
                    queue_depth = len(WEBHOOK_QUEUE)
                with EVENT_SUBSCRIBERS_LOCK:
                    realtime_subscribers = len(EVENT_SUBSCRIBERS)
                self.send_json(
                    {
                        "ok": True,
                        "ts": now_ts(),
                        "queue_depth": queue_depth,
                        "pending_webhooks": pending_webhooks,
                        "pending_scheduled_messages": pending_scheduled,
                        "max_webhook_queue_size": MAX_WEBHOOK_QUEUE_SIZE,
                        "realtime_subscribers": realtime_subscribers,
                    }
                )
                return
            if path == "/metrics":
                self.send_metrics()
                return
            if path == "/":
                self.send_file(STATIC_DIR / "index.html")
                return
            if path.startswith("/static/"):
                safe = Path(path.replace("/static/", "", 1))
                if ".." in safe.parts:
                    self.send_error(HTTPStatus.BAD_REQUEST)
                    return
                self.send_file(STATIC_DIR / safe)
                return
            if path.startswith("/uploads/"):
                safe = Path(path.replace("/uploads/", "", 1))
                if ".." in safe.parts:
                    self.send_error(HTTPStatus.BAD_REQUEST)
                    return
                self.send_file(UPLOADS_DIR / safe)
                return
            if path == "/api/me":
                user = self.current_user()
                self.send_json({"user": user})
                return
            if path == "/api/customers":
                self.api_customers(parsed)
                return
            matched, customer_id = self._extract_customer_id(path, "messages")
            if matched:
                if customer_id is not None:
                    self.api_messages(customer_id)
                return
            matched, customer_id = self._extract_customer_id(path, "notes")
            if matched:
                if customer_id is not None:
                    self.api_private_notes(customer_id)
                return
            matched, customer_id = self._extract_customer_id(path, "scheduled-messages")
            if matched:
                if customer_id is not None:
                    self.api_scheduled_messages(customer_id)
                return
            matched, customer_id = self._extract_customer_id(path, "media")
            if matched:
                if customer_id is not None:
                    self.api_customer_media(customer_id)
                return
            matched, customer_id = self._extract_customer_id(path, "erp")
            if matched:
                if customer_id is not None:
                    self.api_customer_erp(customer_id)
                return
            if path == "/api/operators":
                self.api_operators()
                return
            if path == "/api/queues":
                self.api_queues()
                return
            if path == "/api/quick-replies":
                self.api_quick_replies()
                return
            if path == "/api/team-messages":
                self.api_team_messages()
                return
            if path == "/api/campaigns":
                self.api_campaigns()
                return
            matched, campaign_id = self._extract_campaign_id(path, "export")
            if matched:
                if campaign_id is not None:
                    self.api_export_campaign_csv(campaign_id)
                return
            if path == "/api/dashboard":
                self.api_dashboard()
                return
            if path == "/api/sla":
                self.api_sla()
                return
            if path == "/api/tma-tme":
                self.api_tma_tme(parsed)
                return
            if path == "/api/tma-tme/targets":
                self.api_tma_tme_targets()
                return
            if path == "/api/dashboard/intelligence":
                self.api_dashboard_intelligence()
                return
            if path == "/api/evolution/status":
                self.api_evolution_status()
                return
            if path == "/api/events":
                self.api_events_stream()
                return
            self.send_error(HTTPStatus.NOT_FOUND)
        except APIError as exc:
            self.send_json({"error": exc.message}, exc.status)
        except Exception as exc:
            log_structured("http.error", self.request_id, method="GET", path=self.path, error=str(exc))
            self.send_json({"error": "Erro interno"}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self):
        self.request_id = self.headers.get("X-Request-ID") or str(uuid.uuid4())
        prune_expired_sessions()
        METRICS["http_requests_total"] += 1
        log_structured("http.request", self.request_id, method="POST", path=self.path)
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/api/login":
                self.api_login()
                return
            if path == "/api/logout":
                self.api_logout()
                return
            if path == "/api/customers":
                self.api_create_customer()
                return
            matched, customer_id = self._extract_customer_id(path, "messages")
            if matched:
                if customer_id is not None:
                    self.api_send_message(customer_id)
                return
            matched, customer_id = self._extract_customer_id(path, "quick-reply")
            if matched:
                if customer_id is not None:
                    self.api_send_quick_reply(customer_id)
                return
            matched, customer_id = self._extract_customer_id(path, "notes")
            if matched:
                if customer_id is not None:
                    self.api_add_private_note(customer_id)
                return
            matched, customer_id = self._extract_customer_id(path, "schedule-message")
            if matched:
                if customer_id is not None:
                    self.api_schedule_message(customer_id)
                return
            matched, customer_id = self._extract_customer_id(path, "media")
            if matched:
                if customer_id is not None:
                    self.api_send_media(customer_id)
                return
            matched, customer_id = self._extract_customer_id(path, "media-upload")
            if matched:
                if customer_id is not None:
                    self.api_upload_media_file(customer_id)
                return
            matched, customer_id = self._extract_customer_id(path, "campaign-opt-out")
            if matched:
                if customer_id is not None:
                    self.api_set_campaign_opt_out(customer_id)
                return
            matched, customer_id = self._extract_customer_id(path, "ai-suggest")
            if matched:
                if customer_id is not None:
                    self.api_ai_suggest(customer_id)
                return
            matched, customer_id = self._extract_customer_id(path, "assign")
            if matched:
                if customer_id is not None:
                    self.api_assign_customer(customer_id)
                return
            matched, customer_id = self._extract_customer_id(path, "status")
            if matched:
                if customer_id is not None:
                    self.api_update_status(customer_id)
                return
            matched, customer_id = self._extract_customer_id(path, "transfer")
            if matched:
                if customer_id is not None:
                    self.api_transfer_customer(customer_id)
                return
            matched, customer_id = self._extract_customer_id(path, "finalize")
            if matched:
                if customer_id is not None:
                    self.api_finalize_customer(customer_id)
                return
            matched, customer_id = self._extract_customer_id(path, "send-boleto")
            if matched:
                if customer_id is not None:
                    self.api_send_boleto(customer_id)
                return
            matched, customer_id = self._extract_customer_id(path, "unlock-billing")
            if matched:
                if customer_id is not None:
                    self.api_unlock_billing(customer_id)
                return
            if path == "/api/evolution/create-instance":
                self.api_create_instance()
                return
            if path == "/api/evolution/set-webhook":
                self.api_set_webhook()
                return
            if path == "/api/quick-replies":
                self.api_upsert_quick_reply()
                return
            if path == "/api/team-messages":
                self.api_post_team_message()
                return
            if path == "/api/campaigns":
                self.api_create_campaign()
                return
            matched, scheduled_message_id = self._extract_scheduled_message_id(path, "cancel")
            if matched:
                if scheduled_message_id is not None:
                    self.api_cancel_scheduled_message(scheduled_message_id)
                return
            if path == "/api/webhook/evolution":
                self.api_webhook_evolution()
                return
            if path == "/api/webhook/inbound":
                self.api_webhook_inbound()
                return
            if path == "/api/webhook/reprocess":
                self.api_reprocess_webhooks()
                return
            if path == "/api/change-password":
                self.api_change_password()
                return
            if path == "/api/tma-tme/targets":
                self.api_update_tma_tme_targets()
                return
            self.send_error(HTTPStatus.NOT_FOUND)
        except APIError as exc:
            self.send_json({"error": exc.message}, exc.status)
        except Exception as exc:
            log_structured("http.error", self.request_id, method="POST", path=self.path, error=str(exc))
            self.send_json({"error": "Erro interno"}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def api_login(self):
        payload = self.read_json()
        login_value = (payload.get("email") or payload.get("username") or "").strip().lower()
        retry_after = login_rate_limit_retry_after(login_value, self.client_ip())
        if retry_after:
            METRICS["login_rate_limited_total"] += 1
            self.send_json(
                {"error": "Muitas tentativas de login. Aguarde para tentar novamente."},
                HTTPStatus.TOO_MANY_REQUESTS,
                extra_headers={"Retry-After": retry_after},
            )
            return
        with db() as conn:
            user = conn.execute(
                "select id, name, email, password_hash, role, permissions, must_change_password, active from users where lower(email) = ? or lower(name) = ?",
                (login_value, login_value),
            ).fetchone()
        if not user or not user["active"] or not verify_password(payload.get("password", ""), user["password_hash"]):
            register_login_failure(login_value, self.client_ip())
            self.send_json({"error": "E-mail ou senha inválidos"}, HTTPStatus.UNAUTHORIZED)
            return
        clear_login_failures(login_value, self.client_ip())
        token = create_session(user["id"])
        body = json_dumps(
            {
                "user": {
                    k: user[k]
                    for k in ("id", "name", "email", "role", "permissions", "must_change_password")
                }
            }
        )
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("X-Request-ID", self.request_id)
        self.send_header("Set-Cookie", session_cookie_value(token, SESSION_TTL_SECONDS))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def api_logout(self):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        token = cookie.get("session")
        if token:
            with SESSIONS_LOCK:
                SESSIONS.pop(token.value, None)
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("X-Request-ID", self.request_id)
        self.send_header("Set-Cookie", session_cookie_value("", 0))
        self.end_headers()

    def api_change_password(self):
        user = self.require_user()
        if not user:
            return
        payload = self.read_json()
        old_password = payload.get("old_password", "")
        new_password = payload.get("new_password", "")
        valid, message = validate_password_strength(new_password)
        if not valid:
            self.send_json({"error": message}, HTTPStatus.BAD_REQUEST)
            return
        with db() as conn:
            row = conn.execute(
                "select password_hash from users where id = ?",
                (user["id"],),
            ).fetchone()
            if not row or not verify_password(old_password, row["password_hash"]):
                self.send_json({"error": "Senha atual inválida"}, HTTPStatus.UNAUTHORIZED)
                return
            if verify_password(new_password, row["password_hash"]):
                self.send_json({"error": "Nova senha deve ser diferente da atual"}, HTTPStatus.BAD_REQUEST)
                return
            conn.execute(
                "update users set password_hash = ?, must_change_password = 0 where id = ?",
                (password_hash(new_password), user["id"]),
            )
        log_action(user["id"], "user.password_changed", {"user_id": user["id"]})
        self.send_json({"ok": True})

    def api_customers(self, parsed):
        user = self.require_user()
        if not user:
            return
        query = parse_qs(parsed.query)
        search = f"%{query.get('q', [''])[0].strip()}%"
        status = query.get("status", [""])[0].strip()
        channel_filter = query.get("channel", [""])[0].strip()
        if status and status not in {"open", "pending", "closed"}:
            self.send_json({"error": "Filtro de status inválido"}, HTTPStatus.BAD_REQUEST)
            return
        if channel_filter:
            channel_filter = normalize_channel(channel_filter)
            if not channel_filter:
                self.send_json({"error": "Filtro de canal inválido"}, HTTPStatus.BAD_REQUEST)
                return
        try:
            limit = int(query.get("limit", ["100"])[0])
            offset = int(query.get("offset", ["0"])[0])
        except ValueError:
            self.send_json({"error": "Parâmetros limit/offset inválidos"}, HTTPStatus.BAD_REQUEST)
            return
        limit = max(1, min(limit, 200))
        offset = max(0, offset)
        clause, params = self.visible_customer_clause(user)
        filters = [clause, "(c.name like ? or c.phone like ? or coalesce(c.contact_ref, '') like ?)"]
        params.extend([search, search, search])
        if status:
            filters.append("c.status = ?")
            params.append(status)
        if channel_filter:
            filters.append("c.channel = ?")
            params.append(channel_filter)
        where_sql = " and ".join(filters)
        params.extend([limit, offset])
        with db() as conn:
            rows = conn.execute(
                f"""
                select c.*, q.name queue_name, q.color queue_color, u.name operator_name, coalesce(cp.campaign_opt_out, 0) campaign_opt_out
                from customers c
                join queues q on q.id = c.queue_id
                left join users u on u.id = c.assigned_operator_id
                left join customer_preferences cp on cp.customer_id = c.id
                where {where_sql}
                order by coalesce(c.last_message_at, c.created_at) desc
                limit ? offset ?
                """,
                params,
            ).fetchall()
        self.send_json({"customers": [customer_payload(row) for row in rows]})

    def api_messages(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if not self.require_customer_access(user, customer_id):
            return
        with db() as conn:
            rows = conn.execute(
                "select * from messages where customer_id = ? order by created_at asc, id asc",
                (customer_id,),
            ).fetchall()
        self.send_json({"messages": [dict(row) for row in rows]})

    def api_quick_replies(self):
        user = self.require_user()
        if not user:
            return
        with db() as conn:
            rows = conn.execute(
                "select id, shortcut, body, created_by_user_id, created_at, updated_at from quick_replies order by shortcut asc"
            ).fetchall()
        self.send_json({"quick_replies": [dict(row) for row in rows]})

    def api_upsert_quick_reply(self):
        user = self.require_user()
        if not user:
            return
        if user["role"] != "admin":
            self.send_json({"error": "Somente admin pode gerenciar frases rÃ¡pidas"}, HTTPStatus.FORBIDDEN)
            return
        payload = self.read_json()
        shortcut = str(payload.get("shortcut") or "").strip()
        body = str(payload.get("body") or "").strip()
        if not shortcut or not body:
            self.send_json({"error": "shortcut e body sÃ£o obrigatÃ³rios"}, HTTPStatus.BAD_REQUEST)
            return
        if len(shortcut) > 64:
            self.send_json({"error": "shortcut excede o limite de 64 caracteres"}, HTTPStatus.BAD_REQUEST)
            return
        if len(body) > 4096:
            self.send_json({"error": "body excede o limite de 4096 caracteres"}, HTTPStatus.BAD_REQUEST)
            return
        with db() as conn:
            conn.execute(
                """
                insert into quick_replies (shortcut, body, created_by_user_id, created_at, updated_at)
                values (?, ?, ?, ?, ?)
                on conflict(shortcut) do update set
                    body = excluded.body,
                    created_by_user_id = excluded.created_by_user_id,
                    updated_at = excluded.updated_at
                """,
                (shortcut, body, user["id"], now_ts(), now_ts()),
            )
        log_action(user["id"], "quick_reply.upsert", {"shortcut": shortcut})
        self.send_json({"ok": True})

    def api_team_messages(self):
        user = self.require_user()
        if not user:
            return
        if not user_has_permission(user, "team:chat"):
            self.send_json({"error": "Sem permissao team:chat"}, HTTPStatus.FORBIDDEN)
            return
        query = parse_qs(urlparse(self.path).query)
        try:
            limit = int(query.get("limit", ["100"])[0])
        except (TypeError, ValueError):
            self.send_json({"error": "Parametro limit invalido"}, HTTPStatus.BAD_REQUEST)
            return
        limit = max(1, min(limit, 200))
        with db() as conn:
            rows = conn.execute(
                """
                select tm.id, tm.user_id, tm.body, tm.created_at, coalesce(u.name, 'Usuario') user_name
                from team_messages tm
                left join users u on u.id = tm.user_id
                order by tm.created_at desc, tm.id desc
                limit ?
                """,
                (limit,),
            ).fetchall()
        self.send_json({"messages": [dict(row) for row in rows]})

    def api_post_team_message(self):
        user = self.require_user()
        if not user:
            return
        if not user_has_permission(user, "team:chat"):
            self.send_json({"error": "Sem permissao team:chat"}, HTTPStatus.FORBIDDEN)
            return
        payload = self.read_json()
        body = str(payload.get("body") or "").strip()
        if not body:
            self.send_json({"error": "Mensagem vazia"}, HTTPStatus.BAD_REQUEST)
            return
        if len(body) > 4096:
            self.send_json({"error": "Mensagem excede o limite de 4096 caracteres"}, HTTPStatus.BAD_REQUEST)
            return
        with db() as conn:
            cursor = conn.execute(
                "insert into team_messages (user_id, body, created_at) values (?, ?, ?)",
                (user["id"], body, now_ts()),
            )
        log_action(user["id"], "team_message.posted", {"team_message_id": cursor.lastrowid})
        self.send_json({"ok": True, "id": cursor.lastrowid}, HTTPStatus.CREATED)

    def api_customer_media(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if not self.require_customer_access(user, customer_id):
            return
        with db() as conn:
            rows = conn.execute(
                """
                select
                    m.id,
                    m.customer_id,
                    m.media_type,
                    m.url,
                    m.caption,
                    m.direction,
                    m.created_by_user_id,
                    m.created_at,
                    coalesce(u.name, 'Usuario') created_by_name
                from media_attachments m
                left join users u on u.id = m.created_by_user_id
                where m.customer_id = ?
                order by m.created_at desc, m.id desc
                """,
                (customer_id,),
            ).fetchall()
        self.send_json({"media": [dict(row) for row in rows]})

    def api_send_media(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if not user_has_permission(user, "media:send"):
            self.send_json({"error": "Sem permissao media:send"}, HTTPStatus.FORBIDDEN)
            return
        if not self.require_customer_access(user, customer_id):
            return
        if self.customer_is_finalized(customer_id):
            self.send_json({"error": "Atendimento finalizado. Novas acoes estao bloqueadas."}, HTTPStatus.CONFLICT)
            return
        payload = self.read_json()
        media_type = str(payload.get("media_type") or "").strip().lower()
        url = str(payload.get("url") or "").strip()
        caption = str(payload.get("caption") or "").strip()
        if media_type not in {"image", "video", "gif", "sticker", "file"}:
            self.send_json({"error": "media_type invalido"}, HTTPStatus.BAD_REQUEST)
            return
        if not url:
            self.send_json({"error": "url e obrigatoria"}, HTTPStatus.BAD_REQUEST)
            return
        if len(url) > 2048:
            self.send_json({"error": "url excede o limite"}, HTTPStatus.BAD_REQUEST)
            return
        if caption and len(caption) > 1024:
            self.send_json({"error": "caption excede o limite de 1024 caracteres"}, HTTPStatus.BAD_REQUEST)
            return
        with db() as conn:
            customer = conn.execute("select id from customers where id = ?", (customer_id,)).fetchone()
            if not customer:
                self.send_json({"error": "Cliente nao encontrado"}, HTTPStatus.NOT_FOUND)
                return
            conn.execute(
                """
                insert into media_attachments
                (customer_id, media_type, url, caption, direction, created_by_user_id, created_at)
                values (?, ?, ?, ?, 'outbound', ?, ?)
                """,
                (customer_id, media_type, url, caption or None, user["id"], now_ts()),
            )
            media_line = f"[media:{media_type}] {url}"
            text = f"{media_line}\n{caption}" if caption else media_line
            status = self._send_outbound_for_customer(conn, customer_id, text)
        log_action(user["id"], "media.sent", {"customer_id": customer_id, "media_type": media_type})
        publish_realtime_event(
            "ticket.updated",
            {"customer_id": customer_id, "kind": "media_sent", "media_type": media_type, "by_user_id": user["id"]},
            customer_id=customer_id,
        )
        self.send_json({"ok": True, "status": status})

    def api_upload_media_file(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if not user_has_permission(user, "media:send"):
            self.send_json({"error": "Sem permissao media:send"}, HTTPStatus.FORBIDDEN)
            return
        if not self.require_customer_access(user, customer_id):
            return
        if self.customer_is_finalized(customer_id):
            self.send_json({"error": "Atendimento finalizado. Novas acoes estao bloqueadas."}, HTTPStatus.CONFLICT)
            return
        payload = self.read_json()
        media_type = str(payload.get("media_type") or "").strip().lower()
        filename = str(payload.get("filename") or "").strip()
        content_base64 = str(payload.get("content_base64") or "").strip()
        caption = str(payload.get("caption") or "").strip()
        if media_type not in {"image", "video", "gif", "sticker", "file"}:
            self.send_json({"error": "media_type invalido"}, HTTPStatus.BAD_REQUEST)
            return
        if not filename or not content_base64:
            self.send_json({"error": "filename e content_base64 sao obrigatorios"}, HTTPStatus.BAD_REQUEST)
            return
        try:
            file_bytes = base64.b64decode(content_base64, validate=True)
        except Exception:
            self.send_json({"error": "content_base64 invalido"}, HTTPStatus.BAD_REQUEST)
            return
        try:
            file_url = store_uploaded_file(filename, file_bytes)
        except ValueError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        with db() as conn:
            conn.execute(
                """
                insert into media_attachments
                (customer_id, media_type, url, caption, direction, created_by_user_id, created_at)
                values (?, ?, ?, ?, 'outbound', ?, ?)
                """,
                (customer_id, media_type, file_url, caption or None, user["id"], now_ts()),
            )
            media_line = f"[media:{media_type}] {file_url}"
            text = f"{media_line}\n{caption}" if caption else media_line
            status = self._send_outbound_for_customer(conn, customer_id, text)
        log_action(user["id"], "media.uploaded", {"customer_id": customer_id, "media_type": media_type, "url": file_url})
        publish_realtime_event(
            "ticket.updated",
            {"customer_id": customer_id, "kind": "media_uploaded", "media_type": media_type, "by_user_id": user["id"]},
            customer_id=customer_id,
        )
        self.send_json({"ok": True, "status": status, "url": file_url})

    def api_set_campaign_opt_out(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if user["role"] != "admin":
            self.send_json({"error": "Somente admin pode alterar opt-out de campanha"}, HTTPStatus.FORBIDDEN)
            return
        if not self.require_customer_access(user, customer_id):
            return
        payload = self.read_json()
        value = bool(payload.get("opt_out", True))
        with db() as conn:
            conn.execute(
                """
                insert into customer_preferences (customer_id, campaign_opt_out, updated_at)
                values (?, ?, ?)
                on conflict(customer_id) do update set
                    campaign_opt_out = excluded.campaign_opt_out,
                    updated_at = excluded.updated_at
                """,
                (customer_id, 1 if value else 0, now_ts()),
            )
        log_action(user["id"], "campaign.opt_out_updated", {"customer_id": customer_id, "opt_out": value})
        self.send_json({"ok": True, "customer_id": customer_id, "opt_out": value})

    def api_ai_suggest(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if not user_has_permission(user, "ai:suggest"):
            self.send_json({"error": "Sem permissao ai:suggest"}, HTTPStatus.FORBIDDEN)
            return
        if not self.require_customer_access(user, customer_id):
            return
        with db() as conn:
            customer = conn.execute("select id, name from customers where id = ?", (customer_id,)).fetchone()
            if not customer:
                self.send_json({"error": "Cliente nao encontrado"}, HTTPStatus.NOT_FOUND)
                return
            rows = conn.execute(
                "select direction, body, created_at from messages where customer_id = ? order by created_at desc, id desc limit 10",
                (customer_id,),
            ).fetchall()
        conversation_lines = []
        for row in reversed(rows):
            role = "Cliente" if row["direction"] == "inbound" else "Operador"
            conversation_lines.append(f"{role}: {row['body']}")
        conversation_text = "\n".join(conversation_lines) if conversation_lines else "Sem mensagens anteriores."
        try:
            suggestion, latency_ms = generate_ai_suggestion(customer["name"], conversation_text)
        except RuntimeError as exc:
            fallback = (
                "Entendi seu contexto. Vou verificar o seu caso agora e te retorno em seguida com os prÃ³ximos passos."
            )
            with db() as conn:
                conn.execute(
                    """
                    insert into ai_suggestions (customer_id, user_id, model, prompt, suggestion, latency_ms, created_at)
                    values (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (customer_id, user["id"], "local-fallback", conversation_text, fallback, None, now_ts()),
                )
            self.send_json({"suggestion": fallback, "provider": "fallback", "error": str(exc)})
            return
        with db() as conn:
            conn.execute(
                """
                insert into ai_suggestions (customer_id, user_id, model, prompt, suggestion, latency_ms, created_at)
                values (?, ?, ?, ?, ?, ?, ?)
                """,
                (customer_id, user["id"], OPENAI_MODEL, conversation_text, suggestion, latency_ms, now_ts()),
            )
        log_action(user["id"], "ai.suggested", {"customer_id": customer_id, "latency_ms": latency_ms, "model": OPENAI_MODEL})
        self.send_json({"suggestion": suggestion, "provider": "openai", "model": OPENAI_MODEL, "latency_ms": latency_ms})

    def api_campaigns(self):
        user = self.require_user()
        if not user:
            return
        if user["role"] != "admin":
            self.send_json({"error": "Somente admin pode visualizar campanhas"}, HTTPStatus.FORBIDDEN)
            return
        query = parse_qs(urlparse(self.path).query)
        try:
            limit = int(query.get("limit", ["50"])[0])
        except (TypeError, ValueError):
            self.send_json({"error": "Parametro limit invalido"}, HTTPStatus.BAD_REQUEST)
            return
        limit = max(1, min(limit, 200))
        with db() as conn:
            rows = conn.execute(
                """
                select
                    c.id,
                    c.name,
                    c.body,
                    c.status,
                    c.created_by_user_id,
                    c.scheduled_at,
                    c.rate_per_minute,
                    c.created_at,
                    c.started_at,
                    c.finished_at,
                    coalesce(u.name, 'Usuario') created_by_name,
                    count(ct.id) total_targets,
                    sum(case when ct.status = 'queued' then 1 else 0 end) queued_total,
                    sum(case when ct.status = 'sent' then 1 else 0 end) sent_total,
                    sum(case when ct.status = 'failed' then 1 else 0 end) failed_total
                from campaigns c
                left join users u on u.id = c.created_by_user_id
                left join campaign_targets ct on ct.campaign_id = c.id
                group by c.id, c.name, c.body, c.status, c.created_by_user_id, c.scheduled_at, c.rate_per_minute, c.created_at, c.started_at, c.finished_at, u.name
                order by c.created_at desc, c.id desc
                limit ?
                """,
                (limit,),
            ).fetchall()
        payload = []
        for row in rows:
            item = dict(row)
            item["total_targets"] = int(item.get("total_targets") or 0)
            item["queued_total"] = int(item.get("queued_total") or 0)
            item["sent_total"] = int(item.get("sent_total") or 0)
            item["failed_total"] = int(item.get("failed_total") or 0)
            item["rate_per_minute"] = int(item.get("rate_per_minute") or 0)
            payload.append(item)
        self.send_json({"campaigns": payload})

    def api_create_campaign(self):
        user = self.require_user()
        if not user:
            return
        if user["role"] != "admin":
            self.send_json({"error": "Somente admin pode disparar campanhas"}, HTTPStatus.FORBIDDEN)
            return
        payload = self.read_json()
        name = str(payload.get("name") or "").strip()
        body = str(payload.get("body") or "").strip()
        customer_ids_raw = payload.get("customer_ids")
        scheduled_at_raw = payload.get("scheduled_at")
        rate_per_minute_raw = payload.get("rate_per_minute", 120)
        if not name:
            self.send_json({"error": "name e obrigatorio"}, HTTPStatus.BAD_REQUEST)
            return
        if not body:
            self.send_json({"error": "body e obrigatorio"}, HTTPStatus.BAD_REQUEST)
            return
        if len(name) > 120:
            self.send_json({"error": "name excede o limite de 120 caracteres"}, HTTPStatus.BAD_REQUEST)
            return
        if len(body) > 4096:
            self.send_json({"error": "body excede o limite de 4096 caracteres"}, HTTPStatus.BAD_REQUEST)
            return
        scheduled_at = None
        if scheduled_at_raw not in (None, ""):
            try:
                scheduled_at = int(scheduled_at_raw)
            except (TypeError, ValueError):
                self.send_json({"error": "scheduled_at invalido"}, HTTPStatus.BAD_REQUEST)
                return
            if scheduled_at <= 0:
                self.send_json({"error": "scheduled_at invalido"}, HTTPStatus.BAD_REQUEST)
                return
        try:
            rate_per_minute = int(rate_per_minute_raw)
        except (TypeError, ValueError):
            self.send_json({"error": "rate_per_minute invalido"}, HTTPStatus.BAD_REQUEST)
            return
        if rate_per_minute < 1 or rate_per_minute > 600:
            self.send_json({"error": "rate_per_minute deve ficar entre 1 e 600"}, HTTPStatus.BAD_REQUEST)
            return
        if not isinstance(customer_ids_raw, list) or not customer_ids_raw:
            self.send_json({"error": "customer_ids deve ser uma lista com pelo menos um cliente"}, HTTPStatus.BAD_REQUEST)
            return
        normalized_ids = []
        seen = set()
        for item in customer_ids_raw:
            try:
                customer_id = int(item)
            except (TypeError, ValueError):
                self.send_json({"error": "customer_ids contem valor invalido"}, HTTPStatus.BAD_REQUEST)
                return
            if customer_id <= 0:
                self.send_json({"error": "customer_ids contem valor invalido"}, HTTPStatus.BAD_REQUEST)
                return
            if customer_id not in seen:
                seen.add(customer_id)
                normalized_ids.append(customer_id)
        if len(normalized_ids) > 1000:
            self.send_json({"error": "Limite maximo de 1000 clientes por campanha"}, HTTPStatus.BAD_REQUEST)
            return

        now = now_ts()
        placeholders = ",".join("?" for _ in normalized_ids)
        skipped_not_found_total = 0
        campaign_id = None
        with db() as conn:
            existing_rows = conn.execute(
                f"select id from customers where id in ({placeholders})",
                normalized_ids,
            ).fetchall()
            existing_ids = {int(row["id"]) for row in existing_rows}
            valid_ids = [customer_id for customer_id in normalized_ids if customer_id in existing_ids]
            skipped_not_found_total = len(normalized_ids) - len(valid_ids)
            if not valid_ids:
                self.send_json({"error": "Nenhum cliente valido foi informado"}, HTTPStatus.BAD_REQUEST)
                return
            campaign_cursor = conn.execute(
                """
                insert into campaigns (name, body, status, created_by_user_id, scheduled_at, rate_per_minute, created_at, started_at)
                values (?, ?, 'pending', ?, ?, ?, ?, ?)
                """,
                (name, body, user["id"], scheduled_at, rate_per_minute, now, now),
            )
            campaign_id = campaign_cursor.lastrowid
            conn.executemany(
                """
                insert into campaign_targets (campaign_id, customer_id, status)
                values (?, ?, 'queued')
                """,
                [(campaign_id, customer_id) for customer_id in valid_ids],
            )
        if scheduled_at is None or scheduled_at <= now:
            process_pending_campaign_dispatches(limit_campaigns=3)
        with db() as conn:
            row = conn.execute(
                """
                select
                    c.id,
                    c.status,
                    c.scheduled_at,
                    c.rate_per_minute,
                    count(ct.id) total_targets,
                    sum(case when ct.status = 'queued' then 1 else 0 end) queued_total,
                    sum(case when ct.status = 'sent' then 1 else 0 end) sent_total,
                    sum(case when ct.status = 'failed' then 1 else 0 end) failed_total
                from campaigns c
                left join campaign_targets ct on ct.campaign_id = c.id
                where c.id = ?
                group by c.id, c.status, c.scheduled_at, c.rate_per_minute
                """,
                (campaign_id,),
            ).fetchone()
        log_action(
            user["id"],
            "campaign.created",
            {
                "campaign_id": campaign_id,
                "total_targets": int(row["total_targets"] or 0),
                "queued_total": int(row["queued_total"] or 0),
                "sent_total": int(row["sent_total"] or 0),
                "failed_total": int(row["failed_total"] or 0),
                "skipped_not_found_total": skipped_not_found_total,
                "scheduled_at": scheduled_at,
                "rate_per_minute": rate_per_minute,
            },
        )
        self.send_json(
            {
                "ok": True,
                "campaign_id": campaign_id,
                "status": row["status"],
                "scheduled_at": row["scheduled_at"],
                "rate_per_minute": int(row["rate_per_minute"] or 0),
                "total_targets": int(row["total_targets"] or 0),
                "queued_total": int(row["queued_total"] or 0),
                "sent_total": int(row["sent_total"] or 0),
                "failed_total": int(row["failed_total"] or 0),
                "skipped_not_found_total": skipped_not_found_total,
            },
            HTTPStatus.CREATED,
        )

    def api_export_campaign_csv(self, campaign_id):
        user = self.require_user()
        if not user:
            return
        if user["role"] != "admin":
            self.send_json({"error": "Somente admin pode exportar campanhas"}, HTTPStatus.FORBIDDEN)
            return
        with db() as conn:
            campaign = conn.execute(
                "select id, name, status, scheduled_at, rate_per_minute from campaigns where id = ?",
                (campaign_id,),
            ).fetchone()
            if not campaign:
                self.send_json({"error": "Campanha nao encontrada"}, HTTPStatus.NOT_FOUND)
                return
            rows = conn.execute(
                """
                select
                    ct.id target_id,
                    ct.customer_id,
                    coalesce(c.name, '') customer_name,
                    coalesce(c.channel, 'whatsapp') customer_channel,
                    coalesce(c.contact_ref, c.phone, '') customer_contact,
                    ct.status,
                    coalesce(ct.last_error, '') last_error,
                    ct.sent_at
                from campaign_targets ct
                left join customers c on c.id = ct.customer_id
                where ct.campaign_id = ?
                order by ct.id asc
                """,
                (campaign_id,),
            ).fetchall()
        output = io.StringIO()
        output.write("\ufeff")
        writer = csv.writer(output)
        writer.writerow(
            [
                "campaign_id",
                "campaign_name",
                "campaign_status",
                "scheduled_at",
                "rate_per_minute",
                "target_id",
                "customer_id",
                "customer_name",
                "customer_channel",
                "customer_contact",
                "target_status",
                "last_error",
                "sent_at",
            ]
        )
        for row in rows:
            writer.writerow(
                [
                    campaign["id"],
                    campaign["name"],
                    campaign["status"],
                    campaign["scheduled_at"] or "",
                    campaign["rate_per_minute"],
                    row["target_id"],
                    row["customer_id"],
                    row["customer_name"],
                    row["customer_channel"],
                    row["customer_contact"],
                    row["status"],
                    row["last_error"],
                    row["sent_at"] or "",
                ]
            )
        body = output.getvalue().encode("utf-8")
        filename = f"campaign-{campaign_id}.csv"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("X-Request-ID", self.request_id)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_outbound_for_customer(self, conn, customer_id, text):
        customer = conn.execute(
            "select id, phone, channel, contact_ref from customers where id = ?",
            (customer_id,),
        ).fetchone()
        if not customer:
            raise APIError(HTTPStatus.NOT_FOUND, "Cliente nao encontrado")
        external_id = None
        status = "sent"
        try:
            channel = normalize_channel(customer["channel"] or "whatsapp") or "whatsapp"
            contact_ref = customer["contact_ref"] or customer["phone"]
            status, external_id = dispatch_outbound_text(channel, contact_ref, text)
        except RuntimeError as exc:
            status = f"local: {exc}"
        send_ts = now_ts()
        conn.execute(
            "insert into messages (customer_id, direction, body, status, external_id, created_at) values (?, ?, ?, ?, ?, ?)",
            (customer_id, "outbound", text, status, external_id, send_ts),
        )
        conn.execute(
            "update customers set last_message_at = ?, first_response_at = coalesce(first_response_at, ?) where id = ?",
            (send_ts, send_ts, customer_id),
        )
        return status

    def api_send_quick_reply(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if not user_has_permission(user, "quick_reply:send"):
            self.send_json({"error": "Sem permissao quick_reply:send"}, HTTPStatus.FORBIDDEN)
            return
        if not self.require_customer_access(user, customer_id):
            return
        if self.customer_is_finalized(customer_id):
            self.send_json({"error": "Atendimento finalizado. Novas aÃ§Ãµes estÃ£o bloqueadas."}, HTTPStatus.CONFLICT)
            return
        payload = self.read_json()
        shortcut = str(payload.get("shortcut") or "").strip()
        if not shortcut:
            self.send_json({"error": "shortcut Ã© obrigatÃ³rio"}, HTTPStatus.BAD_REQUEST)
            return
        with db() as conn:
            row = conn.execute(
                "select body from quick_replies where shortcut = ?",
                (shortcut,),
            ).fetchone()
            if not row:
                self.send_json({"error": "Frase rÃ¡pida nÃ£o encontrada"}, HTTPStatus.NOT_FOUND)
                return
            status = self._send_outbound_for_customer(conn, customer_id, row["body"])
        log_action(user["id"], "quick_reply.sent", {"customer_id": customer_id, "shortcut": shortcut})
        publish_realtime_event(
            "ticket.updated",
            {"customer_id": customer_id, "kind": "quick_reply_sent", "shortcut": shortcut, "by_user_id": user["id"]},
            customer_id=customer_id,
        )
        self.send_json({"ok": True, "status": status})

    def api_private_notes(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if not self.require_customer_access(user, customer_id):
            return
        with db() as conn:
            rows = conn.execute(
                """
                select n.id, n.customer_id, n.user_id, n.body, n.created_at, coalesce(u.name, 'UsuÃ¡rio') user_name
                from private_notes n
                left join users u on u.id = n.user_id
                where n.customer_id = ?
                order by n.created_at desc, n.id desc
                """,
                (customer_id,),
            ).fetchall()
        self.send_json({"notes": [dict(row) for row in rows]})

    def api_add_private_note(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if not user_has_permission(user, "notes:write"):
            self.send_json({"error": "Sem permissao notes:write"}, HTTPStatus.FORBIDDEN)
            return
        if not self.require_customer_access(user, customer_id):
            return
        payload = self.read_json()
        body = str(payload.get("body") or "").strip()
        if not body:
            self.send_json({"error": "Nota vazia"}, HTTPStatus.BAD_REQUEST)
            return
        if len(body) > 4096:
            self.send_json({"error": "Nota excede o limite de 4096 caracteres"}, HTTPStatus.BAD_REQUEST)
            return
        with db() as conn:
            conn.execute(
                "insert into private_notes (customer_id, user_id, body, created_at) values (?, ?, ?, ?)",
                (customer_id, user["id"], body, now_ts()),
            )
        log_action(user["id"], "private_note.added", {"customer_id": customer_id})
        publish_realtime_event(
            "ticket.updated",
            {"customer_id": customer_id, "kind": "private_note_added", "by_user_id": user["id"]},
            customer_id=customer_id,
        )
        self.send_json({"ok": True})

    def api_scheduled_messages(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if not self.require_customer_access(user, customer_id):
            return
        with db() as conn:
            rows = conn.execute(
                """
                select s.*, coalesce(u.name, 'UsuÃ¡rio') created_by_name
                from scheduled_messages s
                left join users u on u.id = s.created_by_user_id
                where s.customer_id = ?
                order by s.send_at desc, s.id desc
                """,
                (customer_id,),
            ).fetchall()
        self.send_json({"scheduled_messages": [dict(row) for row in rows]})

    def api_schedule_message(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if not user_has_permission(user, "schedule:manage"):
            self.send_json({"error": "Sem permissao schedule:manage"}, HTTPStatus.FORBIDDEN)
            return
        if not self.require_customer_access(user, customer_id):
            return
        if self.customer_is_finalized(customer_id):
            self.send_json({"error": "Atendimento finalizado. Novas aÃ§Ãµes estÃ£o bloqueadas."}, HTTPStatus.CONFLICT)
            return
        payload = self.read_json()
        body = str(payload.get("body") or "").strip()
        if not body:
            self.send_json({"error": "Mensagem agendada vazia"}, HTTPStatus.BAD_REQUEST)
            return
        if len(body) > 4096:
            self.send_json({"error": "Mensagem excede o limite de 4096 caracteres"}, HTTPStatus.BAD_REQUEST)
            return
        try:
            send_at = int(payload.get("send_at") or 0)
        except (TypeError, ValueError):
            self.send_json({"error": "send_at invÃ¡lido"}, HTTPStatus.BAD_REQUEST)
            return
        if send_at <= 0:
            self.send_json({"error": "send_at invÃ¡lido"}, HTTPStatus.BAD_REQUEST)
            return
        if send_at > now_ts() + (365 * 86400):
            self.send_json({"error": "send_at excede o limite de 365 dias"}, HTTPStatus.BAD_REQUEST)
            return
        with db() as conn:
            customer = conn.execute("select id from customers where id = ?", (customer_id,)).fetchone()
            if not customer:
                self.send_json({"error": "Cliente nao encontrado"}, HTTPStatus.NOT_FOUND)
                return
            cursor = conn.execute(
                """
                insert into scheduled_messages
                (customer_id, body, send_at, status, created_by_user_id, created_at)
                values (?, ?, ?, 'pending', ?, ?)
                """,
                (customer_id, body, send_at, user["id"], now_ts()),
            )
        log_action(user["id"], "scheduled_message.created", {"customer_id": customer_id, "scheduled_message_id": cursor.lastrowid})
        publish_realtime_event(
            "ticket.updated",
            {"customer_id": customer_id, "kind": "scheduled_message_created", "by_user_id": user["id"]},
            customer_id=customer_id,
        )
        self.send_json({"ok": True, "id": cursor.lastrowid}, HTTPStatus.CREATED)

    def api_cancel_scheduled_message(self, scheduled_message_id):
        user = self.require_user()
        if not user:
            return
        if not user_has_permission(user, "schedule:manage"):
            self.send_json({"error": "Sem permissao schedule:manage"}, HTTPStatus.FORBIDDEN)
            return
        with db() as conn:
            row = conn.execute(
                "select id, customer_id, status from scheduled_messages where id = ?",
                (scheduled_message_id,),
            ).fetchone()
            if not row:
                self.send_json({"error": "Agendamento nÃ£o encontrado"}, HTTPStatus.NOT_FOUND)
                return
        if not self.require_customer_access(user, row["customer_id"]):
            return
        if row["status"] != "pending":
            self.send_json({"error": "Somente agendamentos pendentes podem ser cancelados"}, HTTPStatus.CONFLICT)
            return
        with db() as conn:
            conn.execute(
                "update scheduled_messages set status = 'cancelled', sent_at = ?, last_error = ? where id = ? and status = 'pending'",
                (now_ts(), "cancelled_by_user", scheduled_message_id),
            )
        log_action(user["id"], "scheduled_message.cancelled", {"scheduled_message_id": scheduled_message_id})
        publish_realtime_event(
            "ticket.updated",
            {"customer_id": row["customer_id"], "kind": "scheduled_message_cancelled", "by_user_id": user["id"]},
            customer_id=row["customer_id"],
        )
        self.send_json({"ok": True})

    def api_send_message(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if not self.require_customer_access(user, customer_id):
            return
        if self.customer_is_finalized(customer_id):
            self.send_json({"error": "Atendimento finalizado. Novas ações estão bloqueadas."}, HTTPStatus.CONFLICT)
            return
        payload = self.read_json()
        text = payload.get("body", "").strip()
        if not text:
            self.send_json({"error": "Mensagem vazia"}, HTTPStatus.BAD_REQUEST)
            return
        if len(text) > 4096:
            self.send_json({"error": "Mensagem excede o limite de 4096 caracteres"}, HTTPStatus.BAD_REQUEST)
            return
        with db() as conn:
            status = self._send_outbound_for_customer(conn, customer_id, text)
        log_action(user["id"], "message.sent", {"customer_id": customer_id})
        publish_realtime_event(
            "ticket.updated",
            {"customer_id": customer_id, "kind": "outbound_message", "by_user_id": user["id"]},
            customer_id=customer_id,
        )
        self.send_json({"ok": True, "status": status})

    def api_create_customer(self):
        user = self.require_user()
        if not user:
            return
        payload = self.read_json()
        name = payload.get("name", "").strip()
        channel = normalize_channel(payload.get("channel") or "whatsapp")
        if not channel:
            self.send_json({"error": "Canal inválido"}, HTTPStatus.BAD_REQUEST)
            return
        contact_input = payload.get("contact", payload.get("phone", ""))
        contact_ref = normalize_customer_contact(channel, contact_input)
        if not contact_ref:
            self.send_json({"error": "Contato inválido para o canal selecionado"}, HTTPStatus.BAD_REQUEST)
            return
        customer_key = build_customer_key(channel, contact_ref)
        try:
            queue_id = int(payload.get("queue_id") or 0)
        except (TypeError, ValueError):
            self.send_json({"error": "Fila inválida"}, HTTPStatus.BAD_REQUEST)
            return
        if not name or queue_id <= 0:
            self.send_json({"error": "Nome, contato e fila são obrigatórios"}, HTTPStatus.BAD_REQUEST)
            return
        if user["role"] != "admin":
            assigned_operator_id = user["id"]
        else:
            raw_operator_id = payload.get("assigned_operator_id")
            if raw_operator_id in (None, ""):
                assigned_operator_id = None
            else:
                try:
                    assigned_operator_id = int(raw_operator_id)
                except (TypeError, ValueError):
                    self.send_json({"error": "Operador inválido"}, HTTPStatus.BAD_REQUEST)
                    return
        if assigned_operator_id is not None and assigned_operator_id <= 0:
            self.send_json({"error": "Operador inválido"}, HTTPStatus.BAD_REQUEST)
            return
        with db() as conn:
            queue = conn.execute("select id from queues where id = ?", (queue_id,)).fetchone()
            if not queue:
                self.send_json({"error": "Fila inválida"}, HTTPStatus.BAD_REQUEST)
                return
            if assigned_operator_id is not None:
                operator = conn.execute(
                    "select id from users where id = ? and role = 'operator' and active = 1",
                    (assigned_operator_id,),
                ).fetchone()
                if not operator:
                    self.send_json({"error": "Operador inválido"}, HTTPStatus.BAD_REQUEST)
                    return
            try:
                cursor = conn.execute(
                    """
                    insert into customers
                    (name, phone, channel, contact_ref, queue_id, assigned_operator_id, status, last_message_at, sla_due_at, created_at)
                    values (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)
                    """,
                    (
                        name,
                        customer_key,
                        channel,
                        contact_ref,
                        queue_id,
                        assigned_operator_id,
                        now_ts(),
                        now_ts() + DEFAULT_SLA_FIRST_RESPONSE_SECONDS,
                        now_ts(),
                    ),
                )
            except sqlite3.IntegrityError:
                self.send_json({"error": "Contato já cadastrado para este canal"}, HTTPStatus.CONFLICT)
                return
        log_action(user["id"], "customer.created", {"customer_id": cursor.lastrowid})
        publish_realtime_event(
            "ticket.updated",
            {"customer_id": cursor.lastrowid, "kind": "customer_created", "by_user_id": user["id"]},
            customer_id=cursor.lastrowid,
        )
        self.send_json({"ok": True, "id": cursor.lastrowid}, HTTPStatus.CREATED)

    def api_assign_customer(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if user["role"] != "admin":
            self.send_json({"error": "Somente admin pode redistribuir filas"}, HTTPStatus.FORBIDDEN)
            return
        if not self.require_customer_access(user, customer_id):
            return
        if self.customer_is_finalized(customer_id):
            self.send_json({"error": "Atendimento finalizado. Novas ações estão bloqueadas."}, HTTPStatus.CONFLICT)
            return
        payload = self.read_json()
        try:
            operator_id = int(payload.get("operator_id") or 0)
        except (TypeError, ValueError):
            self.send_json({"error": "Operador invalido"}, HTTPStatus.BAD_REQUEST)
            return
        with db() as conn:
            operator = conn.execute(
                "select id from users where id = ? and role = 'operator' and active = 1",
                (operator_id,),
            ).fetchone()
            if not operator:
                self.send_json({"error": "Operador inválido"}, HTTPStatus.BAD_REQUEST)
                return
            conn.execute("update customers set assigned_operator_id = ? where id = ?", (operator_id, customer_id))
        log_action(user["id"], "customer.assigned", {"customer_id": customer_id, "operator_id": operator_id})
        publish_realtime_event(
            "ticket.updated",
            {"customer_id": customer_id, "kind": "assigned", "operator_id": operator_id, "by_user_id": user["id"]},
            customer_id=customer_id,
        )
        self.send_json({"ok": True})

    def api_update_status(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if not self.require_customer_access(user, customer_id):
            return
        if self.customer_is_finalized(customer_id):
            self.send_json({"error": "Atendimento finalizado. Novas ações estão bloqueadas."}, HTTPStatus.CONFLICT)
            return
        payload = self.read_json()
        status = str(payload.get("status") or "").strip().lower()
        if status not in {"open", "pending", "closed"}:
            self.send_json({"error": "Status inválido"}, HTTPStatus.BAD_REQUEST)
            return
        with db() as conn:
            conn.execute(
                "update customers set status = ?, closed_at = case when ? = 'closed' then ? else null end where id = ?",
                (status, status, now_ts(), customer_id),
            )
        log_action(user["id"], "customer.status", {"customer_id": customer_id, "status": status})
        publish_realtime_event(
            "ticket.updated",
            {"customer_id": customer_id, "kind": "status_changed", "status": status, "by_user_id": user["id"]},
            customer_id=customer_id,
        )
        self.send_json({"ok": True})

    def api_transfer_customer(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if not self.require_customer_access(user, customer_id):
            return
        if self.customer_is_finalized(customer_id):
            self.send_json({"error": "Atendimento finalizado. Novas ações estão bloqueadas."}, HTTPStatus.CONFLICT)
            return
        payload = self.read_json()
        try:
            operator_id = int(payload.get("operator_id") or 0)
        except (TypeError, ValueError):
            self.send_json({"error": "Operador invalido"}, HTTPStatus.BAD_REQUEST)
            return
        with db() as conn:
            operator = conn.execute("select id from users where id = ? and role = 'operator' and active = 1", (operator_id,)).fetchone()
            if not operator:
                self.send_json({"error": "Operador inválido"}, HTTPStatus.BAD_REQUEST)
                return
            conn.execute("update customers set assigned_operator_id = ?, finalized = 0 where id = ?", (operator_id, customer_id))
        log_action(user["id"], "customer.transferred", {"customer_id": customer_id, "operator_id": operator_id})
        publish_realtime_event(
            "ticket.updated",
            {"customer_id": customer_id, "kind": "transferred", "operator_id": operator_id, "by_user_id": user["id"]},
            customer_id=customer_id,
        )
        self.send_json({"ok": True})

    def api_finalize_customer(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if not self.require_customer_access(user, customer_id):
            return
        with db() as conn:
            conn.execute(
                "update customers set status = 'closed', finalized = 1, closed_at = ? where id = ?",
                (now_ts(), customer_id),
            )
        log_action(user["id"], "customer.finalized", {"customer_id": customer_id})
        publish_realtime_event(
            "ticket.updated",
            {"customer_id": customer_id, "kind": "finalized", "by_user_id": user["id"]},
            customer_id=customer_id,
        )
        self.send_json({"ok": True})

    def api_customer_erp(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if not self.require_customer_access(user, customer_id):
            return
        with db() as conn:
            row = conn.execute(
                """
                select erp_provider, erp_client_code, erp_financial_pending, erp_connection_data
                from customers
                where id = ?
                """,
                (customer_id,),
            ).fetchone()
        if not row:
            self.send_json({"error": "Cliente não encontrado"}, HTTPStatus.NOT_FOUND)
            return
        try:
            connection_data = json.loads(row["erp_connection_data"] or "{}")
        except json.JSONDecodeError:
            connection_data = {}
        self.send_json(
            {
                "erp_active": bool(row["erp_provider"]),
                "provider": row["erp_provider"],
                "client_code": row["erp_client_code"],
                "financial_pending": bool(row["erp_financial_pending"]),
                "connection_data": connection_data,
            }
        )

    def api_send_boleto(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if not self.require_customer_access(user, customer_id):
            return
        if self.customer_is_finalized(customer_id):
            self.send_json({"error": "Atendimento finalizado. Novas ações estão bloqueadas."}, HTTPStatus.CONFLICT)
            return
        with db() as conn:
            row = conn.execute(
                "select erp_financial_pending from customers where id = ?",
                (customer_id,),
            ).fetchone()
            if not row or not row["erp_financial_pending"]:
                self.send_json({"error": "Cliente sem pendência financeira"}, HTTPStatus.CONFLICT)
                return
            conn.execute(
                "insert into messages (customer_id, direction, body, status, created_at) values (?, 'outbound', ?, 'sent', ?)",
                (customer_id, "Segue seu boleto atualizado para regularização.", now_ts()),
            )
            conn.execute(
                "update customers set last_message_at = ?, first_response_at = coalesce(first_response_at, ?) where id = ?",
                (now_ts(), now_ts(), customer_id),
            )
        log_action(user["id"], "billing.boleto_sent", {"customer_id": customer_id})
        publish_realtime_event(
            "ticket.updated",
            {"customer_id": customer_id, "kind": "boleto_sent", "by_user_id": user["id"]},
            customer_id=customer_id,
        )
        self.send_json({"ok": True})

    def api_unlock_billing(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if not self.require_customer_access(user, customer_id):
            return
        if self.customer_is_finalized(customer_id):
            self.send_json({"error": "Atendimento finalizado. Novas ações estão bloqueadas."}, HTTPStatus.CONFLICT)
            return
        if "billing:unlock" not in parse_permissions(user.get("permissions", "[]")):
            self.send_json({"error": "Sem permissão billing:unlock"}, HTTPStatus.FORBIDDEN)
            return
        with db() as conn:
            conn.execute(
                "insert into messages (customer_id, direction, body, status, created_at) values (?, 'system', ?, 'sent', ?)",
                (customer_id, "Desbloqueio em cobrança solicitado pelo operador.", now_ts()),
            )
            conn.execute(
                "update customers set last_message_at = ?, first_response_at = coalesce(first_response_at, ?) where id = ?",
                (now_ts(), now_ts(), customer_id),
            )
        log_action(user["id"], "billing.unlocked", {"customer_id": customer_id})
        publish_realtime_event(
            "ticket.updated",
            {"customer_id": customer_id, "kind": "billing_unlocked", "by_user_id": user["id"]},
            customer_id=customer_id,
        )
        self.send_json({"ok": True})

    def api_operators(self):
        user = self.require_user()
        if not user:
            return
        with db() as conn:
            rows = conn.execute(
                "select id, name, email from users where role = 'operator' and active = 1 order by name"
            ).fetchall()
        self.send_json({"operators": [dict(row) for row in rows]})

    def api_queues(self):
        user = self.require_user()
        if not user:
            return
        with db() as conn:
            rows = conn.execute("select * from queues order by name").fetchall()
        self.send_json({"queues": [dict(row) for row in rows]})

    def api_dashboard(self):
        user = self.require_user()
        if not user:
            return
        clause, params = self.visible_customer_clause(user)
        with db() as conn:
            totals = conn.execute(
                f"""
                select
                    count(*) total,
                    sum(case when status = 'open' then 1 else 0 end) open_total,
                    sum(case when status = 'pending' then 1 else 0 end) pending_total,
                    sum(case when status = 'closed' then 1 else 0 end) closed_total
                from customers c
                where {clause}
                """,
                params,
            ).fetchone()
        self.send_json({"dashboard": dict(totals)})

    def api_sla(self):
        user = self.require_user()
        if not user:
            return
        clause, params = self.visible_customer_clause(user)
        now = now_ts()

        with db() as conn:
            summary = conn.execute(
                f"""
                select
                    count(*) total,
                    sum(case when c.status != 'closed' and c.first_response_at is null then 1 else 0 end) waiting_first_response,
                    sum(
                        case
                            when c.status != 'closed' and c.first_response_at is null and c.sla_due_at is not null and c.sla_due_at < ?
                            then 1
                            else 0
                        end
                    ) breached_first_response,
                    avg(case when c.first_response_at is not null then c.first_response_at - c.created_at end) avg_first_response_seconds,
                    avg(case when c.closed_at is not null then c.closed_at - c.created_at end) avg_resolution_seconds
                from customers c
                where {clause}
                """,
                [now, *params],
            ).fetchone()

            queue_rows = conn.execute(
                f"""
                select
                    q.id queue_id,
                    q.name queue_name,
                    count(*) total,
                    sum(case when c.status != 'closed' and c.first_response_at is null then 1 else 0 end) waiting_first_response,
                    sum(
                        case
                            when c.status != 'closed' and c.first_response_at is null and c.sla_due_at is not null and c.sla_due_at < ?
                            then 1
                            else 0
                        end
                    ) breached_first_response,
                    avg(case when c.first_response_at is not null then c.first_response_at - c.created_at end) avg_first_response_seconds,
                    avg(case when c.closed_at is not null then c.closed_at - c.created_at end) avg_resolution_seconds
                from customers c
                join queues q on q.id = c.queue_id
                where {clause}
                group by q.id, q.name
                order by q.name asc
                """,
                [now, *params],
            ).fetchall()

        payload_summary = dict(summary)
        payload_summary["avg_first_response_seconds"] = normalize_avg_seconds(payload_summary["avg_first_response_seconds"])
        payload_summary["avg_resolution_seconds"] = normalize_avg_seconds(payload_summary["avg_resolution_seconds"])

        by_queue = []
        for row in queue_rows:
            item = dict(row)
            item["avg_first_response_seconds"] = normalize_avg_seconds(item["avg_first_response_seconds"])
            item["avg_resolution_seconds"] = normalize_avg_seconds(item["avg_resolution_seconds"])
            by_queue.append(item)

        self.send_json({"sla": payload_summary, "by_queue": by_queue, "now": now})

    def _parse_window_days(self, parsed, default_days=30):
        query = parse_qs(parsed.query)
        raw_days = query.get("days", [str(default_days)])[0]
        try:
            days = int(raw_days)
        except (TypeError, ValueError):
            raise APIError(HTTPStatus.BAD_REQUEST, "Parametro days invalido")
        if days < 1 or days > 90:
            raise APIError(HTTPStatus.BAD_REQUEST, "Parametro days deve estar entre 1 e 90")
        return days

    def _parse_target_seconds(self, raw_value, label, minimum_seconds, maximum_seconds):
        try:
            value = int(raw_value)
        except (TypeError, ValueError):
            raise APIError(HTTPStatus.BAD_REQUEST, f"{label} invalido")
        if value < minimum_seconds or value > maximum_seconds:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                f"{label} deve estar entre {minimum_seconds} e {maximum_seconds} segundos",
            )
        return value

    def _build_tma_tme_targets_payload(self, conn):
        global_target, by_queue_targets = load_tma_tme_targets(conn)
        queue_rows = conn.execute("select id, name from queues order by name asc").fetchall()
        queue_payload = []
        for row in queue_rows:
            queue_id = int(row["id"])
            custom_target = by_queue_targets.get(queue_id)
            effective_target = custom_target or global_target
            queue_payload.append(
                {
                    "queue_id": queue_id,
                    "queue_name": row["name"],
                    "tme_target_seconds": int(effective_target["tme_target_seconds"]),
                    "tma_target_seconds": int(effective_target["tma_target_seconds"]),
                    "has_custom_target": bool(custom_target),
                    "updated_at": custom_target["updated_at"] if custom_target else global_target["updated_at"],
                }
            )
        return {"global": global_target, "queues": queue_payload}

    def api_tma_tme_targets(self):
        user = self.require_user()
        if not user:
            return
        with db() as conn:
            payload = self._build_tma_tme_targets_payload(conn)
        self.send_json({"targets": payload, "generated_at": now_ts()})

    def api_update_tma_tme_targets(self):
        user = self.require_user()
        if not user:
            return
        if user["role"] != "admin":
            self.send_json({"error": "Somente admin pode atualizar metas TMA/TME"}, HTTPStatus.FORBIDDEN)
            return

        payload = self.read_json()
        global_payload = payload.get("global")
        queue_payload = payload.get("queues", [])
        if global_payload is not None and not isinstance(global_payload, dict):
            self.send_json({"error": "Campo global invalido"}, HTTPStatus.BAD_REQUEST)
            return
        if not isinstance(queue_payload, list):
            self.send_json({"error": "Campo queues invalido"}, HTTPStatus.BAD_REQUEST)
            return

        with db() as conn:
            existing_queue_ids = {
                int(row["id"]) for row in conn.execute("select id from queues").fetchall()
            }
            if global_payload is not None:
                tme_global = self._parse_target_seconds(
                    global_payload.get("tme_target_seconds"),
                    "TME global",
                    30,
                    86400,
                )
                tma_global = self._parse_target_seconds(
                    global_payload.get("tma_target_seconds"),
                    "TMA global",
                    60,
                    172800,
                )
                conn.execute(
                    """
                    insert into tma_tme_targets (queue_id, tme_target_seconds, tma_target_seconds, updated_at)
                    values (0, ?, ?, ?)
                    on conflict(queue_id) do update set
                        tme_target_seconds = excluded.tme_target_seconds,
                        tma_target_seconds = excluded.tma_target_seconds,
                        updated_at = excluded.updated_at
                    """,
                    (tme_global, tma_global, now_ts()),
                )

            for item in queue_payload:
                if not isinstance(item, dict):
                    self.send_json({"error": "Item de queue invalido"}, HTTPStatus.BAD_REQUEST)
                    return
                try:
                    queue_id = int(item.get("queue_id") or 0)
                except (TypeError, ValueError):
                    self.send_json({"error": "queue_id invalido"}, HTTPStatus.BAD_REQUEST)
                    return
                if queue_id <= 0 or queue_id not in existing_queue_ids:
                    self.send_json({"error": f"Fila invalida para queue_id={queue_id}"}, HTTPStatus.BAD_REQUEST)
                    return

                if bool(item.get("inherit")):
                    conn.execute("delete from tma_tme_targets where queue_id = ?", (queue_id,))
                    continue

                tme_queue = self._parse_target_seconds(
                    item.get("tme_target_seconds"),
                    "TME da fila",
                    30,
                    86400,
                )
                tma_queue = self._parse_target_seconds(
                    item.get("tma_target_seconds"),
                    "TMA da fila",
                    60,
                    172800,
                )
                conn.execute(
                    """
                    insert into tma_tme_targets (queue_id, tme_target_seconds, tma_target_seconds, updated_at)
                    values (?, ?, ?, ?)
                    on conflict(queue_id) do update set
                        tme_target_seconds = excluded.tme_target_seconds,
                        tma_target_seconds = excluded.tma_target_seconds,
                        updated_at = excluded.updated_at
                    """,
                    (queue_id, tme_queue, tma_queue, now_ts()),
                )

            result = self._build_tma_tme_targets_payload(conn)
        log_action(user["id"], "tma_tme.targets_updated", {"updated_queues": len(queue_payload)})
        self.send_json({"ok": True, "targets": result, "updated_at": now_ts()})

    def api_tma_tme(self, parsed):
        user = self.require_user()
        if not user:
            return
        days = self._parse_window_days(parsed)
        now = now_ts()
        window_start = now - (days * 86400)
        clause, base_params = self.visible_customer_clause(user, alias="c")
        where_sql = f"{clause} and c.created_at >= ?"
        params = [*base_params, window_start]

        with db() as conn:
            targets_payload = self._build_tma_tme_targets_payload(conn)
            summary = conn.execute(
                f"""
                with global_target as (
                    select
                        coalesce((select tme_target_seconds from tma_tme_targets where queue_id = 0), ?) as tme_target_seconds,
                        coalesce((select tma_target_seconds from tma_tme_targets where queue_id = 0), ?) as tma_target_seconds
                )
                select
                    count(*) total,
                    sum(case when c.first_response_at is not null then 1 else 0 end) answered_tickets,
                    sum(
                        case
                            when c.first_response_at is not null and c.closed_at is not null and c.closed_at >= c.first_response_at
                            then 1
                            else 0
                        end
                    ) handled_tickets,
                    avg(case when c.first_response_at is not null then c.first_response_at - c.created_at end) avg_tme_seconds,
                    avg(
                        case
                            when c.first_response_at is not null and c.closed_at is not null and c.closed_at >= c.first_response_at
                            then c.closed_at - c.first_response_at
                            else null
                        end
                    ) avg_tma_seconds,
                    sum(
                        case
                            when c.first_response_at is not null
                                 and c.first_response_at - c.created_at <= coalesce(tq.tme_target_seconds, gt.tme_target_seconds)
                            then 1
                            else 0
                        end
                    ) tme_within_target,
                    sum(
                        case
                            when c.first_response_at is not null
                                 and c.closed_at is not null
                                 and c.closed_at >= c.first_response_at
                                 and c.closed_at - c.first_response_at <= coalesce(tq.tma_target_seconds, gt.tma_target_seconds)
                            then 1
                            else 0
                        end
                    ) tma_within_target
                from customers c
                left join tma_tme_targets tq on tq.queue_id = c.queue_id
                cross join global_target gt
                where {where_sql}
                """,
                [DEFAULT_TME_TARGET_SECONDS, DEFAULT_TMA_TARGET_SECONDS, *params],
            ).fetchone()

            queue_rows = conn.execute(
                f"""
                with global_target as (
                    select
                        coalesce((select tme_target_seconds from tma_tme_targets where queue_id = 0), ?) as tme_target_seconds,
                        coalesce((select tma_target_seconds from tma_tme_targets where queue_id = 0), ?) as tma_target_seconds
                )
                select
                    q.id queue_id,
                    q.name queue_name,
                    count(*) total,
                    sum(case when c.first_response_at is not null then 1 else 0 end) answered_tickets,
                    sum(
                        case
                            when c.first_response_at is not null and c.closed_at is not null and c.closed_at >= c.first_response_at
                            then 1
                            else 0
                        end
                    ) handled_tickets,
                    avg(case when c.first_response_at is not null then c.first_response_at - c.created_at end) avg_tme_seconds,
                    avg(
                        case
                            when c.first_response_at is not null and c.closed_at is not null and c.closed_at >= c.first_response_at
                            then c.closed_at - c.first_response_at
                            else null
                        end
                    ) avg_tma_seconds,
                    sum(
                        case
                            when c.first_response_at is not null
                                 and c.first_response_at - c.created_at <= coalesce(tq.tme_target_seconds, gt.tme_target_seconds)
                            then 1
                            else 0
                        end
                    ) tme_within_target,
                    sum(
                        case
                            when c.first_response_at is not null
                                 and c.closed_at is not null
                                 and c.closed_at >= c.first_response_at
                                 and c.closed_at - c.first_response_at <= coalesce(tq.tma_target_seconds, gt.tma_target_seconds)
                            then 1
                            else 0
                        end
                    ) tma_within_target,
                    coalesce(tq.tme_target_seconds, gt.tme_target_seconds) tme_target_seconds,
                    coalesce(tq.tma_target_seconds, gt.tma_target_seconds) tma_target_seconds
                from customers c
                join queues q on q.id = c.queue_id
                left join tma_tme_targets tq on tq.queue_id = q.id
                cross join global_target gt
                where {where_sql}
                group by
                    q.id,
                    q.name,
                    coalesce(tq.tme_target_seconds, gt.tme_target_seconds),
                    coalesce(tq.tma_target_seconds, gt.tma_target_seconds)
                order by q.name asc
                """,
                [DEFAULT_TME_TARGET_SECONDS, DEFAULT_TMA_TARGET_SECONDS, *params],
            ).fetchall()

            operator_rows = conn.execute(
                f"""
                select
                    coalesce(u.name, 'Sem operador') operator_name,
                    count(*) total,
                    sum(case when c.first_response_at is not null then 1 else 0 end) answered_tickets,
                    sum(
                        case
                            when c.first_response_at is not null and c.closed_at is not null and c.closed_at >= c.first_response_at
                            then 1
                            else 0
                        end
                    ) handled_tickets,
                    avg(case when c.first_response_at is not null then c.first_response_at - c.created_at end) avg_tme_seconds,
                    avg(
                        case
                            when c.first_response_at is not null and c.closed_at is not null and c.closed_at >= c.first_response_at
                            then c.closed_at - c.first_response_at
                            else null
                        end
                    ) avg_tma_seconds
                from customers c
                left join users u on u.id = c.assigned_operator_id
                where {where_sql}
                group by u.id, u.name
                order by handled_tickets desc, answered_tickets desc, operator_name asc
                """,
                params,
            ).fetchall()

        summary_payload = dict(summary)
        summary_payload["total"] = int(summary_payload.get("total") or 0)
        summary_payload["answered_tickets"] = int(summary_payload.get("answered_tickets") or 0)
        summary_payload["handled_tickets"] = int(summary_payload.get("handled_tickets") or 0)
        summary_payload["tme_within_target"] = int(summary_payload.get("tme_within_target") or 0)
        summary_payload["tma_within_target"] = int(summary_payload.get("tma_within_target") or 0)
        summary_payload["avg_tme_seconds"] = normalize_avg_seconds(summary_payload.get("avg_tme_seconds"))
        summary_payload["avg_tma_seconds"] = normalize_avg_seconds(summary_payload.get("avg_tma_seconds"))
        summary_payload["tme_compliance_percent"] = percentage(
            summary_payload["tme_within_target"], summary_payload["answered_tickets"]
        )
        summary_payload["tma_compliance_percent"] = percentage(
            summary_payload["tma_within_target"], summary_payload["handled_tickets"]
        )
        summary_payload["target_tme_seconds"] = int(targets_payload["global"]["tme_target_seconds"])
        summary_payload["target_tma_seconds"] = int(targets_payload["global"]["tma_target_seconds"])

        by_queue = []
        for row in queue_rows:
            item = dict(row)
            item["total"] = int(item.get("total") or 0)
            item["answered_tickets"] = int(item.get("answered_tickets") or 0)
            item["handled_tickets"] = int(item.get("handled_tickets") or 0)
            item["tme_within_target"] = int(item.get("tme_within_target") or 0)
            item["tma_within_target"] = int(item.get("tma_within_target") or 0)
            item["tme_target_seconds"] = int(item.get("tme_target_seconds") or 0)
            item["tma_target_seconds"] = int(item.get("tma_target_seconds") or 0)
            item["avg_tme_seconds"] = normalize_avg_seconds(item.get("avg_tme_seconds"))
            item["avg_tma_seconds"] = normalize_avg_seconds(item.get("avg_tma_seconds"))
            item["tme_compliance_percent"] = percentage(item["tme_within_target"], item["answered_tickets"])
            item["tma_compliance_percent"] = percentage(item["tma_within_target"], item["handled_tickets"])
            by_queue.append(item)

        by_operator = []
        for row in operator_rows:
            item = dict(row)
            item["total"] = int(item.get("total") or 0)
            item["answered_tickets"] = int(item.get("answered_tickets") or 0)
            item["handled_tickets"] = int(item.get("handled_tickets") or 0)
            item["avg_tme_seconds"] = normalize_avg_seconds(item.get("avg_tme_seconds"))
            item["avg_tma_seconds"] = normalize_avg_seconds(item.get("avg_tma_seconds"))
            by_operator.append(item)

        self.send_json(
            {
                "summary": summary_payload,
                "by_queue": by_queue,
                "by_operator": by_operator,
                "targets": targets_payload,
                "window_days": days,
                "window_start": window_start,
                "generated_at": now,
            }
        )

    def api_dashboard_intelligence(self):
        user = self.require_user()
        if not user:
            return
        clause, params = self.visible_customer_clause(user)
        now = now_ts()

        with db() as conn:
            base = conn.execute(
                f"""
                select
                    sum(case when c.status != 'closed' then 1 else 0 end) active_tickets,
                    sum(case when c.status != 'closed' and c.assigned_operator_id is null then 1 else 0 end) unassigned_active,
                    sum(
                        case
                            when c.status != 'closed' and c.first_response_at is null and c.sla_due_at is not null and c.sla_due_at < ?
                            then 1
                            else 0
                        end
                    ) overdue_first_response,
                    avg(case when c.status != 'closed' then ? - c.created_at end) avg_active_age_seconds
                from customers c
                where {clause}
                """,
                [now, now, *params],
            ).fetchone()

            queue_rows = conn.execute(
                f"""
                select
                    q.name queue_name,
                    sum(case when c.status != 'closed' then 1 else 0 end) active_tickets,
                    sum(case when c.status != 'closed' and c.first_response_at is null then 1 else 0 end) waiting_first_response,
                    sum(
                        case
                            when c.status != 'closed' and c.first_response_at is null and c.sla_due_at is not null and c.sla_due_at < ?
                            then 1
                            else 0
                        end
                    ) overdue_first_response
                from customers c
                join queues q on q.id = c.queue_id
                where {clause}
                group by q.id, q.name
                order by q.name asc
                """,
                [now, *params],
            ).fetchall()

            operator_rows = conn.execute(
                f"""
                select
                    coalesce(u.name, 'Sem operador') operator_name,
                    sum(case when c.status != 'closed' then 1 else 0 end) active_tickets,
                    sum(case when c.status = 'closed' then 1 else 0 end) closed_tickets,
                    avg(case when c.first_response_at is not null then c.first_response_at - c.created_at end) avg_first_response_seconds
                from customers c
                left join users u on u.id = c.assigned_operator_id
                where {clause}
                group by u.id, u.name
                order by active_tickets desc, operator_name asc
                """,
                params,
            ).fetchall()

        active_tickets = int(base["active_tickets"] or 0)
        unassigned_active = int(base["unassigned_active"] or 0)
        overdue = int(base["overdue_first_response"] or 0)
        avg_age_seconds = int(round(base["avg_active_age_seconds"] or 0))

        alerts = []
        if overdue > 0:
            alerts.append(
                {
                    "level": "critical",
                    "title": "SLA de primeira resposta estourado",
                    "detail": f"{overdue} ticket(s) acima do SLA inicial.",
                }
            )
        if unassigned_active > 0:
            alerts.append(
                {
                    "level": "warning",
                    "title": "Tickets sem operador",
                    "detail": f"{unassigned_active} ticket(s) ativos sem responsável.",
                }
            )
        if active_tickets > 0 and avg_age_seconds > 7200:
            alerts.append(
                {
                    "level": "warning",
                    "title": "Backlog envelhecido",
                    "detail": f"Tempo médio dos tickets ativos em {avg_age_seconds}s.",
                }
            )
        if not alerts:
            alerts.append(
                {
                    "level": "info",
                    "title": "Operação estável",
                    "detail": "Nenhum alerta crítico no momento.",
                }
            )

        queue_health = []
        for row in queue_rows:
            item = dict(row)
            score = (item["overdue_first_response"] or 0) * 3 + (item["waiting_first_response"] or 0)
            item["pressure_score"] = int(score)
            queue_health.append(item)
        queue_health.sort(key=lambda x: x["pressure_score"], reverse=True)

        operators = []
        for row in operator_rows:
            item = dict(row)
            item["avg_first_response_seconds"] = int(round(item["avg_first_response_seconds"] or 0))
            operators.append(item)

        health_score = 100
        health_score -= min(overdue * 12, 60)
        health_score -= min(unassigned_active * 6, 24)
        if avg_age_seconds > 7200:
            health_score -= 10
        health_score = max(0, min(100, health_score))

        recommendations = []
        if overdue > 0:
            recommendations.append("Priorizar imediatamente tickets com SLA estourado.")
        if unassigned_active > 0:
            recommendations.append("Distribuir tickets sem operador para balancear carga.")
        if queue_health and queue_health[0]["pressure_score"] >= 3:
            recommendations.append(f"Reforçar a fila {queue_health[0]['queue_name']} nas próximas horas.")
        if not recommendations:
            recommendations.append("Manter monitoramento contínuo e revisar metas de SLA semanalmente.")

        self.send_json(
            {
                "score": health_score,
                "active_tickets": active_tickets,
                "unassigned_active": unassigned_active,
                "overdue_first_response": overdue,
                "avg_active_age_seconds": avg_age_seconds,
                "alerts": alerts,
                "queue_health": queue_health,
                "operators": operators,
                "recommendations": recommendations,
                "generated_at": now,
            }
        )

    def api_evolution_status(self):
        user = self.require_user()
        if not user:
            return
        self.send_json(
            {
                "configured": evolution.configured(),
                "baseUrl": EVOLUTION_BASE_URL,
                "instance": EVOLUTION_INSTANCE,
            }
        )

    def api_create_instance(self):
        user = self.require_user()
        if not user:
            return
        if user["role"] != "admin":
            self.send_json({"error": "Somente admin configura WhatsApp"}, HTTPStatus.FORBIDDEN)
            return
        try:
            self.send_json({"response": evolution.create_instance()})
        except RuntimeError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def api_set_webhook(self):
        user = self.require_user()
        if not user:
            return
        if user["role"] != "admin":
            self.send_json({"error": "Somente admin configura WhatsApp"}, HTTPStatus.FORBIDDEN)
            return
        payload = self.read_json()
        public_url = payload.get("public_url", "").strip()
        if not public_url:
            self.send_json({"error": "Informe a URL pública"}, HTTPStatus.BAD_REQUEST)
            return
        parsed_url = urlparse(public_url)
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
            self.send_json({"error": "URL pública inválida"}, HTTPStatus.BAD_REQUEST)
            return
        try:
            self.send_json({"response": evolution.set_webhook(public_url)})
        except RuntimeError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def api_webhook_inbound(self):
        payload = self.read_json()
        if WEBHOOK_TOKEN:
            token = self.headers.get("X-Webhook-Token", "")
            if token != WEBHOOK_TOKEN:
                self.send_json({"error": "Webhook token inválido"}, HTTPStatus.FORBIDDEN)
                return
        channel = normalize_channel(payload.get("channel"))
        if not channel:
            self.send_json({"error": "Canal inválido"}, HTTPStatus.BAD_REQUEST)
            return
        contact_input = payload.get("contact", payload.get("from", ""))
        contact_ref = normalize_customer_contact(channel, contact_input)
        if not contact_ref:
            self.send_json({"error": "Contato inválido"}, HTTPStatus.BAD_REQUEST)
            return
        text = str(payload.get("text", payload.get("body", ""))).strip()
        if not text:
            self.send_json({"error": "Mensagem vazia"}, HTTPStatus.BAD_REQUEST)
            return
        customer_name = str(payload.get("name") or contact_ref).strip() or contact_ref
        external_id = str(payload.get("event_id") or payload.get("external_id") or "")[:128]
        customer_key = build_customer_key(channel, contact_ref)
        with db() as conn:
            customer = conn.execute("select id from customers where phone = ?", (customer_key,)).fetchone()
            created_new_customer = False
            if not customer:
                queue_id = conn.execute("select id from queues order by id limit 1").fetchone()["id"]
                operator = conn.execute(
                    """
                    select u.id, count(c.id) load
                    from users u
                    left join customers c on c.assigned_operator_id = u.id and c.status != 'closed'
                    where u.role = 'operator' and u.active = 1
                    group by u.id
                    order by load asc, u.id asc
                    limit 1
                    """
                ).fetchone()
                cursor = conn.execute(
                    """
                    insert into customers
                    (name, phone, channel, contact_ref, queue_id, assigned_operator_id, status, last_message_at, sla_due_at, created_at)
                    values (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)
                    """,
                    (
                        customer_name,
                        customer_key,
                        channel,
                        contact_ref,
                        queue_id,
                        operator["id"] if operator else None,
                        now_ts(),
                        now_ts() + DEFAULT_SLA_FIRST_RESPONSE_SECONDS,
                        now_ts(),
                    ),
                )
                customer_id = cursor.lastrowid
                created_new_customer = True
            else:
                customer_id = customer["id"]
            conn.execute(
                "insert into messages (customer_id, direction, body, external_id, created_at) values (?, 'inbound', ?, ?, ?)",
                (customer_id, text, external_id, now_ts()),
            )
            conn.execute(
                """
                update customers
                set status = 'open',
                    finalized = 0,
                    closed_at = null,
                    last_message_at = ?,
                    sla_due_at = coalesce(sla_due_at, ?)
                where id = ?
                """,
                (now_ts(), now_ts() + DEFAULT_SLA_FIRST_RESPONSE_SECONDS, customer_id),
            )
        METRICS["messages_processed_total"] += 1
        publish_realtime_event(
            "ticket.updated",
            {
                "customer_id": customer_id,
                "source": "webhook",
                "kind": "inbound_message",
                "channel": channel,
                "created_new_customer": created_new_customer,
            },
            customer_id=customer_id,
        )
        self.send_json(
            {"ok": True, "customer_id": customer_id, "channel": channel, "created_new_customer": created_new_customer}
        )

    def api_webhook_evolution(self):
        payload = self.read_json()
        METRICS["webhook_received_total"] += 1
        if WEBHOOK_TOKEN:
            token = self.headers.get("X-Webhook-Token", "")
            if token != WEBHOOK_TOKEN:
                self.send_json({"error": "Webhook token inválido"}, HTTPStatus.FORBIDDEN)
                return
        data = payload.get("data", payload)
        if not isinstance(data, dict):
            data = {}
        key_data = data.get("key", {})
        if not isinstance(key_data, dict):
            key_data = {}
        event_key = str(
            key_data.get("id")
            or data.get("id")
            or payload.get("event_id")
            or hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
        )
        with db() as conn:
            try:
                conn.execute(
                    "insert into webhook_events (event_key, payload, processed, created_at) values (?, ?, 0, ?)",
                    (event_key, json.dumps(payload, ensure_ascii=False), now_ts()),
                )
            except sqlite3.IntegrityError:
                METRICS["webhook_duplicate_total"] += 1
                self.send_json({"ok": True, "duplicate": True, "event_key": event_key})
                return
        with WEBHOOK_COND:
            if len(WEBHOOK_QUEUE) >= MAX_WEBHOOK_QUEUE_SIZE:
                METRICS["webhook_queue_dropped_total"] += 1
                log_structured("webhook.backpressure", self.request_id, event_key=event_key, queue_depth=len(WEBHOOK_QUEUE))
                self.send_json(
                    {"ok": False, "queued": False, "event_key": event_key, "error": "Fila de webhook lotada"},
                    HTTPStatus.SERVICE_UNAVAILABLE,
                )
                return
            WEBHOOK_QUEUE.append((event_key, payload))
            WEBHOOK_COND.notify()
        log_structured("webhook.enqueued", self.request_id, event_key=event_key)
        self.send_json({"ok": True, "queued": True, "event_key": event_key})

    def api_reprocess_webhooks(self):
        user = self.require_user()
        if not user:
            return
        if user["role"] != "admin":
            self.send_json({"error": "Somente admin pode reprocessar"}, HTTPStatus.FORBIDDEN)
            return
        with db() as conn:
            rows = conn.execute(
                "select event_key, payload from webhook_events where processed = 0 order by id asc limit 100"
            ).fetchall()
        count = 0
        skipped_invalid = 0
        skipped_backpressure = 0
        with WEBHOOK_COND:
            for row in rows:
                try:
                    parsed_payload = json.loads(row["payload"])
                except json.JSONDecodeError:
                    skipped_invalid += 1
                    continue
                if len(WEBHOOK_QUEUE) >= MAX_WEBHOOK_QUEUE_SIZE:
                    skipped_backpressure += 1
                    continue
                WEBHOOK_QUEUE.append((row["event_key"], parsed_payload))
                count += 1
            if count:
                WEBHOOK_COND.notify_all()
        self.send_json(
            {
                "ok": True,
                "requeued": count,
                "skipped_invalid": skipped_invalid,
                "skipped_backpressure": skipped_backpressure,
            }
        )

    def customer_is_finalized(self, customer_id):
        with db() as conn:
            row = conn.execute("select finalized from customers where id = ?", (customer_id,)).fetchone()
        return bool(row and row["finalized"])


def customer_payload(row):
    payload = dict(row)
    try:
        payload["tags"] = json.loads(payload.get("tags") or "[]")
    except json.JSONDecodeError:
        payload["tags"] = []
    try:
        payload["erp_connection_data"] = json.loads(payload.get("erp_connection_data") or "{}")
    except json.JSONDecodeError:
        payload["erp_connection_data"] = {}
    payload["channel"] = normalize_channel(payload.get("channel") or "whatsapp") or "whatsapp"
    payload["contact_ref"] = str(payload.get("contact_ref") or payload.get("phone") or "").strip()
    payload["contact"] = payload["contact_ref"]
    return payload


def only_digits(value):
    return "".join(ch for ch in str(value) if ch.isdigit())


def normalize_channel(raw_channel):
    value = str(raw_channel or "").strip().lower().replace(" ", "_")
    if not value:
        return ""
    canonical = CHANNEL_ALIASES.get(value, value)
    if canonical not in SUPPORTED_CHANNELS:
        return ""
    return canonical


def normalize_customer_contact(channel, raw_contact):
    value = str(raw_contact or "").strip()
    if not value:
        return ""
    if channel == "whatsapp":
        digits = only_digits(value)
        if len(digits) < 10:
            return ""
        return digits
    if channel == "telegram":
        candidate = value.lstrip("@")
    elif channel == "instagram":
        candidate = value.lstrip("@").lower()
    elif channel == "facebook_messenger":
        candidate = value
    elif channel == "email":
        candidate = value.lower()
        if "@" not in candidate or "." not in candidate.split("@", 1)[-1]:
            return ""
    elif channel == "webchat":
        candidate = value
    else:
        return ""
    candidate = candidate.strip()
    if len(candidate) < 2 or len(candidate) > 160:
        return ""
    return candidate


def build_customer_key(channel, contact_ref):
    if channel == "whatsapp":
        return contact_ref
    return f"{channel}:{contact_ref}"


def main():
    init_db()
    worker = threading.Thread(target=webhook_worker, daemon=True, name="webhook-worker")
    worker.start()
    scheduler = threading.Thread(target=scheduled_messages_worker, daemon=True, name="scheduled-worker")
    scheduler.start()
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Omnichannel rodando em http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
