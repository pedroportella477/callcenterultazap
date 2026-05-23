import hashlib
import hmac
import json
import os
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

APP_SECRET = os.environ.get("APP_SECRET", "dev-secret-change-me")
EVOLUTION_BASE_URL = os.environ.get("EVOLUTION_BASE_URL", "").rstrip("/")
EVOLUTION_API_KEY = os.environ.get("EVOLUTION_API_KEY", "")
EVOLUTION_INSTANCE = os.environ.get("EVOLUTION_INSTANCE", "atendimento")
WEBHOOK_TOKEN = os.environ.get("WEBHOOK_TOKEN", "")

SESSIONS = {}
WEBHOOK_QUEUE = deque()
WEBHOOK_COND = threading.Condition()
METRICS = {
    "http_requests_total": 0,
    "webhook_received_total": 0,
    "webhook_duplicate_total": 0,
    "webhook_reprocessed_total": 0,
    "webhook_failed_total": 0,
    "messages_processed_total": 0,
}


class APIError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def now_ts():
    return int(time.time())


def json_dumps(payload):
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
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


def init_db():
    with db() as conn:
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
                created_at integer not null,
                processed_at integer
            );
            """
        )

        user_cols = [row["name"] for row in conn.execute("pragma table_info(users)").fetchall()]
        if "permissions" not in user_cols:
            conn.execute("alter table users add column permissions text not null default '[]'")
        if "must_change_password" not in user_cols:
            conn.execute("alter table users add column must_change_password integer not null default 0")
        customer_cols = [row["name"] for row in conn.execute("pragma table_info(customers)").fetchall()]
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
                (name, phone, queue_id, assigned_operator_id, status, tags, last_message_at, created_at)
                values (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [(c[0], c[1], c[2], c[3], c[4], c[5], now_ts(), now_ts()) for c in customers],
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


def log_action(user_id, action, details):
    with db() as conn:
        conn.execute(
            "insert into audit_log (user_id, action, details, created_at) values (?, ?, ?, ?)",
            (user_id, action, json.dumps(details, ensure_ascii=False), now_ts()),
        )


def parse_permissions(raw_value):
    try:
        parsed = json.loads(raw_value or "[]")
        if isinstance(parsed, list):
            return set(str(item) for item in parsed)
    except json.JSONDecodeError:
        pass
    return set()


def log_structured(event, request_id, **fields):
    payload = {"event": event, "request_id": request_id, **fields}
    print(json.dumps(payload, ensure_ascii=True))


def metrics_payload():
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
        "# HELP webhook_reprocessed_total Webhook events reprocessed from queue.",
        "# TYPE webhook_reprocessed_total counter",
        f"webhook_reprocessed_total {METRICS['webhook_reprocessed_total']}",
        "# HELP webhook_failed_total Webhook events failed during processing.",
        "# TYPE webhook_failed_total counter",
        f"webhook_failed_total {METRICS['webhook_failed_total']}",
        "# HELP messages_processed_total Inbound messages processed by worker.",
        "# TYPE messages_processed_total counter",
        f"messages_processed_total {METRICS['messages_processed_total']}",
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
                (name, phone, queue_id, assigned_operator_id, status, last_message_at, created_at)
                values (?, ?, ?, ?, 'open', ?, ?)
                """,
                (phone, phone, queue_id, operator["id"] if operator else None, now_ts(), now_ts()),
            )
            customer_id = cursor.lastrowid
        else:
            customer_id = customer["id"]
        conn.execute(
            "insert into messages (customer_id, direction, body, external_id, created_at) values (?, 'inbound', ?, ?, ?)",
            (customer_id, text, str(key.get("id") or ""), now_ts()),
        )
        conn.execute("update customers set status = 'open', finalized = 0, last_message_at = ? where id = ?", (now_ts(), customer_id))
    METRICS["messages_processed_total"] += 1
    return True


def webhook_worker():
    while True:
        with WEBHOOK_COND:
            while not WEBHOOK_QUEUE:
                WEBHOOK_COND.wait()
            event_key, payload = WEBHOOK_QUEUE.popleft()
        try:
            METRICS["webhook_reprocessed_total"] += 1
            ok = process_inbound_payload(payload)
            with db() as conn:
                conn.execute(
                    "update webhook_events set processed = 1, processed_at = ? where event_key = ?",
                    (now_ts(), event_key),
                )
            if ok:
                log_structured("webhook.processed", "-", event_key=event_key)
            else:
                log_structured("webhook.ignored", "-", event_key=event_key)
        except Exception as exc:
            METRICS["webhook_failed_total"] += 1
            log_structured("webhook.failed", "-", event_key=event_key, error=str(exc))


class Handler(BaseHTTPRequestHandler):
    server_version = "OmniChannel/1.0"

    def log_message(self, fmt, *args):
        return

    def send_json(self, payload, status=HTTPStatus.OK):
        body = json_dumps(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("X-Request-ID", self.request_id)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, path):
        if not path.exists() or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content_type = "text/html; charset=utf-8"
        if path.suffix == ".css":
            content_type = "text/css; charset=utf-8"
        elif path.suffix == ".js":
            content_type = "application/javascript; charset=utf-8"
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

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise APIError(HTTPStatus.BAD_REQUEST, "Content-Length inválido")
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
        session = SESSIONS.get(token.value)
        if not session or session["expires_at"] < now_ts():
            return None
        with db() as conn:
            user = conn.execute(
                "select id, name, email, role, permissions, must_change_password, active from users where id = ? and active = 1",
                (session["user_id"],),
            ).fetchone()
            return dict(user) if user else None

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

    def do_GET(self):
        self.request_id = self.headers.get("X-Request-ID") or str(uuid.uuid4())
        METRICS["http_requests_total"] += 1
        log_structured("http.request", self.request_id, method="GET", path=self.path)
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/health":
                self.send_json({"ok": True, "ts": now_ts()})
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
            if path == "/api/dashboard":
                self.api_dashboard()
                return
            if path == "/api/evolution/status":
                self.api_evolution_status()
                return
            self.send_error(HTTPStatus.NOT_FOUND)
        except APIError as exc:
            self.send_json({"error": exc.message}, exc.status)
        except Exception as exc:
            log_structured("http.error", self.request_id, method="GET", path=self.path, error=str(exc))
            self.send_json({"error": "Erro interno"}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self):
        self.request_id = self.headers.get("X-Request-ID") or str(uuid.uuid4())
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
            if path == "/api/webhook/evolution":
                self.api_webhook_evolution()
                return
            if path == "/api/webhook/reprocess":
                self.api_reprocess_webhooks()
                return
            if path == "/api/change-password":
                self.api_change_password()
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
        with db() as conn:
            user = conn.execute(
                "select id, name, email, password_hash, role, permissions, must_change_password, active from users where lower(email) = ? or lower(name) = ?",
                (login_value, login_value),
            ).fetchone()
        if not user or not user["active"] or not verify_password(payload.get("password", ""), user["password_hash"]):
            self.send_json({"error": "E-mail ou senha inválidos"}, HTTPStatus.UNAUTHORIZED)
            return
        token = secrets.token_urlsafe(32)
        SESSIONS[token] = {"user_id": user["id"], "expires_at": now_ts() + 86400}
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
        self.send_header("Set-Cookie", f"session={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def api_logout(self):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        token = cookie.get("session")
        if token:
            SESSIONS.pop(token.value, None)
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("X-Request-ID", self.request_id)
        self.send_header("Set-Cookie", "session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
        self.end_headers()

    def api_change_password(self):
        user = self.require_user()
        if not user:
            return
        payload = self.read_json()
        old_password = payload.get("old_password", "")
        new_password = payload.get("new_password", "")
        if len(new_password) < 8:
            self.send_json({"error": "Nova senha deve ter pelo menos 8 caracteres"}, HTTPStatus.BAD_REQUEST)
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
        status = query.get("status", [""])[0]
        clause, params = self.visible_customer_clause(user)
        filters = [clause, "(c.name like ? or c.phone like ?)"]
        params.extend([search, search])
        if status:
            filters.append("c.status = ?")
            params.append(status)
        where_sql = " and ".join(filters)
        with db() as conn:
            rows = conn.execute(
                f"""
                select c.*, q.name queue_name, q.color queue_color, u.name operator_name
                from customers c
                join queues q on q.id = c.queue_id
                left join users u on u.id = c.assigned_operator_id
                where {where_sql}
                order by coalesce(c.last_message_at, c.created_at) desc
                """,
                params,
            ).fetchall()
        self.send_json({"customers": [customer_payload(row) for row in rows]})

    def api_messages(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if not self.can_access_customer(user, customer_id):
            self.send_json({"error": "Cliente fora da sua fila"}, HTTPStatus.FORBIDDEN)
            return
        with db() as conn:
            rows = conn.execute(
                "select * from messages where customer_id = ? order by created_at asc, id asc",
                (customer_id,),
            ).fetchall()
        self.send_json({"messages": [dict(row) for row in rows]})

    def api_send_message(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if not self.can_access_customer(user, customer_id):
            self.send_json({"error": "Cliente fora da sua fila"}, HTTPStatus.FORBIDDEN)
            return
        if self.customer_is_finalized(customer_id):
            self.send_json({"error": "Atendimento finalizado. Novas ações estão bloqueadas."}, HTTPStatus.CONFLICT)
            return
        payload = self.read_json()
        text = payload.get("body", "").strip()
        if not text:
            self.send_json({"error": "Mensagem vazia"}, HTTPStatus.BAD_REQUEST)
            return
        with db() as conn:
            customer = conn.execute("select * from customers where id = ?", (customer_id,)).fetchone()
            external_id = None
            status = "sent"
            try:
                if evolution.configured():
                    response = evolution.send_text(customer["phone"], text)
                    external_id = str(response.get("key", {}).get("id") or response.get("messageId") or "")
            except RuntimeError as exc:
                status = f"local: {exc}"
            conn.execute(
                "insert into messages (customer_id, direction, body, status, external_id, created_at) values (?, ?, ?, ?, ?, ?)",
                (customer_id, "outbound", text, status, external_id, now_ts()),
            )
            conn.execute("update customers set last_message_at = ? where id = ?", (now_ts(), customer_id))
        log_action(user["id"], "message.sent", {"customer_id": customer_id})
        self.send_json({"ok": True, "status": status})

    def api_create_customer(self):
        user = self.require_user()
        if not user:
            return
        payload = self.read_json()
        name = payload.get("name", "").strip()
        phone = only_digits(payload.get("phone", ""))
        queue_id = int(payload.get("queue_id") or 0)
        assigned_operator_id = payload.get("assigned_operator_id") or user["id"]
        if user["role"] != "admin":
            assigned_operator_id = user["id"]
        if not name or not phone or not queue_id:
            self.send_json({"error": "Nome, telefone e fila são obrigatórios"}, HTTPStatus.BAD_REQUEST)
            return
        with db() as conn:
            try:
                cursor = conn.execute(
                    """
                    insert into customers
                    (name, phone, queue_id, assigned_operator_id, status, last_message_at, created_at)
                    values (?, ?, ?, ?, 'open', ?, ?)
                    """,
                    (name, phone, queue_id, assigned_operator_id, now_ts(), now_ts()),
                )
            except sqlite3.IntegrityError:
                self.send_json({"error": "Telefone já cadastrado"}, HTTPStatus.CONFLICT)
                return
        log_action(user["id"], "customer.created", {"customer_id": cursor.lastrowid})
        self.send_json({"ok": True, "id": cursor.lastrowid}, HTTPStatus.CREATED)

    def api_assign_customer(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if user["role"] != "admin":
            self.send_json({"error": "Somente admin pode redistribuir filas"}, HTTPStatus.FORBIDDEN)
            return
        if self.customer_is_finalized(customer_id):
            self.send_json({"error": "Atendimento finalizado. Novas ações estão bloqueadas."}, HTTPStatus.CONFLICT)
            return
        payload = self.read_json()
        operator_id = int(payload.get("operator_id") or 0)
        with db() as conn:
            operator = conn.execute("select id from users where id = ? and role = 'operator'", (operator_id,)).fetchone()
            if not operator:
                self.send_json({"error": "Operador inválido"}, HTTPStatus.BAD_REQUEST)
                return
            conn.execute("update customers set assigned_operator_id = ? where id = ?", (operator_id, customer_id))
        log_action(user["id"], "customer.assigned", {"customer_id": customer_id, "operator_id": operator_id})
        self.send_json({"ok": True})

    def api_update_status(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if not self.can_access_customer(user, customer_id):
            self.send_json({"error": "Cliente fora da sua fila"}, HTTPStatus.FORBIDDEN)
            return
        if self.customer_is_finalized(customer_id):
            self.send_json({"error": "Atendimento finalizado. Novas ações estão bloqueadas."}, HTTPStatus.CONFLICT)
            return
        payload = self.read_json()
        status = payload.get("status")
        if status not in {"open", "pending", "closed"}:
            self.send_json({"error": "Status inválido"}, HTTPStatus.BAD_REQUEST)
            return
        with db() as conn:
            conn.execute("update customers set status = ? where id = ?", (status, customer_id))
        log_action(user["id"], "customer.status", {"customer_id": customer_id, "status": status})
        self.send_json({"ok": True})

    def api_transfer_customer(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if not self.can_access_customer(user, customer_id):
            self.send_json({"error": "Cliente fora da sua fila"}, HTTPStatus.FORBIDDEN)
            return
        if self.customer_is_finalized(customer_id):
            self.send_json({"error": "Atendimento finalizado. Novas ações estão bloqueadas."}, HTTPStatus.CONFLICT)
            return
        payload = self.read_json()
        operator_id = int(payload.get("operator_id") or 0)
        with db() as conn:
            operator = conn.execute("select id from users where id = ? and role = 'operator' and active = 1", (operator_id,)).fetchone()
            if not operator:
                self.send_json({"error": "Operador inválido"}, HTTPStatus.BAD_REQUEST)
                return
            conn.execute("update customers set assigned_operator_id = ?, finalized = 0 where id = ?", (operator_id, customer_id))
        log_action(user["id"], "customer.transferred", {"customer_id": customer_id, "operator_id": operator_id})
        self.send_json({"ok": True})

    def api_finalize_customer(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if not self.can_access_customer(user, customer_id):
            self.send_json({"error": "Cliente fora da sua fila"}, HTTPStatus.FORBIDDEN)
            return
        with db() as conn:
            conn.execute("update customers set status = 'closed', finalized = 1 where id = ?", (customer_id,))
        log_action(user["id"], "customer.finalized", {"customer_id": customer_id})
        self.send_json({"ok": True})

    def api_customer_erp(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if not self.can_access_customer(user, customer_id):
            self.send_json({"error": "Cliente fora da sua fila"}, HTTPStatus.FORBIDDEN)
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
        self.send_json(
            {
                "erp_active": bool(row["erp_provider"]),
                "provider": row["erp_provider"],
                "client_code": row["erp_client_code"],
                "financial_pending": bool(row["erp_financial_pending"]),
                "connection_data": json.loads(row["erp_connection_data"] or "{}"),
            }
        )

    def api_send_boleto(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if not self.can_access_customer(user, customer_id):
            self.send_json({"error": "Cliente fora da sua fila"}, HTTPStatus.FORBIDDEN)
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
            conn.execute("update customers set last_message_at = ? where id = ?", (now_ts(), customer_id))
        log_action(user["id"], "billing.boleto_sent", {"customer_id": customer_id})
        self.send_json({"ok": True})

    def api_unlock_billing(self, customer_id):
        user = self.require_user()
        if not user:
            return
        if not self.can_access_customer(user, customer_id):
            self.send_json({"error": "Cliente fora da sua fila"}, HTTPStatus.FORBIDDEN)
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
            conn.execute("update customers set last_message_at = ? where id = ?", (now_ts(), customer_id))
        log_action(user["id"], "billing.unlocked", {"customer_id": customer_id})
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
        try:
            self.send_json({"response": evolution.set_webhook(public_url)})
        except RuntimeError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def api_webhook_evolution(self):
        payload = self.read_json()
        METRICS["webhook_received_total"] += 1
        if WEBHOOK_TOKEN:
            token = self.headers.get("X-Webhook-Token", "")
            if token != WEBHOOK_TOKEN:
                self.send_json({"error": "Webhook token inválido"}, HTTPStatus.FORBIDDEN)
                return
        data = payload.get("data", payload)
        key_data = data.get("key", {})
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
        with WEBHOOK_COND:
            for row in rows:
                WEBHOOK_QUEUE.append((row["event_key"], json.loads(row["payload"])))
                count += 1
            if count:
                WEBHOOK_COND.notify_all()
        self.send_json({"ok": True, "requeued": count})

    def can_access_customer(self, user, customer_id):
        clause, params = self.visible_customer_clause(user)
        with db() as conn:
            row = conn.execute(f"select id from customers c where c.id = ? and {clause}", [customer_id, *params]).fetchone()
        return bool(row)

    def customer_is_finalized(self, customer_id):
        with db() as conn:
            row = conn.execute("select finalized from customers where id = ?", (customer_id,)).fetchone()
        return bool(row and row["finalized"])


def customer_payload(row):
    payload = dict(row)
    payload["tags"] = json.loads(payload.get("tags") or "[]")
    payload["erp_connection_data"] = json.loads(payload.get("erp_connection_data") or "{}")
    return payload


def only_digits(value):
    return "".join(ch for ch in str(value) if ch.isdigit())


def main():
    init_db()
    worker = threading.Thread(target=webhook_worker, daemon=True, name="webhook-worker")
    worker.start()
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Omnichannel rodando em http://127.0.0.1:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
