import http.cookiejar
import json
import os
import base64
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path


class HttpApiIntegrationTests(unittest.TestCase):
    MASTER_DEFAULT_PASSWORD = "admin123"
    MASTER_NEW_PASSWORD = "Admin#1234"

    @classmethod
    def setUpClass(cls):
        cls._tmpdir = tempfile.TemporaryDirectory()
        tmp_path = Path(cls._tmpdir.name)
        root = Path(__file__).resolve().parents[1]
        shutil.copy(root / "app.py", tmp_path / "app.py")
        shutil.copytree(root / "static", tmp_path / "static")

        cls.port = cls._free_port()
        env = os.environ.copy()
        env["PORT"] = str(cls.port)
        env["LOGIN_RATE_LIMIT_ATTEMPTS"] = "3"
        env["LOGIN_RATE_LIMIT_WINDOW_SECONDS"] = "120"
        env["MAX_JSON_BYTES"] = "65536"
        cls.proc = subprocess.Popen(
            [sys.executable, "app.py"],
            cwd=str(tmp_path),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls._wait_ready()

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "proc", None):
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        if getattr(cls, "_tmpdir", None):
            cls._tmpdir.cleanup()

    @classmethod
    def _free_port(cls):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        return port

    @classmethod
    def _wait_ready(cls):
        deadline = time.time() + 10
        last_error = None
        while time.time() < deadline:
            if cls.proc.poll() is not None:
                raise RuntimeError("Servidor encerrou antes de ficar pronto.")
            try:
                with urllib.request.urlopen(f"{cls.base_url}/health", timeout=1) as response:
                    if response.getcode() == 200:
                        return
            except Exception as exc:
                last_error = exc
                time.sleep(0.2)
        raise RuntimeError(f"Servidor não respondeu /health: {last_error}")

    def setUp(self):
        self.cookiejar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookiejar))

    def request_json(self, method, path, payload=None, raw_body=None):
        headers = {"Content-Type": "application/json"}
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
        if raw_body is not None:
            data = raw_body.encode("utf-8")
        req = urllib.request.Request(f"{self.base_url}{path}", data=data, method=method, headers=headers)
        try:
            with self.opener.open(req, timeout=3) as response:
                text = response.read().decode("utf-8")
                parsed = json.loads(text) if text else None
                return response.getcode(), parsed
        except urllib.error.HTTPError as exc:
            text = exc.read().decode("utf-8")
            parsed = json.loads(text) if text else None
            return exc.code, parsed

    def request_raw(self, method, path, payload=None):
        headers = {"Content-Type": "application/json"}
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(f"{self.base_url}{path}", data=data, method=method, headers=headers)
        try:
            with self.opener.open(req, timeout=3) as response:
                return response.getcode(), response.read(), response.headers
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), exc.headers

    def login_master(self, password):
        return self.request_json("POST", "/api/login", {"email": "master", "password": password})

    def login_user(self, login, password):
        return self.request_json("POST", "/api/login", {"email": login, "password": password})

    def ensure_logged_in_master(self):
        code, payload = self.login_master(self.MASTER_NEW_PASSWORD)
        if code == 200:
            return payload
        code, payload = self.login_master(self.MASTER_DEFAULT_PASSWORD)
        if code != 200:
            self.fail("Falha no login master.")
        return payload

    def test_01_default_password_requires_change(self):
        code, payload = self.login_master(self.MASTER_DEFAULT_PASSWORD)
        self.assertEqual(code, 200)
        self.assertEqual(payload["user"]["must_change_password"], 1)

        code, payload = self.request_json("GET", "/api/customers")
        self.assertEqual(code, 428)
        self.assertTrue(payload["must_change_password"])

        code, payload = self.request_json(
            "POST",
            "/api/change-password",
            {"old_password": self.MASTER_DEFAULT_PASSWORD, "new_password": self.MASTER_NEW_PASSWORD},
        )
        self.assertEqual(code, 200)
        self.assertTrue(payload["ok"])

        code, payload = self.login_master(self.MASTER_NEW_PASSWORD)
        self.assertEqual(code, 200)
        self.assertEqual(payload["user"]["must_change_password"], 0)

    def test_02_invalid_json_returns_400(self):
        self.ensure_logged_in_master()
        code, payload = self.request_json("POST", "/api/customers", raw_body="{invalid-json")
        self.assertEqual(code, 400)
        self.assertIn("JSON", payload["error"])

    def test_03_invalid_customer_id_returns_400(self):
        self.ensure_logged_in_master()
        code, payload = self.request_json("GET", "/api/customers/foo/messages")
        self.assertEqual(code, 400)
        self.assertIn("ID de cliente inválido", payload["error"])

    def test_04_finalized_blocks_erp_actions(self):
        self.ensure_logged_in_master()
        code, payload = self.request_json("GET", "/api/customers")
        self.assertEqual(code, 200)
        target = next((c for c in payload["customers"] if not c.get("finalized")), payload["customers"][0])
        customer_id = target["id"]

        code, payload = self.request_json("POST", f"/api/customers/{customer_id}/finalize", {})
        self.assertEqual(code, 200)
        self.assertTrue(payload["ok"])

        code, payload = self.request_json("POST", f"/api/customers/{customer_id}/send-boleto", {})
        self.assertEqual(code, 409)
        self.assertIn("finalizado", payload["error"])

        code, payload = self.request_json("POST", f"/api/customers/{customer_id}/unlock-billing", {})
        self.assertEqual(code, 409)
        self.assertIn("finalizado", payload["error"])

    def test_05_invalid_status_filter_returns_400(self):
        self.ensure_logged_in_master()
        code, payload = self.request_json("GET", "/api/customers?status=invalid")
        self.assertEqual(code, 400)
        self.assertIn("status", payload["error"].lower())

    def test_06_non_existing_customer_returns_404(self):
        self.ensure_logged_in_master()
        code, payload = self.request_json("GET", "/api/customers/999999/messages")
        self.assertEqual(code, 404)
        self.assertIn("cliente", payload["error"].lower())

    def test_07_payload_too_large_returns_413(self):
        oversized_password = "x" * 70000
        raw = json.dumps({"email": "master", "password": oversized_password})
        code, payload = self.request_json("POST", "/api/login", raw_body=raw)
        self.assertEqual(code, 413)
        self.assertIn("payload", payload["error"].lower())

    def test_99_login_rate_limit_returns_429(self):
        for _ in range(3):
            code, payload = self.request_json("POST", "/api/login", {"email": "master", "password": "errada"})
            self.assertEqual(code, 401)
            self.assertIn("senha", payload["error"].lower())

        code, payload = self.request_json("POST", "/api/login", {"email": "master", "password": "errada"})
        self.assertEqual(code, 429)
        self.assertIn("muitas tentativas", payload["error"].lower())

    def test_09_sla_endpoint_returns_summary(self):
        self.ensure_logged_in_master()
        code, payload = self.request_json("GET", "/api/sla")
        self.assertEqual(code, 200)
        self.assertIn("sla", payload)
        self.assertIn("by_queue", payload)
        self.assertIn("waiting_first_response", payload["sla"])
        self.assertIn("breached_first_response", payload["sla"])

    def test_10_create_customer_invalid_queue_returns_400(self):
        self.ensure_logged_in_master()
        code, payload = self.request_json(
            "POST",
            "/api/customers",
            {"name": "Teste", "phone": "5511999998888", "queue_id": 999999},
        )
        self.assertEqual(code, 400)
        self.assertIn("fila", payload["error"].lower())

    def test_11_health_contains_operational_keys(self):
        code, payload = self.request_json("GET", "/health")
        self.assertEqual(code, 200)
        self.assertIn("queue_depth", payload)
        self.assertIn("pending_webhooks", payload)
        self.assertIn("realtime_subscribers", payload)

    def test_12_events_requires_auth(self):
        code, payload = self.request_json("GET", "/api/events")
        self.assertEqual(code, 401)
        self.assertIn("autenticado", payload["error"].lower())

    def test_13_intelligence_endpoint_returns_managed_payload(self):
        self.ensure_logged_in_master()
        code, payload = self.request_json("GET", "/api/dashboard/intelligence")
        self.assertEqual(code, 200)
        self.assertIn("score", payload)
        self.assertIn("alerts", payload)
        self.assertIn("queue_health", payload)
        self.assertIn("operators", payload)
        self.assertIn("recommendations", payload)

    def test_14_tma_tme_endpoint_returns_summary(self):
        self.ensure_logged_in_master()
        code, payload = self.request_json("GET", "/api/tma-tme?days=30")
        self.assertEqual(code, 200)
        self.assertIn("summary", payload)
        self.assertIn("by_queue", payload)
        self.assertIn("by_operator", payload)
        self.assertIn("targets", payload)
        self.assertIn("avg_tme_seconds", payload["summary"])
        self.assertIn("avg_tma_seconds", payload["summary"])
        self.assertIn("tme_compliance_percent", payload["summary"])
        self.assertIn("tma_compliance_percent", payload["summary"])

    def test_15_tma_tme_targets_update_requires_admin(self):
        code, payload = self.login_user("ana@local", "operador123")
        self.assertEqual(code, 200)
        self.assertEqual(payload["user"]["role"], "operator")
        code, payload = self.request_json(
            "POST",
            "/api/tma-tme/targets",
            {"global": {"tme_target_seconds": 200, "tma_target_seconds": 800}},
        )
        self.assertEqual(code, 403)
        self.assertIn("admin", payload["error"].lower())

    def test_16_tma_tme_targets_update_and_read(self):
        self.ensure_logged_in_master()
        code, payload = self.request_json("GET", "/api/queues")
        self.assertEqual(code, 200)
        queue_id = payload["queues"][0]["id"]

        code, payload = self.request_json(
            "POST",
            "/api/tma-tme/targets",
            {
                "global": {"tme_target_seconds": 240, "tma_target_seconds": 900},
                "queues": [
                    {
                        "queue_id": queue_id,
                        "tme_target_seconds": 180,
                        "tma_target_seconds": 720,
                    }
                ],
            },
        )
        self.assertEqual(code, 200)
        self.assertTrue(payload["ok"])

        code, payload = self.request_json("GET", "/api/tma-tme/targets")
        self.assertEqual(code, 200)
        self.assertEqual(payload["targets"]["global"]["tme_target_seconds"], 240)
        self.assertEqual(payload["targets"]["global"]["tma_target_seconds"], 900)

        target_row = next((row for row in payload["targets"]["queues"] if row["queue_id"] == queue_id), None)
        self.assertIsNotNone(target_row)
        self.assertTrue(target_row["has_custom_target"])
        self.assertEqual(target_row["tme_target_seconds"], 180)
        self.assertEqual(target_row["tma_target_seconds"], 720)

    def test_17_quick_reply_crud_and_send(self):
        self.ensure_logged_in_master()
        code, payload = self.request_json(
            "POST",
            "/api/quick-replies",
            {"shortcut": "/saudacao", "body": "Ola! Tudo bem por ai?"},
        )
        self.assertEqual(code, 200)
        self.assertTrue(payload["ok"])

        code, payload = self.request_json("GET", "/api/quick-replies")
        self.assertEqual(code, 200)
        shortcuts = {item["shortcut"] for item in payload["quick_replies"]}
        self.assertIn("/saudacao", shortcuts)

        code, payload = self.request_json("GET", "/api/customers")
        self.assertEqual(code, 200)
        target = next((c for c in payload["customers"] if not c.get("finalized")), payload["customers"][0])
        customer_id = target["id"]

        code, payload = self.request_json(
            "POST",
            f"/api/customers/{customer_id}/quick-reply",
            {"shortcut": "/saudacao"},
        )
        self.assertEqual(code, 200)
        self.assertTrue(payload["ok"])

        code, payload = self.request_json("GET", f"/api/customers/{customer_id}/messages")
        self.assertEqual(code, 200)
        self.assertTrue(any(msg["body"] == "Ola! Tudo bem por ai?" for msg in payload["messages"]))

    def test_18_private_notes_and_schedule_lifecycle(self):
        self.ensure_logged_in_master()
        code, payload = self.request_json("GET", "/api/customers")
        self.assertEqual(code, 200)
        target = next((c for c in payload["customers"] if not c.get("finalized")), payload["customers"][0])
        customer_id = target["id"]

        code, payload = self.request_json(
            "POST",
            f"/api/customers/{customer_id}/notes",
            {"body": "Cliente informou melhor horario apos as 14h."},
        )
        self.assertEqual(code, 200)
        self.assertTrue(payload["ok"])

        code, payload = self.request_json("GET", f"/api/customers/{customer_id}/notes")
        self.assertEqual(code, 200)
        self.assertTrue(any("14h" in note["body"] for note in payload["notes"]))

        schedule_at = int(time.time()) + 300
        code, payload = self.request_json(
            "POST",
            f"/api/customers/{customer_id}/schedule-message",
            {"body": "Lembrete de retorno agendado", "send_at": schedule_at},
        )
        self.assertEqual(code, 201)
        scheduled_id = payload["id"]

        code, payload = self.request_json("GET", f"/api/customers/{customer_id}/scheduled-messages")
        self.assertEqual(code, 200)
        created = next((item for item in payload["scheduled_messages"] if item["id"] == scheduled_id), None)
        self.assertIsNotNone(created)
        self.assertEqual(created["status"], "pending")

        code, payload = self.request_json("POST", f"/api/scheduled-messages/{scheduled_id}/cancel", {})
        self.assertEqual(code, 200)
        self.assertTrue(payload["ok"])

        code, payload = self.request_json("GET", f"/api/customers/{customer_id}/scheduled-messages")
        self.assertEqual(code, 200)
        cancelled = next((item for item in payload["scheduled_messages"] if item["id"] == scheduled_id), None)
        self.assertIsNotNone(cancelled)
        self.assertEqual(cancelled["status"], "cancelled")

    def test_19_scheduled_worker_sends_due_message(self):
        self.ensure_logged_in_master()
        code, payload = self.request_json("GET", "/api/customers")
        self.assertEqual(code, 200)
        target = next((c for c in payload["customers"] if not c.get("finalized")), payload["customers"][0])
        customer_id = target["id"]

        auto_text = f"Mensagem automatica {int(time.time())}"
        code, payload = self.request_json(
            "POST",
            f"/api/customers/{customer_id}/schedule-message",
            {"body": auto_text, "send_at": int(time.time()) - 1},
        )
        self.assertEqual(code, 201)
        scheduled_id = payload["id"]

        sent = False
        deadline = time.time() + 6
        while time.time() < deadline:
            code, current = self.request_json("GET", f"/api/customers/{customer_id}/scheduled-messages")
            self.assertEqual(code, 200)
            row = next((item for item in current["scheduled_messages"] if item["id"] == scheduled_id), None)
            if row and row["status"] == "sent":
                sent = True
                break
            time.sleep(0.4)
        self.assertTrue(sent, "Mensagem agendada nao foi enviada no prazo esperado")

        code, payload = self.request_json("GET", f"/api/customers/{customer_id}/messages")
        self.assertEqual(code, 200)
        self.assertTrue(any(msg["body"] == auto_text for msg in payload["messages"]))

    def test_20_team_chat_post_and_list(self):
        self.ensure_logged_in_master()
        code, payload = self.request_json(
            "POST",
            "/api/team-messages",
            {"body": "Pessoal, vou assumir os tickets da fila comercial."},
        )
        self.assertEqual(code, 201)
        self.assertIn("id", payload)

        code, payload = self.request_json("GET", "/api/team-messages?limit=20")
        self.assertEqual(code, 200)
        self.assertIn("messages", payload)
        self.assertTrue(any("fila comercial" in msg["body"] for msg in payload["messages"]))

    def test_21_media_send_and_list(self):
        self.ensure_logged_in_master()
        code, payload = self.request_json("GET", "/api/customers")
        self.assertEqual(code, 200)
        target = next((c for c in payload["customers"] if not c.get("finalized")), payload["customers"][0])
        customer_id = target["id"]

        code, payload = self.request_json(
            "POST",
            f"/api/customers/{customer_id}/media",
            {
                "media_type": "image",
                "url": "https://example.com/fatura.png",
                "caption": "Segue comprovante",
            },
        )
        self.assertEqual(code, 200)
        self.assertTrue(payload["ok"])

        code, payload = self.request_json("GET", f"/api/customers/{customer_id}/media")
        self.assertEqual(code, 200)
        self.assertTrue(any(item["url"] == "https://example.com/fatura.png" for item in payload["media"]))

    def test_22_campaign_create_and_list(self):
        self.ensure_logged_in_master()
        code, payload = self.request_json("GET", "/api/customers")
        self.assertEqual(code, 200)
        available = [c for c in payload["customers"] if not c.get("finalized")]
        self.assertTrue(len(available) >= 1)
        customer_ids = [available[0]["id"]]
        if len(available) > 1:
            customer_ids.append(available[1]["id"])

        campaign_name = f"campanha-auto-{int(time.time())}"
        code, payload = self.request_json(
            "POST",
            "/api/campaigns",
            {
                "name": campaign_name,
                "body": "Mensagem em massa para clientes selecionados.",
                "customer_ids": customer_ids,
            },
        )
        self.assertEqual(code, 201)
        self.assertTrue(payload["ok"])
        self.assertGreaterEqual(payload["sent_total"], 1)

        code, payload = self.request_json("GET", "/api/campaigns?limit=20")
        self.assertEqual(code, 200)
        names = [item["name"] for item in payload["campaigns"]]
        self.assertIn(campaign_name, names)

    def test_23_media_upload_file_and_list(self):
        self.ensure_logged_in_master()
        code, payload = self.request_json("GET", "/api/customers")
        self.assertEqual(code, 200)
        target = next((c for c in payload["customers"] if not c.get("finalized")), payload["customers"][0])
        customer_id = target["id"]

        encoded = base64.b64encode(b"arquivo de teste").decode("ascii")
        code, payload = self.request_json(
            "POST",
            f"/api/customers/{customer_id}/media-upload",
            {
                "media_type": "file",
                "filename": "comprovante.txt",
                "content_base64": encoded,
                "caption": "Comprovante em anexo",
            },
        )
        self.assertEqual(code, 200)
        self.assertTrue(payload["ok"])
        self.assertTrue(str(payload["url"]).startswith("/uploads/"))

        code, payload = self.request_json("GET", f"/api/customers/{customer_id}/media")
        self.assertEqual(code, 200)
        self.assertTrue(any(item["url"].startswith("/uploads/") for item in payload["media"]))

    def test_24_ai_suggest_returns_text(self):
        self.ensure_logged_in_master()
        code, payload = self.request_json("GET", "/api/customers")
        self.assertEqual(code, 200)
        target = next((c for c in payload["customers"] if not c.get("finalized")), payload["customers"][0])
        customer_id = target["id"]

        code, payload = self.request_json("POST", f"/api/customers/{customer_id}/ai-suggest", {})
        self.assertEqual(code, 200)
        self.assertTrue(payload["provider"] in {"fallback", "openai"})
        self.assertTrue(isinstance(payload["suggestion"], str))
        self.assertGreater(len(payload["suggestion"].strip()), 0)

    def test_25_campaign_scheduled_and_export_csv(self):
        self.ensure_logged_in_master()
        code, payload = self.request_json("GET", "/api/customers")
        self.assertEqual(code, 200)
        available = [c for c in payload["customers"] if not c.get("finalized")]
        self.assertTrue(len(available) >= 1)
        customer_ids = [available[0]["id"]]
        scheduled_at = int(time.time()) + 900
        campaign_name = f"campanha-agendada-{int(time.time())}"

        code, payload = self.request_json(
            "POST",
            "/api/campaigns",
            {
                "name": campaign_name,
                "body": "Mensagem agendada da campanha.",
                "customer_ids": customer_ids,
                "scheduled_at": scheduled_at,
                "rate_per_minute": 30,
            },
        )
        self.assertEqual(code, 201)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["rate_per_minute"], 30)
        self.assertGreaterEqual(payload["queued_total"], 1)
        campaign_id = payload["campaign_id"]

        code, payload = self.request_json("GET", "/api/campaigns?limit=30")
        self.assertEqual(code, 200)
        campaign = next((item for item in payload["campaigns"] if item["id"] == campaign_id), None)
        self.assertIsNotNone(campaign)
        self.assertEqual(campaign["rate_per_minute"], 30)

        code, raw_body, headers = self.request_raw("GET", f"/api/campaigns/{campaign_id}/export")
        self.assertEqual(code, 200)
        self.assertIn("text/csv", headers.get("Content-Type", ""))
        decoded = raw_body.decode("utf-8-sig")
        self.assertIn("campaign_id,campaign_name,campaign_status", decoded)
        self.assertIn(campaign_name, decoded)

    def test_26_create_customer_email_channel_and_filter(self):
        self.ensure_logged_in_master()
        code, payload = self.request_json("GET", "/api/queues")
        self.assertEqual(code, 200)
        queue_id = payload["queues"][0]["id"]
        unique_email = f"cliente{int(time.time())}@dominio.com"

        code, payload = self.request_json(
            "POST",
            "/api/customers",
            {"name": "Cliente Email", "channel": "email", "contact": unique_email, "queue_id": queue_id},
        )
        self.assertEqual(code, 201)
        self.assertTrue(payload["ok"])
        created_id = payload["id"]

        code, payload = self.request_json("GET", "/api/customers?channel=email")
        self.assertEqual(code, 200)
        row = next((item for item in payload["customers"] if item["id"] == created_id), None)
        self.assertIsNotNone(row)
        self.assertEqual(row["channel"], "email")
        self.assertEqual(row["contact"], unique_email)

    def test_27_webhook_inbound_telegram_creates_customer(self):
        self.ensure_logged_in_master()
        handle = f"usuario_telegram_{int(time.time())}"
        text = "Mensagem recebida do Telegram"
        code, payload = self.request_json(
            "POST",
            "/api/webhook/inbound",
            {"channel": "telegram", "contact": handle, "name": "Cliente TG", "text": text, "event_id": str(int(time.time()))},
        )
        self.assertEqual(code, 200)
        self.assertTrue(payload["ok"])
        customer_id = payload["customer_id"]

        code, payload = self.request_json("GET", "/api/customers?channel=telegram")
        self.assertEqual(code, 200)
        row = next((item for item in payload["customers"] if item["id"] == customer_id), None)
        self.assertIsNotNone(row)
        self.assertEqual(row["channel"], "telegram")
        self.assertEqual(row["contact"], handle)

        code, payload = self.request_json("GET", f"/api/customers/{customer_id}/messages")
        self.assertEqual(code, 200)
        self.assertTrue(any(msg["body"] == text and msg["direction"] == "inbound" for msg in payload["messages"]))


if __name__ == "__main__":
    unittest.main()
