import http.cookiejar
import json
import os
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

    def login_master(self, password):
        return self.request_json("POST", "/api/login", {"email": "master", "password": password})

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
        customer_id = payload["customers"][0]["id"]

        code, payload = self.request_json("POST", f"/api/customers/{customer_id}/finalize", {})
        self.assertEqual(code, 200)
        self.assertTrue(payload["ok"])

        code, payload = self.request_json("POST", f"/api/customers/{customer_id}/send-boleto", {})
        self.assertEqual(code, 409)
        self.assertIn("finalizado", payload["error"])

        code, payload = self.request_json("POST", f"/api/customers/{customer_id}/unlock-billing", {})
        self.assertEqual(code, 409)
        self.assertIn("finalizado", payload["error"])


if __name__ == "__main__":
    unittest.main()
