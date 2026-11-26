"""El cliente contra un servidor falso que contesta lo que cada test le guioniza.

No necesita el motor: el servidor lee la petición, la guarda y responde con
las líneas que el test le haya dado. Así se prueba el contrato del cliente con
el protocolo —qué envía, cómo lee eventos y errores— y nada más.
"""

from __future__ import annotations

import json
import os
import shutil
import socketserver
import tempfile
import threading

import pytest

from lybra_client import LybraClient, LybraConnectionError, LybraError


class _ScriptedServer:
    """Un socket Unix que responde a cada petición con ``script(request) -> [mensajes]``."""

    def __init__(self) -> None:
        self.directory = tempfile.mkdtemp(prefix="lybra-client-", dir="/tmp")
        self.path = os.path.join(self.directory, "s.sock")
        self.requests: list = []
        self.script = lambda request: [{"v": 1, "id": request["id"], "ok": True, "result": {}}]
        owner = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                line = self.rfile.readline()
                request = json.loads(line)
                owner.requests.append(request)
                for message in owner.script(request):
                    self.wfile.write(json.dumps(message).encode() + b"\n")

        self.server = socketserver.ThreadingUnixStreamServer(self.path, Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.directory, ignore_errors=True)


@pytest.fixture
def server():
    scripted = _ScriptedServer()
    yield scripted
    scripted.close()


def _ok(result):
    return lambda request: [{"v": 1, "id": request["id"], "ok": True, "result": result}]


def test_a_request_follows_the_protocol_frame(server):
    server.script = _ok({"engineVersion": "0.1.0"})

    assert LybraClient(server.path).info() == {"engineVersion": "0.1.0"}

    request = server.requests[0]
    assert request["v"] == 1 and request["op"] == "engine.info" and request["params"] == {}
    assert isinstance(request["id"], str) and 0 < len(request["id"]) <= 64


def test_unset_scan_options_are_not_sent_and_names_become_camel_case(server):
    server.script = _ok({"scanId": "abc", "status": "queued"})

    scan_id = LybraClient(server.path).scan_start(
        "198.51.100.10", profile="fast", timeout_seconds=60, active_checks=False,
        known_services=[{"port": 22, "product": "OpenSSH", "version": "9.6p1"}])

    assert scan_id == "abc"
    assert server.requests[0]["params"] == {
        "target": "198.51.100.10", "profile": "fast", "timeoutSeconds": 60, "activeChecks": False,
        "knownServices": [{"port": 22, "product": "OpenSSH", "version": "9.6p1"}]}


def test_watch_delivers_only_its_own_progress_events(server):
    def script(request):
        return [
            {"v": 1, "id": request["id"], "event": "progress", "data": {"phase": "discovery"}},
            {"v": 1, "id": "otra", "event": "progress", "data": {"phase": "ajena"}},
            {"v": 1, "id": request["id"], "event": "progress", "data": {"phase": "checks"}},
            {"v": 1, "id": request["id"], "ok": True, "result": {"status": "completed"}},
        ]

    server.script = script
    seen = []

    final = LybraClient(server.path).scan_watch("abc", on_progress=seen.append)

    assert final == {"status": "completed"}
    assert [event["phase"] for event in seen] == ["discovery", "checks"]


def test_a_full_scan_starts_watches_and_collects(server):
    def script(request):
        result = {"scan.start": {"scanId": "abc"}, "scan.watch": {"status": "completed"},
                  "scan.result": {"findings": [{"title": "x"}]}}[request["op"]]
        return [{"v": 1, "id": request["id"], "ok": True, "result": result}]

    server.script = script

    result = LybraClient(server.path).scan("198.51.100.10", profile="fast")

    assert result == {"findings": [{"title": "x"}]}
    assert [request["op"] for request in server.requests] == ["scan.start", "scan.watch", "scan.result"]
    assert all(request["params"].get("scanId") == "abc" for request in server.requests[1:])


def test_an_engine_error_keeps_its_code(server):
    server.script = lambda request: [{"v": 1, "id": request["id"], "ok": False,
                                      "error": {"code": "target_not_allowed", "message": "privada"}}]

    with pytest.raises(LybraError) as error:
        LybraClient(server.path).scan_start("10.0.0.5")

    assert (error.value.code, error.value.message) == ("target_not_allowed", "privada")


def test_a_connection_closed_without_answer_is_a_connection_error(server):
    server.script = lambda request: []

    with pytest.raises(LybraConnectionError):
        LybraClient(server.path).info()


def test_a_missing_socket_is_a_connection_error(tmp_path):
    with pytest.raises(LybraConnectionError) as error:
        LybraClient(str(tmp_path / "no.sock")).info()

    assert isinstance(error.value, ConnectionError)


def test_the_socket_path_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("LYBRA_SOCKET", "/tmp/otro.sock")
    assert LybraClient().socket_path == "/tmp/otro.sock"
    monkeypatch.delenv("LYBRA_SOCKET")
    assert LybraClient().socket_path == "/run/lybra/lybra.sock"


def test_the_knowledge_base_helpers_unwrap_their_lists(server):
    def script(request):
        result = {"kb.products": {"products": [{"vendor": "nginx"}]},
                  "kb.resolve": {"products": [{"vendor": "nginx", "product": "nginx"}]},
                  "kb.advisories": {"advisories": [{"cveId": "CVE-1"}]},
                  "kb.unresolved": {"products": [{"name": "x"}]}}[request["op"]]
        return [{"v": 1, "id": request["id"], "ok": True, "result": result}]

    server.script = script
    client = LybraClient(server.path)

    assert client.kb_products("ngi") == [{"vendor": "nginx"}]
    assert client.kb_resolve(["nginx"]) == [{"vendor": "nginx", "product": "nginx"}]
    assert client.kb_advisories([{"vendor": "nginx", "product": "nginx"}], since="2026-01-01T00:00:00Z",
                                min_cvss=7) == [{"cveId": "CVE-1"}]
    assert client.kb_unresolved(origin="inventory") == [{"name": "x"}]
    assert server.requests[2]["params"] == {"products": [{"vendor": "nginx", "product": "nginx"}], "limit": 20,
                                            "since": "2026-01-01T00:00:00Z", "minCvss": 7}


def test_the_passive_operations_send_their_params_and_wait_for_the_engine_deadline(server):
    server.script = lambda request: [{"v": 1, "id": request["id"], "ok": True, "result": {
        "osint.domain": {"domain": "example.com"}, "osint.hostnames": {"names": ["a.example.com"]},
        "cloud.probe": {"findings": []}}[request["op"]]}]
    client = LybraClient(server.path, timeout=1)
    waits = []
    original = client.call
    client.call = lambda op, params=None, **options: (waits.append(options.get("timeout")),
                                                       original(op, params, **options))[1]

    assert client.osint_domain("example.com", sources=["crtsh"], dkim_selectors=["s1"],
                               timeout_seconds=30) == {"domain": "example.com"}
    assert client.osint_hostnames("93.184.216.34") == ["a.example.com"]
    assert client.cloud_probe(["s3:b"], ["app.example.com"]) == {"findings": []}

    assert [request["params"] for request in server.requests] == [
        {"domain": "example.com", "sources": ["crtsh"], "dkimSelectors": ["s1"], "timeoutSeconds": 30},
        {"address": "93.184.216.34"},
        {"resources": ["s3:b"], "subdomains": ["app.example.com"]}]
    assert waits == [45, 135, 135]


def test_enrichment_is_opt_in_and_sends_the_address_it_is_about(server):
    server.script = _ok({"scanId": "abc", "findings": []})
    client = LybraClient(server.path)

    client.scan_start("198.51.100.10", enrich=True)
    client.analyze([{"product": "nginx"}])
    client.analyze([{"port": 80}], enrich=True, target="198.51.100.10")

    assert [request["params"] for request in server.requests] == [
        {"target": "198.51.100.10", "enrich": True},
        {"services": [{"product": "nginx"}]},
        {"services": [{"port": 80}], "enrich": True, "target": "198.51.100.10"}]
