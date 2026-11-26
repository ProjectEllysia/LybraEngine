"""El núcleo de ``lybrad``: cada operación del protocolo, sin socket y sin red.

Los escaneos corren con unas fases falsas (un puerto 80 con nginx 1.18.0) sobre
una base de conocimiento real en un directorio temporal, así que el camino es el
de producción —validar, encolar, escanear, cruzar con la base, convertir a la
forma de cable— salvo las sondas.
"""

from __future__ import annotations

import threading

import pytest

from lybra import protocol
from lybra.engine import Service
from lybra.kb_queries import KnowledgeBasePhases
from lybra.knowledge_base import KnowledgeBase
from lybra.protocol import ProtocolError, decode_request
from lybra.scanner import ScanSettings
from lybra.service import EngineService, ServiceSettings
from lybra.transport import PortSweep

pytestmark = pytest.mark.unit


class _FakePhases(KnowledgeBasePhases):
    """Un objetivo con nginx 1.18.0 en el 80; la detección por versión usa la base real."""

    gate: threading.Event = None
    reachable = True

    def is_host_reachable(self, target, port, timeout):
        return self.reachable

    def discover_ports(self, target, ports=None, budget_seconds=None, cancel_check=None, on_progress=None):
        if self.gate is not None:
            self.gate.wait(5)
        if on_progress:
            on_progress(1, 1)
        return PortSweep(open_ports=(80,), refused_ports=(), timed_out_ports=(), unreachable_ports=())

    def discover_udp_ports(self, target):
        return []

    def fingerprint_services(self, target, services, cancel_check=None, on_progress=None):
        return [Service(port=80, protocol="tcp", name="http", product="nginx", version="1.18.0")], []

    def run_crawler(self, target, services, cancel_check=None):
        return [], [], {}, {}

    def run_active_checks(self, target, services, **kwargs):
        return []

    def run_api_surface(self, target, services, mode="safe", cancel_check=None, fetch=None):
        return []

    def audit_named_sites(self, address, services, cancel_check, run_checks, extra_candidates=()):
        return []


@pytest.fixture
def kb(tmp_path):
    base = KnowledgeBase(tmp_path / "kb.sqlite")
    base.upsert_cve({"cve_id": "CVE-2021-23017", "cvss_score": 7.7, "severity": "HIGH",
                     "description": "nginx resolver off-by-one"},
                    [{"vendor": "nginx", "product": "nginx", "version_start_including": "0.6.18",
                      "version_end_excluding": "1.20.1"}])
    base.upsert_kev({"cve_id": "CVE-2021-23017", "date_added": None, "due_date": None, "known_ransomware": False})
    base.rebuild_cpe_product_index()
    yield base
    base.close()


def _service(kb, **settings):
    defaults = {"scan": ScanSettings(reachability_check=True, blocking_recheck_ports=0)}
    defaults.update(settings)
    service = EngineService(kb, ServiceSettings(**defaults), phases_factory=_FakePhases,
                            resolve=lambda name: {"public.example": ["93.184.216.7"],
                                                  "internal.example": ["10.1.2.3"]}.get(name, []))
    yield_service = service
    return yield_service


def _call(service, op, params=None, events=None):
    reply = service.handle({"v": 1, "id": "t-1", "op": op, "params": params or {}},
                           emit=events.append if events is not None else None)
    assert reply["id"] == "t-1"
    return reply


def _ok(service, op, params=None, events=None):
    reply = _call(service, op, params, events)
    assert reply["ok"], reply
    return reply["result"]


def _error(service, op, params=None):
    reply = _call(service, op, params)
    assert reply["ok"] is False, reply
    return reply["error"]["code"]


# ============================================================ escaneo

def test_a_scan_goes_from_queued_to_a_camel_case_result(kb):
    service = _service(kb)
    events = []

    scan_id = _ok(service, "scan.start", {"target": "93.184.216.10", "profile": "fast"})["scanId"]
    final = _ok(service, "scan.watch", {"scanId": scan_id}, events)
    result = _ok(service, "scan.result", {"scanId": scan_id})

    assert final["status"] == "completed"
    assert all(event["event"] == "progress" and event["id"] == "t-1" for event in events)
    assert result["status"] == "completed"
    assert result["services"][0]["product"] == "nginx"
    assert result["probedServices"] == [[80, "tcp"]]
    assert result["kbFeedVersion"].startswith("lybra-kb:")
    cve = next(finding for finding in result["findings"] if finding.get("cveIds"))
    assert cve["cveIds"] == ["CVE-2021-23017"] and cve["inKev"] is True
    assert "cve_ids" not in cve
    service.shutdown()


def test_an_unreachable_target_fails_with_its_reason(kb):
    service = _service(kb)
    _FakePhases.reachable = False
    try:
        scan_id = _ok(service, "scan.start", {"target": "93.184.216.10"})["scanId"]
        final = _ok(service, "scan.watch", {"scanId": scan_id})
    finally:
        _FakePhases.reachable = True

    assert final["status"] == "failed"
    assert final["error"]["code"] == "host_unreachable"
    assert _error(service, "scan.result", {"scanId": scan_id}) == "host_unreachable"
    service.shutdown()


def test_private_targets_are_refused_unless_allowed(kb):
    """Un motor que escanea lo que le pidan, junto a una aplicación web, es una
    puerta a la red interna: por defecto dice que no, también a un nombre que
    resuelve dentro."""
    service = _service(kb)
    for target in ("10.0.0.5", "127.0.0.1", "169.254.169.254", "internal.example", "db.local"):
        assert _error(service, "scan.start", {"target": target}) == "target_not_allowed", target
    service.shutdown()

    permissive = _service(kb, allow_private_targets=True)
    assert _ok(permissive, "scan.start", {"target": "10.0.0.5"})["status"] in ("queued", "running")
    permissive.shutdown()


def test_a_name_is_pinned_to_the_address_it_resolved_to(kb):
    seen = []

    class _Spy(_FakePhases):
        def analyze(self, services):
            import socket  # pylint: disable=import-outside-toplevel
            seen.append(socket.getaddrinfo("public.example", 80)[0][4][0])
            return []

    service = EngineService(kb, ServiceSettings(scan=ScanSettings(blocking_recheck_ports=0)), phases_factory=_Spy,
                            resolve=lambda name: ["93.184.216.7"])
    scan_id = _ok(service, "scan.start", {"target": "public.example"})["scanId"]
    _ok(service, "scan.watch", {"scanId": scan_id})

    assert seen == ["93.184.216.7"]
    service.shutdown()


@pytest.mark.parametrize("params, code", [
    ({}, "invalid_params"),
    ({"target": "no es un host"}, "invalid_target"),
    ({"target": "93.184.216.10/28"}, "invalid_target"),
    ({"target": "nowhere.example"}, "invalid_target"),
    ({"target": "93.184.216.10", "profile": "turbo"}, "invalid_params"),
    ({"target": "93.184.216.10", "ports": [0]}, "invalid_params"),
    ({"target": "93.184.216.10", "ports": "80"}, "invalid_params"),
    ({"target": "93.184.216.10", "timeoutSeconds": -1}, "invalid_params"),
    ({"target": "93.184.216.10", "aggressive": "yes"}, "invalid_params"),
])
def test_bad_scan_requests_are_rejected_with_their_code(kb, params, code):
    service = _service(kb)
    assert _error(service, "scan.start", params) == code
    service.shutdown()


def test_a_full_queue_answers_busy(kb):
    service = _service(kb, max_queued_scans=0)
    assert _error(service, "scan.start", {"target": "93.184.216.10"}) == "busy"
    service.shutdown()


def test_a_queued_scan_can_be_cancelled_before_it_starts(kb):
    gate = threading.Event()
    _FakePhases.gate = gate
    service = _service(kb, max_concurrent_scans=1)
    try:
        running = _ok(service, "scan.start", {"target": "93.184.216.10"})["scanId"]
        waiting = _ok(service, "scan.start", {"target": "93.184.216.11"})["scanId"]

        cancelled = _ok(service, "scan.cancel", {"scanId": waiting})
        gate.set()
        finished = _ok(service, "scan.watch", {"scanId": running})
    finally:
        _FakePhases.gate = None
        gate.set()

    assert cancelled["status"] == "cancelled"
    assert finished["status"] == "completed"
    assert _ok(service, "scan.status", {"scanId": waiting})["status"] == "cancelled"
    service.shutdown()


def test_an_unknown_scan_is_not_found(kb):
    service = _service(kb)
    for op in ("scan.status", "scan.result", "scan.cancel", "scan.watch"):
        assert _error(service, op, {"scanId": "nope"}) == "not_found"
    service.shutdown()


def test_the_known_services_feed_the_planner(kb):
    """Lo que la aplicación sabe del escaneo anterior llega al planificador:
    una identidad reciente de la revisión actual no se vuelve a sondear."""
    probed = []

    class _Counting(_FakePhases):
        def fingerprint_services(self, target, services, cancel_check=None, on_progress=None):
            probed.extend(service.port for service in services)
            return list(services), []

    from lybra._shared import isoformat_utc, utcnow_naive  # pylint: disable=import-outside-toplevel
    from lybra.planner import IDENTIFICATION_REVISION  # pylint: disable=import-outside-toplevel
    service = EngineService(kb, ServiceSettings(scan=ScanSettings(blocking_recheck_ports=0)),
                            phases_factory=_Counting)
    known = [{"port": 80, "protocol": "tcp", "product": "nginx", "version": "1.18.0",
              "identifiedAt": isoformat_utc(utcnow_naive()), "identifiedBy": IDENTIFICATION_REVISION}]
    scan_id = _ok(service, "scan.start", {"target": "93.184.216.10", "knownServices": known})["scanId"]
    _ok(service, "scan.watch", {"scanId": scan_id})
    result = _ok(service, "scan.result", {"scanId": scan_id})

    assert probed == []
    assert result["probedServices"] == []
    assert result["services"][0]["version"] == "1.18.0"
    service.shutdown()


# ============================================================ análisis sin red

def test_a_cpe_and_its_version_are_analysed_as_a_confirmed_fact(kb):
    """El caso de Hygeia: un inventario dice qué versión hay instalada, y eso
    es un hecho, no una suposición sacada de un banner."""
    service = _service(kb)

    result = _ok(service, "analyze", {"services": [
        {"cpe": "cpe:2.3:a:nginx:nginx", "version": "1.18.0", "origin": "inventory"},
        {"product": "nginx", "version": "1.25.0", "origin": "inventory"},
    ]})

    vulnerable = [finding for finding in result["findings"] if finding.get("cveIds")]
    assert [finding["cveIds"] for finding in vulnerable] == [["CVE-2021-23017"]]
    assert vulnerable[0]["confirmed"] is True
    service.shutdown()


@pytest.mark.parametrize("services", [None, [], "nginx", [{"version": "1.0"}], [{"port": 70000}],
                                      [{"product": "x", "origin": "rumor"}]])
def test_bad_analyze_requests_are_rejected(kb, services):
    service = _service(kb)
    assert _error(service, "analyze", {"services": services}) == "invalid_params"
    service.shutdown()


# ============================================================ base de conocimiento

def test_the_knowledge_base_operations(kb):
    service = _service(kb)

    assert _ok(service, "kb.cve", {"cveId": "cve-2021-23017"})["inKev"] is True
    assert _error(service, "kb.cve", {"cveId": "CVE-2000-0001"}) == "not_found"
    assert [cve["cveId"] for cve in _ok(service, "kb.version", {"product": "nginx", "version": "1.18.0"})["cves"]] \
        == ["CVE-2021-23017"]
    assert {"vendor": "nginx", "product": "nginx", "displayName": "nginx"} in \
        _ok(service, "kb.products", {"term": "ngi"})["products"]
    assert _ok(service, "kb.resolve", {"names": ["nginx", "nada"]})["products"] == [
        {"vendor": "nginx", "product": "nginx"}]
    assert _ok(service, "kb.advisories", {"products": [{"vendor": "nginx", "product": "nginx"}]})["advisories"] == []
    assert _ok(service, "kb.unresolved")["products"] == []
    assert _ok(service, "kb.status")["sources"]
    assert _ok(service, "engine.info")["kb"]["counts"]["cves"] == 1
    assert _error(service, "kb.sync", {"source": "shodan"}) == "invalid_params"
    service.shutdown()


def test_a_second_sync_while_one_runs_is_busy(kb):
    service = _service(kb)
    service._sync_lock.acquire()  # pylint: disable=protected-access
    try:
        assert _error(service, "kb.sync", {"source": "kev"}) == "busy"
    finally:
        service._sync_lock.release()  # pylint: disable=protected-access
    service.shutdown()


# ============================================================ protocolo

def test_an_unknown_operation_is_named(kb):
    service = _service(kb)
    assert _error(service, "scan.explode") == "unknown_op"
    service.shutdown()


@pytest.mark.parametrize("line, code", [
    (b"no es json", "bad_request"),
    (b"[1, 2]", "bad_request"),
    (b'{"v": 1, "op": "engine.info"}', "bad_request"),
    (b'{"v": 1, "id": "x", "params": {}}', "bad_request"),
    (b'{"v": 2, "id": "x", "op": "engine.info"}', "unsupported_version"),
    (b'{"v": 1, "id": "x", "op": "engine.info", "params": []}', "bad_request"),
])
def test_malformed_requests_are_rejected_with_their_code(line, code):
    with pytest.raises(ProtocolError) as error:
        decode_request(line)
    assert error.value.code == code


def test_engine_values_become_camel_case_json_values():
    from datetime import datetime  # pylint: disable=import-outside-toplevel

    wire = protocol.to_wire({"cve_ids": ("CVE-1",), "_installed_version": "1.0",
                             "seen_at": datetime(2026, 11, 24, 9, 0), "tags": {"b", "a"},
                             "evidence": {"payload": {"status_code": 200, "body": b"ok"}}})

    assert wire == {"cveIds": ["CVE-1"], "installedVersion": "1.0", "seenAt": "2026-11-24T09:00:00Z",
                    "tags": ["a", "b"], "evidence": {"payload": {"statusCode": 200, "body": "ok"}}}
