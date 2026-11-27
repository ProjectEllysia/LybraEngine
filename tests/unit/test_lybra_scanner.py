"""El orquestador del motor: qué fases corren, en qué orden y con qué permisos.

``run_scan`` no hace red por sí mismo: llama a las fases de ``ScanPhases``.
Aquí se sustituyen todas por unas falsas que apuntan lo que se les pide, así
que cada test comprueba una decisión del orquestador —qué se salta, qué se
marca como parcial, qué le llega a cada fase— sin sondas ni base de datos.
"""

from __future__ import annotations

import ipaddress
import socket

import pytest

from lybra import PortSweep, Service
from lybra.core.scanner import (
    ScanAborted,
    ScanPhases,
    ScanRequest,
    ScanSettings,
    run_scan,
)

pytestmark = pytest.mark.unit


def _sweep(open_ports=(80,), refused=(), timed_out=(), truncated=False) -> PortSweep:
    return PortSweep(open_ports=tuple(open_ports), refused_ports=tuple(refused),
                     timed_out_ports=tuple(timed_out), unreachable_ports=(),
                     was_truncated=truncated)


class _Phases(ScanPhases):
    """Fases falsas: apuntan cada llamada y devuelven lo que el test configure."""

    def __init__(self, sweep=None, recheck=None, version_findings=(), active_findings=(),
                 settings=None):
        super().__init__(settings or ScanSettings(reachability_check=False))
        self.sweep = sweep if sweep is not None else _sweep()
        self.recheck = recheck
        self.version_findings = list(version_findings)
        self.active_findings = list(active_findings)
        self.calls: list = []
        self.sweeps = 0
        self.cancel_checks: dict = {}

    def discover_ports(self, target, ports=None, budget_seconds=None, cancel_check=None,
                       on_progress=None):
        self.sweeps += 1
        self.calls.append(("discover", target, ports))
        if self.sweeps > 1 and self.recheck is not None:
            return self.recheck
        return self.sweep

    def discover_udp_ports(self, target):
        self.calls.append(("udp", target))
        return []

    def fingerprint_services(self, target, services, cancel_check=None, on_progress=None):
        self.calls.append(("fingerprint", [service.port for service in services]))
        identified = [Service(port=service.port, protocol=service.protocol, name="http",
                              product="nginx", version="1.24.0") for service in services]
        return identified, []

    def analyze(self, services):
        self.calls.append(("analyze", [(service.port, service.product) for service in services]))
        return [dict(finding) for finding in self.version_findings]

    def run_crawler(self, target, services, cancel_check=None):
        self.calls.append(("crawl", target))
        self.cancel_checks["crawl"] = cancel_check
        return [], ["/admin"], {}, {}

    def run_active_checks(self, target, services, **kwargs):
        self.calls.append(("active", target, kwargs.get("mode"), kwargs.get("proposed_cves")))
        return [dict(finding) for finding in self.active_findings]

    def run_api_surface(self, target, services, mode="safe", cancel_check=None, fetch=None):
        self.calls.append(("api", target))
        return []

    def audit_named_sites(self, address, services, cancel_check, run_checks, extra_candidates=()):
        self.calls.append(("sites", address, tuple(extra_candidates)))
        return []

    def run_credential_checks(self, target, services, mode, discovered_paths=None, cancel_check=None):
        self.calls.append(("credentials", mode, discovered_paths))
        self.cancel_checks["credentials"] = cancel_check
        return []

    def phases_called(self):
        return [call[0] for call in self.calls]


# ============================================================ sin red

def test_known_services_are_analysed_without_touching_the_target():
    """Un inventario ya resuelto se cruza con la base de conocimiento y nada más:
    ni descubrimiento, ni fingerprint, ni checks, aunque estén permitidos."""
    phases = _Phases(version_findings=[{"title": "CVE", "cve_ids": ["CVE-2024-1"]}])
    services = [Service(port=None, protocol="", product="openssl", version="3.0.1", origin="inventory")]

    outcome = run_scan(ScanRequest(target="srv-01", services=services, mode="aggressive"), phases)

    assert phases.phases_called() == ["analyze"]
    assert outcome.findings == [{"title": "CVE", "cve_ids": ["CVE-2024-1"]}]
    assert outcome.is_partial is False


# ============================================================ descubrimiento

def test_an_unreachable_target_aborts_before_the_sweep():
    class _Unreachable(_Phases):
        def is_host_reachable(self, target, port, timeout):
            return False

    phases = _Unreachable(settings=ScanSettings(reachability_check=True))

    with pytest.raises(ScanAborted) as aborted:
        run_scan(ScanRequest(target="203.0.113.5"), phases)

    assert aborted.value.reason == ScanAborted.HOST_UNREACHABLE
    assert "discover" not in phases.phases_called()


def test_a_blocked_sweep_aborts_the_scan():
    """Un barrido bloqueado no es un objetivo limpio: tratarlo como «todo
    cerrado» daría por corregido lo que sigue abierto."""
    class _Blocked(_Phases):
        def discover_ports(self, target, ports=None, **kwargs):
            return None

    with pytest.raises(ScanAborted) as aborted:
        run_scan(ScanRequest(target="203.0.113.5"), _Blocked())

    assert aborted.value.reason == ScanAborted.PORT_DISCOVERY_FAILED


def test_the_requested_ports_reach_the_sweep():
    phases = _Phases()

    run_scan(ScanRequest(target="203.0.113.5", ports=[22, 443], fingerprint=False), phases)

    assert phases.calls[0] == ("discover", "203.0.113.5", [22, 443])


def test_a_truncated_sweep_makes_the_scan_partial():
    outcome = run_scan(ScanRequest(target="203.0.113.5"), _Phases(sweep=_sweep(truncated=True)))

    assert outcome.is_partial is True


def test_an_implausible_sweep_keeps_only_well_known_ports_and_says_so():
    """Un cortafuegos que acepta cualquier puerto: se sigue sólo con los
    puertos conocidos y el resultado avisa de que no se sabe qué hay de verdad."""
    every_port = tuple(range(1000, 1200)) + (80,)
    phases = _Phases(sweep=_sweep(open_ports=every_port), settings=ScanSettings(
        reachability_check=False, implausible_open_ratio=0.5, implausible_min_probed=100))

    outcome = run_scan(ScanRequest(target="203.0.113.5", fingerprint=False), phases)

    assert outcome.is_partial is True
    assert [service.port for service in outcome.services] == [80]
    assert any(finding["category"] == "scan_integrity" for finding in outcome.findings)


# ============================================================ identificación

def test_the_fingerprint_feeds_the_version_detection():
    phases = _Phases()

    outcome = run_scan(ScanRequest(target="203.0.113.5"), phases)

    assert ("analyze", [(80, "nginx")]) in phases.calls
    assert outcome.probed_service_keys == frozenset({(80, "tcp")})


def test_without_permission_to_fingerprint_nothing_is_probed():
    phases = _Phases()

    outcome = run_scan(ScanRequest(target="203.0.113.5", fingerprint=False), phases)

    assert "fingerprint" not in phases.phases_called()
    assert outcome.probed_service_keys == frozenset()


def test_the_planner_reuses_known_identities_and_keeps_the_order():
    """Lo que el escaneo anterior ya identificó no se vuelve a sondear, pero
    sí se analiza: el planificador ahorra la sonda, nunca la detección."""
    class _Planner:
        def partition(self, services):
            return [s for s in services if s.port == 443], [s for s in services if s.port != 443]

        def apply_cached_identity(self, service):
            return Service(port=service.port, protocol=service.protocol, product="OpenSSH", version="9.6")

    phases = _Phases(sweep=_sweep(open_ports=(22, 443)))

    outcome = run_scan(ScanRequest(target="203.0.113.5", planner=_Planner()), phases)

    assert ("fingerprint", [443]) in phases.calls
    assert ("analyze", [(22, "OpenSSH"), (443, "nginx")]) in phases.calls
    assert outcome.probed_service_keys == frozenset({(443, "tcp")})


def test_a_fingerprint_cut_short_seals_no_identity():
    """Un fingerprint cancelado a medias no sondeó todo lo previsto: darlo por
    identificado haría pasar por fresca una identidad que no se miró."""
    cancelled = []

    class _CancelDuringFingerprint(_Phases):
        def fingerprint_services(self, target, services, cancel_check=None, on_progress=None):
            cancelled.append(True)
            return super().fingerprint_services(target, services)

    outcome = run_scan(ScanRequest(target="203.0.113.5"), _CancelDuringFingerprint(),
                       cancel_check=lambda: bool(cancelled))

    assert outcome.is_partial is True
    assert outcome.probed_service_keys == frozenset()


# ============================================================ análisis activo

def test_active_checks_receive_the_cves_the_version_match_proposed():
    phases = _Phases(version_findings=[{"title": "v", "cve_ids": ["CVE-2021-41773"]}])

    run_scan(ScanRequest(target="203.0.113.5"), phases)

    active = next(call for call in phases.calls if call[0] == "active")
    assert active[3] == frozenset({"CVE-2021-41773"})


def test_without_permission_for_active_checks_none_runs():
    phases = _Phases()

    run_scan(ScanRequest(target="203.0.113.5", active_checks=False, crawl=False), phases)

    assert not {"active", "api", "sites", "crawl"} & set(phases.phases_called())


def test_default_credentials_are_only_tried_in_aggressive_mode():
    """La única familia que escribe en el objetivo: un login real."""
    safe = _Phases()
    run_scan(ScanRequest(target="203.0.113.5"), safe)
    aggressive = _Phases()
    run_scan(ScanRequest(target="203.0.113.5", mode="aggressive"), aggressive)

    assert "credentials" not in safe.phases_called()
    assert ("credentials", "aggressive", ["/admin"]) in aggressive.calls


def test_named_sites_are_audited_only_when_the_target_is_an_address():
    by_address = _Phases()
    run_scan(ScanRequest(target="203.0.113.5", site_candidates=(("www.example.org", "registro"),)),
             by_address)
    by_name = _Phases()
    run_scan(ScanRequest(target="www.example.org"), by_name)

    assert ("sites", "203.0.113.5", (("www.example.org", "registro"),)) in by_address.calls
    assert "sites" not in by_name.phases_called()


def test_the_enrichment_sees_the_identification_findings_and_adds_its_own():
    seen = []

    def enrich(findings):
        seen.extend(finding["title"] for finding in findings)
        return [{"title": "sugerencia", "category": "passive_exposure"}]

    phases = _Phases(version_findings=[{"title": "v"}])
    outcome = run_scan(ScanRequest(target="203.0.113.5"), phases, enrich=enrich)

    assert seen == ["v"]
    assert {"title": "sugerencia", "category": "passive_exposure"} in outcome.findings


def test_refutations_come_back_apart_from_the_findings():
    refutation = {"_refutes": "CVE-2021-41773", "title": "refuta"}
    phases = _Phases(active_findings=[{"title": "real"}, refutation])

    outcome = run_scan(ScanRequest(target="203.0.113.5"), phases)

    assert {"title": "real"} in outcome.findings
    assert refutation not in outcome.findings
    assert outcome.refutations


# ============================================================ cierre

def test_a_target_that_stops_answering_leaves_the_scan_partial():
    """Si al final no contesta ninguno de los puertos que estaban abiertos, lo
    comprobado después del bloqueo cayó en el vacío."""
    phases = _Phases(recheck=_sweep(open_ports=(), timed_out=(80,)))

    outcome = run_scan(ScanRequest(target="203.0.113.5"), phases)

    assert outcome.is_partial is True
    assert any(finding["category"] == "scan_integrity" for finding in outcome.findings)


def test_a_target_still_answering_finishes_complete():
    outcome = run_scan(ScanRequest(target="203.0.113.5"), _Phases())

    assert outcome.is_partial is False
    assert not any(finding.get("category") == "scan_integrity" for finding in outcome.findings)


def test_a_scan_by_name_resolves_only_to_the_pinned_address(monkeypatch):
    """Un cambio de DNS a mitad de escaneo no lo desvía: el nombre resuelve a la
    IP validada mientras dura, y vuelve a resolver normal al terminar."""
    def no_dns(host, port, *args, **kwargs):
        """Resuelve sólo IPs literales: cualquier nombre que llegue aquí escapó al pin."""
        try:
            ipaddress.ip_address(host)
        except ValueError as exc:
            raise socket.gaierror(f"sin DNS en los tests: {host}") from exc
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, port))]

    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    resolved = []

    class _Resolving(_Phases):
        def analyze(self, services):
            resolved.append(socket.getaddrinfo("scan-target.invalid", 443)[0][4][0])
            return []

    run_scan(ScanRequest(target="scan-target.invalid", pinned_address="203.0.113.9",
                         fingerprint=False), _Resolving())

    assert resolved == ["203.0.113.9"]
    with pytest.raises(OSError):
        socket.getaddrinfo("scan-target.invalid", 443)


def test_run_scan_hands_its_stop_condition_to_the_crawler_and_the_credentials():
    """El plazo y la cancelación llegan a las dos fases que antes no los miraban."""
    phases = _Phases()
    run_scan(ScanRequest(target="203.0.113.5", mode="aggressive"), phases)

    assert callable(phases.cancel_checks["crawl"])
    assert callable(phases.cancel_checks["credentials"])
    assert phases.cancel_checks["crawl"] is phases.cancel_checks["credentials"]
