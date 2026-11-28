"""El núcleo del servicio ``lybrad``: atiende las operaciones del protocolo.

Está separado del socket a propósito. :class:`EngineService` recibe una
petición ya leída, la resuelve y devuelve el resultado; quién la trajo y cómo
viaja la respuesta es cosa de ``daemon``. Así todo lo que decide el servicio
—validar, encolar, rechazar un objetivo privado, convertir resultados— se
prueba sin abrir ningún socket.

Los escaneos son asíncronos: :meth:`EngineService.handle` encola el escaneo y
responde al momento con su identificador. Corren en un pool acotado
(``max_concurrent_scans``); por encima de eso esperan en cola hasta
``max_queued_scans``, y más allá la petición se rechaza con ``busy``. Los
resultados se guardan en memoria hasta ``result_retention_seconds`` después de
terminar: el motor no recuerda nada de un escaneo a otro.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from ..kb import queries as kb_queries
from . import protocol
from ..core._shared import is_private_target, isoformat_utc, utcnow_naive
from ..analysis.backports import apply_backport_verdicts
from ..recon.cloud import CloudProbe, parse_cloud_resource
from ..analysis.correlation import compute_dedup_key
from ..recon.dns_hygiene import assess_dns_hygiene, is_valid_dkim_selector
from ..kb.queries import KnowledgeBasePhases
from ..kb.sync import SYNC_TARGETS, KnowledgeBaseSync, SyncSettings
from ..kb.store import KnowledgeBase
from ..recon.osint import (OsintSource, ServiceObservation, collect_host_names, collect_passive_intelligence,
                    finding_to_osint_json, normalize_domain)
from ..recon.osint_network import (Deadline, OsintSettings, PassiveNetwork, build_enrichment_findings, build_fetcher,
                            build_lookup, real_network, source_settings)
from ..core.planner import IDENTIFICATION_REVISION, CheckPlanner, KnownService
from .protocol import ProtocolError
from ..core.scanner import ScanAborted, ScanPhases, ScanRequest, ScanSettings, run_scan
from ..net.transport import DEFAULT_PORTS

logger = logging.getLogger(__name__)

ENGINE_VERSION = "0.2.0"

#: Los puertos del perfil ``fast``: los más comunes, para un escaneo rápido.
FAST_PORTS = (
    7, 9, 13, 20, 21, 22, 23, 25, 26, 37, 53, 69, 79, 80, 81, 88, 106, 110, 111, 113, 119, 123,
    135, 137, 138, 139, 143, 144, 161, 179, 199, 254, 255, 280, 311, 389, 427, 443, 445, 464,
    465, 497, 500, 512, 513, 514, 548, 554, 587, 593, 631, 636, 646, 787, 808, 873, 900, 990,
    993, 995, 1000, 1022, 1024, 1025, 1080, 1433, 1434, 1521, 1720, 1723, 1755, 1900, 2001,
    2049, 2181, 2375, 2376, 2379, 2717, 3000, 3128, 3268, 3269, 3306, 3389, 3986, 4444, 4899,
    5000, 5009, 5051, 5060, 5190, 5353, 5357, 5432, 5601, 5666, 5800, 5900,
)

#: Perfil → (puertos, si permite rastreo y checks activos, si permite el planificador).
#: ``fast`` no corre checks activos; ``thorough`` barre los 65 535 puertos sin
#: atajos del planificador.
PROFILES = {
    "fast": (FAST_PORTS, False, True),
    "standard": (DEFAULT_PORTS, True, True),
    "thorough": (tuple(range(1, 65536)), True, False),
}

#: Cuántos servicios puede llevar como mucho una petición ``analyze``.
MAX_ANALYZE_SERVICES = 5000

#: Productos que devuelve como mucho una búsqueda.
MAX_SEARCH_LIMIT = 100

#: Selectores DKIM que admite como mucho ``osint.domain``: cada uno es una
#: consulta DNS, y una lista larga sería la fuerza bruta de selectores que la
#: comprobación rechaza a propósito.
MAX_DKIM_SELECTORS = 10

#: Recursos y subdominios que admite como mucho ``cloud.probe``; cada uno es una
#: petición a un tercero o al DNS.
MAX_CLOUD_RESOURCES = 25
MAX_CLOUD_SUBDOMAINS = 500

#: Plazo por defecto y máximo (segundos) de las operaciones síncronas de red
#: (``osint.*`` y ``cloud.probe``), y plazo del enriquecimiento de un escaneo.
DEFAULT_PASSIVE_BUDGET_SECONDS = 120
MAX_PASSIVE_BUDGET_SECONDS = 600
ENRICH_BUDGET_SECONDS = 60


@dataclass(frozen=True)
class ServiceSettings:  # pylint: disable=too-many-instance-attributes
    """Los ajustes del servicio.

    Attributes:
        max_concurrent_scans: Escaneos que corren a la vez. Por defecto 4.
        max_queued_scans: Escaneos que pueden esperar turno; más allá, ``busy``.
            Por defecto 32.
        result_retention_seconds: Cuánto se guarda el resultado de un escaneo
            terminado. Por defecto 24 horas.
        allow_private_targets: Si se admiten objetivos en redes privadas, de
            loopback o link-local. Por defecto ``False``: un motor que escanea
            lo que le pidan, junto a una aplicación web, es una puerta a la red
            interna.
        planner_max_age_days: Días que vale una identificación anterior para
            no volver a sondear un servicio. Por defecto 7.
        scan: Los ajustes del motor (plazos, ritmo, topes).
        sync: Las fuentes de la base de conocimiento y sus umbrales.
        osint: Las fuentes de inteligencia pasiva, sus claves y sus topes.
    """

    max_concurrent_scans: int = 4
    max_queued_scans: int = 32
    result_retention_seconds: float = 24 * 3600
    allow_private_targets: bool = False
    planner_max_age_days: int = 7
    scan: ScanSettings = field(default_factory=ScanSettings)
    sync: SyncSettings = field(default_factory=SyncSettings)
    osint: OsintSettings = field(default_factory=OsintSettings)


class _Job:  # pylint: disable=too-many-instance-attributes
    """Un escaneo encolado, en curso o terminado, y quien espera noticias de él."""

    def __init__(self, scan_id: str, target: str) -> None:
        self.scan_id = scan_id
        self.target = target
        self.status = "queued"
        self.phase: Optional[str] = None
        self.done = 0
        self.total = 0
        self.detail: Optional[str] = None
        self._events: List[dict] = []
        self.started_at: Optional[datetime] = None
        self.finished_at: Optional[datetime] = None
        self.finished_monotonic: Optional[float] = None
        self.result: Optional[dict] = None
        self.error: Optional[dict] = None
        self.cancelled = threading.Event()
        self.changed = threading.Condition()
        self.revision = 0

    @property
    def is_terminal(self) -> bool:
        """Si el escaneo ya terminó, de cualquier forma."""
        return self.status in ("completed", "partial", "failed", "cancelled")

    def update(self, **fields) -> None:
        """Cambia campos del trabajo y despierta a quien lo esté siguiendo."""
        with self.changed:
            for name, value in fields.items():
                setattr(self, name, value)
            self.revision += 1
            self.changed.notify_all()

    def advance(self, phase: str, done: int, total: int, detail: Optional[str] = None) -> None:
        """Recibe el avance de una fase (la interfaz de progreso de ``run_scan``)."""
        with self.changed:
            if phase != self.phase:
                self.detail = detail
            elif detail is not None:
                self.detail = detail
            self.phase = phase
            self.done = done
            self.total = total
            self.revision += 1
            self.changed.notify_all()

    def note(self, phase: str, message: str) -> None:
        """Anota un detalle en vivo de la fase (p. ej. el check en curso)."""
        with self.changed:
            self.phase = phase
            self.detail = message
            self._events.append({"phase": phase, "message": message})
            self.revision += 1
            self.changed.notify_all()

    def events_since(self, index: int) -> List[dict]:
        """Devuelve los eventos de detalle anotados desde ``index``."""
        return list(self._events[index:])

    def complete(self, phase: str) -> None:
        """Recibe el final de una fase (la interfaz de progreso de ``run_scan``)."""
        self.update(phase=phase, done=self.total, total=self.total, detail=None)

    def status_view(self) -> dict:
        """El estado del escaneo en su forma de cable."""
        progress: dict = {"phase": self.phase, "done": self.done, "total": self.total}
        if self.detail:
            progress["detail"] = self.detail
        view = {"scanId": self.scan_id, "target": self.target, "status": self.status,
                "progress": progress}
        if self.error:
            view["error"] = self.error
        return view


class EngineService:
    """Las operaciones del protocolo, sobre una base de conocimiento y un pool de escaneos.

    Attributes:
        kb: La base de conocimiento.
        settings: Los ajustes del servicio.
    """

    def __init__(self, kb: KnowledgeBase, settings: Optional[ServiceSettings] = None,
                 phases_factory: Optional[Callable[[KnowledgeBase, ScanSettings], ScanPhases]] = None,
                 resolve: Optional[Callable[[str], List[str]]] = None,
                 network_factory: Optional[Callable[[OsintSettings], PassiveNetwork]] = None) -> None:
        """
        Prepara el servicio.

        Args:
            kb: La base de conocimiento.
            settings: Los ajustes; ``None`` usa los de :class:`ServiceSettings`.
            phases_factory: Construye las fases de cada escaneo; ``None`` usa
                :class:`KnowledgeBasePhases`. Sustituible en los tests.
            resolve: ``nombre -> IPs``, para validar y fijar un objetivo por
                nombre; ``None`` usa el resolutor del sistema. Sustituible en
                los tests.
            network_factory: Construye lo que toca la red en ``osint.*``,
                ``cloud.probe`` y el enriquecimiento; ``None`` usa la red de
                verdad (:func:`~lybra.recon.osint_network.real_network`). Sustituible
                en los tests.
        """
        self.kb = kb
        self.settings = settings or ServiceSettings()
        self._phases_factory = phases_factory or KnowledgeBasePhases
        self._resolve = resolve or _resolve_addresses
        self._network_factory = network_factory or real_network
        self._jobs: Dict[str, _Job] = {}
        self._jobs_lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=self.settings.max_concurrent_scans,
                                        thread_name_prefix="lybra-scan")
        self._sync_lock = threading.Lock()
        self._operations: Dict[str, Callable[[dict, Callable[[str, Any], None]], Any]] = {
            "engine.info": self._engine_info,
            "scan.start": self._scan_start,
            "scan.status": self._scan_status,
            "scan.watch": self._scan_watch,
            "scan.result": self._scan_result,
            "scan.cancel": self._scan_cancel,
            "analyze": self._analyze,
            "osint.domain": self._osint_domain,
            "osint.hostnames": self._osint_hostnames,
            "cloud.probe": self._cloud_probe,
            "kb.cve": self._kb_cve,
            "kb.version": self._kb_version,
            "kb.products": self._kb_products,
            "kb.resolve": self._kb_resolve,
            "kb.advisories": self._kb_advisories,
            "kb.unresolved": self._kb_unresolved,
            "kb.status": self._kb_status,
            "kb.sync": self._kb_sync,
            "kb.backfill": self._kb_backfill,
        }

    # ------------------------------------------------------------ entrada

    def handle(self, request: dict, emit: Optional[Callable[[dict], None]] = None) -> dict:
        """
        Atiende una petición ya leída y devuelve su respuesta final.

        Nunca lanza: cualquier error acaba en una respuesta de error. Un error
        no previsto se registra entero en el log y al cliente sólo le llega
        ``internal``.

        Args:
            request: La petición, como la devuelve ``protocol.decode_request``.
            emit: Recibe los eventos intermedios ya construidos (sólo en
                ``scan.watch``); ``None`` los descarta.

        Returns:
            dict: La respuesta final, ``ok`` o de error.
        """
        request_id = request.get("id")
        operation = self._operations.get(request.get("op"))
        if operation is None:
            return protocol.error_response(request_id, protocol.UNKNOWN_OP,
                                           f"operación desconocida: {request.get('op')!r}")

        def emit_event(name: str, data: Any) -> None:
            if emit is not None:
                emit(protocol.event(request_id, name, data))

        try:
            return protocol.response(request_id, operation(request.get("params") or {}, emit_event))
        except ProtocolError as error:
            return protocol.error_response(request_id, error.code, error.message)
        except Exception:  # pylint: disable=broad-exception-caught
            logger.exception("Error atendiendo %s", request.get("op"))
            return protocol.error_response(request_id, protocol.INTERNAL, "error interno del motor")

    def shutdown(self) -> None:
        """Cancela los escaneos en curso y espera a que el pool se vacíe."""
        with self._jobs_lock:
            for job in self._jobs.values():
                job.cancelled.set()
        self._pool.shutdown(wait=True, cancel_futures=True)

    # ------------------------------------------------------------ servicio

    def _engine_info(self, _params: dict, _emit) -> dict:
        """``engine.info``: versiones y estado de la base de conocimiento."""
        state = self.kb.knowledge_state()
        return {
            "engineVersion": ENGINE_VERSION,
            "protocolVersions": [protocol.PROTOCOL_VERSION],
            "identificationRevision": IDENTIFICATION_REVISION,
            "kb": {"feedVersion": kb_queries.kb_feed_version(state), "counts": self.kb.counts()},
        }

    # ------------------------------------------------------------ escaneos

    def _scan_start(self, params: dict, _emit) -> dict:
        """``scan.start``: valida la petición, la encola y responde con su identificador."""
        target = _required_text(params, "target").strip()
        pinned_address = self._validate_target(target)
        profile = params.get("profile", "standard")
        if profile not in PROFILES:
            raise ProtocolError(protocol.INVALID_PARAMS, f"perfil desconocido: {profile!r}; válidos: "
                                f"{', '.join(PROFILES)}")
        profile_ports, profile_allows_checks, profile_allows_planner = PROFILES[profile]
        ports = _ports(params.get("ports")) or profile_ports
        timeout = params.get("timeoutSeconds")
        if timeout is not None and (not isinstance(timeout, (int, float)) or isinstance(timeout, bool)
                                    or timeout <= 0):
            raise ProtocolError(protocol.INVALID_PARAMS, "'timeoutSeconds' tiene que ser un número positivo")
        active_checks = _flag(params, "activeChecks", True) and profile_allows_checks
        planner = None
        if profile_allows_planner and params.get("knownServices"):
            planner = CheckPlanner(_known_surface(params["knownServices"]),
                                   max_age_days=self.settings.planner_max_age_days)
        request = ScanRequest(
            target=target,
            ports=list(ports),
            pinned_address=pinned_address,
            timeout_seconds=timeout,
            fingerprint=_flag(params, "fingerprint", True),
            crawl=_flag(params, "crawl", True) and profile_allows_checks,
            active_checks=active_checks,
            mode="aggressive" if _flag(params, "aggressive", False) and profile != "fast" else "safe",
            planner=planner,
            site_candidates=_site_candidates(params.get("siteCandidates")),
        )
        # El enriquecimiento pregunta a terceros por la IP del objetivo: sólo si quien llama lo pide.
        enrich = self._enricher(pinned_address or target) if _flag(params, "enrich", False) else None
        job = _Job(uuid.uuid4().hex, target)
        with self._jobs_lock:
            self._purge_expired()
            waiting = sum(1 for other in self._jobs.values() if other.status == "queued")
            if waiting >= self.settings.max_queued_scans:
                raise ProtocolError(protocol.BUSY, "la cola de escaneos está llena; inténtalo más tarde")
            self._jobs[job.scan_id] = job
        self._pool.submit(self._run_job, job, request, enrich)
        logger.info("Escaneo %s encolado contra %s (perfil %s)", job.scan_id, target, profile)
        return {"scanId": job.scan_id, "status": job.status}

    def _validate_target(self, target: str) -> Optional[str]:
        """
        Valida el objetivo y, si es un nombre, decide a qué IP se fija.

        Args:
            target: IP o nombre de host.

        Returns:
            Optional[str]: La IP a la que se fija un nombre durante el escaneo,
                o ``None`` si el objetivo ya es una IP.

        Raises:
            ProtocolError: ``invalid_target`` si no es una IP ni un nombre de
                host, o si el nombre no resuelve; ``target_not_allowed`` si es (o
                resuelve a) una dirección privada y el servicio no las admite.
        """
        try:
            address = ipaddress.ip_address(target)
        except ValueError:
            address = None
        if address is not None:
            if not self.settings.allow_private_targets and is_private_target(target):
                raise ProtocolError(protocol.TARGET_NOT_ALLOWED,
                                    f"{target} es una dirección privada y este motor no las admite")
            return None
        if not _is_hostname(target):
            raise ProtocolError(protocol.INVALID_TARGET, f"no es una IP ni un nombre de host: {target!r}")
        if not self.settings.allow_private_targets and is_private_target(target):
            raise ProtocolError(protocol.TARGET_NOT_ALLOWED,
                                f"{target} es un nombre de red interna y este motor no los admite")
        addresses = self._resolve(target)
        if not addresses:
            raise ProtocolError(protocol.INVALID_TARGET, f"{target} no resuelve")
        if not self.settings.allow_private_targets and any(is_private_target(ip) for ip in addresses):
            raise ProtocolError(protocol.TARGET_NOT_ALLOWED,
                                f"{target} resuelve a una dirección privada y este motor no las admite")
        return addresses[0]

    def _run_job(self, job: _Job, request: ScanRequest,
                 enrich: Optional[Callable[[List[dict]], List[dict]]] = None) -> None:
        """Corre un escaneo en un hilo del pool y deja su resultado en el trabajo.

        Args:
            job: El trabajo encolado.
            request: Qué escanear.
            enrich: Añade hallazgos de fuentes de terceros a los de la identificación
                (ver :meth:`_enricher`); ``None`` no consulta a nadie.
        """
        if job.cancelled.is_set():
            job.update(status="cancelled", finished_at=utcnow_naive(), finished_monotonic=time.monotonic())
            return
        job.update(status="running", started_at=utcnow_naive())
        try:
            outcome = run_scan(request, self._phases_factory(self.kb, self.settings.scan),
                               cancel_check=job.cancelled.is_set, progress=job, enrich=enrich)
            findings = apply_backport_verdicts(outcome.findings, self.kb.distro_package_status,
                                               self.kb.distro_release_for)
            status = "cancelled" if job.cancelled.is_set() else ("partial" if outcome.is_partial else "completed")
            result = {
                "scanId": job.scan_id,
                "target": job.target,
                "status": status,
                "startedAt": protocol.to_wire(job.started_at),
                "finishedAt": protocol.to_wire(utcnow_naive()),
                "services": protocol.to_wire(outcome.services),
                "probedServices": sorted([port, transport] for port, transport in outcome.probed_service_keys),
                "identificationRevision": IDENTIFICATION_REVISION,
                "findings": protocol.to_wire(findings),
                "refutations": protocol.to_wire(outcome.refutations),
                "kbFeedVersion": kb_queries.kb_feed_version(self.kb.knowledge_state()),
            }
            job.update(status=status, result=result, finished_at=utcnow_naive(),
                       finished_monotonic=time.monotonic())
            logger.info("Escaneo %s terminado (%s): %d hallazgos", job.scan_id, status, len(findings))
        except ScanAborted as aborted:
            job.update(status="failed", error={"code": aborted.reason, "message": str(aborted)},
                       finished_at=utcnow_naive(), finished_monotonic=time.monotonic())
        except Exception:  # pylint: disable=broad-exception-caught
            logger.exception("Escaneo %s falló", job.scan_id)
            job.update(status="failed", error={"code": protocol.INTERNAL, "message": "error interno del motor"},
                       finished_at=utcnow_naive(), finished_monotonic=time.monotonic())

    def _job(self, params: dict) -> _Job:
        """Busca el trabajo de ``params["scanId"]``, o lanza ``not_found``."""
        scan_id = _required_text(params, "scanId")
        with self._jobs_lock:
            self._purge_expired()
            job = self._jobs.get(scan_id)
        if job is None:
            raise ProtocolError(protocol.NOT_FOUND, f"no hay ningún escaneo {scan_id}")
        return job

    def _purge_expired(self) -> None:
        """Olvida los escaneos terminados hace más de lo que se guardan (con el cerrojo tomado)."""
        horizon = time.monotonic() - self.settings.result_retention_seconds
        for scan_id in [scan_id for scan_id, job in self._jobs.items()
                        if job.finished_monotonic is not None and job.finished_monotonic < horizon]:
            del self._jobs[scan_id]

    def _scan_status(self, params: dict, _emit) -> dict:
        """``scan.status``: el estado y el avance de un escaneo."""
        return self._job(params).status_view()

    def _scan_watch(self, params: dict, emit) -> dict:
        """``scan.watch``: emite el avance hasta que el escaneo termina y responde con su estado final."""
        job = self._job(params)
        seen = -1
        seen_events = 0
        while True:
            with job.changed:
                if job.revision == seen and not job.is_terminal:
                    job.changed.wait(timeout=30)
                seen, view, terminal = job.revision, job.status_view(), job.is_terminal
                new_events = job.events_since(seen_events)
                seen_events += len(new_events)
            if new_events:
                emit("progress", view["progress"] | {"status": view["status"], "events": new_events})
            elif not terminal:
                emit("progress", view["progress"] | {"status": view["status"]})
            if terminal:
                return view

    def _scan_result(self, params: dict, _emit) -> dict:
        """``scan.result``: el resultado de un escaneo terminado."""
        job = self._job(params)
        if job.result is None:
            if job.status == "failed":
                raise ProtocolError(job.error["code"], job.error["message"])
            raise ProtocolError(protocol.NOT_FOUND, f"el escaneo {job.scan_id} aún no tiene resultado "
                                                    f"(estado: {job.status})")
        return job.result

    def _scan_cancel(self, params: dict, _emit) -> dict:
        """``scan.cancel``: pide que un escaneo en cola o en curso se detenga."""
        job = self._job(params)
        if not job.is_terminal:
            job.cancelled.set()
            if job.status == "queued":
                job.update(status="cancelled", finished_at=utcnow_naive(), finished_monotonic=time.monotonic())
        return job.status_view()

    # ------------------------------------------------------------ análisis sin red

    def _analyze(self, params: dict, _emit) -> dict:
        """``analyze``: los hallazgos de servicios ya conocidos, sin tocar la red del objetivo.

        Con ``enrich`` pregunta además a las fuentes de terceros por la IP de
        ``target`` (obligatorio entonces): es lo único que sale del motor.
        """
        raw = params.get("services")
        if not isinstance(raw, list) or not 0 < len(raw) <= MAX_ANALYZE_SERVICES:
            raise ProtocolError(protocol.INVALID_PARAMS,
                                f"'services' tiene que ser una lista de 1 a {MAX_ANALYZE_SERVICES} servicios")
        services = [protocol.service_from_wire(item) for item in raw]
        findings = kb_queries.engine_for(self.kb).analyze(services)
        apply_backport_verdicts(findings, self.kb.distro_package_status, self.kb.distro_release_for)
        if _flag(params, "enrich", False):
            target = _required_text(params, "target").strip()
            try:
                address = str(ipaddress.ip_address(target))
            except ValueError as error:
                raise ProtocolError(protocol.INVALID_PARAMS, "con 'enrich', 'target' tiene que ser una IP") from error
            findings = findings + self._enricher(address)(findings)
        return {"findings": protocol.to_wire(findings),
                "kbFeedVersion": kb_queries.kb_feed_version(self.kb.knowledge_state())}

    # ------------------------------------------------------------ inteligencia pasiva y cloud

    def _enricher(self, address: str) -> Callable[[List[dict]], List[dict]]:
        """
        Construye el enriquecimiento pasivo de un objetivo.

        Args:
            address: La IP del objetivo.

        Returns:
            Callable: ``hallazgos -> hallazgos nuevos``: los CPE que Shodan o Censys
                sugieren para los puertos que el motor no identificó. Sin claves
                configuradas no devuelve nada.
        """
        def enrich(findings: List[dict]) -> List[dict]:
            osint = self.settings.osint
            fetch = build_fetcher(self.kb, osint, self._network_factory(osint), Deadline(ENRICH_BUDGET_SECONDS))
            return build_enrichment_findings(address, findings, fetch, source_settings(osint), utcnow_naive())
        return enrich

    def _passive_budget(self, params: dict) -> Deadline:
        """El plazo de una operación síncrona de red: ``timeoutSeconds`` o el de por defecto, con tope."""
        budget = params.get("timeoutSeconds", DEFAULT_PASSIVE_BUDGET_SECONDS)
        if not isinstance(budget, (int, float)) or isinstance(budget, bool) or budget <= 0:
            raise ProtocolError(protocol.INVALID_PARAMS, "'timeoutSeconds' tiene que ser un número positivo")
        return Deadline(min(budget, MAX_PASSIVE_BUDGET_SECONDS))

    def _osint_domain(self, params: dict, _emit) -> dict:
        """``osint.domain``: lo que fuentes de terceros y el DNS público dicen de un dominio.

        Es síncrona y acotada por un plazo en vez de un trabajo con estado: el
        motor no recuerda nada de una petición a otra, y quien necesite
        ejecutarla en segundo plano (con cola, cancelación y reintento) ya tiene
        su propia cola. El plazo se comprueba entre peticiones: una petición en
        vuelo puede pasarse lo que dure su propio tiempo de espera.
        """
        domain = normalize_domain(_required_text(params, "domain"))
        if domain is None:
            raise ProtocolError(protocol.INVALID_PARAMS, "'domain' no es un nombre de dominio válido")
        selectors = list(dict.fromkeys(item.strip().lower() for item in _text_list(
            params, "dkimSelectors", MAX_DKIM_SELECTORS)))
        if not all(is_valid_dkim_selector(selector) for selector in selectors):
            raise ProtocolError(protocol.INVALID_PARAMS, "'dkimSelectors' trae un selector que no es válido")
        only = _text_list(params, "sources", len(OsintSource))
        if unknown := set(only) - {source.value for source in OsintSource}:
            raise ProtocolError(protocol.INVALID_PARAMS, f"fuentes desconocidas: {', '.join(sorted(unknown))}")
        deadline = self._passive_budget(params)
        osint = self.settings.osint
        network = self._network_factory(osint)
        fetch, lookup = build_fetcher(self.kb, osint, network, deadline), build_lookup(network, deadline)
        report = collect_passive_intelligence(
            domain, fetch, lookup, source_settings(osint, only or None), utcnow_naive(),
            recent_certificate_days=osint.recent_certificate_days, max_subdomains=osint.max_subdomains,
            max_host_lookups=osint.max_host_lookups)
        dns_findings, dns_checks = assess_dns_hygiene(domain, lookup, utcnow_naive(), selectors)
        return protocol.to_wire({
            "domain": domain,
            "sources": [status.to_json() for status in report.source_statuses],
            "dnsChecks": [check.to_json() for check in dns_checks],
            "subdomains": [record.to_json() for record in report.subdomains],
            "observations": [_observation_to_json(observation) for observation in report.observations],
            "findings": [finding_to_osint_json(finding) for finding in report.findings + dns_findings],
        })

    def _osint_hostnames(self, params: dict, _emit) -> dict:
        """``osint.hostnames``: los nombres que Shodan y Censys asocian a una IP («reverse IP» pasivo)."""
        address = _required_text(params, "address").strip()
        try:
            ipaddress.ip_address(address)
        except ValueError as error:
            raise ProtocolError(protocol.INVALID_PARAMS, "'address' tiene que ser una IP") from error
        deadline = self._passive_budget(params)
        osint = self.settings.osint
        fetch = build_fetcher(self.kb, osint, self._network_factory(osint), deadline)
        return {"address": address, "names": collect_host_names(address, fetch, source_settings(osint))}

    def _cloud_probe(self, params: dict, _emit) -> dict:  # pylint: disable=too-many-locals
        """``cloud.probe``: ¿exponen su contenido unos recursos cloud, o son takeover unos subdominios?

        Quien llama decide qué es suyo y qué puede comprobar (igual que con un
        escaneo); el motor sólo se niega a hacer peticiones a nombres que
        resuelvan a una dirección privada cuando el servicio no las admite.
        """
        resources = []
        for raw in _text_list(params, "resources", MAX_CLOUD_RESOURCES):
            resource = parse_cloud_resource(raw)
            if resource is None:
                raise ProtocolError(protocol.INVALID_PARAMS, f"recurso cloud no válido: {raw!r}")
            if resource not in resources:
                resources.append(resource)
        names = []
        for raw in _text_list(params, "subdomains", MAX_CLOUD_SUBDOMAINS):
            name = normalize_domain(raw)
            if name is None:
                raise ProtocolError(protocol.INVALID_PARAMS, f"subdominio no válido: {raw!r}")
            if name not in names:
                names.append(name)
        if not resources and not names:
            raise ProtocolError(protocol.INVALID_PARAMS, "hace falta al menos un recurso o un subdominio")
        deadline = self._passive_budget(params)
        network = self._network_factory(self.settings.osint)

        def get(host: str, port: int, path: str):
            if deadline.is_expired:
                return None
            addresses = self._resolve(host)
            if not addresses or (not self.settings.allow_private_targets
                                 and any(is_private_target(address) for address in addresses)):
                return None
            return network.http_get(host, port, path)

        probe = CloudProbe(get, lambda name: None if deadline.is_expired else network.resolve_cname(name))
        found = [probe.probe_resource(resource) for resource in resources]
        found += [probe.probe_subdomain(name) for name in names]
        observed_at = isoformat_utc(utcnow_naive())
        findings = []
        for finding in (item for item in found if item is not None):
            finding["dedup_key"] = compute_dedup_key({**finding, "host_id": None})
            finding["provenance"] = {"source": "cloud", "observedAt": observed_at}
            findings.append(finding)
        return protocol.to_wire({"resources": [resource.canonical for resource in resources],
                                 "subdomains": [{"name": name} for name in names], "findings": findings})

    # ------------------------------------------------------------ base de conocimiento

    def _kb_cve(self, params: dict, _emit) -> dict:
        """``kb.cve``: la ficha de una CVE, con sus listas acotadas."""
        cve_id = _required_text(params, "cveId").strip().upper()
        detail = kb_queries.public_cve_detail(self.kb, cve_id)
        if detail is None:
            raise ProtocolError(protocol.NOT_FOUND, f"la base de conocimiento no sabe nada de {cve_id}")
        return detail

    def _kb_version(self, params: dict, _emit) -> dict:
        """``kb.version``: las CVE de un producto en una versión."""
        return kb_queries.version_check(self.kb, _required_text(params, "product"),
                                        _required_text(params, "version"))

    def _kb_products(self, params: dict, _emit) -> dict:
        """``kb.products``: productos cuyo nombre empieza por un término."""
        products = kb_queries.search_products(self.kb, _required_text(params, "term"), _limit(params))
        return {"products": [{"vendor": product.vendor, "product": product.product,
                              "displayName": product.display_name} for product in products]}

    def _kb_resolve(self, params: dict, _emit) -> dict:
        """``kb.resolve``: el par ``vendor``/``product`` de cada nombre libre."""
        names = params.get("names")
        if not isinstance(names, list) or not all(isinstance(name, str) for name in names) or len(names) > 1000:
            raise ProtocolError(protocol.INVALID_PARAMS, "'names' tiene que ser una lista de hasta 1000 cadenas")
        return {"products": [{"vendor": vendor, "product": product}
                             for vendor, product in kb_queries.resolve_products(self.kb, names)]}

    def _kb_advisories(self, params: dict, _emit) -> dict:
        """``kb.advisories``: las CVE recientes de unos productos."""
        products = params.get("products")
        if not isinstance(products, list) or not products or len(products) > 200:
            raise ProtocolError(protocol.INVALID_PARAMS, "'products' tiene que ser una lista de 1 a 200 pares")
        pairs = []
        for item in products:
            if not isinstance(item, dict) or not all(isinstance(item.get(key), str) for key in ("vendor", "product")):
                raise ProtocolError(protocol.INVALID_PARAMS, "cada producto necesita 'vendor' y 'product'")
            pairs.append((item["vendor"], item["product"]))
        since = _datetime_param(params, "since") or datetime(1970, 1, 1)
        min_cvss = params.get("minCvss")
        advisories = kb_queries.advisories_for_products(self.kb, pairs, since, min_cvss=min_cvss,
                                                        limit_total=_limit(params))
        return {"advisories": [protocol.to_wire({
            "cve_id": advisory.cve_id, "vendor": advisory.vendor, "product": advisory.product,
            "published": advisory.published, "severity": advisory.severity, "cvss_score": advisory.cvss_score,
            "description": advisory.description, "in_kev": advisory.kev, "epss_score": advisory.epss,
            "url": advisory.url}) for advisory in advisories]}

    def _kb_unresolved(self, params: dict, _emit) -> dict:
        """``kb.unresolved``: los nombres de producto que más veces quedaron sin resolver."""
        origin = params.get("origin")
        if origin not in (None, "network", "inventory"):
            raise ProtocolError(protocol.INVALID_PARAMS, "'origin' tiene que ser 'network' o 'inventory'")
        rows = self.kb.top_unresolved_products(limit=_limit(params, default=50), origin=origin)
        return {"products": [protocol.to_wire({
            "name": row.normalized_name, "origin": row.origin, "occurrences": row.occurrences,
            "first_seen_at": row.first_seen_at, "last_seen_at": row.last_seen_at}) for row in rows]}

    def _kb_status(self, _params: dict, _emit) -> dict:
        """``kb.status``: el estado de cada fuente de la base de conocimiento."""
        return KnowledgeBaseSync(self.kb, self.settings.sync).status()

    def _kb_sync(self, params: dict, _emit) -> dict:
        """``kb.sync``: lanza una sincronización en segundo plano y responde al momento."""
        source = params.get("source", "all")
        if source not in SYNC_TARGETS:
            raise ProtocolError(protocol.INVALID_PARAMS, f"fuente desconocida: {source!r}; válidas: "
                                f"{', '.join(SYNC_TARGETS)}")
        if not self.start_sync(source):
            raise ProtocolError(protocol.BUSY, "ya hay una sincronización en curso")
        return {"started": True, "source": source}

    def _kb_backfill(self, params: dict, emit) -> dict:
        """``kb.backfill``: realiza un llenado histórico de NVD emitiendo progreso."""
        since_raw = params.get("since", "1999-01-01")
        until_raw = params.get("until")
        if not isinstance(since_raw, str):
            raise ProtocolError(protocol.INVALID_PARAMS, "fecha inválida; usa YYYY-MM-DD")
        try:
            start = datetime.strptime(since_raw, "%Y-%m-%d")
        except ValueError as error:
            raise ProtocolError(protocol.INVALID_PARAMS, "fecha inválida; usa YYYY-MM-DD") from error
        
        end = None
        if until_raw is not None:
            if not isinstance(until_raw, str):
                raise ProtocolError(protocol.INVALID_PARAMS, "fecha inválida; usa YYYY-MM-DD")
            try:
                end = datetime.strptime(until_raw, "%Y-%m-%d")
            except ValueError as error:
                raise ProtocolError(protocol.INVALID_PARAMS, "fecha inválida; usa YYYY-MM-DD") from error

        if end is not None and start >= end:
            raise ProtocolError(protocol.INVALID_PARAMS, "'since' tiene que ser anterior a 'until'")

        if not self._sync_lock.acquire(blocking=False):  # pylint: disable=consider-using-with
            raise ProtocolError(protocol.BUSY, "ya hay una sincronización en curso")
        try:
            return KnowledgeBaseSync(self.kb, self.settings.sync).backfill_nvd(
                start, end, on_progress=lambda data: emit("progress", data)
            )
        except ValueError as error:
            raise ProtocolError(protocol.INVALID_PARAMS, str(error)) from error
        finally:
            self._sync_lock.release()

    def start_sync(self, source: str = "all") -> bool:
        """
        Lanza una sincronización de la base en un hilo, si no hay otra en curso.

        Args:
            source: Una de ``kb_sync.SYNC_TARGETS``. Por defecto ``"all"``.

        Returns:
            bool: ``True`` si se lanzó; ``False`` si ya había una en curso.
        """
        if not self._sync_lock.acquire(blocking=False):  # pylint: disable=consider-using-with
            return False

        def run() -> None:
            try:
                KnowledgeBaseSync(self.kb, self.settings.sync).sync_all(only=source)
            except Exception:  # pylint: disable=broad-exception-caught
                logger.exception("La sincronización de la base de conocimiento falló")
            finally:
                self._sync_lock.release()

        threading.Thread(target=run, name="lybra-kb-sync", daemon=True).start()
        return True


# ============================================================ validación de parámetros


def _required_text(params: dict, name: str) -> str:
    """Devuelve el parámetro de texto ``name``, o lanza ``invalid_params`` si falta o está vacío."""
    value = params.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ProtocolError(protocol.INVALID_PARAMS, f"falta '{name}'")
    return value


def _text_list(params: dict, name: str, maximum: int) -> List[str]:
    """Devuelve el parámetro ``name`` como lista de cadenas de a lo sumo ``maximum``; vacía si falta."""
    value = params.get(name)
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > maximum or not all(isinstance(item, str) for item in value):
        raise ProtocolError(protocol.INVALID_PARAMS, f"'{name}' tiene que ser una lista de hasta {maximum} cadenas")
    return value


def _observation_to_json(observation: ServiceObservation) -> dict:
    """Un servicio que una fuente de terceros vio abierto, en camelCase."""
    return {"source": observation.source.value, "address": observation.address, "port": observation.port,
            "protocol": observation.protocol, "product": observation.product, "version": observation.version,
            "cpe": observation.cpe, "observed_at": observation.observed_at,
            "retrieved_at": observation.retrieved_at}


def _flag(params: dict, name: str, default: bool) -> bool:
    """Devuelve el parámetro booleano ``name``, o su valor por defecto; lanza si no es booleano."""
    value = params.get(name, default)
    if not isinstance(value, bool):
        raise ProtocolError(protocol.INVALID_PARAMS, f"'{name}' tiene que ser true o false")
    return value


def _limit(params: dict, default: int = 20) -> int:
    """Devuelve el parámetro ``limit``, acotado a :data:`MAX_SEARCH_LIMIT`."""
    value = params.get("limit", default)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ProtocolError(protocol.INVALID_PARAMS, "'limit' tiene que ser un entero positivo")
    return min(value, MAX_SEARCH_LIMIT)


def _ports(raw: Any) -> Optional[List[int]]:
    """Valida una lista de puertos TCP; ``None`` si no la hay."""
    if raw is None:
        return None
    if (not isinstance(raw, list) or not raw or len(raw) > 65535
            or not all(isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536 for port in raw)):
        raise ProtocolError(protocol.INVALID_PARAMS, "'ports' tiene que ser una lista de puertos entre 1 y 65535")
    return sorted(set(raw))


def _datetime_param(params: dict, name: str) -> Optional[datetime]:
    """Lee un instante ISO 8601 (con ``Z`` o sin zona) como UTC sin zona; ``None`` si falta."""
    value = params.get(name)
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as error:
        raise ProtocolError(protocol.INVALID_PARAMS, f"'{name}' no es una fecha ISO 8601") from error
    return parsed if parsed.tzinfo is None else parsed.astimezone(timezone.utc).replace(tzinfo=None)


def _known_surface(raw: Any) -> dict:
    """Convierte ``knownServices`` en la superficie anterior que espera el planificador."""
    if not isinstance(raw, list):
        raise ProtocolError(protocol.INVALID_PARAMS, "'knownServices' tiene que ser una lista")
    surface = {}
    for item in raw:
        service = protocol.service_from_wire(item)
        if service.port is None:
            continue
        identified_at = _datetime_param(item, "identifiedAt")
        surface[(service.port, service.protocol or "tcp")] = KnownService(
            product=service.product, version=service.version, cpe=service.cpe,
            identified_at=identified_at, identified_by=item.get("identifiedBy"))
    return surface


def _site_candidates(raw: Any) -> tuple:
    """Valida ``siteCandidates``: pares ``{name, origin}`` que quien llama autorizó auditar."""
    if raw is None:
        return ()
    if not isinstance(raw, list) or len(raw) > 100:
        raise ProtocolError(protocol.INVALID_PARAMS, "'siteCandidates' tiene que ser una lista de hasta 100")
    candidates = []
    for item in raw:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not _is_hostname(item["name"]):
            raise ProtocolError(protocol.INVALID_PARAMS, "cada sitio necesita un 'name' que sea un nombre de host")
        candidates.append((item["name"], str(item.get("origin") or "indicado por quien escanea")))
    return tuple(candidates)


def _is_hostname(value: str) -> bool:
    """Si ``value`` es un nombre de host DNS válido (no una IP, ni una lista, ni un rango)."""
    if not value or len(value) > 253 or value.endswith("."):
        return False
    labels = value.split(".")
    return all(label and len(label) <= 63 and label[0] != "-" and label[-1] != "-"
               and all(char.isalnum() or char == "-" for char in label) for label in labels) \
        and not all(label.isdigit() for label in labels)


def _resolve_addresses(name: str) -> List[str]:
    """Las IPs a las que resuelve ``name``, en el orden del resolutor; vacía si no resuelve."""
    try:
        addresses = [info[4][0] for info in socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)]
    except OSError:
        return []
    return list(dict.fromkeys(addresses))
