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

from . import kb_queries, protocol
from ._shared import is_private_target, utcnow_naive
from .backports import apply_backport_verdicts
from .kb_queries import KnowledgeBasePhases
from .kb_sync import SYNC_TARGETS, KnowledgeBaseSync, SyncSettings
from .knowledge_base import KnowledgeBase
from .planner import IDENTIFICATION_REVISION, CheckPlanner, KnownService
from .protocol import ProtocolError
from .scanner import ScanAborted, ScanPhases, ScanRequest, ScanSettings, run_scan
from .transport import DEFAULT_PORTS

logger = logging.getLogger(__name__)

ENGINE_VERSION = "0.1.2"

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
    """

    max_concurrent_scans: int = 4
    max_queued_scans: int = 32
    result_retention_seconds: float = 24 * 3600
    allow_private_targets: bool = False
    planner_max_age_days: int = 7
    scan: ScanSettings = field(default_factory=ScanSettings)
    sync: SyncSettings = field(default_factory=SyncSettings)


class _Job:  # pylint: disable=too-many-instance-attributes
    """Un escaneo encolado, en curso o terminado, y quien espera noticias de él."""

    def __init__(self, scan_id: str, target: str) -> None:
        self.scan_id = scan_id
        self.target = target
        self.status = "queued"
        self.phase: Optional[str] = None
        self.done = 0
        self.total = 0
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

    def advance(self, phase: str, done: int, total: int) -> None:
        """Recibe el avance de una fase (la interfaz de progreso de ``run_scan``)."""
        self.update(phase=phase, done=done, total=total)

    def complete(self, phase: str) -> None:
        """Recibe el final de una fase (la interfaz de progreso de ``run_scan``)."""
        self.update(phase=phase, done=self.total, total=self.total)

    def status_view(self) -> dict:
        """El estado del escaneo en su forma de cable."""
        view = {"scanId": self.scan_id, "target": self.target, "status": self.status,
                "progress": {"phase": self.phase, "done": self.done, "total": self.total}}
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
                 resolve: Optional[Callable[[str], List[str]]] = None) -> None:
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
        """
        self.kb = kb
        self.settings = settings or ServiceSettings()
        self._phases_factory = phases_factory or KnowledgeBasePhases
        self._resolve = resolve or _resolve_addresses
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
            "kb.cve": self._kb_cve,
            "kb.version": self._kb_version,
            "kb.products": self._kb_products,
            "kb.resolve": self._kb_resolve,
            "kb.advisories": self._kb_advisories,
            "kb.unresolved": self._kb_unresolved,
            "kb.status": self._kb_status,
            "kb.sync": self._kb_sync,
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
        job = _Job(uuid.uuid4().hex, target)
        with self._jobs_lock:
            self._purge_expired()
            waiting = sum(1 for other in self._jobs.values() if other.status == "queued")
            if waiting >= self.settings.max_queued_scans:
                raise ProtocolError(protocol.BUSY, "la cola de escaneos está llena; inténtalo más tarde")
            self._jobs[job.scan_id] = job
        self._pool.submit(self._run_job, job, request)
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

    def _run_job(self, job: _Job, request: ScanRequest) -> None:
        """Corre un escaneo en un hilo del pool y deja su resultado en el trabajo."""
        if job.cancelled.is_set():
            job.update(status="cancelled", finished_at=utcnow_naive(), finished_monotonic=time.monotonic())
            return
        job.update(status="running", started_at=utcnow_naive())
        try:
            outcome = run_scan(request, self._phases_factory(self.kb, self.settings.scan),
                               cancel_check=job.cancelled.is_set, progress=job)
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
        while True:
            with job.changed:
                if job.revision == seen and not job.is_terminal:
                    job.changed.wait(timeout=30)
                seen, view, terminal = job.revision, job.status_view(), job.is_terminal
            if terminal:
                return view
            emit("progress", view["progress"] | {"status": view["status"]})

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
        """``analyze``: los hallazgos de servicios ya conocidos, sin tocar la red."""
        raw = params.get("services")
        if not isinstance(raw, list) or not 0 < len(raw) <= MAX_ANALYZE_SERVICES:
            raise ProtocolError(protocol.INVALID_PARAMS,
                                f"'services' tiene que ser una lista de 1 a {MAX_ANALYZE_SERVICES} servicios")
        services = [protocol.service_from_wire(item) for item in raw]
        findings = kb_queries.engine_for(self.kb).analyze(services)
        apply_backport_verdicts(findings, self.kb.distro_package_status, self.kb.distro_release_for)
        return {"findings": protocol.to_wire(findings),
                "kbFeedVersion": kb_queries.kb_feed_version(self.kb.knowledge_state())}

    # ------------------------------------------------------------ base de conocimiento

    def _kb_cve(self, params: dict, _emit) -> dict:
        """``kb.cve``: la ficha de una CVE."""
        cve_id = _required_text(params, "cveId").strip().upper()
        detail = kb_queries.cve_detail(self.kb, cve_id)
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
