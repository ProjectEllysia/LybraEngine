"""La orquestación de un escaneo: de un objetivo a sus hallazgos.

Encadena las capas del motor en el orden en que un escaneo las necesita
—alcanzabilidad, descubrimiento de puertos, fingerprinting, detección por
versión, rastreo, checks activos, superficie de API, sitios con nombre,
credenciales y comprobación final de que el objetivo sigue contestando— y
devuelve lo que vio en un :class:`ScanOutcome`.

Lo que **no** hace es tan importante como lo que hace:

- No guarda nada ni recuerda nada entre escaneos. Lo que se supo del objetivo
  en un escaneo anterior entra como :class:`CheckPlanner` en la petición; el
  ciclo de vida de los hallazgos (nuevo, sigue abierto, corregido) es de quien
  integra el motor.
- No decide qué está permitido. Si el objetivo está autorizado, si se pueden
  correr checks activos o si procede el modo agresivo lo decide quien llama y
  llega ya resuelto en :class:`ScanRequest`.
- No lee configuración. Los ajustes llegan en :class:`ScanSettings`.

Cada fase de red es un método de :class:`ScanPhases`. Quien integra el motor
puede sustituir cualquiera (por ejemplo, la detección por versión con su
propia base de conocimiento) sin tocar el orden del escaneo, que vive en
:func:`run_scan`.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import dataclass, replace
from functools import partial
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

from .api_surface import SPECIFICATION_PATHS, parse_specification
from .api_surface import derive_checks as derive_api_checks
from .checks import (
    CheckRuntime,
    HostRateLimiter,
    HttpProbe,
    NetworkProbe,
    is_ftp_service,
    is_http_service,
    is_tls_service,
    load_checks,
)
from .correlation import split_refutations
from .crawler import crawl, select_scan_directories
from .credentials import CredentialRuntime, load_credentials
from .engine import QOD_OPEN_PORT, LybraEngine, Service
from .fingerprinting.cascade import identify_unknown_service
from .fingerprinting.dispatch import DissectorResult
from .fingerprinting.registry import default_dissectors
from .fingerprinting.tls import TlsProbe
from .script_checks import default_script_plugins
from .transport import (
    WELL_KNOWN_PORTS,
    PortSweep,
    is_sweep_implausible,
    pinned_resolution,
    scan_udp_ports_sync,
    services_from_discovered_ports,
    sweep_with_retries,
)
from .virtual_hosts import (
    depends_on_site,
    has_own_named_sites,
    is_alias_of_default_site,
    mark_default_site_findings,
    select_site_names,
    site_finding,
)

logger = logging.getLogger(__name__)


class ScanAborted(Exception):
    """El escaneo no pudo hacerse, y se sabe por qué.

    Es distinto de un escaneo **parcial**: uno parcial trae resultados ciertos
    sobre parte del objetivo; uno abortado no trae ninguno.

    Attributes:
        reason: Código estable de la causa: ``"host_unreachable"`` (el objetivo
            no contestó a la comprobación de alcanzabilidad) o
            ``"port_discovery_failed"`` (contestaba, pero el barrido de puertos
            quedó bloqueado o falló).
    """

    HOST_UNREACHABLE = "host_unreachable"
    PORT_DISCOVERY_FAILED = "port_discovery_failed"

    def __init__(self, reason: str, message: str) -> None:
        """
        Crea el error con su causa.

        Args:
            reason: :attr:`HOST_UNREACHABLE` o :attr:`PORT_DISCOVERY_FAILED`.
            message: Explicación legible para el log.
        """
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class ScanSettings:  # pylint: disable=too-many-instance-attributes
    """Los ajustes de un escaneo: plazos, ritmo, concurrencia y topes.

    Todos tienen un valor por defecto que es el que el motor usa si nadie dice
    otra cosa; quien integra el motor los construye desde su propia
    configuración.

    Attributes:
        tcp_concurrency: Conexiones TCP simultáneas del barrido. Por defecto 200.
        tcp_timeout: Segundos de plazo por puerto TCP. Por defecto 2.0.
        udp_timeout: Segundos de plazo por sonda UDP. Por defecto 2.0.
        udp_retries: Reintentos del barrido (TCP y UDP). Por defecto 1.
        udp_budget_seconds: Presupuesto de reloj del barrido UDP. Por defecto 20.0.
        rate_limit_interval: Segundos mínimos entre dos peticiones al mismo
            host. Por defecto 0.2.
        rate_limit_max_backoff_factor: Cuántas veces puede alargarse ese
            intervalo contra un host que deja de contestar. Por defecto 8.0.
        host_pool_size: Servicios de un mismo host que se sondean a la vez.
            Por defecto 8.
        http_timeout: Segundos de plazo por petición HTTP. Por defecto 8.
        http_max_body_bytes: Bytes máximos que se leen de un cuerpo HTTP.
            Por defecto 131072.
        http_user_agent: ``User-Agent`` de las peticiones. Por defecto ``"Lybra/1.0"``.
        network_timeout: Plazo de las sondas de red crudas. Por defecto 5.0.
        banner_timeout: Plazo para leer el saludo de un servicio desconocido.
            Por defecto 2.0.
        max_blind_probes: Sondas a ciegas contra un servicio que no saluda.
            Por defecto 2.
        max_payload_expansions: Tope de variantes por check con cargas. Por defecto 25.
        implausible_open_ratio: Fracción de puertos abiertos a partir de la
            cual el barrido se juzga inverosímil. Por defecto 0.5.
        implausible_min_probed: Puertos probados mínimos para aplicar esa
            regla. Por defecto 100.
        blocking_recheck_ports: Puertos abiertos que se vuelven a probar al
            final; 0 desactiva la comprobación. Por defecto 3.
        max_virtual_hosts: Sitios con nombre que se auditan por IP; 0 los
            desactiva. Por defecto 10.
        capture_evidence: Si los checks guardan la evidencia de lo que vieron.
            Por defecto ``True``.
        crawler_max_pages: Páginas por servicio web; 0 desactiva el rastreo.
            Por defecto 50.
        crawler_max_depth: Profundidad máxima del rastreo. Por defecto 3.
        crawler_time_budget_seconds: Presupuesto de reloj del rastreo por
            servicio. Por defecto 20.0.
        crawler_max_scan_directories: Directorios descubiertos sobre los que se
            repiten los checks de ruta. Por defecto 10.
        api_max_endpoints: Checks derivados de una especificación de API; 0
            desactiva el análisis. Por defecto 25.
        api_max_specification_bytes: Bytes máximos de una especificación. Por
            defecto 1048576.
        credential_max_attempts: Intentos por cuenta en el motor de
            credenciales. Por defecto 3.
        reachability_check: Si se comprueba que el objetivo contesta antes de
            barrer sus puertos. Por defecto ``True``.
        reachability_port: Puerto de esa comprobación. Por defecto 80.
        reachability_timeout: Plazo de esa comprobación. Por defecto 3.0.
    """

    tcp_concurrency: int = 200
    tcp_timeout: float = 2.0
    udp_timeout: float = 2.0
    udp_retries: int = 1
    udp_budget_seconds: float = 20.0
    rate_limit_interval: float = 0.2
    rate_limit_max_backoff_factor: float = 8.0
    host_pool_size: int = 8
    http_timeout: float = 8
    http_max_body_bytes: int = 131072
    http_user_agent: str = "Lybra/1.0"
    network_timeout: float = 5.0
    banner_timeout: float = 2.0
    max_blind_probes: int = 2
    max_payload_expansions: int = 25
    implausible_open_ratio: float = 0.5
    implausible_min_probed: int = 100
    blocking_recheck_ports: int = 3
    max_virtual_hosts: int = 10
    capture_evidence: bool = True
    crawler_max_pages: int = 50
    crawler_max_depth: int = 3
    crawler_time_budget_seconds: float = 20.0
    crawler_max_scan_directories: int = 10
    api_max_endpoints: int = 25
    api_max_specification_bytes: int = 1048576
    credential_max_attempts: int = 3
    reachability_check: bool = True
    reachability_port: int = 80
    reachability_timeout: float = 3.0


@dataclass(frozen=True)
class ScanRequest:  # pylint: disable=too-many-instance-attributes
    """Qué escanear y qué está permitido hacer contra ello.

    Attributes:
        target: IP o nombre del objetivo.
        services: Servicios ya conocidos que analizar **sin tocar la red**
            (un inventario de software, por ejemplo), o ``None`` para
            descubrirlos con un barrido propio. Con servicios no se sondea nada:
            ni descubrimiento, ni fingerprinting, ni checks activos.
        ports: Puertos TCP que barrer; ``None`` usa la lista por defecto del
            transporte. Se ignora si hay ``services``.
        pinned_address: La IP validada a la que se fija un objetivo por nombre
            durante todo el escaneo, para que un cambio de DNS a mitad no lo
            desvíe; ``None`` si el objetivo ya es una IP. Por defecto ``None``.
        timeout_seconds: Presupuesto de reloj del escaneo entero; ``None`` o 0
            lo deja sin límite. Al agotarse, el escaneo termina como parcial.
        fingerprint: Si se identifica cada servicio sondeándolo. Por defecto
            ``True``.
        crawl: Si se rastrean los servicios web. Por defecto ``True``.
        active_checks: Si se ejecutan los checks activos, la superficie de API
            y los sitios con nombre. Por defecto ``True``.
        mode: ``"safe"`` o ``"aggressive"``. Sólo el agresivo corre los checks
            que escriben en el objetivo y el motor de credenciales. Por
            defecto ``"safe"``.
        planner: El planificador con lo que se supo del objetivo en escaneos
            anteriores, para reutilizar identidades recientes en vez de volver
            a sondearlas; ``None`` sondea todo. Por defecto ``None``.
        site_candidates: Nombres que la IP no delata y que quien llama ya
            autorizó auditar como sitios, como pares ``(nombre, origen)``. Por
            defecto, ninguno.
    """

    target: str
    services: Optional[Sequence[Service]] = None
    ports: Optional[Sequence[int]] = None
    pinned_address: Optional[str] = None
    timeout_seconds: Optional[float] = None
    fingerprint: bool = True
    crawl: bool = True
    active_checks: bool = True
    mode: str = "safe"
    planner: Optional[object] = None
    site_candidates: Tuple[Tuple[str, str], ...] = ()

    @property
    def probes_network(self) -> bool:
        """Si el escaneo toca el objetivo: ``False`` cuando analiza servicios ya conocidos."""
        return self.services is None


@dataclass(frozen=True)
class ScanOutcome:
    """Lo que vio un escaneo.

    Attributes:
        services: Los servicios del objetivo, ya identificados.
        findings: Los hallazgos, todos en estado ``open``. Incluye los avisos
            sobre la integridad del propio escaneo (categoría
            ``scan_integrity``).
        refutations: Las marcas de los checks refutadores, que no son
            hallazgos: dicen qué hallazgo de versión desmintió una prueba
            activa. Quien lleva el ciclo de vida las aplica (ver
            ``apply_refutations``).
        is_partial: Si el escaneo no llegó a mirar todo el objetivo (plazo
            agotado, cancelación, barrido inverosímil o un objetivo que dejó de
            contestar). **Lo que falta en un resultado parcial no se ha
            comprobado**: no es evidencia de que se haya corregido.
        probed_service_keys: Los ``(puerto, protocolo)`` que este escaneo
            identificó sondeándolos de verdad; los que el planificador
            reutilizó no están. Vacío si el fingerprinting se cortó a medias.
    """

    services: List[Service]
    findings: List[dict]
    refutations: List[dict]
    is_partial: bool
    probed_service_keys: frozenset


class _NoProgress:
    """Un receptor de progreso que no hace nada, para quien no lo pide."""

    def advance(self, phase: str, done: int, total: int) -> None:
        """Ignora el avance de una fase."""

    def complete(self, phase: str) -> None:
        """Ignora el final de una fase."""


class ScanPhases:  # pylint: disable=too-many-public-methods
    """Las fases de red de un escaneo, cada una sustituible por separado.

    :func:`run_scan` decide el orden y las condiciones; esta clase sólo hace
    cada paso. Todas las fases de red son *best-effort*: un fallo cuesta esa
    fase, no el escaneo, salvo el descubrimiento, que sin él no hay nada que
    analizar.

    Attributes:
        settings: Los ajustes del escaneo.
    """

    def __init__(self, settings: Optional[ScanSettings] = None) -> None:
        """
        Crea las fases con sus ajustes.

        Args:
            settings: Los ajustes; ``None`` usa los valores por defecto de
                :class:`ScanSettings`.
        """
        self.settings = settings or ScanSettings()

    # ------------------------------------------------------------ descubrimiento

    def is_host_reachable(self, target: str, port: int, timeout: float) -> bool:
        """
        Comprueba que el objetivo contesta antes de barrer sus puertos.

        Una conexión aceptada o rechazada demuestra que hay alguien al otro
        lado; sólo el silencio (plazo agotado, red inalcanzable) cuenta como
        inalcanzable.

        Args:
            target: IP o nombre del objetivo.
            port: Puerto TCP de la comprobación.
            timeout: Segundos de plazo.

        Returns:
            bool: ``True`` si el objetivo contestó de cualquier forma.
        """
        try:
            with socket.create_connection((target, port), timeout=timeout):
                return True
        except ConnectionRefusedError:
            return True
        except OSError:
            return False

    def discover_ports(self, target: str, ports=None, budget_seconds: Optional[float] = None,
                       cancel_check: Optional[Callable[[], bool]] = None,
                       on_progress: Optional[Callable[[int, int], None]] = None) -> Optional[PortSweep]:
        """
        Descubre los puertos TCP abiertos con el barrido propio del motor.

        Devuelve el barrido entero y no una lista porque los desenlaces son
        tres: **limpio** (``open_ports`` es la superficie), **bloqueado**
        (``None``: nada contestó de ninguna forma, así que no se sabe nada y
        tratarlo como «todo cerrado» daría por corregido lo que sigue abierto)
        y **truncado** (``was_truncated``: se acabó el reloj; lo encontrado es
        cierto y lo que quedó sin mirar es desconocido).

        Args:
            target: IP o nombre del objetivo.
            ports: Puertos a probar; ``None`` usa la lista por defecto del
                transporte.
            budget_seconds: Segundos de reloj para el barrido entero,
                reintentos incluidos. ``None`` lo deja sin límite.
            cancel_check: Devuelve ``True`` cuando hay que dejar de lanzar
                sondas. Por defecto ``None``.
            on_progress: Recibe ``(probados, total)``. Un reintento vuelve a
                contar desde cero. Por defecto ``None``.

        Returns:
            Optional[PortSweep]: El barrido, limpio o truncado; ``None`` si
                quedó bloqueado o falló.
        """
        settings = self.settings
        try:
            sweep = sweep_with_retries(
                target, ports,
                concurrency=settings.tcp_concurrency,
                timeout=settings.tcp_timeout,
                retries=settings.udp_retries,
                budget_seconds=budget_seconds,
                cancel_check=cancel_check,
                on_progress=on_progress,
            )
        except Exception:  # pylint: disable=broad-exception-caught
            logger.exception("Lybra port discovery failed for %s", target)
            return None
        if sweep.is_blocked:
            logger.error(
                "Descubrimiento bloqueado para %s: el host respondió al chequeo de "
                "alcanzabilidad y después ningún puerto contestó. El escaneo falla "
                "en vez de reportar un objetivo limpio.",
                target,
            )
            return None
        if sweep.was_truncated:
            logger.warning(
                "Descubrimiento parcial de %s: %s puertos abiertos encontrados (%s) "
                "antes de agotar el presupuesto. El escaneo continúa marcado como "
                "incompleto y no cerrará ningún hallazgo anterior.",
                target, len(sweep.open_ports), list(sweep.open_ports),
            )
        return sweep

    def discover_udp_ports(self, target: str) -> list:
        """
        Descubre los puertos UDP abiertos con la tabla de sondas curada.

        Nunca devuelve ``None``: el silencio UDP es por definición
        indistinguible de «no hay nada», así que un fallo no justifica tirar un
        descubrimiento TCP bueno. Usa siempre las sondas UDP del transporte,
        nunca la lista TCP de quien llama.

        Args:
            target: IP o nombre del objetivo.

        Returns:
            list: Los puertos UDP abiertos; vacía si no hay o si algo falló.
        """
        settings = self.settings
        try:
            return scan_udp_ports_sync(
                target,
                timeout=settings.udp_timeout,
                retries=settings.udp_retries,
                budget_seconds=settings.udp_budget_seconds,
            )
        except Exception:  # pylint: disable=broad-exception-caught
            logger.exception("Lybra UDP port discovery failed for %s", target)
            return []

    # ------------------------------------------------------------ identificación

    def in_host_pool(self, work: Callable, items: Iterable,
                     on_progress: Optional[Callable[[int, int], None]] = None) -> list:
        """
        Aplica ``work`` a cada elemento con un pool de hilos acotado por host.

        El fingerprinting y los checks activos son casi sólo espera de red; en
        fila india, un servicio mudo retrasa a todos los de detrás. El pool
        decide cuántas sondas pueden estar **esperando** a la vez, no a qué
        ritmo salen: eso lo sigue marcando ``HostRateLimiter``, que es seguro
        entre hilos.

        Args:
            work: La función a aplicar a cada elemento.
            items: Los elementos.
            on_progress: Recibe ``(terminados, total)`` cada vez que termina un
                elemento, en el orden en que terminan. Por defecto ``None``.

        Returns:
            list: Los resultados, **en el orden de entrada**, para que el
                resultado de un escaneo no dependa de qué servicio contestó antes.
        """
        items = list(items)
        if not items:
            return []
        if on_progress is not None:
            work = _reporting_completion(work, len(items), on_progress)
        workers = max(1, min(self.settings.host_pool_size, len(items)))
        if workers == 1:
            return [work(item) for item in items]
        with ThreadPoolExecutor(max_workers=workers) as pool:
            return list(pool.map(work, items))

    def fingerprint_services(self, target: str, services: list,
                             cancel_check: Optional[Callable[[], bool]] = None,
                             on_progress: Optional[Callable[[int, int], None]] = None) -> tuple:
        """
        Identifica cada servicio con los dissectors propios del motor.

        La identificación que sale de aquí **es** la del servicio: alimenta la
        detección por versión y deja un hallazgo informativo con lo que se
        leyó. Un servicio que ningún dissector reclama (un MySQL en el 33060, un
        SSH en el 2222) pasa por la cascada, que pregunta en vez de suponer;
        sólo en TCP, porque leer un saludo no significa nada en un datagrama.

        Args:
            target: IP o nombre del objetivo.
            services: Servicios a identificar.
            cancel_check: Devuelve ``True`` cuando hay que dejar de sondar; los
                servicios que faltan se devuelven sin identificar. Por defecto
                ``None``.
            on_progress: Recibe ``(identificados, total)``. Por defecto ``None``.

        Returns:
            tuple: ``(servicios, hallazgos)``: los servicios con el producto y
                la versión que se leyeron, y los hallazgos informativos del
                fingerprint.
        """
        dissectors = default_dissectors()
        settings = self.settings
        rate_limiter = HostRateLimiter(min_interval=settings.rate_limit_interval)

        def identify(service):
            """Sonda un servicio y devuelve ``(servicio, resultado)``; ``resultado`` es ``None`` si no se leyó nada."""
            if cancel_check is not None and cancel_check():
                return service, None
            dissector = next((dissector for dissector in dissectors if dissector.applies(service)), None)
            result = None
            if dissector is not None:
                try:
                    result = dissector.probe(target, service, rate_limiter)
                except Exception:  # pylint: disable=broad-exception-caught
                    logger.debug("Fingerprinting failed for %s:%s", target, service.port, exc_info=True)
            elif (service.protocol or "tcp").lower() != "udp":
                try:
                    result = identify_unknown_service(
                        target, service, dissectors, rate_limiter,
                        banner_timeout=settings.banner_timeout,
                        max_blind_probes=settings.max_blind_probes,
                    )
                except Exception:  # pylint: disable=broad-exception-caught
                    logger.debug("Cascade failed for %s:%s", target, service.port, exc_info=True)
            return service, result

        findings: list = []
        updated: list = []
        for service, result in self.in_host_pool(identify, services, on_progress=on_progress):
            if result is None:
                updated.append(service)
                continue
            # Lo que el servicio demostró hablar manda sobre la tabla de puertos:
            # un panel web en el 3000 recibe los mismos checks HTTP que uno en el 8080.
            if result.protocol == "http" and not is_http_service(service):
                service = replace(service, name="http")
            # Una huella que no nombra ningún producto («Server: Web») no se reporta.
            if not result.is_generic:
                findings.append(self.fingerprint_finding(service, result))
            findings.extend(self.layer_findings(service, result))
            if result.product and result.version:
                service = replace(service, product=result.product, version=result.version)
            if getattr(result, "components", ()):
                service = replace(service, components=result.components)
            updated.append(service)
        return updated, findings

    def layer_findings(self, service: Service, result) -> list:
        """
        Devuelve un hallazgo informativo por cada capa de servidor adicional.

        Un puerto HTTP no siempre lo atiende un solo programa: un nginx de
        proxy inverso delante de un Apache son dos, los dos expuestos y los dos
        con CVE. Elegir una capa en silencio produce falsos negativos por un
        lado y falsos positivos por el otro.

        Args:
            service: El servicio identificado.
            result: El resultado del dissector, con sus ``extra_layers``.

        Returns:
            list: Un hallazgo ``fingerprint`` por capa con producto conocido.
        """
        layers = [
            DissectorResult(product, version, f"{result.label} {role}", qod=result.qod)
            for product, version, role in getattr(result, "extra_layers", ())
        ]
        return [self.fingerprint_finding(service, layer) for layer in layers if not layer.is_generic]

    def fingerprint_finding(self, service: Service, result) -> dict:
        """
        Construye el hallazgo informativo que dice qué identificó el motor.

        Es una constatación, no un veredicto. Su ``qod`` lo pone el dissector:
        una versión leída de una cabecera explícita vale más que una deducida
        de una página de error.

        Args:
            service: El servicio identificado.
            result: El resultado del dissector.

        Returns:
            dict: El hallazgo, de categoría ``fingerprint``.
        """
        own = f"{result.product or '?'} {result.version or ''}".strip()
        return {
            "title":        f"Fingerprint propio ({result.label}): {own}",
            "category":     "fingerprint",
            "port":         service.port,
            "service":      service.name or None,
            "protocol":     service.protocol,
            "source":       "lybra",
            "check_id":     "lybra:fingerprint@1",
            "feed_version": "lybra-fingerprint-1",
            "qod":          result.qod,
            "confirmed":    False,
            "state":        "open",
        }

    def analyze(self, services: List[Service]) -> List[dict]:
        """
        Convierte los servicios en hallazgos: puertos abiertos y CVE por versión.

        La implementación por defecto no tiene base de conocimiento, así que
        sólo produce los hallazgos que no la necesitan. Quien integra el motor
        la sustituye por un :class:`LybraEngine` con sus consultas.

        Args:
            services: Los servicios ya identificados.

        Returns:
            List[dict]: Los hallazgos.
        """
        return LybraEngine().analyze(services)

    # ------------------------------------------------------------ análisis activo

    def ingested_checks(self, services: list) -> list:  # pylint: disable=unused-argument
        """
        Devuelve checks adicionales a los del feed propio para estos servicios.

        Es el punto por el que quien integra el motor añade checks traducidos
        de otra fuente. Por defecto, ninguno.

        Args:
            services: Los servicios del escaneo.

        Returns:
            list: Los checks adicionales.
        """
        return []

    def run_crawler(self, target: str, services: list,
                    cancel_check: Optional[Callable[[], bool]] = None) -> tuple:
        """
        Rastrea en sólo lectura los servicios web del objetivo.

        Descubre lo que los checks no conocen de antemano: rutas de
        ``robots.txt``, formularios de login y rutas tras autenticación básica.

        Args:
            target: El objetivo (IP o nombre ya fijado a la IP validada).
            services: Los servicios del escaneo.
            cancel_check: Dice si hay que parar; el rastreo se detiene entre
                páginas y no empieza los servicios que quedan. Por defecto
                ``None``.

        Returns:
            tuple: ``(hallazgos, rutas_con_auth_basica, directorios,
                rutas_de_login)``. Los directorios y las rutas de login van por
                puerto (``{puerto: [ruta, ...]}``). Todo vacío si el rastreo
                está desactivado o falló.
        """
        settings = self.settings
        try:
            if settings.crawler_max_pages <= 0:
                return [], [], {}, {}
            fetch = _http_fetch(self.settings)
            findings: list = []
            auth_paths: list = []
            directories_by_port: dict = {}
            login_paths_by_port: dict = {}
            for service in services:
                if not is_http_service(service) or (cancel_check and cancel_check()):
                    continue
                result = crawl(
                    target, service.port, fetch,
                    max_pages=settings.crawler_max_pages,
                    max_depth=settings.crawler_max_depth,
                    time_budget_seconds=settings.crawler_time_budget_seconds,
                    cancel_check=cancel_check,
                )
                findings.extend(crawl_findings(service, result))
                auth_paths.extend(result.basic_auth_paths)
                directories_by_port[service.port] = select_scan_directories(
                    result.directories, settings.crawler_max_scan_directories)
                login_paths_by_port[service.port] = list(result.login_paths)
            return findings, auth_paths, directories_by_port, login_paths_by_port
        except Exception:  # pylint: disable=broad-exception-caught
            logger.exception("Lybra crawl failed for %s", target)
            return [], [], {}, {}

    def run_active_checks(  # pylint: disable=too-many-arguments,too-many-positional-arguments
            self, target: str, services, cancel_check=None, proposed_cves=None,
            mode: str = "safe", discovered_directories=None, discovered_paths=None,
            on_progress=None) -> list:
        """
        Ejecuta los checks activos contra los servicios del objetivo.

        ``mode`` llega ya resuelto: esta capa no decide si el agresivo procede,
        sólo lo aplica. El limitador de esta fase es adaptativo y frena contra
        un host que deja de contestar.

        Args:
            target: El objetivo (IP o nombre ya fijado a la IP validada).
            services: Los servicios del objetivo.
            cancel_check: Dice si hay que parar. Por defecto ``None``.
            proposed_cves: CVE que la detección por versión ya propuso; los
                checks confirmadores y refutadores sólo corren para ellas. Por
                defecto ``None`` (ninguna).
            mode: ``"safe"`` o ``"aggressive"``. Por defecto ``"safe"``.
            discovered_directories: Directorios del rastreo por puerto, sobre
                los que se repiten los checks de ruta. Por defecto ``None``.
            discovered_paths: Rutas de login del rastreo por puerto. Por
                defecto ``None``.
            on_progress: Recibe ``(servicios terminados, total)``. Por defecto
                ``None``.

        Returns:
            list: Los hallazgos (y marcas de refutación) de los checks que
                dispararon; vacía si el runtime falló.
        """
        settings = self.settings
        try:
            runtime = CheckRuntime(
                load_checks() + self.ingested_checks(services),
                _http_fetch(self.settings),
                mode=mode,
                rate_limiter=HostRateLimiter(
                    min_interval=settings.rate_limit_interval,
                    max_backoff_factor=settings.rate_limit_max_backoff_factor,
                ),
                tls_fetch=TlsProbe().fetch,
                network_open=NetworkProbe(timeout=settings.network_timeout).open,
                script_plugins=default_script_plugins(),
                capture_evidence=settings.capture_evidence,
                max_payload_expansions=settings.max_payload_expansions,
                mapper=partial(self.in_host_pool, on_progress=on_progress),
            )
            return runtime.run(target, services, cancel_check=cancel_check,
                               proposed_cves=proposed_cves,
                               discovered_directories=discovered_directories,
                               discovered_paths=discovered_paths)
        except Exception:  # pylint: disable=broad-exception-caught
            logger.exception("Lybra active checks failed for %s", target)
            return []

    def run_api_surface(self, target: str, services: list, mode: str = "safe",
                        cancel_check: Optional[Callable[[], bool]] = None,
                        fetch: Optional[Callable] = None) -> List[dict]:
        """
        Prueba los endpoints que la especificación de cada servicio web declara protegidos.

        Por cada servicio HTTP pide las rutas de ``SPECIFICATION_PATHS`` hasta
        dar con una especificación parseable, deriva de ella los checks y los
        ejecuta. Los de lectura y el de asignación masiva van en runtimes
        **distintos**: el runtime comparte la respuesta de cada petición, y la
        lectura posterior a una escritura devolvería la respuesta de antes de
        escribir. Los de escritura sólo corren en modo ``aggressive``.

        Args:
            target: El objetivo (IP o nombre ya fijado a la IP validada).
            services: Los servicios del escaneo.
            mode: ``"safe"`` o ``"aggressive"``. Por defecto ``"safe"``.
            cancel_check: Dice si hay que parar. Por defecto ``None``.
            fetch: ``(host, port, method, path, body, headers) -> Response |
                None``. Por defecto, una ``HttpProbe`` con los ajustes del escaneo.

        Returns:
            List[dict]: Los hallazgos de los checks derivados que dispararon;
                vacía si ningún servicio publica especificación, si el análisis
                está desactivado o si algo falló.
        """
        settings = self.settings
        if settings.api_max_endpoints < 1:
            return []
        try:
            fetch = fetch or _http_fetch(settings, settings.api_max_specification_bytes)
            limiter = HostRateLimiter(
                min_interval=settings.rate_limit_interval,
                max_backoff_factor=settings.rate_limit_max_backoff_factor,
            )
            findings: List[dict] = []
            for service in services:
                if not is_http_service(service) or (cancel_check and cancel_check()):
                    continue
                checks = _derived_api_checks(
                    target, service, fetch, limiter, settings.api_max_endpoints, cancel_check)
                for check_mode in ("safe", "aggressive"):
                    group = [check for check in checks if check.mode == check_mode]
                    if not group or (check_mode == "aggressive" and mode != "aggressive"):
                        continue
                    findings.extend(CheckRuntime(
                        group, fetch, mode=mode, rate_limiter=limiter,
                        capture_evidence=settings.capture_evidence,
                    ).run(target, [service], cancel_check=cancel_check))
            return findings
        except Exception:  # pylint: disable=broad-exception-caught
            logger.exception("Lybra API surface analysis failed for %s", target)
            return []

    def audit_named_sites(self, address: str, services: list, cancel_check: Callable[[], bool],
                          run_checks: Callable, extra_candidates: Sequence[Tuple[str, str]] = ()) -> list:
        """
        Descubre los sitios con nombre de una IP y repite sobre cada uno los checks web.

        Ver :func:`audit_named_sites`, que es la implementación; este método
        sólo le pasa el tope de sitios de los ajustes.

        Args:
            address: La IP escaneada.
            services: Los servicios del escaneo.
            cancel_check: Devuelve ``True`` si hay que dejar de trabajar.
            run_checks: ``(nombre, servicios) -> hallazgos``.
            extra_candidates: Nombres autorizados que la IP no delata.

        Returns:
            list: Un aviso ``virtual_host`` por sitio y los hallazgos de cada uno.
        """
        return audit_named_sites(address, services, cancel_check, run_checks,
                                 max_sites=self.settings.max_virtual_hosts,
                                 extra_candidates=extra_candidates)

    def run_credential_checks(self, target: str, services: list, mode: str,
                              discovered_paths=None,
                              cancel_check: Optional[Callable[[], bool]] = None) -> list:
        """
        Prueba credenciales por defecto contra los servicios del objetivo.

        Es la única familia de detección que escribe en el objetivo (un login
        real), así que repite por su cuenta la comprobación de modo aunque
        quien llama ya la hizo: dos guardas para lo único que puede bloquear
        una cuenta real.

        Args:
            target: El objetivo (IP o nombre ya fijado a la IP validada).
            services: Los servicios del escaneo.
            mode: Sólo ``"aggressive"`` prueba algo; cualquier otro devuelve
                una lista vacía.
            discovered_paths: Rutas con autenticación básica que encontró el
                rastreo. Por defecto ``None``.
            cancel_check: Dice si hay que parar; no se lanza ningún intento más.
                Por defecto ``None``.

        Returns:
            list: Los hallazgos de credenciales aceptadas; vacía si el modo no
                es agresivo o si algo falló.
        """
        if mode != "aggressive":
            return []
        settings = self.settings
        try:
            runtime = CredentialRuntime(
                load_credentials(),
                _http_fetch(self.settings),
                # Cada intento es un login real: el ritmo es cinco veces más lento
                # que el de los checks de lectura, para no parecer fuerza bruta.
                rate_limiter=HostRateLimiter(min_interval=settings.rate_limit_interval * 5),
                max_attempts_per_account=settings.credential_max_attempts,
                capture_evidence=settings.capture_evidence,
            )
            return runtime.run(target, services, discovered_paths=discovered_paths,
                               cancel_check=cancel_check)
        except Exception:  # pylint: disable=broad-exception-caught
            logger.exception("Lybra credential checks failed for %s", target)
            return []


# ============================================================ el escaneo


def run_scan(request: ScanRequest, phases: Optional[ScanPhases] = None, *,  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
             cancel_check: Optional[Callable[[], bool]] = None,
             progress=None,
             enrich: Optional[Callable[[List[dict]], List[dict]]] = None) -> ScanOutcome:
    """
    Escanea un objetivo y devuelve lo que vio.

    ``request.timeout_seconds`` acota **el escaneo entero**: el descubrimiento
    come de él como presupuesto y las fases de después lo consultan y se cortan
    solas. Un plazo por operación no basta, porque limita cuánto tarda cada
    sonda pero no cuántas se hacen, y eso lo decide el objetivo.

    Cancelar y agotar el reloj significan lo mismo para el resultado: vio parte
    del objetivo, no todo. Los dos terminan bien, con ``is_partial``.

    Args:
        request: Qué escanear y qué está permitido.
        phases: Las fases de red; ``None`` usa :class:`ScanPhases` con los
            ajustes por defecto.
        cancel_check: Devuelve ``True`` cuando hay que cancelar. Por defecto
            ``None`` (no se cancela).
        progress: Recibe el avance con ``advance(fase, hechos, total)`` y
            ``complete(fase)``; las fases son ``"discovery"``,
            ``"fingerprint"`` y ``"checks"``. Por defecto ``None``.
        enrich: Recibe los hallazgos de la identificación y devuelve otros que
            añadir antes del análisis activo (sugerencias de fuentes pasivas,
            por ejemplo). Por defecto ``None``.

    Returns:
        ScanOutcome: Los servicios, los hallazgos y si el resultado es parcial.

    Raises:
        ScanAborted: Si el objetivo no contesta o el barrido de puertos queda
            bloqueado: no hay resultado que devolver.
    """
    phases = phases or ScanPhases()
    progress = progress or _NoProgress()
    target = request.target
    deadline = time.monotonic() + request.timeout_seconds if request.timeout_seconds else None
    is_cancelled = cancel_check or (lambda: False)

    def should_stop() -> bool:
        """Si hay que dejar de mirar el objetivo: cancelación o reloj agotado."""
        return (deadline is not None and time.monotonic() >= deadline) or is_cancelled()

    def remaining_budget() -> Optional[float]:
        """Segundos que quedan del plazo, o ``None`` si no hay plazo."""
        return None if deadline is None else max(0.0, deadline - time.monotonic())

    def discover(scan_target: str, ports) -> Optional[PortSweep]:
        """El barrido TCP con el presupuesto que quede en este momento y la cancelación."""
        return phases.discover_ports(
            scan_target, ports,
            budget_seconds=remaining_budget(),
            cancel_check=should_stop,
            on_progress=partial(progress.advance, "discovery"),
        )

    with ExitStack() as pins:
        if request.pinned_address and request.pinned_address != target:
            pins.enter_context(pinned_resolution(target, request.pinned_address))

        if request.probes_network:
            services, is_partial, implausible_open_ports = _discover_services(
                request, phases, discover)
        else:
            services, is_partial, implausible_open_ports = list(request.services), False, 0
        is_partial = is_partial or should_stop()
        integrity_findings = []
        if implausible_open_ports:
            integrity_findings.append(scan_integrity_finding(
                f"El objetivo acepta conexiones en cualquier puerto "
                f"({implausible_open_ports} «abiertos»): probable "
                f"cortafuegos engañoso; sólo se analizan los puertos conocidos"))
        progress.complete("discovery")

        fingerprint_findings: list = []
        probed_service_keys: set = set()
        if request.probes_network and request.fingerprint and not should_stop():
            planner = request.planner
            if planner is None:
                probed_service_keys = _port_keys_of(services)
                services, fingerprint_findings = phases.fingerprint_services(
                    target, services, cancel_check=should_stop,
                    on_progress=partial(progress.advance, "fingerprint"))
            else:
                to_probe, to_reuse = planner.partition(services)
                probed_service_keys = _port_keys_of(to_probe)
                probed, fingerprint_findings = phases.fingerprint_services(
                    target, to_probe, cancel_check=should_stop,
                    on_progress=partial(progress.advance, "fingerprint"))
                reused = [planner.apply_cached_identity(service) for service in to_reuse]
                services = _merge_fingerprint_results(services, to_probe, probed, to_reuse, reused)
            is_partial = is_partial or should_stop()
            if should_stop():
                # Un fingerprint cortado a medias no sondeó todo lo previsto:
                # darlo por identificado daría por fresca una identidad sin mirar.
                probed_service_keys = set()
        progress.complete("fingerprint")

        findings = phases.analyze(services)
        findings.extend(fingerprint_findings)

        # Las hipótesis que un confirmador puede ascender a hecho: el runtime
        # sólo corre un confirmador cuya CVE esté aquí, nunca «por si acaso».
        proposed_cves = frozenset(cve for finding in findings for cve in (finding.get("cve_ids") or ()))

        if enrich is not None and not should_stop():
            findings.extend(enrich(findings))

        may_probe = request.probes_network
        mode = request.mode
        discovered_auth_paths: list = []
        discovered_directories: dict = {}
        discovered_login_paths: dict = {}
        # El rastreo va antes de los checks activos para que las rutas con
        # puerta lleguen al motor de credenciales.
        if may_probe and request.crawl and not should_stop():
            crawl_result, discovered_auth_paths, discovered_directories, discovered_login_paths = (
                phases.run_crawler(target, services, cancel_check=should_stop))
            findings.extend(crawl_result)
        progress.advance("checks", 1, 3)

        refutations: list = []
        if may_probe and request.active_checks and not should_stop():
            active_findings, refutations = split_refutations(phases.run_active_checks(
                target, services, cancel_check=should_stop, proposed_cves=proposed_cves, mode=mode,
                discovered_directories=discovered_directories, discovered_paths=discovered_login_paths,
                on_progress=lambda done, total: progress.advance("checks", total + done, 3 * total)))
            if not should_stop():
                active_findings += phases.run_api_surface(
                    target, services, mode=mode, cancel_check=should_stop)
            # Escanear una IP audita su sitio por defecto. Los sitios con nombre
            # que la propia IP delata se auditan aparte, cada uno con su nombre,
            # y si alguno sirve una web propia, lo que la IP enseña sin nombre se
            # reporta como su sitio por defecto.
            if _is_ip_address(target) and not should_stop():
                site_findings, site_refutations = split_refutations(phases.audit_named_sites(
                    target, services, should_stop,
                    lambda name, web: phases.run_active_checks(
                        name, web, cancel_check=should_stop, proposed_cves=proposed_cves, mode=mode),
                    extra_candidates=request.site_candidates))
                if has_own_named_sites(site_findings):
                    mark_default_site_findings(active_findings)
                active_findings += site_findings
                refutations += site_refutations
            findings.extend(active_findings)
            is_partial = is_partial or should_stop()
        progress.advance("checks", 2, 3)

        if may_probe and mode == "aggressive" and not should_stop():
            findings.extend(phases.run_credential_checks(
                target, services, mode, discovered_auth_paths, cancel_check=should_stop))

        # ¿Sigue respondiendo el objetivo? Si no contesta ninguno de los puertos
        # que estaban abiertos, lo de después del bloqueo no es un resultado
        # limpio sino uno incompleto.
        if (may_probe and not should_stop()
                and not is_still_reachable(discover, target, services, phases.settings.blocking_recheck_ports)):
            logger.warning("Lybra: el objetivo %s dejó de responder durante el escaneo", target)
            is_partial = True
            integrity_findings.append(scan_integrity_finding(
                "El objetivo dejó de responder durante el escaneo (probable bloqueo "
                "del escáner): los resultados están incompletos"))
        findings.extend(integrity_findings)
        progress.complete("checks")

    return ScanOutcome(
        services=services,
        findings=findings,
        refutations=refutations,
        is_partial=is_partial,
        probed_service_keys=frozenset(probed_service_keys),
    )


def _discover_services(request: ScanRequest, phases: ScanPhases,
                       discover: Callable[[str, Optional[Sequence[int]]], Optional[PortSweep]],
                       ) -> Tuple[List[Service], bool, int]:
    """
    Descubre los servicios del objetivo: alcanzabilidad, barrido TCP y sondas UDP.

    Args:
        request: La petición del escaneo.
        phases: Las fases de red.
        discover: El barrido TCP ya atado a su presupuesto y su cancelación.

    Returns:
        tuple: ``(servicios, es_parcial, puertos_inverosimiles)``. El tercero
            es cuántos puertos «abrieron» en un barrido juzgado inverosímil (un
            cortafuegos que acepta cualquier puerto), o 0; cuando no es 0 sólo
            se conservan los puertos conocidos y el escaneo es parcial.

    Raises:
        ScanAborted: Si el objetivo no contesta a la comprobación de
            alcanzabilidad o el barrido queda bloqueado.
    """
    settings = phases.settings
    target = request.target
    if settings.reachability_check and not phases.is_host_reachable(
            target, port=settings.reachability_port, timeout=settings.reachability_timeout):
        logger.warning("Host '%s' inalcanzable.", target)
        raise ScanAborted(ScanAborted.HOST_UNREACHABLE, f"Host '{target}' inalcanzable.")
    sweep = discover(target, request.ports)
    if sweep is None:
        logger.error("Descubrimiento de puertos fallido para %s", target)
        raise ScanAborted(ScanAborted.PORT_DISCOVERY_FAILED,
                          f"Descubrimiento de puertos fallido para {target}")
    discovered_ports = list(sweep.open_ports)
    is_partial = sweep.was_truncated
    implausible_open_ports = 0
    probed = len(sweep.open_ports) + len(sweep.refused_ports) + len(sweep.timed_out_ports)
    if is_sweep_implausible(len(discovered_ports), probed,
                            settings.implausible_open_ratio, settings.implausible_min_probed):
        logger.warning("Barrido inverosímil en %s: %d de %d puertos abiertos",
                       target, len(discovered_ports), probed)
        implausible_open_ports = len(discovered_ports)
        discovered_ports = [port for port in discovered_ports if port in WELL_KNOWN_PORTS]
        is_partial = True
    # UDP va con su propia tabla de sondas, nunca con la lista TCP de la petición.
    udp_ports = phases.discover_udp_ports(target)
    services = services_from_discovered_ports(discovered_ports)
    services += services_from_discovered_ports(udp_ports, protocol="udp")
    return services, is_partial, implausible_open_ports


# ============================================================ piezas sueltas


def _http_fetch(settings: ScanSettings, max_bytes: Optional[int] = None) -> Callable:
    """
    Devuelve el ``fetch`` de una :class:`HttpProbe` con los ajustes del escaneo.

    Args:
        settings: Los ajustes del escaneo (plazo, tope de cuerpo y ``User-Agent``).
        max_bytes: Tope de bytes del cuerpo que sustituye al de los ajustes, o
            ``None`` para usar ``settings.http_max_body_bytes``. Por defecto ``None``.

    Returns:
        Callable: ``(host, port, method, path, body=None, headers=None) ->
            Response | None``.
    """
    return HttpProbe(
        timeout=settings.http_timeout,
        max_bytes=max_bytes or settings.http_max_body_bytes,
        user_agent=settings.http_user_agent,
    ).fetch


def _is_ip_address(target: str) -> bool:
    """Si ``target`` es una dirección IP literal y no un nombre."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _port_keys_of(services: list) -> set:
    """
    Devuelve las claves ``(puerto, protocolo)`` de los servicios con puerto.

    Args:
        services: Servicios del escaneo; los de inventario (sin puerto) se
            ignoran, porque nunca se sondean por red.

    Returns:
        set: Pares ``(port, protocol)``, con ``"tcp"`` si no trae protocolo.
    """
    return {(service.port, service.protocol or "tcp") for service in services if service.port is not None}


def _merge_fingerprint_results(original: list, probed_inputs: list, probed_outputs: list,
                               reused_inputs: list, reused_outputs: list) -> list:
    """
    Recombina los servicios sondeados y los reutilizados en el orden original.

    El planificador parte la lista por referencia, no por copia, así que se
    emparejan por identidad: no depende de que ``Service`` sea hashable ni de
    que dos servicios con los mismos valores puedan confundirse.

    Args:
        original: Los servicios tal como llegaron.
        probed_inputs: Los que se sondearon.
        probed_outputs: Su resultado, en el mismo orden.
        reused_inputs: Los que se reutilizaron.
        reused_outputs: Su resultado, en el mismo orden.

    Returns:
        list: Los servicios resultantes, en el orden de ``original``.
    """
    probed_map = {id(service): result for service, result in zip(probed_inputs, probed_outputs)}
    reused_map = {id(service): result for service, result in zip(reused_inputs, reused_outputs)}
    return [probed_map.get(id(service), reused_map.get(id(service), service)) for service in original]


def _reporting_completion(work: Callable, total: int,
                          on_progress: Callable[[int, int], None]) -> Callable:
    """
    Envuelve ``work`` para avisar a ``on_progress`` cada vez que termina un elemento.

    Los elementos terminan en hilos distintos, así que la cuenta y el aviso van
    bajo un cerrojo; eso además entrega los avisos en orden creciente.

    Args:
        work: La función que se aplica a cada elemento.
        total: Cuántos elementos hay.
        on_progress: Recibe ``(terminados, total)``.

    Returns:
        Callable: Una función con la misma firma y resultado que ``work``.
    """
    lock = threading.Lock()
    finished = 0

    def counted(item):
        """Aplica ``work`` a ``item`` y cuenta que ha terminado."""
        nonlocal finished
        result = work(item)
        with lock:
            finished += 1
            on_progress(finished, total)
        return result

    return counted


def is_still_reachable(discover: Callable, target: str, services: list, sample_size: int) -> bool:
    """
    Comprueba si alguno de los puertos TCP abiertos sigue aceptando conexiones.

    Es lo que OpenVAS llama «Check open ports»: al final se vuelve a llamar a
    una muestra de los puertos abiertos. Si ninguno contesta, el objetivo
    bloqueó al escáner (un IPS, una regla tipo *fail2ban*) y lo comprobado
    después cayó en el vacío.

    Args:
        discover: El barrido del descubrimiento, ``(target, ports) -> PortSweep
            | None``, con su presupuesto y su cancelación.
        target: El objetivo.
        services: Los servicios descubiertos.
        sample_size: Cuántos puertos se vuelven a probar; 0 desactiva la
            comprobación.

    Returns:
        bool: ``False`` si ninguno respondió o el barrido volvió bloqueado.
            ``True`` si alguno respondió, si no había puertos TCP que probar,
            si la comprobación está desactivada o si el reloj se agotó antes de
            poder mirar: sin evidencia no se declara un bloqueo.
    """
    ports = [service.port for service in services
             if service.port and service.protocol != "udp"][:sample_size]
    if not ports:
        return True
    sweep = discover(target, ports)
    if sweep is None:
        return False
    if sweep.was_truncated and not sweep.open_ports:
        return True
    return bool(sweep.open_ports)


def crawl_findings(service: Service, result) -> list:
    """
    Convierte lo que halló el rastreo en hallazgos informativos.

    Son eventos de superficie, no riesgos: ``robots.txt`` con sus entradas, los
    formularios de login y las rutas tras autenticación básica.

    Args:
        service: El servicio HTTP rastreado.
        result: El ``CrawlResult`` del rastreo.

    Returns:
        list: Un hallazgo por superficie hallada; vacía si no hubo ninguna.
    """
    findings = []
    if result.robots_entries:
        sample = ", ".join(result.robots_entries[:15])
        findings.append(_crawl_finding(
            service, "web_finding", "lybra:robots-txt-entries@1",
            f"robots.txt declara {len(result.robots_entries)} ruta(s) que pide no indexar: {sample}"))
    for path in result.login_paths:
        findings.append(_crawl_finding(
            service, "web_finding", "lybra:login-form-detected@1",
            f"Formulario de acceso detectado en {path}"))
    for path in result.basic_auth_paths:
        findings.append(_crawl_finding(
            service, "exposed_path", "lybra:http-basic-auth-path@1",
            f"Ruta protegida con autenticación básica: {path}"))
    return findings


def _crawl_finding(service: Service, category: str, check_id: str, title: str) -> dict:
    """Construye un hallazgo informativo del rastreo, sin severidad propia (parte de INFO)."""
    return {
        "title":        title,
        "category":     category,
        "port":         service.port,
        "service":      service.name or "http",
        "protocol":     service.protocol,
        "source":       "lybra",
        "check_id":     check_id,
        "feed_version": "lybra-crawler-1",
        "qod":          QOD_OPEN_PORT,
        "confirmed":    False,
        "state":        "open",
    }


def scan_integrity_finding(title: str) -> dict:
    """
    Construye un aviso sobre la integridad del propio escaneo.

    Categoría ``scan_integrity``: no habla de un riesgo del objetivo sino de
    que el resultado está incompleto, así que el ciclo de vida lo trata como
    evento y la puntuación lo deja en INFO.

    Args:
        title: Qué le pasó al escaneo.

    Returns:
        dict: El hallazgo.
    """
    return {
        "title":        title,
        "category":     "scan_integrity",
        "port":         None,
        "service":      None,
        "protocol":     "tcp",
        "source":       "lybra",
        "check_id":     "lybra:scan-integrity@1",
        "feed_version": "lybra-integrity-1",
        "qod":          QOD_OPEN_PORT,
        "confirmed":    False,
        "state":        "open",
    }


def _derived_api_checks(target: str, service: Service, fetch: Callable, limiter: HostRateLimiter,
                        max_endpoints: int,
                        cancel_check: Optional[Callable[[], bool]] = None) -> list:
    """
    Deriva los checks de la primera especificación de API parseable de un servicio.

    Args:
        target: El objetivo.
        service: El servicio web.
        fetch: La función que hace las peticiones.
        limiter: El limitador de ritmo del host.
        max_endpoints: El tope de checks derivados.
        cancel_check: Dice si hay que parar; no se pide ninguna ruta más. Por
            defecto ``None``.

    Returns:
        list: Los checks; vacía si el servicio no publica especificación o si
            se canceló antes de dar con ella.
    """
    for path in SPECIFICATION_PATHS:
        if cancel_check is not None and cancel_check():
            return []
        limiter.acquire(target)
        response = fetch(target, service.port, "GET", path)
        if response is None or response.status != 200:
            continue
        specification = parse_specification(response.body)
        if specification is not None:
            return derive_api_checks(specification, max_endpoints)
    return []


# ============================================================ sitios con nombre


def discover_sites(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        address: str, services: list, limit: int, tls_fetch: Callable,
        reverse_lookup: Optional[Callable[[str], Optional[str]]] = None,
        resolve: Optional[Callable[[str], set]] = None,
        extra_candidates: Sequence[Tuple[str, str]] = (),
        cancel_check: Optional[Callable[[], bool]] = None) -> List[Tuple[str, str]]:
    """
    Busca los sitios con nombre que sirve ``address``, con el origen de cada nombre.

    Los candidatos salen, por este orden, de los certificados de cada servicio
    TLS (el SAN y el CN; el FTP en claro, tras ``AUTH TLS``), del DNS inverso de
    la IP y de ``extra_candidates``. Pasan sólo los que resuelven de vuelta a
    ``address``.

    Args:
        address: La IP escaneada.
        services: Los servicios del escaneo.
        limit: Máximo de sitios; a cero no se hace ninguna consulta.
        tls_fetch: ``(host, port, starttls=None) -> TlsInfo | None``.
        reverse_lookup: ``ip -> nombre | None``. Por defecto, el PTR del sistema.
        resolve: ``nombre -> set de IPs``. Por defecto, el resolutor del sistema.
        extra_candidates: Pares ``(nombre, origen)`` que no delata la IP y que
            quien llama ya decidió que se pueden auditar. Por defecto, ninguno.
        cancel_check: Dice si hay que parar; se consulta antes de cada
            servicio. Por defecto ``None``.

    Returns:
        list: Pares ``(nombre, origen)``; vacía si no hay ninguno o si se
            canceló a medias (con candidatos a medias no se decide nada).
    """
    if limit <= 0:
        return []
    reverse_lookup = reverse_lookup or _reverse_name
    resolve = resolve or _addresses_of
    candidates: List[Tuple[str, str]] = []
    for service in services:
        if cancel_check is not None and cancel_check():
            return []
        is_ftp = is_ftp_service(service) and not is_tls_service(service) and service.port != 990
        if not (is_ftp or is_tls_service(service) or (is_http_service(service) and service.port == 443)):
            continue
        info = tls_fetch(address, service.port, starttls="ftp") if is_ftp else tls_fetch(address, service.port)
        for name in getattr(info, "names", None) or ():
            candidates.append((name, f"certificado TLS de {service.port}/tcp"))
    ptr = reverse_lookup(address)
    if ptr:
        candidates.append((ptr, "DNS inverso de la IP"))
    candidates.extend(extra_candidates)
    return select_site_names(candidates, lambda name: address in resolve(name), limit)


def _reverse_name(address: str) -> Optional[str]:
    """Devuelve el nombre del registro PTR de ``address``, o ``None`` si no tiene."""
    try:
        return socket.gethostbyaddr(address)[0]
    except OSError:
        return None


def _addresses_of(name: str) -> set:
    """Devuelve las IPs a las que resuelve ``name``; vacío si no resuelve."""
    try:
        return {info[4][0] for info in socket.getaddrinfo(name, None)}
    except OSError:
        return set()


def view_site(host: str, web_services: list,
              cancel_check: Optional[Callable[[], bool]] = None) -> dict:
    """
    Resume lo que ``host`` sirve en cada puerto web, para compararlo con otro sitio.

    Una petición ``GET /`` y un saludo TLS por puerto. Se llama con la IP (el
    sitio por defecto) o con un nombre ya fijado a esa IP.

    Args:
        host: La IP o el nombre del sitio.
        web_services: Los servicios HTTP y TLS del escaneo.
        cancel_check: Dice si hay que parar; se consulta antes de cada puerto
            y deja la vista incompleta, así que quien llama debe volver a
            consultarla antes de fiarse de ella. Por defecto ``None``.

    Returns:
        dict: ``puerto -> (estado HTTP, SHA-256 del cuerpo, identidad del
            certificado)``, con ``None`` en lo que no respondió.
    """
    http_probe = HttpProbe()
    tls_probe = TlsProbe()
    views = {}
    for service in web_services:
        if cancel_check is not None and cancel_check():
            break
        response = http_probe.fetch(host, service.port, "GET", "/")
        certificate = tls_probe.fetch(host, service.port) if is_tls_service(service) else None
        views[service.port] = (
            response.status if response else None,
            hashlib.sha256(response.body.encode("utf-8", "ignore")).hexdigest() if response else None,
            (certificate.subject_cn, certificate.issuer_cn, tuple(certificate.names)) if certificate else None,
        )
    return views


def audit_named_sites(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        address: str, services: list, cancel_check: Callable[[], bool], run_checks: Callable,
        view_site_fn: Optional[Callable] = None, extra_candidates: Sequence[Tuple[str, str]] = (),
        max_sites: int = 10, discover: Optional[Callable] = None) -> list:
    """
    Descubre los sitios con nombre de una IP y repite sobre cada uno los checks web.

    Sólo se repiten los checks de los servicios HTTP y TLS, los únicos cuya
    respuesta depende del nombre pedido; aun así, los que describen la máquina
    y no el sitio (las marcas de tiempo TCP) se descartan con
    :func:`depends_on_site`. Cada sitio se audita con la resolución fijada a
    ``address``, así que ninguna conexión sale de la IP autorizada.

    Un nombre que sirve exactamente lo mismo que la IP sin nombre (el DNS
    inverso típico de un hosting) no se audita: se lista diciendo que sirve el
    sitio por defecto.

    Args:
        address: La IP escaneada.
        services: Los servicios del escaneo.
        cancel_check: Devuelve ``True`` si hay que dejar de trabajar.
        run_checks: ``(nombre, servicios) -> hallazgos``; el runtime de checks
            ya configurado con el modo y las CVE propuestas.
        view_site_fn: ``(host, servicios_web) -> {puerto: vista}``. Por
            defecto, :func:`view_site` con las sondas reales.
        extra_candidates: Nombres que la IP no delata y que quien llama
            autorizó. Por defecto, ninguno.
        max_sites: Máximo de sitios. Por defecto 10.
        discover: Sustituto de :func:`discover_sites`, con su misma firma. Por
            defecto ``None``.

    Returns:
        list: Un aviso ``virtual_host`` por sitio y los hallazgos de cada uno,
            con su ``vhost``; vacía si la IP no delata ningún nombre.
    """
    discover = discover or partial(discover_sites, cancel_check=cancel_check)
    sites = discover(address, services, max_sites, TlsProbe().fetch, extra_candidates=extra_candidates)
    web_services = [service for service in services if is_http_service(service) or is_tls_service(service)]
    view_site_fn = view_site_fn or partial(view_site, cancel_check=cancel_check)
    default_views = view_site_fn(address, web_services) if sites and web_services else {}
    findings = []
    for name, origin in sites:
        if cancel_check() or not web_services:
            findings.append(site_finding(name, origin))
            continue
        with pinned_resolution(name, address):
            site_views = view_site_fn(name, web_services)
            if cancel_check():
                # Una vista cortada por la cancelación no se puede comparar.
                findings.append(site_finding(name, origin))
                continue
            if is_alias_of_default_site(default_views, site_views):
                findings.append(site_finding(name, origin, serves_default_site=True))
                continue
            findings.append(site_finding(name, origin))
            for finding in run_checks(name, web_services):
                if not depends_on_site(finding):
                    continue
                finding["vhost"] = name
                findings.append(finding)
    return findings
