"""Cliente del motor de escaneo Lybra (``lybrad``), por su socket Unix.

Habla el protocolo de ``docs/protocolo.md``: un objeto JSON por línea, una
respuesta final por petición y, en ``scan.watch``, eventos de progreso antes de
ella. Sólo usa la biblioteca estándar.

Abre una conexión por petición: en un socket local no cuesta nada medible y
evita compartir una conexión entre hilos.

Ejemplo::

    from lybra_client import LybraClient

    client = LybraClient()                       # LYBRA_SOCKET o /run/lybra/lybra.sock
    scan_id = client.scan_start("198.51.100.10", profile="fast")
    client.scan_watch(scan_id, on_progress=print)
    result = client.scan_result(scan_id)
    for finding in result["findings"]:
        print(finding["title"])
"""

from __future__ import annotations

import itertools
import json
import os
import socket
import threading
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

#: Versión mayor del protocolo que habla este cliente.
PROTOCOL_VERSION = 1

#: Ruta por defecto del socket de ``lybrad``.
DEFAULT_SOCKET = "/run/lybra/lybra.sock"

#: Tamaño máximo de una línea del protocolo, en bytes.
MAX_LINE_BYTES = 16 * 1024 * 1024

#: Plazo por defecto (segundos) que el motor da a ``osint.*`` y ``cloud.probe``;
#: el cliente espera ese plazo más un margen antes de rendirse.
_PASSIVE_BUDGET_SECONDS = 120
_PASSIVE_MARGIN_SECONDS = 15

#: Lo que se pasa como ``timeout`` para usar el del cliente.
_DEFAULT = object()

ProgressCallback = Callable[[Dict[str, Any]], None]


class LybraError(Exception):
    """El motor contestó con un error.

    Attributes:
        code: El código del protocolo: ``bad_request``, ``unsupported_version``,
            ``unknown_op``, ``invalid_params``, ``invalid_target``,
            ``target_not_allowed``, ``not_found``, ``busy`` o ``internal``; y,
            para un escaneo fallido, ``host_unreachable`` o
            ``port_discovery_failed``.
        message: La explicación del motor.
    """

    def __init__(self, code: str, message: str) -> None:
        """
        Crea el error.

        Args:
            code: El código del protocolo.
            message: La explicación del motor.
        """
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class LybraConnectionError(ConnectionError):
    """No se pudo hablar con ``lybrad``: el socket no existe, no hay permiso o se cortó la conexión."""


class LybraClient:
    """Habla con ``lybrad`` por su socket Unix.

    Todos los métodos devuelven el ``result`` del protocolo tal cual, como
    diccionarios con claves en camelCase.

    Attributes:
        socket_path: La ruta del socket.
        timeout: Segundos de espera de cada respuesta; ``None`` espera sin límite.
    """

    def __init__(self, socket_path: Optional[str] = None, timeout: Optional[float] = 60.0) -> None:
        """
        Prepara el cliente; no conecta hasta la primera petición.

        Args:
            socket_path: La ruta del socket; ``None`` usa la variable
                ``LYBRA_SOCKET`` o, si no está, :data:`DEFAULT_SOCKET`.
            timeout: Segundos de espera de cada respuesta. Por defecto 60.
                :meth:`scan_watch` espera siempre sin límite.
        """
        self.socket_path = socket_path or os.environ.get("LYBRA_SOCKET") or DEFAULT_SOCKET
        self.timeout = timeout
        self._ids = itertools.count(1)
        self._ids_lock = threading.Lock()

    # ------------------------------------------------------------ transporte

    def call(self, op: str, params: Optional[Dict[str, Any]] = None,
             on_event: Optional[Callable[[str, Any], None]] = None, timeout: Any = _DEFAULT) -> Any:
        """
        Envía una petición y espera su respuesta final.

        Args:
            op: La operación (``scan.start``, ``kb.cve``…).
            params: Sus parámetros. Por defecto, ninguno.
            on_event: Recibe ``(nombre, datos)`` por cada evento intermedio.
                Por defecto ``None``.
            timeout: Segundos de espera; ``None`` sin límite. Por defecto, el
                del cliente.

        Returns:
            El ``result`` de la respuesta.

        Raises:
            LybraError: Si el motor contesta con un error.
            LybraConnectionError: Si no se puede hablar con el socket, o la
                respuesta no llega o no se entiende.
        """
        with self._ids_lock:
            request_id = f"c-{os.getpid()}-{next(self._ids)}"
        message = {"v": PROTOCOL_VERSION, "id": request_id, "op": op, "params": params or {}}
        line = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout if timeout is _DEFAULT else timeout)
                connection.connect(self.socket_path)
                connection.sendall(line)
                return _read_reply(connection.makefile("rb"), request_id, on_event)
        except LybraConnectionError:
            raise
        except (OSError, ValueError) as error:
            raise LybraConnectionError(f"no se pudo hablar con lybrad en {self.socket_path}: {error}") from error

    # ------------------------------------------------------------ servicio

    def info(self) -> Dict[str, Any]:
        """
        Pide la versión del motor y el estado de su base de conocimiento (``engine.info``).

        Returns:
            dict: ``engineVersion``, ``protocolVersions``, ``identificationRevision`` y ``kb``.
        """
        return self.call("engine.info")

    # ------------------------------------------------------------ escaneos

    def scan_start(  # pylint: disable=too-many-arguments
            self, target: str, *, profile: Optional[str] = None, ports: Optional[Sequence[int]] = None,
            timeout_seconds: Optional[float] = None, fingerprint: Optional[bool] = None,
            crawl: Optional[bool] = None, active_checks: Optional[bool] = None,
            aggressive: Optional[bool] = None, known_services: Optional[Iterable[Dict[str, Any]]] = None,
            site_candidates: Optional[Iterable[Dict[str, str]]] = None,
            enrich: Optional[bool] = None) -> str:
        """
        Encola un escaneo de red (``scan.start``).

        Los parámetros que se dejan en ``None`` no se envían y el motor usa su
        valor por defecto.

        Args:
            target: Un host: IP o nombre.
            profile: ``"fast"``, ``"standard"`` o ``"thorough"``.
            ports: Puertos TCP concretos, que sustituyen a los del perfil.
            timeout_seconds: Presupuesto de reloj del escaneo entero.
            fingerprint: Identificar cada servicio sondeándolo.
            crawl: Rastrear los servicios web.
            active_checks: Checks activos, superficie de API y sitios con nombre.
            aggressive: Permitir checks que escriben en el objetivo y las
                credenciales por defecto.
            known_services: Lo que se sabe del objetivo por escaneos
                anteriores (``Service`` más ``identifiedAt`` e ``identifiedBy``).
            site_candidates: Sitios con nombre autorizados, ``{name, origin}``.
            enrich: Preguntar a Shodan y Censys (si el motor tiene sus claves)
                por la IP del objetivo y añadir los CPE que sugieren para los
                puertos que el motor no identificó. Revela el objetivo a un
                tercero: sólo con permiso de quien lo posee. Por defecto, no.

        Returns:
            str: El identificador del escaneo.

        Raises:
            LybraError: ``invalid_target``, ``target_not_allowed``,
                ``invalid_params`` o ``busy``, entre otros.
        """
        params: Dict[str, Any] = {"target": target}
        for key, value in (("profile", profile), ("ports", list(ports) if ports is not None else None),
                           ("timeoutSeconds", timeout_seconds), ("fingerprint", fingerprint),
                           ("crawl", crawl), ("activeChecks", active_checks), ("aggressive", aggressive),
                           ("knownServices", list(known_services) if known_services is not None else None),
                           ("siteCandidates", list(site_candidates) if site_candidates is not None else None),
                           ("enrich", enrich)):
            if value is not None:
                params[key] = value
        return self.call("scan.start", params)["scanId"]

    def scan_status(self, scan_id: str) -> Dict[str, Any]:
        """
        Pide el estado y el avance de un escaneo (``scan.status``).

        Args:
            scan_id: El escaneo.

        Returns:
            dict: ``scanId``, ``target``, ``status``, ``progress`` y, si falló, ``error``.
        """
        return self.call("scan.status", {"scanId": scan_id})

    def scan_watch(self, scan_id: str, on_progress: Optional[ProgressCallback] = None) -> Dict[str, Any]:
        """
        Espera, sin límite de tiempo, a que un escaneo termine (``scan.watch``).

        Args:
            scan_id: El escaneo.
            on_progress: Recibe cada evento de progreso (``status``, ``phase``,
                ``done``, ``total``). Por defecto ``None``.

        Returns:
            dict: El estado final, como :meth:`scan_status`.
        """
        return self.call("scan.watch", {"scanId": scan_id},
                         on_event=(lambda _name, data: on_progress(data)) if on_progress else None,
                         timeout=None)

    def scan_result(self, scan_id: str) -> Dict[str, Any]:
        """
        Pide el resultado de un escaneo terminado (``scan.result``).

        Args:
            scan_id: El escaneo.

        Returns:
            dict: El ``ScanResult``: ``services``, ``findings``, ``refutations``,
                ``probedServices``, ``identificationRevision``, ``status``…

        Raises:
            LybraError: ``not_found`` si aún no terminó o no existe; el código
                del fallo (``host_unreachable``…) si falló.
        """
        return self.call("scan.result", {"scanId": scan_id})

    def scan_cancel(self, scan_id: str) -> Dict[str, Any]:
        """
        Cancela un escaneo en cola o en curso (``scan.cancel``).

        Args:
            scan_id: El escaneo.

        Returns:
            dict: Su estado tras pedir la cancelación.
        """
        return self.call("scan.cancel", {"scanId": scan_id})

    def scan(self, target: str, on_progress: Optional[ProgressCallback] = None, **options: Any) -> Dict[str, Any]:
        """
        Escanea un objetivo y espera su resultado: encola, sigue y recoge.

        Args:
            target: Un host: IP o nombre.
            on_progress: Recibe cada evento de progreso. Por defecto ``None``.
            **options: Los mismos argumentos con nombre que :meth:`scan_start`.

        Returns:
            dict: El ``ScanResult``.

        Raises:
            LybraError: Si no se pudo encolar o el escaneo falló.
        """
        scan_id = self.scan_start(target, **options)
        self.scan_watch(scan_id, on_progress=on_progress)
        return self.scan_result(scan_id)

    # ------------------------------------------------------------ análisis sin red

    def analyze(self, services: Iterable[Dict[str, Any]], *, enrich: Optional[bool] = None,
                target: Optional[str] = None) -> Dict[str, Any]:
        """
        Analiza servicios ya conocidos sin tocar la red (``analyze``).

        Args:
            services: Los servicios, con ``product`` o ``cpe`` y ``version``
                (y ``origin: "inventory"`` si se leyeron del propio equipo).
            enrich: Preguntar además a las fuentes de terceros por la IP de
                ``target`` (ver :meth:`scan_start`). Por defecto, no.
            target: La IP a la que pertenecen los servicios; obligatoria con ``enrich``.

        Returns:
            dict: ``findings`` y ``kbFeedVersion``.
        """
        params: Dict[str, Any] = {"services": list(services)}
        if enrich is not None:
            params["enrich"] = enrich
        if target is not None:
            params["target"] = target
        return self.call("analyze", params)

    # ------------------------------------------------------------ inteligencia pasiva y cloud

    def osint_domain(self, domain: str, *, sources: Optional[Iterable[str]] = None,
                     dkim_selectors: Optional[Iterable[str]] = None,
                     timeout_seconds: Optional[float] = None) -> Dict[str, Any]:
        """
        Reúne lo que fuentes de terceros y el DNS público dicen de un dominio (``osint.domain``).

        Es síncrona: espera hasta ``timeout_seconds`` (120 por defecto) más un margen.

        Args:
            domain: El dominio.
            sources: Limita la consulta a estas fuentes (``crtsh``, ``shodan``,
                ``censys``, ``securitytrails``). Por defecto, las que el motor
                tiene encendidas y con clave.
            dkim_selectors: Selectores DKIM que comprobar (hasta 10). Por defecto, ninguno.
            timeout_seconds: Plazo del motor para toda la consulta.

        Returns:
            dict: ``domain``, ``sources`` (qué pasó con cada fuente), ``dnsChecks``,
                ``subdomains``, ``observations`` y ``findings``.
        """
        params: Dict[str, Any] = {"domain": domain}
        for key, value in (("sources", sources), ("dkimSelectors", dkim_selectors)):
            if value is not None:
                params[key] = list(value)
        return self._passive_call("osint.domain", params, timeout_seconds)

    def osint_hostnames(self, address: str, *, timeout_seconds: Optional[float] = None) -> List[str]:
        """
        Pide los nombres que Shodan y Censys asocian a una IP (``osint.hostnames``).

        Args:
            address: La IP; una privada no se consulta.
            timeout_seconds: Plazo del motor para toda la consulta.

        Returns:
            list: Los nombres, sin validar; vacía si ninguna fuente está disponible.
        """
        return self._passive_call("osint.hostnames", {"address": address}, timeout_seconds)["names"]

    def cloud_probe(self, resources: Optional[Iterable[str]] = None, subdomains: Optional[Iterable[str]] = None,
                    *, timeout_seconds: Optional[float] = None) -> Dict[str, Any]:
        """
        Comprueba recursos cloud y subdominios susceptibles de takeover (``cloud.probe``).

        Toca a terceros: sólo con recursos y dominios que quien llama tiene
        derecho a comprobar.

        Args:
            resources: Recursos ``proveedor:identificador`` (``s3:nombre``,
                ``gcs:nombre``, ``azure:cuenta/contenedor``, ``firebase:proyecto``;
                hasta 25).
            subdomains: Subdominios que comprobar (hasta 500).
            timeout_seconds: Plazo del motor para toda la comprobación.

        Returns:
            dict: ``resources`` (los canónicos), ``subdomains`` (``{name}``) y ``findings``.
        """
        params: Dict[str, Any] = {}
        for key, value in (("resources", resources), ("subdomains", subdomains)):
            if value is not None:
                params[key] = list(value)
        return self._passive_call("cloud.probe", params, timeout_seconds)

    def _passive_call(self, op: str, params: Dict[str, Any], timeout_seconds: Optional[float]) -> Any:
        """Llama a una operación síncrona de red, esperando el plazo del motor más un margen."""
        if timeout_seconds is not None:
            params["timeoutSeconds"] = timeout_seconds
        wait = (timeout_seconds or _PASSIVE_BUDGET_SECONDS) + _PASSIVE_MARGIN_SECONDS
        return self.call(op, params, timeout=None if self.timeout is None else max(self.timeout, wait))

    # ------------------------------------------------------------ base de conocimiento

    def kb_cve(self, cve_id: str) -> Dict[str, Any]:
        """
        Pide la ficha de una CVE (``kb.cve``).

        Args:
            cve_id: La CVE.

        Returns:
            dict: Lo que sabe cada fuente de ella, con las listas largas (``products``,
                ``applicability``, ``distroStatuses``) acotadas y sus totales en
                ``productsTotal``, ``applicabilityTotal`` y ``distroStatusesTotal``.

        Raises:
            LybraError: ``not_found`` si ninguna fuente la conoce.
        """
        return self.call("kb.cve", {"cveId": cve_id})

    def kb_version(self, product: str, version: str) -> Dict[str, Any]:
        """
        Pregunta qué CVE afectan a un producto en una versión (``kb.version``).

        Args:
            product: El nombre del producto (``nginx``, ``Apache httpd``).
            version: La versión.

        Returns:
            dict: ``recognized``, el CPE resuelto, ``cves``, ``cvesTotal`` y ``endOfLife``.
        """
        return self.call("kb.version", {"product": product, "version": version})

    def kb_products(self, term: str, limit: int = 20) -> List[Dict[str, str]]:
        """
        Busca productos cuyo nombre empieza por ``term`` (``kb.products``).

        Args:
            term: El principio del nombre.
            limit: Cuántos como mucho (hasta 100). Por defecto 20.

        Returns:
            list: ``{vendor, product, displayName}``.
        """
        return self.call("kb.products", {"term": term, "limit": limit})["products"]

    def kb_resolve(self, names: Iterable[str]) -> List[Dict[str, str]]:
        """
        Traduce nombres de producto libres a pares ``vendor``/``product`` (``kb.resolve``).

        Args:
            names: Los nombres (hasta 1000).

        Returns:
            list: ``{vendor, product}`` de los que resuelven, sin repetir.
        """
        return self.call("kb.resolve", {"names": list(names)})["products"]

    def kb_advisories(self, products: Iterable[Dict[str, str]], since: Optional[str] = None,
                      min_cvss: Optional[float] = None, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Pide las CVE recientes de unos productos (``kb.advisories``).

        Args:
            products: ``{vendor, product}`` (de 1 a 200).
            since: Instante ISO 8601 desde el que contar. Por defecto, todas.
            min_cvss: Suelo de CVSS; las CVE sin puntuar se conservan.
            limit: Cuántas como mucho. Por defecto 20.

        Returns:
            list: Los avisos, del más reciente al más antiguo.
        """
        params: Dict[str, Any] = {"products": list(products), "limit": limit}
        if since is not None:
            params["since"] = since
        if min_cvss is not None:
            params["minCvss"] = min_cvss
        return self.call("kb.advisories", params)["advisories"]

    def kb_unresolved(self, origin: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Pide los nombres de producto que más veces quedaron sin resolver (``kb.unresolved``).

        Args:
            origin: ``"network"`` o ``"inventory"``; ``None`` para los dos.
            limit: Cuántos como mucho. Por defecto 50.

        Returns:
            list: ``{name, origin, occurrences, firstSeenAt, lastSeenAt}``.
        """
        params: Dict[str, Any] = {"limit": limit}
        if origin is not None:
            params["origin"] = origin
        return self.call("kb.unresolved", params)["products"]

    def kb_status(self) -> Dict[str, Any]:
        """
        Pide el estado de cada fuente de la base de conocimiento (``kb.status``).

        Returns:
            dict: ``sources``, ``isStale``, ``isUnverified`` y ``feedVersion``.
        """
        return self.call("kb.status")

    def kb_sync(self, source: str = "all") -> Dict[str, Any]:
        """
        Lanza una sincronización de la base en segundo plano (``kb.sync``).

        Args:
            source: ``"all"``, ``"nvd"``, ``"kev"``, ``"epss"`` u ``"oval"``. Por defecto ``"all"``.

        Returns:
            dict: ``{"started": true, "source"}``.

        Raises:
            LybraError: ``busy`` si ya hay una en curso.
        """
        return self.call("kb.sync", {"source": source})

    def kb_backfill(self, since: Optional[str] = None, until: Optional[str] = None,
                    on_progress: Optional[Callable[[Dict[str, Any]], None]] = None) -> Dict[str, Any]:
        """
        Realiza un llenado histórico completo de NVD (``kb.backfill``).

        Args:
            since: Desde cuándo (YYYY-MM-DD).
            until: Hasta cuándo (YYYY-MM-DD).
            on_progress: Recibe cada evento de progreso.

        Returns:
            dict: Resumen del backfill.
        """
        params: Dict[str, Any] = {}
        if since is not None:
            params["since"] = since
        if until is not None:
            params["until"] = until
        handler = (lambda event, data: on_progress(data) if event == "progress" else None) if on_progress else None
        return self.call("kb.backfill", params, on_event=handler, timeout=None)


def _read_reply(reader, request_id: str, on_event: Optional[Callable[[str, Any], None]]) -> Any:
    """
    Lee eventos hasta la respuesta final de ``request_id`` y la devuelve o lanza su error.

    Args:
        reader: El fichero binario de la conexión.
        request_id: El ``id`` de la petición enviada.
        on_event: Recibe ``(nombre, datos)`` por cada evento, o ``None``.

    Returns:
        El ``result`` de la respuesta final.

    Raises:
        LybraError: Si la respuesta final es un error.
        LybraConnectionError: Si la conexión se cierra antes de la respuesta.
        ValueError: Si una línea no es JSON.
    """
    while True:
        raw = reader.readline(MAX_LINE_BYTES + 1)
        if not raw:
            raise LybraConnectionError("lybrad cerró la conexión sin responder")
        reply = json.loads(raw)
        if "event" in reply:
            if on_event is not None and reply.get("id") == request_id:
                on_event(reply["event"], reply.get("data"))
            continue
        if reply.get("ok"):
            return reply.get("result")
        error = reply.get("error") or {}
        raise LybraError(error.get("code", "internal"), error.get("message", ""))
