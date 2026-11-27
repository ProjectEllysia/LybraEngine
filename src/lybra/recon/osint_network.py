"""La costura de red de la inteligencia pasiva y de la exposición cloud.

``osint``, ``dns_hygiene`` y ``cloud`` deciden qué es un hallazgo sin tocar la
red: reciben el *fetcher* de las fuentes, la búsqueda DNS y la petición HTTP ya
hechos. Aquí están los de verdad: las peticiones a crt.sh, Shodan, Censys y
SecurityTrails con sus claves, la caché en la base de conocimiento, las
consultas DNS con ``dnspython`` y el ``GET`` de las sondas cloud. El servicio
los construye por operación (``EngineService``) y los tests los sustituyen por
un :class:`PassiveNetwork` con dobles.

**Nada de esto contacta con el objetivo.** Las fuentes son servicios de
terceros y el DNS se pregunta al resolutor del sistema, que es lo que haría
cualquiera que busque el dominio. Las claves de las fuentes salen de la
configuración del servicio, nunca de una petición.
"""

from __future__ import annotations

import base64
import json
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

import dns.exception
import dns.resolver

from ..core._shared import utcnow_naive
from ..checks.framework import HttpProbe, Response
from ..core.vulndata import fetch_document
from ..kb.store import KnowledgeBase
from .osint import (FetchedDocument, OsintSource, SourceSetting, collect_host_observations,
                    suggest_cpe_findings)

#: URL base de cada fuente.
SOURCE_URLS = {
    OsintSource.CERTIFICATE_TRANSPARENCY: "https://crt.sh",
    OsintSource.SHODAN: "https://api.shodan.io",
    OsintSource.CENSYS: "https://search.censys.io/api/v2",
    OsintSource.SECURITYTRAILS: "https://api.securitytrails.com/v1",
}


@dataclass(frozen=True)
class OsintSettings:  # pylint: disable=too-many-instance-attributes
    """Los ajustes de la inteligencia pasiva.

    Attributes:
        ttl_hours: Horas que vale en caché la respuesta de una fuente. Por
            defecto 24: los datos de terceros cambian despacio y cada consulta a
            una fuente de pago gasta cuota.
        request_timeout_seconds: Tope de cada petición a una fuente, de cada
            consulta DNS y de cada petición de una sonda cloud. Por defecto 30.
        recent_certificate_days: Cuántos días atrás cuenta un certificado como
            «emitido recientemente». Por defecto 30.
        max_subdomains: Tope de hallazgos de subdominio por consulta; la lista
            completa de subdominios se devuelve igualmente. Por defecto 500.
        max_host_lookups: Cuántos nombres del dominio, como mucho, se resuelven
            para preguntar a Shodan y Censys por sus direcciones. Por defecto 10.
        enabled_sources: Valores de :class:`OsintSource` que el operador deja
            consultar. Por defecto, todas; una fuente con clave y sin apagar es
            una fuente que el operador quiere.
        api_keys: Clave de cada fuente que la necesita, por valor de
            :class:`OsintSource` (Censys, con la forma ``<API ID>:<secreto>``).
            Una fuente sin clave se omite. Nunca sale en ``repr``.
    """

    ttl_hours: int = 24
    request_timeout_seconds: int = 30
    recent_certificate_days: int = 30
    max_subdomains: int = 500
    max_host_lookups: int = 10
    enabled_sources: Tuple[str, ...] = tuple(source.value for source in OsintSource)
    api_keys: Mapping[str, str] = field(default_factory=dict, repr=False)


class Deadline:
    """Un plazo de reloj compartido por todas las peticiones de una operación.

    Attributes:
        expires_at: El instante (``time.monotonic``) en que vence.
    """

    def __init__(self, budget_seconds: float) -> None:
        """
        Arranca el plazo.

        Args:
            budget_seconds: Segundos que dura desde ahora.
        """
        self.expires_at = time.monotonic() + budget_seconds

    @property
    def is_expired(self) -> bool:
        """Si el plazo ya venció."""
        return time.monotonic() >= self.expires_at


@dataclass(frozen=True)
class PassiveNetwork:
    """Lo que toca la red en las operaciones pasivas y cloud, sustituible en los tests.

    Attributes:
        download: ``(fuente, consulta) -> JSON | None``: descarga y decodifica
            la respuesta de una fuente, sin caché; ``None`` si la fuente
            contesta 404; lanza ante cualquier otro fallo.
        lookup_records: ``(nombre, tipo) -> valores | None``: la búsqueda DNS de
            :data:`lybra.recon.osint.RecordLookup`.
        resolve_cname: ``nombre -> destino del CNAME | None``.
        http_get: ``(host, puerto, ruta) -> Response | None``: un ``GET`` por
            HTTPS (puerto 443) o HTTP (puerto 80).
    """

    download: Callable[[OsintSource, str], Any]
    lookup_records: Callable[[str, str], Optional[List[str]]]
    resolve_cname: Callable[[str], Optional[str]]
    http_get: Callable[[str, int, str], Optional[Response]]


def real_network(settings: OsintSettings) -> PassiveNetwork:
    """
    Construye la red de verdad: HTTP, ``dnspython`` y la clave de cada fuente.

    Args:
        settings: Los ajustes (claves, plazos de cada petición).

    Returns:
        PassiveNetwork: La red real.
    """
    timeout = settings.request_timeout_seconds
    probe = HttpProbe(timeout=timeout)
    return PassiveNetwork(
        download=lambda source, query: _download_from_source(settings, source, query),
        lookup_records=lambda name, record_type: _lookup_dns_records(name, record_type, timeout),
        resolve_cname=lambda name: _resolve_cname(name, timeout),
        http_get=lambda host, port, path: probe.fetch(host, port, "GET", path),
    )


def source_request(source: OsintSource, query: str, api_key: str) -> Tuple[str, Dict[str, str]]:
    """
    La URL y las cabeceras de la petición a una fuente para una consulta.

    Args:
        source: La fuente.
        query: El dominio (crt.sh, SecurityTrails) o la dirección IP (Shodan, Censys).
        api_key: Su clave de API; vacía para crt.sh.

    Returns:
        Tuple[str, Dict[str, str]]: ``(url, cabeceras)``. La clave de Shodan va
            en la URL porque su API no la acepta de otra forma; por eso ningún
            error de este módulo se registra con su texto.
    """
    base_url = SOURCE_URLS[source]
    quoted = urllib.parse.quote(query, safe="")
    if source is OsintSource.CERTIFICATE_TRANSPARENCY:
        return f"{base_url}/?q={urllib.parse.quote('%.' + query, safe='')}&output=json", {}
    if source is OsintSource.SHODAN:
        return f"{base_url}/shodan/host/{quoted}?key={urllib.parse.quote(api_key, safe='')}", {}
    if source is OsintSource.CENSYS:
        token = base64.b64encode(api_key.encode("utf-8")).decode("ascii")
        return f"{base_url}/hosts/{quoted}", {"Authorization": f"Basic {token}", "Accept": "application/json"}
    return f"{base_url}/domain/{quoted}/subdomains?children_only=false", {"APIKEY": api_key,
                                                                         "Accept": "application/json"}


def _download_from_source(settings: OsintSettings, source: OsintSource, query: str) -> Any:
    """
    Descarga y decodifica la respuesta de una fuente, sin caché.

    Args:
        settings: Los ajustes (clave y plazo de la fuente).
        source: La fuente.
        query: Lo consultado.

    Returns:
        Any: El JSON decodificado, o ``None`` cuando la fuente responde 404
            (Shodan y Censys lo hacen con una dirección que nunca vieron): es una
            respuesta, no un fallo.

    Raises:
        Exception: Cualquier otro error de red o de formato; quien llama lo
            cuenta como fuente caída.
    """
    url, headers = source_request(source, query, settings.api_keys.get(source.value, ""))
    try:
        body = fetch_document(url, timeout=settings.request_timeout_seconds, headers=headers)
    except Exception as error:
        if getattr(getattr(error, "response", None), "status_code", None) == 404:
            return None
        raise
    return json.loads(body) if body.strip() else None


def _lookup_dns_records(name: str, record_type: str, timeout: float) -> Optional[List[str]]:
    """
    Consulta el DNS con ``dnspython``.

    Args:
        name: El nombre consultado.
        record_type: El tipo (``"A"``, ``"TXT"``, ``"MX"``, ``"CAA"``, ``"SOA"``, ``"DS"``…).
        timeout: Segundos que se espera la respuesta.

    Returns:
        Optional[List[str]]: Los valores en texto (un TXT con sus trozos unidos,
            como lo lee un receptor); lista vacía si el nombre no existe o no
            tiene registros de ese tipo; ``None`` si el DNS no dio una respuesta
            definitiva (tiempo agotado, servidores que fallan): eso no prueba
            que el registro no exista.
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = float(timeout)
    try:
        answer = resolver.resolve(name, record_type, raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN:
        return []
    except dns.exception.DNSException:
        return None
    if answer.rrset is None:
        return []
    return [b"".join(rdata.strings).decode("utf-8", "replace") if record_type == "TXT" else rdata.to_text()
            for rdata in answer.rrset]


def _resolve_cname(name: str, timeout: float) -> Optional[str]:
    """
    El destino al que apunta un nombre por CNAME, según el DNS.

    Args:
        name: El nombre consultado.
        timeout: Segundos que se espera la respuesta.

    Returns:
        Optional[str]: El destino del primer CNAME; ``None`` si el nombre no es
            un CNAME, no existe o el DNS no dio una respuesta definitiva. En los
            tres casos no hay nada que comprobar.
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = float(timeout)
    try:
        answer = resolver.resolve(name, "CNAME", raise_on_no_answer=False)
    except dns.exception.DNSException:
        return None
    return next((rdata.to_text() for rdata in answer.rrset), None) if answer.rrset is not None else None


def source_settings(settings: OsintSettings,
                    only: Optional[List[str]] = None) -> Dict[OsintSource, SourceSetting]:
    """
    Qué fuentes están encendidas y con clave en este despliegue.

    Args:
        settings: Los ajustes del servicio.
        only: Valores de :class:`OsintSource` a los que se limita la consulta; las
            demás cuentan como apagadas. Por defecto ``None``: las que el
            operador deja consultar.

    Returns:
        Dict[OsintSource, SourceSetting]: Una entrada por fuente.
    """
    return {
        source: SourceSetting(
            is_enabled=source.value in settings.enabled_sources and (only is None or source.value in only),
            has_credentials=bool(settings.api_keys.get(source.value)))
        for source in OsintSource
    }


def build_fetcher(kb: KnowledgeBase, settings: OsintSettings, network: PassiveNetwork,
                  deadline: Deadline) -> Callable[[OsintSource, str], FetchedDocument]:
    """
    El fetcher que recibe la capa pura: descarga con caché y con plazo.

    Una respuesta de la caché sigue vigente mientras no pasen ``ttl_hours`` desde
    su descarga; un fallo de la descarga no se cachea. Con el plazo vencido no
    se descarga nada y la fuente cuenta como caída.

    Args:
        kb: La base de conocimiento, donde vive la caché.
        settings: Los ajustes (TTL).
        network: Quien descarga de verdad.
        deadline: El plazo de la operación.

    Returns:
        Callable: ``(fuente, consulta) -> FetchedDocument``.
    """
    ttl = timedelta(hours=settings.ttl_hours)

    def fetch(source: OsintSource, query: str) -> FetchedDocument:
        """Consulta una fuente pasando por la caché; ``TimeoutError`` si el plazo venció."""
        cached = kb.get_osint_cache(source.value, query)
        if cached is not None and cached[1] + ttl > utcnow_naive():
            return FetchedDocument(payload=cached[0], retrieved_at=cached[1], was_cached=True)
        if deadline.is_expired:
            raise TimeoutError("plazo agotado")
        payload = network.download(source, query)
        fetched_at = utcnow_naive()
        kb.save_osint_cache(source.value, query, payload, fetched_at)
        return FetchedDocument(payload=payload, retrieved_at=fetched_at, was_cached=False)
    return fetch


def build_lookup(network: PassiveNetwork, deadline: Deadline) -> Callable[[str, str], Optional[List[str]]]:
    """
    La búsqueda DNS que recibe la capa pura, con plazo.

    Args:
        network: Quien consulta de verdad.
        deadline: El plazo de la operación; vencido, toda búsqueda devuelve
            ``None`` («sin respuesta definitiva»).

    Returns:
        Callable: ``(nombre, tipo) -> lista | None``.
    """
    return lambda name, record_type: (None if deadline.is_expired
                                      else network.lookup_records(name, record_type))


def build_enrichment_findings(address: str, findings: List[dict],
                              fetch: Callable[[OsintSource, str], FetchedDocument],
                              settings: Mapping[OsintSource, SourceSetting], now: datetime) -> List[dict]:
    """
    CPE sugeridos por fuentes externas para los puertos que el motor no identificó.

    Pregunta a Shodan y Censys por la dirección del objetivo, pasando por la
    caché, y propone un CPE para cada puerto sin resolver en el que la fuente lo
    tenga claro (ver ``suggest_cpe_findings``). Un fallo de las fuentes no
    rompe nada: devuelve lo que haya.

    Args:
        address: La IP del objetivo; una privada no se consulta.
        findings: Los hallazgos que el motor ya produjo para el objetivo.
        fetch: El fetcher de :func:`build_fetcher`.
        settings: Qué fuentes están encendidas y con clave.
        now: El instante de referencia (UTC sin zona).

    Returns:
        List[dict]: Hallazgos ``passive_exposure`` con su procedencia; lista
            vacía si no hay puertos sin resolver, la IP es privada o ninguna
            fuente está disponible.
    """
    if not any(finding.get("category") == "open_port" and finding.get("cpe_resolved") is False
               for finding in findings):
        return []
    observations, _ = collect_host_observations([address], fetch, settings)
    return suggest_cpe_findings(findings, observations, now)
