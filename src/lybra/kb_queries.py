"""Las preguntas que se le hacen a la base de conocimiento desde fuera del escaneo.

El escaneo consulta la base a través del motor (:func:`engine_for`). Estas otras
consultas son las que una aplicación hace por su cuenta: la ficha de una CVE,
si una versión concreta de un producto es vulnerable, los avisos recientes de
unos productos, o buscar un producto por nombre. Devuelven valores planos
(diccionarios en camelCase o dataclasses), listos para serializar.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Tuple

from ._shared import isoformat_utc
from .end_of_life import check_end_of_life
from .engine import LybraEngine, Service
from .kb import kb_feed_version, normalize_product_name, parse_cpe23
from .knowledge_base import KnowledgeBase
from .scanner import ScanPhases, ScanSettings

_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

#: Productos y paquetes de distribución que devuelve como mucho la ficha
#: pública de una CVE: una CVE de un componente muy extendido casa con cientos.
PUBLIC_CVE_LIST_LIMIT = 50

#: CVE que devuelve como mucho la consulta pública de una versión, las más
#: urgentes primero.
PUBLIC_VERSION_CVE_LIMIT = 25


def engine_for(kb: KnowledgeBase, record_resolutions: bool = True) -> LybraEngine:
    """
    Construye el motor de detección con las consultas de una base de conocimiento.

    Args:
        kb: La base de conocimiento.
        record_resolutions: Si el motor anota en la base los nombres de
            producto que no logra resolver. ``False`` para consultas que no
            deben contar en esas estadísticas (las anónimas). Por defecto ``True``.

    Returns:
        LybraEngine: El motor, firmado con la versión actual de la base.
    """
    return LybraEngine(
        cve_lookup=kb.cves_for_cpe,
        kev_lookup=kb.is_in_kev,
        epss_lookup=kb.epss_score,
        product_alias_lookup=kb.resolve_product_alias,
        feed_version=kb_feed_version(kb.knowledge_state()),
        record_resolution=kb.record_resolution if record_resolutions else None,
        exploit_evidence_lookup=kb.exploit_evidence,
    )


@dataclass(frozen=True)
class CveAdvisory:  # pylint: disable=too-many-instance-attributes
    """Una CVE reciente de un producto, con su contexto de explotación.

    Attributes:
        cve_id: La CVE.
        vendor: El fabricante CPE por el que se encontró.
        product: El producto CPE por el que se encontró.
        published: Cuándo se publicó.
        severity: ``CRITICAL``, ``HIGH``… o cadena vacía si no está puntuada.
        cvss_score: La puntuación CVSS, o ``None``.
        description: La descripción de NVD, **en inglés**: sirve de contexto,
            no para enseñarla tal cual a un usuario final de otro idioma.
        kev: Si está en el catálogo KEV.
        epss: Probabilidad de explotación en 30 días (0-1), o ``None``.
    """

    cve_id: str
    vendor: str
    product: str
    published: Optional[datetime] = None
    severity: str = ""
    cvss_score: Optional[float] = None
    description: str = ""
    kev: bool = False
    epss: Optional[float] = None

    @property
    def url(self) -> str:
        """La ficha de la CVE en NVD."""
        return f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"


@dataclass(frozen=True)
class KbProduct:
    """Un producto del índice, para un buscador.

    Attributes:
        vendor: El fabricante CPE.
        product: El producto CPE.
        display_name: El nombre normalizado por el que se encontró.
    """

    vendor: str
    product: str
    display_name: str


def advisories_for_products(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        kb: KnowledgeBase, products: List[Tuple[str, str]], since: datetime,
        min_cvss: Optional[float] = None, limit_per_product: int = 5,
        limit_total: int = 20) -> List[CveAdvisory]:
    """
    Devuelve los avisos recientes de unos productos, con KEV y EPSS.

    Args:
        kb: La base de conocimiento.
        products: Pares ``(vendor, product)``.
        since: Publicadas desde este instante.
        min_cvss: Suelo de CVSS; las CVE sin puntuar se conservan. Por defecto ``None``.
        limit_per_product: Tope por producto. Por defecto 5.
        limit_total: Tope global, tras ordenar por fecha. Por defecto 20.

    Returns:
        List[CveAdvisory]: Los avisos, del más reciente al más antiguo.
    """
    rows = kb.recent_cves_for_products(products, since, min_cvss=min_cvss,
                                       limit_per_product=limit_per_product)
    if not rows:
        return []
    cve_ids = [cve.cve_id for _, _, cve in rows]
    kev_ids = kb.kev_ids_in(cve_ids)
    epss_by_id = kb.epss_scores_for(cve_ids)
    advisories = [
        CveAdvisory(cve_id=cve.cve_id, vendor=vendor, product=product, published=cve.published,
                    severity=cve.severity or "", cvss_score=cve.cvss_score,
                    description=cve.description or "", kev=cve.cve_id in kev_ids,
                    epss=epss_by_id.get(cve.cve_id))
        for vendor, product, cve in rows
    ]
    advisories.sort(key=lambda advisory: advisory.published or datetime.min, reverse=True)
    return advisories[:limit_total]


def search_products(kb: KnowledgeBase, term: str, limit: int = 20) -> List[KbProduct]:
    """
    Busca productos del índice cuyo nombre empieza por ``term``.

    Args:
        kb: La base de conocimiento.
        term: El principio del nombre.
        limit: Cuántos como mucho. Por defecto 20.

    Returns:
        List[KbProduct]: Por orden alfabético.
    """
    return [KbProduct(vendor, product, name) for vendor, product, name in kb.search_products(term, limit=limit)]


def resolve_products(kb: KnowledgeBase, names: List[str]) -> List[Tuple[str, str]]:
    """
    Traduce nombres de producto libres a pares ``(vendor, product)``.

    Los nombres que no resuelven se descartan en silencio, que es lo correcto
    para un inventario lleno de software sin presencia en NVD.

    Args:
        kb: La base de conocimiento.
        names: Los nombres, como los escribe una persona o un inventario.

    Returns:
        List[Tuple[str, str]]: Los pares resueltos, sin repetir y en orden.
    """
    resolved: List[Tuple[str, str]] = []
    for name in names:
        key = normalize_product_name(name or "")
        pair = kb.resolve_product_alias(key) if key else None
        if pair and pair not in resolved:
            resolved.append(pair)
    return resolved


def cve_detail(kb: KnowledgeBase, cve_id: str) -> Optional[dict]:
    """
    Reúne todo lo que la base sabe de una CVE, fuente a fuente.

    Args:
        kb: La base de conocimiento.
        cve_id: La CVE, en mayúsculas.

    Returns:
        Optional[dict]: ``cveId``, ``published``, ``cvssScore``, ``severity``,
            ``description``, ``products``, ``cweIds``, ``applicability`` (cada
            regla de NVD con su rango de versiones), ``inKev``, ``epssScore``,
            ``epssPercentile`` y ``distroStatuses``. Una fuente que no la
            conoce deja sus campos vacíos. ``None`` si no la conoce ninguna.
    """
    cves = kb.get_cves_with_matches([cve_id])
    cve = cves[0] if cves else None
    kev = kb.get_kev(cve_id)
    epss = kb.get_epss(cve_id)
    statuses = kb.distro_statuses_for_cve(cve_id)
    if cve is None and kev is None and epss is None and not statuses:
        return None
    products = sorted({(match.vendor, match.product) for match in cve.cpe_matches}) if cve else []
    return {
        "cveId": cve_id,
        "published": isoformat_utc(cve.published) if cve and cve.published else None,
        "cvssScore": cve.cvss_score if cve else None,
        "severity": cve.severity if cve else None,
        "description": cve.description if cve else None,
        "products": [{"vendor": vendor, "product": product} for vendor, product in products],
        "cweIds": list(cve.cwe_ids) if cve else [],
        "applicability": [
            {"vendor": match.vendor, "product": match.product,
             "versionStartIncluding": match.version_start_including,
             "versionStartExcluding": match.version_start_excluding,
             "versionEndIncluding": match.version_end_including,
             "versionEndExcluding": match.version_end_excluding,
             "exactVersion": match.exact_version, "requiredOs": match.required_os}
            for match in cve.cpe_matches
        ] if cve else [],
        "inKev": kev is not None,
        "epssScore": epss.score if epss else None,
        "epssPercentile": epss.percentile if epss else None,
        "distroStatuses": [
            {"vendor": row.vendor, "release": row.release, "package": row.package,
             "status": row.status, "fixedIn": row.fixed_in}
            for row in statuses
        ],
    }


def public_cve_detail(kb: KnowledgeBase, cve_id: str) -> Optional[dict]:
    """
    Devuelve la ficha de una CVE con sus listas acotadas, para una consulta anónima.

    Args:
        kb: La base de conocimiento.
        cve_id: La CVE, en mayúsculas y con formato válido.

    Returns:
        Optional[dict]: Lo mismo que :func:`cve_detail`, con ``products`` y
            ``distroStatuses`` cortadas a :data:`PUBLIC_CVE_LIST_LIMIT` y sus
            totales en ``productsTotal`` y ``distroStatusesTotal``; ``None`` si
            no se conoce.
    """
    detail = cve_detail(kb, cve_id)
    if detail is None:
        return None
    for key in ("products", "distroStatuses", "applicability"):
        detail[f"{key}Total"] = len(detail[key])
        detail[key] = detail[key][:PUBLIC_CVE_LIST_LIMIT]
    return detail


def search(kb: KnowledgeBase, query: str, limit: int = 20) -> dict:
    """
    Responde qué sabe la base de una CVE o de un producto.

    Args:
        kb: La base de conocimiento.
        query: Un identificador de CVE (sin distinguir mayúsculas) o el
            principio del nombre de un producto.
        limit: Cuántos productos como mucho. Por defecto 20.

    Returns:
        dict: ``{"kind": "cve", "cve": dict | None}`` para un identificador de
            CVE, o ``{"kind": "product", "products": [...]}`` con ``vendor``,
            ``product`` y ``displayName``.
    """
    query = query.strip()
    if _CVE_ID.match(query):
        return {"kind": "cve", "cve": cve_detail(kb, query.upper())}
    return {"kind": "product", "products": [
        {"vendor": product.vendor, "product": product.product, "displayName": product.display_name}
        for product in search_products(kb, query, limit=limit)
    ]}


def version_check(kb: KnowledgeBase, product: str, version: str) -> dict:
    """
    Dice qué CVE afectan a un producto en una versión, y si está fuera de soporte.

    Es el motor con una sola entrada: el producto y la versión pasan por la
    misma resolución de CPE y la misma correlación que un servicio de un
    escaneo, como un dato de inventario (la versión la da quien pregunta, no se
    adivina). No anota los nombres que no resuelven: una consulta anónima no
    debe contar en esas estadísticas.

    Args:
        kb: La base de conocimiento.
        product: El nombre del producto (``nginx``, ``Apache httpd``).
        version: La versión del fabricante (``1.18.0``).

    Returns:
        dict: ``recognized`` (si el nombre resolvió a un CPE); ``vendor``,
            ``product`` y ``version`` del CPE resuelto, o ``None``; ``cves``,
            hasta :data:`PUBLIC_VERSION_CVE_LIMIT` entradas ``{cveId,
            cvssScore, epssScore, inKev}`` de la más urgente a la menos;
            ``cvesTotal``; y ``endOfLife``, ``{cycle, date, isPast}`` si el
            catálogo de fin de soporte conoce la rama, o ``None``.
    """
    findings = engine_for(kb, record_resolutions=False).analyze(
        [Service(port=None, protocol="", product=product, version=version, origin="inventory")])
    cves = [
        {"cveId": finding["cve_ids"][0], "cvssScore": finding["cvss_score"],
         "epssScore": finding["epss_score"], "inKev": finding["in_kev"]}
        for finding in findings if finding.get("cve_ids")
    ]
    cves.sort(key=lambda cve: (cve["inKev"], cve["epssScore"] or 0, cve["cvssScore"] or 0), reverse=True)
    cpe = next((parse_cpe23(finding["cpe"]) for finding in findings if finding.get("cpe")), None)
    end_of_life = check_end_of_life(cpe["vendor"], cpe["product"], cpe["version"]) if cpe else None
    return {
        "recognized": bool(findings and findings[0].get("cpe_resolved")),
        "vendor": cpe["vendor"] if cpe else None,
        "product": cpe["product"] if cpe else None,
        "version": cpe["version"] if cpe else None,
        "cves": cves[:PUBLIC_VERSION_CVE_LIMIT],
        "cvesTotal": len(cves),
        "endOfLife": {
            "cycle": end_of_life.cycle,
            "date": end_of_life.eol_date.isoformat(),
            "isPast": end_of_life.is_past,
        } if end_of_life else None,
    }


class KnowledgeBasePhases(ScanPhases):
    """Las fases de un escaneo con la detección por versión contra una base de conocimiento.

    Attributes:
        kb: La base de conocimiento.
        settings: Los ajustes del escaneo.
    """

    def __init__(self, kb: KnowledgeBase, settings: Optional[ScanSettings] = None) -> None:
        """
        Prepara las fases.

        Args:
            kb: La base de conocimiento que consulta la detección por versión.
            settings: Los ajustes; ``None`` usa los de :class:`ScanSettings`.
        """
        super().__init__(settings)
        self.kb = kb

    def analyze(self, services: List[Service]) -> List[dict]:
        """
        Convierte los servicios en hallazgos con la base de conocimiento.

        Args:
            services: Los servicios ya identificados.

        Returns:
            List[dict]: Los hallazgos de puerto abierto, de CVE por versión y
                de fin de soporte.
        """
        return engine_for(self.kb).analyze(services)
