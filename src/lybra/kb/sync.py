"""La sincronización de la base de conocimiento con sus fuentes públicas.

Descarga NVD (sólo lo modificado en los últimos días), el catálogo KEV de
CISA, las puntuaciones EPSS y los avisos de cada distribución (OVAL de Debian y
Ubuntu, CSAF de Red Hat), y los escribe en la :class:`KnowledgeBase`.

Cada fuente se sincroniza y se anota por separado: una que falla deja su error
registrado y las demás siguen. Una URL caída de KEV no debe dejar sin EPSS ni
sin NVD a nadie.

El primer llenado de NVD (unas 350 000 CVE) no es lo que hace la sincronización
de cada día, que sólo trae unos días de cambios: se hace una vez con
:meth:`KnowledgeBaseSync.sync_nvd_backfill`, o importando una base ya llena.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional

from ..core._shared import isoformat_utc, utcnow_naive
from ..core.vulndata import (
    NVD_PAUSE_NO_KEY,
    NVD_PAUSE_WITH_KEY,
    fetch_epss,
    fetch_kev,
    fetch_oval,
    ingest_kev,
    ingest_nvd_cve,
    iter_nvd_pages,
    kb_feed_version,
    parse_csaf_advisory,
    parse_epss_rows,
    parse_oval_definitions,
)
from .store import KnowledgeBase

logger = logging.getLogger(__name__)

#: Las fuentes públicas por defecto. ``oval`` va por distribución:
#: ``"<vendor>[:<release>]"`` → URL del feed.
DEFAULT_SOURCES: Dict[str, object] = {
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "epss": "https://epss.cyentia.com/epss_scores-current.csv.gz",
    "oval": {
        "debian:11": "https://www.debian.org/security/oval/oval-definitions-bullseye.xml.bz2",
        "debian:12": "https://www.debian.org/security/oval/oval-definitions-bookworm.xml.bz2",
        "debian:13": "https://www.debian.org/security/oval/oval-definitions-trixie.xml.bz2",
        "ubuntu:20.04": "https://security-metadata.canonical.com/oval/com.ubuntu.focal.cve.oval.xml.bz2",
        "ubuntu:22.04": "https://security-metadata.canonical.com/oval/com.ubuntu.jammy.cve.oval.xml.bz2",
        "ubuntu:24.04": "https://security-metadata.canonical.com/oval/com.ubuntu.noble.cve.oval.xml.bz2",
    },
}

#: Lo que se puede pedir sincronizar: una fuente, o ``"all"`` para todas.
SYNC_TARGETS = ("all", "nvd", "kev", "epss", "oval")


@dataclass(frozen=True)
class SyncSettings:
    """De dónde se sincroniza y cuándo se considera vieja cada fuente.

    Attributes:
        sources: Nombre de fuente → URL; ``oval`` es a su vez distribución →
            URL. Una fuente que falta (o con URL vacía) no se sincroniza. Por
            defecto, :data:`DEFAULT_SOURCES`.
        nvd_window_days: Cuántos días de cambios de NVD trae cada sincronización.
            Tiene que quedar holgadamente por debajo de :data:`NVD_MAX_WINDOW_DAYS`.
            Por defecto 8.
        nvd_api_key: Clave de la API de NVD, que sube su límite de peticiones;
            ``None`` sin clave. Por defecto ``None``.
        max_age_days: Días a partir de los cuales una fuente se da por vieja,
            por fuente (``oval`` vale para todas las distribuciones). Por
            defecto 3 para NVD y 7 para el resto.
    """

    sources: Dict[str, object] = field(default_factory=lambda: dict(DEFAULT_SOURCES))
    nvd_window_days: int = 8
    nvd_api_key: Optional[str] = None
    max_age_days: Dict[str, int] = field(default_factory=lambda: {"nvd": 3, "kev": 7, "epss": 7, "oval": 7})


#: NVD documenta un tope de 120 días por petición, pero en la práctica, pasados
#: unos 20 días, **ignora el filtro de fechas sin avisar** y devuelve el
#: catálogo entero (medido contra la API: 18 días → 9 397 resultados; 25 días →
#: 346 605). Un llenado histórico se trocea en ventanas de 14 días.
NVD_MAX_WINDOW_DAYS = 14

#: CVE que se escriben por transacción al sincronizar NVD.
NVD_BATCH_SIZE = 200

_NVD_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.000"


def source_names(sources: Dict[str, object]) -> List[str]:
    """
    Devuelve los nombres con los que se registra cada fuente configurada.

    NVD, KEV y EPSS son una fuente cada una. OVAL se desdobla en una por
    distribución, ``oval:<entrada>``, porque así se sincroniza y así falla.

    Args:
        sources: Las fuentes, con la forma de :attr:`SyncSettings.sources`.

    Returns:
        List[str]: Ordenados, p. ej. ``["epss", "kev", "nvd", "oval:debian:12"]``.
    """
    names = [name for name in sources if name != "oval"]
    names += [f"oval:{key}" for key in (sources.get("oval") or {})]
    return sorted(names)


class KnowledgeBaseSync:
    """Llena y refresca la base de conocimiento desde sus fuentes.

    Attributes:
        kb: La base de conocimiento que se escribe.
        settings: Las fuentes y los umbrales.
    """

    def __init__(self, kb: KnowledgeBase, settings: Optional[SyncSettings] = None,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        """
        Prepara la sincronización.

        Args:
            kb: La base de conocimiento.
            settings: Fuentes y umbrales; ``None`` usa los de :class:`SyncSettings`.
            sleep: La pausa entre ventanas de NVD, sustituible en los tests.
                Por defecto ``time.sleep``.
        """
        self.kb = kb
        self.settings = settings or SyncSettings()
        self._sleep = sleep

    # ------------------------------------------------------------ fuentes

    def sync_kev(self, url: str) -> int:
        """
        Espeja el catálogo KEV de CISA.

        Args:
            url: La URL del catálogo en JSON.

        Returns:
            int: Cuántas entradas se escribieron.
        """
        rows = [row for row in (ingest_kev(vuln) for vuln in fetch_kev(url)) if row]
        with self.kb.transaction():
            for row in rows:
                self.kb.upsert_kev(row)
        logger.info("KB: KEV, %d entradas", len(rows))
        return len(rows)

    def sync_epss(self, url: str) -> int:
        """
        Espeja las puntuaciones EPSS del día.

        Args:
            url: La URL del CSV (normalmente comprimido en gzip).

        Returns:
            int: Cuántas puntuaciones se escribieron.
        """
        count = self.kb.bulk_upsert_epss(list(parse_epss_rows(fetch_epss(url))))
        logger.info("KB: EPSS, %d puntuaciones", count)
        return count

    def sync_oval(self, key: str, url) -> int:
        """
        Espeja los avisos de una distribución.

        El formato se deduce del contenido: JSON es CSAF (Red Hat y derivadas),
        lo demás es OVAL (Debian, Ubuntu), que llega en bzip2 y se descomprime
        mientras se lee.

        Args:
            key: La entrada, ``"debian:12"``, ``"ubuntu:24.04"`` o ``"rhel"``
                (sin versión, el feed vale para todas).
            url: La URL del feed. Se comprueba porque llega de una configuración
                editada a mano.

        Returns:
            int: Cuántos pronunciamientos se escribieron.

        Raises:
            ValueError: Si ``url`` no es una URL ``http(s)``.
        """
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            raise ValueError(f"la fuente OVAL '{key}' no es una URL http(s): {url!r}")
        vendor, _, release = key.partition(":")
        document = fetch_oval(url)
        if document.lstrip().startswith(b"{"):
            rows = parse_csaf_advisory(json.loads(document), vendor=vendor)
        else:
            rows = parse_oval_definitions(document, vendor, release or None)
        count = 0
        with self.kb.transaction():
            for row in rows:
                self.kb.upsert_distro_pkg_status(row)
                count += 1
        logger.info("KB: OVAL/CSAF '%s', %d pronunciamientos", key, count)
        return count

    def sync_nvd(self, base_url: str, window_days: int = 8, api_key: Optional[str] = None) -> int:
        """
        Espeja las CVE de NVD modificadas en los últimos ``window_days`` días.

        Args:
            base_url: La URL de la API de CVE de NVD.
            window_days: Días de cambios que se traen. Por defecto 8.
            api_key: Clave de la API de NVD, o ``None``. Por defecto ``None``.

        Returns:
            int: Cuántas CVE se escribieron.
        """
        end = utcnow_naive()
        count = self.sync_nvd_backfill(base_url, end - timedelta(days=window_days), end, api_key=api_key)
        logger.info("KB: NVD, %d CVE (ventana de %d días)", count, window_days)
        return count

    def sync_nvd_backfill(self, base_url: str, start: datetime, end: Optional[datetime] = None,
                          api_key: Optional[str] = None,
                          on_progress: Optional[Callable[[dict], None]] = None) -> int:
        """
        Espeja todas las CVE de NVD modificadas entre ``start`` y ``end``.

        Trocea el periodo en ventanas de :data:`NVD_MAX_WINDOW_DAYS` días, las
        que NVD filtra bien, y escribe en lotes de :data:`NVD_BATCH_SIZE` para
        que un periodo largo no sea una única transacción gigante. Entre
        ventanas hace una pausa para no superar el límite de peticiones de NVD.

        Args:
            base_url: La URL de la API de CVE de NVD.
            start: Desde cuándo.
            end: Hasta cuándo; ``None`` es ahora. Por defecto ``None``.
            api_key: Clave de la API de NVD, o ``None``. Por defecto ``None``.
            on_progress: Recibe el progreso de cada ventana. Por defecto ``None``.

        Returns:
            int: Cuántas CVE se escribieron en total.
        """
        effective_key = api_key if api_key is not None else self.settings.nvd_api_key
        end = end or utcnow_naive()
        windows: List[tuple[datetime, datetime]] = []
        window_start = start
        while window_start < end:
            window_end = min(window_start + timedelta(days=NVD_MAX_WINDOW_DAYS), end)
            windows.append((window_start, window_end))
            window_start = window_end

        total = 0
        for index, (window_start, window_end) in enumerate(windows):
            if index > 0:
                self._sleep(NVD_PAUSE_WITH_KEY if effective_key else NVD_PAUSE_NO_KEY)
            if on_progress is not None:
                on_progress({
                    "phase": "backfill",
                    "done": index,
                    "total": len(windows),
                    "cves": total,
                    "windowStart": window_start.date().isoformat(),
                    "windowEnd": window_end.date().isoformat(),
                    "hasApiKey": bool(effective_key),
                })
            batch: list = []
            count = 0
            for item in iter_nvd_pages(base_url, window_start.strftime(_NVD_DATE_FORMAT),
                                       window_end.strftime(_NVD_DATE_FORMAT), effective_key):
                parsed = ingest_nvd_cve(item)
                if parsed:
                    batch.append(parsed)
                if len(batch) >= NVD_BATCH_SIZE:
                    count += self._write_cves(batch)
                    batch = []
            count += self._write_cves(batch)
            logger.info("KB: NVD %s → %s, %d CVE", window_start.date(), window_end.date(), count)
            total += count
            if on_progress is not None:
                on_progress({
                    "phase": "backfill",
                    "done": index + 1,
                    "total": len(windows),
                    "cves": total,
                    "windowStart": window_start.date().isoformat(),
                    "windowEnd": window_end.date().isoformat(),
                    "hasApiKey": bool(effective_key),
                })
        return total

    def backfill_nvd(self, start: datetime, end: Optional[datetime] = None,
                     api_key: Optional[str] = None,
                     on_progress: Optional[Callable[[dict], None]] = None) -> dict:
        """
        Realiza un llenado histórico completo de NVD, reconstruye el índice y anota el estado.

        Args:
            start: Desde cuándo.
            end: Hasta cuándo; ``None`` es ahora.
            api_key: Clave de la API de NVD, o ``None``.
            on_progress: Recibe el progreso.

        Returns:
            dict: Resumen del backfill.
        """
        base_url = self.settings.sources.get("nvd")
        if not base_url:
            raise ValueError("la fuente 'nvd' no está configurada")
        actual_end = end or utcnow_naive()
        if start >= actual_end:
            raise ValueError("'since' tiene que ser anterior a 'until'")
        effective_key = api_key if api_key is not None else self.settings.nvd_api_key
        try:
            rows = self.sync_nvd_backfill(str(base_url), start, actual_end, api_key=effective_key, on_progress=on_progress)
        except Exception as error:
            self._record("nvd", error=f"{type(error).__name__}: {error}")
            raise
        self._record("nvd", rows_upserted=rows)
        # We need total_windows count for the index phase progress event
        # Let's calculate total_windows again or keep it
        total_windows = 0
        w_start = start
        while w_start < actual_end:
            total_windows += 1
            w_start = min(w_start + timedelta(days=NVD_MAX_WINDOW_DAYS), actual_end)

        if on_progress is not None:
            on_progress({
                "phase": "index",
                "done": total_windows,
                "total": total_windows,
                "cves": rows,
                "hasApiKey": bool(effective_key),
            })
        aliases = self.kb.rebuild_cpe_product_index()
        return {
            "cves": rows,
            "cpeProductAliases": aliases,
            "since": start.date().isoformat(),
            "until": actual_end.date().isoformat(),
            "usedApiKey": bool(effective_key),
        }

    def _write_cves(self, batch: list) -> int:
        """Escribe un lote de CVE en una transacción y devuelve cuántas eran."""
        with self.kb.transaction():
            for cve_row, cpe_matches in batch:
                self.kb.upsert_cve(cve_row, cpe_matches)
        return len(batch)

    # ------------------------------------------------------------ todas

    def sync_source(self, source: str, run: Callable[[], int]) -> Optional[int]:
        """
        Sincroniza una fuente y anota cómo salió, sin dejar escapar el error.

        No propagar la excepción es el motivo de este método: una fuente rota
        debe costar esa fuente, no las demás.

        Args:
            source: El nombre con el que se anota (``nvd``, ``oval:debian:12``…).
            run: Lo que sincroniza la fuente; devuelve las filas escritas.

        Returns:
            Optional[int]: Las filas escritas, o ``None`` si falló.
        """
        try:
            rows = run()
        except Exception as error:  # pylint: disable=broad-exception-caught
            logger.exception("KB: la sincronización de '%s' falló", source)
            self._record(source, error=f"{type(error).__name__}: {error}")
            return None
        self._record(source, rows_upserted=rows)
        return rows

    def _record(self, source: str, rows_upserted: Optional[int] = None, error: Optional[str] = None) -> None:
        """Anota el intento; un fallo al anotar se registra en el log y no tumba la sincronización."""
        try:
            self.kb.record_sync(source, rows_upserted, error)
        except Exception:  # pylint: disable=broad-exception-caught
            logger.exception("KB: no se pudo registrar el estado de '%s'", source)

    def sync_all(self, only: Optional[str] = None) -> Dict[str, Optional[int]]:
        """
        Sincroniza cada fuente configurada una vez.

        NVD es siempre la ventana corta de cambios, nunca el histórico. Si NVD
        sale bien se reconstruye el índice de nombres de producto, que se deriva
        de sus reglas.

        Args:
            only: Sincronizar sólo ``"nvd"``, ``"kev"``, ``"epss"`` u ``"oval"``
                (todas sus distribuciones); ``None`` o ``"all"`` para todas. Por
                defecto ``None``.

        Returns:
            dict: Filas escritas por fuente; ``None`` en la que falló, que es
                distinto de 0 (salió bien y no había nada nuevo). Con NVD
                correcto, también ``cpeProductAliases``.

        Raises:
            ValueError: Si ``only`` no es uno de :data:`SYNC_TARGETS`.
        """
        if only not in (None, *SYNC_TARGETS):
            raise ValueError(f"fuente desconocida: {only!r}; válidas: {', '.join(SYNC_TARGETS)}")
        only = None if only == "all" else only
        sources = self.settings.sources
        summary: Dict[str, Optional[int]] = {}

        def wanted(name: str) -> bool:
            return bool(sources.get(name)) and only in (None, name)

        if wanted("kev"):
            summary["kev"] = self.sync_source("kev", lambda: self.sync_kev(sources["kev"]))
        if wanted("epss"):
            summary["epss"] = self.sync_source("epss", lambda: self.sync_epss(sources["epss"]))
        for key, url in ((sources.get("oval") or {}) if only in (None, "oval") else {}).items():
            summary[f"oval:{key}"] = self.sync_source(
                f"oval:{key}", lambda key=key, url=url: self.sync_oval(key, url))
        if wanted("nvd"):
            summary["nvd"] = self.sync_source("nvd", lambda: self.sync_nvd(
                sources["nvd"], window_days=self.settings.nvd_window_days,
                api_key=self.settings.nvd_api_key))
            if summary["nvd"] is not None:
                summary["cpeProductAliases"] = self.kb.rebuild_cpe_product_index()
        logger.info("KB: sincronización terminada: %s", summary)
        return summary

    def status(self) -> dict:
        """
        Dice qué sabe la base de conocimiento y cuándo lo aprendió.

        Junta dos preguntas distintas: **cuándo se preguntó, y si funcionó**
        (lo que detecta una sincronización rota, que si no sólo deja líneas de
        log), y **cuán reciente es lo que se sabe** (la fecha más nueva de los
        propios datos).

        Recorre las fuentes **configuradas**, no las anotadas: una que no se ha
        sincronizado nunca no tiene anotación, y es la que más importa.
        **Nunca sincronizada no es lo mismo que vieja**: una base importada
        tiene contenido sin haber sincronizado nunca. Sólo se afirma que una
        fuente está vieja cuando se puede demostrar: su último éxito pasó del
        plazo, o no tiene ninguno **y** está vacía. Con contenido y sin
        anotación es ``isUnverified``: información, no alarma.

        Returns:
            dict: ``{"sources": [...], "isStale": bool, "isUnverified": bool,
                "feedVersion": str}``, con una entrada por fuente configurada.
        """
        now = utcnow_naive()
        records = {record.source: record for record in self.kb.sync_status()}
        content_state = self.kb.knowledge_state()
        filled = self.kb.has_content()
        entries = []
        for name in source_names(self.settings.sources):
            record = records.get(name)
            limit_days = self.settings.max_age_days.get(name.partition(":")[0])
            has_content = filled.get(name, False)
            age_days = None
            if record is not None and record.last_success_at is not None:
                age_days = round((now - record.last_success_at).total_seconds() / 86400, 2)
            if age_days is not None:
                is_stale = limit_days is not None and age_days > limit_days
                is_unverified = False
            else:
                is_stale = not has_content
                is_unverified = has_content
            newest = content_state.get(name)
            entries.append({
                "source": name,
                "lastAttemptAt": isoformat_utc(record.last_attempt_at) if record else None,
                "lastSuccessAt": isoformat_utc(record.last_success_at) if record else None,
                "rowsUpserted": record.rows_upserted if record else None,
                "error": record.error if record else None,
                "neverSynced": record is None or record.last_success_at is None,
                "hasContent": has_content,
                "ageDays": age_days,
                "maxAgeDays": limit_days,
                "isStale": is_stale,
                "isUnverified": is_unverified,
                "newestContentAt": isoformat_utc(newest) if newest else None,
            })
        return {
            "sources": entries,
            "isStale": any(entry["isStale"] for entry in entries),
            "isUnverified": any(entry["isUnverified"] for entry in entries),
            "feedVersion": kb_feed_version(content_state),
        }
