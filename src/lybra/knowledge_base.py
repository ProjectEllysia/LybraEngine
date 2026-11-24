"""La base de conocimiento local del motor: NVD, CISA KEV, EPSS y avisos de distribución.

Es un espejo en un fichero SQLite de lo que el motor necesita saber para
convertir «este servicio corre nginx 1.18.0» en «le afectan estas CVE, y estas
dos se están explotando ahora mismo». Vive en el propio motor para que no
dependa de ninguna aplicación: quien lo integra no tiene que guardarle nada.

Qué hay dentro:

- **CVE de NVD** y, por cada una, sus reglas de aplicabilidad (qué
  ``vendor:product`` y qué rango de versiones afecta).
- **KEV**: el catálogo de CISA de vulnerabilidades que se explotan en la
  práctica.
- **EPSS**: la probabilidad estimada de que una CVE se explote en 30 días.
- **Avisos de distribución** (OVAL de Debian y Ubuntu, CSAF de Red Hat): si un
  paquete concreto de una distribución ya trae el parche, aunque su número de
  versión diga lo contrario.
- Un **índice de nombres de producto** derivado de NVD, para resolver «Apache
  httpd» a ``apache:http_server``.
- Lo que el motor no logró identificar, y el estado de cada sincronización.

La lectura y escritura de los feeds (descargar, parsear) está en ``kb``; la
sincronización que los encadena, en ``kb_sync``. Este módulo sólo guarda y
consulta.

Se puede usar desde varios hilos a la vez: cada hilo abre su propia conexión, y
el fichero va en modo WAL para que las lecturas de un escaneo no esperen a que
termine una sincronización.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple, Union

from ._shared import utcnow_naive
from .kb import normalize_product_name, split_distro_version, version_in_range

logger = logging.getLogger(__name__)

#: Versión del esquema. Sube cuando cambia la forma de una tabla; una base con
#: otra versión se rechaza en vez de leerse mal.
SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cve (
    id                    INTEGER PRIMARY KEY,
    cve_id                TEXT NOT NULL UNIQUE,
    published             TEXT,
    last_modified         TEXT,
    cvss_score            REAL,
    cvss_vector           TEXT,
    severity              TEXT,
    description           TEXT,
    cwe_ids               TEXT,
    has_exploit_reference INTEGER NOT NULL DEFAULT 0,
    source                TEXT NOT NULL DEFAULT 'nvd'
);
CREATE INDEX IF NOT EXISTS ix_cve_published ON cve (published);

CREATE TABLE IF NOT EXISTS cpe_match (
    id                      INTEGER PRIMARY KEY,
    cve_rowid               INTEGER NOT NULL REFERENCES cve (id) ON DELETE CASCADE,
    vendor                  TEXT NOT NULL,
    product                 TEXT NOT NULL,
    version_start_including TEXT,
    version_start_excluding TEXT,
    version_end_including   TEXT,
    version_end_excluding   TEXT,
    exact_version           TEXT,
    required_os             TEXT
);
CREATE INDEX IF NOT EXISTS ix_cpe_match_vendor_product ON cpe_match (vendor, product);
CREATE INDEX IF NOT EXISTS ix_cpe_match_cve ON cpe_match (cve_rowid);

CREATE TABLE IF NOT EXISTS cpe_product_alias (
    normalized_name TEXT PRIMARY KEY,
    vendor          TEXT NOT NULL,
    product         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS kev (
    cve_id           TEXT PRIMARY KEY,
    date_added       TEXT,
    due_date         TEXT,
    known_ransomware INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS epss (
    cve_id     TEXT PRIMARY KEY,
    score      REAL,
    percentile REAL,
    scored_at  TEXT
);

CREATE TABLE IF NOT EXISTS distro_advisory (
    advisory_id TEXT PRIMARY KEY,
    vendor      TEXT NOT NULL,
    title       TEXT,
    cve_ids     TEXT,
    published   TEXT
);

CREATE TABLE IF NOT EXISTS distro_pkg_status (
    id       INTEGER PRIMARY KEY,
    vendor   TEXT NOT NULL,
    release  TEXT,
    package  TEXT NOT NULL,
    cve_id   TEXT NOT NULL,
    fixed_in TEXT,
    status   TEXT NOT NULL DEFAULT 'unknown'
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_distro_pkg_status
    ON distro_pkg_status (vendor, IFNULL(release, ''), package, cve_id);
CREATE INDEX IF NOT EXISTS ix_distro_pkg_status_cve ON distro_pkg_status (cve_id);
CREATE INDEX IF NOT EXISTS ix_distro_pkg_status_package ON distro_pkg_status (vendor, package);

CREATE TABLE IF NOT EXISTS unresolved_product (
    normalized_name TEXT NOT NULL,
    origin          TEXT NOT NULL,
    occurrences     INTEGER NOT NULL DEFAULT 1,
    first_seen_at   TEXT,
    last_seen_at    TEXT,
    PRIMARY KEY (normalized_name, origin)
);

CREATE TABLE IF NOT EXISTS sync_status (
    source          TEXT PRIMARY KEY,
    last_attempt_at TEXT,
    last_success_at TEXT,
    rows_upserted   INTEGER,
    error           TEXT
);
"""

_CVE_COLUMNS = ("cve_id", "published", "last_modified", "cvss_score", "cvss_vector", "severity",
                "description", "cwe_ids", "has_exploit_reference", "source")
_MATCH_COLUMNS = ("vendor", "product", "version_start_including", "version_start_excluding",
                  "version_end_including", "version_end_excluding", "exact_version", "required_os")


@dataclass
class CpeMatchRecord:  # pylint: disable=too-many-instance-attributes
    """Una regla de aplicabilidad de una CVE: qué producto y qué rango de versiones afecta.

    Attributes:
        vendor: El fabricante en la nomenclatura CPE (``apache``).
        product: El producto en la nomenclatura CPE (``http_server``).
        version_start_including: Primera versión afectada, inclusive; ``None`` si no hay límite.
        version_start_excluding: Primera versión afectada, exclusive; ``None`` si no hay límite.
        version_end_including: Última versión afectada, inclusive; ``None`` si no hay límite.
        version_end_excluding: Primera versión ya corregida; ``None`` si no hay límite.
        exact_version: La única versión afectada cuando la regla fija una; ``None`` si es un rango.
        required_os: La plataforma que la regla exige además del producto; ``None`` si no exige ninguna.
    """

    vendor: str
    product: str
    version_start_including: Optional[str] = None
    version_start_excluding: Optional[str] = None
    version_end_including: Optional[str] = None
    version_end_excluding: Optional[str] = None
    exact_version: Optional[str] = None
    required_os: Optional[str] = None


@dataclass
class CveRecord:  # pylint: disable=too-many-instance-attributes
    """Una CVE tal como la guarda la base de conocimiento.

    Attributes:
        cve_id: El identificador (``CVE-2021-41773``).
        published: Cuándo la publicó NVD, en UTC; ``None`` si no consta.
        last_modified: Cuándo la modificó NVD por última vez, en UTC; ``None`` si no consta.
        cvss_score: La puntuación CVSS base, de 0 a 10; ``None`` si NVD aún no la ha analizado.
        cvss_vector: El vector CVSS; ``None`` si no hay puntuación.
        severity: ``CRITICAL``, ``HIGH``, ``MEDIUM``, ``LOW`` o ``NONE``; ``None`` sin puntuación.
        description: La descripción de NVD, **en inglés**.
        cwe_ids: Las debilidades (``CWE-22``) que NVD le asigna.
        has_exploit_reference: Si NVD enlaza alguna referencia etiquetada como exploit.
        source: De dónde viene; hoy siempre ``"nvd"``.
        required_os: Sólo en los resultados de :meth:`KnowledgeBase.cves_for_cpe`:
            la plataforma que exigen **todas** las reglas que casaron, o ``None``
            si alguna no exige ninguna.
        cpe_matches: Sólo en los resultados de :meth:`KnowledgeBase.get_cves_with_matches`:
            todas sus reglas de aplicabilidad.
    """

    cve_id: str
    published: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    cwe_ids: List[str] = field(default_factory=list)
    has_exploit_reference: bool = False
    source: str = "nvd"
    required_os: Optional[str] = None
    cpe_matches: List[CpeMatchRecord] = field(default_factory=list)


@dataclass(frozen=True)
class KevRecord:
    """Una entrada del catálogo KEV de CISA.

    Attributes:
        cve_id: La CVE.
        date_added: Cuándo entró en el catálogo.
        due_date: El plazo que CISA da a las agencias federales para corregirla.
        known_ransomware: Si se sabe que la usan campañas de ransomware.
    """

    cve_id: str
    date_added: Optional[datetime] = None
    due_date: Optional[datetime] = None
    known_ransomware: bool = False


@dataclass(frozen=True)
class EpssRecord:
    """La puntuación EPSS de una CVE.

    Attributes:
        cve_id: La CVE.
        score: Probabilidad estimada de explotación en los próximos 30 días, de 0 a 1.
        percentile: Qué fracción de las CVE puntúa por debajo, de 0 a 1.
        scored_at: El día al que corresponde la puntuación.
    """

    cve_id: str
    score: Optional[float] = None
    percentile: Optional[float] = None
    scored_at: Optional[datetime] = None


@dataclass(frozen=True)
class DistroStatus:
    """Lo que una distribución dice de un paquete frente a una CVE.

    Attributes:
        vendor: La distribución (``debian``, ``ubuntu``, ``rhel``).
        release: La versión de la distribución (``12``, ``24.04``), o ``None``
            si el aviso vale para todas.
        package: El paquete fuente.
        cve_id: La CVE.
        fixed_in: La versión del paquete que trae la corrección, o ``None``.
        status: ``fixed``, ``not_affected``, ``affected`` o ``unknown``.
    """

    vendor: str
    release: Optional[str]
    package: str
    cve_id: str
    fixed_in: Optional[str]
    status: str


@dataclass(frozen=True)
class SyncRecord:
    """El último intento de sincronizar una fuente.

    Attributes:
        source: La fuente (``nvd``, ``kev``, ``epss``, ``oval:debian:12``…).
        last_attempt_at: Cuándo se intentó por última vez.
        last_success_at: Cuándo salió bien por última vez; se conserva aunque
            los intentos siguientes fallen.
        rows_upserted: Filas escritas en el último intento correcto.
        error: El error del último intento, o ``None`` si salió bien.
    """

    source: str
    last_attempt_at: Optional[datetime]
    last_success_at: Optional[datetime]
    rows_upserted: Optional[int]
    error: Optional[str]


@dataclass(frozen=True)
class UnresolvedRecord:
    """Un nombre de producto que el motor no logró traducir a un CPE.

    Attributes:
        normalized_name: El nombre, normalizado.
        origin: ``network`` (leído de un banner) o ``inventory`` (de un inventario).
        occurrences: Cuántas veces se ha visto sin resolver.
        first_seen_at: La primera vez.
        last_seen_at: La última vez.
    """

    normalized_name: str
    origin: str
    occurrences: int
    first_seen_at: Optional[datetime]
    last_seen_at: Optional[datetime]


def _to_text(value: Optional[datetime]) -> Optional[str]:
    """Guarda un instante como ISO 8601 sin zona (UTC implícito), o ``None``."""
    return value.isoformat() if value is not None else None


def _to_datetime(value: Optional[str]) -> Optional[datetime]:
    """Lee un instante guardado con :func:`_to_text`, o ``None``."""
    return datetime.fromisoformat(value) if value else None


def _stored(column: str, value):
    """Convierte un valor de una fila de los ingestores a lo que guarda SQLite."""
    if isinstance(value, datetime):
        return _to_text(value)
    if column in ("cwe_ids", "cve_ids") and value is not None:
        return json.dumps(value)
    if isinstance(value, bool):
        return int(value)
    return value


class KnowledgeBase:  # pylint: disable=too-many-public-methods
    """La base de conocimiento del motor, en un fichero SQLite.

    Sus métodos de consulta tienen la forma que espera el motor
    (``LybraEngine`` los recibe como consultas inyectadas; ver
    :func:`lybra.kb_queries.engine_for`). Los de escritura los usa
    ``kb_sync``.

    Attributes:
        path: Dónde está el fichero; ``":memory:"`` para una base en memoria
            (sólo útil en tests, y entonces compartida por todos los hilos).
    """

    def __init__(self, path: Union[str, Path]) -> None:
        """
        Abre (y crea si no existe) la base de conocimiento.

        Args:
            path: Ruta del fichero SQLite, o ``":memory:"``.

        Raises:
            RuntimeError: Si el fichero tiene un esquema de otra versión.
        """
        self.path = str(path)
        self._local = threading.local()
        self._shared: Optional[sqlite3.Connection] = None
        if self.path == ":memory:":
            self._shared = self._open()
        connection = self._connection()
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, SCHEMA_VERSION):
            raise RuntimeError(
                f"La base de conocimiento {self.path} tiene el esquema {version}; "
                f"este motor usa el {SCHEMA_VERSION}")
        # ``executescript`` confirma por su cuenta: no puede ir dentro de una
        # transacción, y cada sentencia del esquema es idempotente.
        connection.executescript(_SCHEMA)
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    # ------------------------------------------------------------ conexión

    def _open(self) -> sqlite3.Connection:
        """Abre una conexión con los ajustes de la base."""
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None,
                                     check_same_thread=self.path != ":memory:")
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        if self.path != ":memory:":
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = NORMAL")
        return connection

    def _connection(self) -> sqlite3.Connection:
        """Devuelve la conexión de este hilo, abriéndola si hace falta."""
        if self._shared is not None:
            return self._shared
        connection = getattr(self._local, "connection", None)
        if connection is None:
            connection = self._local.connection = self._open()
        return connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """
        Agrupa varias escrituras en una transacción: o entran todas o ninguna.

        Las transacciones anidadas se funden en la de fuera.

        Yields:
            sqlite3.Connection: La conexión del hilo, dentro de la transacción.
        """
        connection = self._connection()
        if connection.in_transaction:
            yield connection
            return
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
        except BaseException:
            connection.execute("ROLLBACK")
            raise
        connection.execute("COMMIT")

    def close(self) -> None:
        """Cierra la conexión de este hilo (y la compartida, en una base en memoria)."""
        connection = getattr(self._local, "connection", None)
        if connection is not None:
            connection.close()
            self._local.connection = None
        if self._shared is not None:
            self._shared.close()
            self._shared = None

    def _rows(self, sql: str, parameters: Iterable = ()) -> List[sqlite3.Row]:
        """Ejecuta una consulta y devuelve todas sus filas."""
        return self._connection().execute(sql, tuple(parameters)).fetchall()

    def _value(self, sql: str, parameters: Iterable = ()):
        """Ejecuta una consulta y devuelve la primera columna de la primera fila, o ``None``."""
        row = self._connection().execute(sql, tuple(parameters)).fetchone()
        return row[0] if row else None

    # ------------------------------------------------------------ la pregunta del motor

    def cves_for_cpe(self, vendor: str, product: str, version: str) -> List[CveRecord]:
        """
        Devuelve las CVE que afectan a ``vendor:product`` en ``version``.

        Filtra en SQL por producto y aplica la lógica de rangos en Python (ver
        ``kb.version_in_range``). Una CVE puede tener varias reglas para el
        mismo producto, unas condicionadas a una plataforma y otras no; si casan
        varias, gana la **menos** restrictiva: una regla incondicional demuestra
        que la CVE aplica aquí, diga lo que diga otra más estrecha.

        Args:
            vendor: El fabricante CPE.
            product: El producto CPE.
            version: La versión instalada.

        Returns:
            List[CveRecord]: Las CVE, sin repetir, en el orden en que aparece
                su primera regla; cada una con ``required_os`` puesto.
        """
        rows = self._rows(
            "SELECT m.*, c.cve_id AS cve_name, c.published, c.last_modified, c.cvss_score, "
            "c.cvss_vector, c.severity, c.description, c.cwe_ids, c.has_exploit_reference, c.source "
            "FROM cpe_match m JOIN cve c ON c.id = m.cve_rowid "
            "WHERE m.vendor = ? AND m.product = ? ORDER BY m.id",
            (vendor, product))
        order: List[int] = []
        entries: Dict[int, CveRecord] = {}
        for row in rows:
            match = {column: row[column] for column in _MATCH_COLUMNS}
            if not version_in_range(version, match):
                continue
            key = row["cve_rowid"]
            if key not in entries:
                order.append(key)
                entries[key] = _cve_from_row(row, cve_column="cve_name")
                entries[key].required_os = row["required_os"]
            elif entries[key].required_os and not row["required_os"]:
                entries[key].required_os = None
        return [entries[key] for key in order]

    def resolve_product_alias(self, normalized_name: str) -> Optional[Tuple[str, str]]:
        """
        Busca un nombre de producto normalizado en el índice derivado de NVD.

        Es la última estrategia con la que el motor intenta resolver un CPE,
        tras un CPE explícito y los alias curados del feed.

        Args:
            normalized_name: El nombre, ya normalizado (``kb.normalize_product_name``).

        Returns:
            Optional[Tuple[str, str]]: ``(vendor, product)``, o ``None`` si el
                nombre no está o era ambiguo.
        """
        row = self._connection().execute(
            "SELECT vendor, product FROM cpe_product_alias WHERE normalized_name = ?",
            (normalized_name,)).fetchone()
        return (row["vendor"], row["product"]) if row else None

    def get_kev(self, cve_id: str) -> Optional[KevRecord]:
        """
        Busca una CVE en el catálogo KEV.

        Args:
            cve_id: La CVE.

        Returns:
            Optional[KevRecord]: La entrada, o ``None`` si no está en KEV.
        """
        row = self._connection().execute("SELECT * FROM kev WHERE cve_id = ?", (cve_id,)).fetchone()
        if row is None:
            return None
        return KevRecord(cve_id=row["cve_id"], date_added=_to_datetime(row["date_added"]),
                         due_date=_to_datetime(row["due_date"]),
                         known_ransomware=bool(row["known_ransomware"]))

    def is_in_kev(self, cve_id: str) -> bool:
        """
        Indica si una CVE está en el catálogo KEV.

        Args:
            cve_id: La CVE.

        Returns:
            bool: ``True`` si CISA la tiene catalogada como explotada.
        """
        return self._value("SELECT 1 FROM kev WHERE cve_id = ?", (cve_id,)) is not None

    def get_epss(self, cve_id: str) -> Optional[EpssRecord]:
        """
        Busca la puntuación EPSS de una CVE.

        Args:
            cve_id: La CVE.

        Returns:
            Optional[EpssRecord]: La puntuación, o ``None`` si EPSS no la puntúa.
        """
        row = self._connection().execute("SELECT * FROM epss WHERE cve_id = ?", (cve_id,)).fetchone()
        if row is None:
            return None
        return EpssRecord(cve_id=row["cve_id"], score=row["score"], percentile=row["percentile"],
                          scored_at=_to_datetime(row["scored_at"]))

    def epss_score(self, cve_id: str) -> Optional[float]:
        """
        Devuelve la probabilidad EPSS de una CVE.

        Args:
            cve_id: La CVE.

        Returns:
            Optional[float]: De 0 a 1, o ``None`` si EPSS no la puntúa.
        """
        return self._value("SELECT score FROM epss WHERE cve_id = ?", (cve_id,))

    def kev_ids_in(self, cve_ids: List[str]) -> set:
        """
        Dice cuáles de ``cve_ids`` están en KEV, con una sola consulta.

        Args:
            cve_ids: Las CVE.

        Returns:
            set: Las que están en KEV.
        """
        if not cve_ids:
            return set()
        marks = ",".join("?" * len(cve_ids))
        return {row[0] for row in self._rows(f"SELECT cve_id FROM kev WHERE cve_id IN ({marks})", cve_ids)}

    def epss_scores_for(self, cve_ids: List[str]) -> Dict[str, Optional[float]]:
        """
        Devuelve la puntuación EPSS de varias CVE, con una sola consulta.

        Args:
            cve_ids: Las CVE.

        Returns:
            dict: ``{cve_id: score}`` de las que EPSS puntúa.
        """
        if not cve_ids:
            return {}
        marks = ",".join("?" * len(cve_ids))
        return {row[0]: row[1] for row in
                self._rows(f"SELECT cve_id, score FROM epss WHERE cve_id IN ({marks})", cve_ids)}

    def exploit_evidence(self, cve_id: str) -> Optional[str]:
        """
        Dice qué madurez de explotación consta para una CVE, sin contar KEV.

        Sólo puede decir ``"poc"``: la señal es la referencia que NVD etiqueta
        como exploit, que afirma que alguien publicó algo que demuestra el fallo,
        no cuán usable es. KEV, la evidencia más fuerte, la combina el motor
        aparte (``correlation.exploit_maturity``).

        Args:
            cve_id: La CVE.

        Returns:
            Optional[str]: ``"poc"``, o ``None`` si no consta nada.
        """
        value = self._value("SELECT has_exploit_reference FROM cve WHERE cve_id = ?", (cve_id,))
        return "poc" if value else None

    def record_resolution(self, normalized_name: str, origin: str, was_resolved: bool) -> None:
        """
        Lleva la cuenta de los nombres de producto que no resuelven a un CPE.

        Si falla, suma uno a su contador; **si resuelve, borra la fila**. Lo
        segundo cierra el bucle: al añadir el alias que faltaba, el nombre sale
        del ranking en el siguiente escaneo, y el ranking mide el trabajo que
        queda y no el que hubo.

        Args:
            normalized_name: El nombre, normalizado.
            origin: ``"network"`` o ``"inventory"``.
            was_resolved: Si esta vez se resolvió.
        """
        with self.transaction() as db:
            if was_resolved:
                db.execute("DELETE FROM unresolved_product WHERE normalized_name = ? AND origin = ?",
                           (normalized_name, origin))
                return
            now = _to_text(utcnow_naive())
            db.execute(
                "INSERT INTO unresolved_product (normalized_name, origin, occurrences, first_seen_at, last_seen_at) "
                "VALUES (?, ?, 1, ?, ?) ON CONFLICT (normalized_name, origin) "
                "DO UPDATE SET occurrences = occurrences + 1, last_seen_at = excluded.last_seen_at",
                (normalized_name, origin, now, now))

    def top_unresolved_products(self, limit: int = 50, origin: Optional[str] = None) -> List[UnresolvedRecord]:
        """
        Devuelve los nombres que más veces han quedado sin resolver, el peor primero.

        Args:
            limit: Cuántos como mucho. Por defecto 50.
            origin: Sólo los de ese origen (``"network"`` o ``"inventory"``);
                ``None`` para todos. Por defecto ``None``.

        Returns:
            List[UnresolvedRecord]: Ordenados por apariciones y luego por nombre.
        """
        where, parameters = ("WHERE origin = ?", [origin]) if origin else ("", [])
        rows = self._rows(f"SELECT * FROM unresolved_product {where} "
                          "ORDER BY occurrences DESC, normalized_name ASC LIMIT ?", parameters + [limit])
        return [UnresolvedRecord(row["normalized_name"], row["origin"], row["occurrences"],
                                 _to_datetime(row["first_seen_at"]), _to_datetime(row["last_seen_at"]))
                for row in rows]

    # ------------------------------------------------------------ distribuciones

    def distro_package_status(self, vendor: str, release: Optional[str],
                              package: str, cve_id: str) -> Optional[tuple]:
        """
        Dice qué afirma una distribución sobre un paquete y una CVE.

        Un aviso sin ``release`` vale para todas las versiones de la
        distribución; el que la nombra manda sobre él.

        Args:
            vendor: La distribución.
            release: Su versión, o ``None`` si no se sabe.
            package: El paquete fuente.
            cve_id: La CVE.

        Returns:
            Optional[tuple]: ``(status, fixed_in)``, o ``None`` si no se ha
                pronunciado, que no es lo mismo que decir que está a salvo.
        """
        rows = self._rows("SELECT release, status, fixed_in FROM distro_pkg_status "
                          "WHERE vendor = ? AND package = ? AND cve_id = ? ORDER BY id",
                          (vendor, package, cve_id))
        specific = [row for row in rows if release and row["release"] == release]
        generic = [row for row in rows if row["release"] is None]
        chosen = specific or generic
        return (chosen[0]["status"], chosen[0]["fixed_in"]) if chosen else None

    def distro_release_for(self, vendor: str, package: str, version: str) -> Optional[str]:
        """
        Deduce qué versión de la distribución trae un paquete, dada su versión exacta.

        Ubuntu firma la revisión sin la versión de la distribución
        (``9.6p1-3ubuntu13.19`` no dice «24.04»), pero cada versión empaqueta su
        propia versión upstream. La que tiene correcciones con la misma versión
        upstream que el paquete instalado es la suya.

        Args:
            vendor: La distribución.
            package: El paquete fuente.
            version: La versión instalada, con su revisión.

        Returns:
            Optional[str]: La versión de la distribución, o ``None`` si no
                encaja ninguna o encajan varias (no se adivina).
        """
        upstream = split_distro_version(version)[1]
        rows = self._rows("SELECT DISTINCT release, fixed_in FROM distro_pkg_status "
                          "WHERE vendor = ? AND package = ? AND release IS NOT NULL "
                          "AND fixed_in IS NOT NULL", (vendor, package))
        releases = {row["release"] for row in rows if split_distro_version(row["fixed_in"])[1] == upstream}
        return releases.pop() if len(releases) == 1 else None

    def distro_statuses_for_cve(self, cve_id: str) -> List[DistroStatus]:
        """
        Devuelve todo lo que las distribuciones han dicho de una CVE.

        Args:
            cve_id: La CVE, en mayúsculas.

        Returns:
            List[DistroStatus]: Por distribución, versión y paquete; vacía si
                ninguna la menciona.
        """
        rows = self._rows("SELECT * FROM distro_pkg_status WHERE cve_id = ? "
                          "ORDER BY vendor, release, package", (cve_id,))
        return [DistroStatus(row["vendor"], row["release"], row["package"], row["cve_id"],
                             row["fixed_in"], row["status"]) for row in rows]

    # ------------------------------------------------------------ descubrimiento

    def recent_cves_for_products(self, products: List[Tuple[str, str]], since: datetime,
                                 min_cvss: Optional[float] = None,
                                 limit_per_product: int = 5) -> List[Tuple[str, str, CveRecord]]:
        """
        Devuelve las CVE recientes de unos productos, sin mirar versiones.

        Responde otra pregunta que :meth:`cves_for_cpe` («qué ha sido notable en
        este producto», no «¿esta versión es vulnerable?»), así que aquí una
        regla sin límites de versión sí cuenta.

        Args:
            products: Pares ``(vendor, product)``.
            since: Sólo CVE publicadas desde este instante.
            min_cvss: Suelo de CVSS; las CVE sin puntuar se conservan, porque
                sin puntuar significa «aún no analizada», no «inofensiva». Por
                defecto ``None``.
            limit_per_product: Las N más nuevas por producto, para que uno
                ruidoso no desplace a los demás. Por defecto 5.

        Returns:
            List[Tuple[str, str, CveRecord]]: ``(vendor, product, cve)``, la
                más nueva primero dentro de cada producto.
        """
        results: List[Tuple[str, str, CveRecord]] = []
        for vendor, product in products:
            parameters: list = [vendor, product, _to_text(since)]
            floor = ""
            if min_cvss is not None:
                floor = "AND (c.cvss_score IS NULL OR c.cvss_score >= ?)"
                parameters.append(min_cvss)
            rows = self._rows(
                "SELECT DISTINCT c.* FROM cve c JOIN cpe_match m ON m.cve_rowid = c.id "
                "WHERE m.vendor = ? AND m.product = ? AND c.published IS NOT NULL AND c.published >= ? "
                f"{floor} ORDER BY c.published DESC LIMIT ?", parameters + [limit_per_product])
            results.extend((vendor, product, _cve_from_row(row)) for row in rows)
        return results

    def search_products(self, term: str, limit: int = 20) -> List[Tuple[str, str, str]]:
        """
        Busca productos del índice cuyo nombre empieza por ``term``.

        Args:
            term: El principio del nombre; se ignoran mayúsculas y espacios de
                los extremos.
            limit: Cuántos como mucho. Por defecto 20.

        Returns:
            List[Tuple[str, str, str]]: ``(vendor, product, nombre)``, por orden
                alfabético; vacía si ``term`` está vacío.
        """
        term = (term or "").strip().lower()
        if not term:
            return []
        escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        rows = self._rows("SELECT vendor, product, normalized_name FROM cpe_product_alias "
                          "WHERE normalized_name LIKE ? ESCAPE '\\' ORDER BY normalized_name LIMIT ?",
                          (f"{escaped}%", limit))
        return [(row[0], row[1], row[2]) for row in rows]

    def get_cves_with_matches(self, cve_ids: List[str]) -> List[CveRecord]:
        """
        Devuelve varias CVE con todas sus reglas de aplicabilidad.

        Args:
            cve_ids: Las CVE.

        Returns:
            List[CveRecord]: Las que existen, cada una con ``cpe_matches``.
        """
        if not cve_ids:
            return []
        marks = ",".join("?" * len(cve_ids))
        cves = {row["id"]: _cve_from_row(row)
                for row in self._rows(f"SELECT * FROM cve WHERE cve_id IN ({marks})", cve_ids)}
        if cves:
            keys = ",".join("?" * len(cves))
            for row in self._rows(f"SELECT * FROM cpe_match WHERE cve_rowid IN ({keys}) ORDER BY id",
                                  list(cves)):
                cves[row["cve_rowid"]].cpe_matches.append(
                    CpeMatchRecord(**{column: row[column] for column in _MATCH_COLUMNS}))
        return list(cves.values())

    # ------------------------------------------------------------ estado

    def knowledge_state(self) -> Dict[str, Optional[datetime]]:
        """
        Devuelve la fecha más nueva que trae cada fuente, tal como está ahora.

        Es lo que hace reproducible un hallazgo: dos escaneos del mismo
        objetivo pueden discrepar porque cambió el objetivo **o** porque la base
        aprendió algo entretanto. OVAL no tiene fecha propia en sus filas, así
        que se usa el último éxito de su sincronización, el **más antiguo** de
        todas las distribuciones.

        Returns:
            dict: ``{"nvd": datetime | None, "kev": ..., "epss": ..., "oval": ...}``;
                ``None`` en una fuente vacía.
        """
        return {
            "nvd": _to_datetime(self._value("SELECT MAX(last_modified) FROM cve")),
            "kev": _to_datetime(self._value("SELECT MAX(date_added) FROM kev")),
            "epss": _to_datetime(self._value("SELECT MAX(scored_at) FROM epss")),
            "oval": _to_datetime(self._value(
                "SELECT MIN(last_success_at) FROM sync_status WHERE source LIKE 'oval:%'")),
        }

    def counts(self) -> Dict[str, int]:
        """
        Cuenta las filas de cada tabla principal.

        Returns:
            dict: ``cves``, ``cpeMatches``, ``kev``, ``epss`` y ``distroPkgStatus``.
        """
        return {
            "cves": self._value("SELECT COUNT(*) FROM cve"),
            "cpeMatches": self._value("SELECT COUNT(*) FROM cpe_match"),
            "kev": self._value("SELECT COUNT(*) FROM kev"),
            "epss": self._value("SELECT COUNT(*) FROM epss"),
            "distroPkgStatus": self._value("SELECT COUNT(*) FROM distro_pkg_status"),
        }

    def has_content(self) -> Dict[str, bool]:
        """
        Dice si cada fuente tiene algo dentro, por nombre de fuente.

        Distingue «nunca sincronizada» de «vacía»: una base importada de otro
        sitio tiene contenido sin haber sincronizado nunca, y avisar de que está
        vieja sería un falso positivo. OVAL va por distribución
        (``oval:<vendor>[:<release>]``), igual que se sincroniza.

        Returns:
            dict: ``{fuente: tiene_contenido}``.
        """
        totals = self.counts()
        filled = {"nvd": totals["cves"] > 0, "kev": totals["kev"] > 0, "epss": totals["epss"] > 0}
        for row in self._rows("SELECT DISTINCT vendor, release FROM distro_pkg_status"):
            filled[f"oval:{row[0]}:{row[1]}" if row[1] else f"oval:{row[0]}"] = True
        return filled

    def record_sync(self, source: str, rows_upserted: Optional[int] = None,
                    error: Optional[str] = None) -> None:
        """
        Anota el desenlace de un intento de sincronizar una fuente.

        Se llama siempre, salga bien o mal. Si falla, ``last_success_at`` se
        conserva: la distancia entre él y ``last_attempt_at`` es justo «cuánto
        lleva roto». Si sale bien, el error se borra: la tabla dice cómo está
        la fuente ahora, no lo que pasó alguna vez.

        Args:
            source: La fuente.
            rows_upserted: Filas escritas, si salió bien. Por defecto ``None``.
            error: El mensaje del fallo; su presencia marca el intento como
                fallido. Se recorta a 500 caracteres. Por defecto ``None``.
        """
        now = _to_text(utcnow_naive())
        with self.transaction() as db:
            db.execute("INSERT INTO sync_status (source) VALUES (?) ON CONFLICT (source) DO NOTHING", (source,))
            if error is None:
                db.execute("UPDATE sync_status SET last_attempt_at = ?, last_success_at = ?, "
                           "rows_upserted = ?, error = NULL WHERE source = ?",
                           (now, now, rows_upserted, source))
            else:
                db.execute("UPDATE sync_status SET last_attempt_at = ?, error = ? WHERE source = ?",
                           (now, error[:500], source))

    def sync_status(self) -> List[SyncRecord]:
        """
        Devuelve el estado de sincronización de cada fuente registrada.

        Returns:
            List[SyncRecord]: Por nombre de fuente.
        """
        return [SyncRecord(row["source"], _to_datetime(row["last_attempt_at"]),
                           _to_datetime(row["last_success_at"]), row["rows_upserted"], row["error"])
                for row in self._rows("SELECT * FROM sync_status ORDER BY source")]

    # ------------------------------------------------------------ escritura

    def upsert_cve(self, cve_row: dict, cpe_matches: List[dict]) -> None:
        """
        Inserta o actualiza una CVE y **sustituye** sus reglas de aplicabilidad.

        Args:
            cve_row: La CVE, con las claves de ``kb.ingest_nvd_cve``.
            cpe_matches: Sus reglas, con las claves de ``kb.ingest_nvd_cve``.
        """
        columns = [column for column in _CVE_COLUMNS if column in cve_row]
        values = [_stored(column, cve_row[column]) for column in columns]
        updates = ", ".join(f"{column} = excluded.{column}" for column in columns if column != "cve_id")
        with self.transaction() as db:
            rowid = db.execute(
                f"INSERT INTO cve ({', '.join(columns)}) VALUES ({', '.join('?' * len(columns))}) "
                f"ON CONFLICT (cve_id) DO UPDATE SET {updates} RETURNING id", values).fetchone()[0]
            db.execute("DELETE FROM cpe_match WHERE cve_rowid = ?", (rowid,))
            db.executemany(
                f"INSERT INTO cpe_match (cve_rowid, {', '.join(_MATCH_COLUMNS)}) "
                f"VALUES (?, {', '.join('?' * len(_MATCH_COLUMNS))})",
                [(rowid, *(match.get(column) for column in _MATCH_COLUMNS)) for match in cpe_matches])

    def upsert_kev(self, kev_row: dict) -> None:
        """
        Inserta o actualiza una entrada de KEV.

        Args:
            kev_row: La entrada, con las claves de ``kb.ingest_kev``.
        """
        self._upsert("kev", "cve_id", kev_row)

    def bulk_upsert_epss(self, rows: List[dict]) -> int:
        """
        Inserta o actualiza muchas puntuaciones EPSS en una sola transacción.

        El feed trae una puntuación para casi cada CVE conocida (más de 300 000
        filas), así que se escribe en bloque.

        Args:
            rows: Las puntuaciones, con las claves de ``kb.parse_epss_rows``.

        Returns:
            int: Cuántas filas se escribieron.
        """
        with self.transaction() as db:
            db.executemany(
                "INSERT INTO epss (cve_id, score, percentile, scored_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT (cve_id) DO UPDATE SET score = excluded.score, "
                "percentile = excluded.percentile, scored_at = excluded.scored_at",
                [(row["cve_id"], row.get("score"), row.get("percentile"), _to_text(row.get("scored_at")))
                 for row in rows])
        return len(rows)

    def upsert_distro_pkg_status(self, row: dict) -> None:
        """
        Guarda lo que una distribución dice de un paquete frente a una CVE.

        Una fila sin paquete o sin CVE no dice nada aplicable y se ignora.

        Args:
            row: Con las claves ``vendor``, ``release``, ``package``,
                ``cve_id``, ``fixed_in`` y ``status``.
        """
        if not row.get("package") or not row.get("cve_id"):
            return
        with self.transaction() as db:
            db.execute(
                "INSERT INTO distro_pkg_status (vendor, release, package, cve_id, fixed_in, status) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (vendor, IFNULL(release, ''), package, cve_id) "
                "DO UPDATE SET fixed_in = excluded.fixed_in, status = excluded.status",
                (row["vendor"], row.get("release"), row["package"], row["cve_id"],
                 row.get("fixed_in"), row.get("status", "unknown")))

    def upsert_distro_advisory(self, row: dict) -> None:
        """
        Guarda la cabecera de un aviso de distribución (DSA, USN, RHSA…).

        Args:
            row: Con las claves ``advisory_id``, ``vendor``, ``title``,
                ``cve_ids`` y ``published``.
        """
        self._upsert("distro_advisory", "advisory_id", row)

    def _upsert(self, table: str, key: str, row: dict) -> None:
        """Inserta o actualiza una fila de ``table`` por su clave ``key``."""
        columns = list(row)
        updates = ", ".join(f"{column} = excluded.{column}" for column in columns if column != key)
        with self.transaction() as db:
            db.execute(
                f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({', '.join('?' * len(columns))}) "
                f"ON CONFLICT ({key}) DO UPDATE SET {updates}",
                [_stored(column, row[column]) for column in columns])

    def rebuild_cpe_product_index(self) -> int:
        """
        Reconstruye el índice de nombres de producto a partir de las reglas de NVD.

        Cada par ``(vendor, product)`` se indexa con dos claves normalizadas,
        porque un inventario y NVD nombran distinto el mismo software:

        1. El producto solo (``microsoft:edge`` → ``"edge"``): el vocabulario
           de NVD tal cual.
        2. Fabricante y producto juntos (``"microsoft edge"``): lo que muestran
           los inventarios de Windows, que la clave 1 nunca casaría.

        **La clave 1 gana si chocan**: es la lectura directa, y la 2 sólo llena
        huecos. Un nombre que corresponde a más de un par dentro de su espacio
        de claves se descarta entero (``"git"`` es de media docena de
        fabricantes): elegir uno al azar cruzaría CVE contra el software
        equivocado. Para esos casos están los alias curados del feed.

        Se borra y se rehace entero: corre una vez por sincronización, y así un
        nombre que deja de ser único sale del índice en vez de quedarse.

        Returns:
            int: Cuántos alias se escribieron.
        """
        by_product: Dict[str, set] = {}
        by_vendor_product: Dict[str, set] = {}
        for vendor, product in self._rows("SELECT DISTINCT vendor, product FROM cpe_match"):
            key = normalize_product_name(product)
            if key:
                by_product.setdefault(key, set()).add((vendor, product))
            vendor_key = normalize_product_name(f"{vendor} {product}")
            if vendor_key:
                by_vendor_product.setdefault(vendor_key, set()).add((vendor, product))

        def unambiguous(grouped: dict) -> dict:
            return {key: next(iter(pairs)) for key, pairs in grouped.items() if len(pairs) == 1}

        resolved = unambiguous(by_product)
        for key, pair in unambiguous(by_vendor_product).items():
            resolved.setdefault(key, pair)
        with self.transaction() as db:
            db.execute("DELETE FROM cpe_product_alias")
            db.executemany("INSERT INTO cpe_product_alias (normalized_name, vendor, product) VALUES (?, ?, ?)",
                           [(key, vendor, product) for key, (vendor, product) in resolved.items()])
        logger.info("KB: índice de productos reconstruido (%d alias: %d por producto, %d con fabricante)",
                    len(resolved), len(by_product), len(by_vendor_product))
        return len(resolved)


def _cve_from_row(row: sqlite3.Row, cve_column: str = "cve_id") -> CveRecord:
    """Construye un :class:`CveRecord` desde una fila que trae las columnas de ``cve``."""
    return CveRecord(
        cve_id=row[cve_column],
        published=_to_datetime(row["published"]),
        last_modified=_to_datetime(row["last_modified"]),
        cvss_score=row["cvss_score"],
        cvss_vector=row["cvss_vector"],
        severity=row["severity"],
        description=row["description"],
        cwe_ids=json.loads(row["cwe_ids"]) if row["cwe_ids"] else [],
        has_exploit_reference=bool(row["has_exploit_reference"]),
        source=row["source"],
    )
