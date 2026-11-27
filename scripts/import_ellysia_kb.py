"""Importa la base de conocimiento de EllysiaServer (PostgreSQL) a la del motor (SQLite).

Llenar NVD desde cero son unas 350 000 CVE y más de una hora bajo el límite de
peticiones de NVD sin clave. Si ya hay una instalación de EllysiaServer con la
base llena, esto la copia en minutos.

Sólo lee de PostgreSQL. Conserva los identificadores de las CVE, así que las
reglas de aplicabilidad se copian tal cual sin remapear nada. Al terminar
comprueba dos cosas: que cada tabla tiene las mismas filas en las dos bases, y
que la pregunta del motor («qué CVE afectan a este producto en esta versión»)
da la misma respuesta en las dos para una muestra de productos.

Uso::

    pip install 'lybra-engine[ellysia-import]'
    python scripts/import_ellysia_kb.py \
        --dsn postgresql://usuario:clave@127.0.0.1:15432/ellysia \
        --output /var/lib/lybra/kb.sqlite

La contraseña también puede ir en ``PGPASSWORD`` en vez de en el DSN.
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import sys
import time
from datetime import datetime
from pathlib import Path

from lybra.core.vulndata import version_in_range
from lybra.kb.store import KnowledgeBase

logger = logging.getLogger("import_ellysia_kb")

#: Tabla de EllysiaServer → (tabla del motor, columnas de origen, columnas de destino).
_TABLES = (
    ("CveEntry", "cve",
     ("id", "cve_id", "published", "last_modified", "cvss_score", "cvss_vector", "severity",
      "description", "cwe_ids", "has_exploit_reference", "source"),
     None),
    ("CpeMatch", "cpe_match",
     ("id", "cve_id", "vendor", "product", "version_start_including", "version_start_excluding",
      "version_end_including", "version_end_excluding", "exact_version", "required_os"),
     ("id", "cve_rowid", "vendor", "product", "version_start_including", "version_start_excluding",
      "version_end_including", "version_end_excluding", "exact_version", "required_os")),
    ("CpeProductAlias", "cpe_product_alias", ("normalized_name", "vendor", "product"), None),
    ("KevEntry", "kev", ("cve_id", "date_added", "due_date", "known_ransomware"), None),
    ("EpssScore", "epss", ("cve_id", "score", "percentile", "scored_at"), None),
    ("DistroAdvisory", "distro_advisory", ("advisory_id", "vendor", "title", "cve_ids", "published"), None),
    ("DistroPkgStatus", "distro_pkg_status",
     ("vendor", "release", "package", "cve_id", "fixed_in", "status"), None),
    ("UnresolvedProduct", "unresolved_product",
     ("normalized_name", "origin", "occurrences", "first_seen_at", "last_seen_at"), None),
    ("KbSyncStatus", "sync_status",
     ("source", "last_attempt_at", "last_success_at", "rows_upserted", "error"), None),
)

_CHUNK = 20_000


def _value(value):
    """
    Convierte un valor de PostgreSQL a lo que guarda la base del motor.

    Args:
        value: El valor tal como lo devuelve psycopg2.

    Returns:
        Las fechas como ISO 8601 sin zona, las listas y diccionarios (JSONB)
        como JSON, los booleanos como 0/1, y el resto tal cual.
    """
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (list, dict)):
        return json.dumps(value)
    if isinstance(value, bool):
        return int(value)
    return value


def copy_table(source, kb: KnowledgeBase, origin: str, target: str, columns, target_columns) -> int:
    """
    Copia una tabla de PostgreSQL a la base del motor, por bloques.

    Args:
        source: La conexión de psycopg2.
        kb: La base del motor.
        origin: La tabla de EllysiaServer.
        target: La tabla del motor.
        columns: Las columnas que se leen.
        target_columns: Sus nombres en el motor, o ``None`` si se llaman igual.

    Returns:
        int: Cuántas filas se copiaron.
    """
    target_columns = target_columns or columns
    insert = (f"INSERT INTO {target} ({', '.join(target_columns)}) "
              f"VALUES ({', '.join('?' * len(target_columns))})")
    total = 0
    with source.cursor(name=f"copy_{target}") as cursor, kb.transaction() as db:
        cursor.itersize = _CHUNK
        cursor.execute(f'SELECT {", ".join(columns)} FROM "{origin}"')
        while True:
            rows = cursor.fetchmany(_CHUNK)
            if not rows:
                break
            db.executemany(insert, [tuple(_value(value) for value in row) for row in rows])
            total += len(rows)
    logger.info("%s → %s: %d filas", origin, target, total)
    return total


def verify_counts(source, kb: KnowledgeBase) -> bool:
    """
    Comprueba que cada tabla tiene las mismas filas en las dos bases.

    Args:
        source: La conexión de psycopg2.
        kb: La base del motor.

    Returns:
        bool: ``True`` si coinciden todas.
    """
    matches = True
    with source.cursor() as cursor:
        for origin, target, _, _ in _TABLES:
            cursor.execute(f'SELECT COUNT(*) FROM "{origin}"')
            expected = cursor.fetchone()[0]
            got = kb._value(f"SELECT COUNT(*) FROM {target}")  # pylint: disable=protected-access
            if expected != got:
                logger.error("%s: %d filas en PostgreSQL, %d en el motor", origin, expected, got)
                matches = False
    return matches


def verify_matcher(source, kb: KnowledgeBase, samples: int) -> bool:
    """
    Comprueba que la pregunta del motor da lo mismo en las dos bases.

    Toma una muestra de reglas de aplicabilidad con una versión concreta, y
    para cada una calcula en PostgreSQL —con la misma lógica de rangos— qué
    CVE afectan a ese producto en esa versión, y lo compara con
    :meth:`KnowledgeBase.cves_for_cpe`.

    Args:
        source: La conexión de psycopg2.
        kb: La base del motor.
        samples: Cuántas consultas comparar.

    Returns:
        bool: ``True`` si coinciden todas.
    """
    with source.cursor() as cursor:
        cursor.execute('SELECT vendor, product, COALESCE(exact_version, version_end_including, '
                       'version_start_including) FROM "CpeMatch" '
                       'WHERE COALESCE(exact_version, version_end_including, version_start_including) IS NOT NULL '
                       'ORDER BY random() LIMIT %s', (samples,))
        queries = cursor.fetchall()
        mismatches = 0
        for vendor, product, version in queries:
            cursor.execute('SELECT DISTINCT c.cve_id, m.version_start_including, m.version_start_excluding, '
                           'm.version_end_including, m.version_end_excluding, m.exact_version '
                           'FROM "CpeMatch" m JOIN "CveEntry" c ON c.id = m.cve_id '
                           'WHERE m.vendor = %s AND m.product = %s', (vendor, product))
            expected = {row[0] for row in cursor.fetchall() if version_in_range(version, {
                "version_start_including": row[1], "version_start_excluding": row[2],
                "version_end_including": row[3], "version_end_excluding": row[4], "exact_version": row[5]})}
            got = {cve.cve_id for cve in kb.cves_for_cpe(vendor, product, version)}
            if expected != got:
                mismatches += 1
                logger.error("%s:%s %s: PostgreSQL %d CVE, motor %d", vendor, product, version,
                             len(expected), len(got))
    logger.info("Pregunta del motor: %d de %d consultas coinciden", len(queries) - mismatches, len(queries))
    return mismatches == 0


def main(argv=None) -> int:
    """
    Importa la base y la verifica.

    Args:
        argv: Los argumentos de la línea de órdenes; ``None`` usa ``sys.argv``.

    Returns:
        int: 0 si se importó y las dos verificaciones pasan; 1 si no; 2 si el
            destino ya tiene datos.
    """
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", maxsplit=1)[0])
    parser.add_argument("--dsn", required=True, help="DSN de PostgreSQL de EllysiaServer")
    parser.add_argument("--output", required=True, type=Path, help="Fichero SQLite de destino (nuevo)")
    parser.add_argument("--samples", type=int, default=500, help="Consultas del motor que comparar")
    arguments = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

    import psycopg2  # pylint: disable=import-outside-toplevel

    kb = KnowledgeBase(arguments.output)
    if kb.counts()["cves"]:
        logger.error("%s ya tiene datos; la importación sólo llena una base vacía", arguments.output)
        return 2
    started = time.monotonic()
    with psycopg2.connect(arguments.dsn) as source:
        source.set_session(readonly=True)
        for origin, target, columns, target_columns in _TABLES:
            copy_table(source, kb, origin, target, columns, target_columns)
        logger.info("Copia terminada en %.0f s", time.monotonic() - started)
        random.seed(0)
        counts_ok = verify_counts(source, kb)
        matcher_ok = verify_matcher(source, kb, arguments.samples)
    logger.info("Recuentos: %s", json.dumps(kb.counts()))
    return 0 if counts_ok and matcher_ok else 1


if __name__ == "__main__":
    sys.exit(main())
