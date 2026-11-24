"""La base de conocimiento local: la pregunta del motor, el índice de productos y el estado.

Cada test abre una base SQLite nueva en un directorio temporal, la llena con
filas con la forma que producen los ingestores de ``kb`` y le pregunta. Nada
sale a la red.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta

import pytest

from lybra._shared import utcnow_naive
from lybra.kb_queries import advisories_for_products, cve_detail, version_check
from lybra.kb_sync import KnowledgeBaseSync, SyncSettings
from lybra.knowledge_base import SCHEMA_VERSION, KnowledgeBase

pytestmark = pytest.mark.unit


@pytest.fixture
def kb(tmp_path):
    base = KnowledgeBase(tmp_path / "kb.sqlite")
    yield base
    base.close()


def _cve_row(cve_id="CVE-2021-41773", score=7.5, published=None):
    return {"cve_id": cve_id, "cvss_score": score, "cvss_vector": "CVSS:3.1/AV:N", "severity": "HIGH",
            "description": "Path traversal", "cwe_ids": ["CWE-22"], "source": "nvd", "published": published}


def _match(vendor="apache", product="http_server", **bounds):
    row = {"vendor": vendor, "product": product, "version_start_including": None,
           "version_start_excluding": None, "version_end_including": None,
           "version_end_excluding": None, "exact_version": None, "required_os": None}
    row.update(bounds)
    return row


# ============================================================ la pregunta del motor

def test_a_cve_applies_only_inside_its_version_range(kb):
    kb.upsert_cve(_cve_row(), [_match(version_start_including="2.4.0", version_end_excluding="2.4.50")])

    assert [cve.cve_id for cve in kb.cves_for_cpe("apache", "http_server", "2.4.49")] == ["CVE-2021-41773"]
    assert kb.cves_for_cpe("apache", "http_server", "2.4.50") == []
    assert kb.cves_for_cpe("apache", "tomcat", "2.4.49") == []


def test_a_platform_gated_rule_says_which_platform_it_needs(kb):
    """El motor no puede comprobar el sistema operativo exigido, así que tiene
    que saber que la regla lo exige para no darlo por confirmado."""
    kb.upsert_cve(_cve_row(), [_match(exact_version="2.4.59", required_os="windows_10")])

    hit = kb.cves_for_cpe("apache", "http_server", "2.4.59")

    assert hit[0].required_os == "windows_10"


def test_an_unconditional_rule_wins_over_a_platform_gated_one(kb):
    """Si una sola de las reglas que casan es incondicional, la CVE aplica sin
    más: la condición de la otra no puede colarse en el resultado."""
    kb.upsert_cve(_cve_row(), [
        _match(exact_version="2.4.59", required_os="windows_10"),
        _match(version_start_including="2.4.0", version_end_excluding="2.4.60"),
    ])

    hit = kb.cves_for_cpe("apache", "http_server", "2.4.59")

    assert [cve.cve_id for cve in hit] == ["CVE-2021-41773"]
    assert hit[0].required_os is None


def test_re_syncing_a_cve_updates_it_and_replaces_its_rules(kb):
    kb.upsert_cve(_cve_row(score=7.5), [_match(exact_version="2.4.49")])
    kb.upsert_cve(_cve_row(score=9.8), [_match(exact_version="2.4.50")])

    assert kb.counts()["cves"] == 1
    assert kb.counts()["cpeMatches"] == 1
    assert kb.cves_for_cpe("apache", "http_server", "2.4.49") == []
    assert kb.cves_for_cpe("apache", "http_server", "2.4.50")[0].cvss_score == 9.8


def test_kev_epss_and_exploit_evidence_are_answered(kb):
    kb.upsert_cve(dict(_cve_row(), has_exploit_reference=True), [])
    kb.upsert_kev({"cve_id": "CVE-2021-41773", "known_ransomware": True, "date_added": None, "due_date": None})
    kb.bulk_upsert_epss([{"cve_id": "CVE-2021-41773", "score": 0.97, "percentile": 0.99, "scored_at": None}])

    assert kb.get_kev("CVE-2021-41773").known_ransomware is True
    assert kb.is_in_kev("CVE-2021-41773") and not kb.is_in_kev("CVE-2000-0001")
    assert kb.epss_score("CVE-2021-41773") == 0.97
    assert kb.exploit_evidence("CVE-2021-41773") == "poc"
    assert kb.exploit_evidence("CVE-2000-0001") is None


# ============================================================ índice de productos

def test_unambiguous_names_resolve_by_product_and_by_vendor_and_product(kb):
    kb.upsert_cve(_cve_row("CVE-1111-1111"), [_match("7-zip", "7-zip", exact_version="1.0")])
    kb.upsert_cve(_cve_row("CVE-7777-7777"), [_match("microsoft", "edge", exact_version="1.0")])

    assert kb.rebuild_cpe_product_index() == 4
    assert kb.resolve_product_alias("7 zip") == ("7-zip", "7-zip")
    assert kb.resolve_product_alias("microsoft edge") == ("microsoft", "edge")
    assert kb.resolve_product_alias("edge") == ("microsoft", "edge")
    assert kb.resolve_product_alias("totally unknown app") is None


def test_the_product_key_wins_over_a_colliding_vendor_key(kb):
    """«adobe reader» es a la vez un nombre de producto y un nombre con
    fabricante; gana la lectura directa en vez de descartarse por ambiguo."""
    kb.upsert_cve(_cve_row("CVE-8888-8888"), [_match("adobe", "adobe_reader", exact_version="1.0")])
    kb.upsert_cve(_cve_row("CVE-9999-9999"), [_match("adobe", "reader", exact_version="1.0")])
    kb.rebuild_cpe_product_index()

    assert kb.resolve_product_alias("adobe reader") == ("adobe", "adobe_reader")


def test_an_ambiguous_name_is_never_guessed(kb):
    """«git» es de varios fabricantes sin relación: elegir uno cruzaría CVE
    contra el software equivocado."""
    kb.upsert_cve(_cve_row("CVE-3333-3333"), [_match("git-scm", "git", exact_version="1.0")])
    kb.upsert_cve(_cve_row("CVE-4444-4444"), [_match("jenkins", "git", exact_version="1.0")])

    assert kb.rebuild_cpe_product_index() == 2
    assert kb.resolve_product_alias("git") is None
    assert kb.resolve_product_alias("jenkins git") == ("jenkins", "git")


def test_a_name_that_stops_being_unique_leaves_the_index(kb):
    kb.upsert_cve(_cve_row("CVE-5555-5555"), [_match("solo-vendor", "widget", exact_version="1.0")])
    kb.rebuild_cpe_product_index()
    assert kb.resolve_product_alias("widget") == ("solo-vendor", "widget")

    kb.upsert_cve(_cve_row("CVE-6666-6666"), [_match("other-vendor", "widget", exact_version="1.0")])
    kb.rebuild_cpe_product_index()

    assert kb.resolve_product_alias("widget") is None


def test_products_are_searched_by_prefix_and_wildcards_are_literal(kb):
    kb.upsert_cve(_cve_row(), [_match("microsoft", "windows")])
    kb.rebuild_cpe_product_index()

    assert ("microsoft", "windows") in [(v, p) for v, p, _ in kb.search_products("wind")]
    assert ("microsoft", "windows") in [(v, p) for v, p, _ in kb.search_products("microsoft win")]
    assert kb.search_products("%") == []
    assert kb.search_products("") == []


# ============================================================ descubrimiento

_NOW = datetime(2026, 8, 1)


def test_recent_cves_are_filtered_by_date_newest_first_and_include_unbounded_rules(kb):
    """Una regla sin límites de versión es ruido para el matcher pero noticia
    para «qué ha pasado en este producto»: por eso son dos consultas."""
    for cve_id, days in (("CVE-2026-0001", 10), ("CVE-2026-0002", 2), ("CVE-2019-9999", 2500)):
        kb.upsert_cve(_cve_row(cve_id, published=_NOW - timedelta(days=days)), [_match("microsoft", "windows")])

    rows = kb.recent_cves_for_products([("microsoft", "windows")], since=_NOW - timedelta(days=365))

    assert [cve.cve_id for _, _, cve in rows] == ["CVE-2026-0002", "CVE-2026-0001"]
    assert kb.cves_for_cpe("microsoft", "windows", "10.0.19041") == []


def test_a_cvss_floor_keeps_unscored_cves(kb):
    """Sin puntuación significa «aún no analizada», no «inofensiva»."""
    for cve_id, score in (("CVE-2026-0201", 9.8), ("CVE-2026-0202", 2.1), ("CVE-2026-0203", None)):
        kb.upsert_cve(_cve_row(cve_id, score=score, published=_NOW), [_match("microsoft", "windows")])

    rows = kb.recent_cves_for_products([("microsoft", "windows")], since=_NOW - timedelta(days=1), min_cvss=7.0)

    assert sorted(cve.cve_id for _, _, cve in rows) == ["CVE-2026-0201", "CVE-2026-0203"]


def test_advisories_come_enriched_with_kev_and_epss(kb):
    kb.upsert_cve(_cve_row("CVE-2026-0401", published=_NOW - timedelta(days=1)), [_match("microsoft", "windows")])
    kb.upsert_cve(_cve_row("CVE-2026-0402", published=_NOW - timedelta(days=3)), [_match("microsoft", "windows")])
    kb.upsert_kev({"cve_id": "CVE-2026-0401", "known_ransomware": False, "date_added": None, "due_date": None})
    kb.bulk_upsert_epss([{"cve_id": "CVE-2026-0401", "score": 0.87, "percentile": 0.99, "scored_at": None}])

    exploited, quiet = advisories_for_products(kb, [("microsoft", "windows")], since=_NOW - timedelta(days=365))

    assert (exploited.cve_id, exploited.kev, exploited.epss) == ("CVE-2026-0401", True, 0.87)
    assert exploited.url == "https://nvd.nist.gov/vuln/detail/CVE-2026-0401"
    assert (quiet.kev, quiet.epss) == (False, None)


def test_a_cve_detail_joins_every_source(kb):
    kb.upsert_cve(_cve_row(), [_match()])
    kb.upsert_distro_pkg_status({"vendor": "debian", "release": "12", "package": "apache2",
                                 "cve_id": "CVE-2021-41773", "fixed_in": "2.4.51-1", "status": "fixed"})

    detail = cve_detail(kb, "CVE-2021-41773")

    assert detail["products"] == [{"vendor": "apache", "product": "http_server"}]
    assert detail["distroStatuses"][0]["fixedIn"] == "2.4.51-1"
    assert detail["inKev"] is False
    assert cve_detail(kb, "CVE-2000-0001") is None


def test_a_version_check_goes_through_the_engine_without_counting_unresolved_names(kb):
    kb.upsert_cve(_cve_row(), [_match(version_start_including="2.4.0", version_end_excluding="2.4.50")])

    vulnerable = version_check(kb, "Apache httpd", "2.4.49")
    unknown = version_check(kb, "chachiservidor", "1.0")

    assert [cve["cveId"] for cve in vulnerable["cves"]] == ["CVE-2021-41773"]
    assert unknown["recognized"] is False
    assert kb.top_unresolved_products() == []


# ============================================================ distribuciones

def _ubuntu(release, fixed_in, cve_id="CVE-2024-6387"):
    return {"vendor": "ubuntu", "release": release, "package": "openssh", "cve_id": cve_id,
            "fixed_in": fixed_in, "status": "fixed"}


def test_the_ubuntu_release_is_deduced_from_the_upstream_version_of_its_fixes(kb):
    """`9.6p1-3ubuntu13.19` no dice «24.04», pero sólo 24.04 empaqueta 9.6p1."""
    kb.upsert_distro_pkg_status(_ubuntu("24.04", "1:9.6p1-3ubuntu13.3"))
    kb.upsert_distro_pkg_status(_ubuntu("22.04", "1:8.9p1-3ubuntu0.10"))

    noble = kb.distro_release_for("ubuntu", "openssh", "9.6p1-3ubuntu13.19")

    assert noble == "24.04"
    assert kb.distro_release_for("ubuntu", "openssh", "8.9p1-3ubuntu0.13") == "22.04"
    assert kb.distro_release_for("ubuntu", "openssh", "7.2p2-4ubuntu2.10") is None
    assert kb.distro_package_status("ubuntu", noble, "openssh", "CVE-2024-6387") == ("fixed", "1:9.6p1-3ubuntu13.3")


def test_an_ambiguous_release_is_not_guessed(kb):
    kb.upsert_distro_pkg_status(_ubuntu("24.04", "1:9.6p1-3ubuntu13.3"))
    kb.upsert_distro_pkg_status(_ubuntu("24.10", "1:9.6p1-3ubuntu14.1"))

    assert kb.distro_release_for("ubuntu", "openssh", "9.6p1-3ubuntu13.19") is None


def test_a_specific_release_wins_over_a_generic_advisory_and_null_releases_do_not_duplicate(kb):
    generic = {"vendor": "rhel", "release": None, "package": "openssl", "cve_id": "CVE-2024-1",
               "fixed_in": "3.0.7-1", "status": "fixed"}
    kb.upsert_distro_pkg_status(generic)
    kb.upsert_distro_pkg_status(dict(generic, fixed_in="3.0.7-2"))
    kb.upsert_distro_pkg_status(dict(generic, release="9", status="not_affected", fixed_in=None))

    assert kb.counts()["distroPkgStatus"] == 2
    assert kb.distro_package_status("rhel", "9", "openssl", "CVE-2024-1") == ("not_affected", None)
    assert kb.distro_package_status("rhel", "8", "openssl", "CVE-2024-1") == ("fixed", "3.0.7-2")
    assert kb.distro_package_status("rhel", "8", "openssl", "CVE-2099-1") is None


# ============================================================ nombres sin resolver

def test_unresolved_names_are_ranked_and_a_resolution_removes_them(kb):
    for _ in range(3):
        kb.record_resolution("chachiservidor", "network", False)
    kb.record_resolution("chachiservidor", "inventory", False)
    kb.record_resolution("apache http server", "network", True)

    top = [(row.normalized_name, row.origin, row.occurrences) for row in kb.top_unresolved_products()]
    assert top == [("chachiservidor", "network", 3), ("chachiservidor", "inventory", 1)]

    kb.record_resolution("chachiservidor", "network", True)
    assert [row.origin for row in kb.top_unresolved_products()] == ["inventory"]


# ============================================================ estado

def _sources():
    return {"nvd": "https://nvd.invalid", "kev": "https://kev.invalid", "epss": "https://epss.invalid",
            "oval": {"debian:12": "https://debian.invalid", "ubuntu:24.04": "https://ubuntu.invalid"}}


def _status(kb):
    status = KnowledgeBaseSync(kb, SyncSettings(sources=_sources())).status()
    return status, {entry["source"]: entry for entry in status["sources"]}


def test_a_failed_sync_keeps_the_last_success_and_a_good_one_clears_the_error(kb):
    kb.record_sync("nvd", rows_upserted=120)
    kb.record_sync("nvd", error="503 desde el feed")
    record = {record.source: record for record in kb.sync_status()}["nvd"]
    assert record.last_success_at is not None and record.last_attempt_at >= record.last_success_at
    assert (record.error, record.rows_upserted) == ("503 desde el feed", 120)

    kb.record_sync("nvd", rows_upserted=9)
    record = {record.source: record for record in kb.sync_status()}["nvd"]
    assert (record.error, record.rows_upserted) == (None, 9)


def test_every_configured_source_is_reported_even_if_never_synced(kb):
    status, by_source = _status(kb)

    assert set(by_source) == {"nvd", "kev", "epss", "oval:debian:12", "oval:ubuntu:24.04"}
    assert all(entry["neverSynced"] and entry["isStale"] for entry in by_source.values())
    assert status["isStale"] is True


def test_an_aged_source_is_stale_by_its_own_threshold(kb):
    for source in ("nvd", "kev", "epss", "oval:debian:12", "oval:ubuntu:24.04"):
        kb.record_sync(source, rows_upserted=1)
    four_days_ago = (utcnow_naive() - timedelta(days=4)).isoformat()
    with kb.transaction() as db:
        db.execute("UPDATE sync_status SET last_success_at = ?", (four_days_ago,))

    _, by_source = _status(kb)

    assert by_source["nvd"]["isStale"] is True     # NVD: 3 días
    assert by_source["kev"]["isStale"] is False    # KEV: 7 días


def test_content_without_a_sync_record_is_unverified_not_stale(kb):
    """El día del despliegue de una base importada: hay cientos de miles de CVE
    y ninguna sincronización registrada. Gritar «vieja» ahí enseña a ignorar
    los avisos."""
    kb.upsert_cve(_cve_row(), [])
    kb.upsert_distro_pkg_status({"vendor": "debian", "release": "12", "package": "openssh",
                                 "cve_id": "CVE-2024-6387", "fixed_in": "1:9.2p1-2+deb12u3", "status": "fixed"})

    status, by_source = _status(kb)

    assert (by_source["nvd"]["isStale"], by_source["nvd"]["isUnverified"]) == (False, True)
    assert by_source["oval:debian:12"]["isStale"] is False
    assert by_source["oval:ubuntu:24.04"]["isStale"] is True
    assert status["isStale"] is True and status["isUnverified"] is True


def test_the_knowledge_state_reads_the_newest_date_of_each_source(kb):
    kb.upsert_cve(dict(_cve_row(), last_modified=datetime(2026, 11, 20, 8, 0)), [])

    state = kb.knowledge_state()

    assert state["nvd"] == datetime(2026, 11, 20, 8, 0)
    assert state["kev"] is None and state["epss"] is None and state["oval"] is None


# ============================================================ el fichero

def test_the_base_persists_and_rejects_a_foreign_schema(tmp_path):
    path = tmp_path / "kb.sqlite"
    first = KnowledgeBase(path)
    first.upsert_cve(_cve_row(), [_match(exact_version="2.4.49")])
    first.close()

    reopened = KnowledgeBase(path)
    assert reopened.counts()["cves"] == 1
    with reopened.transaction() as db:
        db.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    reopened.close()

    with pytest.raises(RuntimeError):
        KnowledgeBase(path)


def test_a_failed_transaction_writes_nothing(kb):
    with pytest.raises(ValueError):
        with kb.transaction():
            kb.upsert_cve(_cve_row(), [_match()])
            raise ValueError("a mitad")

    assert kb.counts()["cves"] == 0


def test_several_threads_can_read_while_another_writes(kb):
    """Un escaneo consulta mientras la sincronización escribe: cada hilo tiene su conexión."""
    kb.upsert_cve(_cve_row(), [_match(exact_version="2.4.49")])
    errors = []

    def read():
        try:
            for _ in range(50):
                assert kb.cves_for_cpe("apache", "http_server", "2.4.49")
        except Exception as error:  # pylint: disable=broad-exception-caught
            errors.append(error)

    readers = [threading.Thread(target=read) for _ in range(4)]
    for reader in readers:
        reader.start()
    for number in range(50):
        kb.upsert_cve(_cve_row(f"CVE-2026-{number:04d}"), [_match(exact_version="9.9")])
    for reader in readers:
        reader.join()

    assert errors == []
    assert kb.counts()["cves"] == 51
