"""La sincronización de la base de conocimiento, con las descargas sustituidas.

Los lectores de red (``fetch_kev``, ``fetch_epss``, ``fetch_oval`` e
``iter_nvd_pages``) se cambian por funciones que devuelven documentos con la
forma real de cada fuente, así que se ejercita todo menos la descarga: el
parseo, la escritura, el aislamiento entre fuentes y la anotación del estado.
"""

from __future__ import annotations

import gzip
import json
from datetime import datetime

import pytest

from lybra.kb import sync as kb_sync
from lybra.kb.queries import KnowledgeBasePhases
from lybra.kb.sync import KnowledgeBaseSync, SyncSettings
from lybra.kb.store import KnowledgeBase
from lybra.core.scanner import ScanRequest, ScanSettings, run_scan
from lybra.core.engine import Service

pytestmark = pytest.mark.unit

_NVD_ITEM = {"cve": {
    "id": "CVE-2021-41773",
    "published": "2021-10-05T12:15:07.777",
    "lastModified": "2022-01-01T00:00:00.000",
    "descriptions": [{"lang": "en", "value": "Path traversal in Apache 2.4.49"}],
    "metrics": {"cvssMetricV31": [{"cvssData": {
        "baseScore": 7.5, "vectorString": "CVSS:3.1/AV:N", "baseSeverity": "HIGH"}}]},
    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-22"}]}],
    "configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
    ]}]}],
}}

_KEV = [{"cveID": "CVE-2021-41773", "dateAdded": "2021-11-03", "dueDate": "2021-11-17",
         "knownRansomwareCampaignUse": "Known"}]

_EPSS = gzip.decompress(gzip.compress(
    b"#model_version:v2025.03.14,score_date:2026-11-23T00:00:00+0000\n"
    b"cve,epss,percentile\nCVE-2021-41773,0.94,0.99\n")).decode()

_CSAF = json.dumps({
    "document": {"tracking": {"id": "RHSA-2024:0001"}},
    "vulnerabilities": [{"cve": "CVE-2021-41773", "product_status": {
        "fixed": ["AppStream-9.3.0.Z.MAIN:httpd-0:2.4.57-5.el9.x86_64"]}}],
}).encode()


@pytest.fixture
def kb(tmp_path):
    base = KnowledgeBase(tmp_path / "kb.sqlite")
    yield base
    base.close()


@pytest.fixture
def feeds(monkeypatch):
    """Sustituye las descargas por los documentos de arriba y apunta cada petición."""
    requested = []
    monkeypatch.setattr(kb_sync, "fetch_kev", lambda url: requested.append(url) or _KEV)
    monkeypatch.setattr(kb_sync, "fetch_epss", lambda url: requested.append(url) or _EPSS)
    monkeypatch.setattr(kb_sync, "fetch_oval", lambda url: requested.append(url) or _CSAF)

    def nvd_pages(base_url, start, end, api_key=None):
        requested.append((base_url, start, end))
        yield _NVD_ITEM

    monkeypatch.setattr(kb_sync, "iter_nvd_pages", nvd_pages)
    return requested


def _settings(**sources):
    default = {"nvd": "https://nvd.invalid", "kev": "https://kev.invalid", "epss": "https://epss.invalid",
               "oval": {"rhel": "https://rhel.invalid/csaf.json"}}
    default.update(sources)
    return SyncSettings(sources=default)


def _sync(kb, settings=None):
    return KnowledgeBaseSync(kb, settings or _settings(), sleep=lambda _seconds: None)


def test_a_full_sync_fills_every_source_and_the_product_index(kb, feeds):
    summary = _sync(kb).sync_all()

    assert summary == {"kev": 1, "epss": 1, "oval:rhel": 1, "nvd": 1, "cpeProductAliases": 2}
    assert kb.cves_for_cpe("apache", "http_server", "2.4.49")[0].cvss_score == 7.5
    assert kb.is_in_kev("CVE-2021-41773")
    assert kb.epss_score("CVE-2021-41773") == 0.94
    assert kb.resolve_product_alias("http server") == ("apache", "http_server")
    assert kb.distro_statuses_for_cve("CVE-2021-41773")
    assert all(record.error is None for record in kb.sync_status())


def test_a_broken_source_costs_only_itself(kb, feeds, monkeypatch):
    """Una URL caída de EPSS no puede dejar sin KEV ni sin NVD a nadie: se
    anota su error y las demás siguen."""
    def broken(url):
        raise ConnectionError("503 desde el feed")

    monkeypatch.setattr(kb_sync, "fetch_epss", broken)

    summary = _sync(kb).sync_all()

    assert summary["epss"] is None
    assert summary["kev"] == 1 and summary["nvd"] == 1
    records = {record.source: record for record in kb.sync_status()}
    assert records["epss"].error == "ConnectionError: 503 desde el feed"
    assert records["epss"].last_success_at is None
    assert records["kev"].error is None


def test_a_failed_nvd_sync_does_not_rebuild_the_index(kb, feeds, monkeypatch):
    def broken(*args, **kwargs):
        raise TimeoutError("NVD no contesta")
        yield  # pragma: no cover

    monkeypatch.setattr(kb_sync, "iter_nvd_pages", broken)

    summary = _sync(kb).sync_all(only="nvd")

    assert summary == {"nvd": None}


def test_only_one_source_can_be_synced(kb, feeds):
    assert _sync(kb).sync_all(only="kev") == {"kev": 1}
    assert _sync(kb).sync_all(only="oval") == {"oval:rhel": 1}
    with pytest.raises(ValueError):
        _sync(kb).sync_all(only="shodan")


def test_an_oval_entry_that_is_not_a_url_is_recorded_as_a_failure(kb, feeds):
    summary = _sync(kb, _settings(oval={"debian:12": "debian.org/oval.xml"})).sync_all(only="oval")

    assert summary == {"oval:debian:12": None}
    assert "no es una URL" in kb.sync_status()[0].error


def test_a_long_nvd_backfill_is_cut_into_windows_nvd_filters_correctly(kb, feeds):
    """Pasados unos 20 días NVD ignora el filtro de fechas y devuelve el
    catálogo entero: un mes se pide en tres ventanas, con pausa entre ellas."""
    pauses = []
    sync = KnowledgeBaseSync(kb, _settings(), sleep=pauses.append)

    sync.sync_nvd_backfill("https://nvd.invalid", datetime(2026, 1, 1), datetime(2026, 2, 1))

    windows = [request[1:] for request in feeds if isinstance(request, tuple)]
    assert windows == [
        ("2026-01-01T00:00:00.000", "2026-01-15T00:00:00.000"),
        ("2026-01-15T00:00:00.000", "2026-01-29T00:00:00.000"),
        ("2026-01-29T00:00:00.000", "2026-02-01T00:00:00.000"),
    ]
    assert pauses == [6.0, 6.0]


def test_a_synced_base_drives_a_scan_of_known_services(kb, feeds):
    """De la sincronización al hallazgo: un inventario con Apache 2.4.49 sale
    con su CVE, en KEV y con EPSS, sin tocar la red."""
    _sync(kb).sync_all()
    services = [Service(port=None, protocol="", product="Apache httpd", version="2.4.49", origin="inventory")]

    outcome = run_scan(ScanRequest(target="srv-01", services=services),
                       KnowledgeBasePhases(kb, ScanSettings(reachability_check=False)))

    finding = next(finding for finding in outcome.findings if finding.get("cve_ids"))
    assert finding["cve_ids"] == ["CVE-2021-41773"]
    assert finding["in_kev"] is True and finding["epss_score"] == 0.94
    assert finding["confirmed"] is True
    assert finding["feed_version"].startswith("lybra-kb:")


def test_the_status_after_a_sync_is_fresh(kb, feeds):
    _sync(kb).sync_all()

    status = _sync(kb).status()

    assert status["isStale"] is False
    assert {entry["source"] for entry in status["sources"]} == {"nvd", "kev", "epss", "oval:rhel"}
    assert all(entry["ageDays"] == 0 for entry in status["sources"])


def test_nvd_pause_constants_and_backfill(kb, feeds):
    from lybra.core.vulndata import NVD_PAUSE_NO_KEY, NVD_PAUSE_WITH_KEY, iter_nvd_pages
    assert NVD_PAUSE_NO_KEY == 6.0
    assert NVD_PAUSE_WITH_KEY == 0.65

    # Test iter_nvd_pages pause selection (we can mock _http_get)
    from lybra.core import vulndata
    slept = []
    monkeypatch_sleep = lambda s: slept.append(s)
    
    # Test backfill_nvd
    sync = KnowledgeBaseSync(kb, _settings(), sleep=monkeypatch_sleep)
    events = []
    res = sync.backfill_nvd(datetime(2026, 1, 1), datetime(2026, 1, 3), api_key="test-key", on_progress=events.append)
    assert res["cves"] >= 1
    assert res["usedApiKey"] is True
    assert events
    assert any(e["phase"] == "backfill" for e in events)
    assert any(e["phase"] == "index" for e in events)

    # Test backfill_nvd missing source or invalid range
    sync_no_nvd = KnowledgeBaseSync(kb, SyncSettings(sources={}), sleep=monkeypatch_sleep)
    with pytest.raises(ValueError, match="no está configurada"):
        sync_no_nvd.backfill_nvd(datetime(2026, 1, 2), datetime(2026, 1, 1))

    with pytest.raises(ValueError, match="tiene que ser anterior"):
        sync.backfill_nvd(datetime(2026, 1, 2), datetime(2026, 1, 1))


def test_backfill_reports_progress_per_batch_within_a_window(kb, monkeypatch):
    from lybra.kb import sync as sync_mod

    fake_items = [
        {"cve": {"id": f"CVE-2026-{i:04d}", "descriptions": [{"lang": "en", "value": "d"}],
                 "lastModified": "2026-01-02T00:00:00.000"}}
        for i in range(5)
    ]
    monkeypatch.setattr(sync_mod, "NVD_BATCH_SIZE", 2)
    monkeypatch.setattr(sync_mod, "iter_nvd_pages", lambda *a, **kw: iter(fake_items))

    events = []
    sync = KnowledgeBaseSync(kb, _settings(), sleep=lambda _s: None)
    total = sync.sync_nvd_backfill("https://nvd.invalid", datetime(2026, 1, 1), datetime(2026, 1, 5),
                                   on_progress=events.append)

    assert total == 5
    assert [(e["done"], e["cves"]) for e in events] == [(0, 0), (0, 2), (0, 4), (1, 5)]
