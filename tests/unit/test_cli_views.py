"""Las vistas de ``lybra`` para info, kb, status, cancel, osint y cloud. Sin sockets."""

from __future__ import annotations

import io
import json

import pytest
from rich.console import Console

from lybra.app import cli
from lybra.app.ui import views
from lybra.app.ui.console import THEME
from lybra_client import LybraClient

pytestmark = pytest.mark.unit

_INFO = {"engineVersion": "0.2.0", "protocolVersions": [1], "identificationRevision": 7,
         "kb": {"feedVersion": "nvd:2026-01-01|kev:2026-01-02", "counts": {"cves": 250000, "kev": 1200}}}
_KB_STATUS = {"feedVersion": "nvd:2026-01-01", "isStale": True, "isUnverified": True, "sources": [
    {"source": "nvd", "ageDays": 0.5, "isStale": False, "isUnverified": False, "error": None},
    {"source": "kev", "ageDays": 9.0, "isStale": True, "isUnverified": False, "error": "timeout al descargar"},
    {"source": "epss", "ageDays": None, "isStale": False, "isUnverified": True, "error": None}]}
_STATUS = {"scanId": "s1", "target": "10.0.0.1", "status": "running",
           "progress": {"phase": "checks", "done": 3, "total": 10}}
_FAILED = {"scanId": "s1", "target": "10.0.0.1", "status": "failed", "progress": {"phase": None, "done": 0, "total": 0},
           "error": {"code": "scan_failed", "message": "no hay ruta al objetivo"}}
_CANCEL = {"scanId": "s1", "target": "10.0.0.1", "status": "cancelled",
           "progress": {"phase": None, "done": 0, "total": 0}}
_CVE = {"cveId": "CVE-2024-6387", "published": "2024-07-01T13:15:00Z", "cvssScore": 8.1,
        "cvssVector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "severity": "HIGH", "inKev": True,
        "description": "Una condición de carrera en el manejador de señales de sshd " * 4,
        "products": [{"vendor": "openbsd", "product": "openssh"}], "productsTotal": 9, "cweIds": ["CWE-364"],
        "epssScore": 0.123, "epssPercentile": 0.97}
_VERSION = {"recognized": True, "vendor": "nginx", "product": "nginx", "version": "1.18.0", "cvesTotal": 2,
            "cves": [{"cveId": "CVE-2021-23017", "cvssScore": 7.7, "epssScore": 0.1, "inKev": False},
                     {"cveId": "CVE-2019-9511", "cvssScore": 7.5, "epssScore": 0.5, "inKev": True}],
            "endOfLife": {"cycle": "1.18", "date": "2021-04-20", "isPast": True}}
_DOMAIN = {
    "domain": "example.com",
    "sources": [{"source": "crtsh", "label": "crt.sh", "outcome": "ok", "cached": True, "detail": None},
                {"source": "shodan", "label": "Shodan", "outcome": "failed", "cached": False, "detail": "cuota"},
                {"source": "censys", "label": "Censys", "outcome": "skipped", "cached": False, "detail": "sin clave"}],
    "dnsChecks": [{"check": "spf", "status": "passed"}, {"check": "dmarc", "status": "failed"},
                  {"check": "dnssec", "status": "not_evaluated"}, {"check": "dkim", "status": "not_applicable"}],
    "subdomains": [{"name": "www.example.com", "sources": ["crtsh"], "lastSeenAt": "2026-01-02T00:00:00Z"},
                   {"name": "dev.example.com", "sources": ["crtsh", "shodan"], "lastSeenAt": None}],
    "observations": [{"source": "shodan", "address": "93.184.216.34", "port": 443, "protocol": "tcp",
                      "product": "nginx", "version": "1.18.0"}],
    "findings": [{"title": "DMARC ausente", "category": "dns_hygiene", "checkId": "lybra:dns-dmarc@1",
                  "priority": "MEDIUM", "port": None, "state": "open"}]}
_CLOUD = {"resources": ["s3:mi-bucket"], "subdomains": [{"name": "app.example.com"}], "findings": [
    {"title": "Bucket S3 público (mi-bucket)", "severity": "HIGH", "service": "s3:mi-bucket",
     "checkId": "lybra:cloud-s3-public-bucket@1"},
    {"title": "Subdominio susceptible de takeover: app.example.com", "severity": "HIGH",
     "service": "app.example.com", "checkId": "lybra:cloud-takeover-github@1"}]}
_NAMES = ["mail.example.com", "www.example.com"]


def _plain(render, *args, width=80):
    console = Console(file=io.StringIO(), theme=THEME, force_terminal=False, width=width, highlight=False)
    render(console, *args)
    return console.file.getvalue()


def _check_clean(text, width):
    assert "\x1b" not in text
    for line in text.splitlines():
        assert line == line.rstrip(), repr(line)
        assert len(line) <= width, repr(line)


def test_info_view():
    text = _plain(views.render_info, _INFO)
    assert "◆ Motor Lybra" in text and "0.2.0" in text and "rev 7" in text and "250000 cves" in text
    _check_clean(text, 80)


def test_info_highlights_stale_sources():
    stale = {**_INFO, "kb": {**_INFO["kb"], "sources": [{"source": "kev", "isStale": True}]}}
    assert "! desactualizada: kev" in _plain(views.render_info, stale)


def test_kb_status_table_states_and_feed():
    text = _plain(views.render_kb_status, _KB_STATUS)
    assert "al día" in text and "VIEJA" in text and "sin verificar" in text
    assert "9 días" in text and "nunca sincronizada" in text and "timeout al descargar" in text
    assert text.rstrip().endswith("nvd:2026-01-01")
    _check_clean(text, 80)


def test_scan_status_cancel_and_sync_lines():
    assert _plain(views.render_scan_status, _STATUS).strip() == "● running · 10.0.0.1 · checks · 3/10"
    failed = _plain(views.render_scan_status, _FAILED)
    assert failed.startswith("✗ failed · 10.0.0.1") and "└ no hay ruta al objetivo" in failed
    assert _plain(views.render_scan_status, {**_STATUS, "status": "partial"}).startswith("! partial")
    assert _plain(views.render_scan_status, {**_STATUS, "status": "completed"}).startswith("✓ completed")
    assert _plain(views.render_cancel, _CANCEL).startswith("✓ Cancelación pedida para s1 (10.0.0.1): cancelled")
    assert _plain(views.render_cancel, {**_CANCEL, "status": "completed"}).startswith("! El escaneo s1")
    assert "✓ Sincronización iniciada" in _plain(views.render_sync, {"started": True, "source": "kev"})
    assert "✗ No se inició" in _plain(views.render_sync, {"started": False})


def test_cve_card():
    text = _plain(views.render_cve, _CVE)
    assert "CVE-2024-6387  HIGH  8.1  KEV  EPSS 0.123 (p97)" in text
    assert "CVSS:3.1/AV:N" in text and "2024-07-01" in text and "9 productos: openbsd:openssh (+8)" in text
    _check_clean(text, 80)
    _check_clean(_plain(views.render_cve, _CVE, width=40), 40)
    assert "Sin datos de NVD" in _plain(views.render_cve, {"cveId": "CVE-1-1", "inKev": True})


def test_version_view_reuses_findings():
    text = _plain(views.render_version, _VERSION, "nginx", "1.18.0")
    assert "fin de soporte 2021-04-20 (1.18) — superado" in text
    assert "nginx 1.18.0 — CVE-2021-23017" in text and "· 1 en KEV" in text
    assert "no reconocido" in _plain(views.render_version, {"recognized": False}, "x", "1")
    _check_clean(text, 80)


def test_osint_domain_sections():
    text = _plain(views.render_osint_domain, _DOMAIN)
    for part in ("Dominio example.com", "Fuentes", "Subdominios (2)", "Servicios vistos (1)", "Higiene DNS",
                 "Hallazgos", "93.184.216.34:443/tcp", "nginx 1.18.0", "caché", "sin clave", "DMARC ausente",
                 "✓ spf", "✗ dmarc", "! dnssec", "2 subdominios · 1 servicio visto · 1/4 comprobaciones DNS"):
        assert part in text, part
    _check_clean(text, 80)
    _check_clean(_plain(views.render_osint_domain, _DOMAIN, width=50), 50)
    assert "Ninguno" in _plain(views.render_osint_domain, {})


def test_hostnames_and_cloud():
    text = _plain(views.render_hostnames, _NAMES, "93.184.216.34")
    assert "Nombres de 93.184.216.34" in text and "mail.example.com" in text and "2 nombres" in text
    assert "Ninguna fuente" in _plain(views.render_hostnames, [], "1.1.1.1")
    cloud = _plain(views.render_cloud, _CLOUD)
    assert "Recursos expuestos (1)" in cloud and "s3:mi-bucket" in cloud
    assert "takeover (1)" in cloud and "app.example.com" in cloud and "2 exposiciones" in cloud
    _check_clean(cloud, 80)
    assert "Nada expuesto" in _plain(views.render_cloud, {"resources": ["s3:x"]})


def test_render_backfill():
    result = {"cves": 500, "cpeProductAliases": 50, "since": "2024-01-01", "until": "2024-01-07", "usedApiKey": True}
    text = _plain(views.render_backfill, result)
    assert "Backfill de NVD completado" in text and "2024-01-01 → 2024-01-07" in text and "500" in text
    _check_clean(text, 80)
    _check_clean(_plain(views.render_backfill, {**result, "usedApiKey": False}, width=45), 45)


def test_backfill_view_non_tty():
    console = Console(file=io.StringIO(), theme=THEME, force_terminal=False, width=80, highlight=False)
    from lybra.app.ui.progress import BackfillView
    with BackfillView(console, "2024-01-01") as view:
        view({"phase": "backfill", "done": 10, "total": 100, "cves": 5, "hasApiKey": False})
        view({"phase": "backfill", "done": 20, "total": 100, "cves": 12})
        view.finish(True)
    text = console.file.getvalue()
    assert "\r" not in text
    assert "\x1b" not in text
    assert "Sin LYBRA_NVD_API_KEY" in text
    assert "backfill completado" in text


def test_kb_backfill_invalid_dates(capsys, fake_client):
    fake_client("kb.backfill", {})
    assert cli.main(["kb", "backfill", "--since", "bad-date"]) == 2
    assert "Fecha 'since' inválida" in capsys.readouterr().err

    assert cli.main(["kb", "backfill", "--since", "2024-01-01", "--until", "bad-date"]) == 2
    assert "Fecha 'until' inválida" in capsys.readouterr().err

    assert cli.main(["kb", "backfill", "--since", "2024-01-01", "--until", "2024-01-01"]) == 2
    assert "no puede ser posterior o igual a 'until'" in capsys.readouterr().err

    assert cli.main(["kb", "backfill", "--since", "2024-01-02", "--until", "2024-01-01"]) == 2
    assert "no puede ser posterior o igual a 'until'" in capsys.readouterr().err


def test_kb_backfill_direct_kb(monkeypatch, tmp_path, capsys):
    from datetime import datetime
    from lybra.kb.sync import KnowledgeBaseSync
    def mock_backfill(self, start, end, on_progress=None):
        assert isinstance(start, datetime)
        assert isinstance(end, datetime)
        return {"cves": 5, "cpeProductAliases": 1, "since": str(start), "until": str(end), "usedApiKey": True}
    monkeypatch.setattr(KnowledgeBaseSync, "backfill_nvd", mock_backfill)
    kb_path = tmp_path / "test.db"
    assert cli.main(["kb", "backfill", "--since", "2024-01-01", "--until", "2024-01-07", "--kb", str(kb_path)]) == 0
    assert "Backfill de NVD completado" in capsys.readouterr().out




# --- la línea de órdenes, sin sockets

_RESPONSES = {
    ("info",): ("info", _INFO, "Motor Lybra"),
    ("status", "s1"): ("scan_status", _STATUS, "● running"),
    ("cancel", "s1"): ("scan_cancel", _CANCEL, "✓ Cancelación pedida"),
    ("kb", "status"): ("kb.status", _KB_STATUS, "VIEJA"),
    ("kb", "sync"): ("kb.sync", {"started": True, "source": "all"}, "✓ Sincronización iniciada"),
    ("kb", "backfill", "--since", "2024-01-01"): ("kb.backfill", {"cves": 100, "cpeProductAliases": 10, "since": "2024-01-01", "until": "2026-01-01", "usedApiKey": True}, "Backfill de NVD completado"),
    ("kb", "cve", "CVE-2024-6387"): ("kb.cve", _CVE, "CVE-2024-6387  HIGH"),
    ("kb", "version", "nginx", "1.18.0"): ("kb.version", _VERSION, "CVE-2021-23017"),
    ("osint", "domain", "example.com"): ("osint_domain", _DOMAIN, "Subdominios (2)"),
    ("osint", "hostnames", "93.184.216.34"): ("osint_hostnames", _NAMES, "2 nombres"),
    ("cloud", "probe", "--resource", "s3:mi-bucket"): ("cloud_probe", _CLOUD, "Recursos expuestos (1)"),
}



@pytest.fixture
def fake_client(monkeypatch):
    def install(method, value):
        if "." in method:
            monkeypatch.setattr(LybraClient, "call", lambda self, op, params=None, **kw: value)
        else:
            monkeypatch.setattr(LybraClient, method, lambda self, *args, **kw: value)
    return install


@pytest.mark.parametrize("argv", list(_RESPONSES))
def test_each_command_renders_plain_and_keeps_json(fake_client, capsys, argv):
    method, value, expected = _RESPONSES[argv]
    fake_client(method, value)

    assert cli.main(list(argv)) == 0
    captured = capsys.readouterr()
    assert expected in captured.out
    assert "\x1b" not in captured.out + captured.err
    assert all(line == line.rstrip() for line in captured.out.splitlines())

    assert cli.main([*argv, "--json"]) == 0
    assert capsys.readouterr().out == json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def test_kb_backfill_keyboard_interrupt(monkeypatch, tmp_path, capsys):
    from lybra.kb.sync import KnowledgeBaseSync

    def interrupt_backfill(self, start, end, on_progress=None):
        if on_progress:
            on_progress({"phase": "backfill", "done": 1, "total": 10, "cves": 5, "hasApiKey": True})
        raise KeyboardInterrupt

    monkeypatch.setattr(KnowledgeBaseSync, "backfill_nvd", interrupt_backfill)
    kb_path = tmp_path / "test.db"
    assert cli.main(["kb", "backfill", "--since", "2024-01-01", "--until", "2024-01-07", "--kb", str(kb_path)]) == 130
    captured = capsys.readouterr()
    assert "backfill interrumpido" in captured.err
    assert "Traceback" not in captured.err


def test_kb_backfill_json_keyboard_interrupt(monkeypatch, tmp_path, capsys):
    from lybra.kb.sync import KnowledgeBaseSync

    monkeypatch.setattr(KnowledgeBaseSync, "backfill_nvd", lambda *a, **kw: (_ for _ in ()).throw(KeyboardInterrupt()))
    kb_path = tmp_path / "test.db"
    assert cli.main(["kb", "backfill", "--since", "2024-01-01", "--kb", str(kb_path), "--json"]) == 130
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Operación cancelada por el usuario" in captured.err


def test_scan_keyboard_interrupt(monkeypatch, capsys):
    monkeypatch.setattr(LybraClient, "scan_start", lambda self, *a, **kw: "scan-1")

    def interrupt_watch(self, scan_id, on_progress=None):
        if on_progress:
            on_progress({"phase": "discovery", "done": 1, "total": 2})
        raise KeyboardInterrupt

    monkeypatch.setattr(LybraClient, "scan_watch", interrupt_watch)
    assert cli.main(["scan", "127.0.0.1"]) == 130
    captured = capsys.readouterr()
    assert "Operación cancelada por el usuario" in captured.err


def test_command_keyboard_interrupt(monkeypatch, capsys):
    monkeypatch.setattr(LybraClient, "info", lambda self: (_ for _ in ()).throw(KeyboardInterrupt()))
    assert cli.main(["info"]) == 130
    assert "Operación cancelada por el usuario" in capsys.readouterr().err
