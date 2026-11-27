"""La presentación de ``lybra``: agrupación de hallazgos, color y ``--json``. Sin sockets."""

from __future__ import annotations

import io
import json

import pytest
from rich.console import Console

from lybra.app import cli
from lybra.app.ui.console import THEME, make_consoles
from lybra.app.ui.findings import group_findings, render_findings, render_result
from lybra.app.ui.progress import PhaseView
from lybra_client import LybraClient


def _finding(title, port=None, **extra):
    base = {"title": title, "category": "misconfiguration", "port": port, "protocol": "tcp" if port else None,
            "checkId": "lybra:hsts@2", "priority": "MEDIUM", "state": "open"}
    return base | extra


def _plain(findings=None, result=None, width=100):
    console = Console(file=io.StringIO(), theme=THEME, force_terminal=False, width=width, highlight=False)
    if result is not None:
        render_result(console, result)
    else:
        render_findings(console, findings)
    return console.file.getvalue()


def test_the_same_check_on_several_ports_and_vhosts_is_one_group():
    findings = [_finding("Falta HSTS", 8443), _finding("Falta HSTS", 443, checkId="lybra:hsts@3"),
                _finding("Falta HSTS", 443, vhost="app.example.com"),
                _finding("Falta HSTS", 443, vhost="api.example.com")]
    (group,) = group_findings(findings)
    assert group.locations == [(443, "tcp"), (8443, "tcp")]
    assert group.vhosts == ["app.example.com", "api.example.com"]
    assert group.count == 4
    text = _plain(findings)
    assert "443/tcp · 8443/tcp" in text and "app.example.com · api.example.com" in text
    assert "4 hallazgos · 1 distinto" in text


def test_cves_group_by_title_and_keep_max_cvss_and_kev():
    cve = {"category": "outdated_software", "cveIds": ["CVE-2024-6387"], "checkId": "lybra:version-match@1"}
    groups = group_findings([
        _finding("OpenSSH — CVE-2024-6387", 22, cvssScore=8.1, priority="HIGH", **cve),
        _finding("OpenSSH — CVE-2024-6387", 2222, cvssScore=9.8, priority="HIGH", inKev=True, **cve),
        _finding("OpenSSH — CVE-2023-1", 22, cvssScore=5.0, priority="HIGH", **(cve | {"cveIds": ["CVE-2023-1"]}))])
    assert len(groups) == 2
    assert groups[0].cvss == 9.8 and groups[0].kev and len(groups[0].locations) == 2


def test_groups_are_sorted_by_priority_then_cvss_with_severity_fallback():
    groups = group_findings([
        _finding("bajo", 1, priority="LOW"),
        {"title": "solo severidad", "severity": "CRITICAL", "port": 5, "protocol": "tcp"},
        _finding("alto 7", 2, priority="HIGH", cvssScore=7.0),
        _finding("alto 9", 3, priority="HIGH", cvssScore=9.0),
        _finding("info", 4, priority="INFO")])
    assert [g.title for g in groups] == ["solo severidad", "alto 9", "alto 7", "bajo", "info"]


def test_priority_wins_over_severity():
    (group,) = group_findings([_finding("x", 1, priority="LOW", severity="CRITICAL")])
    assert group.priority == "LOW"


def test_open_port_infos_collapse_into_one_line():
    ports = [_finding(f"Puerto {port}/tcp abierto", port, category="open_port", priority="INFO",
                      service=name, checkId="lybra:open-port@1")
             for port, name in ((22, "ssh"), (80, "http"), (443, "https"), (25, "smtp"), (53, "dns"), (21, "ftp"),
                                (3306, "mysql"))]
    (group,) = group_findings(ports)
    assert group.open_ports and group.count == 7
    text = _plain(ports)
    assert "Puerto abierto: ssh, http, https, smtp, dns  (+2)" in text
    assert "└" not in text


def test_fixed_and_kev_tags_and_the_summary():
    text = _plain([_finding("Viejo", 80, state="fixed"),
                   _finding("Explotado", 22, priority="CRITICAL", cvssScore=9.8, inKev=True)])
    assert "KEV" in text and "corregido" in text
    assert "● 1 crítico" in text and "● 1 medio" in text and "· 1 en KEV" in text


def test_a_narrow_terminal_wraps_the_title_under_its_column():
    text = _plain([_finding("palabra " * 12, 80)], width=40)
    assert max(len(line) for line in text.splitlines()) <= 40


def test_result_header_partial_warning_and_no_findings():
    result = {"target": "10.0.0.1", "status": "partial", "services": [{}], "findings": [],
              "startedAt": "2026-01-01T00:00:00Z", "finishedAt": "2026-01-01T00:01:05Z"}
    text = _plain(result=result)
    assert "10.0.0.1 · partial · 1 servicio · 1m 05s" in text
    assert "! Resultado PARCIAL: lo que no aparece no se ha comprobado." in text
    assert "✓ Sin hallazgos" in text


def test_no_ansi_when_not_a_tty_or_with_no_color(monkeypatch, capsys):
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    out, err = make_consoles("auto")
    render_findings(out, [_finding("x", 80, priority="HIGH", inKev=True)])
    assert "\x1b" not in capsys.readouterr().out

    monkeypatch.setenv("NO_COLOR", "1")
    forced = Console(file=io.StringIO(), theme=THEME, force_terminal=True, highlight=False)
    render_findings(forced, [_finding("x", 80, priority="HIGH")])
    assert "\x1b[3" not in forced.file.getvalue() and "\x1b[1;3" not in forced.file.getvalue()

    monkeypatch.delenv("NO_COLOR")
    out, _ = make_consoles("always")
    assert out.is_terminal and out.color_system is not None
    out, _ = make_consoles("never")
    assert not out.is_terminal


def test_phase_view_prints_plain_lines_without_carriage_returns():
    console = Console(file=io.StringIO(), theme=THEME, force_terminal=False, highlight=False)
    with PhaseView(console, "10.0.0.1", "fast") as view:
        for phase in ("discovery", "discovery", "fingerprint", "fases-raras"):
            view({"status": "running", "phase": phase, "done": 1, "total": 2})
        view.finish("partial")
    text = console.file.getvalue()
    assert "\r" not in text and "\x1b" not in text
    assert "scan 10.0.0.1 · perfil fast" in text
    assert "✓ descubrimiento" in text and "✓ huella" in text and "! fases-raras" in text


# --- la línea de órdenes, sin sockets

_RESULT = {"scanId": "s1", "target": "10.0.0.1", "status": "completed", "services": [],
           "findings": [_finding("Falta HSTS", 443, vhost="a.example.com")]}


@pytest.fixture
def fake_client(monkeypatch):
    monkeypatch.setattr(LybraClient, "scan_start", lambda self, target, **kw: "s1")
    monkeypatch.setattr(LybraClient, "scan_watch",
                        lambda self, scan_id, on_progress=None: (on_progress({"status": "running", "phase": "checks",
                                                                              "done": 1, "total": 2}),
                                                                 {"status": "completed"})[1])
    monkeypatch.setattr(LybraClient, "scan_result", lambda self, scan_id: _RESULT)
    monkeypatch.setattr(LybraClient, "analyze", lambda self, services, **kw: {"findings": _RESULT["findings"]})


@pytest.mark.parametrize("argv", (["--json", "scan", "10.0.0.1"], ["scan", "10.0.0.1", "--json"],
                                  ["scan", "--json", "10.0.0.1"]))
def test_json_is_accepted_before_and_after_the_subcommand_and_is_unchanged(fake_client, capsys, argv):
    assert cli.main(argv) == 0
    captured = capsys.readouterr()
    assert captured.out == json.dumps(_RESULT, ensure_ascii=False, indent=2) + "\n"
    assert captured.err == ""


def test_json_after_a_nested_subcommand_parses():
    assert cli.build_parser().parse_args(["kb", "status", "--json"]).json is True
    assert cli.build_parser().parse_args(["--json", "kb", "status"]).json is True
    assert cli.build_parser().parse_args(["kb", "status"]).json is False
    assert cli.build_parser().parse_args(["--color", "never", "info"]).color == "never"
    assert cli.build_parser().parse_args(["info", "--color", "always"]).color == "always"


def test_scan_renders_grouped_findings_without_ansi_when_piped(fake_client, capsys):
    assert cli.main(["scan", "10.0.0.1"]) == 0
    captured = capsys.readouterr()
    assert "10.0.0.1 · completed" in captured.out and "a.example.com" in captured.out
    assert "\x1b" not in captured.out + captured.err and "\r" not in captured.err
    assert "perfil standard" in captured.err


def test_analyze_and_errors_use_the_new_view(fake_client, monkeypatch, capsys):
    assert cli.main(["analyze", "--product", "nginx", "--version", "1.0"]) == 0
    assert "Falta HSTS" in capsys.readouterr().out
    assert cli.main(["analyze", "--version", "1.0"]) == 2
    assert "✗ Hace falta --cpe o --product" in capsys.readouterr().err

    def boom(self, scan_id):
        raise OSError("sin socket")
    monkeypatch.setattr(LybraClient, "scan_result", boom)
    assert cli.main(["result", "s1"]) == 3
    assert "✗ No se pudo hablar con lybrad en" in capsys.readouterr().err


def test_no_line_has_trailing_whitespace_at_any_width():
    findings = [_finding("Falta HSTS " * 6, 443, vhost="app.example.com", cvssScore=5.3),
                _finding("Explotado", 22, priority="CRITICAL", cvssScore=9.8, inKev=True, state="fixed"),
                _finding("Puerto 22/tcp abierto", 22, category="open_port", priority="INFO", service="ssh"),
                _finding("Sin puerto", None, priority="LOW")]
    for width in (30, 40, 80, 120):
        for text in (_plain(findings, width=width), _plain(result={"target": "x", "status": "partial",
                                                                    "findings": findings}, width=width)):
            assert all(line == line.rstrip() for line in text.splitlines()), (width, text)


def test_columns_use_two_space_gutters():
    text = _plain([_finding("Explotado", 22, priority="CRITICAL", cvssScore=9.8, inKev=True)])
    assert " CRITICAL  9.8  Explotado" in text
    assert "                └ 22/tcp" in text
