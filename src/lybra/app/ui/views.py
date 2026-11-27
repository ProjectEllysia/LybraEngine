"""Vistas del resto de órdenes de ``lybra``: info, kb, status, cancel, osint y cloud.

Todas reciben la respuesta del motor tal cual (forma de cable, camelCase) y son
tolerantes con las claves que falten. Con ``--json`` no se usan.
"""

from __future__ import annotations

from typing import List, Optional, Sequence

from rich.console import Console
from rich.text import Text

from lybra.app.ui.console import symbols_for
from lybra.app.ui.findings import PRIORITY_LADDER, render_findings
from lybra.app.ui.layout import emit, heading, key_values, paragraph, render_table
from lybra.app.ui.progress import phase_name

_MAX_ROWS = 25
_MAX_PRODUCTS = 6
_OUTCOME_STYLES = {"ok": "ok", "partial": "warn", "failed": "err", "disabled": "muted", "skipped": "muted"}
#: Estado del escaneo -> (símbolo de ``Symbols``, estilo).
_SCAN_MARKS = {"completed": ("ok", "ok"), "partial": ("warn", "warn"), "failed": ("err", "err"),
               "cancelled": ("err", "err"), "running": ("dot", "brand"), "queued": ("dot", "muted")}


def _line(console: Console, text: str, style: str = "", indent: int = 0) -> None:
    """Escribe un texto partido al ancho, con ``indent`` espacios a la izquierda."""
    paragraph(console, text, style, indent)


def _plural(count: int, one: str, many: str) -> str:
    """``1 nombre`` / ``3 nombres``."""
    return f"{count} {one if count == 1 else many}"


def _day(value: Optional[str]) -> str:
    """La fecha de un instante ISO 8601 (``2024-07-01T...`` pasa a ``2024-07-01``)."""
    return str(value)[:10] if value else "—"


def _more(console: Console, total: int, shown: int) -> None:
    """Avisa de las filas que no se enseñan."""
    if total > shown:
        emit(console, Text(f"  … y {total - shown} más", style="muted"))


def _section(console: Console, title: str) -> None:
    """Una línea en blanco y un título de sección."""
    emit(console, Text(""))
    heading(console, title)


def _summary(console: Console, parts: Sequence[str]) -> None:
    """La línea final de resumen, tras una línea en blanco."""
    emit(console, Text(""))
    paragraph(console, f" {symbols_for(console).sep} ".join(parts), "bold")


def render_info(console: Console, info: dict) -> None:
    """
    Escribe la versión del motor, el protocolo y el estado de la base de conocimiento.

    Args:
        console: La consola de stdout.
        info: La respuesta de ``engine.info``.
    """
    sym = symbols_for(console)
    kb = info.get("kb") or {}
    heading(console, f"{sym.brand} Motor Lybra")
    pairs: List[tuple] = [("versión", str(info.get("engineVersion", "?"))),
                          ("protocolo", ", ".join(str(v) for v in info.get("protocolVersions") or []) or "?")]
    if info.get("identificationRevision") is not None:
        pairs.append(("identificación", f"rev {info['identificationRevision']}"))
    pairs.append(("feed de la KB", str(kb.get("feedVersion", "?"))))
    counts = kb.get("counts") or {}
    if counts:
        pairs.append(("datos", f" {sym.sep} ".join(f"{value} {name}" for name, value in counts.items())))
    stale = [entry.get("source") for entry in kb.get("sources") or [] if entry.get("isStale")]
    if kb.get("isStale") or stale:
        pairs.append(("estado", Text(f"{sym.warn} desactualizada" + (f": {', '.join(stale)}" if stale else ""),
                                     style="warn")))
    key_values(console, pairs)


def _source_state(entry: dict) -> Text:
    """VIEJA (aviso), sin verificar (tenue) o al día (ok)."""
    if entry.get("isStale"):
        return Text("VIEJA", style="warn")
    if entry.get("isUnverified"):
        return Text("sin verificar", style="muted")
    return Text("al día", style="ok")


def render_kb_status(console: Console, status: dict) -> None:
    """
    Escribe una tabla con el estado de cada fuente de la base de conocimiento.

    Args:
        console: La consola de stdout.
        status: La respuesta de ``kb.status``.
    """
    rows = []
    for entry in status.get("sources") or []:
        age = entry.get("ageDays")
        rows.append([Text(str(entry.get("source", "?"))), _source_state(entry),
                     Text(f"{age:g} días" if age is not None else "nunca sincronizada", style="muted"),
                     Text(str(entry.get("error") or ""), style="err")])
    render_table(console, ("fuente", "estado", "antigüedad", "error"), rows, empty="Sin fuentes configuradas")
    emit(console, Text(""))
    emit(console, Text(f"  {status.get('feedVersion', '')}", style="muted"))


def render_scan_status(console: Console, view: dict) -> None:
    """
    Escribe el estado de un escaneo en una línea (y su error debajo, si falló).

    Args:
        console: La consola de stdout.
        view: La respuesta de ``scan.status``.
    """
    sym = symbols_for(console)
    status = str(view.get("status", "?"))
    glyph, style = _SCAN_MARKS.get(status, ("dot", "muted"))
    progress = view.get("progress") or {}
    parts = [status, str(view.get("target", "?"))]
    if status in ("queued", "running"):
        parts.append(phase_name(progress.get("phase")))
        if progress.get("total"):
            parts.append(f"{progress.get('done') or 0}/{progress['total']}")
    _line(console, f"{getattr(sym, glyph)} {f' {sym.sep} '.join(parts)}", style)
    error = view.get("error")
    if error:
        message = error.get("message", error) if isinstance(error, dict) else error
        _line(console, f"{sym.branch} {message}", "err", indent=2)


def render_cancel(console: Console, view: dict) -> None:
    """
    Escribe el desenlace de una petición de cancelación.

    Args:
        console: La consola de stdout.
        view: La respuesta de ``scan.cancel`` (el estado tras pedirla).
    """
    sym = symbols_for(console)
    status = str(view.get("status", "?"))
    scan = f"{view.get('scanId', '?')} ({view.get('target', '?')})"
    if status in ("completed", "partial", "failed"):
        _line(console, f"{sym.warn} El escaneo {scan} ya había terminado: {status}", "warn")
    else:
        _line(console, f"{sym.ok} Cancelación pedida para {scan}: {status}", "ok")


def render_sync(console: Console, response: dict) -> None:
    """
    Escribe si se lanzó la sincronización de la base de conocimiento.

    Args:
        console: La consola de stdout.
        response: La respuesta de ``kb.sync``.
    """
    sym = symbols_for(console)
    source = response.get("source", "all")
    if response.get("started"):
        _line(console, f"{sym.ok} Sincronización iniciada en segundo plano (fuente: {source})", "ok")
    else:
        _line(console, f"{sym.err} No se inició la sincronización (fuente: {source})", "err")


def render_cve(console: Console, detail: dict) -> None:
    """
    Escribe la ficha de una CVE.

    Args:
        console: La consola de stdout.
        detail: La respuesta de ``kb.cve``.
    """
    sym = symbols_for(console)
    head = Text(str(detail.get("cveId", "?")), style="bold")
    severity = str(detail.get("severity") or "").upper()
    if severity:
        head.append(f"  {severity}", style=severity.lower() if severity in PRIORITY_LADDER else "muted")
    if detail.get("cvssScore") is not None:
        head.append(f"  {detail['cvssScore']:.1f}")
    if detail.get("inKev"):
        head.append("  KEV", style="kev")
    if detail.get("epssScore") is not None:
        percentile = detail.get("epssPercentile")
        head.append(f"  EPSS {detail['epssScore']:.3f}" + (f" (p{percentile * 100:.0f})" if percentile is not None
                                                           else ""), style="muted")
    paragraph(console, head)
    pairs: List[tuple] = []
    if detail.get("cvssVector"):
        pairs.append(("vector", str(detail["cvssVector"])))
    pairs.append(("publicada", _day(detail.get("published"))))
    if detail.get("cweIds"):
        pairs.append(("CWE", ", ".join(detail["cweIds"])))
    products = detail.get("products") or []
    total = detail.get("productsTotal", len(products))
    if products:
        names = [f"{item.get('vendor')}:{item.get('product')}" for item in products[:_MAX_PRODUCTS]]
        pairs.append(("afecta a", f"{_plural(total, 'producto', 'productos')}: {', '.join(names)}"
                                  + (f" (+{total - len(names)})" if total > len(names) else "")))
    key_values(console, pairs)
    if detail.get("description"):
        emit(console, Text(""))
        _line(console, str(detail["description"]), indent=2)
    elif detail.get("cvssScore") is None:
        _line(console, f"{sym.warn} Sin datos de NVD para esta CVE (sólo KEV, EPSS o distros).", "warn", indent=2)


def _priority_from_score(score: Optional[float]) -> str:
    """La prioridad que corresponde a un CVSS (para pintar las CVE de ``kb.version``)."""
    if score is None or score <= 0:
        return "INFO"
    return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"


def render_version(console: Console, response: dict, product: str, version: str) -> None:
    """
    Escribe las CVE de un producto en una versión, como bloques de hallazgos.

    Args:
        console: La consola de stdout.
        response: La respuesta de ``kb.version``.
        product: El producto consultado.
        version: La versión consultada.
    """
    sym = symbols_for(console)
    if not response.get("recognized"):
        _line(console, f"{sym.warn} Producto no reconocido: {product} {version}", "warn")
        return
    head = Text(f"{response.get('vendor')}:{response.get('product')} {response.get('version')}", style="bold")
    eol = response.get("endOfLife")
    if eol:
        head.append(f"  {sym.sep}  fin de soporte {eol.get('date')} ({eol.get('cycle')})"
                    + (" — superado" if eol.get("isPast") else ""), style="warn" if eol.get("isPast") else "muted")
    paragraph(console, head)
    emit(console, Text(""))
    cves = response.get("cves") or []
    render_findings(console, [
        {"title": f"{product} {version} — {cve.get('cveId')}", "category": "outdated_software",
         "checkId": "lybra:version-match", "cveIds": [cve.get("cveId")], "cvssScore": cve.get("cvssScore"),
         "inKev": cve.get("inKev"), "priority": _priority_from_score(cve.get("cvssScore"))} for cve in cves])
    total = response.get("cvesTotal", len(cves))
    if total > len(cves):
        emit(console, Text(f" Se muestran {len(cves)} de {total} CVE", style="muted"))


def render_osint_domain(console: Console, result: dict) -> None:
    """
    Escribe la inteligencia pasiva de un dominio: fuentes, subdominios, servicios, DNS y hallazgos.

    Args:
        console: La consola de stdout.
        result: La respuesta de ``osint.domain``.
    """
    sym = symbols_for(console)
    heading(console, f"{sym.brand} Dominio {result.get('domain', '?')}")

    _section(console, "Fuentes")
    rows = []
    for item in result.get("sources") or []:
        note = f" {sym.sep} ".join(part for part in ("caché" if item.get("cached") else "", item.get("detail")) if part)
        rows.append([Text(str(item.get("label") or item.get("source", "?"))),
                     Text(str(item.get("outcome", "?")), style=_OUTCOME_STYLES.get(str(item.get("outcome")), "")),
                     Text(note, style="muted")])
    render_table(console, ("fuente", "resultado", "detalle"), rows, empty="Ninguna")

    subdomains = result.get("subdomains") or []
    _section(console, f"Subdominios ({len(subdomains)})")
    render_table(console, ("nombre", "fuentes", "visto"), [
        [Text(str(item.get("name", "?"))), Text(", ".join(item.get("sources") or []), style="muted"),
         Text(_day(item.get("lastSeenAt")), style="muted")] for item in subdomains[:_MAX_ROWS]], empty="Ninguno")
    _more(console, len(subdomains), _MAX_ROWS)

    observations = result.get("observations") or []
    _section(console, f"Servicios vistos ({len(observations)})")
    render_table(console, ("dirección", "servicio", "fuente"), [
        [Text(f"{item.get('address', '?')}:{item.get('port', '?')}/{item.get('protocol') or 'tcp'}"),
         Text(" ".join(str(item[key]) for key in ("product", "version") if item.get(key)) or "—"),
         Text(str(item.get("source", "?")), style="muted")] for item in observations[:_MAX_ROWS]], empty="Ninguno")
    _more(console, len(observations), _MAX_ROWS)

    checks = result.get("dnsChecks") or []
    _section(console, "Higiene DNS")
    marks = {"passed": (sym.ok, "ok", "correcta"), "failed": (sym.err, "err", "con fallos"),
             "not_evaluated": (sym.warn, "warn", "sin respuesta del DNS"),
             "not_applicable": (sym.sep, "muted", "no aplica")}
    rows = []
    for item in checks:
        mark, style, label = marks.get(str(item.get("status")), (sym.warn, "warn", str(item.get("status"))))
        rows.append([Text(f"{mark} {item.get('check', '?')}", style=style), Text(label, style="muted")])
    render_table(console, (), rows, empty="Ninguna")

    findings = result.get("findings") or []
    if findings:
        _section(console, "Hallazgos")
        render_findings(console, findings)
    failed = sum(1 for item in checks if item.get("status") == "failed")
    _summary(console, [_plural(len(subdomains), "subdominio", "subdominios"),
                       _plural(len(observations), "servicio visto", "servicios vistos"),
                       f"{failed}/{len(checks)} comprobaciones DNS con fallos",
                       _plural(len(findings), "hallazgo", "hallazgos")])


def render_hostnames(console: Console, names: Sequence[str], address: str) -> None:
    """
    Escribe los nombres que las fuentes de terceros asocian a una IP.

    Args:
        console: La consola de stdout.
        names: Los nombres (la respuesta de ``osint.hostnames``).
        address: La IP consultada.
    """
    sym = symbols_for(console)
    heading(console, f"{sym.brand} Nombres de {address}")
    if not names:
        _line(console, "Ninguna fuente conoce nombres para esa IP (¿hay claves de Shodan o Censys?)", "muted",
              indent=2)
        return
    for name in names:
        _line(console, name, indent=2)
    _summary(console, [_plural(len(names), "nombre", "nombres")])


def render_cloud(console: Console, result: dict) -> None:
    """
    Escribe lo comprobado en ``cloud.probe``: recursos expuestos y takeovers.

    Args:
        console: La consola de stdout.
        result: La respuesta de ``cloud.probe``.
    """
    sym = symbols_for(console)
    names = [item.get("name") for item in result.get("subdomains") or []]
    heading(console, f"{sym.brand} Exposición cloud")
    key_values(console, [("recursos", ", ".join(result.get("resources") or []) or "—"),
                         ("subdominios", ", ".join(names) or "—")])
    findings = result.get("findings") or []
    takeovers = [item for item in findings if "takeover" in str(item.get("checkId", ""))]
    exposed = [item for item in findings if item not in takeovers]
    for title, group in ((f"Recursos expuestos ({len(exposed)})", exposed),
                         (f"Subdominios susceptibles de takeover ({len(takeovers)})", takeovers)):
        _section(console, title)
        rows = []
        for item in group:
            priority = str(item.get("priority") or item.get("severity") or "INFO").upper()
            rows.append([Text(priority, style=priority.lower() if priority in PRIORITY_LADDER else "muted"),
                         Text(str(item.get("service") or "?")), Text(str(item.get("title", "")), style="muted")])
        render_table(console, (), rows, empty="Ninguno")
    if findings:
        _summary(console, [f"{sym.warn} {_plural(len(findings), 'exposición', 'exposiciones')}"])
    else:
        emit(console, Text(""))
        emit(console, Text(f"{sym.ok} Nada expuesto en lo comprobado", style="ok"))
