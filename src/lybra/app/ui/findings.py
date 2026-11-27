"""Hallazgos agrupados: la misma incidencia en varios puertos o sitios se muestra una sola vez.

El motor emite un hallazgo por puerto y por vhost (el mismo check HTTP en el 80 y el
443, los checks de sitio repetidos por cada nombre, una CVE por servicio). Aquí se
agrupan **sólo en la vista**; el JSON no se toca.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Sequence, Tuple

from rich.console import Console
from rich.text import Text

from lybra.app.ui.console import symbols_for
from lybra.app.ui.layout import emit, paragraph, wrap

#: De menos a más grave (igual que ``analysis.correlation.PRIORITY_LADDER``, sin importar el motor).
PRIORITY_LADDER = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
_RANK = {name: index for index, name in enumerate(PRIORITY_LADDER)}

#: Categoría del hallazgo informativo de puerto abierto (``core.engine._informational_finding``).
OPEN_PORT_CATEGORY = "open_port"
_OPEN_PORT_NAMES_SHOWN = 5
#: Columnas antes del título: `` CRITICAL  9.8  ``.
_PREFIX = 16

_PRIORITY_NOUNS = {"CRITICAL": ("crítico", "críticos"), "HIGH": ("alto", "altos"), "MEDIUM": ("medio", "medios"),
                   "LOW": ("bajo", "bajos"), "INFO": ("info", "info")}


@dataclass
class Group:
    """Los hallazgos que son la misma incidencia, con sus ubicaciones.

    Attributes:
        priority: ``INFO`` … ``CRITICAL``.
        title: El título compartido.
        identity: Qué la distingue de otra con el mismo título (CVE, check o categoría).
        locations: ``(puerto, protocolo)`` distintos, por puerto.
        vhosts: Los vhosts distintos, en orden de aparición.
        cvss: El CVSS más alto, si lo hay.
        kev: Si alguno está en KEV.
        fixed: Si todos están corregidos.
        count: Cuántos hallazgos del motor agrupa.
        open_ports: Si es la línea colapsada de puertos abiertos.
        names: Con ``open_ports``, el nombre de cada servicio.
    """

    priority: str
    title: str
    identity: str
    locations: List[Tuple[int, str]] = field(default_factory=list)
    vhosts: List[str] = field(default_factory=list)
    cvss: Optional[float] = None
    kev: bool = False
    fixed: bool = False
    count: int = 0
    open_ports: bool = False
    names: List[str] = field(default_factory=list)


def effective_priority(finding: dict) -> str:
    """La prioridad de un hallazgo, con ``severity`` de respaldo (como los exportadores)."""
    for key in ("priority", "severity"):
        value = str(finding.get(key) or "").upper()
        if value in _RANK:
            return value
    return "INFO"


def _identity(finding: dict) -> str:
    """CVE, o check sin su versión (``lybra:hsts@2`` → ``lybra:hsts``), o categoría."""
    cves = finding.get("cveIds")
    if cves:
        return ",".join(sorted(cves))
    if finding.get("checkId"):
        return re.sub(r"@\d+$", "", str(finding["checkId"]))
    return str(finding.get("category") or "")


def group_findings(findings: Sequence[dict]) -> List[Group]:
    """
    Agrupa hallazgos por (prioridad, título, identidad).

    Los INFO de puerto abierto se funden en una sola línea. El orden es por
    prioridad descendente, CVSS descendente y primer puerto.

    Args:
        findings: Hallazgos en forma de cable (camelCase).

    Returns:
        List[Group]: Los grupos ordenados.
    """
    groups: Dict[tuple, Group] = {}
    fixed_flags: Dict[tuple, List[bool]] = {}
    for finding in findings:
        priority = effective_priority(finding)
        title = finding.get("title") or ""
        if priority == "INFO" and finding.get("category") == OPEN_PORT_CATEGORY:
            key: tuple = ("open-ports",)
            group = groups.setdefault(key, Group("INFO", "Puerto abierto", "open-ports", open_ports=True))
            port = finding.get("port")
            name = finding.get("service") or (f"{port}/{finding.get('protocol')}" if port else "?")
            if name not in group.names:
                group.names.append(name)
        else:
            identity = _identity(finding)
            key = (priority, title, identity)
            group = groups.setdefault(key, Group(priority, title, identity))
        group.count += 1
        fixed_flags.setdefault(key, []).append(finding.get("state") == "fixed")
        if finding.get("port") is not None:
            location = (int(finding["port"]), str(finding.get("protocol") or ""))
            if location not in group.locations:
                group.locations.append(location)
        if finding.get("vhost") and finding["vhost"] not in group.vhosts:
            group.vhosts.append(finding["vhost"])
        score = finding.get("cvssScore")
        if score is not None and (group.cvss is None or score > group.cvss):
            group.cvss = score
        group.kev = group.kev or bool(finding.get("inKev"))
    for key, group in groups.items():
        group.fixed = all(fixed_flags[key])
        group.locations.sort()
    return sorted(groups.values(), key=lambda g: (-_RANK[g.priority], -(g.cvss or 0),
                                                  g.locations[0][0] if g.locations else 0))


def _open_ports_title(group: Group) -> str:
    """``Puerto abierto: ssh, http, https  (+2)``."""
    shown = group.names[:_OPEN_PORT_NAMES_SHOWN]
    extra = len(group.names) - len(shown)
    return f"Puerto abierto: {', '.join(shown)}" + (f"  (+{extra})" if extra else "")


def _plural(count: int, noun: Tuple[str, str]) -> str:
    """``1 alto`` / ``3 altos``."""
    return f"{count} {noun[0] if count == 1 else noun[1]}"


def render_findings(console: Console, findings: Sequence[dict]) -> None:
    """
    Escribe los hallazgos agrupados y su resumen en ``console``.

    Args:
        console: La consola de stdout.
        findings: Hallazgos en forma de cable.
    """
    sym = symbols_for(console)
    if not findings:
        console.print(Text(f"{sym.ok} Sin hallazgos", style="ok"))
        return
    groups = group_findings(findings)
    sep = f" {sym.sep} "
    indent = " " * _PREFIX
    for group in groups:
        tags = Text()
        if group.kev:
            tags.append("KEV", style="kev")
        if group.fixed:
            tags.append(" " if tags else "").append("corregido", style="fixed")
        title = _open_ports_title(group) if group.open_ports else group.title
        room = console.width - _PREFIX - (tags.cell_len + 2 if tags else 0)
        for number, part in enumerate(wrap(console, Text(title, style="info" if group.open_ports else ""), room)):
            line = Text()
            if number == 0:
                line.append(f" {group.priority:<8}  ", style=group.priority.lower())
                line.append(f"{group.cvss:>3.1f}" if group.cvss is not None else "   ", style="muted")
                line.append("  ")
            else:
                line.append(indent)
            line.append_text(part)
            if number == 0 and tags:
                line.append(" " * max(console.width - line.cell_len - tags.cell_len, 2))
                line.append_text(tags)
            emit(console, line)
        sublines = []
        if group.locations and not group.open_ports:
            sublines.append(sep.join(f"{port}/{proto}" if proto else str(port) for port, proto in group.locations))
        if group.vhosts:
            sublines.append(sep.join(group.vhosts))
        for subline in sublines:
            for part in wrap(console, Text(f"{sym.branch} {subline}", style="muted"), console.width - _PREFIX):
                emit(console, Text(indent).append_text(part))

    console.print(Text(sym.rule * min(console.width, 40), style="muted"))
    paragraph(console, f" {_plural(len(findings), ('hallazgo', 'hallazgos'))} {sym.sep} "
                       f"{_plural(len(groups), ('distinto', 'distintos'))}")
    summary = Text(" ")
    for priority in reversed(PRIORITY_LADDER):
        count = sum(1 for group in groups if group.priority == priority)
        if count:
            summary.append(f"{sym.dot} ", style=priority.lower())
            summary.append(f"{_plural(count, _PRIORITY_NOUNS[priority])}  ")
    kev = sum(1 for group in groups if group.kev)
    if kev:
        summary.append(f"{sym.sep} {kev} en KEV", style="kev")
    paragraph(console, summary)


def _duration(result: dict) -> Optional[str]:
    """La duración del escaneo a partir de ``startedAt`` y ``finishedAt``, si están."""
    try:
        started = datetime.fromisoformat(str(result["startedAt"]).replace("Z", "+00:00"))
        finished = datetime.fromisoformat(str(result["finishedAt"]).replace("Z", "+00:00"))
    except (KeyError, ValueError):
        return None
    seconds = max((finished - started).total_seconds(), 0)
    return f"{seconds:.1f}s" if seconds < 60 else f"{int(seconds // 60)}m {int(seconds % 60):02d}s"


def render_result(console: Console, result: dict) -> None:
    """
    Escribe el resultado de un escaneo: cabecera, aviso de parcial y hallazgos.

    Args:
        console: La consola de stdout.
        result: La respuesta de ``scan.result``.
    """
    sym = symbols_for(console)
    parts = [str(result.get("target")), str(result.get("status")),
             _plural(len(result.get("services") or []), ("servicio", "servicios"))]
    duration = _duration(result)
    if duration:
        parts.append(duration)
    paragraph(console, f" {sym.sep} ".join(parts), "bold")
    if result.get("status") == "partial":
        paragraph(console, f"{sym.warn} Resultado PARCIAL: lo que no aparece no se ha comprobado.", "warn")
    console.print()
    render_findings(console, result.get("findings") or [])
