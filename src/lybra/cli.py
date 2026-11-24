"""``lybra``: la línea de órdenes del motor, cliente de ``lybrad``.

Ejemplos::

    lybra info
    lybra scan 203.0.113.10 --profile fast          # espera y muestra los hallazgos
    lybra scan 203.0.113.10 --no-wait               # sólo encola y dice el identificador
    lybra result <scanId> --json
    lybra analyze --cpe cpe:2.3:a:openssl:openssl --version 3.0.1
    lybra analyze --product "Apache httpd" --version 2.4.49
    lybra kb status
    lybra kb sync --source kev
    lybra kb cve CVE-2024-6387
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from lybra_client import LybraClient, LybraError

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _print_json(value) -> None:
    """Escribe un valor como JSON legible."""
    json.dump(value, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


def _print_findings(findings: List[dict]) -> None:
    """Escribe los hallazgos como tabla, los más graves primero y los informativos al final."""
    def key(finding: dict):
        return (_SEVERITY_ORDER.get((finding.get("severity") or "").upper(), 4),
                -(finding.get("cvssScore") or 0), finding.get("port") or 0)

    for finding in sorted(findings, key=key):
        where = f"{finding.get('port')}/{finding.get('protocol')}" if finding.get("port") else "-"
        score = finding.get("cvssScore")
        marks = "".join(mark for flag, mark in ((finding.get("inKev"), " [KEV]"),
                                                (finding.get("state") == "fixed", " [corregido]")) if flag)
        print(f"{where:>10}  {(f'{score:.1f}' if score is not None else '-'):>4}  {finding.get('title')}{marks}")
    print(f"\n{len(findings)} hallazgos")


def _scan(client: LybraClient, arguments) -> int:
    """``lybra scan``: encola un escaneo y, salvo ``--no-wait``, espera y muestra el resultado."""
    scan_id = client.scan_start(
        arguments.target, profile=arguments.profile, aggressive=arguments.aggressive,
        active_checks=not arguments.no_active_checks,
        ports=[int(port) for port in arguments.ports.split(",")] if arguments.ports else None,
        timeout_seconds=arguments.timeout or None)
    if arguments.no_wait:
        print(scan_id)
        return 0

    def show(progress: dict) -> None:
        if not arguments.json:
            total = progress.get("total") or 0
            done = f" {progress.get('done')}/{total}" if total else ""
            print(f"\r[{progress.get('status')}] {progress.get('phase') or '…'}{done}   ", end="", file=sys.stderr,
                  flush=True)

    final = client.scan_watch(scan_id, on_progress=show)
    if not arguments.json:
        print(file=sys.stderr)
    if final["status"] == "failed":
        print(f"El escaneo falló: {final.get('error', {}).get('message')}", file=sys.stderr)
        return 1
    return _show_result(client.scan_result(scan_id), arguments.json)


def _show_result(result: dict, as_json: bool) -> int:
    """Muestra el resultado de un escaneo, como JSON o como tabla."""
    if as_json:
        _print_json(result)
        return 0
    print(f"{result['target']}: {result['status']} ({len(result['services'])} servicios)")
    if result["status"] == "partial":
        print("Resultado PARCIAL: lo que no aparece no se ha comprobado.")
    _print_findings(result["findings"])
    return 0


def _analyze(client: LybraClient, arguments) -> int:
    """``lybra analyze``: las CVE de un producto o CPE en una versión, sin tocar la red."""
    if not (arguments.cpe or arguments.product):
        print("Hace falta --cpe o --product", file=sys.stderr)
        return 2
    service = {"version": arguments.version, "origin": "inventory"}
    service["cpe" if arguments.cpe else "product"] = arguments.cpe or arguments.product
    result = client.analyze([service])
    if arguments.json:
        _print_json(result)
    else:
        _print_findings(result["findings"])
    return 0


def _kb(client: LybraClient, arguments) -> int:
    """``lybra kb …``: estado, sincronización y consultas de la base de conocimiento."""
    if arguments.kb_command == "status":
        status = client.call("kb.status")
        if arguments.json:
            _print_json(status)
            return 0
        for entry in status["sources"]:
            state = "VIEJA" if entry["isStale"] else ("sin verificar" if entry["isUnverified"] else "al día")
            age = f"{entry['ageDays']} días" if entry["ageDays"] is not None else "nunca sincronizada"
            error = f" — {entry['error']}" if entry["error"] else ""
            print(f"{entry['source']:<20} {state:<14} {age}{error}")
        print(f"\n{status['feedVersion']}")
        return 0
    if arguments.kb_command == "sync":
        _print_json(client.call("kb.sync", {"source": arguments.source}))
        return 0
    if arguments.kb_command == "cve":
        _print_json(client.call("kb.cve", {"cveId": arguments.cve_id}))
        return 0
    _print_json(client.call("kb.version", {"product": arguments.product, "version": arguments.version}))
    return 0


def build_parser() -> argparse.ArgumentParser:
    """
    Construye el analizador de argumentos de ``lybra``.

    Returns:
        argparse.ArgumentParser: Con las órdenes ``info``, ``scan``, ``status``,
            ``result``, ``cancel``, ``analyze`` y ``kb``.
    """
    parser = argparse.ArgumentParser(prog="lybra", description="Cliente del motor de escaneo Lybra.")
    parser.add_argument("--socket", help="ruta del socket de lybrad (por defecto LYBRA_SOCKET o "
                                         "/run/lybra/lybra.sock)")
    parser.add_argument("--json", action="store_true", help="salida en JSON")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("info", help="versión del motor y estado de su base de conocimiento")

    scan = commands.add_parser("scan", help="escanear un objetivo")
    scan.add_argument("target", help="IP o nombre de host")
    scan.add_argument("--profile", choices=("fast", "standard", "thorough"), default="standard")
    scan.add_argument("--ports", help="puertos TCP separados por comas; sustituye al perfil")
    scan.add_argument("--timeout", type=float, help="presupuesto de reloj del escaneo, en segundos")
    scan.add_argument("--aggressive", action="store_true",
                      help="permitir checks que escriben en el objetivo y credenciales por defecto")
    scan.add_argument("--no-active-checks", action="store_true", help="no ejecutar checks activos")
    scan.add_argument("--no-wait", action="store_true", help="encolar y devolver el identificador")

    for name, text in (("status", "estado de un escaneo"), ("result", "resultado de un escaneo"),
                       ("cancel", "cancelar un escaneo")):
        command = commands.add_parser(name, help=text)
        command.add_argument("scan_id")

    analyze = commands.add_parser("analyze", help="CVE de un producto o CPE en una versión, sin red")
    analyze.add_argument("--cpe")
    analyze.add_argument("--product")
    analyze.add_argument("--version", required=True)

    kb = commands.add_parser("kb", help="base de conocimiento")
    kb_commands = kb.add_subparsers(dest="kb_command", required=True)
    kb_commands.add_parser("status", help="estado de cada fuente")
    sync = kb_commands.add_parser("sync", help="sincronizar en segundo plano")
    sync.add_argument("--source", default="all", choices=("all", "nvd", "kev", "epss", "oval"))
    cve = kb_commands.add_parser("cve", help="ficha de una CVE")
    cve.add_argument("cve_id")
    version = kb_commands.add_parser("version", help="CVE de un producto en una versión")
    version.add_argument("product")
    version.add_argument("version")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """
    Ejecuta una orden de ``lybra``.

    Args:
        argv: Los argumentos; ``None`` usa ``sys.argv``.

    Returns:
        int: 0 si salió bien; 1 si el motor devolvió un error o un escaneo
            falló; 2 por un uso incorrecto; 3 si no se pudo hablar con ``lybrad``.
    """
    arguments = build_parser().parse_args(argv)
    client = LybraClient(arguments.socket)
    try:
        if arguments.command == "info":
            _print_json(client.info())
        elif arguments.command == "scan":
            return _scan(client, arguments)
        elif arguments.command == "status":
            _print_json(client.scan_status(arguments.scan_id))
        elif arguments.command == "result":
            return _show_result(client.scan_result(arguments.scan_id), arguments.json)
        elif arguments.command == "cancel":
            _print_json(client.scan_cancel(arguments.scan_id))
        elif arguments.command == "analyze":
            return _analyze(client, arguments)
        else:
            return _kb(client, arguments)
    except LybraError as error:
        print(f"Error del motor ({error.code}): {error.message}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"No se pudo hablar con lybrad en {client.socket_path}: {error}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
