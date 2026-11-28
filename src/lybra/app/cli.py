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
    lybra kb backfill --since 2020-01-01
    lybra kb cve CVE-2024-6387
    lybra osint domain example.com --dkim-selector selector1
    lybra osint hostnames 203.0.113.10
    lybra cloud probe --resource s3:mi-bucket --subdomain app.example.com
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from lybra_client import LybraClient, LybraError
from rich.text import Text

from lybra.app.ui.console import COLOR_MODES, make_consoles, symbols_for
from lybra.app.ui import views
from lybra.app.ui.findings import render_findings, render_result
from lybra.app.ui.progress import BackfillView, PhaseView


def _print_json(value) -> None:
    """Escribe un valor como JSON legible."""
    json.dump(value, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


def _scan(client: LybraClient, arguments, out, err) -> int:
    """``lybra scan``: encola un escaneo y, salvo ``--no-wait``, espera y muestra el resultado."""
    scan_id = client.scan_start(
        arguments.target, profile=arguments.profile, aggressive=arguments.aggressive,
        active_checks=not arguments.no_active_checks,
        ports=[int(port) for port in arguments.ports.split(",")] if arguments.ports else None,
        timeout_seconds=arguments.timeout or None, enrich=arguments.enrich or None)
    if arguments.no_wait:
        print(scan_id)
        return 0

    if arguments.json:
        final = client.scan_watch(scan_id, on_progress=lambda _progress: None)
    else:
        cancelled = False
        with PhaseView(err, arguments.target, arguments.profile) as view:
            try:
                final = client.scan_watch(scan_id, on_progress=view)
                view.finish(final["status"])
            except KeyboardInterrupt:
                view.finish("cancelled")
                cancelled = True
        if cancelled:
            _fail(err, "Operación cancelada por el usuario.")
            return 130
    if final["status"] == "failed":
        _fail(err, f"El escaneo falló: {final.get('error', {}).get('message')}")
        return 1
    return _show_result(client.scan_result(scan_id), arguments.json, out)


def _fail(err, message: str) -> None:
    """Escribe un error en stderr, con ``✗`` y en rojo si hay color."""
    text = Text(f"{symbols_for(err).err} {message}", style="err")
    err.print(text, soft_wrap=True)


def _show_result(result: dict, as_json: bool, out) -> int:
    """Muestra el resultado de un escaneo, como JSON o como bloques agrupados."""
    if as_json:
        _print_json(result)
    else:
        render_result(out, result)
    return 0


def _analyze(client: LybraClient, arguments, out, err) -> int:
    """``lybra analyze``: las CVE de un producto o CPE en una versión, sin tocar la red."""
    if not (arguments.cpe or arguments.product):
        _fail(err, "Hace falta --cpe o --product")
        return 2
    service = {"version": arguments.version, "origin": "inventory"}
    service["cpe" if arguments.cpe else "product"] = arguments.cpe or arguments.product
    if arguments.enrich and not arguments.target:
        _fail(err, "--enrich necesita --target")
        return 2
    result = client.analyze([service], enrich=arguments.enrich or None, target=arguments.target)
    if arguments.json:
        _print_json(result)
    else:
        render_findings(out, result["findings"])
    return 0


def _emit(value, as_json: bool, out, render) -> None:
    """Escribe ``value`` como JSON (``--json``) o con la vista ``render(out, value)``."""
    if as_json:
        _print_json(value)
    else:
        render(out, value)


def _passive(client: LybraClient, arguments, out, err) -> int:
    """``lybra osint ...`` y ``lybra cloud probe``: inteligencia pasiva y exposición cloud."""
    timeout = arguments.timeout or None
    if arguments.command == "cloud":
        if not (arguments.resource or arguments.subdomain):
            _fail(err, "Hace falta --resource o --subdomain")
            return 2
        _emit(client.cloud_probe(arguments.resource, arguments.subdomain, timeout_seconds=timeout),
              arguments.json, out, views.render_cloud)
    elif arguments.osint_command == "domain":
        _emit(client.osint_domain(arguments.domain, sources=arguments.source or None,
                                  dkim_selectors=arguments.dkim_selector or None, timeout_seconds=timeout),
              arguments.json, out, views.render_osint_domain)
    else:
        names = client.osint_hostnames(arguments.address, timeout_seconds=timeout)
        _emit(names, arguments.json, out, lambda console, value: views.render_hostnames(console, value,
                                                                                         arguments.address))
    return 0


def _kb(client: LybraClient, arguments, out, err) -> int:
    """``lybra kb ...``: estado, sincronización y consultas de la base de conocimiento."""
    if arguments.kb_command == "status":
        _emit(client.call("kb.status"), arguments.json, out, views.render_kb_status)
    elif arguments.kb_command == "sync":
        _emit(client.call("kb.sync", {"source": arguments.source}), arguments.json, out, views.render_sync)
    elif arguments.kb_command == "cve":
        _emit(client.call("kb.cve", {"cveId": arguments.cve_id}), arguments.json, out, views.render_cve)
    elif arguments.kb_command == "backfill":
        return _kb_backfill(client, arguments, out, err)
    else:
        _emit(client.call("kb.version", {"product": arguments.product, "version": arguments.version}),
              arguments.json, out, lambda console, value: views.render_version(console, value, arguments.product,
                                                                                arguments.version))
    return 0


def _kb_backfill(client: LybraClient, arguments, out, err) -> int:
    """``lybra kb backfill``: primer llenado histórico de CVE desde NVD."""
    from datetime import datetime
    import os
    try:
        start_dt = datetime.strptime(arguments.since, "%Y-%m-%d")
    except ValueError:
        _fail(err, f"Fecha 'since' inválida (debe ser YYYY-MM-DD): {arguments.since}")
        return 2

    end_dt = None
    if arguments.until:
        try:
            end_dt = datetime.strptime(arguments.until, "%Y-%m-%d")
        except ValueError:
            _fail(err, f"Fecha 'until' inválida (debe ser YYYY-MM-DD): {arguments.until}")
            return 2
        if start_dt >= end_dt:
            _fail(err, f"La fecha 'since' ({arguments.since}) no puede ser posterior o igual a 'until' ({arguments.until})")
            return 2

    def run_backfill(on_progress):
        if arguments.kb:
            from lybra.kb.store import KnowledgeBase
            from lybra.kb.sync import KnowledgeBaseSync, SyncSettings
            base = KnowledgeBase(arguments.kb)
            try:
                sync = KnowledgeBaseSync(base, SyncSettings(nvd_api_key=os.environ.get("LYBRA_NVD_API_KEY") or None))
                return sync.backfill_nvd(start_dt, end_dt, on_progress=on_progress)
            finally:
                base.close()
        else:
            params = {"since": arguments.since}
            if arguments.until:
                params["until"] = arguments.until
            return client.call(
                "kb.backfill",
                params,
                on_event=(lambda ev, data: on_progress(data) if ev == "progress" else None) if on_progress else None,
                timeout=None
            )

    try:
        if arguments.json:
            summary = run_backfill(None)
            _print_json(summary)
        else:
            with BackfillView(err, arguments.since, arguments.until) as view:
                try:
                    summary = run_backfill(view)
                except KeyboardInterrupt:
                    view.finish(False)
                    return 130
                view.finish(True)
            views.render_backfill(out, summary)
    except Exception as error:
        if arguments.kb:
            _fail(err, f"Falló el backfill de NVD: {error}")
            return 1
        raise

    return 0



def build_parser() -> argparse.ArgumentParser:
    """
    Construye el analizador de argumentos de ``lybra``.

    Returns:
        argparse.ArgumentParser: Con las órdenes ``info``, ``scan``, ``status``,
            ``result``, ``cancel``, ``analyze``, ``kb``, ``osint`` y ``cloud``.
    """
    parser = argparse.ArgumentParser(prog="lybra", description="Cliente del motor de escaneo Lybra.")
    parser.add_argument("--socket", help="ruta del socket de lybrad (por defecto LYBRA_SOCKET o "
                                         "/run/lybra/lybra.sock)")
    parser.add_argument("--json", action="store_true", help="salida en JSON")
    parser.add_argument("--color", choices=COLOR_MODES, default="auto",
                        help="color en la salida (respeta NO_COLOR y FORCE_COLOR con auto)")
    # --json y --color también se aceptan tras la suborden; sin valor por defecto para no pisar el de arriba.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    common.add_argument("--color", choices=COLOR_MODES, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("info", parents=[common], help="versión del motor y estado de su base de conocimiento")

    scan = commands.add_parser("scan", parents=[common], help="escanear un objetivo")
    scan.add_argument("target", help="IP o nombre de host")
    scan.add_argument("--profile", choices=("fast", "standard", "thorough"), default="standard")
    scan.add_argument("--ports", help="puertos TCP separados por comas; sustituye al perfil")
    scan.add_argument("--timeout", type=float, help="presupuesto de reloj del escaneo, en segundos")
    scan.add_argument("--aggressive", action="store_true",
                      help="permitir checks que escriben en el objetivo y credenciales por defecto")
    scan.add_argument("--no-active-checks", action="store_true", help="no ejecutar checks activos")
    scan.add_argument("--enrich", action="store_true",
                      help="preguntar a Shodan y Censys por la IP del objetivo (se lo revela a un tercero)")
    scan.add_argument("--no-wait", action="store_true", help="encolar y devolver el identificador")

    for name, text in (("status", "estado de un escaneo"), ("result", "resultado de un escaneo"),
                       ("cancel", "cancelar un escaneo")):
        command = commands.add_parser(name, parents=[common], help=text)
        command.add_argument("scan_id")

    analyze = commands.add_parser("analyze", parents=[common], help="CVE de un producto o CPE en una versión, sin red")
    analyze.add_argument("--cpe")
    analyze.add_argument("--product")
    analyze.add_argument("--version", required=True)
    analyze.add_argument("--enrich", action="store_true", help="preguntar a Shodan y Censys por --target")
    analyze.add_argument("--target", help="la IP a la que pertenece el servicio (con --enrich)")

    osint = commands.add_parser("osint", parents=[common], help="inteligencia pasiva: fuentes de terceros y DNS público")
    osint_commands = osint.add_subparsers(dest="osint_command", required=True)
    domain = osint_commands.add_parser("domain", parents=[common], help="subdominios, servicios vistos y higiene DNS de un dominio")
    domain.add_argument("domain")
    domain.add_argument("--source", action="append", choices=("crtsh", "shodan", "censys", "securitytrails"),
                        help="limita la consulta a esta fuente (repetible)")
    domain.add_argument("--dkim-selector", action="append", help="selector DKIM que comprobar (repetible)")
    hostnames = osint_commands.add_parser("hostnames", parents=[common], help="nombres que Shodan y Censys asocian a una IP")
    hostnames.add_argument("address")
    cloud = commands.add_parser("cloud", parents=[common], help="exposición cloud")
    cloud_commands = cloud.add_subparsers(dest="cloud_command", required=True)
    probe = cloud_commands.add_parser("probe", parents=[common], help="recursos cloud abiertos y subdominios con takeover")
    probe.add_argument("--resource", action="append", help="proveedor:identificador, p. ej. s3:bucket (repetible)")
    probe.add_argument("--subdomain", action="append", help="subdominio que comprobar (repetible)")
    for command in (domain, hostnames, probe):
        command.add_argument("--timeout", type=float, help="plazo del motor para la consulta, en segundos")

    kb = commands.add_parser("kb", parents=[common], help="base de conocimiento")
    kb_commands = kb.add_subparsers(dest="kb_command", required=True)
    kb_commands.add_parser("status", parents=[common], help="estado de cada fuente")
    sync = kb_commands.add_parser("sync", parents=[common], help="sincronizar en segundo plano")
    sync.add_argument("--source", default="all", choices=("all", "nvd", "kev", "epss", "oval"))
    backfill = kb_commands.add_parser("backfill", parents=[common], help="primer llenado histórico de CVE desde NVD")
    backfill.add_argument("--since", default="1999-01-01", help="fecha inicial YYYY-MM-DD (por defecto 1999-01-01)")
    backfill.add_argument("--until", default=None, help="fecha final YYYY-MM-DD (por defecto hoy)")
    backfill.add_argument("--kb", default=None, help="poblar directamente este fichero SQLite sin pasar por lybrad")
    cve = kb_commands.add_parser("cve", parents=[common], help="ficha de una CVE")
    cve.add_argument("cve_id")
    version = kb_commands.add_parser("version", parents=[common], help="CVE de un producto en una versión")
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
    out, err = make_consoles(arguments.color)
    client = LybraClient(arguments.socket)
    try:
        if arguments.command == "info":
            _emit(client.info(), arguments.json, out, views.render_info)
        elif arguments.command == "scan":
            return _scan(client, arguments, out, err)
        elif arguments.command == "status":
            _emit(client.scan_status(arguments.scan_id), arguments.json, out, views.render_scan_status)
        elif arguments.command == "result":
            return _show_result(client.scan_result(arguments.scan_id), arguments.json, out)
        elif arguments.command == "cancel":
            _emit(client.scan_cancel(arguments.scan_id), arguments.json, out, views.render_cancel)
        elif arguments.command == "analyze":
            return _analyze(client, arguments, out, err)
        elif arguments.command in ("osint", "cloud"):
            return _passive(client, arguments, out, err)
        else:
            return _kb(client, arguments, out, err)
    except KeyboardInterrupt:
        _fail(err, "Operación cancelada por el usuario.")
        return 130
    except LybraError as error:
        _fail(err, f"Error del motor ({error.code}): {error.message}")
        return 1
    except OSError as error:
        _fail(err, f"No se pudo hablar con lybrad en {client.socket_path}: {error}")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
