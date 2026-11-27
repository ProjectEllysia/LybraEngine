"""``lybrad``: el servicio del motor, escuchando en un socket Unix.

Lee las peticiones línea a línea (``protocol``), se las pasa a
:class:`~lybra.app.service.EngineService` y escribe las respuestas. Cada conexión
tiene su hilo; una conexión puede llevar varias peticiones seguidas.

El socket se crea con permisos ``0660`` y, si existe, con el grupo ``lybra``:
quien pertenece al grupo puede usar el motor y nadie más llega al socket.

La configuración sale, por orden de prioridad, de los argumentos, de las
variables de entorno (``LYBRA_SOCKET``, ``LYBRA_KB``, ``LYBRA_NVD_API_KEY``,
``LYBRA_SHODAN_API_KEY``, ``LYBRA_CENSYS_API_KEY``, ``LYBRA_SECURITYTRAILS_API_KEY``) y de
un fichero TOML (``/etc/lybra/lybrad.toml`` o el de ``--config``)::

    [daemon]
    socket = "/run/lybra/lybra.sock"
    socket_group = "lybra"
    max_concurrent_scans = 4
    max_queued_scans = 32
    allow_private_targets = false

    [kb]
    path = "/var/lib/lybra/kb.sqlite"
    sync_interval_hours = 24      # 0 desactiva la sincronización periódica
    nvd_window_days = 8

    [scan]                        # cualquier campo de lybra.core.scanner.ScanSettings
    tcp_concurrency = 200

    [osint]                       # cualquier campo de lybra.recon.osint_network.OsintSettings
    ttl_hours = 24                # (las claves de API, mejor en el entorno)
    enabled_sources = ["crtsh", "shodan", "censys", "securitytrails"]
"""

from __future__ import annotations

import argparse
import dataclasses
import grp
import logging
import os
import signal
import socketserver
import sys
import threading
import tomllib
from pathlib import Path
from typing import Optional

from . import protocol
from ..kb.sync import SyncSettings
from ..kb.store import KnowledgeBase
from .protocol import ProtocolError
from ..recon.osint import OsintSource
from ..recon.osint_network import OsintSettings
from ..core.scanner import ScanSettings
from .service import EngineService, ServiceSettings

logger = logging.getLogger("lybrad")

DEFAULT_CONFIG = "/etc/lybra/lybrad.toml"
DEFAULT_KB = "/var/lib/lybra/kb.sqlite"


class _Handler(socketserver.StreamRequestHandler):
    """Atiende una conexión: una petición por línea, una respuesta final por petición."""

    def handle(self) -> None:
        """Lee peticiones hasta que el cliente cierra o manda una línea demasiado larga."""
        service: EngineService = self.server.service  # type: ignore[attr-defined]
        write_lock = threading.Lock()

        def send(message: dict) -> None:
            with write_lock:
                self.wfile.write(protocol.encode(message))
                self.wfile.flush()

        while True:
            line = self.rfile.readline(protocol.MAX_LINE_BYTES + 1)
            if not line:
                return
            if len(line) > protocol.MAX_LINE_BYTES:
                send(protocol.error_response(None, protocol.BAD_REQUEST, "la línea supera el tamaño máximo"))
                return
            if not line.strip():
                continue
            try:
                request = protocol.decode_request(line)
            except ProtocolError as error:
                send(protocol.error_response(None, error.code, error.message))
                continue
            try:
                send(service.handle(request, emit=send))
            except (BrokenPipeError, ConnectionResetError):
                return


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """Servidor de socket Unix con un hilo por conexión."""

    daemon_threads = True
    allow_reuse_address = True


def serve(service: EngineService, socket_path: str, group: Optional[str] = "lybra") -> _Server:
    """
    Abre el socket y devuelve el servidor, sin empezar a atender.

    Un socket viejo de una ejecución anterior se borra antes de crear el nuevo.

    Args:
        service: El núcleo que atiende las peticiones.
        socket_path: Dónde se crea el socket.
        group: El grupo dueño del socket, si existe en el sistema; ``None``
            para no cambiarlo. Por defecto ``"lybra"``.

    Returns:
        El servidor, listo para ``serve_forever()``.
    """
    path = Path(socket_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_socket():
        path.unlink()
    server = _Server(str(path), _Handler)
    server.service = service  # type: ignore[attr-defined]
    os.chmod(path, 0o660)
    if group:
        try:
            os.chown(path, -1, grp.getgrnam(group).gr_gid)
        except (KeyError, PermissionError):
            logger.warning("No se pudo dar el socket al grupo %r; queda con el grupo del proceso", group)
    return server


def load_settings(config_path: Optional[str]) -> dict:
    """
    Lee el fichero de configuración TOML.

    Args:
        config_path: La ruta, o ``None`` para probar :data:`DEFAULT_CONFIG`.

    Returns:
        dict: Las secciones ``daemon``, ``kb`` y ``scan``, vacías si el fichero
            no existe (y no se pidió uno concreto).

    Raises:
        SystemExit: Si se pidió un fichero que no existe, o no es TOML válido.
    """
    path = Path(config_path or DEFAULT_CONFIG)
    if not path.exists():
        if config_path:
            raise SystemExit(f"no existe el fichero de configuración {path}")
        return {}
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        raise SystemExit(f"{path} no es TOML válido: {error}") from error


def build_service_settings(config: dict, allow_private: Optional[bool] = None) -> ServiceSettings:
    """
    Construye los ajustes del servicio a partir de la configuración leída.

    Args:
        config: Lo que devolvió :func:`load_settings`.
        allow_private: Si se pasó ``--allow-private-targets``, que manda sobre el
            fichero; ``None`` deja mandar al fichero.

    Returns:
        ServiceSettings: Los ajustes.

    Raises:
        SystemExit: Si ``[scan]`` trae una clave que no es un ajuste del motor.
    """
    daemon, kb, scan = config.get("daemon", {}), config.get("kb", {}), config.get("scan", {})
    known = {item.name for item in dataclasses.fields(ScanSettings)}
    unknown = set(scan) - known
    if unknown:
        raise SystemExit(f"claves desconocidas en [scan]: {', '.join(sorted(unknown))}")
    sync = SyncSettings(nvd_window_days=kb.get("nvd_window_days", 8),
                        nvd_api_key=os.environ.get("LYBRA_NVD_API_KEY") or kb.get("nvd_api_key"))
    return ServiceSettings(
        osint=_build_osint_settings(config.get("osint", {})),
        max_concurrent_scans=daemon.get("max_concurrent_scans", 4),
        max_queued_scans=daemon.get("max_queued_scans", 32),
        allow_private_targets=allow_private if allow_private is not None
        else daemon.get("allow_private_targets", False),
        scan=ScanSettings(**scan),
        sync=sync,
    )


def _build_osint_settings(osint: dict) -> OsintSettings:
    """
    Construye los ajustes de la inteligencia pasiva desde ``[osint]`` y el entorno.

    Args:
        osint: La sección ``[osint]`` del fichero (vacía si no está). Sus claves
            son los campos de ``OsintSettings`` y, para las claves de API,
            ``<fuente>_api_key``; la variable ``LYBRA_<FUENTE>_API_KEY`` manda
            sobre el fichero.

    Returns:
        OsintSettings: Los ajustes.

    Raises:
        SystemExit: Si ``[osint]`` trae una clave desconocida.
    """
    keys = {f"{source.value}_api_key": source.value for source in OsintSource}
    fields = {item.name for item in dataclasses.fields(OsintSettings)} - {"api_keys"}
    unknown = set(osint) - fields - set(keys)
    if unknown:
        raise SystemExit(f"claves desconocidas en [osint]: {', '.join(sorted(unknown))}")
    api_keys = {source: os.environ.get(f"LYBRA_{source.upper()}_API_KEY") or osint.get(key) or ""
                for key, source in keys.items()}
    values = {name: osint[name] for name in fields if name in osint}
    if "enabled_sources" in values:
        values["enabled_sources"] = tuple(values["enabled_sources"])
    return OsintSettings(**values, api_keys={source: key for source, key in api_keys.items() if key})


def _periodic_sync(service: EngineService, interval_hours: float, stop: threading.Event) -> None:
    """Sincroniza la base al arrancar si está vacía y después cada ``interval_hours`` horas."""
    if not service.kb.counts()["cves"]:
        logger.info("La base de conocimiento está vacía: se sincroniza ahora")
        service.start_sync()
    while not stop.wait(interval_hours * 3600):
        service.start_sync()


def main(argv=None) -> int:
    """
    Arranca ``lybrad`` y atiende hasta recibir SIGTERM o SIGINT.

    Args:
        argv: Los argumentos; ``None`` usa ``sys.argv``.

    Returns:
        int: 0 al terminar de forma ordenada.
    """
    parser = argparse.ArgumentParser(prog="lybrad", description="El servicio del motor de escaneo Lybra.")
    parser.add_argument("--config", help=f"fichero TOML (por defecto {DEFAULT_CONFIG}, si existe)")
    parser.add_argument("--socket", help=f"ruta del socket (por defecto {protocol.DEFAULT_SOCKET})")
    parser.add_argument("--kb", help=f"fichero de la base de conocimiento (por defecto {DEFAULT_KB})")
    parser.add_argument("--allow-private-targets", action="store_true", default=None,
                        help="admitir objetivos en redes privadas")
    parser.add_argument("--log-level", default="INFO")
    arguments = parser.parse_args(argv)
    logging.basicConfig(level=arguments.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    config = load_settings(arguments.config)
    daemon_config, kb_config = config.get("daemon", {}), config.get("kb", {})
    socket_path = arguments.socket or os.environ.get("LYBRA_SOCKET") or daemon_config.get(
        "socket", protocol.DEFAULT_SOCKET)
    kb_path = arguments.kb or os.environ.get("LYBRA_KB") or kb_config.get("path", DEFAULT_KB)

    service = EngineService(KnowledgeBase(kb_path), build_service_settings(config, arguments.allow_private_targets))
    server = serve(service, socket_path, daemon_config.get("socket_group", "lybra"))
    stop = threading.Event()
    interval = kb_config.get("sync_interval_hours", 24)
    if interval:
        threading.Thread(target=_periodic_sync, args=(service, interval, stop), name="lybra-kb-schedule",
                         daemon=True).start()

    def terminate(signum, _frame) -> None:
        logger.info("Señal %s: cerrando", signal.Signals(signum).name)
        stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    logger.info("lybrad escuchando en %s (base de conocimiento: %s, objetivos privados: %s)", socket_path,
                kb_path, "sí" if service.settings.allow_private_targets else "no")
    try:
        server.serve_forever()
    finally:
        service.shutdown()
        server.server_close()
        Path(socket_path).unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
