"""Cliente del protocolo de ``lybrad``, sólo con la biblioteca estándar.

Abre una conexión al socket por petición: es lo más simple y, en un socket
local, no cuesta nada medible.

Ejemplo::

    client = LybraClient()
    scan_id = client.scan_start("203.0.113.10", profile="fast")
    client.scan_watch(scan_id, on_progress=print)
    result = client.scan_result(scan_id)
"""

from __future__ import annotations

import itertools
import json
import os
import socket
from typing import Any, Callable, Dict, List, Optional

from . import protocol


class LybraError(Exception):
    """El motor contestó con un error.

    Attributes:
        code: El código del protocolo (``invalid_params``, ``not_found``…).
        message: La explicación del motor.
    """

    def __init__(self, code: str, message: str) -> None:
        """
        Crea el error.

        Args:
            code: El código del protocolo.
            message: La explicación.
        """
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class LybraClient:
    """Habla con ``lybrad`` por su socket Unix.

    Attributes:
        socket_path: La ruta del socket.
        timeout: Segundos de espera de cada respuesta; ``None`` espera sin límite.
    """

    def __init__(self, socket_path: Optional[str] = None, timeout: Optional[float] = 60.0) -> None:
        """
        Prepara el cliente.

        Args:
            socket_path: La ruta del socket; ``None`` usa ``LYBRA_SOCKET`` o
                ``/run/lybra/lybra.sock``.
            timeout: Segundos de espera de cada respuesta. Por defecto 60;
                ``None`` sin límite (lo que usa :meth:`scan_watch`).
        """
        self.socket_path = socket_path or os.environ.get("LYBRA_SOCKET") or protocol.DEFAULT_SOCKET
        self.timeout = timeout
        self._ids = itertools.count(1)

    def call(self, op: str, params: Optional[Dict[str, Any]] = None,
             on_event: Optional[Callable[[str, Any], None]] = None, timeout: Optional[float] = -1) -> Any:
        """
        Envía una petición y espera su respuesta final.

        Args:
            op: La operación (``scan.start``, ``kb.cve``…).
            params: Sus parámetros. Por defecto ninguno.
            on_event: Recibe ``(nombre, datos)`` por cada evento intermedio.
                Por defecto ``None``.
            timeout: Segundos de espera; ``-1`` usa :attr:`timeout`.

        Returns:
            El ``result`` de la respuesta.

        Raises:
            LybraError: Si el motor contesta con un error.
            OSError: Si no se puede hablar con el socket.
        """
        request_id = f"c-{os.getpid()}-{next(self._ids)}"
        message = {"v": protocol.PROTOCOL_VERSION, "id": request_id, "op": op, "params": params or {}}
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(self.timeout if timeout == -1 else timeout)
            connection.connect(self.socket_path)
            connection.sendall(protocol.encode(message))
            reader = connection.makefile("rb")
            while True:
                line = reader.readline(protocol.MAX_LINE_BYTES + 1)
                if not line:
                    raise ConnectionError("el motor cerró la conexión sin responder")
                reply = json.loads(line)
                if "event" in reply:
                    if on_event is not None:
                        on_event(reply["event"], reply.get("data"))
                    continue
                if reply.get("ok"):
                    return reply.get("result")
                error = reply.get("error") or {}
                raise LybraError(error.get("code", protocol.INTERNAL), error.get("message", ""))

    # ------------------------------------------------------------ atajos

    def info(self) -> dict:
        """Versiones del motor y estado de su base de conocimiento (``engine.info``)."""
        return self.call("engine.info")

    def scan_start(self, target: str, **params) -> str:
        """
        Encola un escaneo (``scan.start``).

        Args:
            target: IP o nombre del objetivo.
            **params: El resto de parámetros del protocolo (``profile``,
                ``ports``, ``timeoutSeconds``, ``knownServices``…).

        Returns:
            str: El identificador del escaneo.
        """
        return self.call("scan.start", {"target": target, **params})["scanId"]

    def scan_status(self, scan_id: str) -> dict:
        """El estado de un escaneo (``scan.status``)."""
        return self.call("scan.status", {"scanId": scan_id})

    def scan_watch(self, scan_id: str, on_progress: Optional[Callable[[dict], None]] = None) -> dict:
        """
        Espera a que un escaneo termine (``scan.watch``).

        Args:
            scan_id: El escaneo.
            on_progress: Recibe cada evento de progreso. Por defecto ``None``.

        Returns:
            dict: El estado final.
        """
        return self.call("scan.watch", {"scanId": scan_id},
                         on_event=(lambda _name, data: on_progress(data)) if on_progress else None,
                         timeout=None)

    def scan_result(self, scan_id: str) -> dict:
        """El resultado de un escaneo terminado (``scan.result``)."""
        return self.call("scan.result", {"scanId": scan_id})

    def scan_cancel(self, scan_id: str) -> dict:
        """Cancela un escaneo (``scan.cancel``)."""
        return self.call("scan.cancel", {"scanId": scan_id})

    def analyze(self, services: List[dict]) -> dict:
        """
        Analiza servicios ya conocidos sin tocar la red (``analyze``).

        Args:
            services: Los servicios, con ``product`` o ``cpe`` y ``version``
                (y ``origin: "inventory"`` si son datos leídos del equipo).

        Returns:
            dict: ``findings`` y ``kbFeedVersion``.
        """
        return self.call("analyze", {"services": services})
