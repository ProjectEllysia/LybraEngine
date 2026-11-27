"""El formato de los mensajes entre ``lybrad`` y sus clientes (ver ``docs/protocolo.md``).

Cada mensaje es un objeto JSON en una sola línea terminada en ``\\n``. Este
módulo sabe leerlos y escribirlos, y convertir los valores del motor (hallazgos
con claves ``snake_case``, ``Service``, fechas, tuplas) a la forma que viaja
(claves ``camelCase``, listas, fechas ISO 8601 con ``Z``) y de vuelta.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from datetime import date, datetime
from typing import Any, Dict, Optional

from ..core.engine import Service

#: Versión mayor del protocolo que habla este motor.
PROTOCOL_VERSION = 1

#: Tamaño máximo de una línea, en bytes. El servicio cierra la conexión ante una más larga.
MAX_LINE_BYTES = 16 * 1024 * 1024

#: Ruta por defecto del socket; ``LYBRA_SOCKET`` la cambia en los dos extremos.
DEFAULT_SOCKET = "/run/lybra/lybra.sock"

BAD_REQUEST = "bad_request"
UNSUPPORTED_VERSION = "unsupported_version"
UNKNOWN_OP = "unknown_op"
INVALID_PARAMS = "invalid_params"
INVALID_TARGET = "invalid_target"
TARGET_NOT_ALLOWED = "target_not_allowed"
NOT_FOUND = "not_found"
BUSY = "busy"
KB_UNAVAILABLE = "kb_unavailable"
INTERNAL = "internal"

_ID_MAX_LENGTH = 64
_CAMEL_BOUNDARY = re.compile(r"_([a-z0-9])")


class ProtocolError(Exception):
    """Un error que se le devuelve al cliente con su código.

    Attributes:
        code: Uno de los códigos de error del protocolo (``invalid_params``,
            ``not_found``…).
        message: Explicación legible; nunca lleva detalles internos.
    """

    def __init__(self, code: str, message: str) -> None:
        """
        Crea el error.

        Args:
            code: El código de error del protocolo.
            message: La explicación para el cliente.
        """
        super().__init__(message)
        self.code = code
        self.message = message


def encode(message: Dict[str, Any]) -> bytes:
    """
    Serializa un mensaje como una línea JSON.

    Args:
        message: El mensaje, ya en su forma de cable.

    Returns:
        bytes: El JSON en UTF-8, sin saltos de línea internos y terminado en ``\\n``.
    """
    return json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"


def decode_request(line: bytes) -> Dict[str, Any]:
    """
    Lee y valida una petición.

    Args:
        line: La línea recibida, con o sin el ``\\n`` final.

    Returns:
        dict: La petición, con ``v``, ``id``, ``op`` y ``params`` (un
            diccionario, vacío si no venía).

    Raises:
        ProtocolError: ``bad_request`` si no es un objeto JSON con ``id`` y
            ``op`` de tipo cadena; ``unsupported_version`` si ``v`` no es una
            versión que este motor hable.
    """
    try:
        message = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProtocolError(BAD_REQUEST, "el mensaje no es JSON válido") from error
    if not isinstance(message, dict):
        raise ProtocolError(BAD_REQUEST, "el mensaje tiene que ser un objeto JSON")
    request_id, op, params = message.get("id"), message.get("op"), message.get("params", {})
    if not isinstance(request_id, str) or not 0 < len(request_id) <= _ID_MAX_LENGTH:
        raise ProtocolError(BAD_REQUEST, f"'id' tiene que ser una cadena de 1 a {_ID_MAX_LENGTH} caracteres")
    if not isinstance(op, str) or not op:
        raise ProtocolError(BAD_REQUEST, "falta 'op'")
    if message.get("v") != PROTOCOL_VERSION:
        raise ProtocolError(UNSUPPORTED_VERSION, f"este motor habla la versión {PROTOCOL_VERSION} del protocolo")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise ProtocolError(BAD_REQUEST, "'params' tiene que ser un objeto")
    return {"v": PROTOCOL_VERSION, "id": request_id, "op": op, "params": params}


def response(request_id: Optional[str], result: Any) -> Dict[str, Any]:
    """
    Construye la respuesta final de una petición que salió bien.

    Args:
        request_id: El ``id`` de la petición.
        result: El resultado, ya en su forma de cable.

    Returns:
        dict: ``{"v", "id", "ok": true, "result"}``.
    """
    return {"v": PROTOCOL_VERSION, "id": request_id, "ok": True, "result": result}


def error_response(request_id: Optional[str], code: str, message: str) -> Dict[str, Any]:
    """
    Construye la respuesta final de una petición que falló.

    Args:
        request_id: El ``id`` de la petición, o ``None`` si no se pudo leer.
        code: El código de error.
        message: La explicación.

    Returns:
        dict: ``{"v", "id", "ok": false, "error": {"code", "message"}}``.
    """
    return {"v": PROTOCOL_VERSION, "id": request_id, "ok": False, "error": {"code": code, "message": message}}


def event(request_id: str, name: str, data: Any) -> Dict[str, Any]:
    """
    Construye un evento intermedio de una petición de seguimiento.

    Args:
        request_id: El ``id`` de la petición.
        name: El nombre del evento (``progress``).
        data: Sus datos, ya en su forma de cable.

    Returns:
        dict: ``{"v", "id", "event", "data"}``.
    """
    return {"v": PROTOCOL_VERSION, "id": request_id, "event": name, "data": data}


def camel_case(key: str) -> str:
    """
    Convierte una clave ``snake_case`` del motor en ``camelCase``.

    El guion bajo inicial de las claves internas de un hallazgo
    (``_installed_version``, ``_evidence``) se quita: en el cable no hay claves
    privadas.

    Args:
        key: La clave.

    Returns:
        str: La clave en camelCase (``cve_ids`` → ``cveIds``).
    """
    return _CAMEL_BOUNDARY.sub(lambda match: match.group(1).upper(), key.lstrip("_"))


def to_wire(value: Any) -> Any:
    """
    Convierte un valor del motor a su forma de cable, recursivamente.

    Args:
        value: Un hallazgo, una lista de ellos, un ``Service``, una fecha…

    Returns:
        El mismo dato hecho de tipos JSON: claves de diccionario en camelCase,
        tuplas y conjuntos como listas (los conjuntos, ordenados), fechas como
        ISO 8601 (UTC con ``Z``) y bytes como texto UTF-8.
    """
    if isinstance(value, Service):
        return service_to_wire(value)
    if isinstance(value, dict):
        return {camel_case(str(key)): to_wire(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_wire(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(to_wire(item) for item in value)
    if isinstance(value, datetime):
        return value.isoformat() + ("Z" if value.tzinfo is None else "")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value


def service_to_wire(service: Service) -> Dict[str, Any]:
    """
    Convierte un ``Service`` a su forma de cable.

    Args:
        service: El servicio.

    Returns:
        dict: ``port``, ``protocol``, ``name``, ``product``, ``version``,
            ``cpe``, ``origin`` y ``components`` (lista de pares producto/versión).
    """
    wire = {camel_case(key): value for key, value in asdict(service).items() if key != "components"}
    wire["components"] = [list(component) for component in service.components]
    return wire


def service_from_wire(raw: Any) -> Service:
    """
    Construye un ``Service`` desde su forma de cable, validándolo.

    Args:
        raw: El objeto recibido.

    Returns:
        Service: El servicio. ``origin`` por defecto es ``"network"``.

    Raises:
        ProtocolError: ``invalid_params`` si no es un objeto, si un campo
            tiene un tipo que no toca o si no dice nada analizable (ni
            producto, ni CPE, ni puerto).
    """
    if not isinstance(raw, dict):
        raise ProtocolError(INVALID_PARAMS, "cada servicio tiene que ser un objeto")
    port = raw.get("port")
    if port is not None and (not isinstance(port, int) or isinstance(port, bool) or not 0 < port < 65536):
        raise ProtocolError(INVALID_PARAMS, f"puerto no válido: {port!r}")
    text = {}
    for key in ("protocol", "name", "product", "version", "cpe", "origin"):
        value = raw.get(key)
        if value is not None and not isinstance(value, str):
            raise ProtocolError(INVALID_PARAMS, f"'{key}' tiene que ser una cadena")
        text[key] = (value or "").strip()
    if text["origin"] and text["origin"] not in ("network", "inventory"):
        raise ProtocolError(INVALID_PARAMS, "'origin' tiene que ser 'network' o 'inventory'")
    if not (text["product"] or text["cpe"] or port is not None):
        raise ProtocolError(INVALID_PARAMS, "un servicio necesita al menos 'product', 'cpe' o 'port'")
    return Service(port=port, protocol=text["protocol"], name=text["name"], product=text["product"],
                   version=text["version"], cpe=_complete_cpe23(text["cpe"]) or None,
                   origin=text["origin"] or "network")


def _complete_cpe23(cpe: str) -> str:
    """
    Rellena con ``*`` los campos que falten de un CPE 2.3 escrito corto.

    ``cpe:2.3:a:nginx:nginx`` es como lo escribe una persona o un inventario,
    pero un CPE 2.3 tiene 13 campos y el motor sólo entiende la forma completa.

    Args:
        cpe: El CPE recibido, posiblemente vacío.

    Returns:
        str: El CPE con sus 13 campos si era 2.3 (``cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*``);
            cualquier otro valor, tal cual.
    """
    parts = cpe.split(":")
    if len(parts) < 13 and cpe.lower().startswith("cpe:2.3:"):
        return ":".join(parts + ["*"] * (13 - len(parts)))
    return cpe
