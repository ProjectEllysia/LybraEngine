"""Configuración común de la suite del motor.

Dos sellos se aplican a todos los tests sin que nadie los pida:

- ninguna conexión sale de loopback (salvo los objetivos reales que el operador
  declare para el banco de paridad), y
- el limitador de ritmo del motor no duerme de verdad.

Sin ellos, un test que olvide mockear una sonda sale a la red y espera el plazo
entero de cada petición; con la red sellada el limitador ve un host que nunca
contesta y frena al máximo, y la suite tarda minutos en lugar de segundos.
"""

from __future__ import annotations

import inspect
import ipaddress
import socket
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from unittest import mock

import pytest

# Se carga por ruta y no por nombre: el banco de paridad comparte este módulo
# con el sello, y por nombre dependería del orden de recolección.
_REAL_TARGETS_SPEC = spec_from_file_location(
    "lybra_real_targets", Path(__file__).resolve().parent / "oracle" / "_real_targets.py"
)
_real_targets = module_from_spec(_REAL_TARGETS_SPEC)
_REAL_TARGETS_SPEC.loader.exec_module(_real_targets)


def _is_loopback(address) -> bool:
    """
    Indica si el argumento de ``socket.connect`` apunta a loopback.

    Args:
        address: La dirección tal como la recibe ``socket.connect``: una tupla
            ``(host, puerto, ...)`` para IP, o una ruta para un socket Unix.

    Returns:
        bool: ``True`` para loopback y para cualquier dirección que no sea IP
            (sockets Unix y familias exóticas, que no salen a la red); ``False``
            para el resto, incluido un nombre sin resolver, que es el lado
            conservador.
    """
    if not isinstance(address, tuple) or not address:
        return True
    try:
        return ipaddress.ip_address(address[0]).is_loopback
    except ValueError:
        return address[0] in ("localhost", "")


@pytest.fixture(scope="session", autouse=True)
def _no_outbound_sockets():
    """
    Corta al instante cualquier conexión que no sea a loopback.

    Se corta en ``socket.connect`` porque es el único punto por el que pasan
    todas las sondas: urllib, TLS y las conexiones crudas del descubrimiento de
    puertos. Un ``ConnectionRefusedError`` inmediato es indistinguible de un
    host inalcanzable para el motor, que trata cualquier ``OSError`` como "no
    hay servicio", solo que sin la espera. El DNS inverso se sella igual,
    porque es la otra forma de salir a la red sin abrir un socket propio.

    Las direcciones declaradas en ``LYBRA_REAL_TARGETS`` (ver
    ``oracle/_real_targets.py``) quedan permitidas: es una lista blanca de
    direcciones concretas, no un interruptor que apague el sello.

    Yields:
        None: El sello queda activo durante toda la sesión de tests.
    """
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_gethostbyaddr = socket.gethostbyaddr
    allowed = _real_targets.allowed_outbound_addresses()

    def is_permitted(address) -> bool:
        return _is_loopback(address) or (
            isinstance(address, tuple) and bool(address) and address[0] in allowed
        )

    def guarded_connect(self, address):
        if not is_permitted(address):
            raise ConnectionRefusedError(
                f"La suite de tests no permite conexiones fuera de loopback: {address!r}"
            )
        return real_connect(self, address)

    def guarded_connect_ex(self, address):
        if not is_permitted(address):
            return 111  # ECONNREFUSED, la convención de connect_ex
        return real_connect_ex(self, address)

    def guarded_gethostbyaddr(ip):
        if not is_permitted((ip,)):
            raise socket.herror(f"DNS inverso bloqueado en tests: {ip!r}")
        return real_gethostbyaddr(ip)

    with (
        mock.patch.object(socket.socket, "connect", guarded_connect),
        mock.patch.object(socket.socket, "connect_ex", guarded_connect_ex),
        mock.patch.object(socket, "gethostbyaddr", guarded_gethostbyaddr),
    ):
        yield


@pytest.fixture(scope="session", autouse=True)
def _no_real_pacing_waits():
    """
    Hace que el limitador de ritmo del motor no duerma de verdad.

    Se cambia sólo el valor por defecto de ``sleeper`` en
    ``HostRateLimiter``: un test que inyecta su propia espera (los del propio
    limitador, que comprueban el calendario con un reloj falso) la conserva. El
    limitador sigue reservando turnos y calculando intervalos igual que en
    producción; lo único que desaparece es la espera.

    Yields:
        None: El parche queda activo durante toda la sesión de tests.
    """
    from lybra.checks import HostRateLimiter  # pylint: disable=import-outside-toplevel

    defaults = HostRateLimiter.__init__.__defaults__
    # ``__defaults__`` cubre los últimos parámetros posicionales, en orden.
    defaulted_names = list(inspect.signature(HostRateLimiter.__init__).parameters)[-len(defaults):]
    sleeper_position = defaulted_names.index("sleeper")
    patched_defaults = (
        defaults[:sleeper_position] + (lambda _seconds: None,) + defaults[sleeper_position + 1:]
    )
    with mock.patch.object(HostRateLimiter.__init__, "__defaults__", patched_defaults):
        yield
