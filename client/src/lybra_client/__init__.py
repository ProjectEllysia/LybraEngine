"""Cliente de Python del motor de escaneo Lybra.

Habla con ``lybrad`` por su socket Unix siguiendo el protocolo de
LybraEngine (``docs/protocolo.md``). Sólo usa la biblioteca estándar.
"""

from .client import (
    DEFAULT_SOCKET,
    PROTOCOL_VERSION,
    LybraClient,
    LybraConnectionError,
    LybraError,
)

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_SOCKET",
    "PROTOCOL_VERSION",
    "LybraClient",
    "LybraConnectionError",
    "LybraError",
]
