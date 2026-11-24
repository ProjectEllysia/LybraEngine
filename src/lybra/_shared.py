"""Utilidades pequeñas que el motor comparte entre sus módulos.

Son las únicas piezas que el motor tomaba de la aplicación que lo integra; viven
aquí para que el paquete no dependa de nadie. Ninguna tiene más dependencia que
la biblioteca estándar.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Optional

#: Sufijos de nombre que identifican una red interna.
#:
#: ``.local`` es mDNS (RFC 6762) y ``.home.arpa`` es el nombre que el RFC 8375
#: reserva para redes domésticas; ``.internal`` lo reserva el ICANN para uso
#: privado. El resto son convenciones muy extendidas en redes corporativas que,
#: sin estar reservadas por ningún estándar, no resuelven en la internet pública.
#:
#: Errar aquí es asimétrico: clasificar como pública una red interna sólo infla
#: la prioridad de un hallazgo, mientras que lo contrario la rebaja y puede
#: esconder algo que sí está expuesto. Por eso la lista se queda en nombres que
#: de verdad no salen a internet.
PRIVATE_HOST_SUFFIXES = (
    ".local",
    ".home.arpa",
    ".internal",
    ".lan",
    ".intranet",
    ".corp",
    ".home",
)

#: Nombres sin sufijo que también son la máquina local.
PRIVATE_HOST_NAMES = ("localhost",)


def is_private_target(target: str) -> bool:
    """
    Indica si un objetivo vive en una red interna.

    Args:
        target: Una dirección IP (v4 o v6) o un nombre de host.

    Returns:
        bool: ``True`` para una dirección privada, de loopback o link-local, y
            para un nombre que sólo resuelve dentro de una red interna. Un nombre
            que no se reconoce se trata como público: equivocarse hacia
            "privado" rebajaría la prioridad de un hallazgo que quizá sí está
            expuesto.
    """
    stripped = target.strip()
    try:
        address = ipaddress.ip_address(stripped)
    except ValueError:
        lowered = stripped.lower()
        return (lowered in PRIVATE_HOST_NAMES
                or any(lowered.endswith(suffix) for suffix in PRIVATE_HOST_SUFFIXES))
    return address.is_private or address.is_loopback or address.is_link_local


def classify_exposure(target: str) -> str:
    """
    Clasifica la exposición de un objetivo en la forma que consume el scoring.

    Args:
        target: Una dirección IP o un nombre de host.

    Returns:
        str: ``"private"`` si el objetivo vive en una red interna (ver
            :func:`is_private_target`); ``"public"`` en cualquier otro caso.
    """
    return "private" if is_private_target(target) else "public"


def utcnow_naive() -> datetime:
    """
    Devuelve el instante actual en UTC como ``datetime`` sin zona horaria.

    El motor trabaja siempre en UTC *naive*; la ausencia de ``tzinfo`` es
    intencional y uniforme en todo el paquete.

    Returns:
        datetime: Ahora, en UTC, con ``tzinfo`` a ``None``.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


def isoformat_utc(dt: Optional[datetime]) -> Optional[str]:
    """
    Serializa un ``datetime`` naive-UTC a ISO 8601 marcado como UTC.

    ``datetime.isoformat()`` sobre un naive no añade zona, y quien lo lee
    (JavaScript, por ejemplo) lo interpretaría como hora local. El sufijo ``Z``
    elimina la ambigüedad.

    Args:
        dt: El instante a serializar, que se asume naive-UTC, o ``None``.

    Returns:
        Optional[str]: La cadena ISO 8601 con sufijo ``Z`` (p. ej.
            ``"2026-11-24T09:34:05Z"``), o ``None`` si ``dt`` es ``None``.
    """
    if dt is None:
        return None
    return dt.isoformat() + "Z"
