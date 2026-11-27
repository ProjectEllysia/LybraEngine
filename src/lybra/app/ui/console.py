"""Consolas de ``rich`` para stdout y stderr, con el tema y los símbolos de ``lybra``."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Optional, Tuple

from rich.console import Console
from rich.theme import Theme

COLOR_MODES = ("auto", "always", "never")

#: Un estilo por prioridad (en minúsculas) y por tipo de mensaje.
THEME = Theme({
    "critical": "bold bright_magenta",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
    "kev": "bold red",
    "fixed": "dim green strike",
    "ok": "green",
    "warn": "yellow",
    "err": "red",
    "muted": "dim",
    "brand": "bold cyan",
})


@dataclass(frozen=True)
class Symbols:
    """Los símbolos de la interfaz (Unicode, o ASCII si el terminal no los admite)."""

    brand: str = "◆"
    ok: str = "✓"
    err: str = "✗"
    warn: str = "!"
    dot: str = "●"
    branch: str = "└"
    sep: str = "·"
    rule: str = "─"


_ASCII = Symbols(brand="*", ok="v", err="x", warn="!", dot="*", branch="`", sep="-", rule="-")


def symbols_for(console: Console) -> Symbols:
    """
    Elige los símbolos que el terminal de ``console`` puede escribir.

    Args:
        console: La consola de destino.

    Returns:
        Symbols: Los Unicode, o los ASCII si su codificación no los admite.
    """
    unicode_symbols = Symbols()
    try:
        "".join(vars(unicode_symbols).values()).encode(console.encoding or "ascii")
    except (UnicodeEncodeError, LookupError):
        return _ASCII
    return unicode_symbols


def _make(mode: str, stderr: bool) -> Console:
    """Una consola que respeta ``mode``, ``NO_COLOR`` y ``FORCE_COLOR`` (``rich`` lee estas dos)."""
    options = {"theme": THEME, "stderr": stderr, "highlight": False}
    if mode == "always":
        stream = sys.stderr if stderr else sys.stdout
        # Forzado hacia un pipe no hay consola de Windows que gobernar: se escribe ANSI y ya.
        legacy = None if stream.isatty() else False
        return Console(force_terminal=True, no_color=False, legacy_windows=legacy, **options)
    if mode == "never":
        return Console(force_terminal=False, no_color=True, **options)
    return Console(**options)


def make_consoles(mode: str = "auto") -> Tuple[Console, Console]:
    """
    Crea las consolas de stdout y de stderr.

    Sin TTY (o con ``never``) no emiten secuencias ANSI y no hay vista en vivo.
    Con ``auto`` mandan ``NO_COLOR`` y ``FORCE_COLOR``.

    Args:
        mode: ``auto``, ``always`` o ``never``.

    Returns:
        Tuple[Console, Console]: ``(stdout, stderr)``.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:  # un terminal sin UTF-8 no debe tumbar la salida por un carácter raro
                reconfigure(errors="replace")
            except (ValueError, OSError):
                pass
    return _make(mode, False), _make(mode, True)


def is_live(console: Console) -> bool:
    """Si ``console`` admite una vista en vivo (TTY interactivo, no ``dumb``)."""
    return console.is_terminal and not console.is_dumb_terminal


def engine_version() -> Optional[str]:
    """La versión instalada del motor, sin importar el motor."""
    try:
        from importlib.metadata import version
        return version("lybra-engine")
    except Exception:  # pylint: disable=broad-exception-caught
        return None
