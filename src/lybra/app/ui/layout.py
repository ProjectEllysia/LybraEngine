"""Maquetación en columnas sin relleno a la derecha: ninguna línea termina en espacios."""

from __future__ import annotations

from typing import List, Optional, Sequence

from rich.console import Console
from rich.text import Text

_MIN_LAST = 12


def wrap(console: Console, text: Text, width: int) -> List[Text]:
    """
    Parte ``text`` en líneas de como mucho ``width`` celdas, sin espacios al final.

    Args:
        console: La consola de destino.
        text: El texto.
        width: El ancho máximo (al menos 1).

    Returns:
        List[Text]: Una o más líneas.
    """
    lines = list(text.wrap(console, max(width, 1))) or [Text()]
    for line in lines:
        line.rstrip()
    return lines


def emit(console: Console, line: Text) -> None:
    """Escribe una línea ya maquetada, sin volver a partirla ni rellenarla."""
    line.rstrip()
    console.print(line, soft_wrap=True)


def paragraph(console: Console, text, style: str = "", indent: int = 0) -> None:
    """
    Escribe un texto partido al ancho de la consola, sin espacios al final de cada línea.

    Args:
        console: La consola de destino.
        text: Un ``str`` o un ``Text``.
        style: Estilo de un ``str``.
        indent: Espacios a la izquierda de cada línea.
    """
    text = text if isinstance(text, Text) else Text(str(text), style=style)
    for part in wrap(console, text, console.width - indent):
        emit(console, Text(" " * indent).append_text(part))


def heading(console: Console, title: str) -> None:
    """Escribe un título de sección con el estilo de la marca."""
    paragraph(console, title, "brand")


def key_values(console: Console, pairs: Sequence[tuple], indent: int = 2) -> None:
    """
    Escribe pares clave/valor con las claves alineadas; el valor se parte bajo su columna.

    Args:
        console: La consola de destino.
        pairs: ``(clave, valor)`` con el valor como ``str`` o ``Text``.
        indent: Sangría de la izquierda.
    """
    key_width = max((len(key) for key, _ in pairs), default=0)
    room = console.width - indent - key_width - 2
    for key, value in pairs:
        value = value if isinstance(value, Text) else Text(str(value))
        for number, part in enumerate(wrap(console, value, room)):
            line = Text(" " * indent)
            line.append(key.ljust(key_width) if number == 0 else " " * key_width, style="muted")
            line.append("  ")
            line.append_text(part)
            emit(console, line)


def render_table(console: Console, headers: Sequence[str], rows: Sequence[Sequence[Text]], indent: int = 2,
                 gap: int = 2, max_column: int = 36, empty: Optional[str] = None) -> None:
    """
    Escribe una tabla de columnas alineadas; la última se parte en varias líneas.

    No usa el relleno de ``rich.table``: las columnas intermedias se rellenan sólo
    entre celdas, y cada línea se recorta por la derecha.

    Args:
        console: La consola de destino.
        headers: Los encabezados (en tenue); vacío para omitirlos.
        rows: Las filas, con una ``Text`` por columna.
        indent: Sangría de la izquierda.
        gap: Espacios entre columnas.
        max_column: Ancho máximo de las columnas intermedias; las celdas largas se acortan con ``…``.
        empty: Texto tenue si no hay filas.
    """
    if not rows:
        if empty:
            emit(console, Text(" " * indent + empty, style="muted"))
        return
    count = len(rows[0])
    widths = []
    for column in range(count - 1):
        cells = [row[column].cell_len for row in rows] + ([len(headers[column])] if headers else [])
        widths.append(min(max(cells), max_column))
    last_room = max(console.width - indent - sum(widths) - gap * (count - 1), _MIN_LAST)
    if headers:
        head = Text(" " * indent)
        for column, width in enumerate(widths):
            head.append(headers[column].ljust(width) + " " * gap)
        head.append(headers[-1])
        head.stylize("muted")
        emit(console, head)
    for row in rows:
        parts = wrap(console, row[-1].copy(), last_room)
        for number, part in enumerate(parts):
            line = Text(" " * indent)
            for column, width in enumerate(widths):
                if number == 0:
                    cell = row[column].copy()
                    cell.truncate(width, overflow="ellipsis", pad=True)
                    line.append_text(cell)
                else:
                    line.append(" " * width)
                line.append(" " * gap)
            line.append_text(part)
            emit(console, line)
