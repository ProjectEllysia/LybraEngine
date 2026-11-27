"""La vista de fases de un escaneo: ``scan_watch`` la usa como ``on_progress``."""

from __future__ import annotations

import time
from typing import Dict, List, Optional, Tuple

from rich.console import Console, Group
from rich.live import Live
from rich.progress_bar import ProgressBar
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from lybra.app.ui.console import engine_version, is_live, symbols_for

PHASE_NAMES: Dict[str, str] = {"discovery": "descubrimiento", "fingerprint": "huella",
                               "analyze": "análisis", "checks": "checks"}


def phase_name(phase: Optional[str]) -> str:
    """El nombre en español de una fase; las desconocidas salen tal cual."""
    return PHASE_NAMES.get(phase or "", phase or "en cola")


def _seconds(value: float) -> str:
    return f"{value:.1f}s" if value < 60 else f"{int(value // 60)}m {int(value % 60):02d}s"


class PhaseView:
    """Muestra las fases de un escaneo en stderr, con tiempos medidos en el cliente.

    Con TTY usa una vista en vivo (fases cerradas, y la activa con spinner y barra);
    sin TTY escribe una línea por cambio de fase, sin ``\\r``. Se usa como
    ``on_progress`` y como gestor de contexto; ``finish`` cierra la fase activa.

    Attributes:
        console: La consola de stderr.
    """

    def __init__(self, console: Console, target: str, profile: str) -> None:
        """
        Args:
            console: La consola de stderr.
            target: El objetivo del escaneo.
            profile: El perfil (``fast``, ``standard``, ``thorough``).
        """
        self.console = console
        self.target = target
        self.profile = profile
        self._sym = symbols_for(console)
        self._live: Optional[Live] = None
        self._closed: List[Tuple[str, float, str]] = []   # (fase, segundos, estado)
        self._phase: Optional[str] = None
        self._started = time.monotonic()
        self._progress: Dict = {}

    # --- ciclo de vida

    def __enter__(self) -> "PhaseView":
        version = engine_version()
        header = Text(f"{self._sym.brand} lybra", style="brand")
        header.append(f"{' ' + version if version else ''} {self._sym.sep} scan {self.target} "
                      f"{self._sym.sep} perfil {self.profile}")
        self.console.print(header)
        if is_live(self.console):
            self._live = Live(self, console=self.console, refresh_per_second=10, transient=False)
            self._live.start()
        return self

    def __exit__(self, *_exc) -> None:
        if self._live is not None:
            self._live.stop()
            self._live = None

    def __call__(self, progress: dict) -> None:
        """Procesa un evento de avance (``status``, ``phase``, ``done``, ``total``)."""
        phase = progress.get("phase")
        if phase != self._phase and (phase is not None or self._phase is not None):
            self._close("ok")
            self._phase = phase
            self._started = time.monotonic()
            if self._live is None and phase:
                self.console.print(Text(f"{self._sym.sep} {phase_name(phase)}", style="muted"))
        self._progress = progress

    def finish(self, status: str = "completed") -> None:
        """
        Cierra la fase activa con el estado final.

        Args:
            status: ``completed`` (✓), ``partial`` (!), ``failed`` o ``cancelled`` (✗).
        """
        self._close({"partial": "warn", "failed": "err", "cancelled": "err"}.get(status, "ok"))
        self._phase = None
        if self._live is not None:
            self._live.refresh()

    # --- interno

    def _close(self, state: str) -> None:
        if self._phase is None:
            return
        elapsed = time.monotonic() - self._started
        self._closed.append((self._phase, elapsed, state))
        if self._live is None:
            self.console.print(self._done_line(self._phase, elapsed, state))
        self._phase = None

    def _done_line(self, phase: str, elapsed: float, state: str) -> Text:
        mark = {"ok": self._sym.ok, "warn": self._sym.warn, "err": self._sym.err}[state]
        return Text(f"{mark} {phase_name(phase):<15}{_seconds(elapsed)}", style=state)

    def __rich__(self) -> Group:
        """Lo que pinta la vista en vivo."""
        lines: List = [self._done_line(*closed) for closed in self._closed]
        if self._phase is not None or not self._closed:
            total = self._progress.get("total") or 0
            done = self._progress.get("done") or 0
            row = Table.grid(padding=(0, 1))
            for _ in range(5):
                row.add_column(no_wrap=True)
            bar = ProgressBar(total=total, completed=min(done, total), width=20) if total else ""
            row.add_row(Spinner("dots", style="brand"), Text(f"{phase_name(self._phase):<14}"), bar,
                        Text(f"{done}/{total}" if total else "", style="muted"),
                        Text(_seconds(time.monotonic() - self._started), style="muted"))
            lines.append(row)
        return Group(*lines)
