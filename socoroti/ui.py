"""Saida de terminal: cores, icones, tabelas e perguntas."""

from __future__ import annotations

import os
import shutil
import sys
import textwrap
from typing import Iterable, Optional, Sequence

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"

_COR_SEVERIDADE = {
    "ok": GREEN,
    "info": CYAN,
    "aviso": YELLOW,
    "erro": RED,
    "critico": RED + BOLD,
}

_ICONE_UTF8 = {
    "ok": "✔",
    "info": "·",
    "aviso": "!",
    "erro": "✖",
    "critico": "✖",
    "bullet": "▸",
    "seta": "→",
    "topo": "═",
    "linha": "─",
    "check": "•",
}

_ICONE_ASCII = {
    "ok": "OK",
    "info": "-",
    "aviso": "!",
    "erro": "X",
    "critico": "XX",
    "bullet": ">",
    "seta": "->",
    "topo": "=",
    "linha": "-",
    "check": "*",
}


def habilitar_vt_windows() -> bool:
    """Ativa sequencias ANSI no console do Windows (Windows 10+)."""
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


class UI:
    def __init__(
        self,
        color: bool = True,
        ascii_only: bool = False,
        verbose: bool = False,
        interactive: Optional[bool] = None,
    ) -> None:
        self.verbose = verbose
        self.ascii_only = ascii_only or os.environ.get("SOCORRO_ASCII") == "1"
        self.interactive = (
            interactive
            if interactive is not None
            else bool(getattr(sys.stdin, "isatty", lambda: False)())
        )
        if color and not os.environ.get("NO_COLOR") and not os.environ.get("SOCORRO_SEM_COR"):
            self.color = habilitar_vt_windows() or os.name != "nt"
        else:
            self.color = False
        self.icons = _ICONE_ASCII if self.ascii_only else _ICONE_UTF8

    # ------------------------------------------------------------------ base
    def paint(self, text: str, *styles: str) -> str:
        if not self.color or not styles:
            return text
        return "".join(styles) + text + RESET

    def sym(self, name: str) -> str:
        return self.icons.get(name, name)

    def largura(self) -> int:
        try:
            return max(60, min(shutil.get_terminal_size((100, 24)).columns, 160))
        except Exception:
            return 100

    def escrever(self, texto: str = "") -> None:
        print(texto, flush=True)

    def linha(self, char: Optional[str] = None) -> None:
        self.escrever(self.paint(char or self.sym("linha") * self.largura(), DIM))

    def espaco(self) -> None:
        self.escrever()

    # --------------------------------------------------------------- titulos
    def titulo(self, texto: str, subtitulo: str = "") -> None:
        larg = self.largura()
        self.espaco()
        self.escrever(self.paint(self.sym("topo") * larg, CYAN + DIM))
        self.escrever(self.paint("  " + texto.upper(), BOLD + CYAN))
        if subtitulo:
            self.escrever(self.paint("  " + subtitulo, DIM))
        self.escrever(self.paint(self.sym("topo") * larg, CYAN + DIM))

    def secao(self, texto: str) -> None:
        self.espaco()
        self.escrever(self.paint(f"{self.sym('bullet')} {texto}", BOLD + WHITE))

    def subsecao(self, texto: str) -> None:
        self.escrever(self.paint(f"  {self.sym('seta')} {texto}", BOLD))

    # --------------------------------------------------------------- estados
    def _marcado(self, severidade: str, texto: str) -> None:
        icone = self.sym(severidade)
        cor = _COR_SEVERIDADE.get(severidade, "")
        self.escrever(f"  {self.paint(icone, cor)} {texto}")

    def ok(self, texto: str) -> None:
        self._marcado("ok", texto)

    def info(self, texto: str) -> None:
        self._marcado("info", texto)

    def aviso(self, texto: str) -> None:
        self._marcado("aviso", self.paint(texto, YELLOW) if self.color else texto)

    def erro(self, texto: str) -> None:
        self._marcado("erro", self.paint(texto, RED) if self.color else texto)

    def critico(self, texto: str) -> None:
        self._marcado("critico", self.paint(texto, RED + BOLD) if self.color else texto)

    def item(self, texto: str, detalhe: str = "") -> None:
        linha = f"  {self.paint(self.sym('check'), DIM)} {texto}"
        if detalhe:
            linha += f"  {self.paint(detalhe, DIM)}"
        self.escrever(linha)

    def kv(self, chave: str, valor: object) -> None:
        self.escrever(f"  {self.paint(str(chave) + ':', DIM):<28} {valor}")

    def codigo(self, texto: str) -> None:
        for linha in str(texto).splitlines():
            self.escrever("    " + self.paint(linha, CYAN))

    def paragrafo(self, texto: str, indent: int = 2) -> None:
        larg = self.largura() - indent - 2
        for linha in textwrap.wrap(texto, width=max(30, larg)):
            self.escrever(" " * indent + linha)

    def tabela(
        self,
        cabecalho: Sequence[str],
        linhas: Iterable[Sequence[object]],
        alinhamentos: Optional[Sequence[str]] = None,
    ) -> None:
        linhas_txt = [[("" if c is None else str(c)) for c in linha] for linha in linhas]
        larguras = [len(c) for c in cabecalho]
        for linha in linhas_txt:
            for i, celula in enumerate(linha[: len(larguras)]):
                larguras[i] = max(larguras[i], min(len(celula), 42))
        alinh = list(alinhamentos or ["<"] * len(cabecalho))

        def fmt(celulas: Sequence[str], estilo: str = "") -> str:
            partes = []
            for i, larg in enumerate(larguras):
                cel = celulas[i] if i < len(celulas) else ""
                if len(cel) > larg:
                    cel = cel[: max(0, larg - 1)] + ("..." if self.ascii_only else "…")
                partes.append(f"{cel:{alinh[i] if i < len(alinh) else '<'}{larg}}")
            texto = "  " + "  ".join(partes)
            return self.paint(texto, estilo) if estilo else texto

        self.escrever(fmt(list(cabecalho), DIM + BOLD))
        self.escrever(self.paint("  " + self.sym("linha") * (sum(larguras) + 2 * (len(larguras) - 1)), DIM))
        for linha in linhas_txt:
            self.escrever(fmt(linha))

    # ------------------------------------------------------------- perguntas
    def confirmar(self, pergunta: str, padrao: bool = False) -> bool:
        if not self.interactive:
            return padrao
        sufixo = " [S/n] " if padrao else " [s/N] "
        try:
            resposta = input(self.paint(pergunta + sufixo, BOLD)).strip().lower()
        except (EOFError, KeyboardInterrupt):
            self.espaco()
            return False
        if not resposta:
            return padrao
        return resposta in ("s", "sim", "y", "yes", "1")

    def escolher(self, pergunta: str, opcoes: list[str], padrao: int = 1) -> int:
        self.espaco()
        self.escrever(self.paint(pergunta, BOLD))
        for i, opcao in enumerate(opcoes, 1):
            self.escrever(f"  {self.paint(str(i), CYAN)}) {opcao}")
        while True:
            try:
                bruto = input(self.paint(f"Escolha [{padrao}]: ", DIM)).strip()
            except (EOFError, KeyboardInterrupt):
                self.espaco()
                return padrao
            if not bruto:
                return padrao
            if bruto.isdigit() and 1 <= int(bruto) <= len(opcoes):
                return int(bruto)
            self.aviso("Opcao invalida.")

    def pausar(self, texto: str = "Pressione ENTER para continuar...") -> None:
        if not self.interactive:
            return
        try:
            input(self.paint(texto, DIM))
        except (EOFError, KeyboardInterrupt):
            pass
