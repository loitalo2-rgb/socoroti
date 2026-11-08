"""Execucao de comandos externos com log, timeout e decodificacao segura."""

from __future__ import annotations

import json
import locale
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Optional

IS_WINDOWS = os.name == "nt"


def _codepages_windows() -> list[str]:
    cps: list[str] = []
    try:
        import ctypes

        for fn in ("GetOEMCP", "GetACP", "GetConsoleOutputCP"):
            try:
                cp = int(getattr(ctypes.windll.kernel32, fn)())
                if cp and f"cp{cp}" not in cps:
                    cps.append(f"cp{cp}")
            except Exception:
                pass
    except Exception:
        pass
    return cps


_CODIFICACOES = ["utf-8"] + (_codepages_windows() if IS_WINDOWS else []) + [
    locale.getpreferredencoding(False) or "utf-8",
    "cp1252",
    "latin-1",
]


def decodificar(dados: bytes) -> str:
    """Decodifica saida de programas externos tentando os encodings comuns."""
    if not dados:
        return ""
    for enc in _CODIFICACOES:
        try:
            return dados.decode(enc).lstrip("\ufeff")
        except (UnicodeDecodeError, LookupError):
            continue
    return dados.decode("utf-8", errors="replace")


@dataclass
class Result:
    args: Any
    code: int
    out: str = ""
    err: str = ""
    seconds: float = 0.0
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.code == 0 and not self.timed_out

    @property
    def saida(self) -> str:
        return (self.out or "").strip()


@dataclass
class Runner:
    verbose: bool = False
    historico: list[Result] = field(default_factory=list)
    _ps: Optional[str] = None

    # ------------------------------------------------------------------ base
    def run(
        self,
        args: list[str],
        timeout: int = 30,
        env: Optional[dict[str, str]] = None,
        input_text: Optional[str] = None,
    ) -> Result:
        inicio = time.perf_counter()
        ambiente = None
        if env:
            ambiente = os.environ.copy()
            ambiente.update(env)
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                timeout=timeout,
                input=input_text.encode() if input_text is not None else None,
                env=ambiente,
                stdin=subprocess.DEVNULL if input_text is None else None,
            )
            res = Result(
                args=args,
                code=proc.returncode,
                out=decodificar(proc.stdout),
                err=decodificar(proc.stderr),
                seconds=time.perf_counter() - inicio,
            )
        except subprocess.TimeoutExpired as exc:
            res = Result(
                args=args,
                code=124,
                out=decodificar(exc.stdout or b""),
                err=decodificar(exc.stderr or b""),
                seconds=time.perf_counter() - inicio,
                timed_out=True,
            )
        except FileNotFoundError:
            res = Result(args=args, code=127, err=f"comando nao encontrado: {args[0]}",
                         seconds=time.perf_counter() - inicio)
        except OSError as exc:
            res = Result(args=args, code=126, err=str(exc), seconds=time.perf_counter() - inicio)

        self.historico.append(res)
        if self.verbose:
            print(f"    $ {' '.join(args) if isinstance(args, list) else args}  -> {res.code} ({res.seconds:.2f}s)",
                  flush=True)
        return res

    def run_shell(self, comando: str, timeout: int = 30) -> Result:
        if IS_WINDOWS:
            return self.run(["cmd", "/c", comando], timeout=timeout)
        return self.run(["/bin/sh", "-c", comando], timeout=timeout)

    def which(self, nome: str) -> Optional[str]:
        return shutil.which(nome)

    # ------------------------------------------------------------ powershell
    def _powershell(self) -> str:
        if self._ps:
            return self._ps
        if IS_WINDOWS:
            self._ps = shutil.which("pwsh") or shutil.which("powershell") or "powershell"
        else:
            self._ps = "pwsh"
        return self._ps

    def ps(self, script: str, timeout: int = 40) -> Result:
        prefixo = (
            "$ProgressPreference='SilentlyContinue';"
            "$ErrorActionPreference='SilentlyContinue';"
            "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
            "$OutputEncoding=[System.Text.Encoding]::UTF8;"
        )
        return self.run(
            [
                self._powershell(),
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                prefixo + script,
            ],
            timeout=timeout,
        )

    def ps_json(self, script: str, timeout: int = 40, padrao: Any = None) -> Any:
        embalado = f"@(\n{script}\n) | ConvertTo-Json -Depth 8 -Compress"
        res = self.ps(embalado, timeout=timeout)
        texto = res.out.strip()
        if not texto:
            return [] if padrao is None else padrao
        try:
            dados = json.loads(texto)
        except json.JSONDecodeError:
            # As vezes o PowerShell mistura um aviso antes do JSON.
            inicio = min([i for i in (texto.find("["), texto.find("{")) if i >= 0], default=-1)
            if inicio < 0:
                return [] if padrao is None else padrao
            try:
                dados = json.loads(texto[inicio:])
            except json.JSONDecodeError:
                return [] if padrao is None else padrao
        if dados is None:
            return [] if padrao is None else padrao
        return dados if isinstance(dados, list) else [dados]

    # ------------------------------------------------------------- utilidades
    def ler_arquivo(self, caminho: str, limite: int = 200_000) -> str:
        try:
            with open(caminho, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read(limite)
        except OSError:
            return ""
