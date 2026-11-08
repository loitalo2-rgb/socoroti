"""Informacoes de plataforma, permissoes e pastas do SocorroTI."""

from __future__ import annotations

import os
import platform
import socket
import sys
import time
from pathlib import Path

IS_WINDOWS = os.name == "nt"


def eh_windows() -> bool:
    return IS_WINDOWS


def eh_linux() -> bool:
    return sys.platform.startswith("linux")


def eh_admin() -> bool:
    if IS_WINDOWS:
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def nome_sistema() -> str:
    if IS_WINDOWS:
        try:
            return f"Windows {platform.release()} (build {platform.version()})"
        except Exception:
            return "Windows"
    if eh_linux():
        try:
            with open("/etc/os-release", "r", encoding="utf-8", errors="replace") as fh:
                dados = {}
                for linha in fh:
                    if "=" in linha:
                        k, v = linha.rstrip().split("=", 1)
                        dados[k] = v.strip('"')
            return dados.get("PRETTY_NAME") or "Linux"
        except OSError:
            return "Linux"
    return platform.platform()


def hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return platform.node() or "desconhecido"


def usuario() -> str:
    return os.environ.get("USERNAME") or os.environ.get("USER") or "desconhecido"


def agora() -> str:
    return time.strftime("%d/%m/%Y %H:%M:%S")


def selo_tempo() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def raiz_ferramenta() -> Path:
    """Pasta do projeto (README, socorro.cmd, socoroti/) ou pasta do .exe."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def pasta_dados() -> Path:
    """Pasta de dados portatil (gravada ao lado da ferramenta, se possivel)."""
    personalizada = os.environ.get("SOCORRO_DADOS")
    candidatos: list[Path] = []
    if personalizada:
        candidatos.append(Path(personalizada).expanduser())
    candidatos.append(raiz_ferramenta() / "dados")
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        candidatos.append(Path(base) / "SocorroTI")
    else:
        base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
        candidatos.append(Path(base) / "socorro-ti")

    for pasta in candidatos:
        try:
            pasta.mkdir(parents=True, exist_ok=True)
            teste = pasta / ".escrita.tmp"
            teste.write_text("ok", encoding="utf-8")
            teste.unlink(missing_ok=True)
            return pasta
        except OSError:
            continue
    return Path.cwd()


def pasta_relatorios() -> Path:
    pasta = pasta_dados() / "relatorios"
    pasta.mkdir(parents=True, exist_ok=True)
    return pasta


def dica_admin() -> str:
    if IS_WINDOWS:
        return "Abra o terminal como Administrador e rode o comando novamente."
    return "Rode novamente com sudo:  sudo socorro ..."


def reexecutar_como_admin() -> bool:
    """No Windows, tenta reabrir o programa elevado (UAC). Retorna True se abriu."""
    if not IS_WINDOWS:
        return False
    try:
        import ctypes

        parametros = " ".join(f'"{a}"' if " " in a else a for a in sys.argv)
        executavel = sys.executable
        if getattr(sys, "frozen", False):
            executavel = sys.executable
            parametros = " ".join(f'"{a}"' if " " in a else a for a in sys.argv[1:])
        else:
            parametros = "-m socoroti " + " ".join(
                f'"{a}"' if " " in a else a for a in sys.argv[1:]
            )
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", executavel, parametros, str(raiz_ferramenta()), 1
        )
        return rc > 32
    except Exception:
        return False
