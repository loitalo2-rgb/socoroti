"""Backup de emergencia: copia os dados do usuario para o pendrive com conferencia.

Feito para o momento anterior a uma formatacao/reinstalacao. Copia apenas
arquivos comuns, nao segue links simbolicos, nao apaga nada na origem e
confere o tamanho de cada arquivo copiado.
"""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from . import platform_info
from .report import Report
from .runner import IS_WINDOWS
from .system import bytes_legivel

AREA = "backup"

_JUNK = {
    "desktop.ini",
    "thumbs.db",
    ".ds_store",
    ".localized",
}
_SUFIXOS_LIXO = (".tmp", ".part", ".partial", ".crdownload", ".download", ".lock")


class BackupError(ValueError):
    """Configuracao invalida do backup."""


def _xdg_dirs() -> dict[str, Path]:
    """Le ~/.config/user-dirs.dirs para respeitar pastas localizadas no Linux."""
    saida: dict[str, Path] = {}
    arquivo = Path.home() / ".config" / "user-dirs.dirs"
    try:
        texto = arquivo.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return saida
    for linha in texto.splitlines():
        m = re.match(r'\s*(XDG_[A-Z]+_DIR)\s*=\s*"?(.+?)"?\s*$', linha)
        if not m:
            continue
        valor = m.group(2).replace("$HOME", str(Path.home()))
        saida[m.group(1)] = Path(valor)
    return saida


def pastas_padrao() -> list[tuple[str, Path]]:
    """Pastas comuns do usuario que existem nesta maquina."""
    casa = Path.home()
    candidatos: list[tuple[str, Path]] = []
    if IS_WINDOWS:
        for base in (casa, casa / "OneDrive"):
            for nome in ("Desktop", "Documents", "Downloads", "Pictures", "Videos", "Music"):
                candidatos.append((nome, base / nome))
    else:
        xdg = _xdg_dirs()
        mapa = [
            ("XDG_DESKTOP_DIR", "Desktop"),
            ("XDG_DOCUMENTS_DIR", "Documents"),
            ("XDG_DOWNLOAD_DIR", "Downloads"),
            ("XDG_PICTURES_DIR", "Pictures"),
            ("XDG_VIDEOS_DIR", "Videos"),
            ("XDG_MUSIC_DIR", "Music"),
        ]
        for chave, rotulo in mapa:
            candidatos.append((rotulo, xdg.get(chave, casa / rotulo)))

    vistos: set[str] = set()
    existentes: list[tuple[str, Path]] = []
    for rotulo, caminho in candidatos:
        try:
            resolvido = caminho.resolve()
        except OSError:
            continue
        chave = str(resolvido).lower()
        if chave in vistos or not caminho.is_dir():
            continue
        vistos.add(chave)
        existentes.append((rotulo, caminho))
    return existentes


def pastas_chaves() -> list[tuple[str, Path]]:
    """Pastas sensiveis incluidas apenas com --incluir-chaves."""
    casa = Path.home()
    itens = [
        ("Chaves SSH", casa / ".ssh"),
        ("Chaves GPG", casa / ".gnupg"),
        ("Credenciais AWS", casa / ".aws"),
    ]
    return [(r, c) for r, c in itens if c.is_dir()]


def _ignorar(nome: str) -> bool:
    baixo = nome.lower()
    return baixo in _JUNK or baixo.startswith("~$") or baixo.endswith(_SUFIXOS_LIXO)


def _walk_arquivos(origem: Path) -> Iterable[tuple[Path, int]]:
    """Percorre sem seguir links e sem entrar em pastas de sistema."""
    for raiz, dirs, arquivos in os.walk(origem, followlinks=False):
        dirs[:] = [
            d for d in dirs
            if not Path(raiz, d).is_symlink() and d.lower() not in ("$recycle.bin", "system volume information")
        ]
        for nome in arquivos:
            caminho = Path(raiz, nome)
            if _ignorar(nome):
                continue
            try:
                if caminho.is_symlink() or not caminho.is_file():
                    continue
                yield caminho, caminho.stat().st_size
            except OSError:
                continue


def medir(origens: list[tuple[str, Path]]) -> list[dict[str, Any]]:
    saida: list[dict[str, Any]] = []
    for rotulo, origem in origens:
        arquivos = 0
        total = 0
        for _, tamanho in _walk_arquivos(origem):
            arquivos += 1
            total += tamanho
        saida.append({"rotulo": rotulo, "origem": origem, "arquivos": arquivos, "bytes": total})
    return saida


def validar(origens: list[tuple[str, Path]], destino: Path) -> None:
    if not origens:
        raise BackupError("Nenhuma pasta de origem encontrada para o backup.")
    if not destino.exists() or not destino.is_dir():
        raise BackupError(f"Destino invalido ou inexistente: {destino}")
    destino_res = destino.resolve()
    for _, origem in origens:
        origem_res = origem.resolve()
        if destino_res == origem_res or origem_res in destino_res.parents:
            raise BackupError(
                f"O destino ({destino}) esta dentro da pasta de origem ({origem}). "
                "Escolha uma pasta fora dos dados a copiar."
            )


def _rotulos_unicos(origens: list[tuple[str, Path]]) -> list[tuple[str, Path]]:
    usados: set[str] = set()
    saida: list[tuple[str, Path]] = []
    for rotulo, origem in origens:
        base = re.sub(r"[^A-Za-z0-9._ -]+", "_", rotulo).strip(" ._") or "pasta"
        nome = base
        contador = 2
        while nome.lower() in usados:
            nome = f"{base}_{contador}"
            contador += 1
        usados.add(nome.lower())
        saida.append((nome, origem))
    return saida


def copiar(
    origens: list[tuple[str, Path]],
    destino: Path,
    simular: bool = False,
    limite_bytes: int = 0,
    ao_pasta: Optional[Callable[[dict[str, Any]], None]] = None,
) -> dict[str, Any]:
    """Copia os dados e devolve um resumo com erros, ignorados e verificacao."""
    destino = Path(destino).expanduser()
    validar(origens, destino)
    origem_rotulada = _rotulos_unicos(origens)

    plano = medir(origem_rotulada)
    total_previsto = sum(p["bytes"] for p in plano)
    livre = shutil.disk_usage(destino).free
    base = destino / f"SocorroTI-backup-{platform_info.hostname()}-{platform_info.selo_tempo()}"

    resultado: dict[str, Any] = {
        "destino": str(base),
        "simulado": simular,
        "arquivos": 0,
        "bytes": 0,
        "bytes_previstos": total_previsto,
        "arquivos_previstos": sum(p["arquivos"] for p in plano),
        "espaco_livre": livre,
        "espaco_insuficiente": total_previsto > livre,
        "pastas": [],
        "erros": [],
        "ignorados": 0,
        "omitidos_limite": 0,
        "limite_atingido": False,
    }

    if not simular:
        base.mkdir(parents=True, exist_ok=True)

    for info in plano:
        rotulo, origem = info["rotulo"], info["origem"]
        res_pasta = {
            "rotulo": rotulo,
            "origem": str(origem),
            "arquivos": 0,
            "bytes": 0,
            "erros": 0,
        }
        for caminho, tamanho in _walk_arquivos(origem):
            if limite_bytes and resultado["bytes"] + res_pasta["bytes"] + tamanho > limite_bytes:
                resultado["limite_atingido"] = True
                resultado["omitidos_limite"] += 1
                continue
            if simular:
                res_pasta["arquivos"] += 1
                res_pasta["bytes"] += tamanho
                continue
            try:
                relativo = caminho.relative_to(origem)
            except ValueError:
                relativo = Path(caminho.name)
            alvo = base / rotulo / relativo
            try:
                alvo.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(caminho, alvo)
                copiado = alvo.stat().st_size
                if copiado != tamanho:
                    raise OSError(f"tamanho diferente apos copia ({copiado} != {tamanho})")
                res_pasta["arquivos"] += 1
                res_pasta["bytes"] += tamanho
            except OSError as exc:
                res_pasta["erros"] += 1
                if len(resultado["erros"]) < 50:
                    resultado["erros"].append({"arquivo": str(caminho), "erro": str(exc)})
        resultado["pastas"].append(res_pasta)
        resultado["arquivos"] += res_pasta["arquivos"]
        resultado["bytes"] += res_pasta["bytes"]
        if ao_pasta:
            ao_pasta(res_pasta)

    return resultado


def imprimir(resultado: dict[str, Any], ui: Any) -> None:
    ui.secao("Backup de emergencia")
    ui.kv("Destino", resultado["destino"] + (" (simulacao)" if resultado["simulado"] else ""))
    ui.kv("Arquivos", f"{resultado['arquivos']} de {resultado['arquivos_previstos']} previstos")
    ui.kv("Tamanho", f"{bytes_legivel(resultado['bytes'])} de {bytes_legivel(resultado['bytes_previstos'])}")
    ui.kv("Espaco livre no destino", bytes_legivel(resultado["espaco_livre"]))
    ui.tabela(
        ["Pasta", "Arquivos", "Tamanho", "Erros"],
        [[p["rotulo"], p["arquivos"], bytes_legivel(p["bytes"]), p["erros"]] for p in resultado["pastas"]],
    )
    if resultado["espaco_insuficiente"]:
        ui.erro("Espaco insuficiente no destino para copiar tudo.")
    if resultado["limite_atingido"]:
        ui.aviso(f"Limite de tamanho atingido: {resultado['omitidos_limite']} arquivo(s) ficaram de fora.")
    if resultado["erros"]:
        ui.erro(f"{len(resultado['erros'])} erro(s) de copia. Veja o relatorio.")
    elif not resultado["simulado"]:
        ui.ok("Copia concluida e conferida arquivo por arquivo.")


def relatorio(resultado: dict[str, Any]) -> Report:
    r = Report("Backup de emergencia", area=AREA)
    r.meta["Destino"] = resultado["destino"]
    r.meta["Modo"] = "simulacao" if resultado["simulado"] else "copia real"
    r.meta["Resumo"] = (
        f"{resultado['arquivos']} arquivos, {bytes_legivel(resultado['bytes'])}"
    )
    r.h2("Resumo")
    r.tabela(
        ["Campo", "Valor"],
        [
            ["Arquivos copiados", resultado["arquivos"]],
            ["Tamanho copiado", bytes_legivel(resultado["bytes"])],
            ["Arquivos previstos", resultado["arquivos_previstos"]],
            ["Tamanho previsto", bytes_legivel(resultado["bytes_previstos"])],
            ["Espaco livre no destino", bytes_legivel(resultado["espaco_livre"])],
            ["Limite atingido", "sim" if resultado["limite_atingido"] else "nao"],
        ],
    )
    r.h2("Por pasta")
    r.tabela(
        ["Pasta", "Origem", "Arquivos", "Tamanho", "Erros"],
        [[p["rotulo"], p["origem"], p["arquivos"], bytes_legivel(p["bytes"]), p["erros"]]
         for p in resultado["pastas"]],
    )
    if resultado["erros"]:
        r.h2("Arquivos com erro")
        r.tabela(["Arquivo", "Erro"], [[e["arquivo"], e["erro"]] for e in resultado["erros"]])
    r.h2("Verificacao")
    r.p(
        "Cada arquivo copiado teve o tamanho conferido. Nada foi apagado da origem. "
        "Antes de formatar, abra alguns arquivos no destino para confirmar."
    )
    return r
