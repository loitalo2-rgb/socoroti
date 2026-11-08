"""Preparacao de pendrive: copia o kit e gera o guia de boot.

O SocorroTI nao cria sozinho um pendrive inicializavel: para dar boot e preciso
um carregador (Ventoy, Rufus) e um sistema vivo (Linux live/Windows PE). O que
este modulo faz e deixar a pasta pronta, sem apagar nada, e explicar o passo a
passo de cada caminho.
"""

from __future__ import annotations

import os
import shutil
import zipfile
from pathlib import Path
from typing import Any, Optional

from . import platform_info
from .report import Report
from .runner import IS_WINDOWS, Runner

AREA = "pendrive"

_IGNORAR = {
    "dados",
    ".git",
    "__pycache__",
    "tests",
    ".venv",
    "venv",
    "dist",
    "build",
    ".pytest_cache",
    ".mypy_cache",
    "socorro.spec",
}


class PendriveError(ValueError):
    """Destino invalido ou perigoso para preparar o kit."""


# --------------------------------------------------------------------------- dispositivos
def listar_removiveis(runner: Runner) -> list[dict[str, Any]]:
    """Lista volumes removiveis/USB com letra ou ponto de montagem."""
    if IS_WINDOWS:
        dados = runner.ps_json(
            r"""
$saida = @()
Get-CimInstance Win32_LogicalDisk | ForEach-Object {
  $letra = [string]$_.DeviceID
  $usb = $false
  try {
    $part = Get-Partition -DriveLetter $letra[0] -ErrorAction Stop
    $disk = Get-Disk -Number $part.DiskNumber -ErrorAction Stop
    $usb = ([string]$disk.BusType -eq 'USB')
    $modelo = [string]$disk.FriendlyName
  } catch { $modelo = '' }
  if ([int]$_.DriveType -eq 2 -or $usb) {
    $saida += [pscustomobject]@{
      caminho=$letra + '\'; rotulo=[string]$_.VolumeName; modelo=$modelo;
      fs=[string]$_.FileSystem; total=[double]$_.Size; livre=[double]$_.FreeSpace;
      removivel=([int]$_.DriveType -eq 2)
    }
  }
}
@($saida)
""",
            timeout=45,
        )
        return [
            {
                "caminho": str(d.get("caminho") or ""),
                "rotulo": str(d.get("rotulo") or ""),
                "modelo": str(d.get("modelo") or ""),
                "fs": str(d.get("fs") or ""),
                "total": int(float(d.get("total") or 0)),
                "livre": int(float(d.get("livre") or 0)),
                "removivel": bool(d.get("removivel")),
            }
            for d in dados
            if isinstance(d, dict) and d.get("caminho")
        ]

    res = runner.run(["lsblk", "-J", "-o", "NAME,SIZE,TYPE,RM,MOUNTPOINT,MODEL,TRAN,FSTYPE"],
                     timeout=20)
    try:
        import json

        dados = json.loads(res.out or "{}")
    except ValueError:
        return []

    saida: list[dict[str, Any]] = []

    def visitar(no: dict[str, Any]) -> None:
        for filho in no.get("children") or []:
            tipo = str(filho.get("type") or "")
            tran = str(filho.get("tran") or "")
            rm = str(filho.get("rm") or "").lower() in ("1", "true")
            ponto = str(filho.get("mountpoint") or filho.get("mountpoints", [None])[0] or "")
            if tipo == "part" and ponto and (rm or tran == "usb"):
                saida.append(
                    {
                        "caminho": ponto,
                        "rotulo": str(filho.get("label") or ""),
                        "modelo": str(filho.get("model") or no.get("model") or ""),
                        "fs": str(filho.get("fstype") or ""),
                        "total": _tamanho(str(filho.get("size") or "")),
                        "livre": 0,
                        "removivel": rm,
                    }
                )
            visitar(filho)

    for disco in dados.get("blockdevices") or []:
        tran = str(disco.get("tran") or "")
        rm = str(disco.get("rm") or "").lower() in ("1", "true")
        if rm or tran == "usb":
            visitar(disco)
    return saida


def _tamanho(texto: str) -> int:
    texto = texto.strip().upper()
    if not texto:
        return 0
    mult = 1
    if texto.endswith("K"):
        mult, texto = 1024, texto[:-1]
    elif texto.endswith("M"):
        mult, texto = 1024 ** 2, texto[:-1]
    elif texto.endswith("G"):
        mult, texto = 1024 ** 3, texto[:-1]
    elif texto.endswith("T"):
        mult, texto = 1024 ** 4, texto[:-1]
    try:
        return int(float(texto.replace(",", ".")) * mult)
    except ValueError:
        return 0


# --------------------------------------------------------------------------- preparacao
def _destino_perigoso(destino: Path) -> str:
    if IS_WINDOWS:
        sistema = (os.environ.get("SystemDrive") or "C:").rstrip("\\").lower()
        letra = destino.resolve().drive.rstrip("\\").lower()
        if letra and letra == sistema:
            return "e a unidade do sistema (C:)"
        return ""
    caminho = str(destino.resolve())
    protegidos = ("/", "/boot", "/etc", "/usr", "/var", "/home", "/root")
    if caminho in protegidos or caminho.startswith(("/boot/", "/etc/", "/usr/")):
        return "e uma pasta do sistema"
    return ""


def validar_destino(destino: Path, origem: Path, forcar: bool = False) -> None:
    if not destino.exists() or not destino.is_dir():
        raise PendriveError(f"Destino invalido ou inexistente: {destino}")
    if not forcar:
        motivo = _destino_perigoso(destino)
        if motivo:
            raise PendriveError(
                f"O destino {destino} {motivo}. Escolha o pendrive. "
                "Use --forcar apenas se souber exatamente o que esta fazendo."
            )
    origem_res = origem.resolve()
    destino_res = destino.resolve()
    if destino_res == origem_res or origem_res in destino_res.parents:
        raise PendriveError(
            "O destino esta dentro da pasta do kit. Escolha outra pasta para evitar copia recursiva."
        )


def _contar(pasta: Path) -> tuple[int, int]:
    arquivos = 0
    total = 0
    for raiz, _, nomes in os.walk(pasta):
        for nome in nomes:
            try:
                total += (Path(raiz) / nome).stat().st_size
                arquivos += 1
            except OSError:
                continue
    return arquivos, total


def _extrair_python(pasta_python: Path, zip_python: Path) -> None:
    if not zip_python.is_file():
        raise PendriveError(f"Arquivo do Python portatil nao encontrado: {zip_python}")
    pasta_python.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(zip_python) as zf:
            zf.extractall(pasta_python)
    except (OSError, zipfile.BadZipFile) as exc:
        raise PendriveError(f"Nao foi possivel extrair o Python portatil: {exc}") from exc

    # O pacote embeddable ignora PYTHONPATH; adicionamos a raiz do kit ao ._pth.
    for pth in pasta_python.glob("python*._pth"):
        try:
            linhas = pth.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        if ".." not in [l.strip() for l in linhas]:
            pth.write_text("\n".join(linhas + ["..", ""]), encoding="utf-8")


def preparar(
    destino: Path,
    origem: Optional[Path] = None,
    python_zip: Optional[Path] = None,
    forcar: bool = False,
) -> dict[str, Any]:
    """Copia o kit para <destino>/SocorroTI e devolve um resumo."""
    origem = (origem or platform_info.raiz_ferramenta()).resolve()
    destino = Path(destino).expanduser()
    validar_destino(destino, origem, forcar=forcar)

    kit = destino / "SocorroTI"
    kit.mkdir(parents=True, exist_ok=True)
    erros: list[dict[str, str]] = []
    copiados = 0

    for item in origem.iterdir():
        if item.name in _IGNORAR or item.name.endswith((".pyc", ".pyo")):
            continue
        alvo = kit / item.name
        try:
            if item.is_dir():
                shutil.copytree(
                    item,
                    alvo,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
                    dirs_exist_ok=True,
                )
            else:
                shutil.copy2(item, alvo)
                copiados += 1
        except OSError as exc:
            erros.append({"item": str(item), "erro": str(exc)})

    if python_zip:
        try:
            _extrair_python(kit / "python", Path(python_zip).expanduser())
            (kit / "socorro-pe.cmd").write_text(
                "@echo off\r\n"
                "setlocal\r\n"
                "cd /d \"%~dp0\"\r\n"
                "set PYTHONUTF8=1\r\n"
                "set PYTHONIOENCODING=utf-8\r\n"
                '".\\python\\python.exe" -m socoroti %*\r\n',
                encoding="utf-8",
            )
        except PendriveError as exc:
            erros.append({"item": str(python_zip), "erro": str(exc)})

    executavel = False
    origem_exe = origem / "dist" / "socorro.exe"
    if origem_exe.is_file():
        try:
            shutil.copy2(origem_exe, kit / "socorro.exe")
            executavel = True
        except OSError as exc:
            erros.append({"item": str(origem_exe), "erro": str(exc)})

    (kit / "INICIAR-AQUI.txt").write_text(_iniciar_aqui(), encoding="utf-8")
    try:
        (kit / "GUIA-BOOT.md").write_text(gerar_guia().render(), encoding="utf-8")
    except OSError as exc:
        erros.append({"item": "GUIA-BOOT.md", "erro": str(exc)})
    arquivos, total = _contar(kit)
    return {
        "destino": str(kit),
        "arquivos": arquivos,
        "bytes": total,
        "copiados_raiz": copiados,
        "python_embutido": bool(python_zip and (kit / "python").is_dir()),
        "executavel": executavel,
        "erros": erros,
    }


def _iniciar_aqui() -> str:
    return """SocorroTI - kit portatil de primeiros socorros de TI
=====================================================

Este pendrive contem o programa, mas NAO e inicializavel sozinho.
Para dar boot, use Ventoy ou Rufus com uma ISO (veja o guia).

COMO RODAR

Guia completo de boot: GUIA-BOOT.md

Windows normal (com Python 3.9+):
    socorro.cmd diagnostico

Windows PE/Hiren's (com o Python embutido):
    socorro-pe.cmd diagnostico

Windows PE/Hiren's (executavel unico):
    socorro.exe diagnostico

Linux live (Ubuntu/Fedora/etc.):
    cd /media/$USER/<PENDRIVE>/SocorroTI
    bash socorro.sh diagnostico
    # ou: python3 -m socoroti diagnostico

ATALHOS QUE MAIS QUEBRAM GALHO NO RESGATE

    sudo bash socorro.sh rede diagnostico
    sudo bash socorro.sh rede monitor --duracao 600
    sudo bash socorro.sh sistema diagnostico
    sudo bash socorro.sh acesso playbooks
    sudo bash socorro.sh backup --destino /media/$USER/<OUTRO_PENDRIVE> --auto

CUIDADOS

- O backup nao pode ser gravado no mesmo pendrive de boot se ele estiver cheio.
- BitLocker/LUKS sem a chave nao tem recuperacao legitima. O kit apenas orienta.
- Em Linux live, confirme o disco certo antes de montar ou copiar dados.
- Relatorios ficam em SocorroTI/dados/relatorios.
"""


# --------------------------------------------------------------------------- guia
def gerar_guia() -> Report:
    r = Report("Pendrive de boot com o SocorroTI", area="guia-pendrive")
    r.meta["Resumo"] = "Como transformar o kit em um pendrive utilizavel no resgate."
    r.h2("Antes de tudo: os arquivos sozinhos nao inicializam")
    r.p(
        "Um pendrive so da boot se tiver um carregador e um sistema operacional. "
        "O SocorroTI e um programa Python; ele precisa de um sistema vivo para rodar. "
        "O caminho mais simples e o Ventoy: o pendrive inicializa ISOs e ainda deixa "
        "a pasta do kit acessivel no mesmo dispositivo."
    )
    r.h2("Opcao A - Ventoy (recomendada)")
    r.p("O Ventoy instala um carregador uma unica vez e depois voce so copia arquivos ISO.")
    r.lista([
        "Faca backup do pendrive: a instalacao do Ventoy apaga o conteudo.",
        "Baixe o Ventoy em https://www.ventoy.net e rode Ventoy2Disk.",
        "Escolha o pendrive (confira o tamanho e o modelo) e instale (MBR + FAT32/exFAT).",
        "Copie para o pendrive: uma ISO de Linux live (Ubuntu/Fedora), a ISO do Windows se quiser reinstalar, e opcionalmente Hiren's BootCD PE.",
        "Copie a pasta SocorroTI (gerada por este comando) para a particao de dados do Ventoy.",
        "No cliente: tecla de boot (F12/F2/F10/ESC) -> pendrive -> escolha a ISO no menu do Ventoy.",
    ])
    r.h3("Dentro do Linux live")
    r.codigo(
        "cd /media/$USER/Ventoy/SocorroTI\n"
        "bash socorro.sh rede diagnostico\n"
        "bash socorro.sh rede monitor --duracao 600 --csv",
        "bash",
    )
    r.h2("Opcao B - Rufus + Linux live")
    r.lista([
        "Baixe uma ISO de Linux live (Ubuntu, Fedora, Debian) e o Rufus.",
        "No Rufus, selecione a ISO e o pendrive; isso APAGA o pendrive.",
        "Depois de gravar, copie a pasta SocorroTI para o pendrive (se houver espaco).",
        "No cliente, de boot pelo pendrive e escolha 'Try Ubuntu' (ou equivalente).",
        "Abra o terminal e rode: bash /media/$USER/<PENDRIVE>/SocorroTI/socorro.sh diagnostico",
    ])
    r.h2("Opcao C - Windows PE / Hiren's")
    r.p(
        "Windows PE nao vem com Python. Use uma destas saidas: "
        "(1) prepare o kit com --python-zip apontando para o Python embeddable; "
        "(2) gere socorro.exe com PyInstaller e copie para o pendrive."
    )
    r.codigo(
        "# no seu Windows, uma vez:\n"
        "pip install pyinstaller\n"
        "pyinstaller --onefile --name socorro socorro.py\n"
        "# copie dist\\socorro.exe para o pendrive e rode: socorro.exe diagnostico",
        "powershell",
    )
    r.p(
        "Python embeddable: https://www.python.org/downloads/windows/ -> "
        "'Windows embeddable package (64-bit)'. Depois: "
        "socorro pendrive preparar --destino E:\\ --python-zip python-3.x-embed-amd64.zip"
    )
    r.h2("O que funciona em cada ambiente")
    r.tabela(
        ["Recurso", "Windows normal", "Linux live", "Windows PE"],
        [
            ["Diagnostico de rede", "sim", "sim", "sim"],
            ["Correcoes de rede", "sim (admin)", "sim (root)", "parcial"],
            ["Monitor/rota/portas", "sim", "sim", "sim"],
            ["Backup de arquivos", "sim", "sim", "sim"],
            ["Playbooks/chroot", "sim", "sim", "sim"],
            ["Python necessario", "instalado", "ja vem", "embutido/.exe"],
        ],
    )
    r.h2("Cuidados no resgate")
    r.lista([
        "Confirme o disco certo antes de montar, copiar ou reparar. Em live, discos aparecem com nomes diferentes.",
        "Nao grave o backup dentro do mesmo pendrive de boot se ele estiver sem espaco; use outro pendrive ou HD externo.",
        "BitLocker/LUKS: sem a chave nao existe recuperacao legitima; o kit orienta, nao burla.",
        "Em redes corporativas, correcoes de DNS/proxy podem quebrar nomes internos. Reverta depois.",
        "Secure Boot pode bloquear alguns ISOs; prefira ISOs assinadas ou ajuste o firmware conscientemente.",
    ])
    r.h2("Comandos para preparar a pasta")
    r.codigo(
        "socorro pendrive listar\n"
        "socorro pendrive preparar --destino E:\\\n"
        "socorro pendrive preparar --destino /media/user/PENDRIVE\n"
        "socorro pendrive preparar --destino E:\\ --python-zip python-3.13-embed-amd64.zip",
        "bash",
    )
    return r
