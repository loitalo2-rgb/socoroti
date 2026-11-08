"""Recuperacao de senha em um unico comando.

Tres caminhos, escolhidos automaticamente:

1. Windows com sessao de administrador: redefine a senha na hora (``net user``/
   ``Set-LocalUser``), desbloqueia e ativa a conta.
2. Linux com root: redefine a senha de qualquer conta local via ``chpasswd``.
3. Linux live com o disco do Windows montado: limpa a senha offline com
   ``chntpw`` (ferramenta de resgate reconhecida), fazendo backup do SAM antes.

O modulo nunca cria backdoors nem contorna autenticacao: usa apenas a
administracao legitima da propria maquina. A senha nao e gravada em relatorio.
"""

from __future__ import annotations

import json
import os
import shutil
import secrets
import string
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from . import platform_info
from .runner import IS_WINDOWS, Runner

# Sem caracteres ambiguos (0/O, 1/l/I) para facilitar a digitacao no cliente.
_SENHA_LETRAS = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"
_SENHA_NUMEROS = "23456789"
_SENHA_SIMBOLOS = "!@#$%*-_+=?"

_CAMINHOS_SAM = (
    "Windows/System32/config",
    "WINDOWS/System32/config",
    "windows/system32/config",
    "WINNT/System32/config",
)


@dataclass
class Conta:
    nome: str
    ativa: bool = True
    admin: bool = False
    bloqueada: bool = False
    detalhe: str = ""

    def para_dict(self) -> dict[str, Any]:
        return {
            "nome": self.nome,
            "ativa": self.ativa,
            "admin": self.admin,
            "bloqueada": self.bloqueada,
            "detalhe": self.detalhe,
        }


@dataclass
class Resultado:
    ok: bool
    mensagem: str
    caminho: str = ""
    usuario: str = ""
    senha: str = ""
    detalhes: list[str] = field(default_factory=list)

    def para_dict(self, ocultar_senha: bool = True) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "mensagem": self.mensagem,
            "caminho": self.caminho,
            "usuario": self.usuario,
            "senha": "" if ocultar_senha else self.senha,
            "detalhes": self.detalhes,
        }


# --------------------------------------------------------------------------- senha
def gerar_senha(tamanho: int = 14) -> str:
    """Gera uma senha forte e sem caracteres ambiguos."""
    tamanho = max(8, int(tamanho))
    minusculas = "abcdefghijkmnopqrstuvwxyz"
    maiusculas = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    obrigatorios = [
        secrets.choice(minusculas),
        secrets.choice(maiusculas),
        secrets.choice(_SENHA_NUMEROS),
        secrets.choice(_SENHA_SIMBOLOS),
    ]
    alfabeto = _SENHA_LETRAS + _SENHA_NUMEROS + _SENHA_SIMBOLOS
    resto = [secrets.choice(alfabeto) for _ in range(tamanho - len(obrigatorios))]
    caracteres = obrigatorios + resto
    secrets.SystemRandom().shuffle(caracteres)
    return "".join(caracteres)


# --------------------------------------------------------------------------- contas
def listar_contas(runner: Runner) -> list[Conta]:
    """Lista contas locais que fazem sentido para login."""
    if IS_WINDOWS:
        return _contas_windows(runner)
    return _contas_linux(runner)


def _contas_windows(runner: Runner) -> list[Conta]:
    dados = runner.ps_json(
        r"""
$admins = @()
try {
  $grupo = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
  $admins = @(Get-LocalGroupMember -Group $grupo.Name -ErrorAction SilentlyContinue |
    ForEach-Object { ([string]$_.Name -split '\\')[-1].ToLower() })
} catch {}
$saida = @()
Get-LocalUser -ErrorAction SilentlyContinue | ForEach-Object {
  $nome = [string]$_.Name
  $saida += [pscustomobject]@{
    nome = $nome
    ativa = [bool]$_.Enabled
    admin = ($admins -contains $nome.ToLower())
    bloqueada = $false
    detalhe = [string]$_.Description
  }
}
@($saida)
""",
        timeout=40,
    )
    contas = [
        Conta(
            nome=str(d.get("nome") or ""),
            ativa=bool(d.get("ativa", True)),
            admin=bool(d.get("admin")),
            bloqueada=bool(d.get("bloqueada")),
            detalhe=str(d.get("detalhe") or ""),
        )
        for d in dados
        if isinstance(d, dict) and d.get("nome")
    ]
    if contas:
        return _filtrar(contas)

    # Windows PE: Get-LocalUser pode nao existir; cai para 'net user'.
    res = runner.run(["net", "user"], timeout=30)
    nomes: list[str] = []
    coletando = False
    ignorar = {"-------------------------------------------------------------------------------"}
    for linha in (res.out or "").splitlines():
        limpa = linha.strip()
        if limpa in ignorar or limpa.startswith("---"):
            coletando = True
            continue
        if not coletando:
            continue
        if not limpa or limpa.startswith("The command") or limpa.startswith("O comando"):
            coletando = False
            continue
        nomes.extend(limpa.split())
    return _filtrar([Conta(nome=n) for n in nomes])


def _contas_linux(runner: Runner) -> list[Conta]:
    res = runner.run(["getent", "passwd"], timeout=30)
    contas: list[Conta] = []
    for linha in (res.out or "").splitlines():
        partes = linha.split(":")
        if len(partes) < 7:
            continue
        nome, _, uid, _, _, home, shell = partes[:7]
        try:
            if int(uid) < 1000 and nome != "root":
                continue
        except ValueError:
            continue
        if shell.endswith(("nologin", "false")):
            continue
        contas.append(Conta(nome=nome, detalhe=home))
    return contas


def _filtrar(contas: list[Conta]) -> list[Conta]:
    sistema = {"defaultaccount", "wdagutilityaccount", "guest", "convidado",
               "defaultuser0", "administrador", "administrator"}
    vistas: set[str] = set()
    saida: list[Conta] = []
    for conta in contas:
        chave = conta.nome.lower()
        if chave in vistas:
            continue
        vistas.add(chave)
        conta.detalhe = conta.detalhe or ("conta integrada" if chave in sistema else "")
        saida.append(conta)
    return saida


# --------------------------------------------------------------------------- online
def _ps_aspas(texto: str) -> str:
    """Escapa um valor para uso entre aspas simples no PowerShell."""
    return "'" + str(texto).replace("'", "''") + "'"


def redefinir_windows(runner: Runner, usuario: str, senha: str) -> Resultado:
    """Redefine, ativa e desbloqueia uma conta local do Windows."""
    script = f"""
$ErrorActionPreference = 'Stop'
$nome = {_ps_aspas(usuario)}
$texto = {_ps_aspas(senha)}
$ok = $false
$erro = ''
try {{
  $conta = Get-LocalUser -Name $nome -ErrorAction Stop
  $segredo = ConvertTo-SecureString -AsPlainText -Force -String $texto
  Set-LocalUser -Name $nome -Password $segredo -PasswordNeverExpires $true -ErrorAction Stop
  Enable-LocalUser -Name $nome -ErrorAction SilentlyContinue
  $ok = [bool](Get-LocalUser -Name $nome -ErrorAction SilentlyContinue).Enabled
}} catch {{
  $erro = $_.Exception.Message
}}
if (-not $ok) {{
  $ErrorActionPreference = 'Continue'
  $saida = (net user $nome $texto 2>&1 | Out-String).Trim()
  if ($LASTEXITCODE -eq 0) {{
    net user $nome /active:yes 2>&1 | Out-Null
    $ok = $true
  }} elseif (-not $erro) {{
    $erro = $saida
  }}
}}
if ($ok) {{
  $ErrorActionPreference = 'Continue'
  net user $nome /active:yes 2>&1 | Out-Null
  'SOCORRO_OK'
}} else {{ 'SOCORRO_FALHOU: ' + $erro; exit 1 }}
"""
    res = runner.ps(script, timeout=60)
    saida = res.out or ""
    if "SOCORRO_OK" in saida:
        return Resultado(True, f"Senha de '{usuario}' redefinida, conta ativa e sem expiracao.",
                         "windows", usuario, senha)
    linhas = [l.strip() for l in (saida + "\n" + (res.err or "")).splitlines() if l.strip()]
    detalhe = " ".join(linhas[-2:])[:300] or "sem detalhe"
    detalhe = detalhe.replace("SOCORRO_FALHOU:", "").strip()
    return Resultado(False, f"Falha ao redefinir no Windows: {detalhe}",
                     "windows", usuario, senha)


def redefinir_linux(runner: Runner, usuario: str, senha: str) -> Resultado:
    """Redefine a senha de uma conta local no Linux (precisa de root)."""
    res = runner.run(["chpasswd"], timeout=30, input_text=f"{usuario}:{senha}\n")
    if res.ok:
        # Desbloqueia/ativa a conta, se o comando existir.
        runner.run(["usermod", "-U", usuario], timeout=20)
        runner.run(["passwd", "-u", usuario], timeout=20)
        return Resultado(True, f"Senha de '{usuario}' redefinida.", "linux", usuario, senha)
    detalhe = (res.err or res.out or "sem detalhe").strip().splitlines()
    return Resultado(False, f"Falha ao redefinir no Linux: {detalhe[-1] if detalhe else 'erro'}",
                     "linux", usuario, senha)


# --------------------------------------------------------------------------- offline
def _pasta_config_windows(base: Path) -> Optional[Path]:
    for relativo in _CAMINHOS_SAM:
        pasta = base / relativo
        if (pasta / "SAM").is_file():
            return pasta
    return None


def localizar_windows() -> Optional[Path]:
    """Procura uma instalacao do Windows em discos ja montados."""
    candidatos: list[Path] = []
    for raiz in ("/mnt", "/media", "/run/media"):
        pasta = Path(raiz)
        if not pasta.is_dir():
            continue
        for item in pasta.iterdir():
            if item.is_dir():
                candidatos.append(item)
                try:
                    candidatos.extend([p for p in item.iterdir() if p.is_dir()])
                except OSError:
                    continue
    for candidato in candidatos:
        config = _pasta_config_windows(candidato)
        if config:
            return config
    return None


def particoes_ntfs(runner: Runner) -> list[dict[str, str]]:
    """Lista particoes NTFS visiveis (para montar e resgatar offline)."""
    res = runner.run(["lsblk", "-J", "-o", "NAME,FSTYPE,SIZE,MOUNTPOINT,LABEL"], timeout=20)
    try:
        dados = json.loads(res.out or "{}")
    except ValueError:
        return []
    saida: list[dict[str, str]] = []

    def visitar(no: dict[str, Any]) -> None:
        if str(no.get("fstype") or "") in ("ntfs", "ntfs3", "fuseblk"):
            saida.append({
                "dispositivo": "/dev/" + str(no.get("name") or ""),
                "tamanho": str(no.get("size") or ""),
                "montagem": str(no.get("mountpoint") or ""),
                "rotulo": str(no.get("label") or ""),
            })
        for filho in no.get("children") or []:
            visitar(filho)

    for disco in dados.get("blockdevices") or []:
        visitar(disco)
    return saida


def montar_windows(runner: Runner) -> Optional[Path]:
    """Monta a primeira particao NTFS com Windows e devolve a pasta config."""
    montado = localizar_windows()
    if montado:
        return montado
    if not platform_info.eh_admin():
        return None
    for parte in particoes_ntfs(runner):
        if parte.get("montagem"):
            continue
        destino = Path(tempfile.mkdtemp(prefix="socoroti-win-", dir="/mnt"))
        for tipo in ("ntfs3", "ntfs-3g", "ntfs"):
            res = runner.run(["mount", "-t", tipo, parte["dispositivo"], str(destino)], timeout=40)
            if res.ok:
                config = _pasta_config_windows(destino)
                if config:
                    return config
                runner.run(["umount", str(destino)], timeout=30)
                break
    return None


def chntpw_disponivel(runner: Runner) -> bool:
    return runner.which("chntpw") is not None


def redefinir_offline(runner: Runner, config: Path, usuario: str,
                      instalar: bool = False) -> Resultado:
    """Limpa a senha de uma conta do Windows com chntpw (Linux live)."""
    if not (config / "SAM").is_file():
        return Resultado(False, f"NAO encontrei o SAM em {config}", str(config), usuario)
    if not chntpw_disponivel(runner):
        if instalar:
            res = runner.run(["apt-get", "install", "-y", "chntpw"], timeout=300)
            if not res.ok:
                return Resultado(
                    False,
                    "Nao foi possivel instalar o chntpw. Rode: sudo apt install chntpw",
                    str(config), usuario,
                )
        else:
            return Resultado(
                False,
                "Ferramenta chntpw nao instalada. Rode: sudo apt install chntpw",
                str(config), usuario,
            )

    backup = config / ".socoroti-backup"
    try:
        backup.mkdir(exist_ok=True)
        for nome in ("SAM", "SYSTEM", "SECURITY"):
            origem = config / nome
            if origem.is_file():
                shutil.copy2(origem, backup / f"{nome}.bak")
    except OSError as exc:
        return Resultado(False, f"Nao consegui fazer backup do SAM: {exc}", str(config), usuario)

    # Menu do chntpw: 1 = limpar senha, 2 = desbloquear/ativar, q = sair, y = gravar.
    entrada = "1\n2\nq\ny\n"
    res = runner.run(
        ["chntpw", "-u", usuario, "-i", "SAM", "SYSTEM", "SECURITY"],
        timeout=120,
        input_text=entrada,
        cwd=str(config),
    )
    texto = ((res.out or "") + "\n" + (res.err or "")).lower()
    falhou = "not found" in texto or "no user" in texto or res.code not in (0, 1)
    if falhou:
        detalhe = (res.err or res.out or "sem detalhe").strip().splitlines()
        return Resultado(False, f"chntpw falhou: {detalhe[-1] if detalhe else 'erro'}",
                         str(config), usuario)
    return Resultado(
        True,
        f"Senha de '{usuario}' limpa. Entre sem senha e cadastre uma nova no primeiro login.",
        str(config), usuario, "",
        [f"Backup do SAM em {backup}"],
    )


# --------------------------------------------------------------------------- orquestra
def resolver_usuario(contas: list[Conta], pedido: Optional[str]) -> Optional[str]:
    """Devolve o nome exato da conta (sem diferenciar maiusculas)."""
    if not pedido:
        return None
    for conta in contas:
        if conta.nome.lower() == pedido.lower():
            return conta.nome
    return None


def _mtime_perfil(nome: str, raiz_usuarios: Optional[Path] = None) -> float:
    raiz = raiz_usuarios or Path("C:/Users")
    try:
        return (raiz / nome).stat().st_mtime
    except OSError:
        return 0.0


def conta_principal(contas: list[Conta], atual: Optional[str] = None,
                    raiz_usuarios: Optional[Path] = None) -> Optional[str]:
    """Escolhe sozinho a conta que o tecnico quer recuperar.

    Prioriza contas humanas ativas com perfil no disco, depois a conta com o
    perfil mais recente e, por fim, qualquer conta ativa.
    """
    ativas = [c for c in contas if c.ativa] or contas
    if not ativas:
        return None
    humanas = [c for c in ativas if c.detalhe != "conta integrada"] or ativas
    preferidas = [c for c in humanas if _mtime_perfil(c.nome, raiz_usuarios) > 0] or humanas
    atual_lower = (atual or "").lower()
    sem_atual = [c for c in preferidas if c.nome.lower() != atual_lower]
    escolhas = sem_atual or preferidas
    return max(escolhas, key=lambda c: (_mtime_perfil(c.nome, raiz_usuarios),
                                        c.nome.lower() != atual_lower)).nome


def contas_offline(runner: Runner, config: Path) -> list[str]:
    """Lista as contas do SAM com chntpw (precisa do chntpw instalado)."""
    if not chntpw_disponivel(runner):
        return []
    res = runner.run(["chntpw", "-l", "SAM"], timeout=40, cwd=str(config))
    nomes: list[str] = []
    for linha in (res.out or "").splitlines():
        if ":" not in linha:
            continue
        chave, _, valor = linha.partition(":")
        if "username" in chave.lower() or "usuario" in chave.lower():
            nome = valor.strip()
            if nome:
                nomes.append(nome)
    return nomes


def conta_offline_principal(config: Path, nomes: list[str]) -> Optional[str]:
    """Escolhe a conta offline pelo perfil mais recente em C:\\Users."""
    raiz = config.parents[2] if len(config.parents) > 2 else config.parent
    usuarios = raiz / "Users"
    candidatos = [n for n in nomes if n.lower() not in
                  ("administrator", "administrador", "defaultaccount", "guest",
                   "convidado", "wdagutilityaccount", "defaultuser0")]
    lista = candidatos or nomes
    if not lista:
        return None
    return max(lista, key=lambda n: (_mtime_perfil(n, usuarios), n)).strip() or None
