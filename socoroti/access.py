"""Diagnostico de acesso: contas, bloqueios, RDP/SSH, boot e recuperacao.

Foco: descobrir POR QUE o acesso foi perdido (local ou remoto) e montar um
plano seguro de recuperacao. Nada aqui contorna autenticacao: as acoes usam
canais administrativos legitimos e exigem confirmacao.
"""

from __future__ import annotations

import datetime as dt
import os
import platform
import re
import shutil
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from . import platform_info
from .model import Action, Diagnosis, Finding, Step, deduplicar_acoes, ordenar_findings
from .runner import IS_WINDOWS, Runner

AREA = "acesso"

CONTAS_IGNORADAS = {
    "defaultaccount",
    "guest",
    "convidado",
    "wdagutilityaccount",
    "administrator",
    "administrador",
}


@dataclass
class Conta:
    nome: str
    tipo: str = "local"
    ativo: bool = True
    bloqueada: bool = False
    senha_requerida: bool = True
    senha_expira: str = ""
    ultimo_login: str = ""
    admin: bool = False
    descricao: str = ""
    status: str = ""


@dataclass
class AccessInfo:
    sistema: str = ""
    host: str = ""
    usuario: str = ""
    admin_atual: bool = False
    dominio: str = ""
    dominio_ingressado: bool = False
    contas: list[Conta] = field(default_factory=list)
    nomes_admin: list[str] = field(default_factory=list)
    grupo_admin: str = "Administrators"
    rdp_habilitado: bool = False
    rdp_servico: str = "desconhecido"
    rdp_firewall: bool = False
    rdp_ouvindo: bool = False
    ssh_ativo: bool = False
    ssh_habilitado: bool = False
    ssh_config: dict[str, str] = field(default_factory=dict)
    ssh_root: bool = False
    firewall: list[dict[str, Any]] = field(default_factory=list)
    portas_remotas: list[dict[str, Any]] = field(default_factory=list)
    portas_ouvindo: list[int] = field(default_factory=list)
    bitlocker: list[dict[str, Any]] = field(default_factory=list)
    secure_boot: str = "desconhecido"
    uefi: Optional[bool] = None
    winre: str = "desconhecido"
    winre_texto: str = ""
    luks: bool = False
    boot: str = ""
    uptime_s: float = 0.0
    reinicio_pendente: bool = False
    sessoes: list[str] = field(default_factory=list)
    ultimos_logins: list[str] = field(default_factory=list)
    disco_sistema_livre_pct: Optional[float] = None
    extras: dict[str, Any] = field(default_factory=dict)


def _agora() -> dt.datetime:
    return dt.datetime.now()


def _data_br(valor: str) -> Optional[dt.datetime]:
    valor = (valor or "").strip()
    if not valor:
        return None
    for formato in ("%Y-%m-%d", "%Y-%m-%d %H:%M", "%d/%m/%Y", "%m/%d/%Y", "%Y-%m-%dT%H:%M:%S"):
        try:
            return dt.datetime.strptime(valor[: len(formato) + 2].strip(), formato)
        except ValueError:
            continue
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})", valor)
    if m:
        try:
            return dt.datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            return None
    return None


# --------------------------------------------------------------------------- coleta
def _coletar_windows(runner: Runner, info: AccessInfo) -> None:
    script = r"""
$adminGroup = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue
$adminNames = @()
if ($adminGroup) {
  $adminNames = @($adminGroup | Get-LocalGroupMember -ErrorAction SilentlyContinue |
    ForEach-Object { ($_.Name -split '\\')[-1] })
}
$users = @()
if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
  $users = Get-LocalUser | ForEach-Object {
    [pscustomobject]@{
      nome=[string]$_.Name; ativo=[bool]$_.Enabled; senha=[bool]$_.PasswordRequired;
      expira= if ($_.PasswordExpires) { $_.PasswordExpires.ToString('yyyy-MM-dd') } else { '' };
      login= if ($_.LastLogon) { $_.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { '' };
      desc=[string]$_.Description; admin=($adminNames -contains $_.Name)
    }
  }
}
$rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue
$svc = Get-Service TermService -ErrorAction SilentlyContinue
$rdpFw = @(Get-NetFirewallRule -Name 'RemoteDesktop-UserMode-In-TCP' -ErrorAction SilentlyContinue |
  ForEach-Object { [pscustomobject]@{nome=[string]$_.DisplayName; ativo=[bool]$_.Enabled} })
$sshSvc = Get-Service sshd -ErrorAction SilentlyContinue
$fw = @(Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{nome=[string]$_.Name; ativo=[bool]$_.Enabled} })
$listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  ForEach-Object { [pscustomobject]@{porta=[int]$_.LocalPort; pid=[int]$_.OwningProcess} })
$bt = @()
try { $bt = @(Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
  [pscustomobject]@{volume=[string]$_.MountPoint; status=[string]$_.VolumeStatus;
    protecao=[string]$_.ProtectionStatus} }) } catch {}
$sb = 'indisponivel'
try { if (Confirm-SecureBootUEFI -ErrorAction Stop) { $sb = 'ativo' } else { $sb = 'desativado' } } catch { $sb = 'indisponivel' }
$pend = $false
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pend = $true }
if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations') { $pend = $true }
$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$disco = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
[pscustomobject]@{
  users=@($users); adminNames=@($adminNames); adminGroup=if($adminGroup){[string]$adminGroup.Name}else{'Administrators'};
  rdp_deny=if($rdp){[int]$rdp.fDenyTSConnections}else{1};
  rdp_svc=if($svc){[string]$svc.StartType + ' / ' + [string]$svc.Status}else{'ausente'};
  rdp_fw=@($rdpFw); ssh_svc=if($sshSvc){[string]$sshSvc.Status}else{'ausente'};
  firewall=@($fw); listen=@($listen); bitlocker=@($bt); secureboot=$sb;
  dominio=[string]$cs.Domain; parte_dominio=[bool]$cs.PartOfDomain;
  boot_epoch=if($os.LastBootUpTime){[long]([DateTimeOffset]$os.LastBootUpTime).ToUnixTimeSeconds()}else{0};
  pendente=$pend;
  livre_pct=if($disco -and $disco.Size -gt 0){[double](100.0*$disco.FreeSpace/$disco.Size)}else{$null}
}
"""
    dados = runner.ps_json(script, timeout=60)
    d: dict[str, Any] = dados[0] if dados and isinstance(dados[0], dict) else {}
    info.sistema = platform_info.nome_sistema()
    info.host = platform_info.hostname()
    info.usuario = platform_info.usuario()
    info.dominio = str(d.get("dominio") or "")
    info.dominio_ingressado = bool(d.get("parte_dominio"))
    info.grupo_admin = str(d.get("adminGroup") or "Administrators")
    info.nomes_admin = [str(n) for n in (d.get("adminNames") or [])]
    info.rdp_habilitado = int(d.get("rdp_deny") or 1) == 0
    info.rdp_servico = str(d.get("rdp_svc") or "desconhecido")
    info.rdp_firewall = any(bool(r.get("ativo")) for r in (d.get("rdp_fw") or []))
    info.ssh_ativo = str(d.get("ssh_svc") or "").lower() == "running"
    info.secure_boot = str(d.get("secureboot") or "desconhecido")
    info.reinicio_pendente = bool(d.get("pendente"))
    info.bitlocker = [
        {"volume": str(b.get("volume") or ""), "status": str(b.get("status") or ""),
         "protecao": str(b.get("protecao") or "")}
        for b in (d.get("bitlocker") or [])
    ]
    boot_epoch = int(d.get("boot_epoch") or 0)
    if boot_epoch > 0:
        info.uptime_s = max(0.0, time.time() - boot_epoch)
        info.boot = time.strftime("%d/%m/%Y %H:%M", time.localtime(boot_epoch))
    if d.get("livre_pct") is not None:
        try:
            info.disco_sistema_livre_pct = float(d["livre_pct"])
        except (TypeError, ValueError):
            pass

    for u in d.get("users") or []:
        nome = str(u.get("nome") or "")
        if not nome:
            continue
        expira = str(u.get("expira") or "")
        expirada = False
        data_exp = _data_br(expira)
        if data_exp and data_exp < _agora():
            expirada = True
        info.contas.append(Conta(
            nome=nome, ativo=bool(u.get("ativo")), senha_requerida=bool(u.get("senha")),
            senha_expira=expira, ultimo_login=str(u.get("login") or ""),
            admin=bool(u.get("admin")) or nome.lower() in {n.lower() for n in info.nomes_admin},
            descricao=str(u.get("desc") or ""), status="expirada" if expirada else "",
        ))

    portas = {int(x.get("porta") or 0) for x in (d.get("listen") or [])}
    info.portas_ouvindo = sorted(p for p in portas if p)
    info.rdp_ouvindo = 3389 in portas
    info.portas_remotas = [
        {"porta": p, "servico": "RDP"} for p in (3389,) if p in portas
    ] + [{"porta": p, "servico": "SSH"} for p in (22,) if p in portas and info.ssh_ativo]
    info.firewall = [
        {"nome": str(f.get("nome") or ""), "ativo": bool(f.get("ativo"))}
        for f in (d.get("firewall") or [])
    ]

    # WinRE (exige admin; falha silenciosa sem permissao).
    res = runner.run(["reagentc", "/info"], timeout=20)
    info.winre_texto = res.saida
    texto = res.out.lower()
    if res.ok:
        if re.search(r"(enabled|ativado|habilitado)\s*:\s*(yes|sim|true)", texto):
            info.winre = "habilitado"
        elif re.search(r"(enabled|ativado|habilitado)\s*:\s*(no|nao|não|false)", texto):
            info.winre = "desabilitado"
        else:
            info.winre = "desconhecido"
    else:
        info.winre = "sem permissao"

    # Sessoes locais/remotas.
    res = runner.run(["quser"], timeout=15)
    if res.ok:
        for linha in res.out.splitlines()[1:]:
            if linha.strip() and not linha.strip().startswith(">"):
                info.sessoes.append(" ".join(linha.split()))
            elif linha.strip().startswith(">"):
                info.sessoes.append(" ".join(linha.split()))


def _ler(caminho: str) -> str:
    try:
        with open(caminho, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _sem_acento(texto: str) -> str:
    import unicodedata

    return (
        unicodedata.normalize("NFKD", texto)
        .encode("ascii", "ignore")
        .decode("ascii")
        .lower()
    )


def _coletar_linux(runner: Runner, info: AccessInfo) -> None:
    info.sistema = platform_info.nome_sistema()
    info.host = platform_info.hostname()
    info.usuario = platform_info.usuario()

    # Membros dos grupos administrativos.
    membros_admin: set[str] = set()
    for grupo in ("sudo", "wheel", "admin"):
        res = runner.run(["getent", "group", grupo], timeout=10)
        if not res.ok:
            continue
        linha = res.saida
        partes = linha.split(":")
        if len(partes) >= 4:
            for membro in partes[3].split(","):
                if membro.strip():
                    membros_admin.add(membro.strip())
    info.nomes_admin = sorted(membros_admin)
    info.grupo_admin = "sudo/wheel"

    res = runner.run(["getent", "passwd"], timeout=15)
    for linha in res.out.splitlines():
        partes = linha.split(":")
        if len(partes) < 7:
            continue
        nome, uid, gid, gecos, home, shell = partes[0], partes[2], partes[3], partes[4], partes[5], partes[6]
        if not uid.isdigit():
            continue
        uid_i = int(uid)
        if not (uid_i == 0 or 1000 <= uid_i < 60000):
            continue
        if shell.endswith(("nologin", "false", "sync")):
            continue
        conta = Conta(
            nome=nome,
            admin=nome in membros_admin or uid_i == 0,
            descricao=gecos,
            status="",
        )
        st = runner.run(["passwd", "-S", nome], timeout=10)
        campos = st.out.split()
        if st.ok and len(campos) >= 2:
            estado = campos[1].upper()
            conta.ativo = estado not in ("L", "LK")
            conta.bloqueada = estado in ("L", "LK")
            if estado == "NP":
                conta.senha_requerida = False
            conta.status = estado
            # passwd -S: nome status ultima_alteracao min max aviso inativo
            if len(campos) >= 6 and campos[2] not in ("", "0"):
                data_base = _data_br(campos[2])
                try:
                    max_dias = int(campos[4])
                except ValueError:
                    max_dias = 99999
                if data_base and max_dias < 99999:
                    expira = data_base + dt.timedelta(days=max_dias)
                    conta.senha_expira = expira.strftime("%Y-%m-%d")
                    if expira < _agora():
                        conta.status = "expirada"
        else:
            conta.status = "desconhecido"
        info.contas.append(conta)

    # SSH
    ssh_ativo = False
    ssh_habilitado = False
    for servico in ("ssh", "sshd"):
        r = runner.run(["systemctl", "is-active", servico], timeout=10)
        if r.out.strip() == "active":
            ssh_ativo = True
        r = runner.run(["systemctl", "is-enabled", servico], timeout=10)
        if r.out.strip() in ("enabled", "static", "indirect"):
            ssh_habilitado = True
    info.ssh_ativo = ssh_ativo
    info.ssh_habilitado = ssh_habilitado
    sshd_config = _ler("/etc/ssh/sshd_config")
    for chave in ("PermitRootLogin", "PasswordAuthentication", "Port", "AllowUsers", "PubkeyAuthentication"):
        m = re.search(rf"(?mi)^\s*{chave}\s+(\S+)", sshd_config)
        if m:
            info.ssh_config[chave] = m.group(1)
    info.ssh_root = info.ssh_config.get("PermitRootLogin", "").lower() in ("yes", "without-password", "prohibit-password")

    # Portas ouvindo
    res = runner.run(["ss", "-ltn"], timeout=15)
    portas: set[int] = set()
    for linha in res.out.splitlines()[1:]:
        partes = linha.split()
        if len(partes) >= 4:
            m = re.search(r":(\d+)$", partes[3])
            if m:
                portas.add(int(m.group(1)))
    info.portas_ouvindo = sorted(portas)
    info.rdp_ouvindo = 3389 in portas
    info.rdp_habilitado = info.rdp_ouvindo
    info.rdp_servico = "xrdp ativo" if runner.run(["systemctl", "is-active", "xrdp"], timeout=8).out.strip() == "active" else "inativo"
    info.portas_remotas = [
        {"porta": p, "servico": "SSH" if p == 22 else "RDP" if p == 3389 else "?"}
        for p in (22, 3389) if p in portas
    ]

    # Firewall
    for nome, cmd in (
        ("ufw", ["ufw", "status"]),
        ("firewalld", ["firewall-cmd", "--state"]),
        ("nftables", ["systemctl", "is-active", "nftables"]),
    ):
        if shutil.which(cmd[0]):
            r = runner.run(cmd, timeout=10)
            if not r.ok:
                # Sem permissao ou servico ausente: nao afirmamos que esta desligado.
                continue
            estado = _sem_acento(r.out)
            ativo = ("active" in estado or "running" in estado) and "inactive" not in estado
            info.firewall.append({"nome": nome, "ativo": ativo})

    # Boot / criptografia
    info.uefi = os.path.isdir("/sys/firmware/efi")
    if info.uefi:
        for arq in os.listdir("/sys/firmware/efi/efivars") if os.path.isdir("/sys/firmware/efi/efivars") else []:
            if arq.startswith("SecureBoot-"):
                try:
                    with open(os.path.join("/sys/firmware/efi/efivars", arq), "rb") as fh:
                        dados = fh.read()
                    info.secure_boot = "ativo" if len(dados) > 4 and dados[4] == 1 else "desativado"
                except OSError:
                    pass
                break
    res = runner.run(["lsblk", "-o", "NAME,TYPE"], timeout=10)
    info.luks = "crypt" in res.out
    info.reinicio_pendente = os.path.exists("/var/run/reboot-required")
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as fh:
            info.uptime_s = float(fh.read().split()[0])
        info.boot = time.strftime("%d/%m/%Y %H:%M", time.localtime(time.time() - info.uptime_s))
    except (OSError, ValueError, IndexError):
        pass
    try:
        uso = shutil.disk_usage("/")
        info.disco_sistema_livre_pct = 100.0 * uso.free / uso.total if uso.total else None
    except OSError:
        pass

    res = runner.run(["who"], timeout=10)
    info.sessoes = [l for l in res.out.splitlines() if l.strip()]
    res = runner.run(["last", "-n", "5", "-w"], timeout=10)
    info.ultimos_logins = [l for l in res.out.splitlines()[:5] if l.strip()]

    if info.luks:
        info.extras["criptografia"] = "LUKS detectado"


def coletar(runner: Runner) -> AccessInfo:
    info = AccessInfo()
    info.admin_atual = platform_info.eh_admin()
    if IS_WINDOWS:
        _coletar_windows(runner, info)
    else:
        _coletar_linux(runner, info)
    return info


# --------------------------------------------------------------------------- regras
def _conta_ignorada(nome: str) -> bool:
    return nome.lower() in CONTAS_IGNORADAS


def diagnosticar(runner: Runner, incluir_remoto: bool = False) -> Diagnosis:
    info = coletar(runner)
    diag = Diagnosis(area=AREA, title="Diagnostico de acesso e recuperacao")
    achados: list[Finding] = []

    def add(id_: str, sev: str, titulo: str, detalhe: str = "", causa: str = "") -> None:
        achados.append(Finding(id=id_, area=AREA, severity=sev, title=titulo, detail=detalhe, cause=causa))

    if not info.admin_atual:
        add("sem_admin", "info", "Diagnostico rodando sem privilegios de administrador",
            "Algumas informacoes (WinRE, BitLocker, contas de outros usuarios) ficam limitadas.",
            "Abra o terminal como Administrador/root para ver tudo.")

    admins = [c for c in info.contas if c.admin]
    admins_ativos = [c for c in admins if c.ativo and not c.bloqueada and c.status != "expirada"]
    if not admins_ativos and admins:
        sev = "aviso" if info.dominio_ingressado else "critico"
        add("sem_admin_ativo", sev, "Nenhuma conta administradora local ativa",
            "Contas admin: " + ", ".join(f"{c.nome} ({'ativa' if c.ativo else 'inativa'})" for c in admins),
            "Sem admin ativo nao da para recuperar senha/servicos pela propria maquina; sera preciso midia de recuperacao.")
    elif not info.contas:
        add("sem_contas", "info", "Lista de contas indisponivel",
            "Nao foi possivel ler as contas locais.", "Rode como administrador/root.")

    desativadas = [c.nome for c in info.contas if not c.ativo and not _conta_ignorada(c.nome) and not c.admin]
    if desativadas:
        add("contas_desativadas", "info", "Contas desativadas: " + ", ".join(desativadas),
            "Se alguma dessas e a sua, ela precisa ser reativada por um administrador.", "")

    bloqueadas = [c.nome for c in info.contas if c.bloqueada]
    if bloqueadas:
        add("contas_bloqueadas", "erro", "Conta(s) bloqueada(s) por tentativas: " + ", ".join(bloqueadas),
            "Bloqueio por senha errada (pam_faillock).", "Desbloqueie com faillock/pam_tally2 ou aguarde a politica de bloqueio.")

    expiradas: list[str] = []
    for conta in info.contas:
        if _conta_ignorada(conta.nome):
            continue
        expirada = conta.status == "expirada"
        if conta.senha_expira:
            data_exp = _data_br(conta.senha_expira)
            if data_exp and data_exp < _agora():
                expirada = True
        if expirada:
            expiradas.append(conta.nome)
    if expiradas:
        add("senhas_expiradas", "aviso", "Senha(s) expirada(s): " + ", ".join(sorted(set(expiradas))),
            "Login pode falhar mesmo com a senha correta.", "Redefina a senha ou ajuste a politica de expiracao.")

    # Acesso remoto
    if IS_WINDOWS:
        if info.rdp_habilitado:
            if "running" in info.rdp_servico.lower():
                add("rdp_ativo", "info", "RDP habilitado e servico rodando",
                    f"Porta 3389 ouvindo: {'sim' if info.rdp_ouvindo else 'nao'}; regra de firewall: {'sim' if info.rdp_firewall else 'nao'}.",
                    "" if info.rdp_ouvindo else "Servico/porta inconsistente: reinicie o TermService.")
            else:
                add("rdp_servico_parado", "erro", "RDP habilitado, mas servico parado",
                    f"TermService: {info.rdp_servico}",
                    "Servico TermService parado impede conexao remota.")
            if not info.rdp_firewall:
                add("rdp_sem_firewall", "aviso", "RDP sem regra de firewall ativa",
                    "A regra RemoteDesktop-UserMode-In-TCP nao esta habilitada.",
                    "Firewall bloqueia a porta 3389.")
        else:
            add("rdp_desativado", "info", "RDP desativado",
                "Area de Trabalho Remota nao esta habilitada nesta maquina.",
                "Se voce precisa entrar remotamente, habilite o RDP (com seguranca).")
    else:
        if info.ssh_ativo:
            add("ssh_ativo", "info", "SSH ativo", f"Porta 22 ouvindo: {'sim' if 22 in info.portas_ouvindo else 'nao'}.",
                "" if 22 in info.portas_ouvindo else "Servico ativo mas sem porta: verifique ListenAddress/firewall.")
        else:
            add("ssh_parado", "info", "SSH nao esta rodando",
                "Servico ssh/sshd inativo.", "Habilite com: sudo systemctl enable --now ssh")
        if info.ssh_root:
            add("ssh_root", "aviso", "SSH permite login direto de root",
                f"PermitRootLogin {info.ssh_config.get('PermitRootLogin')}",
                "Risco de seguranca; prefira usuario comum + sudo.")
        if info.rdp_ouvindo:
            add("xrdp_ativo", "info", "RDP (xrdp) ouvindo na porta 3389", "", "")

    if not info.portas_remotas:
        add("sem_remoto", "aviso", "Nenhum acesso remoto ativo (RDP/SSH)",
            "Se voce perdeu o acesso remoto, nao ha servico escutando para entrar.",
            "Habilite RDP/SSH localmente ou use ferramenta de acesso remoto assistido.")
    else:
        add("remoto_ok", "ok", "Acesso remoto disponivel",
            ", ".join(f"{p['servico']}:{p['porta']}" for p in info.portas_remotas),
            "Teste a conexao de outra maquina antes de concluir que o problema e o PC.")

    for fw in info.firewall:
        if not fw.get("ativo") and fw.get("nome") in ("Domain", "Private", "Public", "ufw", "firewalld"):
            add("firewall_desligado", "aviso", f"Firewall desligado ({fw.get('nome')})",
                "Maquina exposta na rede.", "Religue o firewall e libere apenas o necessario.")

    # Boot / recuperacao
    if IS_WINDOWS:
        if info.winre == "habilitado":
            add("winre_ok", "info", "Windows RE (ambiente de recuperacao) disponivel",
                "Shift+Reiniciar abre as opcoes de recuperacao.", "")
        elif info.winre == "desabilitado":
            add("winre_desabilitado", "aviso", "Windows RE desabilitado",
                "Sem WinRE, o reparo de inicializacao fica limitado.",
                "Reative com: reagentc /enable (como admin).")
        elif info.winre == "sem permissao":
            add("winre_desconhecido", "info", "WinRE: sem permissao para consultar",
                "Rode como administrador para verificar reagentc.", "")
        for b in info.bitlocker:
            if (b.get("protecao") or "").lower() in ("on", "1", "ligado") or (b.get("status") or "").lower() in ("fullyencrypted", "encrypted"):
                add("bitlocker_ativo", "aviso", f"BitLocker ativo em {b.get('volume')}",
                    "Sem a chave de recuperacao, nem midia de boot acessa o disco.",
                    "Guarde a chave de 48 digitos na conta Microsoft/AD ou impressa em local seguro.")
        if info.secure_boot not in ("desconhecido", "indisponivel"):
            add("secure_boot", "info", f"Secure Boot: {info.secure_boot}", "", "")
    else:
        if info.uefi is not None:
            add("uefi", "info", f"Boot: {'UEFI' if info.uefi else 'Legacy/BIOS'}",
                f"Secure Boot: {info.secure_boot}" if info.uefi else "", "")
        if info.luks:
            add("luks", "aviso", "Disco criptografado (LUKS)",
                "A recuperacao offline exige a senha da criptografia.",
                "Sem a passphrase, os dados nao podem ser acessados por midia de boot.")

    if info.disco_sistema_livre_pct is not None and info.disco_sistema_livre_pct < 5:
        add("disco_cheio", "erro", f"Disco do sistema quase cheio ({info.disco_sistema_livre_pct:.1f}% livre)",
            "Falta de espaco pode impedir login, atualizacoes e servicos.",
            "Libere espaco antes de qualquer outra recuperacao.")

    if info.reinicio_pendente:
        add("reinicio_pendente", "info", "Reinicio pendente", "", "Reinicie quando possivel.")

    if info.uptime_s > 30 * 86400:
        add("uptime_longo", "info", f"Ligado ha {int(info.uptime_s // 86400)} dias",
            f"Ultimo boot: {info.boot}", "")

    if info.sessoes:
        add("sessoes", "info", "Sessoes ativas",
            " | ".join(info.sessoes[:3]), "Se ha sessao de outro admin, ele pode ajudar na recuperacao.")

    if info.dominio_ingressado:
        add("dominio", "info", f"Maquina no dominio {info.dominio}",
            "Para contas de dominio, quem recupera senha/bloqueio e o administrador do AD.",
            "Use Unlock-ADAccount / Set-ADAccountPassword ou o console do AD.")

    if not any(f.severity in ("aviso", "erro", "critico") for f in achados):
        add("ok", "ok", "Acesso local e remoto sem alertas",
            "Contas, servicos e boot sem problemas evidentes.")

    diag.findings = ordenar_findings(achados)
    diag.actions = _planejar(info, diag, incluir_remoto=incluir_remoto)
    diag.summary = _resumo(diag, info)
    diag.data = {
        "Sistema": info.sistema,
        "Host": info.host,
        "Usuario atual": info.usuario,
        "Administrador": info.admin_atual,
        "Dominio": info.dominio or "(nenhum)",
        "Contas": [
            {"nome": c.nome, "admin": c.admin, "ativo": c.ativo, "bloqueada": c.bloqueada,
             "senha_expira": c.senha_expira, "ultimo_login": c.ultimo_login, "status": c.status}
            for c in info.contas
        ],
        "RDP": {
            "habilitado": info.rdp_habilitado, "servico": info.rdp_servico,
            "firewall": info.rdp_firewall, "porta_3389": info.rdp_ouvindo,
        },
        "SSH": {"ativo": info.ssh_ativo, "habilitado": info.ssh_habilitado, "config": info.ssh_config},
        "Portas remotas": info.portas_remotas,
        "Firewall": info.firewall,
        "WinRE": info.winre,
        "BitLocker": info.bitlocker,
        "Secure Boot": info.secure_boot,
        "UEFI": info.uefi,
        "LUKS": info.luks,
        "Boot": info.boot,
        "Uptime (dias)": round(info.uptime_s / 86400, 1),
        "Reinicio pendente": info.reinicio_pendente,
        "Sessoes": info.sessoes,
        "Ultimos logins": info.ultimos_logins,
        "Disco sistema livre %": round(info.disco_sistema_livre_pct, 1) if info.disco_sistema_livre_pct is not None else None,
    }
    return diag


def _resumo(diag: Diagnosis, info: AccessInfo) -> str:
    graves = [f for f in diag.findings if f.severity in ("critico", "erro")]
    if graves:
        return f"{graves[0].title}. {graves[0].cause}".strip()
    avisos = [f for f in diag.findings if f.severity == "aviso"]
    if avisos:
        return f"{avisos[0].title}. {avisos[0].cause}".strip()
    if info.portas_remotas:
        return "Acesso local e remoto disponiveis; nenhum bloqueio evidente."
    return "Sem problemas de conta/boot, mas nenhum acesso remoto ativo."


def _planejar(info: AccessInfo, diag: Diagnosis, incluir_remoto: bool = False) -> list[Action]:
    ids = {f.id for f in diag.findings}
    acoes: list[Action] = []

    def add(a: Action) -> None:
        if a.applies in ("any", "windows" if IS_WINDOWS else "linux"):
            acoes.append(a)

    if IS_WINDOWS:
        if incluir_remoto or ids & {"rdp_servico_parado", "rdp_sem_firewall"}:
            add(Action(
                "ativar_rdp", "Habilitar Area de Trabalho Remota (RDP)", risk="medio", needs_admin=True,
                why="Liga o servico, libera a regra de firewall e permite entrar de outra maquina.",
                steps=[
                    Step("Habilitar RDP no registro",
                         ps="Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 0"),
                    Step("Liberar regra de firewall do RDP",
                         ps="Enable-NetFirewallRule -Name 'RemoteDesktop-UserMode-In-TCP'"),
                    Step("Configurar e iniciar TermService",
                         ps="Set-Service -Name TermService -StartupType Manual; Start-Service TermService"),
                ],
                note="RDP exposto na internet e risco alto. Use VPN/ZeroTier/Tailscale ou encaminhe porta so com senha forte e NLA.",
            ))
        if info.winre == "desabilitado":
            add(Action(
                "ativar_winre", "Reativar Windows RE", risk="baixo", needs_admin=True,
                why="Deixa o ambiente de recuperacao disponivel para reparar boot e fazer restore.",
                steps=[Step("Habilitar WinRE", argv=["reagentc", "/enable"])],
            ))

        desativadas = [c.nome for c in info.contas if not c.ativo and not _conta_ignorada(c.nome)]
        for nome in desativadas:
            add(Action(
                f"habilitar_conta:{nome}", f"Reativar conta {nome}", risk="baixo", needs_admin=True,
                why="Se essa conta precisa voltar a entrar na maquina.",
                steps=[Step(f"Ativar {nome}", argv=["net", "user", nome, "/active:yes"])],
            ))

        add(Action(
            "resetar_senha", "Redefinir senha de uma conta (assistido)", manual=True, needs_admin=True,
            why="Redefinir senha exige que voce ja esteja logado em uma conta administradora.",
            steps=[
                Step("Definir nova senha (o comando pede a senha, sem gravar no historico):"),
                Step("net user NOME_DO_USUARIO *"),
                Step("Ativar a conta, se estiver desativada:  net user NOME_DO_USUARIO /active:yes"),
                Step(f"Conceder admin, se necessario:  net localgroup \"{info.grupo_admin}\" NOME_DO_USUARIO /add"),
                Step("Se for conta de dominio:  Unlock-ADAccount -Identity usuario  e  Set-ADAccountPassword -Identity usuario -Reset"),
            ],
            note="Sem outra conta admin, use o cartao de recuperacao (socorro cartao) e as opcoes oficiais do Windows.",
        ))
        add(Action(
            "admin_integrado", "Usar/ativar o Administrador integrado (assistido)", manual=True,
            why="O Windows mantem uma conta 'Administrator' oculta que pode ser ativada por outro admin.",
            steps=[
                Step("Verifique se existe:  Get-LocalUser | Where-Object {$_.SID -like '*-500'}"),
                Step("Ative e defina senha:  net user Administrator *  e  net user Administrator /active:yes"),
                Step("Depois de recuperar o acesso, desative-a novamente por seguranca."),
            ],
        ))
    else:
        if incluir_remoto and "ssh_parado" in ids:
            add(Action(
                "ativar_ssh", "Habilitar servidor SSH", risk="medio", needs_admin=True,
                why="Permite administrar a maquina remotamente pela rede.",
                steps=[
                    Step("Instalar (se necessario) e habilitar",
                         shell="(command -v sshd >/dev/null || sudo apt-get install -y openssh-server) && sudo systemctl enable --now ssh"),
                    Step("Conferir porta 22", shell="ss -ltn | grep ':22 ' || true"),
                ],
                note="Se o firewall estiver ativo, libere a porta 22 apenas para redes confiaveis.",
            ))
        if info.ssh_root:
            add(Action(
                "endurecer_ssh", "Desabilitar login direto de root", risk="baixo", needs_admin=True,
                why="Reduz risco de invasao por forca bruta.",
                steps=[
                    Step("Editar /etc/ssh/sshd_config (PermitRootLogin no) e recarregar",
                         shell="sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl reload ssh 2>/dev/null || systemctl reload sshd"),
                ],
            ))

        bloqueadas = [c.nome for c in info.contas if c.bloqueada]
        for nome in bloqueadas:
            add(Action(
                f"desbloquear_conta:{nome}", f"Desbloquear conta {nome}", risk="baixo", needs_admin=True,
                why="Remove o bloqueio por tentativas de senha erradas.",
                steps=[Step(f"Resetar contador de falhas de {nome}",
                            shell=f"faillock --user {nome} --reset 2>/dev/null || pam_tally2 -r -u {nome} 2>/dev/null || true")],
            ))

        expiradas = [c.nome for c in info.contas if c.status == "expirada"]
        for nome in expiradas:
            add(Action(
                f"renovar_senha:{nome}", f"Remover expiracao da senha de {nome}", risk="baixo", needs_admin=True,
                why="Conta com senha expirada nao entra mesmo com a senha correta.",
                steps=[Step(f"Ajustar expiracao de {nome}", argv=["chage", "-E", "-1", "-M", "99999", nome])],
            ))

        add(Action(
            "resetar_senha", "Redefinir senha (assistido)", manual=True, needs_admin=True,
            why="Com acesso administrativo local, a redefinicao e direta.",
            steps=[
                Step("Definir nova senha:  sudo passwd NOME_DO_USUARIO"),
                Step("Desbloquear a senha:  sudo usermod -U NOME_DO_USUARIO  (ou sudo passwd -u NOME)"),
                Step("Remover expiracao:  sudo chage -E -1 -M 99999 NOME_DO_USUARIO"),
                Step("Garantir admin:  sudo usermod -aG sudo NOME_DO_USUARIO"),
            ],
            note="Sem acesso local e sem outra conta admin, use o playbook de boot/recovery com midia live (acesso fisico autorizado).",
        ))

    if "disco_cheio" in ids:
        add(Action(
            "liberar_disco", "Liberar espaco no disco do sistema", manual=True,
            why="Sem espaco o login e os servicos falham.",
            steps=[Step("Rode: socorro sistema limpeza"), Step("Remova logs/caches antigos e arquivos grandes pessoais.")],
        ))

    if "bitlocker_ativo" in ids:
        add(Action(
            "chave_bitlocker", "Localizar a chave de recuperacao do BitLocker", manual=True,
            why="Sem a chave, nem WinRE acessa o disco.",
            steps=[
                Step("Conta Microsoft: account.microsoft.com/devices/recoverykey"),
                Step("AD/Intune: console de dispositivos ou Get-BitLockerVolume -MountPoint C: | Select KeyProtector"),
                Step("Guarde a chave impressa junto do equipamento (local seguro)."),
            ],
        ))

    if "luks" in ids:
        add(Action(
            "chave_luks", "Separar a passphrase do LUKS", manual=True,
            why="A recuperacao offline com midia live exige a senha de criptografia.",
            steps=[Step("Tenha a passphrase em maos antes de iniciar o resgate por pendrive.")],
        ))

    add(Action(
        "cartao_recuperacao", "Gerar cartao de recuperacao", manual=True,
        why="Deixa os caminhos de boot/resgate documentados e impressos.",
        steps=[Step("Rode: socorro cartao --destino .")],
    ))

    return deduplicar_acoes(acoes)


def listar_usuarios(runner: Runner) -> list[str]:
    """Lista usuários locais do sistema."""
    if platform_info.eh_windows():
        out = runner.executar(["net", "user"])
        # Parsing simplificado da saída do 'net user'
        linhas = [l.strip() for l in out.splitlines() if l.strip()]
        # Remove cabeçalho e rodapé (varia conforme o idioma)
        return [u for linha in linhas for u in linha.split() if u not in ("User", "accounts", "for", "The", "command", "completed", "successfully")]
    else:
        # Linux
        out = runner.executar(["getent", "passwd"])
        return [l.split(":")[0] for l in out.splitlines()]

def promover_a_admin(runner: Runner, usuario: str) -> tuple[bool, str]:
    """Promove um usuário a administrador (ou root/sudo)."""
    if platform_info.eh_windows():
        # Comando Windows
        res = runner.executar(["net", "localgroup", "administrators", usuario, "/add"])
        return (True, "Sucesso") if "successfully" in res.lower() else (False, res)
    else:
        # Comando Linux (adiciona ao grupo sudo/wheel)
        grupo = "sudo" if runner.executar(["grep", "-q", "sudo", "/etc/group"]) else "wheel"
        res = runner.executar(["usermod", "-aG", grupo, usuario])
        return (True, "Sucesso") if not res else (False, res)
def imprimir_diagnostico(diag: Diagnosis, ui: Any) -> None:
    d = diag.data
    ui.secao("Maquina e contas")
    ui.kv("Sistema", d.get("Sistema", ""))
    ui.kv("Host / usuario", f"{d.get('Host')} / {d.get('Usuario atual')}")
    ui.kv("Administrador agora", "sim" if d.get("Administrador") else "NAO (diagnostico limitado)")
    if d.get("Dominio") and d["Dominio"] != "(nenhum)":
        ui.kv("Dominio", d["Dominio"])

    contas = d.get("Contas") or []
    if contas:
        linhas = []
        for c in contas:
            estado = "ativa" if c.get("ativo") else "desativada"
            if c.get("bloqueada"):
                estado = "BLOQUEADA"
            if c.get("status") == "expirada":
                estado = "senha expirada"
            tipo = "admin" if c.get("admin") else "usuario"
            if str(c.get("nome") or "").lower() in ("wdagutilityaccount", "defaultaccount", "guest", "convidado"):
                tipo = "sistema"
            linhas.append([c.get("nome"), tipo,
                           estado, c.get("senha_expira") or "-", c.get("ultimo_login") or "-"])
        ui.tabela(["Conta", "Tipo", "Estado", "Senha expira", "Ultimo login"], linhas)
    else:
        ui.aviso("Contas nao puderam ser lidas.")

    ui.secao("Acesso remoto")
    rdp = d.get("RDP") or {}
    ui.item("RDP (3389)", f"{'habilitado' if rdp.get('habilitado') else 'desativado'} | servico: {rdp.get('servico')} | firewall: {'sim' if rdp.get('firewall') else 'nao'} | porta: {'sim' if rdp.get('porta_3389') else 'nao'}")
    ssh = d.get("SSH") or {}
    if ssh:
        ui.item("SSH (22)", f"{'ativo' if ssh.get('ativo') else 'inativo'} | habilitado no boot: {'sim' if ssh.get('habilitado') else 'nao'}")
        for chave, valor in (ssh.get("config") or {}).items():
            ui.escrever("       " + ui.paint(f"{chave} {valor}", "\033[2m"))
    if d.get("Portas remotas"):
        ui.item("Portas remotas", ", ".join(f"{p['servico']}:{p['porta']}" for p in d["Portas remotas"]))
    if d.get("Sessoes"):
        ui.item("Sessoes ativas", " | ".join(d["Sessoes"][:3]))

    ui.secao("Boot e recuperacao")
    if IS_WINDOWS:
        ui.item("Windows RE", str(d.get("WinRE")))
        bt = d.get("BitLocker") or []
        if bt:
            ui.item("BitLocker", "; ".join(f"{b.get('volume')}: {b.get('status')}/{b.get('protecao')}" for b in bt))
        else:
            ui.item("BitLocker", "nao detectado/consultado")
        ui.item("Secure Boot", str(d.get("Secure Boot")))
    else:
        ui.item("Boot", "UEFI" if d.get("UEFI") else "Legacy/BIOS")
        ui.item("Secure Boot", str(d.get("Secure Boot")))
        ui.item("Disco criptografado (LUKS)", "sim" if d.get("LUKS") else "nao")
    ui.item("Ultimo boot", f"{d.get('Boot')} ({d.get('Uptime (dias)')} dias)")
    if d.get("Reinicio pendente"):
        ui.info("Reinicio pendente")

    ui.secao("Diagnostico de acesso")
    for f in diag.findings:
        texto = f.title + (f"  ({f.detail})" if f.detail else "")
        if f.severity == "ok":
            ui.ok(texto)
        elif f.severity == "info":
            ui.info(texto)
        elif f.severity == "aviso":
            ui.aviso(texto)
        elif f.severity == "erro":
            ui.erro(texto)
        else:
            ui.critico(texto)
        if f.cause:
            ui.escrever("      " + ui.paint("causa: " + f.cause, "\033[2m"))
    if diag.summary:
        ui.espaco()
        ui.escrever("  " + ui.paint("RESUMO: ", "\033[1m") + diag.summary)
