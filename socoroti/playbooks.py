"""Playbooks de recuperacao e cartao de emergencia imprimivel.

Os roteiros assumem ACESSO FISICO AUTORIZADO ao equipamento. Nao ha here
nenhum mecanismo de burlar autenticacao remota: sao os procedimentos padrao
de administrador (midia de recuperacao, WinRE, GRUB, chroot, RDP/SSH).
"""

from __future__ import annotations

import html
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from . import __version__, platform_info


@dataclass
class Passo:
    texto: str
    comando: str = ""
    linguagem: str = "bash"


@dataclass
class Playbook:
    id: str
    titulo: str
    quando: str
    sistema: str = "any"
    aviso: str = ""
    passos: list[Passo] = field(default_factory=list)
    notas: list[str] = field(default_factory=list)


PLAYBOOKS: list[Playbook] = [
    Playbook(
        id="windows-senha",
        titulo="Windows: perdi a senha ou a conta esta bloqueada",
        quando="Voce ve a tela de login, mas nao entra; conta local ou Microsoft.",
        sistema="windows",
        aviso="Use somente em equipamento proprio ou com autorizacao do dono.",
        passos=[
            Passo("Se a conta for Microsoft, redefina em outro aparelho e entre com a nova senha.",
                  "https://account.microsoft.com/security", "text"),
            Passo("No Windows 11 22H2+, contas locais podem ter perguntas de seguranca na tela de login: clique em 'Esqueci minha senha'."),
            Passo("Se existe OUTRA conta administradora ativa, entre nela e redefina a sua senha (o comando pede a nova senha, sem gravar no historico).",
                  "net user SEU_USUARIO *"),
            Passo("Ainda na outra conta admin, ative a conta se estiver desativada e garanta que ela seja admin.",
                  "net user SEU_USUARIO /active:yes\nnet localgroup \"Administradores\" SEU_USUARIO /add"),
            Passo("Se voce criou um disco de redefinicao de senha, use-o na tela de login (link 'Redefinir senha')."),
            Passo("Conta de dominio: apenas o administrador do AD resolve.",
                  "Unlock-ADAccount -Identity usuario\nSet-ADAccountPassword -Identity usuario -Reset", "powershell"),
            Passo("Sem nenhuma outra conta admin: use 'Resetar este PC' mantendo arquivos pelo WinRE. Isso recria as contas (exige a chave do BitLocker, se houver)."),
            Passo("Ultimo recurso: acessar os arquivos por um pendrive Linux e reinstalar o Windows. Faca backup antes."),
        ],
        notas=[
            "Evite tutoriais que substituem utilman.exe/sethc.exe: isso e backdoor e pode ser bloqueado por antivirus.",
            "Depois de recuperar: crie uma segunda conta admin, um disco de redefinicao e guarde a chave do BitLocker.",
        ],
    ),
    Playbook(
        id="windows-boot",
        titulo="Windows: nao inicia, tela azul ou erro de boot",
        quando="O PC liga, mas trava no logo, da erro de disco/boot ou reinicia sozinho.",
        sistema="windows",
        passos=[
            Passo("Desconecte pendrives, HDs externos e hubs. Anote a mensagem/erro exata."),
            Passo("Entre no Windows RE: ligue e segure o botao power ate desligar; repita 3 vezes. Ou use Shift+Reiniciar na tela de login."),
            Passo("No WinRE: Solucao de Problemas > Opcoes Avancadas > Reparo de Inicializacao. Se nao resolver, teste Restaurar Sistema."),
            Passo("Abra o Prompt de Comando do WinRE e rode, um por vez:",
                  "bootrec /fixmbr\nbootrec /fixboot\nbootrec /rebuildbcd\nchkdsk C: /f /r", "bat"),
            Passo("Verifique o sistema de arquivos e os arquivos do Windows:",
                  "sfc /scannow /offbootdir=C:\\ /offwindir=C:\\Windows\ndism /image:C:\\ /cleanup-image /restorehealth", "bat"),
            Passo("UEFI: confira a ordem de boot e se o disco aparece. Se o Windows foi instalado em UEFI, a entrada 'Windows Boot Manager' precisa existir. Para recriar (identifique a particao EFI com diskpart):",
                  "diskpart\nlist volume\nselect volume X   REM particao EFI (FAT32, ~100-500 MB)\nassign letter=S\nexit\nbcdboot C:\\Windows /s S: /f UEFI", "bat"),
            Passo("Se aparecer a tela do BitLocker, informe a chave de 48 digitos (conta Microsoft/AD). Sem ela, o disco nao abre."),
            Passo("Se o disco nao aparece nem na BIOS/UEFI: reencaixe SATA/NVMe, troque cabo/porta e teste o disco em outro PC (SMART)."),
            Passo("Nada resolveu? Inicie um Linux live, copie os arquivos importantes e reinstale o Windows."),
        ],
        notas=[
            "Evite 'bootrec /fixboot' em UEFI se der 'Acesso negado'; use bcdboot.",
            "Nao use ferramentas desconhecidas de 'reparo automatico' de terceiros.",
        ],
    ),
    Playbook(
        id="linux-senha",
        titulo="Linux: perdi a senha (root ou usuario) com acesso fisico",
        quando="Voce tem o equipamento em maos e precisa redefinir a senha local.",
        sistema="linux",
        aviso="Requer acesso fisico e autorizacao. Em disco LUKS, tenha a passphrase antes.",
        passos=[
            Passo("Ligue o computador e, no menu do GRUB, pressione 'e' para editar a entrada de boot."),
            Passo("Na linha que comeca com 'linux', troque 'ro' por 'rw' e acrescente 'init=/bin/bash' no final. Ctrl+X para iniciar."),
            Passo("Remonte o sistema como leitura/escrita (se necessario) e redefina a senha:",
                  "mount -o remount,rw /\npasswd SEU_USUARIO\npasswd root", "bash"),
            Passo("Se der 'Authentication token manipulation error', confira se a raiz esta rw e se /etc/passwd nao esta imutavel (chattr -i /etc/passwd /etc/shadow)."),
            Passo("Se o sistema usa SELinux (Fedora/RHEL), crie o marcador para relabel no proximo boot:",
                  "touch /.autorelabel", "bash"),
            Passo("Saia com seguranca:",
                  "exec /sbin/init", "bash"),
            Passo("Alternativa com pendrive live (funciona tambem com LUKS): monte o sistema e entre em chroot:",
                  "lsblk\nsudo cryptsetup open /dev/nvme0n1p3 cryptroot   # somente se for LUKS\nsudo mount /dev/mapper/cryptroot /mnt            # ou /dev/nvme0n1p2\nsudo mount /dev/nvme0n1p1 /mnt/boot/efi\nfor d in dev dev/pts proc sys run; do sudo mount --bind /$d /mnt/$d; done\nsudo chroot /mnt /bin/bash\npasswd SEU_USUARIO\nexit\nsudo umount -R /mnt", "bash"),
            Passo("Depois de entrar: desbloqueie a conta se preciso e confirme que o usuario esta no grupo sudo.",
                  "sudo passwd -u SEU_USUARIO\nsudo usermod -aG sudo SEU_USUARIO", "bash"),
        ],
        notas=[
            "Se o GRUB pedir senha ou o Secure Boot bloquear a edicao, use um pendrive live da mesma distribuicao.",
            "Em LVM, ative com: sudo vgchange -ay",
            "Em btrfs com subvolumes, monte com -o subvol=@ (e @home) antes do chroot.",
        ],
    ),
    Playbook(
        id="linux-boot",
        titulo="Linux: nao inicia, GRUB rescue ou tela preta",
        quando="Aparece 'grub rescue>', kernel panic, ou o sistema para antes do login.",
        sistema="linux",
        passos=[
            Passo("No 'grub rescue>', descubra a particao que tem /boot/grub:",
                  "ls\nls (hd0,gpt2)/boot/grub", "bash"),
            Passo("Aponte o GRUB para ela e carregue o menu:",
                  "set root=(hd0,gpt2)\nset prefix=(hd0,gpt2)/boot/grub\ninsmod normal\nnormal", "bash"),
            Passo("Se entrar no sistema, reinstale o GRUB:",
                  "sudo update-grub\nsudo grub-install /dev/nvme0n1     # ou /dev/sda", "bash"),
            Passo("Se o boot para por erro de filesystem (ex.: 'UNEXPECTED INCONSISTENCY'), rode o fsck na particao indicada:",
                  "sudo fsck -f /dev/nvme0n1p2", "bash"),
            Passo("Disco cheio pode impedir o login grafico. Pelo console (Ctrl+Alt+F3) ou recovery, libere espaco:",
                  "df -h\nsudo journalctl --vacuum-time=7d\nsudo apt-get clean", "bash"),
            Passo("Se uma atualizacao quebrou o boot, use um pendrive live e repare pelo chroot:",
                  "sudo mount /dev/nvme0n1p2 /mnt\nsudo mount /dev/nvme0n1p1 /mnt/boot/efi\nfor d in dev dev/pts proc sys run; do sudo mount --bind /$d /mnt/$d; done\nsudo chroot /mnt\nupdate-initramfs -u -k all\ngrub-install /dev/nvme0n1\nupdate-grub\nexit", "bash"),
            Passo("Em tela preta com cursor: teste Ctrl+Alt+F2/F3 para console, e nomodeset como parametro temporario do kernel."),
            Passo("Verifique a saude do disco com smartctl (se disponivel) antes de reinstalar qualquer coisa."),
        ],
        notas=[
            "Tenha um pendrive live da mesma distro: e a ferramenta de resgate mais confiavel.",
            "No Debian/Ubuntu, o pacote boot-repair automatiza boa parte do reparo.",
        ],
    ),
    Playbook(
        id="windows-remoto",
        titulo="Windows: perdi o acesso remoto (RDP parou de entrar)",
        quando="Antes voce acessava por RDP e agora nao conecta mais.",
        sistema="windows",
        passos=[
            Passo("Na maquina (ou por outro acesso), confirme servico, porta, firewall e registro:",
                  "Get-Service TermService\nGet-NetTCPConnection -LocalPort 3389 -State Listen\nGet-NetFirewallRule -Name 'RemoteDesktop-UserMode-In-TCP'\n(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections",
                  "powershell"),
            Passo("Se necessario, habilite tudo de uma vez (como admin):",
                  "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 0\nEnable-NetFirewallRule -Name 'RemoteDesktop-UserMode-In-TCP'\nSet-Service TermService -StartupType Manual\nStart-Service TermService",
                  "powershell"),
            Passo("Do outro computador, teste a porta antes de abrir o RDP:",
                  "Test-NetConnection NOME_OU_IP -Port 3389", "powershell"),
            Passo("Confirme que o usuario esta no grupo de usuarios de RDP:",
                  "Add-LocalGroupMember -Group 'Remote Desktop Users' -Member SEU_USUARIO", "powershell"),
            Passo("Se o IP mudou: use nome DNS, IP fixo/reserva DHCP, ou um acesso tipo ZeroTier/Tailscale."),
            Passo("Se o roteador encaminha a porta 3389: confirme o IP interno, o CGNAT do provedor e se a porta mudou."),
            Passo("Se a conta foi bloqueada por tentativas: aguarde a politica de bloqueio ou desbloqueie no AD (conta de dominio)."),
            Passo("Se o RDP cai logo apos conectar: verifique NLA, certificado, atualizacao recente e driver de video."),
        ],
        notas=[
            "Nunca exponha RDP direto na internet sem VPN, senha forte, NLA e limite de tentativas.",
            "Alternativas: Quick Assist (Windows), RustDesk, MeshCentral ou SSH/WinRM.",
        ],
    ),
    Playbook(
        id="linux-remoto",
        titulo="Linux: perdi o acesso remoto (SSH parou de entrar)",
        quando="Antes voce entrava por SSH e agora recebe 'connection refused/timeout'.",
        sistema="linux",
        passos=[
            Passo("Confira se o servico esta ativo e habilitado, e se a porta esta ouvindo:",
                  "systemctl status ssh --no-pager\nss -ltnp | grep ':22 '", "bash"),
            Passo("Habilite/inicie se estiver parado:",
                  "sudo systemctl enable --now ssh", "bash"),
            Passo("Teste a configuracao e recarregue depois de qualquer edicao:",
                  "sudo sshd -t && sudo systemctl reload ssh", "bash"),
            Passo("Verifique firewall (UFW/firewalld) e regras de nuvem (security group):",
                  "sudo ufw status verbose\nsudo firewall-cmd --list-all", "bash"),
            Passo("Se for 'timeout', o pacote nao chega: IP mudou, rota/VPN, provedor ou firewall na frente."),
            Passo("Se for 'permission denied', veja bloqueio por falhas e autenticacao:",
                  "sudo faillock --user SEU_USUARIO\nsudo journalctl -u ssh -n 50 --no-pager\nsudo lastb | head", "bash"),
            Passo("Se a chave deixou de funcionar, confira permissoes do ~/.ssh (700) e authorized_keys (600), e o dono dos arquivos."),
            Passo("Se o disco encheu, o sshd pode nao iniciar:",
                  "df -h\nsudo journalctl --vacuum-time=7d", "bash"),
        ],
        notas=[
            "Mantenha um acesso alternativo (console do provedor, IPMI, Tailscale) para nao ficar sem porta de entrada.",
            "Evite PermitRootLogin yes; use usuario com sudo e chaves.",
        ],
    ),
    Playbook(
        id="bitlocker",
        titulo="BitLocker: pede a chave de recuperacao e eu nao tenho",
        quando="Aparece a tela azul do BitLocker pedindo a chave de 48 digitos.",
        sistema="windows",
        passos=[
            Passo("Nao tente adivinhar. A chave e de 48 digitos e foi gerada na ativacao."),
            Passo("Conta Microsoft: entre em account.microsoft.com/devices/recoverykey em outro aparelho."),
            Passo("Empresa: peca ao administrador do AD/Intune (as chaves podem estar no console)."),
            Passo("Se voce tem a chave: digite os 48 digitos; se o teclado estiver errado, use 'Opcoes avancadas' e o layout correto."),
            Passo("Se o problema comecou apos atualizacao de BIOS/firmware, a chave ainda e a mesma; se voce tem acesso ao Windows, suspenda a protecao antes de atualizar:",
                  "manage-bde -protectors -disable C: -RebootCount 1", "bat"),
            Passo("Sem a chave nao existe recuperacao dos dados por meios legitimos: resta reinstalar (perdendo o conteudo) apos backup inviavel."),
        ],
        notas=[
            "Guarde a chave impressa em local seguro ou no cofre de senhas da empresa.",
            "Ative o backup automatico da chave no AD/Entra ID antes de precisar.",
        ],
    ),
    Playbook(
        id="rede-local",
        titulo="Rede local: ninguem navega / nao pega IP",
        quando="Varios equipamentos sem internet, switch/roteador suspeito ou sem DHCP.",
        passos=[
            Passo("Confirme o alcance: um aparelho ou todos? Wi-Fi e cabo? Se todos, o problema e do roteador/provedor."),
            Passo("No roteador/switch, confira luzes de link, fonte e reinicie (desligue 30 s)."),
            Passo("Se ha switch gerenciado, acesse o console e verifique portas, VLANs, loop e erros."),
            Passo("Teste DHCP: se o PC pega 169.254.x.x, o DHCP nao respondeu. Reinicie o servico DHCP do roteador ou o servidor."),
            Passo("Procure IP duplicado/conflito e loops (dois cabos no mesmo switch)."),
            Passo("Se PoE: confira orcamento de energia e se a porta alimenta o AP."),
            Passo("Se o provedor estiver fora, anote horario, testes e abra chamado com protocolo."),
        ],
        notas=["Tenha um notebook com este kit e um cabo de rede curto na mochila."],
    ),
    Playbook(
        id="prevencao",
        titulo="Prevencao: deixe a maquina recuperavel antes de precisar",
        quando="Checklist para implantar em clientes e no seu proprio equipamento.",
        passos=[
            Passo("Duas contas administradoras ativas, com senhas diferentes e guardadas no cofre."),
            Passo("Perguntas de seguranca configuradas (contas locais) e disco de redefinicao de senha criado."),
            Passo("Chave do BitLocker/LUKS guardada e testada; documente onde esta."),
            Passo("Acesso remoto por VPN/overlay (ZeroTier/Tailscale/WireGuard), nao RDP/SSH exposto."),
            Passo("Backup automatico testado (restauracao tambem!)."),
            Passo("Documentacao: hostname, IP, MAC, modelo, serie, contatos do provedor, senha do BIOS em local seguro."),
            Passo("Cartao de recuperacao impresso e guardado com o equipamento (socorro cartao)."),
        ],
    ),
]


def listar() -> list[Playbook]:
    return PLAYBOOKS


def obter(id_: str) -> Optional[Playbook]:
    for pb in PLAYBOOKS:
        if pb.id == id_:
            return pb
    return None


def para_markdown(pb: Playbook) -> str:
    linhas = [f"# {pb.titulo}", "", f"**Quando usar:** {pb.quando}", ""]
    if pb.aviso:
        linhas += [f"> **Atencao:** {pb.aviso}", ""]
    for i, passo in enumerate(pb.passos, 1):
        linhas.append(f"{i}. {passo.texto}")
        if passo.comando:
            lang = "" if passo.linguagem == "text" else passo.linguagem
            linhas += ["", f"   ```{lang}", *[f"   {l}" for l in passo.comando.splitlines()], "   ```", ""]
    if pb.notas:
        linhas += ["", "## Notas", ""]
        linhas += [f"- {n}" for n in pb.notas]
    return "\n".join(linhas).rstrip() + "\n"


def imprimir(pb: Playbook, ui: Any) -> None:
    ui.titulo(pb.titulo, pb.quando)
    if pb.aviso:
        ui.aviso(pb.aviso)
        ui.espaco()
    for i, passo in enumerate(pb.passos, 1):
        ui.escrever(f"  {ui.paint(str(i) + '.', CYAN + BOLD)} {passo.texto}")
        if passo.comando:
            ui.codigo(passo.comando)
            ui.espaco()
    if pb.notas:
        ui.secao("Notas")
        for nota in pb.notas:
            ui.item(nota)


CYAN = "\033[36m"
BOLD = "\033[1m"


# --------------------------------------------------------------------------- cartao
def _html_escape(texto: str) -> str:
    return html.escape(texto)


def gerar_cartao(destino: Optional[Path] = None, dados: Optional[dict[str, Any]] = None) -> tuple[Path, Path]:
    """Gera cartao de recuperacao em Markdown e HTML (imprimivel)."""
    dados = dados or {}
    pasta = Path(destino) if destino else platform_info.pasta_dados() / "cartao"
    pasta.mkdir(parents=True, exist_ok=True)
    selo = time.strftime("%Y%m%d")
    md_path = pasta / f"cartao-recuperacao-{selo}.md"
    html_path = pasta / f"cartao-recuperacao-{selo}.html"

    campos = [
        ("Empresa / cliente", dados.get("empresa", "")),
        ("Equipamento / modelo", dados.get("modelo", "")),
        ("Hostname", dados.get("hostname", platform_info.hostname())),
        ("IP / MAC", dados.get("rede", "")),
        ("Usuario administrador", dados.get("usuario", platform_info.usuario())),
        ("Cofre de senhas (local)", dados.get("cofre", "")),
        ("Chave BitLocker/LUKS (onde esta)", dados.get("chave", "")),
        ("Provedor / suporte", dados.get("provedor", "")),
        ("Contato de emergencia", dados.get("contato", "")),
    ]

    md = ["# Cartao de recuperacao - SocorroTI", "", f"Gerado em {platform_info.agora()}", "", "## Identificacao", ""]
    for rotulo, valor in campos:
        md.append(f"- **{rotulo}:** {valor or '________________________________'}")
    md += [
        "",
        "## Windows: sem acesso / nao inicia",
        "1. Outra conta admin: `net user SEU_USUARIO *` e `net user SEU_USUARIO /active:yes`.",
        "2. Sem conta admin: Shift+Reiniciar > Solucao de Problemas > Opcoes Avancadas > Reparo de Inicializacao / Restaurar Sistema.",
        "3. Prompt do WinRE: `bootrec /fixmbr`, `bootrec /rebuildbcd`, `chkdsk C: /f /r`.",
        "4. Boot UEFI: `bcdboot C:\\Windows /s S: /f UEFI` (S: = particao EFI).",
        "5. BitLocker: chave de 48 digitos em account.microsoft.com/devices/recoverykey.",
        "",
        "## Linux: senha / boot",
        "1. GRUB > `e` > trocar `ro` por `rw` e adicionar `init=/bin/bash` > Ctrl+X.",
        "2. `mount -o remount,rw /` e `passwd usuario`.",
        "3. GRUB rescue: `ls`, `set root=(hd0,gpt2)`, `set prefix=(hd0,gpt2)/boot/grub`, `insmod normal`, `normal`.",
        "4. Depois: `sudo update-grub && sudo grub-install /dev/nvme0n1`.",
        "5. Pendrive live + chroot para reparos: `mount`, `mount --bind`, `chroot`, `update-initramfs -u -k all`.",
        "",
        "## Acesso remoto",
        "- Windows (admin): habilitar RDP, firewall RemoteDesktop-UserMode-In-TCP, TermService.",
        "- Linux (admin): `sudo systemctl enable --now ssh` e liberar porta 22 no firewall.",
        "- Preferir VPN/ZeroTier/Tailscale em vez de porta aberta na internet.",
        "",
        "## Antes de formatar",
        "- [ ] Backupe os dados com pendrive live.",
        "- [ ] Confirme a chave de criptografia.",
        "- [ ] Registre o problema e os testes feitos (socorro diagnostico).",
        "",
        "> Uso restrito a tecnicos autorizados. Nao contorne autenticacao de terceiros.",
    ]
    md_path.write_text("\n".join(md) + "\n", encoding="utf-8")

    linhas_campos = "".join(
        f"<tr><th>{_html_escape(rotulo)}</th><td>{_html_escape(str(valor)) or '&nbsp;'}</td></tr>"
        for rotulo, valor in campos
    )
    html_doc = f"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8">
<title>Cartao de recuperacao - SocorroTI</title>
<style>
  @page {{ size: A4; margin: 14mm; }}
  body {{ font-family: Segoe UI, Arial, sans-serif; color:#111; font-size: 12px; }}
  h1 {{ font-size: 20px; margin: 0 0 2px; }}
  .sub {{ color:#555; margin-bottom: 12px; }}
  h2 {{ font-size: 14px; background:#111; color:#fff; padding:4px 8px; margin: 14px 0 6px; }}
  table.id {{ width:100%; border-collapse: collapse; margin-bottom: 6px; }}
  table.id th {{ text-align:left; width: 32%; padding:4px 6px; background:#f1f1f1; border:1px solid #ccc; }}
  table.id td {{ padding:4px 6px; border:1px solid #ccc; height: 18px; }}
  ol {{ margin: 4px 0 0 18px; padding: 0; }}
  li {{ margin: 3px 0; }}
  code {{ font-family: Consolas, monospace; background:#f3f3f3; padding:0 3px; }}
  .foot {{ margin-top: 16px; font-size: 10px; color:#666; border-top:1px solid #ccc; padding-top:6px; }}
  ul.check {{ list-style:none; padding-left: 0; }}
  @media print {{ .no-print {{ display:none; }} }}
</style></head><body>
<h1>Cartao de recuperacao - SocorroTI</h1>
<div class="sub">Gerado em {_html_escape(platform_info.agora())} &middot; mantenha impresso com o equipamento</div>
<table class="id">{linhas_campos}</table>
<h2>Windows: sem acesso / nao inicia</h2>
<ol>
<li>Outra conta admin: <code>net user SEU_USUARIO *</code> e <code>net user SEU_USUARIO /active:yes</code>.</li>
<li>Sem conta admin: Shift+Reiniciar &gt; Solucao de Problemas &gt; Opcoes Avancadas &gt; Reparo de Inicializacao / Restaurar Sistema.</li>
<li>Prompt do WinRE: <code>bootrec /fixmbr</code>, <code>bootrec /rebuildbcd</code>, <code>chkdsk C: /f /r</code>.</li>
<li>Boot UEFI: <code>bcdboot C:\\Windows /s S: /f UEFI</code> (S: = particao EFI).</li>
<li>BitLocker: chave de 48 digitos em account.microsoft.com/devices/recoverykey.</li>
</ol>
<h2>Linux: senha / boot</h2>
<ol>
<li>GRUB &gt; <code>e</code> &gt; trocar <code>ro</code> por <code>rw</code> e adicionar <code>init=/bin/bash</code> &gt; Ctrl+X.</li>
<li><code>mount -o remount,rw /</code> e <code>passwd usuario</code>.</li>
<li>GRUB rescue: <code>ls</code>, <code>set root=(hd0,gpt2)</code>, <code>set prefix=(hd0,gpt2)/boot/grub</code>, <code>insmod normal</code>, <code>normal</code>.</li>
<li>Depois: <code>sudo update-grub &amp;&amp; sudo grub-install /dev/nvme0n1</code>.</li>
<li>Pendrive live + chroot: <code>mount</code>, <code>mount --bind</code>, <code>chroot</code>, <code>update-initramfs -u -k all</code>.</li>
</ol>
<h2>Acesso remoto</h2>
<ul>
<li>Windows (admin): habilitar RDP, firewall <code>RemoteDesktop-UserMode-In-TCP</code>, <code>TermService</code>.</li>
<li>Linux (admin): <code>sudo systemctl enable --now ssh</code> e liberar porta 22 no firewall.</li>
<li>Preferir VPN/ZeroTier/Tailscale em vez de porta aberta na internet.</li>
</ul>
<h2>Antes de formatar</h2>
<ul class="check">
<li>&#9744; Backupe os dados com pendrive live.</li>
<li>&#9744; Confirme a chave de criptografia.</li>
<li>&#9744; Registre o problema e os testes feitos (<code>socorro diagnostico</code>).</li>
</ul>
<div class="foot">Uso restrito a tecnicos autorizados. Nao contorne autenticacao de terceiros.
SocorroTI v{__version__}.</div>
</body></html>
"""
    html_path.write_text(html_doc, encoding="utf-8")
    return md_path, html_path
