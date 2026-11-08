"""Diagnostico do computador: disco, memoria, CPU, saude e limpeza."""

from __future__ import annotations

import os
import platform
import re
import shutil
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from . import platform_info
from .model import Diagnosis, Finding, ordenar_findings
from .runner import IS_WINDOWS, Runner

AREA = "sistema"


@dataclass
class Disco:
    nome: str
    ponto: str
    total: int
    livre: int
    fs: str = ""

    @property
    def usado_pct(self) -> float:
        return 0.0 if self.total <= 0 else 100.0 * (self.total - self.livre) / self.total


@dataclass
class Processo:
    nome: str
    pid: int = 0
    cpu: float = 0.0
    mem_mb: float = 0.0


@dataclass
class SystemInfo:
    sistema: str = ""
    kernel: str = ""
    host: str = ""
    uptime_s: float = 0.0
    boot: str = ""
    cpu: str = ""
    cores: int = 0
    carga: str = ""
    ram_total: int = 0
    ram_livre: int = 0
    swap_total: int = 0
    swap_livre: int = 0
    discos: list[Disco] = field(default_factory=list)
    processos: list[Processo] = field(default_factory=list)
    saude_discos: list[dict[str, Any]] = field(default_factory=list)
    reinicio_pendente: bool = False
    temperatura: Optional[float] = None
    extras: dict[str, Any] = field(default_factory=dict)

    @property
    def ram_usada_pct(self) -> float:
        return 0.0 if self.ram_total <= 0 else 100.0 * (self.ram_total - self.ram_livre) / self.ram_total


def bytes_legivel(valor: float) -> str:
    for unidade in ("B", "KB", "MB", "GB", "TB"):
        if abs(valor) < 1024 or unidade == "TB":
            if unidade == "B":
                return f"{valor:.0f} B"
            return f"{valor:.1f} {unidade}"
        valor /= 1024
    return f"{valor:.1f} TB"


def _uptime_legivel(segundos: float) -> str:
    segundos = max(0, int(segundos))
    dias, resto = divmod(segundos, 86400)
    horas, resto = divmod(resto, 3600)
    minutos = resto // 60
    partes = []
    if dias:
        partes.append(f"{dias}d")
    if horas or dias:
        partes.append(f"{horas}h")
    partes.append(f"{minutos}min")
    return " ".join(partes)


def _coletar_windows(runner: Runner, info: SystemInfo) -> None:
    script = r"""
$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$discos = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
  [pscustomobject]@{nome=[string]$_.DeviceID; volume=[string]$_.VolumeName;
    total=[double]$_.Size; livre=[double]$_.FreeSpace; fs=[string]$_.FileSystem}
}
$procs = Get-Process | Sort-Object CPU -Descending | Select-Object -First 8 | ForEach-Object {
  [pscustomobject]@{nome=[string]$_.ProcessName; pid=[int]$_.Id;
    cpu=[double]($_.CPU); mem=[double]($_.WorkingSet64)}
}
$saude = Get-PhysicalDisk -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{nome=[string]$_.FriendlyName; saude=[string]$_.HealthStatus;
    operacao=[string]$_.OperationalStatus; tipo=[string]$_.MediaType; tamanho=[double]$_.Size}
}
$pend = $false
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pend = $true }
if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations') { $pend = $true }
if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing' -Name RebootPending -ErrorAction SilentlyContinue).RebootPending -eq 1) { $pend = $true }
[pscustomobject]@{
  boot=[string]$os.LastBootUpTime; ram_total=[double]$os.TotalVisibleMemorySize;
  boot_epoch=if($os.LastBootUpTime){[long]([DateTimeOffset]$os.LastBootUpTime).ToUnixTimeSeconds()}else{0};
  ram_livre=[double]$os.FreePhysicalMemory; cpu=[string]$cpu.Name; cores=[int]$cpu.NumberOfCores;
  carga=[double]$cpu.LoadPercentage; discos=@($discos); procs=@($procs); saude=@($saude); pendente=$pend
}
"""
    dados = runner.ps_json(script, timeout=60)
    d: dict[str, Any] = dados[0] if dados and isinstance(dados[0], dict) else {}
    info.sistema = platform_info.nome_sistema()
    info.kernel = platform.version()
    info.host = platform_info.hostname()
    info.cpu = str(d.get("cpu") or platform.processor() or "")
    info.cores = int(d.get("cores") or os.cpu_count() or 1)
    info.ram_total = int(float(d.get("ram_total") or 0)) * 1024
    info.ram_livre = int(float(d.get("ram_livre") or 0)) * 1024
    info.carga = f"{float(d.get('carga') or 0):.0f}%"
    info.reinicio_pendente = bool(d.get("pendente"))
    boot_epoch = int(d.get("boot_epoch") or 0)
    if boot_epoch > 0:
        info.uptime_s = max(0.0, time.time() - boot_epoch)
        info.boot = time.strftime("%d/%m/%Y %H:%M", time.localtime(boot_epoch))
    for item in d.get("discos") or []:
        total = int(float(item.get("total") or 0))
        livre = int(float(item.get("livre") or 0))
        nome = str(item.get("nome") or "?")
        info.discos.append(Disco(nome=nome, ponto=nome + "\\", total=total, livre=livre,
                                  fs=str(item.get("fs") or "")))
        if item.get("volume"):
            info.discos[-1].nome = f"{nome} ({item['volume']})"
    for p in d.get("procs") or []:
        info.processos.append(Processo(nome=str(p.get("nome") or "?"), pid=int(p.get("pid") or 0),
                                       cpu=float(p.get("cpu") or 0),
                                       mem_mb=float(p.get("mem") or 0) / 1024 / 1024))
    for s in d.get("saude") or []:
        info.saude_discos.append({
            "nome": str(s.get("nome") or "?"),
            "saude": str(s.get("saude") or "?"),
            "operacao": str(s.get("operacao") or "?"),
            "tipo": str(s.get("tipo") or "?"),
            "tamanho": int(float(s.get("tamanho") or 0)),
        })


def _coletar_linux(runner: Runner, info: SystemInfo) -> None:
    info.sistema = platform_info.nome_sistema()
    info.kernel = platform.release()
    info.host = platform_info.hostname()
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as fh:
            info.uptime_s = float(fh.read().split()[0])
        info.boot = time.strftime("%d/%m/%Y %H:%M", time.localtime(time.time() - info.uptime_s))
    except (OSError, ValueError, IndexError):
        pass

    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8", errors="replace") as fh:
            for linha in fh:
                if linha.lower().startswith("model name"):
                    info.cpu = linha.split(":", 1)[1].strip()
                    break
    except OSError:
        info.cpu = platform.processor()
    info.cores = os.cpu_count() or 1
    try:
        info.carga = open("/proc/loadavg", "r", encoding="utf-8").read().split()[0]
    except OSError:
        pass

    try:
        mem: dict[str, int] = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for linha in fh:
                parts = linha.split()
                if len(parts) >= 2:
                    mem[parts[0].rstrip(":")] = int(parts[1]) * 1024
        info.ram_total = mem.get("MemTotal", 0)
        info.ram_livre = mem.get("MemAvailable", mem.get("MemFree", 0))
        info.swap_total = mem.get("SwapTotal", 0)
        info.swap_livre = mem.get("SwapFree", 0)
    except OSError:
        pass

    res = runner.run(["df", "-P", "-B1"], timeout=20)
    for linha in res.out.splitlines()[1:]:
        partes = linha.split()
        if len(partes) < 6:
            continue
        fs_nome, total, usado, livre, pct, ponto = partes[0], partes[1], partes[2], partes[3], partes[4], " ".join(partes[5:])
        if not total.isdigit():
            continue
        if fs_nome.startswith(("tmpfs", "devtmpfs", "squashfs", "overlay", "udev", "efivarfs")):
            continue
        info.discos.append(Disco(nome=fs_nome, ponto=ponto, total=int(total),
                                  livre=int(livre), fs=""))

    res = runner.run(["ps", "-eo", "pid,comm,%cpu,%mem", "--sort=-%cpu"], timeout=15)
    for linha in res.out.splitlines()[1:9]:
        partes = linha.split(None, 3)
        if len(partes) < 4 or not partes[0].isdigit():
            continue
        try:
            info.processos.append(Processo(nome=partes[1], pid=int(partes[0]),
                                            cpu=float(partes[2].replace(",", ".")),
                                            mem_mb=float(partes[3].replace(",", ".")) / 100 * max(1, info.ram_total) / 1024 / 1024))
        except ValueError:
            continue

    # Temperatura (se exposta pelo kernel).
    temps: list[float] = []
    base = "/sys/class/thermal"
    try:
        for zona in os.listdir(base):
            if not zona.startswith("thermal_zone"):
                continue
            try:
                with open(os.path.join(base, zona, "temp"), "r") as fh:
                    valor = float(fh.read().strip())
                temps.append(valor / 1000 if valor > 1000 else valor)
            except (OSError, ValueError):
                continue
    except OSError:
        pass
    if temps:
        info.temperatura = max(temps)

    if shutil.which("journalctl"):
        res = runner.run(["journalctl", "--disk-usage"], timeout=10)
        if res.ok:
            info.extras["journal"] = res.saida


def coletar(runner: Runner) -> SystemInfo:
    info = SystemInfo()
    if IS_WINDOWS:
        _coletar_windows(runner, info)
    else:
        _coletar_linux(runner, info)
    return info


def _disco_sistema(info: SystemInfo) -> Optional[Disco]:
    for d in info.discos:
        if d.ponto in ("C:\\", "/"):
            return d
    return info.discos[0] if info.discos else None


def diagnosticar(runner: Runner) -> Diagnosis:
    info = coletar(runner)
    diag = Diagnosis(area=AREA, title="Diagnostico do computador")
    achados: list[Finding] = []

    def add(id_: str, sev: str, titulo: str, detalhe: str = "", causa: str = "") -> None:
        achados.append(Finding(id=id_, area=AREA, severity=sev, title=titulo, detail=detalhe, cause=causa))

    for disco in info.discos:
        pct = disco.usado_pct
        detalhe = f"{disco.nome} em {disco.ponto}: {bytes_legivel(disco.livre)} livres de {bytes_legivel(disco.total)} ({pct:.0f}% usado)"
        if pct >= 97:
            add("disco_cheio", "critico", f"Disco praticamente cheio ({pct:.0f}%)", detalhe,
                "Sem espaco o Windows/Linux falha em atualizacoes, logs e ate no login.")
        elif pct >= 90:
            add("disco_cheio", "erro", f"Disco com pouco espaco ({pct:.0f}% usado)", detalhe,
                "Reserve pelo menos 10-15% livres para o sistema respirar.")
        elif pct >= 80:
            add("disco_quase", "aviso", f"Disco enchendo ({pct:.0f}% usado)", detalhe,
                "Planeje limpeza ou aumento de espaco.")

    if info.ram_total and info.ram_usada_pct >= 92:
        add("ram_cheia", "aviso", f"Memoria RAM quase esgotada ({info.ram_usada_pct:.0f}%)",
            f"{bytes_legivel(info.ram_livre)} livres de {bytes_legivel(info.ram_total)}",
            "Muitos programas abertos ou vazamento de memoria; o sistema fica lento e pode travar.")

    if info.uptime_s > 30 * 86400:
        add("uptime_longo", "info", f"Computador ligado ha {_uptime_legivel(info.uptime_s)}",
            f"Ultimo boot: {info.boot}",
            "Reiniciar aplica atualizacoes e limpa estado acumulado.")

    if info.reinicio_pendente:
        add("reinicio_pendente", "aviso", "Reinicio pendente",
            "Ha atualizacoes/instalacoes aguardando reinicializacao.",
            "Reinicie para evitar falhas de instalacao e lentidao.")

    for s in info.saude_discos:
        saude = (s.get("saude") or "").lower()
        if saude and saude not in ("healthy", "saudavel", "ok", "unknown"):
            add("disco_saude", "erro", f"Disco com problema de saude: {s.get('nome')}",
                f"Status: {s.get('saude')} | operacao: {s.get('operacao')}",
                "Risco de perda de dados. Faca backup e troque o disco.")

    if info.temperatura is not None and info.temperatura >= 85:
        add("temperatura", "aviso", f"Temperatura alta ({info.temperatura:.0f} C)",
            "CPU/acelerador acima do ideal.", "Limpeza de cooler/pasta termica ou ambiente quente.")

    try:
        carga = float(str(info.carga).replace("%", "").replace(",", "."))
        if "%" not in str(info.carga) and carga > info.cores * 2:
            add("carga_alta", "aviso", f"Carga alta ({info.carga})",
                f"{info.cores} nucleos disponiveis.",
                "Processo consumindo CPU ou maquina subdimensionada.")
    except ValueError:
        pass

    if not any(f.severity in ("aviso", "erro", "critico") for f in achados):
        add("ok", "ok", "Hardware e sistema sem alertas", "Disco, memoria e temperatura dentro do esperado.")

    diag.findings = ordenar_findings(achados)
    problema = next((f for f in diag.findings if f.severity in ("critico", "erro", "aviso")), None)
    if problema:
        diag.summary = f"{problema.title}. {problema.cause}"
    else:
        diag.summary = "Computador sem alertas de disco, memoria ou temperatura."
    diag.data = {
        "Sistema": info.sistema,
        "Kernel": info.kernel,
        "Host": info.host,
        "Boot": info.boot,
        "Uptime": _uptime_legivel(info.uptime_s),
        "CPU": f"{info.cpu} ({info.cores} nucleos) | carga {info.carga}",
        "RAM": f"{bytes_legivel(info.ram_livre)} livres de {bytes_legivel(info.ram_total)} ({info.ram_usada_pct:.0f}% usado)",
        "Swap": f"{bytes_legivel(info.swap_livre)} livres de {bytes_legivel(info.swap_total)}" if info.swap_total else "",
        "Discos": [
            {"disco": d.nome, "ponto": d.ponto, "total": bytes_legivel(d.total),
             "livre": bytes_legivel(d.livre), "usado_pct": round(d.usado_pct, 1)}
            for d in info.discos
        ],
        "Saude dos discos": info.saude_discos,
        "Temperatura": info.temperatura,
        "Processos (top CPU)": [
            {"nome": p.nome, "pid": p.pid, "cpu": p.cpu, "mem_mb": round(p.mem_mb, 1)}
            for p in info.processos
        ],
        "Reinicio pendente": info.reinicio_pendente,
    }
    return diag


def imprimir_diagnostico(diag: Diagnosis, ui: Any) -> None:
    d = diag.data
    ui.secao("Computador")
    ui.kv("Sistema", d.get("Sistema", ""))
    ui.kv("Host", d.get("Host", ""))
    ui.kv("Ultimo boot", f"{d.get('Boot', '')} (ligado ha {d.get('Uptime', '?')})")
    ui.kv("CPU", d.get("CPU", ""))
    ui.kv("Memoria", d.get("RAM", ""))
    if d.get("Swap"):
        ui.kv("Swap", d["Swap"])
    if d.get("Temperatura") is not None:
        ui.kv("Temperatura", f"{d['Temperatura']:.0f} C")

    ui.secao("Discos")
    linhas = []
    for disco in d.get("Discos", []):
        linhas.append([disco.get("disco", ""), disco.get("ponto", ""), disco.get("total", ""),
                       disco.get("livre", ""), f"{int(round(disco.get('usado_pct', 0) + 0.0001))}%"])
    if linhas:
        ui.tabela(["Disco", "Ponto", "Total", "Livre", "Uso"], linhas)
    for s in d.get("Saude dos discos", []) or []:
        ui.item(f"{s.get('nome')}: {s.get('saude')}", f"{s.get('tipo')} | {s.get('operacao')}")

    procs = d.get("Processos (top CPU)") or []
    if procs:
        ui.secao("Processos que mais consomem CPU")
        ui.tabela(["Processo", "PID", "CPU (s)", "RAM"],
                  [[p.get("nome"), p.get("pid"), f"{p.get('cpu', 0):.1f}", bytes_legivel((p.get('mem_mb') or 0) * 1024 * 1024)] for p in procs])

    ui.secao("Diagnostico")
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


# --------------------------------------------------------------------------- limpeza
def analisar_limpeza(runner: Runner) -> list[dict[str, Any]]:
    itens: list[dict[str, Any]] = []
    if IS_WINDOWS:
        temp = os.environ.get("TEMP") or os.environ.get("TMP") or ""
        alvos = [
            ("Temp do usuario", temp),
            ("Temp do Windows", r"C:\Windows\Temp"),
            ("Cache do Windows Update", r"C:\Windows\SoftwareDistribution\Download"),
            ("Prefetch", r"C:\Windows\Prefetch"),
        ]
        for rotulo, caminho in alvos:
            if not caminho or not os.path.isdir(caminho):
                continue
            dados = runner.ps_json(
                f"$itens = Get-ChildItem -LiteralPath '{caminho}' -Recurse -Force -ErrorAction SilentlyContinue;"
                f"[pscustomobject]@{{total=[double](($itens | Measure-Object Length -Sum).Sum); arquivos=[int]$itens.Count}}",
                timeout=60,
            )
            if dados:
                total = int(float(dados[0].get("total") or 0))
                itens.append({"rotulo": rotulo, "caminho": caminho, "bytes": total,
                              "arquivos": int(dados[0].get("arquivos") or 0)})
    else:
        alvos = [
            ("Temp do sistema", "/tmp"),
            ("Cache do usuario", os.path.expanduser("~/.cache")),
            ("Cache do apt", "/var/cache/apt/archives"),
            ("Logs do sistema", "/var/log"),
        ]
        for rotulo, caminho in alvos:
            if not os.path.isdir(caminho):
                continue
            res = runner.run(["du", "-sb", caminho], timeout=60)
            partes = res.out.split()
            if partes and partes[0].isdigit():
                itens.append({"rotulo": rotulo, "caminho": caminho, "bytes": int(partes[0]), "arquivos": 0})
        if shutil.which("journalctl"):
            res = runner.run(["journalctl", "--disk-usage"], timeout=15)
            m = re.search(r"take up\s+([\d.,]+)\s*([KMG]?B)", res.out, re.I)
            if m:
                valor = float(m.group(1).replace(",", "."))
                mult = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3}.get(m.group(2).upper(), 1)
                itens.append({"rotulo": "Journal (logs systemd)", "caminho": "journalctl", "bytes": int(valor * mult), "arquivos": 0})
    return itens


def recomendar_limpeza(itens: list[dict[str, Any]]) -> list[str]:
    sugestoes: list[str] = []
    if IS_WINDOWS:
        sugestoes = [
            "Abrir a Limpeza de Disco:  cleanmgr /d C:",
            "Limpar cache do Windows Update (servico wuauserv parado):  net stop wuauserv  e apague C:\\Windows\\SoftwareDistribution\\Download\\*  e  net start wuauserv",
            "Limpar componentes antigos do Windows:  Dism /Online /Cleanup-Image /StartComponentCleanup /ResetBase",
            "Esvaziar a Lixeira e remover instaladores antigos em Downloads.",
            "Ativar Sensor de Armazenamento (Configuracoes > Sistema > Armazenamento).",
        ]
    else:
        sugestoes = [
            "Limpar cache do apt (Debian/Ubuntu):  sudo apt-get clean && sudo apt-get autoremove --purge",
            "Reduzir journal:  sudo journalctl --vacuum-time=7d",
            "Limpar cache do usuario:  rm -rf ~/.cache/*  (feche os programas antes)",
            "Limpar /tmp antigo:  sudo find /tmp -type f -atime +7 -delete",
            "Remover kernels antigos:  sudo apt-get autoremove --purge",
        ]
    sugestoes.append("Nunca apague pastas do sistema manualmente sem conferir o conteudo.")
    return sugestoes


def imprimir_limpeza(itens: list[dict[str, Any]], ui: Any) -> None:
    total = sum(i["bytes"] for i in itens)
    ui.secao("Espaco recuperavel (estimativa)")
    linhas = [[i["rotulo"], i["caminho"], bytes_legivel(i["bytes"]),
               (str(i["arquivos"]) if i.get("arquivos") else "-")] for i in itens]
    ui.tabela(["Local", "Caminho", "Tamanho", "Arquivos"], linhas)
    ui.espaco()
    ui.info(f"Total mapeado: {bytes_legivel(total)}")
    ui.secao("Comandos recomendados")
    for s in recomendar_limpeza(itens):
        ui.item(s)
