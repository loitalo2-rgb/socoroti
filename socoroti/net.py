"""Diagnostico e correcao de rede para Windows e Linux.

Fluxo:
  coletar_info()      -> interfaces, rotas, DNS, Wi-Fi, proxy
  executar_testes()   -> ping, DNS, TCP, HTTP (em paralelo)
  diagnosticar()      -> achados + plano de acao
  executar_acoes()    -> aplica correcoes com confirmacao
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import statistics
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from . import platform_info
from .model import Action, Diagnosis, Finding, Step, deduplicar_acoes, ordenar_findings
from .runner import IS_WINDOWS, Runner

AREA = "rede"

VIRTUAL_KEYWORDS = (
    "virtual",
    "tap",
    "tun",
    "vpn",
    "zerotier",
    "wireguard",
    "tailscale",
    "openvpn",
    "hyper-v",
    "vmware",
    "virtualbox",
    "loopback",
    "wintun",
    "npcap",
    "bluetooth",
    "docker",
    "veth",
    "virbr",
    "bridge",
)
WIFI_KEYWORDS = ("wi-fi", "wifi", "wireless", "wlan", "802.11", "sem fio")


# --------------------------------------------------------------------------- dados
@dataclass
class Iface:
    nome: str
    desc: str = ""
    up: bool = False
    status: str = ""
    velocidade: str = ""
    ips: list[str] = field(default_factory=list)
    gateway: Optional[str] = None
    dns: list[str] = field(default_factory=list)
    wifi: bool = False
    virtual: bool = False
    dhcp: Optional[bool] = None
    indice: Optional[int] = None


@dataclass
class Route:
    iface: str
    gateway: str
    metric: int = 0
    ifmetric: int = 0

    @property
    def peso(self) -> int:
        return self.metric + self.ifmetric


@dataclass
class WifiInfo:
    ssid: str = ""
    sinal: Optional[int] = None
    estado: str = ""
    radio: str = ""
    taxa: str = ""
    conectado: bool = False


@dataclass
class NetInfo:
    interfaces: list[Iface] = field(default_factory=list)
    rotas: list[Route] = field(default_factory=list)
    dns: list[str] = field(default_factory=list)
    wifi: Optional[WifiInfo] = None
    proxy: dict[str, Any] = field(default_factory=dict)
    hostname: str = ""
    sistema: str = ""

    def por_nome(self, nome: str) -> Optional[Iface]:
        for i in self.interfaces:
            if i.nome.lower() == nome.lower():
                return i
        return None

    def ativa(self) -> tuple[Optional[Iface], Optional[Route]]:
        rotas = sorted(self.rotas, key=lambda r: r.peso)
        for rota in rotas:
            iface = self.por_nome(rota.iface)
            if iface and iface.up:
                return iface, rota
        for iface in self.interfaces:
            if iface.up and iface.ips:
                return iface, None
        for iface in self.interfaces:
            if iface.up:
                return iface, None
        return None, None


@dataclass
class PingResult:
    alvo: str
    ok: bool = False
    enviados: int = 0
    recebidos: int = 0
    perda: float = 100.0
    rtt_min: Optional[float] = None
    rtt_avg: Optional[float] = None
    rtt_max: Optional[float] = None
    erro: str = ""

    def resumo(self) -> str:
        if not self.ok and self.recebidos == 0:
            return "sem resposta"
        partes = [f"{self.recebidos}/{self.enviados} respostas"]
        if self.perda:
            partes.append(f"perda {self.perda:.0f}%")
        if self.rtt_avg is not None:
            partes.append(f"media {self.rtt_avg:.0f} ms")
        return ", ".join(partes)


@dataclass
class DnsResult:
    host: str
    ok: bool = False
    ips: list[str] = field(default_factory=list)
    ms: float = 0.0
    erro: str = ""


@dataclass
class TcpResult:
    host: str
    porta: int
    ok: bool = False
    ms: float = 0.0
    erro: str = ""


@dataclass
class NetTests:
    pings: dict[str, PingResult] = field(default_factory=dict)
    dns: list[DnsResult] = field(default_factory=list)
    tcp: list[TcpResult] = field(default_factory=list)
    http: dict[str, Any] = field(default_factory=dict)
    mtu: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- parsers
_RE_TTL = re.compile(r"\bttl[=:]\s*\d+", re.I)
_RE_TEMPO = re.compile(
    r"(?:tempo|tiempo|temps|time|zeit|tijd)\s*[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", re.I
)
_RE_QUALQUER_MS = re.compile(r"(\d+(?:[.,]\d+)?)\s*ms", re.I)


def parse_ping(texto: str, enviados: int) -> PingResult:
    """Interpreta a saida do ping em pt/en/es/fr sem depender do idioma."""
    tempos: list[float] = []
    linhas_resposta = [l for l in texto.splitlines() if _RE_TTL.search(l)]
    if not linhas_resposta:
        linhas_resposta = [l for l in texto.splitlines() if _RE_TEMPO.search(l)]
    for linha in linhas_resposta:
        m = _RE_TEMPO.search(linha) or _RE_QUALQUER_MS.search(linha)
        if m:
            try:
                tempos.append(float(m.group(1).replace(",", ".")))
            except ValueError:
                pass

    recebidos = len(tempos) if tempos else len(linhas_resposta)
    perda = 100.0 * (enviados - recebidos) / enviados if enviados else 100.0
    perda = max(0.0, min(100.0, perda))

    # Se nao conseguimos contar respostas, tenta a porcentagem explicita.
    if recebidos == 0:
        m = re.search(r"(\d{1,3}(?:[.,]\d+)?)\s*%", texto)
        if m:
            try:
                perda = float(m.group(1).replace(",", "."))
            except ValueError:
                pass
        if perda < 100 and "100%" not in texto:
            recebidos = max(0, round(enviados * (1 - perda / 100)))
        else:
            perda = 100.0

    res = PingResult(alvo="", enviados=enviados, recebidos=recebidos, perda=perda)
    if tempos:
        res.rtt_min = min(tempos)
        res.rtt_max = max(tempos)
        res.rtt_avg = statistics.fmean(tempos)
        res.ok = recebidos > 0
    elif recebidos > 0:
        res.ok = True
    if not res.ok:
        baixo = texto.lower()
        if "inacess" in baixo or "unreachable" in baixo:
            res.erro = "destino inacessivel"
        elif "desconhecido" in baixo or "unknown" in baixo or "could not find" in baixo:
            res.erro = "nome nao resolvido"
        elif "geral" in baixo or "general failure" in baixo:
            res.erro = "falha geral (adaptador sem rota)"
    return res


def _com_timeout(fn: Callable[[], Any], segundos: float) -> Any:
    caixa: dict[str, Any] = {}

    def alvo() -> None:
        try:
            caixa["valor"] = fn()
        except BaseException as exc:  # noqa: BLE001 - repassado adiante
            caixa["erro"] = exc

    t = threading.Thread(target=alvo, daemon=True)
    t.start()
    t.join(segundos)
    if t.is_alive():
        raise TimeoutError(f"tempo esgotado ({segundos:.0f}s)")
    if "erro" in caixa:
        raise caixa["erro"]
    return caixa.get("valor")


def ping(runner: Runner, alvo: str, contagem: int = 4, timeout_ms: int = 1000) -> PingResult:
    if IS_WINDOWS:
        args = ["ping", "-n", str(contagem), "-w", str(timeout_ms), alvo]
    else:
        args = ["ping", "-c", str(contagem), "-W", str(max(1, timeout_ms // 1000)), "-i", "0.25", alvo]
    res = runner.run(args, timeout=max(10, contagem * 2 + 8))
    p = parse_ping(res.out + "\n" + res.err, contagem)
    p.alvo = alvo
    if res.code == 127:
        p.erro = "comando ping nao encontrado"
    elif res.timed_out:
        p.erro = "ping travou"
    return p


def testar_dns(host: str, timeout: float = 5.0) -> DnsResult:
    inicio = time.perf_counter()
    try:
        infos = _com_timeout(lambda: socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP), timeout)
        ips = sorted({i[4][0] for i in infos})
        return DnsResult(host=host, ok=True, ips=ips[:4], ms=(time.perf_counter() - inicio) * 1000)
    except Exception as exc:
        return DnsResult(host=host, ok=False, ms=(time.perf_counter() - inicio) * 1000, erro=str(exc))


def testar_tcp(host: str, porta: int, timeout: float = 4.0) -> TcpResult:
    inicio = time.perf_counter()
    try:
        sock = socket.create_connection((host, porta), timeout=timeout)
        sock.close()
        return TcpResult(host=host, porta=porta, ok=True, ms=(time.perf_counter() - inicio) * 1000)
    except Exception as exc:
        return TcpResult(host=host, porta=porta, ok=False, ms=(time.perf_counter() - inicio) * 1000,
                         erro=str(exc))


def testar_http(timeout: float = 7.0) -> dict[str, Any]:
    """Testa conectividade HTTP real e detecta portal captivo."""
    endpoints = [
        ("http://connectivitycheck.gstatic.com/generate_204", 204),
        ("http://detectportal.firefox.com/success.txt", 200),
    ]
    tentativas: list[dict[str, Any]] = []
    for url, esperado in endpoints:
        inicio = time.perf_counter()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SocorroTI/1.0"})
            # Sem proxy: queremos saber se a conexao direta funciona.
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(req, timeout=timeout) as resp:
                status = resp.status
                final = resp.geturl()
                corpo = resp.read(512)
            ok = status == esperado and (esperado != 200 or b"success" in corpo.lower())
            item = {
                "url": url,
                "status": status,
                "final": final,
                "ok": ok,
                "portal": (not ok) and (status in (200, 302, 303, 307, 511) or final.rstrip("/") != url.rstrip("/")),
                "ms": (time.perf_counter() - inicio) * 1000,
            }
        except urllib.error.HTTPError as exc:
            item = {
                "url": url,
                "status": exc.code,
                "final": exc.geturl(),
                "ok": False,
                "portal": exc.code in (200, 302, 303, 307, 511) or exc.geturl().rstrip("/") != url.rstrip("/"),
                "ms": (time.perf_counter() - inicio) * 1000,
                "erro": f"HTTP {exc.code}",
            }
        except Exception as exc:  # noqa: BLE001
            item = {
                "url": url,
                "status": 0,
                "ok": False,
                "portal": False,
                "ms": (time.perf_counter() - inicio) * 1000,
                "erro": str(exc),
            }
        tentativas.append(item)
        if item.get("ok"):
            return {"ok": True, "portal": False, "tentativas": tentativas, "ms": item["ms"]}
    portal = any(t.get("portal") for t in tentativas)
    return {
        "ok": False,
        "portal": portal,
        "tentativas": tentativas,
        "erro": tentativas[-1].get("erro", "sem resposta HTTP") if tentativas else "sem resposta",
    }


def testar_mtu(runner: Runner, alvo: str, tamanhos: tuple[int, ...] = (1472, 1400, 1240)) -> dict[str, Any]:
    resultados: dict[str, Any] = {}
    for tamanho in tamanhos:
        if IS_WINDOWS:
            args = ["ping", "-f", "-l", str(tamanho), "-n", "2", "-w", "1500", alvo]
        else:
            args = ["ping", "-M", "do", "-s", str(tamanho), "-c", "2", "-W", "2", alvo]
        res = runner.run(args, timeout=15)
        p = parse_ping(res.out + "\n" + res.err, 2)
        resultados[str(tamanho)] = p.ok
        if not p.ok:
            break
    menor_ok = None
    for tamanho in sorted((int(t) for t in resultados), reverse=True):
        if resultados[str(tamanho)]:
            menor_ok = tamanho
            break
    return {"resultados": resultados, "maior_payload_ok": menor_ok}


# --------------------------------------------------------------------------- coleta
def _bool(valor: Any) -> bool:
    if isinstance(valor, bool):
        return valor
    return str(valor).strip().lower() in ("1", "true", "yes", "sim", "up", "enabled", "connected", "conectado")


def _parece_virtual(nome: str, desc: str) -> bool:
    texto = f"{nome} {desc}".lower()
    return any(k in texto for k in VIRTUAL_KEYWORDS)


def _parece_wifi(nome: str, desc: str, media: str = "") -> bool:
    texto = f"{nome} {desc} {media}".lower()
    return any(k in texto for k in WIFI_KEYWORDS)


def _sem_acento(texto: str) -> str:
    import unicodedata

    return (
        unicodedata.normalize("NFKD", texto)
        .encode("ascii", "ignore")
        .decode("ascii")
        .lower()
    )


def _dedup(lista: list[str]) -> list[str]:
    vistos: set[str] = set()
    saida: list[str] = []
    for item in lista:
        if item and item not in vistos:
            vistos.add(item)
            saida.append(item)
    return saida


def _coletar_windows(runner: Runner, info: NetInfo) -> None:
    script = r"""
$adapters = Get-NetAdapter | ForEach-Object {
  [pscustomobject]@{
    nome=[string]$_.Name; desc=[string]$_.InterfaceDescription;
    status=[string]$_.Status; velocidade=[string]$_.LinkSpeed;
    media=[string]$_.MediaType; indice=[int]$_.ifIndex;
    virtual=([string]$_.Virtual -eq 'True')
  }
}
$cfg = Get-NetIPConfiguration | ForEach-Object {
  [pscustomobject]@{
    nome=[string]$_.InterfaceAlias;
    ipv4=@($_.IPv4Address | ForEach-Object { $_.IPAddress + '/' + $_.PrefixLength });
    gw=@($_.IPv4DefaultGateway | ForEach-Object { $_.NextHop });
    dns=@(($_.DNSServer | ForEach-Object { $_.ServerAddresses }) | Where-Object { $_ -and $_ -notmatch ':' })
  }
}
$rotas = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | ForEach-Object {
  [pscustomobject]@{nome=[string]$_.InterfaceAlias; gw=[string]$_.NextHop;
    metrica=[int]$_.RouteMetric; metrica_if=[int]$_.InterfaceMetric}
}
$dhcp = Get-NetIPInterface -AddressFamily IPv4 | ForEach-Object {
  [pscustomobject]@{nome=[string]$_.InterfaceAlias; dhcp=[string]$_.Dhcp}
}
[pscustomobject]@{adapters=@($adapters); cfg=@($cfg); rotas=@($rotas); dhcp=@($dhcp)}
"""
    dados = runner.ps_json(script, timeout=45)
    pacote: dict[str, Any] = {}
    for item in dados:
        if isinstance(item, dict) and "adapters" in item:
            pacote = item
            break
    adapters = pacote.get("adapters") or []
    cfg = {str(c.get("nome", "")).lower(): c for c in (pacote.get("cfg") or [])}
    dhcp = {str(d.get("nome", "")).lower(): _bool(d.get("dhcp")) for d in (pacote.get("dhcp") or [])}

    for a in adapters:
        nome = str(a.get("nome") or "")
        if not nome or nome.lower().startswith("loopback"):
            continue
        desc = str(a.get("desc") or "")
        c = cfg.get(nome.lower(), {})
        iface = Iface(
            nome=nome,
            desc=desc,
            up=_bool(a.get("status")) or str(a.get("status", "")).lower() == "up",
            status=str(a.get("status") or ""),
            velocidade=str(a.get("velocidade") or ""),
            ips=[str(x) for x in (c.get("ipv4") or [])],
            gateway=(str((c.get("gw") or [""])[0]) if (c.get("gw") or [""])[0] else None),
            dns=[str(x) for x in (c.get("dns") or [])],
            wifi=_parece_wifi(nome, desc, str(a.get("media") or "")),
            virtual=bool(a.get("virtual")) or _parece_virtual(nome, desc),
            dhcp=dhcp.get(nome.lower()),
            indice=a.get("indice"),
        )
        info.interfaces.append(iface)
        info.dns.extend(iface.dns)

    for r in pacote.get("rotas") or []:
        gw = str(r.get("gw") or "")
        if not gw or gw in ("0.0.0.0", "::"):
            continue
        info.rotas.append(
            Route(
                iface=str(r.get("nome") or ""),
                gateway=gw,
                metric=int(r.get("metrica") or 0),
                ifmetric=int(r.get("metrica_if") or 0),
            )
        )


def _coletar_linux(runner: Runner, info: NetInfo) -> None:
    res = runner.run(["ip", "-j", "addr", "show"], timeout=15)
    links: list[dict[str, Any]] = []
    if res.ok:
        try:
            links = json.loads(res.out or "[]")
        except json.JSONDecodeError:
            links = []
    if not links:
        # Fallback minimo sem iproute2.
        res = runner.run(["ifconfig", "-a"], timeout=15)
        for bloco in re.split(r"\n(?=\S)", res.out):
            m = re.match(r"^(\S+):", bloco)
            if not m:
                continue
            nome = m.group(1)
            ips = re.findall(r"inet\s+(\d+\.\d+\.\d+\.\d+)", bloco)
            up = "UP" in bloco.split("\n", 1)[0]
            info.interfaces.append(
                Iface(nome=nome, up=up, ips=ips, wifi=os.path.isdir(f"/sys/class/net/{nome}/wireless"),
                      virtual=_parece_virtual(nome, ""))
            )

    for link in links:
        nome = str(link.get("ifname") or "")
        if not nome or nome == "lo":
            continue
        flags = link.get("flags") or []
        oper = str(link.get("operstate") or "").lower()
        up = oper in ("up", "unknown") and "UP" in [str(f).upper() for f in flags] or oper == "up"
        ips: list[str] = []
        for addr in link.get("addr_info") or []:
            if addr.get("family") == "inet" and addr.get("local"):
                ips.append(f"{addr['local']}/{addr.get('prefixlen', 24)}")
        wifi = os.path.isdir(f"/sys/class/net/{nome}/wireless") or nome.startswith(("wl", "wlan"))
        desc = ""
        try:
            desc = runner.ler_arquivo(f"/sys/class/net/{nome}/device/uevent").splitlines()[0]
        except Exception:
            desc = ""
        info.interfaces.append(
            Iface(
                nome=nome,
                desc=desc[:80],
                up=bool(up),
                status="up" if up else oper or "down",
                velocidade="",
                ips=ips,
                wifi=wifi or _parece_wifi(nome, desc),
                virtual=_parece_virtual(nome, desc),
            )
        )

    res_rotas = runner.run(["ip", "-j", "route", "show", "default"], timeout=10)
    rotas: list[dict[str, Any]] = []
    if res_rotas.ok and res_rotas.out.strip():
        try:
            rotas = json.loads(res_rotas.out)
        except json.JSONDecodeError:
            rotas = []
    for r in rotas:
        gw = str(r.get("gateway") or "")
        dev = str(r.get("dev") or "")
        if not gw or not dev:
            continue
        info.rotas.append(
            Route(
                iface=dev,
                gateway=gw,
                metric=int(r.get("metric") or r.get("priority") or 0),
                ifmetric=0,
            )
        )

    # Gateway e DNS por interface (quando disponivel).
    for rota in info.rotas:
        iface = info.por_nome(rota.iface)
        if iface and not iface.gateway:
            iface.gateway = rota.gateway

    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as fh:
            for linha in fh:
                m = re.match(r"\s*nameserver\s+(\S+)", linha)
                if m and ":" not in m.group(1):
                    info.dns.append(m.group(1))
    except OSError:
        pass


def _coletar_wifi_windows(runner: Runner) -> Optional[WifiInfo]:
    res = runner.run(["netsh", "wlan", "show", "interfaces"], timeout=15)
    texto = res.out
    normalizado = _sem_acento(texto)
    if not texto.strip() or "nenhuma interface" in normalizado or "no wireless interface" in normalizado:
        return None
    w = WifiInfo()
    for linha in texto.splitlines():
        if ":" not in linha:
            continue
        chave, valor = linha.split(":", 1)
        chave = _sem_acento(chave.strip())
        valor = valor.strip()
        if chave == "ssid":
            w.ssid = valor
        elif "sinal" in chave or chave == "signal":
            m = re.search(r"(\d+)\s*%", valor)
            if m:
                w.sinal = int(m.group(1))
        elif chave in ("estado", "state"):
            w.estado = valor
        elif "radio" in chave and "tipo" in chave:
            w.radio = valor
        elif "receive rate" in chave or "taxa de recep" in chave:
            w.taxa = valor
    if not w.ssid and w.sinal is None and not w.estado:
        return None
    w.conectado = bool(w.ssid) or "conect" in _sem_acento(w.estado)
    return w


def _coletar_wifi_linux(runner: Runner, info: NetInfo) -> Optional[WifiInfo]:
    if runner.which("nmcli"):
        res = runner.run(
            ["nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL,RATE", "device", "wifi", "list"], timeout=20
        )
        for linha in res.out.splitlines():
            m = re.match(r"^\*:(.*):(\d+):(.*)$", linha)
            if m:
                return WifiInfo(
                    ssid=m.group(1).replace("\\:", ":"),
                    sinal=int(m.group(2)),
                    taxa=m.group(3),
                    estado="conectado",
                    conectado=True,
                )
    wifi_iface = next((i for i in info.interfaces if i.wifi and i.up), None)
    if not wifi_iface:
        return None
    if runner.which("iwgetid"):
        ssid = runner.run(["iwgetid", "-r"], timeout=10).saida
        if ssid:
            w = WifiInfo(ssid=ssid, estado="conectado", conectado=True)
            link = runner.run(["iw", "dev", wifi_iface.nome, "link"], timeout=10).out
            m = re.search(r"signal:\s*(-?\d+)\s*dBm", link)
            if m:
                dbm = int(m.group(1))
                w.sinal = max(0, min(100, 2 * (dbm + 100)))
            return w
    return None


def _coletar_proxy(runner: Runner, info: NetInfo) -> None:
    proxy: dict[str, Any] = {"enabled": False, "server": "", "pac": "", "env": {}}
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "NO_PROXY", "no_proxy"):
        valor = os.environ.get(var)
        if valor:
            proxy["env"][var] = valor
            if var.upper() != "NO_PROXY":
                proxy["enabled"] = True
    if IS_WINDOWS:
        dados = runner.ps_json(
            r"""
$p = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
[pscustomobject]@{
  enable=[int]($p.ProxyEnable); server=[string]($p.ProxyServer);
  pac=[string]($p.AutoConfigURL)
}
""",
            timeout=20,
        )
        if dados:
            d = dados[0]
            proxy["server"] = str(d.get("server") or "")
            proxy["pac"] = str(d.get("pac") or "")
            if int(d.get("enable") or 0) == 1 and proxy["server"]:
                proxy["enabled"] = True
    info.proxy = proxy


def coletar_info(runner: Runner) -> NetInfo:
    info = NetInfo(hostname=platform_info.hostname(), sistema=platform_info.nome_sistema())
    if IS_WINDOWS:
        _coletar_windows(runner, info)
        info.wifi = _coletar_wifi_windows(runner)
    else:
        _coletar_linux(runner, info)
        info.wifi = _coletar_wifi_linux(runner, info)
    info.dns = _dedup([d for d in info.dns if d])
    _coletar_proxy(runner, info)
    info.interfaces.sort(key=lambda i: (not i.up, i.virtual, i.nome.lower()))
    return info


# --------------------------------------------------------------------------- testes
def executar_testes(
    runner: Runner,
    info: NetInfo,
    contagem: int = 4,
    completo: bool = False,
    ao_terminar: Optional[Callable[[str, Any], None]] = None,
) -> NetTests:
    testes = NetTests()
    iface, rota = info.ativa()
    gateway = (rota.gateway if rota else (iface.gateway if iface else None))

    tarefas: dict[str, Callable[[], Any]] = {}
    if gateway:
        tarefas["gateway"] = lambda: ping(runner, gateway, min(contagem, 3))
    tarefas["internet"] = lambda: ping(runner, "1.1.1.1", contagem)
    tarefas["internet_alt"] = lambda: ping(runner, "8.8.8.8", contagem)
    tarefas["host"] = lambda: ping(runner, "www.google.com", contagem)
    for host in ("www.google.com", "www.cloudflare.com", "www.microsoft.com"):
        tarefas[f"dns:{host}"] = (lambda h=host: testar_dns(h))
    tarefas["tcp:1.1.1.1:443"] = lambda: testar_tcp("1.1.1.1", 443)
    tarefas["tcp:8.8.8.8:443"] = lambda: testar_tcp("8.8.8.8", 443)
    tarefas["tcp:www.google.com:443"] = lambda: testar_tcp("www.google.com", 443)
    if info.dns:
        dns1 = info.dns[0]
        tarefas[f"tcp:{dns1}:53"] = (lambda d=dns1: testar_tcp(d, 53))
    tarefas["http"] = testar_http

    from concurrent.futures import ThreadPoolExecutor, as_completed

    with ThreadPoolExecutor(max_workers=10) as pool:
        futuros = {pool.submit(fn): nome for nome, fn in tarefas.items()}
        for futuro in as_completed(futuros):
            nome = futuros[futuro]
            try:
                valor = futuro.result()
            except Exception as exc:  # noqa: BLE001
                valor = exc
            if nome.startswith("dns:"):
                testes.dns.append(valor if isinstance(valor, DnsResult) else DnsResult(nome[4:], erro=str(valor)))
            elif nome.startswith("tcp:"):
                testes.tcp.append(valor if isinstance(valor, TcpResult) else TcpResult(nome, 0, erro=str(valor)))
            elif nome == "http":
                testes.http = valor if isinstance(valor, dict) else {"ok": False, "erro": str(valor)}
            else:
                testes.pings[nome] = valor if isinstance(valor, PingResult) else PingResult(nome, erro=str(valor))
            if ao_terminar:
                ao_terminar(nome, valor)

    if completo:
        alvo_mtu = "1.1.1.1"
        testes.mtu = testar_mtu(runner, alvo_mtu)

    # Ordena para saida estavel.
    testes.dns.sort(key=lambda d: d.host)
    testes.tcp.sort(key=lambda t: (t.host, t.porta))
    return testes


# --------------------------------------------------------------------------- regras
def _pior_ping(pings: list[Optional[PingResult]]) -> Optional[PingResult]:
    validos = [p for p in pings if p]
    if not validos:
        return None
    return max(validos, key=lambda p: (p.perda, -(p.rtt_avg or 0)))


def diagnosticar(
    runner: Runner,
    contagem: int = 4,
    completo: bool = False,
    ao_terminar: Optional[Callable[[str, Any], None]] = None,
    info: Optional[NetInfo] = None,
    testes: Optional[NetTests] = None,
) -> Diagnosis:
    info = info if info is not None else coletar_info(runner)
    diag = Diagnosis(area=AREA, title="Diagnostico de rede", data={})
    achados: list[Finding] = []

    def add(id_: str, sev: str, titulo: str, detalhe: str = "", causa: str = "") -> None:
        achados.append(Finding(id=id_, area=AREA, severity=sev, title=titulo, detail=detalhe, cause=causa))

    iface, rota = info.ativa()
    ativos = [i for i in info.interfaces if i.up]
    virtuais_ativas = [i for i in ativos if i.virtual and i.ips and (not iface or i.nome != iface.nome)]

    if not ativos:
        add(
            "sem_link",
            "critico",
            "Nenhuma interface de rede ativa",
            "Nao ha adaptador conectado. Cabo desconectado, Wi-Fi desligado ou adaptador desabilitado.",
            "Problema fisico/local, nao no provedor.",
        )
        diag.findings = achados
        diag.actions = _planejar(info, diag, somente_manuais=True)
        diag.summary = "Sem link de rede: verifique cabo, Wi-Fi e o adaptador de rede antes de olhar o provedor."
        diag.data = _dados_info(info, NetTests())
        return diag

    if iface:
        v4 = [ip for ip in iface.ips if ":" not in ip]
        if not v4:
            add(
                "sem_ip",
                "erro",
                "Adaptador ativo sem endereco IPv4",
                f"Interface {iface.nome} esta ligada, mas sem IP.",
                "DHCP nao respondeu ou IP fixo nao configurado.",
            )
        elif any(ip.startswith("169.254.") for ip in v4):
            add(
                "dhcp_falhou",
                "erro",
                "IP automatico invalido (169.254.x.x)",
                f"{iface.nome}: {', '.join(v4)}",
                "O servidor DHCP do roteador nao entregou endereco. Cabo/porta/DHCP ou Wi-Fi com problema.",
            )

    if not info.rotas:
        add(
            "sem_gateway",
            "erro",
            "Sem rota padrao (gateway)",
            "Existe IP, mas o computador nao sabe por onde sair para a internet.",
            "Gateway nao configurado ou DHCP incompleto.",
        )
    else:
        rotas_ordenadas = sorted(info.rotas, key=lambda r: r.peso)
        principal = rotas_ordenadas[0]
        concorrentes = [
            r for r in rotas_ordenadas[1:]
            if r.gateway != principal.gateway and r.peso - principal.peso < 200
        ]
        if concorrentes:
            add(
                "rotas_conflitantes",
                "aviso",
                "Mais de uma rota padrao disputando a saida",
                "; ".join(f"{r.iface} via {r.gateway} (metrica {r.peso})" for r in [principal] + concorrentes),
                "VPN/adaptador virtual ou duas redes ativas ao mesmo tempo.",
            )
        rota = principal
        iface = info.por_nome(principal.iface) or iface

    if info.wifi:
        w = info.wifi
        if not w.conectado:
            add("wifi_desconectado", "erro", "Wi-Fi sem conexao", w.estado or "interface sem rede.",
                "Rede Wi-Fi fora de alcance, senha alterada ou adaptador desligado.")
        elif w.sinal is not None:
            if w.sinal < 25:
                add("wifi_fraco", "erro", f"Sinal Wi-Fi muito fraco ({w.sinal}%)",
                    f"SSID: {w.ssid or '?'} | taxa: {w.taxa or '?'}", "Distancia/obstaculos ou antena do roteador.")
            elif w.sinal < 45:
                add("wifi_fraco", "aviso", f"Sinal Wi-Fi fraco ({w.sinal}%)",
                    f"SSID: {w.ssid or '?'} | taxa: {w.taxa or '?'}",
                    "Sinal baixo causa perda de pacotes e lentidao.")

    for i in virtuais_ativas:
        add(
            "vpn_ativa",
            "info",
            f"Adaptador virtual ativo: {i.nome}",
            f"IP: {', '.join(i.ips)}. Se a internet piorou depois de ativa-lo, desligue a VPN/overlay e teste.",
            "VPN/overlay pode criar rotas e DNS proprios.",
        )

    if info.proxy.get("enabled"):
        detalhe = info.proxy.get("server") or info.proxy.get("pac")
        if not detalhe:
            detalhe = ", ".join(
                f"{k}={v}" for k, v in (info.proxy.get("env") or {}).items()
                if k.upper() != "NO_PROXY"
            )
        add(
            "proxy_ativo",
            "info",
            "Proxy configurado no sistema",
            f"Proxy: {detalhe}",
            "Proxy fora do ar ou mal configurado derruba navegacao mesmo com ping funcionando.",
        )

    testes = testes if testes is not None else executar_testes(
        runner, info, contagem=contagem, completo=completo, ao_terminar=ao_terminar
    )

    gateway = rota.gateway if rota else (iface.gateway if iface else None)
    p_gw = testes.pings.get("gateway")
    p_inet = testes.pings.get("internet")
    p_alt = testes.pings.get("internet_alt")
    internet_ok = bool((p_inet and p_inet.ok) or (p_alt and p_alt.ok))

    if gateway and p_gw is not None:
        if p_gw.recebidos == 0:
            add(
                "gateway_mudo",
                "critico",
                "Gateway (roteador) nao responde",
                f"{gateway}: {p_gw.resumo()}. O computador nao alcanca nem o roteador.",
                "Cabo/porta/Wi-Fi, roteador travado ou IP na rede errada.",
            )
        elif p_gw.perda > 0:
            sev = "erro" if p_gw.perda >= 30 else "aviso"
            add(
                "gateway_perda",
                sev,
                f"Perda de pacotes no gateway ({p_gw.perda:.0f}%)",
                f"{gateway}: {p_gw.resumo()}",
                "Cabo ruim, Wi-Fi instavel, porta do switch ou roteador sobrecarregado.",
            )
        elif p_gw.rtt_avg and p_gw.rtt_avg > 15:
            add("gateway_lento", "aviso", f"Gateway lento ({p_gw.rtt_avg:.0f} ms)",
                "O primeiro salto ja esta com latencia alta.",
                "Rede local congestionada, Wi-Fi ruim ou roteador sobrecarregado.")

    if gateway and p_gw is not None and p_gw.recebidos > 0:
        if not internet_ok:
            add(
                "sem_internet",
                "erro",
                "Sem acesso a internet (mas o roteador responde)",
                f"1.1.1.1: {p_inet.resumo() if p_inet else '?'} | 8.8.8.8: {p_alt.resumo() if p_alt else '?'}",
                "Link do provedor, modem, roteador sem WAN ou bloqueio de ICMP/firewall.",
            )
        else:
            if p_inet and not p_inet.ok and p_alt and p_alt.ok:
                add("icmp_parcial", "info", "1.1.1.1 bloqueado, mas internet funciona via 8.8.8.8",
                    "Alguns provedores bloqueiam ICMP para certos destinos.", "Nada a corrigir.")
            perdas = [p for p in (p_inet, p_alt) if p and p.ok and p.perda > 0]
            if perdas:
                pior = max(perdas, key=lambda p: p.perda)
                sev = "erro" if pior.perda >= 20 else "aviso"
                add(
                    "perda_pacotes",
                    sev,
                    f"Perda de pacotes na internet ({pior.perda:.0f}%)",
                    f"{pior.alvo}: {pior.resumo()}",
                    "Wi-Fi/cabo instavel ou congestionamento no provedor.",
                )
            latencias = [p.rtt_avg for p in (p_inet, p_alt) if p and p.ok and p.rtt_avg]
            if latencias and max(latencias) > 150:
                add(
                    "latencia_alta",
                    "aviso",
                    f"Latencia alta ({max(latencias):.0f} ms)",
                    "Acima de 150 ms ja atrapalha videochamadas e acesso remoto.",
                    "Wi-Fi, rede saturada, rota do provedor ou destino distante.",
                )

    dns_ok = [d for d in testes.dns if d.ok]
    if internet_ok and not dns_ok:
        add(
            "dns_falha",
            "erro",
            "DNS nao resolve nomes",
            "Ping por IP funciona, mas nenhum nome (google/cloudflare/microsoft) resolve.",
            "Servidor DNS inacessivel, cache corrompido ou DNS do roteador/provedor fora.",
        )
    elif dns_ok and len(dns_ok) < len(testes.dns):
        falhas = [d.host for d in testes.dns if not d.ok]
        add(
            "dns_parcial",
            "aviso",
            "Resolucao de nomes instavel",
            f"Falhou para: {', '.join(falhas)}",
            "DNS lento/instavel ou bloqueio seletivo.",
        )
    lentos = [d for d in dns_ok if d.ms > 1000]
    if lentos:
        add(
            "dns_lento",
            "aviso",
            f"DNS lento ({max(d.ms for d in lentos):.0f} ms)",
            "Respostas de DNS acima de 1 s causam sensacao de internet lenta.",
            "Servidor DNS distante ou sobrecarregado.",
        )

    http = testes.http or {}
    if http.get("portal"):
        add(
            "portal_captivo",
            "aviso",
            "Portal de autenticacao (Wi-Fi publico/hotel)",
            "A conexao e redirecionada para uma pagina de login.",
            "Falta autenticar no portal para liberar a internet.",
        )
    elif internet_ok and not http.get("ok"):
        tcp_host = next((t for t in testes.tcp if t.host == "www.google.com" and t.porta == 443), None)
        if tcp_host and tcp_host.ok:
            add(
                "http_bloqueado",
                "aviso",
                "HTTP/HTTPS bloqueado para teste de conectividade",
                f"Erro: {http.get('erro', 'sem resposta')}",
                "Firewall/antivirus/proxy interceptando, ou rede exige autenticacao.",
            )

    tcp_ok = any(t.ok for t in testes.tcp if t.porta == 443 and t.host in ("1.1.1.1", "8.8.8.8"))
    if internet_ok and not tcp_ok:
        add(
            "tcp_bloqueado",
            "erro",
            "Conexoes TCP (443) bloqueadas",
            "Ping funciona, mas nao abre conexao com nenhum destino na porta 443.",
            "Firewall/antivirus bloqueando saida ou politica da rede.",
        )

    if testes.mtu:
        maior = testes.mtu.get("maior_payload_ok")
        if maior is not None and maior < 1400:
            add(
                "mtu_baixo",
                "aviso",
                f"MTU efetivo baixo (payload {maior})",
                "Pacotes grandes falham: alguns sites abrem e outros ficam carregando.",
                "VPN/tunel ou rota com MTU menor; ajuste a MTU da interface.",
            )
        elif maior is None:
            add("mtu_falha", "info", "Teste de MTU nao concluido",
                "Nenhum pacote grande passou; pode ser bloqueio de ICMP.", "Sem acao se a internet funciona.")

    if not any(f.severity in ("aviso", "erro", "critico") for f in achados):
        detalhe = ""
        if p_gw and p_gw.rtt_avg is not None:
            detalhe = f"Gateway {gateway} em {p_gw.rtt_avg:.0f} ms"
        add("tudo_ok", "ok", "Rede operacional", detalhe, "Nenhum problema detectado nos testes basicos.")

    diag.findings = ordenar_findings(achados)
    diag.actions = _planejar(info, diag)
    diag.summary = _resumo(diag, info, testes)
    diag.data = _dados_info(info, testes)
    return diag


def _resumo(diag: Diagnosis, info: NetInfo, testes: NetTests) -> str:
    problemas = [f for f in diag.findings if f.severity in ("aviso", "erro", "critico")]
    if not problemas:
        p_inet = testes.pings.get("internet") or testes.pings.get("internet_alt")
        extra = f" Latencia media: {p_inet.rtt_avg:.0f} ms." if p_inet and p_inet.rtt_avg else ""
        return "Rede operacional: link, gateway, DNS e internet respondendo." + extra
    principal = problemas[0]
    texto = f"{principal.title}."
    if principal.cause:
        texto += f" Causa provavel: {principal.cause}"
    if len(problemas) > 1:
        texto += f" (+{len(problemas) - 1} outros achados)"
    return texto


def _dados_info(info: NetInfo, testes: NetTests) -> dict[str, Any]:
    return {
        "Interfaces": [
            {
                "nome": i.nome,
                "descricao": i.desc,
                "ativo": i.up,
                "ipv4": i.ips,
                "gateway": i.gateway,
                "dns": i.dns,
                "wifi": i.wifi,
                "virtual": i.virtual,
                "dhcp": i.dhcp,
            }
            for i in info.interfaces
        ],
        "Rotas padrao": [
            {"interface": r.iface, "gateway": r.gateway, "metrica": r.peso} for r in info.rotas
        ],
        "Wi-Fi": vars(info.wifi) if info.wifi else None,
        "Proxy": info.proxy,
        "Pings": {nome: vars(p) for nome, p in testes.pings.items()},
        "DNS": [vars(d) for d in testes.dns],
        "TCP": [vars(t) for t in testes.tcp],
        "HTTP": testes.http,
        "MTU": testes.mtu,
    }


# --------------------------------------------------------------------------- acoes
def _sistema() -> str:
    return "windows" if IS_WINDOWS else "linux"


def _planejar(info: NetInfo, diag: Diagnosis, somente_manuais: bool = False) -> list[Action]:
    iface, _ = info.ativa()
    iface_nome = iface.nome if iface else ""
    acoes: list[Action] = []
    ids = {f.id for f in diag.findings}

    def add(a: Action) -> None:
        if a.applies in ("any", _sistema()):
            acoes.append(a)

    if "sem_link" in ids or "wifi_desconectado" in ids:
        add(Action(
            "verificar_cabo", "Verificar cabo, Wi-Fi e adaptador", manual=True,
            why="Sem link fisico nao existe diagnostico de provedor que resolva.",
            steps=[
                Step("Confira se o cabo esta firme nas duas pontas e se a luz da porta acende."),
                Step("Teste outra porta do switch/roteador e outro cabo."),
                Step("No notebook, ligue o Wi-Fi e conecte na rede correta."),
                Step("Veja se o adaptador nao esta desabilitado (Gerenciador de Dispositivos / Configuracoes de Rede)."),
            ],
        ))
        if IS_WINDOWS:
            add(Action(
                "ativar_adapter", f"Reativar adaptador {iface_nome or 'de rede'}", risk="baixo",
                why="Reinicia o adaptador e tenta subir o link novamente.",
                steps=[
                    Step(f"Habilitar adaptador {iface_nome}", ps=f"Enable-NetAdapter -Name '{iface_nome}' -Confirm:$false"),
                ],
            ))
        return acoes

    if ids & {"dhcp_falhou", "sem_ip", "sem_gateway"}:
        if IS_WINDOWS:
            add(Action(
                "renovar_dhcp", "Renovar IP via DHCP", risk="medio",
                why="Descarta IP invalido e pede um novo endereco ao roteador.",
                steps=[
                    Step("Liberar IP atual", argv=["ipconfig", "/release"]),
                    Step("Solicitar novo IP", argv=["ipconfig", "/renew"], timeout=90),
                ],
                note="A conexao cai por alguns segundos durante a renovacao.",
            ))
            add(Action(
                "reiniciar_adapter", "Reiniciar o adaptador de rede", risk="medio", needs_admin=True,
                why="Reseta o driver/adaptador sem reiniciar o computador.",
                steps=[Step(f"Reiniciar {iface_nome}", ps=f"Restart-NetAdapter -Name '{iface_nome}' -Confirm:$false")],
            ))
        else:
            add(Action(
                "renovar_dhcp", "Renovar IP via DHCP", risk="medio", needs_admin=True,
                why="Pede novo endereco ao DHCP e reaplica a configuracao.",
                steps=[
                    Step(
                        f"Reaplicar conexao em {iface_nome}",
                        shell=(
                            f"nmcli device reapply {iface_nome} 2>/dev/null || "
                            f"(dhclient -r {iface_nome} 2>/dev/null; dhclient {iface_nome})"
                        ),
                    ),
                ],
                note="Se usa IP fixo, revise a configuracao antes de renovar.",
            ))

    if "rotas_conflitantes" in ids:
        add(Action(
            "ver_rotas", "Conferir rotas e desligar VPN/overlay", manual=True,
            why="Duas rotas padrao fazem o trafego sair pela interface errada.",
            steps=[
                Step("Veja a tabela de rotas: " + ("route print" if IS_WINDOWS else "ip route")),
                Step("Desconecte VPN/ZeroTier/Tailscale e teste novamente."),
                Step("Se for proposital, ajuste a metrica para a interface correta."),
            ],
        ))

    if "wifi_fraco" in ids:
        add(Action(
            "wifi_aproximar", "Melhorar sinal Wi-Fi", manual=True,
            why="Sinal abaixo de 45% derruba velocidade e causa perda de pacotes.",
            steps=[
                Step("Aproxime-se do roteador ou troque para 5 GHz se estiver perto."),
                Step("Evite paredes/metal entre o notebook e o roteador."),
                Step("Considere repetidor/mesh ou cabo de rede."),
            ],
        ))
    if "wifi_desconectado" in ids:
        add(Action(
            "wifi_conectar", "Reconectar no Wi-Fi", risk="baixo",
            why="Refaz a associacao com o ponto de acesso.",
            manual=not IS_WINDOWS,
            steps=[
                Step("Desconectar", argv=["netsh", "wlan", "disconnect"]) if IS_WINDOWS else
                Step("Reconectar pela interface grafica ou: nmcli device wifi connect \"SUA_REDE\""),
            ],
        ))

    if ids & {"gateway_mudo", "gateway_perda", "gateway_lento"}:
        add(Action(
            "reiniciar_adapter", "Reiniciar o adaptador de rede", risk="medio", needs_admin=True,
            why="Resolve driver/adaptador travado quando o gateway para de responder.",
            steps=[Step(f"Reiniciar {iface_nome}", ps=f"Restart-NetAdapter -Name '{iface_nome}' -Confirm:$false")] if IS_WINDOWS else
                  [Step(f"Baixar/subir {iface_nome}", shell=f"ip link set {iface_nome} down; sleep 2; ip link set {iface_nome} up")],
        ))
        add(Action(
            "reiniciar_roteador", "Reiniciar roteador/modem", manual=True,
            why="Se nem o gateway responde, o roteador pode estar travado.",
            steps=[
                Step("Tire o roteador da tomada por 30 segundos e ligue novamente."),
                Step("Aguarde 2 minutos e teste de novo."),
                Step("Se o problema voltar sempre, verifique fonte/cabos e temperatura do equipamento."),
            ],
        ))

    if "sem_internet" in ids:
        add(Action(
            "reiniciar_roteador", "Reiniciar roteador/modem", manual=True,
            why="O computador chega ao roteador, mas o roteador nao chega a internet.",
            steps=[
                Step("Reinicie modem e roteador (desligue 30 s)."),
                Step("Confira as luzes de WAN/Internet no modem."),
                Step("Teste outro aparelho na mesma rede: se todos falham, o problema e do provedor."),
                Step("Ligue para o provedor com o horario e os testes deste relatorio em maos."),
            ],
        ))
        add(Action(
            "verificar_provedor", "Conferir link do provedor", manual=True,
            why="Falha de WAN/ISP nao se corrige no computador.",
            steps=[
                Step("Acesse o painel do provedor (ou app) e veja se ha manutencao/queda na regiao."),
                Step("Anote a hora e o resultado dos pings do relatorio."),
                Step("Peca protocolo de atendimento e teste de sinal no modem."),
            ],
        ))

    if "perda_pacotes" in ids or "latencia_alta" in ids:
        add(Action(
            "verificar_cabo", "Testar cabo/porta e Wi-Fi", manual=True,
            why="Perda e latencia normalmente vem da camada fisica ou do Wi-Fi.",
            steps=[
                Step("Troque o cabo e a porta do switch."),
                Step("Teste por cabo em vez de Wi-Fi para isolar o problema."),
                Step("Se for Wi-Fi, aproxime do roteador e troque para 5 GHz."),
            ],
        ))

    if "dns_falha" in ids or "dns_parcial" in ids or "dns_lento" in ids:
        if IS_WINDOWS:
            add(Action(
                "limpar_dns", "Limpar cache de DNS", risk="baixo",
                why="Cache corrompido causa falha mesmo com servidor DNS bom.",
                steps=[Step("Limpar cache", argv=["ipconfig", "/flushdns"])],
            ))
            add(Action(
                "dns_publico", "Trocar DNS para 1.1.1.1/8.8.8.8", risk="medio", needs_admin=True,
                why="Testa se o DNS do roteador/provedor e o culpado.",
                steps=[
                    Step(f"Configurar DNS em {iface_nome}",
                         ps=f"Set-DnsClientServerAddress -InterfaceAlias '{iface_nome}' -ServerAddresses 1.1.1.1,8.8.8.8"),
                    Step("Limpar cache", argv=["ipconfig", "/flushdns"]),
                ],
                note="Em rede corporativa isso pode quebrar nomes internos. Reverta depois se necessario.",
            ))
            add(Action(
                "restart_dnscache", "Reiniciar servico de DNS do Windows", risk="medio", needs_admin=True,
                why="Se o servico Dnscache travou, reinicia-lo resolve.",
                steps=[Step("Reiniciar Dnscache", ps="Restart-Service Dnscache -Force")],
            ))
        else:
            add(Action(
                "limpar_dns", "Limpar cache de DNS", risk="baixo", needs_admin=True,
                why="Cache local corrompido causa falha mesmo com servidor bom.",
                steps=[
                    Step("Limpar cache (systemd-resolved)", shell="resolvectl flush-caches 2>/dev/null || systemd-resolve --flush-caches 2>/dev/null || true"),
                ],
            ))
            add(Action(
                "dns_publico", "Trocar DNS para 1.1.1.1/8.8.8.8", risk="medio", needs_admin=True,
                why="Testa se o DNS do roteador/provedor e o culpado.",
                steps=[
                    Step(f"Configurar DNS em {iface_nome}",
                         shell=f"resolvectl dns {iface_nome} 1.1.1.1 8.8.8.8 2>/dev/null || true"),
                    Step("Limpar cache", shell="resolvectl flush-caches 2>/dev/null || true"),
                ],
                note="Em rede corporativa isso pode quebrar nomes internos.",
            ))

    if "portal_captivo" in ids:
        add(Action(
            "abrir_portal", "Autenticar no portal Wi-Fi", manual=True,
            why="A rede so libera internet depois do login na pagina do portal.",
            steps=[
                Step("Abra o navegador em http://neverssl.com e siga a pagina de login."),
                Step("Se nao abrir, desconecte e conecte novamente no Wi-Fi."),
            ],
        ))

    if "proxy_ativo" in ids:
        if IS_WINDOWS:
            add(Action(
                "desativar_proxy", "Desativar proxy do usuario (teste)", risk="baixo",
                why="Proxy mal configurado derruba a navegacao mesmo com rede boa.",
                steps=[
                    Step("Desativar proxy do Internet Settings",
                         ps="Set-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value 0"),
                    Step("Limpar proxy de servicos", ps="netsh winhttp reset proxy"),
                ],
                note="Se a empresa usa proxy obrigatorio, reative depois.",
            ))
        else:
            add(Action(
                "desativar_proxy", "Remover proxy do ambiente (teste)", manual=True,
                why="Variaveis HTTP_PROXY/HTTPS_PROXY podem apontar para um proxy fora do ar.",
                steps=[Step("Rode sem proxy: env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy <comando>"),
                       Step("Se resolver, remova as variaveis dos arquivos de perfil/ambiente.")],
            ))

    if "tcp_bloqueado" in ids or "http_bloqueado" in ids:
        add(Action(
            "verificar_firewall", "Conferir firewall/antivirus/proxy", manual=True,
            why="Ping passa mas TCP nao: algo esta filtrando a saida.",
            steps=[
                Step("Desative temporariamente o antivirus/firewall e teste."),
                Step("Verifique regras de bloqueio de saida e politicas de proxy."),
                Step("Teste em outra rede (4G do celular) para confirmar."),
            ],
        ))

    if "mtu_baixo" in ids:
        if IS_WINDOWS:
            add(Action(
                "ajustar_mtu", "Ajustar MTU da interface", manual=True,
                why="Pacotes grandes falham em tunel/VPN ou link com MTU menor.",
                steps=[
                    Step("Descubra o payload que passa: ping -f -l 1472 1.1.1.1 (reduza ate funcionar)."),
                    Step("Some 28 ao valor que funcionou e aplique (ex.: 1400):"),
                    Step(f"netsh interface ipv4 set subinterface \"{iface_nome}\" mtu=1400 store=persistent"),
                ],
            ))
        else:
            add(Action(
                "ajustar_mtu", "Ajustar MTU da interface", manual=True,
                why="Pacotes grandes falham em tunel/VPN ou link com MTU menor.",
                steps=[
                    Step("Descubra o payload que passa: ping -M do -s 1472 1.1.1.1 (reduza ate funcionar)."),
                    Step(f"sudo ip link set dev {iface_nome} mtu 1400"),
                ],
            ))

    if not somente_manuais and not acoes:
        add(Action(
            "monitorar", "Monitorar a conexao", manual=True,
            why="Sem falha evidente, acompanhe perda e latencia por alguns minutos.",
            steps=[Step("Rode: socorro rede ping 1.1.1.1"), Step("Anote os momentos de queda e correlacione com horario.")],
        ))

    return deduplicar_acoes(acoes)


# --------------------------------------------------------------------------- execucao
def _resultado_curto(res: Any, ui: Any) -> None:
    saida = (res.out or res.err or "").strip()
    if not saida:
        ui.info("sem saida")
        return
    linhas = [l for l in saida.splitlines() if l.strip()]
    for linha in linhas[:4]:
        ui.escrever("      " + ui.paint(linha[:140], "\033[2m"))
    if len(linhas) > 4:
        ui.escrever("      " + ui.paint(f"... ({len(linhas) - 4} linhas omitidas)", "\033[2m"))


def executar_acoes(
    runner: Runner,
    acoes: list[Action],
    ui: Any,
    auto: bool = False,
    incluir_alto: bool = False,
) -> list[tuple[str, bool, str]]:
    admin = platform_info.eh_admin()
    resultados: list[tuple[str, bool, str]] = []
    for acao in acoes:
        ui.espaco()
        ui.subsecao(acao.title)
        if acao.why:
            ui.paragrafo(acao.why, indent=4)
        if acao.risk == "alto" and not incluir_alto:
            ui.aviso("Acao de risco alto: pulada (use --tudo para incluir).")
            resultados.append((acao.title, False, "risco alto ignorado"))
            continue
        if acao.manual:
            ui.info("Acao assistida - execute manualmente:")
            for passo in acao.steps:
                ui.item(passo.desc)
            if acao.note:
                ui.info(acao.note)
            resultados.append((acao.title, True, "orientacao exibida"))
            continue
        if acao.needs_admin and not admin:
            ui.aviso("Requer administrador. " + platform_info.dica_admin())
            for passo in acao.steps:
                if passo.ps:
                    ui.codigo(passo.ps)
                elif passo.argv:
                    ui.codigo(" ".join(passo.argv))
                elif passo.shell:
                    ui.codigo(passo.shell)
            resultados.append((acao.title, False, "sem permissao de administrador"))
            continue
        if not auto and not ui.confirmar(f"Executar '{acao.title}' agora?", padrao=False):
            ui.info("Pulada.")
            resultados.append((acao.title, False, "pulada pelo usuario"))
            continue

        sucesso = True
        for passo in acao.steps:
            ui.item(passo.desc)
            if passo.ps:
                res = runner.ps(passo.ps, timeout=passo.timeout)
            elif passo.argv:
                res = runner.run(passo.argv, timeout=passo.timeout)
            elif passo.shell:
                res = runner.run_shell(passo.shell, timeout=passo.timeout)
            else:
                continue
            _resultado_curto(res, ui)
            if not res.ok and not passo.ignore_error:
                ui.erro(f"Falhou (codigo {res.code}).")
                sucesso = False
                break
            if not res.ok:
                ui.aviso(f"Codigo {res.code} (continuando).")
        if acao.note:
            ui.info(acao.note)
        resultados.append((acao.title, sucesso, "executada" if sucesso else "com falha"))
    return resultados


# --------------------------------------------------------------------------- saida
def _fmt_ms(valor: Optional[float]) -> str:
    return "-" if valor is None else f"{valor:.0f} ms"


def imprimir_diagnostico(diag: Diagnosis, ui: Any) -> None:
    dados = diag.data
    ui.secao("Interfaces de rede")
    rotas = dados.get("Rotas padrao") or []
    principal = min(rotas, key=lambda r: r.get("metrica", 0))["interface"] if rotas else None
    linhas = []
    for i in dados.get("Interfaces", []):
        estado = "ATIVA" if i.get("ativo") else i.get("status") or "parada"
        ips = ", ".join(i.get("ipv4") or []) or "sem IP"
        extras = []
        if i.get("nome") == principal:
            extras.append("rota padrao")
        if i.get("gateway"):
            extras.append(f"gw {i['gateway']}")
        if i.get("wifi"):
            extras.append("Wi-Fi")
        if i.get("virtual"):
            extras.append("virtual")
        linhas.append([i.get("nome", ""), estado, ips, "  ".join(extras)])
    if linhas:
        ui.tabela(["Interface", "Estado", "IPv4", "Detalhes"], linhas)
    else:
        ui.aviso("Nenhuma interface encontrada.")

    wi = dados.get("Wi-Fi")
    if wi and (wi.get("ssid") or wi.get("sinal") is not None):
        sinal = f"{wi.get('sinal')}%" if wi.get("sinal") is not None else "?"
        ui.item(f"Wi-Fi: {wi.get('ssid') or '(sem SSID)'}", f"sinal {sinal} | {wi.get('taxa') or ''}")
    proxy = dados.get("Proxy") or {}
    if proxy.get("enabled"):
        detalhe = proxy.get("server") or proxy.get("pac") or ", ".join(
            f"{k}={v}" for k, v in (proxy.get("env") or {}).items() if k.upper() != "NO_PROXY"
        )
        ui.item("Proxy configurado", str(detalhe))

    ui.secao("Testes de conectividade")
    linhas = []
    for nome, p in dados.get("Pings", {}).items():
        if not isinstance(p, dict):
            continue
        rotulo = {
            "gateway": "Gateway (roteador)",
            "internet": "Internet 1.1.1.1",
            "internet_alt": "Internet 8.8.8.8",
            "host": "Internet www.google.com",
        }.get(nome, nome)
        alvo = p.get("alvo", "")
        status = "OK" if p.get("ok") else "FALHA"
        detalhe = f"{p.get('recebidos', 0)}/{p.get('enviados', 0)}"
        if p.get("rtt_avg") is not None:
            detalhe += f" | media {p['rtt_avg']:.0f} ms"
        if p.get("perda"):
            detalhe += f" | perda {p['perda']:.0f}%"
        if p.get("erro"):
            detalhe += f" | {p['erro']}"
        linhas.append([rotulo, alvo, status, detalhe])
    for d in dados.get("DNS", []):
        linhas.append(["DNS " + str(d.get("host")), "resolver", "OK" if d.get("ok") else "FALHA",
                       f"{d.get('ms', 0):.0f} ms" + (f" | {d.get('erro')}" if d.get("erro") else "")])
    for t in dados.get("TCP", []):
        linhas.append([f"TCP {t.get('host')}:{t.get('porta')}", "conexao", "OK" if t.get("ok") else "FALHA",
                       f"{t.get('ms', 0):.0f} ms" + (f" | {t.get('erro')}" if t.get("erro") else "")])
    http = dados.get("HTTP") or {}
    if http:
        if http.get("ok"):
            estado = "OK"
            det = f"{http.get('ms', 0):.0f} ms"
        elif http.get("portal"):
            estado = "PORTAL"
            det = "redirecionado para login"
        else:
            estado = "FALHA"
            det = str(http.get("erro") or "")[:60]
        linhas.append(["HTTP (conectividade)", "generate_204", estado, det])
    mtu = dados.get("MTU") or {}
    if mtu:
        linhas.append(["MTU", "pacote grande", "OK" if mtu.get("maior_payload_ok") else "FALHA",
                       f"payload max {mtu.get('maior_payload_ok') or '-'}"])
    if linhas:
        ui.tabela(["Teste", "Alvo", "Resultado", "Detalhe"], linhas, ["<", "<", "<", "<"])

    ui.secao("Diagnostico")
    for f in diag.findings:
        texto = f.title
        if f.detail:
            texto += f"  {ui.paint('(' + f.detail + ')', '\033[2m')}"
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


def imprimir_plano(acoes: list[Action], ui: Any) -> None:
    if not acoes:
        return
    ui.secao("Plano de acao sugerido")
    for i, a in enumerate(acoes, 1):
        risco = {"baixo": "risco baixo", "medio": "risco medio", "alto": "RISCO ALTO"}.get(a.risk, a.risk)
        admin = " | admin" if a.needs_admin else ""
        manual = " | manual" if a.manual else ""
        ui.item(f"{i}. {a.title}", f"[{risco}{admin}{manual}]")
        if a.why:
            ui.escrever("       " + ui.paint(a.why, "\033[2m"))


def ping_continuo(runner: Runner, ui: Any, alvo: str, contagem: int = 10, intervalo: float = 0.5) -> PingResult:
    """Mostra ping linha a linha, com resumo final."""
    ui.titulo(f"Ping para {alvo}", f"{contagem} pacotes | Ctrl+C para parar")
    tempos: list[float] = []
    recebidos = 0
    for i in range(contagem):
        p = ping(runner, alvo, 1, timeout_ms=int(max(1, intervalo) * 1000))
        if p.recebidos:
            recebidos += 1
            ms = p.rtt_avg or 0
            tempos.append(ms)
            barra = "#" * min(40, max(1, int(ms / 10)))
            ui.escrever(f"  {i + 1:>3}  {ui.paint(f'{ms:7.1f} ms', GREEN if ms < 80 else YELLOW if ms < 200 else RED)}  {ui.paint(barra, CYAN)}")
        else:
            ui.escrever(f"  {i + 1:>3}  {ui.paint('   timeout', RED)}")
        if i < contagem - 1:
            time.sleep(max(0.2, intervalo))
    res = PingResult(alvo=alvo, enviados=contagem, recebidos=recebidos,
                     perda=100.0 * (contagem - recebidos) / max(1, contagem))
    if tempos:
        res.ok = True
        res.rtt_min, res.rtt_avg, res.rtt_max = min(tempos), statistics.fmean(tempos), max(tempos)
    ui.espaco()
    if res.recebidos:
        ui.ok(f"{res.recebidos}/{contagem} respostas | perda {res.perda:.0f}% | min {res.rtt_min:.0f} ms | media {res.rtt_avg:.0f} ms | max {res.rtt_max:.0f} ms")
    else:
        ui.erro(f"Sem resposta de {alvo}.")
    return res


# Constantes de cor usadas acima (evita import circular de ui).
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
