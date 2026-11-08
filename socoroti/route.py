"""Descoberta de rota (traceroute) com interpretacao do ponto de falha."""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass
from typing import Any, Optional

from .model import Diagnosis, Finding
from .report import Report
from .runner import IS_WINDOWS, Runner

AREA = "rede-rota"

_RE_HOP = re.compile(r"^\s*(\d+)\??:?\s+(.+)$")
_RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_MS = re.compile(r"<?\s*(\d+(?:[.,]\d+)?)\s*ms", re.I)


@dataclass
class Hop:
    numero: int
    ip: str = ""
    ms: Optional[float] = None
    timeouts: int = 0

    @property
    def respondeu(self) -> bool:
        return bool(self.ip)


def parse_rota(texto: str) -> list[Hop]:
    """Interpreta tracert (Windows), traceroute e tracepath (Linux)."""
    hops: list[Hop] = []
    vistos: set[int] = set()
    for linha in texto.splitlines():
        m = _RE_HOP.match(linha)
        if not m:
            continue
        numero = int(m.group(1))
        if numero <= 0 or numero > 255 or numero in vistos:
            continue
        resto = m.group(2)
        # Linhas de resumo/cabecalho que comecam com numero nao tem ms nem "*".
        ips = _RE_IP.findall(resto)
        tempos = [float(x.replace(",", ".")) for x in _RE_MS.findall(resto)]
        timeouts = resto.count("*")
        if not ips and not tempos and not timeouts:
            # tracepath pode mostrar o hostname sem IP.
            primeiro = resto.split()[0] if resto.split() else ""
            if not primeiro or primeiro.lower() in ("no", "sem", "limit"):
                continue
        vistos.add(numero)
        hops.append(
            Hop(
                numero=numero,
                ip=ips[0] if ips else "",
                ms=(sum(tempos) / len(tempos)) if tempos else None,
                timeouts=timeouts,
            )
        )
    hops.sort(key=lambda h: h.numero)
    return hops


def resolver(alvo: str) -> str:
    try:
        infos = socket.getaddrinfo(alvo, None, proto=socket.IPPROTO_TCP)
        for familia, _, _, _, sockaddr in infos:
            if familia == socket.AF_INET:
                return sockaddr[0]
    except OSError:
        pass
    return ""


def analisar(hops: list[Hop], alvo: str, ip_alvo: str = "") -> Diagnosis:
    diag = Diagnosis(area=AREA, title="Rota ate o destino")
    diag.data = {
        "Alvo": alvo,
        "IP do alvo": ip_alvo or "(nao resolvido)",
        "Saltos": [
            {"salto": h.numero, "ip": h.ip or "*", "ms": h.ms, "timeouts": h.timeouts}
            for h in hops
        ],
    }
    achados: list[Finding] = []

    if not hops:
        achados.append(
            Finding(
                id="rota_sem_dados",
                area=AREA,
                severity="erro",
                title="Nenhum salto foi registrado",
                detail="O comando de rota nao retornou dados. Pode estar ausente ou bloqueado.",
                cause="traceroute/tracert indisponivel ou ICMP filtrado na origem.",
            )
        )
        diag.findings = achados
        diag.summary = "Nao foi possivel mapear a rota ate o destino."
        return diag

    respondidos = [h for h in hops if h.respondeu]
    alcancou = bool(ip_alvo) and any(h.ip == ip_alvo for h in hops)
    ultimo = respondidos[-1] if respondidos else None
    primeiro_mudo = next((h for h in hops if not h.respondeu), None)

    if alcancou:
        achados.append(
            Finding(
                id="rota_ok",
                area=AREA,
                severity="ok",
                title="Rota completa ate o destino",
                detail=f"{alvo} respondeu no salto "
                       f"{next(h.numero for h in hops if h.ip == ip_alvo)}.",
                cause="Nenhum problema de roteamento detectado.",
            )
        )
        diag.summary = f"A rota chega ao destino em {len(hops)} salto(s) sem falhas."
    elif not respondidos:
        achados.append(
            Finding(
                id="rota_muda",
                area=AREA,
                severity="erro",
                title="Nenhum salto respondeu",
                detail="Todos os saltos ficaram mudos (timeout).",
                cause="Sem rota, link local quebrado ou ICMP bloqueado por politica de rede.",
            )
        )
        diag.summary = "Nem o primeiro salto respondeu: verifique o link local antes de culpar o provedor."
    else:
        numero = ultimo.numero if ultimo else 0
        if numero <= 1:
            sev, onde, causa = "erro", "na sua rede local", "gateway/roteador local ou cabo/Wi-Fi."
        elif numero <= 3:
            sev, onde, causa = "erro", "no comeco do caminho do provedor", "link/roteador do provedor ou modem."
        else:
            sev, onde, causa = "aviso", "fora da sua rede", "rota externa, peer ou destino distante."
        achados.append(
            Finding(
                id="rota_parcial",
                area=AREA,
                severity=sev,
                title=f"Rota para no salto {numero} ({ultimo.ip if ultimo else '?'})",
                detail=(
                    f"Ultimo salto que respondeu: {numero} ({ultimo.ip if ultimo else '?'}). "
                    f"Depois disso, sem resposta."
                    if ultimo else "Sem saltos respondendo."
                ),
                cause=f"Falha {onde}: {causa}",
            )
        )
        if primeiro_mudo and primeiro_mudo.numero < numero:
            achados.append(
                Finding(
                    id="rota_buraco",
                    area=AREA,
                    severity="info",
                    title=f"Salto {primeiro_mudo.numero} nao responde, mas saltos seguintes sim",
                    detail="Alguns roteadores nao respondem a ICMP de proposito.",
                    cause="Nao indica falha: e comum em redes que filtram ICMP.",
                )
            )
        diag.summary = (
            f"A conexao chega ate o salto {numero} ({ultimo.ip if ultimo else '?'}) e para. "
            f"Provavel problema {onde}."
        )

    # Latencia por salto: destaca saltos muito lentos.
    lentos = [h for h in respondidos if h.ms is not None and h.ms > 200]
    if lentos:
        pior = max(lentos, key=lambda h: h.ms or 0)
        achados.append(
            Finding(
                id="rota_lenta",
                area=AREA,
                severity="aviso",
                title=f"Salto {pior.numero} com latencia alta ({pior.ms:.0f} ms)",
                detail=f"{pior.ip}: media {pior.ms:.0f} ms.",
                cause="Congestionamento no salto ou enlace lento.",
            )
        )

    diag.findings = achados
    return diag


def executar(runner: Runner, alvo: str, max_saltos: int = 20) -> tuple[list[Hop], str]:
    """Executa a melhor ferramenta disponivel e devolve saltos + comando usado."""
    ip_alvo = resolver(alvo)
    if IS_WINDOWS:
        res = runner.run(
            ["tracert", "-d", "-h", str(max_saltos), "-w", "1000", alvo],
            timeout=max(60, max_saltos * 4),
        )
        return parse_rota(res.out + "\n" + res.err), "tracert"

    if runner.which("traceroute"):
        res = runner.run(
            ["traceroute", "-n", "-m", str(max_saltos), "-w", "2", "-q", "1", alvo],
            timeout=max(60, max_saltos * 4),
        )
        return parse_rota(res.out + "\n" + res.err), "traceroute"
    if runner.which("tracepath"):
        res = runner.run(["tracepath", "-n", alvo], timeout=max(60, max_saltos * 4))
        return parse_rota(res.out + "\n" + res.err), "tracepath"
    if runner.which("mtr"):
        res = runner.run(
            ["mtr", "-n", "-r", "-c", "1", "-m", str(max_saltos), alvo],
            timeout=max(90, max_saltos * 5),
        )
        return parse_rota(res.out + "\n" + res.err), "mtr"
    return [], "nenhum"


def imprimir(diag: Diagnosis, ui: Any, comando: str = "") -> None:
    dados = diag.data
    ui.secao("Rota")
    ui.kv("Alvo", f"{dados.get('Alvo')}" + (f" ({dados['IP do alvo']})" if dados.get("IP do alvo") and dados.get("IP do alvo") != dados.get("Alvo") else ""))
    if comando:
        ui.kv("Ferramenta", comando)
    linhas = []
    for h in dados.get("Saltos", []):
        status = "sem resposta" if h.get("ip") == "*" else "respondeu"
        ms = "-" if h.get("ms") is None else f"{h['ms']:.0f} ms"
        linhas.append([h.get("salto"), h.get("ip"), ms, status])
    if linhas:
        ui.tabela(["Salto", "IP", "Latencia", "Estado"], linhas)
    ui.secao("Diagnostico")
    for f in diag.findings:
        if f.severity == "ok":
            ui.ok(f.title)
        elif f.severity == "info":
            ui.info(f.title)
        elif f.severity == "aviso":
            ui.aviso(f.title)
        else:
            ui.erro(f.title)
        if f.detail:
            ui.escrever("      " + ui.paint(f.detail, "\033[2m"))
        if f.cause:
            ui.escrever("      " + ui.paint("causa: " + f.cause, "\033[2m"))
    if diag.summary:
        ui.espaco()
        ui.escrever("  " + ui.paint("RESUMO: ", "\033[1m") + diag.summary)


def relatorio(diag: Diagnosis, comando: str = "") -> Report:
    r = Report("Rota ate o destino", area=AREA)
    r.meta["Resumo"] = diag.summary
    r.meta["Ferramenta"] = comando
    r.h2("Resumo")
    r.p(diag.summary)
    r.h2("Saltos")
    r.tabela(
        ["Salto", "IP", "Latencia (ms)", "Timeouts"],
        [
            [h.get("salto"), h.get("ip"), h.get("ms", "-"), h.get("timeouts", 0)]
            for h in diag.data.get("Saltos", [])
        ],
    )
    r.h2("Diagnostico")
    r.findings(diag.findings)
    return r
