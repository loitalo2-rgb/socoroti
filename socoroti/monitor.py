"""Monitor de estabilidade da conexao ao longo do tempo.

O diagnostico normal e uma foto. Este modulo acompanha a rede por varios
minutos, registra cada amostra e responde a pergunta que mais aparece no
plantao: "a internet cai de vez em quando".

A leitura separa dois cenarios:

- falha tambem no gateway  -> problema local (cabo, Wi-Fi, roteador);
- gateway OK, alvo falha   -> problema do provedor/rota externa.

Tambem salva as amostras em CSV, que servem como prova para o chamado.
"""

from __future__ import annotations

import csv
import statistics
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

from . import net, platform_info
from .report import Report

AREA = "rede-monitor"


@dataclass
class Amostra:
    """Uma leitura pontual da conexao."""

    instante: float
    alvo_ok: bool = False
    alvo_ms: Optional[float] = None
    gateway_testado: bool = False
    gateway_ok: bool = False
    gateway_ms: Optional[float] = None


def _quedas(amostras: list[Amostra], campo_ok: str, intervalo: float) -> list[dict[str, Any]]:
    """Agrupa falhas consecutivas em quedas com inicio, fim e duracao."""
    quedas: list[dict[str, Any]] = []
    i = 0
    n = len(amostras)
    while i < n:
        if getattr(amostras[i], campo_ok):
            i += 1
            continue
        inicio = i
        while i < n and not getattr(amostras[i], campo_ok):
            i += 1
        fim = i  # exclusivo
        quedas.append(
            {
                "inicio": amostras[inicio].instante,
                "fim": amostras[fim - 1].instante + intervalo,
                "duracao_s": (fim - inicio) * intervalo,
                "amostras": fim - inicio,
            }
        )
    return quedas


def duracao_legivel(segundos: float) -> str:
    if segundos < 90:
        return f"{segundos:.0f} s"
    if segundos < 5400:
        return f"{segundos / 60:.0f} min"
    return f"{segundos / 3600:.1f} h"


def _stats(valores: list[float]) -> dict[str, Optional[float]]:
    if not valores:
        return {"min": None, "avg": None, "max": None, "jitter": None}
    jitter = None
    if len(valores) > 1:
        variacoes = [abs(valores[i] - valores[i - 1]) for i in range(1, len(valores))]
        jitter = statistics.fmean(variacoes)
    return {
        "min": min(valores),
        "avg": statistics.fmean(valores),
        "max": max(valores),
        "jitter": jitter,
    }


def analisar(
    amostras: list[Amostra],
    intervalo: float,
    alvo: str = "1.1.1.1",
    gateway: str = "",
) -> dict[str, Any]:
    """Transforma as amostras em um resumo com conclusao e gravidade."""
    n = len(amostras)
    if n == 0:
        return {
            "amostras": 0,
            "duracao_s": 0.0,
            "alvo": alvo,
            "gateway": gateway,
            "perda_alvo_pct": 0.0,
            "perda_gateway_pct": None,
            "quedas": [],
            "quedas_gateway": [],
            "tempo_fora_s": 0.0,
            "rtt_min": None,
            "rtt_avg": None,
            "rtt_max": None,
            "jitter_ms": None,
            "severidade": "info",
            "titulo": "Nenhuma amostra coletada",
            "causa": "",
            "conclusao": "O monitor nao chegou a coletar dados.",
        }

    gw = [a for a in amostras if a.gateway_testado]
    perda_alvo = 100.0 * sum(1 for a in amostras if not a.alvo_ok) / n
    perda_gw = 100.0 * sum(1 for a in gw if not a.gateway_ok) / len(gw) if gw else None

    quedas_alvo = _quedas(amostras, "alvo_ok", intervalo)
    quedas_gw = _quedas(amostras, "gateway_ok", intervalo) if gw else []

    # Uma queda do alvo e "local" se, nas mesmas amostras, o gateway tambem caiu.
    for queda in quedas_alvo:
        locais = [
            a for a in amostras
            if queda["inicio"] <= a.instante <= queda["fim"] and a.gateway_testado
        ]
        queda["escopo"] = "local" if any(not a.gateway_ok for a in locais) else "externa"

    tempo_fora = sum(q["duracao_s"] for q in quedas_alvo)
    stats = _stats([a.alvo_ms for a in amostras if a.alvo_ok and a.alvo_ms is not None])

    severidade = "ok"
    titulo = "Conexao estavel durante o monitoramento"
    causa = ""
    conclusao = (
        f"{n} amostras em {duracao_legivel(n * intervalo)}: nenhuma queda e latencia dentro do esperado."
    )

    rtt_max = stats["max"]
    jitter = stats["jitter"]
    if perda_gw is not None and perda_gw >= 1:
        if perda_gw >= 50:
            severidade = "critico"
        elif perda_gw >= 10:
            severidade = "erro"
        else:
            severidade = "aviso"
        titulo = f"Falhas tambem no gateway ({perda_gw:.0f}% das amostras)"
        causa = "Rede local: cabo, porta do switch, Wi-Fi ou roteador sobrecarregado."
        conclusao = (
            "O roteador/gateway deixou de responder junto com a internet. "
            "Isso indica problema local (cabo/Wi-Fi/roteador), nao no provedor."
        )
    elif perda_alvo >= 1:
        if perda_alvo >= 10:
            severidade = "erro"
        else:
            severidade = "aviso"
        titulo = f"Quedas de internet ({perda_alvo:.0f}% das amostras)"
        causa = "Link do provedor, modem/WAN ou rota externa instavel."
        conclusao = (
            "O gateway continuou respondendo enquanto a internet falhou. "
            "O problema esta depois do roteador: provedor, modem ou rota externa."
        )
    elif (rtt_max is not None and rtt_max > 150) or (jitter is not None and jitter > 40):
        severidade = "aviso"
        titulo = "Conexao sem quedas, mas com latencia alta"
        causa = "Congestionamento, Wi-Fi ruim ou rota distante."
        conclusao = (
            f"Sem perda de pacotes, porem a latencia chegou a {rtt_max:.0f} ms "
            f"(jitter {jitter:.0f} ms). Videochamadas e acesso remoto podem travar."
        )

    return {
        "amostras": n,
        "duracao_s": n * intervalo,
        "alvo": alvo,
        "gateway": gateway,
        "perda_alvo_pct": round(perda_alvo, 1),
        "perda_gateway_pct": None if perda_gw is None else round(perda_gw, 1),
        "quedas": quedas_alvo,
        "quedas_gateway": quedas_gw,
        "tempo_fora_s": tempo_fora,
        "rtt_min": None if stats["min"] is None else round(stats["min"], 1),
        "rtt_avg": None if stats["avg"] is None else round(stats["avg"], 1),
        "rtt_max": None if stats["max"] is None else round(stats["max"], 1),
        "jitter_ms": None if stats["jitter"] is None else round(stats["jitter"], 1),
        "severidade": severidade,
        "titulo": titulo,
        "causa": causa,
        "conclusao": conclusao,
    }


def monitorar(
    runner: net.Runner,
    alvo: str,
    duracao: float,
    intervalo: float,
    gateway: Optional[str] = None,
    ao_amostrar: Optional[Callable[[Amostra, int, int], None]] = None,
    dormir: Callable[[float], None] = time.sleep,
) -> list[Amostra]:
    """Coleta amostras de ping ate completar a duracao; Ctrl+C encerra e devolve o parcial."""
    amostras: list[Amostra] = []
    total = max(1, int(duracao / max(0.5, intervalo)))
    inicio = time.time()
    timeout_ms = int(max(500, min(5000, intervalo * 1000)))
    try:
        for indice in range(total):
            instante = time.time()
            amostra = Amostra(instante=instante)
            p_alvo = net.ping(runner, alvo, 1, timeout_ms=timeout_ms)
            amostra.alvo_ok = bool(p_alvo.recebidos)
            amostra.alvo_ms = p_alvo.rtt_avg if amostra.alvo_ok else None
            if gateway:
                p_gw = net.ping(runner, gateway, 1, timeout_ms=timeout_ms)
                amostra.gateway_testado = True
                amostra.gateway_ok = bool(p_gw.recebidos)
                amostra.gateway_ms = p_gw.rtt_avg if amostra.gateway_ok else None
            amostras.append(amostra)
            if ao_amostrar:
                ao_amostrar(amostra, indice + 1, total)
            if indice < total - 1:
                restante = (inicio + (indice + 1) * intervalo) - time.time()
                dormir(max(0.0, restante))
    except KeyboardInterrupt:
        # Encerra limpo: o que ja foi coletado vira relatorio.
        pass
    return amostras


# --------------------------------------------------------------------------- saida
def _hora(epoch: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(epoch))


def imprimir_amostra(amostra: Amostra, indice: int, total: int, alvo: str, gateway: str, ui: Any) -> None:
    def fmt(ok: bool, ms: Optional[float]) -> str:
        if not ok:
            return ui.paint("FALHA", "\033[31m")
        valor = "-" if ms is None else f"{ms:.0f} ms"
        cor = "\033[32m" if (ms or 0) < 80 else "\033[33m" if (ms or 0) < 200 else "\033[31m"
        return ui.paint(valor, cor)

    partes = [f"  {indice:>4}/{total}", _hora(amostra.instante)]
    if amostra.gateway_testado:
        partes.append(f"gw {gateway}: {fmt(amostra.gateway_ok, amostra.gateway_ms)}")
    partes.append(f"{alvo}: {fmt(amostra.alvo_ok, amostra.alvo_ms)}")
    ui.escrever("  ".join(partes))


def imprimir_analise(resumo: dict[str, Any], ui: Any) -> None:
    ui.secao("Resumo do monitoramento")
    ui.kv("Amostras", f"{resumo['amostras']} em {duracao_legivel(resumo['duracao_s'])}")
    ui.kv("Perda para o alvo", f"{resumo['perda_alvo_pct']:.0f}%")
    if resumo.get("perda_gateway_pct") is not None:
        ui.kv("Perda no gateway", f"{resumo['perda_gateway_pct']:.0f}%")
    if resumo.get("rtt_avg") is not None:
        ui.kv(
            "Latencia",
            f"min {resumo['rtt_min']:.0f} ms | media {resumo['rtt_avg']:.0f} ms | "
            f"max {resumo['rtt_max']:.0f} ms | jitter {resumo['jitter_ms']:.0f} ms",
        )
    quedas = resumo.get("quedas") or []
    ui.kv("Quedas", f"{len(quedas)} | tempo fora {resumo['tempo_fora_s']:.0f} s")
    if quedas:
        ui.espaco()
        ui.tabela(
            ["Inicio", "Fim", "Duracao", "Escopo"],
            [[_hora(q["inicio"]), _hora(q["fim"]), f"{q['duracao_s']:.0f} s", q.get("escopo", "?")]
             for q in quedas],
        )
    ui.espaco()
    sev = resumo["severidade"]
    texto = resumo["titulo"]
    {"ok": ui.ok, "info": ui.info, "aviso": ui.aviso, "erro": ui.erro, "critico": ui.critico}.get(
        sev, ui.info
    )(texto)
    if resumo.get("causa"):
        ui.escrever("      " + ui.paint("causa: " + resumo["causa"], "\033[2m"))
    ui.escrever("  " + ui.paint("CONCLUSAO: ", "\033[1m") + resumo["conclusao"])


def salvar_csv(amostras: list[Amostra], destino) -> Any:
    destino.parent.mkdir(parents=True, exist_ok=True)
    with open(destino, "w", newline="", encoding="utf-8") as fh:
        escritor = csv.writer(fh, delimiter=";")
        escritor.writerow(
            ["instante", "gateway_testado", "gateway_ok", "gateway_ms", "alvo_ok", "alvo_ms"]
        )
        for a in amostras:
            escritor.writerow(
                [
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a.instante)),
                    int(a.gateway_testado),
                    int(a.gateway_ok),
                    "" if a.gateway_ms is None else f"{a.gateway_ms:.1f}",
                    int(a.alvo_ok),
                    "" if a.alvo_ms is None else f"{a.alvo_ms:.1f}",
                ]
            )
    return destino


def relatorio(resumo: dict[str, Any], amostras: list[Amostra]) -> Report:
    r = Report("Monitor de estabilidade da rede", area=AREA)
    r.meta["Resumo"] = resumo["titulo"]
    r.meta["Alvo"] = resumo["alvo"]
    if resumo.get("gateway"):
        r.meta["Gateway"] = resumo["gateway"]
    r.h2("Conclusao")
    r.p(resumo["conclusao"])
    if resumo.get("causa"):
        r.p(f"**Causa provavel:** {resumo['causa']}")
    r.h2("Resumo")
    r.tabela(
        ["Metrica", "Valor"],
        [
            ["Amostras", f"{resumo['amostras']} em {duracao_legivel(resumo['duracao_s'])}"],
            ["Perda para o alvo", f"{resumo['perda_alvo_pct']:.0f}%"],
            ["Perda no gateway", "-" if resumo.get("perda_gateway_pct") is None else f"{resumo['perda_gateway_pct']:.0f}%"],
            ["Latencia media", "-" if resumo.get("rtt_avg") is None else f"{resumo['rtt_avg']:.0f} ms"],
            ["Latencia maxima", "-" if resumo.get("rtt_max") is None else f"{resumo['rtt_max']:.0f} ms"],
            ["Jitter", "-" if resumo.get("jitter_ms") is None else f"{resumo['jitter_ms']:.0f} ms"],
            ["Quedas", f"{len(resumo.get('quedas') or [])} ({resumo['tempo_fora_s']:.0f} s fora)"],
        ],
    )
    quedas = resumo.get("quedas") or []
    if quedas:
        r.h2("Quedas registradas")
        r.tabela(
            ["Inicio", "Fim", "Duracao (s)", "Escopo"],
            [[_hora(q["inicio"]), _hora(q["fim"]), f"{q['duracao_s']:.0f}", q.get("escopo", "?")]
             for q in quedas],
        )
    r.h2("Amostras")
    r.tabela(
        ["Instante", "Gateway", "Alvo"],
        [
            [
                time.strftime("%d/%m %H:%M:%S", time.localtime(a.instante)),
                ("-" if not a.gateway_testado else ("ok" if a.gateway_ok else "FALHA")),
                ("ok" if a.alvo_ok else "FALHA"),
            ]
            for a in amostras
        ],
    )
    r.p("Amostras completas tambem podem ser salvas em CSV com `socorro rede monitor --csv`.")
    r.p(f"Gerado por SocorroTI em {platform_info.hostname()}.")
    return r
