"""Teste de portas TCP: diferencia servico parado, firewall e host fora do ar."""

from __future__ import annotations

import errno
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Optional

from .report import Report

AREA = "rede-portas"

SERVICOS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "SQL Server",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    6379: "Redis",
    8080: "HTTP alternativo",
    8443: "HTTPS alternativo",
    9000: "App/Portainer",
}

_PORTAS_PADRAO = "80,443,22,3389"


def parse_portas(texto: str) -> list[int]:
    """Aceita '80,443', '1-1024', '22 80' e misturas; devolve ordenado e unico."""
    portas: set[int] = set()
    for parte in (texto or "").replace(";", ",").replace(" ", ",").split(","):
        parte = parte.strip()
        if not parte:
            continue
        if "-" in parte:
            inicio, _, fim = parte.partition("-")
            try:
                a, b = int(inicio), int(fim)
            except ValueError:
                continue
            if a > b:
                a, b = b, a
            for porta in range(max(1, a), min(65535, b) + 1):
                portas.add(porta)
        else:
            try:
                porta = int(parte)
            except ValueError:
                continue
            if 1 <= porta <= 65535:
                portas.add(porta)
    return sorted(portas)


def portas_padrao() -> list[int]:
    return parse_portas(_PORTAS_PADRAO)


def _status_por_erro(exc: BaseException) -> str:
    if isinstance(exc, socket.timeout):
        return "filtrada"
    if isinstance(exc, ConnectionRefusedError):
        return "fechada"
    if isinstance(exc, OSError):
        if exc.errno in (errno.ECONNREFUSED, 10061):
            return "fechada"
        if exc.errno in (errno.ETIMEDOUT, 10060):
            return "filtrada"
        if exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, 10051, 10065):
            return "inacessivel"
        texto = str(exc).lower()
        if "refused" in texto or "recus" in texto:
            return "fechada"
        if "timed out" in texto or "tempo" in texto:
            return "filtrada"
    return "erro"


def _testar_porta(ip: str, porta: int, timeout: float) -> dict[str, Any]:
    inicio = time.perf_counter()
    try:
        with socket.create_connection((ip, porta), timeout=timeout):
            return {
                "porta": porta,
                "servico": SERVICOS.get(porta, ""),
                "estado": "aberta",
                "ms": (time.perf_counter() - inicio) * 1000,
            }
    except BaseException as exc:  # noqa: BLE001 - convertido em estado
        return {
            "porta": porta,
            "servico": SERVICOS.get(porta, ""),
            "estado": _status_por_erro(exc),
            "ms": (time.perf_counter() - inicio) * 1000,
            "erro": str(exc),
        }


def testar(host: str, portas: Optional[list[int]] = None, timeout: float = 2.0,
           workers: int = 32) -> dict[str, Any]:
    """Resolve o host e testa todas as portas em paralelo."""
    portas = portas or portas_padrao()
    resultado: dict[str, Any] = {
        "host": host,
        "ip": "",
        "portas": [],
        "erro": "",
        "abertas": 0,
        "fechadas": 0,
        "filtradas": 0,
    }
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        ip = ""
        for familia, _, _, _, sockaddr in infos:
            if familia == socket.AF_INET:
                ip = sockaddr[0]
                break
        if not ip and infos:
            ip = infos[0][4][0]
        if not ip:
            raise OSError("host sem endereco IP")
        resultado["ip"] = ip
    except OSError as exc:
        resultado["erro"] = f"Nao foi possivel resolver '{host}': {exc}"
        return resultado

    itens: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(portas) or 1))) as pool:
        futuros = {pool.submit(_testar_porta, resultado["ip"], p, timeout): p for p in portas}
        for futuro in as_completed(futuros):
            itens.append(futuro.result())
    itens.sort(key=lambda i: i["porta"])
    resultado["portas"] = itens
    resultado["abertas"] = sum(1 for i in itens if i["estado"] == "aberta")
    resultado["fechadas"] = sum(1 for i in itens if i["estado"] == "fechada")
    resultado["filtradas"] = sum(1 for i in itens if i["estado"] == "filtrada")
    return resultado


def resumo(resultado: dict[str, Any]) -> tuple[str, str]:
    """Retorna (gravidade, texto) para a conclusao."""
    if resultado.get("erro"):
        return "erro", resultado["erro"]
    abertas = resultado.get("abertas", 0)
    filtradas = resultado.get("filtradas", 0)
    fechadas = resultado.get("fechadas", 0)
    if abertas:
        return "ok", f"{abertas} porta(s) aberta(s): o host esta acessivel."
    if filtradas:
        return "aviso", (
            "Nenhuma porta aberta e varias sem resposta: firewall/rota bloqueando, "
            "host desligado ou IP errado."
        )
    if fechadas:
        return "aviso", (
            "O host respondeu, mas recusou todas as portas testadas: "
            "servico parado ou porta diferente."
        )
    return "info", "Nenhum resultado conclusivo."


def imprimir(resultado: dict[str, Any], ui: Any) -> None:
    ui.secao("Teste de portas")
    ui.kv("Host", f"{resultado.get('host')} {('(' + resultado['ip'] + ')') if resultado.get('ip') else ''}".strip())
    if resultado.get("erro"):
        ui.erro(resultado["erro"])
        return
    linhas = []
    for item in resultado["portas"]:
        ms = f"{item.get('ms', 0):.0f} ms"
        linhas.append([item["porta"], item.get("servico", ""), item["estado"], ms])
    ui.tabela(["Porta", "Servico", "Estado", "Tempo"], linhas)
    ui.espaco()
    ui.info(
        f"abertas: {resultado['abertas']} | fechadas: {resultado['fechadas']} | "
        f"filtradas/sem resposta: {resultado['filtradas']}"
    )
    severidade, texto = resumo(resultado)
    {"ok": ui.ok, "info": ui.info, "aviso": ui.aviso, "erro": ui.erro}.get(severidade, ui.info)(texto)


def relatorio(resultado: dict[str, Any]) -> Report:
    severidade, texto = resumo(resultado)
    r = Report("Teste de portas TCP", area=AREA)
    r.meta["Resumo"] = texto
    r.meta["Host"] = f"{resultado.get('host')} {resultado.get('ip') or ''}".strip()
    r.h2("Resumo")
    r.p(texto)
    r.h2("Portas testadas")
    r.tabela(
        ["Porta", "Servico", "Estado", "Tempo (ms)"],
        [[i["porta"], i.get("servico", ""), i["estado"], f"{i.get('ms', 0):.0f}"]
         for i in resultado.get("portas", [])],
    )
    r.h2("Como interpretar")
    r.lista(
        [
            "aberta: algo esta atendendo na porta.",
            "fechada: o host respondeu e recusou (servico parado).",
            "filtrada: sem resposta (firewall, host desligado ou IP errado).",
            "inacessivel: nao ha rota ate o host.",
        ]
    )
    return r
