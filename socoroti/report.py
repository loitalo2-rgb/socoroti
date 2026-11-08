"""Geracao de relatorios em Markdown/JSON, prontos para anexar em chamados."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Optional

from . import __version__, platform_info
from .model import Action, Diagnosis, Finding, ROTULO_SEVERIDADE, ordenar_findings

_ICONE_MD = {
    "ok": "OK",
    "info": "INFO",
    "aviso": "ATENCAO",
    "erro": "ERRO",
    "critico": "CRITICO",
}


def _celula(texto: object) -> str:
    return str(texto if texto is not None else "").replace("|", "\\|").replace("\n", " ")


def tabela_md(cabecalho: list[str], linhas: Iterable[Iterable[object]]) -> str:
    saida = ["| " + " | ".join(_celula(c) for c in cabecalho) + " |"]
    saida.append("|" + "|".join(["---"] * len(cabecalho)) + "|")
    for linha in linhas:
        saida.append("| " + " | ".join(_celula(c) for c in linha) + " |")
    return "\n".join(saida)


class Report:
    def __init__(self, titulo: str, area: str = "geral") -> None:
        self.titulo = titulo
        self.area = area
        self.blocos: list[str] = []
        self.meta: dict[str, Any] = {}

    def h1(self, texto: str) -> None:
        self.blocos.append(f"# {texto}")

    def h2(self, texto: str) -> None:
        self.blocos.append(f"## {texto}")

    def h3(self, texto: str) -> None:
        self.blocos.append(f"### {texto}")

    def p(self, texto: str) -> None:
        self.blocos.append(texto)

    def lista(self, itens: Iterable[str]) -> None:
        self.blocos.append("\n".join(f"- {i}" for i in itens))

    def codigo(self, texto: str, linguagem: str = "") -> None:
        self.blocos.append(f"```{linguagem}\n{texto.rstrip()}\n```")

    def tabela(self, cabecalho: list[str], linhas: Iterable[Iterable[object]]) -> None:
        self.blocos.append(tabela_md(cabecalho, linhas))

    def findings(self, findings: list[Finding]) -> None:
        if not findings:
            return
        for f in ordenar_findings(findings):
            self.blocos.append(f"**[{_ICONE_MD[f.severity]}] {f.title}**")
            if f.detail:
                self.blocos.append(f.detail)
            if f.cause:
                self.blocos.append(f"*Causa provavel:* {f.cause}")
            self.blocos.append("")

    def acoes(self, acoes: list[Action]) -> None:
        if not acoes:
            return
        for i, a in enumerate(acoes, 1):
            risco = {"baixo": "baixo", "medio": "medio", "alto": "alto"}.get(a.risk, a.risk)
            self.blocos.append(f"**{i}. {a.title}** (risco {risco})")
            if a.why:
                self.blocos.append(a.why)
            if a.manual:
                self.blocos.append("_Acao assistida (o SocorroTI mostra o caminho, nao executa)._")
            for passo in a.steps:
                if passo.desc:
                    self.blocos.append(f"- {passo.desc}")
                if passo.ps:
                    self.codigo(passo.ps, "powershell")
                if passo.argv:
                    self.codigo(" ".join(passo.argv), "bash")
                if passo.shell:
                    self.codigo(passo.shell, "bash")
            if a.note:
                self.blocos.append(f"> {a.note}")
            self.blocos.append("")

    def render(self) -> str:
        partes: list[str] = []
        meta = {
            "Gerado em": platform_info.agora(),
            "Maquina": platform_info.hostname(),
            "Sistema": platform_info.nome_sistema(),
            "Usuario": platform_info.usuario(),
            "Administrador": "sim" if platform_info.eh_admin() else "nao",
            "SocorroTI": __version__,
        }
        meta.update(self.meta)
        partes.append(f"# {self.titulo}")
        partes.append(
            tabela_md(["Campo", "Valor"], [[k, v] for k, v in meta.items()])
        )
        partes.append("")
        partes.extend(self.blocos)
        return "\n\n".join(partes).rstrip() + "\n"

    def salvar(self, prefixo: Optional[str] = None) -> Path:
        nome = prefixo or f"{self.area}-{platform_info.selo_tempo()}"
        if not nome.endswith(".md"):
            nome += ".md"
        destino = platform_info.pasta_relatorios() / nome
        destino.write_text(self.render(), encoding="utf-8")
        return destino


def relatorio_diagnostico(diag: Diagnosis) -> Report:
    r = Report(diag.title, area=diag.area)
    r.meta["Resumo"] = diag.summary or ""
    r.h2("Resumo")
    r.p(diag.summary or "Sem resumo.")
    r.h2("Achados")
    if diag.findings:
        r.tabela(
            ["Gravidade", "Achado", "Detalhe", "Causa provavel"],
            [
                [_ICONE_MD[f.severity], f.title, f.detail, f.cause]
                for f in ordenar_findings(diag.findings)
            ],
        )
    else:
        r.p("Nenhum achado registrado.")
    if diag.actions:
        r.h2("Plano de acao")
        r.acoes(diag.actions)
    if diag.data:
        r.h2("Dados coletados")
        for chave, valor in diag.data.items():
            r.h3(str(chave))
            if isinstance(valor, (dict, list)):
                r.codigo(json.dumps(valor, ensure_ascii=False, indent=2, default=str), "json")
            else:
                r.p(str(valor))
    return r


def salvar_json(dados: Any, prefixo: str) -> Path:
    nome = prefixo if prefixo.endswith(".json") else prefixo + ".json"
    destino = platform_info.pasta_relatorios() / nome
    destino.write_text(json.dumps(dados, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return destino
