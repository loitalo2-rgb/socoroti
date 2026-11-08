"""Modelos de dados compartilhados: achados, acoes e diagnosticos."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

# Ordem de gravidade: quanto maior, mais serio.
SEVERIDADE = {
    "ok": 0,
    "info": 1,
    "aviso": 2,
    "erro": 3,
    "critico": 4,
}

ROTULO_SEVERIDADE = {
    "ok": "OK",
    "info": "INFO",
    "aviso": "ATENCAO",
    "erro": "ERRO",
    "critico": "CRITICO",
}


@dataclass
class Finding:
    """Um achado do diagnostico (o que esta errado e por que)."""

    id: str
    area: str
    severity: str
    title: str
    detail: str = ""
    cause: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERIDADE:
            raise ValueError(f"severidade invalida: {self.severity}")


@dataclass
class Step:
    """Um passo executavel de uma acao de correcao."""

    desc: str
    argv: Optional[list[str]] = None
    ps: Optional[str] = None
    shell: Optional[str] = None
    ignore_error: bool = True
    timeout: int = 60


@dataclass
class Action:
    """Acao de correcao recomendada (manual ou executavel)."""

    key: str
    title: str
    why: str
    risk: str = "baixo"  # baixo | medio | alto
    needs_admin: bool = False
    manual: bool = False
    steps: list[Step] = field(default_factory=list)
    note: str = ""
    applies: str = "any"  # any | windows | linux


@dataclass
class Diagnosis:
    """Resultado completo de um diagnostico."""

    area: str
    title: str
    findings: list[Finding] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    summary: str = ""

    @property
    def pior(self) -> str:
        pior = "ok"
        for f in self.findings:
            if SEVERIDADE[f.severity] > SEVERIDADE[pior]:
                pior = f.severity
        return pior

    def por_severidade(self, minimo: str = "info") -> list[Finding]:
        limite = SEVERIDADE[minimo]
        return [f for f in self.findings if SEVERIDADE[f.severity] >= limite]

    def contagem(self) -> dict[str, int]:
        out = {k: 0 for k in SEVERIDADE}
        for f in self.findings:
            out[f.severity] += 1
        return out


def ordenar_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: -SEVERIDADE[f.severity])


def deduplicar_acoes(acoes: list[Action]) -> list[Action]:
    vistos: set[str] = set()
    saida: list[Action] = []
    for a in acoes:
        if a.key in vistos:
            continue
        vistos.add(a.key)
        saida.append(a)
    return saida
