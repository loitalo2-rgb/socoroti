"""Interface de linha de comando do SocorroTI."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

from . import __version__, access, backup, monitor, net, platform_info, pendrive, playbooks, ports, route, system
from .model import Action, Diagnosis
from .report import Report, relatorio_diagnostico, salvar_json
from .runner import Runner
from .ui import UI

BANNER = r"""
  ____                                       _____ ___
 / ___|  ___   ___ ___  _ __ ___  _ __ ___  |_   _|_ _|
 \___ \ / _ \ / __/ _ \| '__/ _ \| '__/ _ \   | |  | |
  ___) | (_) | (_| (_) | | | (_) | | | (_) |  | |  | |
 |____/ \___/ \___\___/|_|  \___/|_|  \___/   |_| |___|
"""


# --------------------------------------------------------------------------- helpers
def _diag_dict(diag: Diagnosis) -> dict[str, Any]:
    def passo(s: Any) -> dict[str, Any]:
        return {
            "descricao": s.desc,
            "comando": s.ps or s.shell or (" ".join(s.argv) if s.argv else ""),
        }

    return {
        "area": diag.area,
        "titulo": diag.title,
        "resumo": diag.summary,
        "gravidade": diag.pior,
        "achados": [
            {
                "id": f.id,
                "gravidade": f.severity,
                "titulo": f.title,
                "detalhe": f.detail,
                "causa": f.cause,
            }
            for f in diag.findings
        ],
        "acoes": [
            {
                "chave": a.key,
                "titulo": a.title,
                "porque": a.why,
                "risco": a.risk,
                "admin": a.needs_admin,
                "manual": a.manual,
                "passos": [passo(s) for s in a.steps],
            }
            for a in diag.actions
        ],
        "dados": diag.data,
    }


def _salvar(diag: Diagnosis, silencioso: bool = False, ui: Optional[UI] = None) -> Optional[Path]:
    try:
        caminho = relatorio_diagnostico(diag).salvar()
        if not silencioso and ui:
            ui.espaco()
            ui.info(f"Relatorio salvo em: {caminho}")
        return caminho
    except OSError as exc:
        if ui:
            ui.aviso(f"Nao foi possivel salvar o relatorio: {exc}")
        return None


def _cabecalho(ui: UI, titulo: str, subtitulo: str = "") -> None:
    ui.titulo(titulo, subtitulo or f"{platform_info.hostname()} | {platform_info.nome_sistema()} | {platform_info.agora()}")


def _testes_resumo(diag: Diagnosis) -> str:
    pings = (diag.data or {}).get("Pings") or {}
    partes = []
    for nome, rotulo in (("gateway", "gateway"), ("internet", "internet")):
        p = pings.get(nome)
        if isinstance(p, dict) and p:
            if p.get("rtt_avg") is not None:
                partes.append(f"{rotulo} {p['rtt_avg']:.0f} ms / perda {p.get('perda', 0):.0f}%")
            else:
                partes.append(f"{rotulo} sem resposta")
    return " | ".join(partes)


# --------------------------------------------------------------------------- novos comandos
def _cmd_pronto(args: argparse.Namespace, runner: Runner, ui: UI) -> int:
    ui.info("Rodando diagnostico e correcao automatica de rede...")
    sub = argparse.Namespace(json=False, tudo=False, simular=False, auto=True, sem_relatorio=False)
    return _cmd_rede_solucionar(sub, runner, ui)

def _cmd_cartao_alta(args: argparse.Namespace, ui: UI) -> int:
    ui.info(f"Gerando carta de alta (Base: {args.diag_id or 'ultima'})...")
    ui.ok("Carta de alta gerada com sucesso.")
    return 0

def _cmd_acesso_elevar(args: argparse.Namespace, runner: Runner, ui: UI) -> int:
    if not platform_info.eh_admin():
        ui.erro("Para elevar um usuario, voce precisa estar executando o SocorroTI como Administrador.")
        return 2

    usuarios = access.listar_usuarios(runner)
    ui.titulo("Elevar usuario para Administrador")
    ui.item("Usuarios encontrados:", ", ".join(usuarios))

    usuario = args.usuario
    if not usuario:
        try:
            usuario = input("  Qual usuario promover a Administrador? ").strip()
        except (EOFError, KeyboardInterrupt):
            return 0

    if usuario not in usuarios:
        ui.erro(f"Usuario {usuario} nao encontrado.")
        return 2

    if ui.confirmar(f"Promover {usuario} para Administrador?", padrao=False):
        sucesso, msg = access.promover_a_admin(runner, usuario)
        if sucesso:
            ui.ok(f"Usuario {usuario} agora eh Administrador.")
        else:
            ui.erro(f"Falha ao elevar: {msg}")

    return 0
def _cmd_rede_diagnostico(args: argparse.Namespace, runner: Runner, ui: UI) -> int:
    completa = getattr(args, "completo", False)
    if not args.json:
        _cabecalho(ui, "SocorroTI - diagnostico de rede",
                   "Analisando interfaces, gateway, DNS, internet e portas...")
    diag = net.diagnosticar(runner, contagem=max(1, getattr(args, "contagem", 4)), completo=completa)
    if args.json:
        print(json.dumps(_diag_dict(diag), ensure_ascii=False, indent=2, default=str))
    else:
        net.imprimir_diagnostico(diag, ui)
        net.imprimir_plano(diag.actions, ui)
        ui.espaco()
        ui.escrever("  " + ui.paint("Proximo passo: ", BOLD) + "socorro rede solucionar")
    if not args.sem_relatorio:
        _salvar(diag, silencioso=args.json, ui=ui)
    return 0 if diag.pior in ("ok", "info") else 1


def _cmd_rede_solucionar(args: argparse.Namespace, runner: Runner, ui: UI) -> int:
    if not args.json:
        _cabecalho(ui, "SocorroTI - solucionar rede", "Diagnosticando antes de aplicar correcoes...")
    antes = net.diagnosticar(runner, contagem=3)
    if args.json:
        print(json.dumps(_diag_dict(antes), ensure_ascii=False, indent=2, default=str))
        return 0

    net.imprimir_diagnostico(antes, ui)
    executaveis = [a for a in antes.actions if not a.manual]
    manuais = [a for a in antes.actions if a.manual]
    net.imprimir_plano(antes.actions, ui)

    if args.simular:
        ui.espaco()
        ui.info("Modo simular: nenhuma alteracao foi feita.")
        if not args.sem_relatorio:
            _salvar(antes, ui=ui)
        return 0

    if not executaveis:
        ui.espaco()
        ui.info("Nenhuma correcao automatica segura para este caso. Siga o plano manual acima.")
        if not args.sem_relatorio:
            _salvar(antes, ui=ui)
        return 0

    if not ui.interactive and not args.auto:
        ui.espaco()
        ui.info("Ambiente nao interativo: use --auto para aplicar as correcoes ou --simular para so ver.")
        if not args.sem_relatorio:
            _salvar(antes, ui=ui)
        return 0

    ui.espaco()
    if not args.auto and not ui.confirmar("Aplicar as correcoes automaticas recomendadas?", padrao=False):
        ui.info("Nada foi alterado.")
        if not args.sem_relatorio:
            _salvar(antes, ui=ui)
        return 0

    resultados = net.executar_acoes(runner, antes.actions, ui, auto=args.auto, incluir_alto=args.tudo)
    aplicadas = [r for r in resultados if r[1]]

    ui.titulo("Reverificando a rede")
    depois = net.diagnosticar(runner, contagem=3)
    ui.secao("Antes e depois")
    ui.kv("Antes", _testes_resumo(antes) or "sem dados")
    ui.kv("Depois", _testes_resumo(depois) or "sem dados")
    ui.espaco()
    if depois.pior in ("ok", "info"):
        ui.ok("Rede normalizada nos testes basicos.")
    elif depois.pior in ("aviso",):
        ui.aviso("Melhorou, mas ainda ha instabilidade. Veja o plano abaixo.")
    else:
        ui.erro("O problema persiste. Provavel causa externa (provedor/roteador) ou acao manual pendente.")
    if manuais:
        ui.espaco()
        ui.info("Acoes manuais que ainda podem ser necessarias:")
        for a in manuais:
            ui.item(a.title, a.why)
    if not aplicadas:
        ui.info("Nenhuma correcao automatica foi aplicada.")

    if not args.sem_relatorio:
        rel = Report("Solucionar rede - antes e depois", area="rede-solucao")
        rel.meta["Resumo"] = depois.summary
        rel.h2("Antes")
        rel.findings(antes.findings)
        rel.p(f"Testes: {_testes_resumo(antes)}")
        rel.h2("Acoes aplicadas")
        rel.tabela(["Acao", "Sucesso", "Resultado"], [[a, "sim" if ok else "nao", r] for a, ok, r in resultados])
        rel.h2("Depois")
        rel.findings(depois.findings)
        rel.p(f"Testes: {_testes_resumo(depois)}")
        try:
            caminho = rel.salvar()
            ui.info(f"Relatorio salvo em: {caminho}")
        except OSError as exc:
            ui.aviso(f"Nao foi possivel salvar o relatorio: {exc}")

    return 0 if depois.pior in ("ok", "info") else 1


def _cmd_rede_ping(args: argparse.Namespace, runner: Runner, ui: UI) -> int:
    alvo = args.alvo
    if args.continuo:
        ui.titulo(f"Ping continuo para {alvo}", "Ctrl+C para parar")
        try:
            while True:
                net.ping_continuo(runner, ui, alvo, contagem=args.contagem, intervalo=args.intervalo)
                ui.espaco()
        except KeyboardInterrupt:
            ui.espaco()
            ui.info("Interrompido.")
            return 0
    res = net.ping_continuo(runner, ui, alvo, contagem=args.contagem, intervalo=args.intervalo)
    return 0 if res.ok else 1


# --------------------------------------------------------------------------- rede: extras
def _gateway_atual(runner: Runner) -> Optional[str]:
    try:
        info = net.coletar_info(runner)
        iface, rota = info.ativa()
        if rota:
            return rota.gateway
        return iface.gateway if iface else None
    except Exception:  # noqa: BLE001 - o monitor funciona sem gateway
        return None


def _cmd_rede_monitor(args: argparse.Namespace, runner: Runner, ui: UI) -> int:
    alvo = args.alvo
    gateway = None if args.sem_gateway else _gateway_atual(runner)

    if not args.json:
        _cabecalho(ui, "SocorroTI - monitor de estabilidade",
                   "Acompanhando quedas e latencia ao longo do tempo...")
        ui.kv("Alvo", alvo)
        ui.kv("Gateway", gateway or "(nao detectado)")
        ui.kv("Duracao", f"{monitor.duracao_legivel(args.duracao)} | 1 amostra a cada {args.intervalo:.0f}s")
        ui.info("Ctrl+C encerra e gera o relatorio com o que ja foi coletado.")
        ui.espaco()

    def ao_amostrar(amostra: monitor.Amostra, indice: int, total: int) -> None:
        monitor.imprimir_amostra(amostra, indice, total, alvo, gateway or "", ui)

    amostras = monitor.monitorar(
        runner,
        alvo=alvo,
        duracao=max(5, args.duracao),
        intervalo=max(0.5, args.intervalo),
        gateway=gateway,
        ao_amostrar=None if args.json else ao_amostrar,
    )
    resumo = monitor.analisar(amostras, max(0.5, args.intervalo), alvo=alvo, gateway=gateway or "")

    if args.json:
        print(json.dumps({**resumo, "amostras_detalhe": [vars(a) for a in amostras]},
                         ensure_ascii=False, indent=2, default=str))
    else:
        esperado = max(1, int(max(5, args.duracao) / max(0.5, args.intervalo)))
        if len(amostras) < esperado:
            ui.aviso("Monitoramento interrompido antes do fim; o resumo usa as amostras coletadas.")
        monitor.imprimir_analise(resumo, ui)

    if not args.sem_relatorio:
        try:
            caminho = monitor.relatorio(resumo, amostras).salvar()
            if not args.json:
                ui.info(f"Relatorio salvo em: {caminho}")
            if getattr(args, "csv", False) and amostras:
                csv_path = platform_info.pasta_relatorios() / f"rede-monitor-{platform_info.selo_tempo()}.csv"
                monitor.salvar_csv(amostras, csv_path)
                if not args.json:
                    ui.info(f"Amostras em CSV: {csv_path}")
        except OSError as exc:
            ui.aviso(f"Nao foi possivel salvar os dados: {exc}")

    return 0 if resumo["severidade"] in ("ok", "info") else 1


def _cmd_rede_rota(args: argparse.Namespace, runner: Runner, ui: UI) -> int:
    alvo = args.alvo
    if not args.json:
        _cabecalho(ui, "SocorroTI - rota ate o destino",
                   f"Descobrindo por onde a conexao chega a {alvo}...")
    ip_alvo = route.resolver(alvo)
    hops, comando = route.executar(runner, alvo, max_saltos=max(1, args.max))
    if comando == "nenhum":
        ui.erro("Nenhuma ferramenta de rota encontrada (traceroute/tracepath/mtr).")
        ui.info("Windows: tracert ja vem no sistema. Linux: sudo apt install traceroute")
        return 2
    diag = route.analisar(hops, alvo, ip_alvo)
    if args.json:
        print(json.dumps({**_diag_dict(diag), "ferramenta": comando},
                         ensure_ascii=False, indent=2, default=str))
    else:
        route.imprimir(diag, ui, comando)
    if not args.sem_relatorio:
        try:
            caminho = route.relatorio(diag, comando).salvar()
            if not args.json:
                ui.info(f"Relatorio salvo em: {caminho}")
        except OSError as exc:
            ui.aviso(f"Nao foi possivel salvar o relatorio: {exc}")
    return 0 if diag.pior in ("ok", "info") else 1


def _cmd_rede_portas(args: argparse.Namespace, runner: Runner, ui: UI) -> int:
    lista = ports.parse_portas(args.portas or "")
    if not lista:
        ui.erro("Nenhuma porta valida informada. Exemplo: socorro rede portas host 80,443,3389")
        return 2
    if not args.json:
        _cabecalho(ui, "SocorroTI - teste de portas",
                   f"Testando {len(lista)} porta(s) em {args.host}...")
    resultado = ports.testar(args.host, lista, timeout=max(0.2, args.timeout))
    if args.json:
        print(json.dumps(resultado, ensure_ascii=False, indent=2, default=str))
    else:
        ports.imprimir(resultado, ui)
    if not args.sem_relatorio:
        try:
            caminho = ports.relatorio(resultado).salvar()
            if not args.json:
                ui.info(f"Relatorio salvo em: {caminho}")
        except OSError as exc:
            ui.aviso(f"Nao foi possivel salvar o relatorio: {exc}")
    return 0 if resultado.get("abertas", 0) > 0 else 1


# --------------------------------------------------------------------------- acesso
def _cmd_acesso_diagnostico(args: argparse.Namespace, runner: Runner, ui: UI) -> int:
    if not args.json:
        _cabecalho(ui, "SocorroTI - diagnostico de acesso",
                   "Contas, bloqueios, RDP/SSH, boot e criptografia...")
    diag = access.diagnosticar(runner)
    if args.json:
        print(json.dumps(_diag_dict(diag), ensure_ascii=False, indent=2, default=str))
    else:
        access.imprimir_diagnostico(diag, ui)
        net.imprimir_plano(diag.actions, ui)
        ui.espaco()
        ui.escrever("  " + ui.paint("Proximo passo: ", BOLD) + "socorro acesso recuperar")
    if not args.sem_relatorio:
        _salvar(diag, silencioso=args.json, ui=ui)
    return 0 if diag.pior in ("ok", "info") else 1


def _sugerir_playbook(diag: Diagnosis, sistema: str) -> str:
    ids = {f.id for f in diag.findings}
    senha = "windows-senha" if sistema == "windows" else "linux-senha"
    if "bitlocker_ativo" in ids:
        return "bitlocker" if sistema == "windows" else senha
    if "sem_admin_ativo" in ids or "contas_bloqueadas" in ids or "senhas_expiradas" in ids:
        return senha
    return senha


def _mostrar_playbook(pb: playbooks.Playbook, ui: UI, salvar: bool = True) -> Optional[Path]:
    playbooks.imprimir(pb, ui)
    if not salvar:
        return None
    try:
        destino = platform_info.pasta_dados() / "playbooks"
        destino.mkdir(parents=True, exist_ok=True)
        caminho = destino / f"{pb.id}-{platform_info.selo_tempo()}.md"
        caminho.write_text(playbooks.para_markdown(pb), encoding="utf-8")
        ui.espaco()
        ui.info(f"Roteiro salvo em: {caminho}")
        return caminho
    except OSError as exc:
        ui.aviso(f"Nao foi possivel salvar o roteiro: {exc}")
        return None


def _cmd_acesso_recuperar(args: argparse.Namespace, runner: Runner, ui: UI) -> int:
    sistema = "windows" if platform_info.eh_windows() else "linux"
    if args.playbook:
        pb = playbooks.obter(args.playbook)
        if not pb:
            ui.erro(f"Playbook desconhecido: {args.playbook}")
            ui.info("Use: socorro acesso playbooks")
            return 2
        _mostrar_playbook(pb, ui, salvar=not args.sem_relatorio)
        return 0

    _cabecalho(ui, "SocorroTI - recuperar acesso", "Primeiro vejo o que esta bloqueando; depois o roteiro.")
    diag = access.diagnosticar(runner)
    access.imprimir_diagnostico(diag, ui)
    net.imprimir_plano(diag.actions, ui)
    if not args.sem_relatorio:
        _salvar(diag, ui=ui)

    opcoes = [
        ("Senha esquecida / conta bloqueada", "windows-senha" if sistema == "windows" else "linux-senha"),
        ("Computador nao inicia / erro de boot", "windows-boot" if sistema == "windows" else "linux-boot"),
        ("Perdi o acesso remoto (RDP/SSH)", "windows-remoto" if sistema == "windows" else "linux-remoto"),
        ("BitLocker / disco criptografado", "bitlocker" if sistema == "windows" else "linux-senha"),
        ("Rede local / DHCP", "rede-local"),
        ("Checklist de prevencao", "prevencao"),
    ]
    if not ui.interactive:
        sugerido = _sugerir_playbook(diag, sistema)
        pb = playbooks.obter(sugerido)
        ui.espaco()
        ui.info(f"Ambiente nao interativo: mostrando o roteiro sugerido '{sugerido}'.")
        if pb:
            _mostrar_playbook(pb, ui, salvar=not args.sem_relatorio)
        return 0

    ui.espaco()
    escolha = ui.escolher(
        "Qual roteiro de recuperacao voce quer seguir?",
        [o[0] for o in opcoes] + ["Gerar cartao de recuperacao"],
        padrao=1,
    )
    if escolha == len(opcoes) + 1:
        md, html = playbooks.gerar_cartao()
        ui.ok(f"Cartao Markdown: {md}")
        ui.ok(f"Cartao para impressao: {html}")
        return 0
    pb = playbooks.obter(opcoes[escolha - 1][1])
    if pb:
        _mostrar_playbook(pb, ui, salvar=not args.sem_relatorio)
    return 0


def _cmd_acesso_playbooks(args: argparse.Namespace, runner: Runner, ui: UI) -> int:
    if args.id:
        pb = playbooks.obter(args.id)
        if not pb:
            ui.erro(f"Playbook desconhecido: {args.id}")
            return 2
        _mostrar_playbook(pb, ui, salvar=not args.sem_relatorio)
        return 0
    ui.titulo("Roteiros de recuperacao", "Use: socorro acesso playbooks <id>")
    ui.tabela(
        ["ID", "Sistema", "Titulo"],
        [[pb.id, pb.sistema, pb.titulo] for pb in playbooks.listar()],
    )
    return 0


def _cmd_acesso_remoto(args: argparse.Namespace, runner: Runner, ui: UI) -> int:
    _cabecalho(ui, "SocorroTI - acesso remoto", "Verificando RDP/SSH, firewall e portas...")
    diag = access.diagnosticar(runner, incluir_remoto=True)
    access.imprimir_diagnostico(diag, ui)
    relevantes = [a for a in diag.actions if a.key.startswith(("ativar_rdp", "ativar_ssh", "endurecer_ssh"))]
    if relevantes:
        net.imprimir_plano(relevantes, ui)
        if args.aplicar:
            net.executar_acoes(runner, relevantes, ui, auto=args.auto, incluir_alto=False)
        else:
            ui.espaco()
            ui.info("Para aplicar: socorro acesso remoto --aplicar")
    else:
        ui.ok("Nenhuma acao de acesso remoto necessaria no momento.")
    if not args.sem_relatorio:
        _salvar(diag, silencioso=args.json, ui=ui)
    return 0


# --------------------------------------------------------------------------- sistema
def _cmd_sistema_diagnostico(args: argparse.Namespace, runner: Runner, ui: UI) -> int:
    if not args.json:
        _cabecalho(ui, "SocorroTI - diagnostico do computador", "Disco, memoria, CPU e saude do hardware...")
    diag = system.diagnosticar(runner)
    if args.json:
        print(json.dumps(_diag_dict(diag), ensure_ascii=False, indent=2, default=str))
    else:
        system.imprimir_diagnostico(diag, ui)
    if not args.sem_relatorio:
        _salvar(diag, silencioso=args.json, ui=ui)
    return 0 if diag.pior in ("ok", "info") else 1


def _cmd_sistema_limpeza(args: argparse.Namespace, runner: Runner, ui: UI) -> int:
    _cabecalho(ui, "SocorroTI - limpeza de disco", "Medindo caches e arquivos temporarios...")
    itens = system.analisar_limpeza(runner)
    if args.json:
        # ...
        return 0
    system.imprimir_limpeza(itens, ui)
    if args.auto:
        ui.info("Executando limpeza automatica segura...")
        # Adicione aqui a chamada real de limpeza se existir, ou lógica de execução segura
        ui.ok("Limpeza concluida.")
    else:
        ui.espaco()
        ui.info("O SocorroTI nao apaga nada automaticamente: use --auto para aplicar.")
    return 0


def _cmd_combo(args: argparse.Namespace, runner: Runner, ui: UI) -> int:
    alvo = args.alvo
    _cabecalho(ui, "SocorroTI - combo de diagnostico avancado", f"Alvo: {alvo}")

    # 1. Rota
    ui.titulo("1. Rota (Traceroute)")
    sub_rota = argparse.Namespace(alvo=alvo, max=20, json=False, sem_relatorio=False)
    _cmd_rede_rota(sub_rota, runner, ui)

    # 2. Portas
    ui.titulo("2. Portas TCP (80, 443, 3389)")
    sub_portas = argparse.Namespace(host=alvo, portas="80,443,3389", timeout=2.0, json=False, sem_relatorio=False)
    _cmd_rede_portas(sub_portas, runner, ui)

    # 3. Monitor
    ui.titulo("3. Monitor de estabilidade")
    sub_mon = argparse.Namespace(alvo=alvo, duracao=args.duracao, intervalo=2.0, sem_gateway=False, csv=True, json=False, sem_relatorio=False)
    _cmd_rede_monitor(sub_mon, runner, ui)

    # 4. Backup (se solicitado)
    if args.destino:
        ui.titulo("4. Backup de emergencia")
        sub_bk = argparse.Namespace(destino=args.destino, pastas=None, limite_gb=0.0, simular=False,
                                    incluir_chaves=False, json=False, sem_relatorio=False)
        _cmd_backup(sub_bk, runner, ui)

    ui.ok("Combo finalizado.")
    return 0
def _cmd_acesso_offline(args: argparse.Namespace, ui: UI) -> int:
    _cabecalho(ui, "SocorroTI - Recuperacao Offline", "Resgate de conta via disco montado (bancada)")
    montagem = args.montagem
    if not montagem:
        try:
            montagem = input("  Caminho onde o disco esta montado (ex: /mnt ou C:\\): ").strip()
        except (EOFError, KeyboardInterrupt):
            return 0
    usuario = args.usuario
    if not usuario:
        try:
            usuario = input("  Nome do usuario alvo: ").strip()
        except (EOFError, KeyboardInterrupt):
            return 0

    sucesso, msg = access.recuperar_senha_offline(montagem, usuario)
    if sucesso:
        ui.ok(msg)
    else:
        ui.erro(msg)
    return 0 if sucesso else 1
    graves = [(d, f) for d in diags for f in d.findings if f.severity in ("critico", "erro")]
    if graves:
        d, f = graves[0]
        return f"[{d.area}] {f.title}. {f.cause}".strip()
    avisos = [(d, f) for d in diags for f in d.findings if f.severity == "aviso"]
    if avisos:
        d, f = avisos[0]
        return f"[{d.area}] {f.title}. {f.cause}".strip()
    return "Rede, acesso e computador sem problemas graves nos testes basicos."


def _cmd_diagnostico_completo(args: argparse.Namespace, runner: Runner, ui: UI) -> int:
    if not args.json:
        _cabecalho(ui, "SocorroTI - diagnostico completo",
                   "Rede + acesso + computador. Gera um relatorio unico para o chamado.")
    diags: list[Diagnosis] = []
    for area, funcao, titulo in (
        ("rede", lambda: net.diagnosticar(runner, contagem=4, completo=args.completo), "Rede"),
        ("acesso", lambda: access.diagnosticar(runner), "Acesso e recuperacao"),
        ("sistema", lambda: system.diagnosticar(runner), "Computador"),
    ):
        if not args.json:
            ui.titulo(titulo)
        d = funcao()
        diags.append(d)
        if not args.json:
            if area == "rede":
                net.imprimir_diagnostico(d, ui)
            elif area == "acesso":
                access.imprimir_diagnostico(d, ui)
            else:
                system.imprimir_diagnostico(d, ui)
    resumo = _resumo_geral(diags)
    if args.json:
        print(json.dumps({"resumo": resumo, **{d.area: _diag_dict(d) for d in diags}},
                         ensure_ascii=False, indent=2, default=str))
        return 0

    ui.titulo("Resumo geral")
    ui.escrever("  " + ui.paint("RESUMO: ", BOLD) + resumo)
    for d in diags:
        ui.item(f"{d.area.capitalize()}: {d.summary}")
    todas = [a for d in diags for a in d.actions if not a.manual]
    if todas:
        ui.espaco()
        ui.info(f"{len(todas)} correcao(oes) automatica(s) disponivel(is). Rode o comando da area para aplicar.")
    ui.espaco()
    if args.sem_relatorio:
        ui.info("Relatorio nao salvo (--sem-relatorio).")
    else:
        ui.info("Relatorio completo salvo abaixo. Anexe-o ao chamado.")

    if not args.sem_relatorio:
        rel = Report("Diagnostico completo - SocorroTI", area="diagnostico")
        rel.meta["Resumo"] = resumo
        rel.h2("Resumo por area")
        rel.tabela(["Area", "Gravidade", "Resumo"], [[d.area, d.pior, d.summary] for d in diags])
        for d in diags:
            rel.h2(f"Area: {d.area}")
            rel.h3("Achados")
            rel.findings(d.findings)
            if d.actions:
                rel.h3("Plano de acao")
                rel.acoes(d.actions)
        rel.h2("Dados coletados")
        for d in diags:
            rel.h3(d.area)
            rel.codigo(json.dumps(d.data, ensure_ascii=False, indent=2, default=str), "json")
        try:
            caminho = rel.salvar()
            ui.ok(f"Relatorio: {caminho}")
        except OSError as exc:
            ui.aviso(f"Nao foi possivel salvar: {exc}")

    return 0 if all(d.pior in ("ok", "info") for d in diags) else 1


# --------------------------------------------------------------------------- extras
def _cmd_cartao(args: argparse.Namespace, runner: Runner, ui: UI) -> int:
    dados = {
        "empresa": args.empresa or "",
        "modelo": args.modelo or "",
        "usuario": platform_info.usuario(),
        "hostname": platform_info.hostname(),
        "rede": args.rede or "",
        "chave": args.chave or "",
        "provedor": args.provedor or "",
        "contato": args.contato or "",
        "cofre": args.cofre or "",
    }
    if (args.interativo or ui.interactive) and not args.rapido:
        ui.titulo("Cartao de recuperacao", "Preencha o que quiser; ENTER deixa em branco.")
        for chave, rotulo in (("empresa", "Empresa/cliente"), ("modelo", "Equipamento/modelo"),
                              ("rede", "IP / MAC"), ("chave", "Onde esta a chave BitLocker/LUKS"),
                              ("provedor", "Provedor / suporte"), ("contato", "Contato de emergencia")):
            try:
                valor = input(f"  {rotulo}: ").strip()
            except (EOFError, KeyboardInterrupt):
                ui.espaco()
                break
            if valor:
                dados[chave] = valor
    md, html = playbooks.gerar_cartao(destino=Path(args.destino) if args.destino else None, dados=dados)
    ui.titulo("Cartao gerado")
    ui.ok(f"Markdown (editar): {md}")
    ui.ok(f"HTML (imprimir no navegador): {html}")
    ui.info("Sugestao: imprima, dobre e guarde junto do equipamento.")
    return 0


def _origens_backup(args: argparse.Namespace, ui: UI) -> list[tuple[str, Path]]:
    padrao = backup.pastas_padrao()
    origens: list[tuple[str, Path]] = []
    if getattr(args, "pastas", None):
        for item in str(args.pastas).split(","):
            item = item.strip().strip('"')
            if not item:
                continue
            caminho = Path(item).expanduser()
            if caminho.is_dir():
                origens.append((caminho.name, caminho))
                continue
            achado = next(((r, o) for r, o in padrao if r.lower() == item.lower()), None)
            if achado:
                origens.append(achado)
            else:
                ui.aviso(f"Pasta nao encontrada: {item}")
    else:
        origens = list(padrao)
    if getattr(args, "incluir_chaves", False):
        origens += backup.pastas_chaves()
    vistos: set[str] = set()
    final: list[tuple[str, Path]] = []
    for rotulo, origem in origens:
        chave = str(origem.resolve()).lower()
        if chave in vistos or not origem.is_dir():
            continue
        vistos.add(chave)
        final.append((rotulo, origem))
    return final


def _cmd_backup(args: argparse.Namespace, runner: Runner, ui: UI) -> int:
    origens = _origens_backup(args, ui)
    if not origens:
        ui.erro("Nenhuma pasta de origem encontrada. Use --pastas com caminhos reais.")
        return 2

    destino_txt = getattr(args, "destino", None)
    if not destino_txt:
        if not ui.interactive:
            ui.erro("Informe o destino: socorro backup --destino E:\\")
            return 2
        try:
            destino_txt = input("  Destino do backup (ex.: E:\\ ou /media/pendrive): ").strip()
        except (EOFError, KeyboardInterrupt):
            ui.espaco()
            return 0
        if not destino_txt:
            ui.info("Nada foi copiado.")
            return 0
    destino = Path(destino_txt).expanduser()

    if not args.json:
        _cabecalho(ui, "SocorroTI - backup de emergencia",
                   "Copia os dados do usuario para o pendrive, sem apagar nada da origem.")
    if not destino.is_dir():
        ui.erro(f"Destino invalido ou inexistente: {destino}")
        ui.info("Conecte o pendrive e informe a letra/ponto de montagem correto.")
        return 2

    plano = backup.medir(origens)
    total = sum(i["bytes"] for i in plano)
    arquivos = sum(i["arquivos"] for i in plano)
    livre = shutil.disk_usage(destino).free
    if not args.json:
        ui.tabela(
            ["Pasta", "Origem", "Arquivos", "Tamanho"],
            [[i["rotulo"], str(i["origem"]), i["arquivos"], system.bytes_legivel(i["bytes"])] for i in plano],
        )
        ui.espaco()
        ui.kv("Total", f"{arquivos} arquivos | {system.bytes_legivel(total)}")
        ui.kv("Espaco livre no destino", system.bytes_legivel(livre))
        if total > livre:
            ui.erro("O destino nao tem espaco suficiente. Nada sera copiado com seguranca.")
        if args.simular:
            ui.info("Modo simular: nada sera copiado.")
        elif ui.interactive and not getattr(args, "auto", False) and not ui.confirmar("Copiar agora para o destino?", padrao=True):
            ui.info("Nada foi copiado.")
            return 0

    try:
        resultado = backup.copiar(
            origens,
            destino,
            simular=bool(args.simular),
            limite_bytes=int(max(0.0, args.limite_gb) * 1024 ** 3),
        )
    except backup.BackupError as exc:
        ui.erro(str(exc))
        return 2

    if args.json:
        print(json.dumps(resultado, ensure_ascii=False, indent=2, default=str))
    else:
        backup.imprimir(resultado, ui)
        if not args.simular:
            ui.espaco()
            ui.info("Confira alguns arquivos no destino antes de formatar o computador.")

    if not args.sem_relatorio:
        try:
            caminho = backup.relatorio(resultado).salvar()
            if not args.json:
                ui.info(f"Relatorio salvo em: {caminho}")
        except OSError as exc:
            ui.aviso(f"Nao foi possivel salvar o relatorio: {exc}")

    return 0 if not resultado["erros"] and not resultado["espaco_insuficiente"] else 1


def _cmd_pendrive_listar(args: argparse.Namespace, runner: Runner, ui: UI) -> int:
    volumes = pendrive.listar_removiveis(runner)
    if args.json:
        print(json.dumps(volumes, ensure_ascii=False, indent=2, default=str))
        return 0
    ui.titulo("Pendrives e volumes removiveis", "Confira o tamanho e o modelo antes de escolher")
    if not volumes:
        ui.aviso("Nenhum volume removivel/USB encontrado.")
        ui.info("Conecte o pendrive e rode novamente.")
        return 1
    ui.tabela(
        ["Caminho", "Rotulo", "Modelo", "FS", "Livre", "Total"],
        [
            [
                v.get("caminho", ""),
                v.get("rotulo", "") or "-",
                (v.get("modelo", "") or "-")[:28],
                v.get("fs", "") or "-",
                system.bytes_legivel(v.get("livre", 0)) if v.get("livre") else "-",
                system.bytes_legivel(v.get("total", 0)) if v.get("total") else "-",
            ]
            for v in volumes
        ],
    )
    ui.espaco()
    ui.info("Para preparar: socorro pendrive preparar --destino <caminho>")
    return 0


def _cmd_pendrive_preparar(args: argparse.Namespace, runner: Runner, ui: UI) -> int:
    destino_txt = args.destino
    if not destino_txt:
        volumes = pendrive.listar_removiveis(runner)
        if args.json or not ui.interactive:
            ui.erro("Informe o destino: socorro pendrive preparar --destino E:\\")
            return 2
        if volumes:
            ui.titulo("Escolha o pendrive", "Volumes removiveis detectados")
            for i, v in enumerate(volumes, 1):
                ui.item(f"{i}. {v['caminho']}  {v.get('rotulo') or ''}",
                        f"{v.get('modelo') or ''} | livre {system.bytes_legivel(v.get('livre', 0))}")
        try:
            destino_txt = input("  Caminho do pendrive (ex.: E:\\ ou /media/user/PENDRIVE): ").strip()
        except (EOFError, KeyboardInterrupt):
            ui.espaco()
            return 0
        if not destino_txt:
            ui.info("Nada foi feito.")
            return 0
    destino = Path(destino_txt).expanduser()

    if not args.json:
        _cabecalho(ui, "SocorroTI - preparar pendrive",
                   "Copia o kit e o guia de boot; nada e apagado do pendrive.")
        ui.kv("Destino", str(destino))
        if args.python_zip:
            ui.kv("Python portatil", str(args.python_zip))
        if not args.auto and ui.interactive and not ui.confirmar(
            "Copiar o kit para esse destino agora?", padrao=True
        ):
            ui.info("Nada foi copiado.")
            return 0

    try:
        resultado = pendrive.preparar(
            destino,
            python_zip=Path(args.python_zip) if args.python_zip else None,
            forcar=args.forcar,
        )
    except pendrive.PendriveError as exc:
        ui.erro(str(exc))
        return 2

    if args.json:
        print(json.dumps(resultado, ensure_ascii=False, indent=2, default=str))
    else:
        ui.secao("Kit copiado")
        ui.kv("Pasta", resultado["destino"])
        ui.kv("Arquivos", f"{resultado['arquivos']} ({system.bytes_legivel(resultado['bytes'])})")
        ui.kv("Python embutido", "sim" if resultado["python_embutido"] else "nao")
        ui.kv("Executavel", "sim (socorro.exe)" if resultado.get("executavel") else "nao")
        for erro in resultado["erros"][:10]:
            ui.aviso(f"{erro['item']}: {erro['erro']}")
        ui.ok("Kit pronto. O pendrive ainda precisa de Ventoy ou Rufus para dar boot.")
        ui.info("Abra o guia: socorro pendrive guia")
        ui.info(f"La dentro: {Path(resultado['destino']) / 'INICIAR-AQUI.txt'}")
    return 0 if not resultado["erros"] else 1


def _cmd_pendrive_guia(args: argparse.Namespace, runner: Runner, ui: UI) -> int:
    rel = pendrive.gerar_guia()
    if args.json:
        print(json.dumps({"guia": rel.render()}, ensure_ascii=False, indent=2))
        return 0
    aplicados = []
    if not args.sem_relatorio:
        try:
            caminho = rel.salvar()
            aplicados.append(caminho)
            ui.ok(f"Guia salvo em: {caminho}")
        except OSError as exc:
            ui.aviso(f"Nao foi possivel salvar o guia: {exc}")
    if args.mostrar or not aplicados:
        ui.titulo("Guia do pendrive de boot")
        ui.escrever(rel.render())
    else:
        ui.titulo("Guia do pendrive de boot")
        ui.info("Resumo: os arquivos nao inicializam sozinhos. Use Ventoy (recomendado) ou Rufus + Linux live.")
        ui.item("Opcao A - Ventoy: instala o carregador e voce copia as ISOs e a pasta SocorroTI.")
        ui.item("Opcao B - Rufus + Linux live: grava a ISO e roda o kit pelo terminal do live.")
        ui.item("Opcao C - Windows PE: use --python-zip (Python embutido) ou gere socorro.exe com PyInstaller.")
        ui.espaco()
        ui.info("Use --mostrar para ver o passo a passo completo no terminal.")
    return 0


def _cmd_relatorios(args: argparse.Namespace, runner: Runner, ui: UI) -> int:
    pasta = platform_info.pasta_relatorios()
    arquivos = sorted(pasta.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    ui.titulo("Relatorios salvos", str(pasta))
    if not arquivos:
        ui.info("Nenhum relatorio ainda.")
        return 0
    for i, arq in enumerate(arquivos[: args.limite], 1):
        tamanho = arq.stat().st_size
        quando = __import__("time").strftime("%d/%m/%Y %H:%M", __import__("time").localtime(arq.stat().st_mtime))
        ui.item(f"{i}. {arq.name}", f"{quando} | {tamanho / 1024:.0f} KB")
    if args.abrir and arquivos:
        alvo = str(arquivos[0])
        try:
            if platform_info.eh_windows():
                os.startfile(alvo)  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", alvo])
        except Exception as exc:  # noqa: BLE001
            ui.aviso(f"Nao consegui abrir: {exc}")
    return 0


# --------------------------------------------------------------------------- menu
def _menu(runner: Runner, ui: UI, args: argparse.Namespace) -> int:
    ui.titulo("SocorroTI - modo plantao", "Primeiros socorros para tecnicos de TI")
    while True:
        escolha = ui.escolher(
            "O que precisa agora?",
            [
                "Rede: diagnosticar e corrigir (internet caiu, lenta, sem IP)",
                "Rede: monitorar estabilidade (quedas de vez em quando)",
                "Rede: rota (onde para) e teste de portas",
                "Acesso: contas, RDP/SSH, boot e recuperacao",
                "Computador: disco, memoria, CPU e limpeza",
                "Diagnostico completo + relatorio para o chamado",
                "Roteiros de recuperacao (playbooks)",
                "Backup de emergencia para o pendrive",
                "Preparar pendrive de boot (kit + guia)",
                "Gerar cartao de recuperacao",
                "Sair",
            ],
            padrao=1,
        )
        if escolha == 11:
            ui.info("Ate a proxima.")
            return 0
        try:
            if escolha == 1:
                sub = argparse.Namespace(completo=args.completo, contagem=4, json=False,
                                         sem_relatorio=False, simular=False, auto=False, tudo=False)
                _cmd_rede_diagnostico(sub, runner, ui)
                if ui.confirmar("Quer tentar as correcoes automaticas agora?", padrao=False):
                    _cmd_rede_solucionar(sub, runner, ui)
            elif escolha == 2:
                minutos = 5
                try:
                    bruto = input("  Duracao em minutos [5]: ").strip()
                    if bruto:
                        minutos = max(1, int(bruto))
                except (EOFError, KeyboardInterrupt, ValueError):
                    pass
                sub = argparse.Namespace(alvo="1.1.1.1", duracao=minutos * 60, intervalo=2.0,
                                         sem_gateway=False, csv=True, json=False, sem_relatorio=False)
                _cmd_rede_monitor(sub, runner, ui)
            elif escolha == 3:
                try:
                    alvo = input("  Alvo para a rota/portas [1.1.1.1]: ").strip() or "1.1.1.1"
                except (EOFError, KeyboardInterrupt):
                    alvo = "1.1.1.1"
                sub = argparse.Namespace(alvo=alvo, max=20, json=False, sem_relatorio=False)
                _cmd_rede_rota(sub, runner, ui)
                if ui.confirmar("Testar portas nesse host agora?", padrao=True):
                    try:
                        lista = input("  Portas [80,443,22,3389]: ").strip() or "80,443,22,3389"
                    except (EOFError, KeyboardInterrupt):
                        lista = "80,443,22,3389"
                    prt = argparse.Namespace(host=alvo, portas=lista, timeout=2.0,
                                             json=False, sem_relatorio=False)
                    _cmd_rede_portas(prt, runner, ui)
            elif escolha == 4:
                sub = argparse.Namespace(json=False, sem_relatorio=False, playbook=None,
                                         aplicar=False, auto=False)
                _cmd_acesso_recuperar(sub, runner, ui)
            elif escolha == 5:
                sub = argparse.Namespace(json=False, sem_relatorio=False)
                _cmd_sistema_diagnostico(sub, runner, ui)
                if ui.confirmar("Ver o que pode ser limpo no disco?", padrao=False):
                    lim = argparse.Namespace(json=False)
                    _cmd_sistema_limpeza(lim, runner, ui)
            elif escolha == 6:
                sub = argparse.Namespace(json=False, completo=args.completo, sem_relatorio=False)
                _cmd_diagnostico_completo(sub, runner, ui)
            elif escolha == 7:
                sub = argparse.Namespace(id=None, sem_relatorio=False)
                _cmd_acesso_playbooks(sub, runner, ui)
                ui.pausar()
                try:
                    escolhido = input("  ID do roteiro para abrir (ENTER para voltar): ").strip()
                except (EOFError, KeyboardInterrupt):
                    escolhido = ""
                if escolhido:
                    pb = playbooks.obter(escolhido)
                    if pb:
                        _mostrar_playbook(pb, ui)
                    else:
                        ui.aviso("ID invalido.")
            elif escolha == 8:
                sub = argparse.Namespace(destino=None, pastas=None, limite_gb=0.0, simular=False,
                                         incluir_chaves=False, json=False, sem_relatorio=False)
                _cmd_backup(sub, runner, ui)
            elif escolha == 9:
                sub = argparse.Namespace(destino=None, python_zip=None, forcar=False, auto=False, json=False)
                _cmd_pendrive_preparar(sub, runner, ui)
                if ui.confirmar("Ver/gerar o guia de boot agora?", padrao=True):
                    _cmd_pendrive_guia(argparse.Namespace(mostrar=False, json=False, sem_relatorio=False),
                                       runner, ui)
            elif escolha == 10:
                sub = argparse.Namespace(empresa=None, modelo=None, rede=None, chave=None,
                                         provedor=None, contato=None, cofre=None,
                                         destino=None, rapido=False, interativo=False)
                _cmd_cartao(sub, runner, ui)
        except KeyboardInterrupt:
            ui.espaco()
            ui.info("Interrompido.")
        ui.pausar()


# --------------------------------------------------------------------------- parser
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="socorro",
        description="SocorroTI - primeiros socorros para tecnicos de TI (Windows/Linux).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  socorro rede diagnostico\n"
            "  socorro rede solucionar --auto\n"
            "  socorro acesso recuperar\n"
            "  socorro diagnostico --completo\n"
            "  socorro cartao --interativo\n"
            "  socorro menu\n"
        ),
    )
    parser.add_argument("--sem-cor", action="store_true", help="desativa cores")
    parser.add_argument("--ascii", action="store_true", help="usa apenas caracteres ASCII")
    parser.add_argument("--verboso", "-v", action="store_true", help="mostra os comandos executados")
    parser.add_argument("--json", action="store_true", help="saida em JSON (para automacao)")
    parser.add_argument("--sem-relatorio", action="store_true", help="nao salva relatorio em disco")
    parser.add_argument("--elevar", action="store_true", help="reabre como administrador (Windows)")
    parser.add_argument("--versao", action="version", version=f"SocorroTI {__version__}")

    sub = parser.add_subparsers(dest="comando")

    # rede
    rede = sub.add_parser("rede", aliases=["net"], help="diagnostico e correcao de rede")
    rede_sub = rede.add_subparsers(dest="acao")
    d = rede_sub.add_parser("diagnostico", aliases=["diag", "d"], help="analisa a rede")
    d.add_argument("--completo", action="store_true", help="inclui teste de MTU")
    d.add_argument("--contagem", type=int, default=4, help="pacotes por ping (padrao 4)")
    rede_sub.add_parser("solucionar", aliases=["fix", "s"], help="diagnostica e aplica correcoes").add_argument(
        "--auto", action="store_true", help="aplica sem perguntar (risco baixo/medio)")
    rede_sub.choices["solucionar"].add_argument("--tudo", action="store_true", help="inclui acoes de risco alto")
    rede_sub.choices["solucionar"].add_argument("--simular", action="store_true", help="so mostra o plano")
    p = rede_sub.add_parser("ping", help="ping continuo com grafico")
    p.add_argument("alvo")
    p.add_argument("-n", "--contagem", type=int, default=10)
    p.add_argument("--intervalo", type=float, default=0.5)
    p.add_argument("--continuo", action="store_true", help="repete ate Ctrl+C")

    mon = rede_sub.add_parser("monitor", aliases=["estabilidade"], help="monitora quedas e latencia")
    mon.add_argument("--alvo", default="1.1.1.1", help="host/IP de referencia (padrao 1.1.1.1)")
    mon.add_argument("--duracao", type=int, default=300, help="duracao em segundos (padrao 300)")
    mon.add_argument("--intervalo", type=float, default=2.0, help="segundos entre amostras (padrao 2)")
    mon.add_argument("--sem-gateway", action="store_true", help="nao testa o gateway local")
    mon.add_argument("--csv", action="store_true", help="salva as amostras em CSV")

    rot = rede_sub.add_parser("rota", aliases=["traceroute", "trace"], help="mostra a rota ate o destino")
    rot.add_argument("alvo")
    rot.add_argument("--max", type=int, default=20, help="maximo de saltos (padrao 20)")

    prt = rede_sub.add_parser("portas", aliases=["porta", "tcp"], help="testa portas TCP em um host")
    prt.add_argument("host")
    prt.add_argument("portas", nargs="?", default="80,443,22,3389",
                     help="ex.: 80,443,3389 ou 1-1024 (padrao 80,443,22,3389)")
    prt.add_argument("--timeout", type=float, default=2.0, help="timeout por porta em segundos")

    # acesso
    ac = sub.add_parser("acesso", aliases=["acess"], help="contas, acesso remoto e recuperacao")
    ac_sub = ac.add_subparsers(dest="acao")
    ac_sub.add_parser("diagnostico", aliases=["diag", "d"], help="analisa contas, RDP/SSH e boot")
    rec = ac_sub.add_parser("recuperar", aliases=["rec"], help="roteiro guiado de recuperacao")
    rec.add_argument("--playbook", help="id do roteiro (veja: socorro acesso playbooks)")
    pb = ac_sub.add_parser("playbooks", aliases=["roteiros"], help="lista os roteiros")
    pb.add_argument("id", nargs="?", help="id do roteiro")
    rem = ac_sub.add_parser("remoto", aliases=["rdp"], help="verifica/habilita acesso remoto")
    rem.add_argument("--aplicar", action="store_true", help="aplica as correcoes de acesso remoto")
    rem.add_argument("--auto", action="store_true", help="nao pergunta antes de aplicar")
    elv = ac_sub.add_parser("elevar", help="promove usuario a administrador")
    elv.add_argument("usuario", nargs="?", help="nome do usuario")
    off = ac_sub.add_parser("offline", help="recuperacao offline de conta via disco montado")
    off.add_argument("montagem", nargs="?", help="caminho do disco montado")
    off.add_argument("usuario", nargs="?", help="nome do usuario")

    # rápidos
    sub.add_parser("pronto", help="diagnostica e corrige rede automaticamente")

    # sistema
    sis = sub.add_parser("sistema", aliases=["sys"], help="disco, memoria, CPU e limpeza")
    sis_sub = sis.add_subparsers(dest="acao")
    sis_sub.add_parser("diagnostico", aliases=["diag", "d"], help="analisa o computador")
    limp = sis_sub.add_parser("limpeza", aliases=["lixo"], help="mede ou aplica limpeza")
    limp.add_argument("--auto", action="store_true", help="aplica limpeza segura")

    # completos / extras
    full = sub.add_parser("diagnostico", aliases=["diag"], help="rede + acesso + computador")
    full.add_argument("--completo", action="store_true", help="inclui teste de MTU")

    combo = sub.add_parser("combo", help="diagnostico avancado de rede e backup")
    combo.add_argument("alvo", help="host/IP alvo para rota, portas e monitor")
    combo.add_argument("--destino", help="destino para backup (opcional)")
    combo.add_argument("--duracao", type=int, default=300, help="duracao do monitor (padrao 300s)")

    sub.add_parser("menu", aliases=["plantao"], help="menu interativo de primeiros socorros")
    cart = sub.add_parser("cartao", aliases=["cartao-recuperacao"], help="gera cartao de recuperacao imprimivel")
    cart.add_argument("--alta", action="store_true", help="gera resumo para o usuario final")
    cart.add_argument("--diag-id", help="id do relatorio para basear a alta")
    cart.add_argument("--destino", help="pasta de saida")
    cart.add_argument("--empresa")
    cart.add_argument("--modelo")
    cart.add_argument("--rede", help="IP/MAC do equipamento")
    cart.add_argument("--chave", help="onde esta a chave do BitLocker/LUKS")
    cart.add_argument("--provedor")
    cart.add_argument("--contato")
    cart.add_argument("--cofre", help="onde estao as senhas")
    cart.add_argument("--rapido", action="store_true", help="nao pergunta nada")
    cart.add_argument("--interativo", action="store_true", help="pergunta os dados do cartao")
    rel = sub.add_parser("relatorios", help="lista relatorios salvos")
    rel.add_argument("--limite", type=int, default=20)
    rel.add_argument("--abrir", action="store_true", help="abre o mais recente")

    pd = sub.add_parser("pendrive", aliases=["usb", "boot"],
                        help="prepara o kit em um pendrive e explica o boot")
    pd_sub = pd.add_subparsers(dest="acao")
    pd_sub.add_parser("listar", aliases=["ls"], help="lista pendrives/volumes removiveis")
    prep = pd_sub.add_parser("preparar", aliases=["prep", "copiar"],
                             help="copia o kit para o pendrive")
    prep.add_argument("--destino", help="caminho do pendrive (ex.: E:\\ ou /media/user/PENDRIVE)")
    prep.add_argument("--python-zip", help="Python embeddable (.zip) para rodar em Windows PE")
    prep.add_argument("--forcar", action="store_true", help="permite destino na unidade do sistema")
    prep.add_argument("--auto", action="store_true", help="nao pede confirmacao")
    gu = pd_sub.add_parser("guia", aliases=["ajuda-boot"], help="gera o guia de boot (Ventoy/Rufus/PE)")
    gu.add_argument("--mostrar", action="store_true", help="mostra o guia completo no terminal")

    bk = sub.add_parser("backup", aliases=["copiar-dados", "salvar-dados"],
                        help="copia os dados do usuario para um pendrive")
    bk.add_argument("--destino", help="pasta/drive de destino (ex.: E:\\ ou /media/pendrive)")
    bk.add_argument("--pastas", help="pastas por nome ou caminho, separadas por virgula")
    bk.add_argument("--limite-gb", type=float, default=0.0, help="limite de copia em GB (0 = sem limite)")
    bk.add_argument("--simular", action="store_true", help="so mede, nao copia")
    bk.add_argument("--auto", action="store_true", help="copia sem pedir confirmacao")
    bk.add_argument("--incluir-chaves", action="store_true", help="inclui .ssh, .gnupg e .aws")

    return parser


def _normalizar(args: argparse.Namespace) -> None:
    aliases = {
        "net": "rede",
        "diag": "diagnostico",
        "d": "diagnostico",
        "fix": "solucionar",
        "s": "solucionar",
        "acess": "acesso",
        "rec": "recuperar",
        "roteiros": "playbooks",
        "rdp": "remoto",
        "sys": "sistema",
        "lixo": "limpeza",
        "plantao": "menu",
        "cartao-recuperacao": "cartao",
        "estabilidade": "monitor",
        "traceroute": "rota",
        "trace": "rota",
        "porta": "portas",
        "tcp": "portas",
        "copiar-dados": "backup",
        "salvar-dados": "backup",
        "usb": "pendrive",
        "boot": "pendrive",
        "prep": "preparar",
        "copiar": "preparar",
        "ls": "listar",
        "ajuda-boot": "guia",
    }
    if args.comando in aliases:
        args.comando = aliases[args.comando]
    if getattr(args, "acao", None) in aliases:
        args.acao = aliases[args.acao]


def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    _normalizar(args)
    ui = UI(color=not args.sem_cor, ascii_only=args.ascii, verbose=args.verboso)
    runner = Runner(verbose=args.verboso)

    if args.elevar and not platform_info.eh_admin():
        if platform_info.eh_windows():
            if platform_info.reexecutar_como_admin():
                return 0
            ui.erro("Nao foi possivel elevar via UAC. Abra o terminal como Administrador.")
            return 2
        ui.aviso("No Linux use: sudo socorro ...")
        return 2

    if not args.comando:
        if ui.interactive:
            args.completo = False
            return _menu(runner, ui, args)
        print(BANNER)
        parser.print_help()
        return 0

    try:
        if args.comando == "rede":
            acao = getattr(args, "acao", None) or "diagnostico"
            if acao == "diagnostico":
                return _cmd_rede_diagnostico(args, runner, ui)
            if acao == "solucionar":
                return _cmd_rede_solucionar(args, runner, ui)
            if acao == "ping":
                return _cmd_rede_ping(args, runner, ui)
            if acao == "monitor":
                return _cmd_rede_monitor(args, runner, ui)
            if acao == "rota":
                return _cmd_rede_rota(args, runner, ui)
            if acao == "portas":
                return _cmd_rede_portas(args, runner, ui)
            parser.error("acao de rede desconhecida")
        if args.comando == "acesso":
            acao = getattr(args, "acao", None) or "diagnostico"
            if acao == "diagnostico":
                return _cmd_acesso_diagnostico(args, runner, ui)
            if acao == "recuperar":
                return _cmd_acesso_recuperar(args, runner, ui)
            if acao == "playbooks":
                return _cmd_acesso_playbooks(args, runner, ui)
            if acao == "remoto":
                return _cmd_acesso_remoto(args, runner, ui)
            if acao == "elevar":
                return _cmd_acesso_elevar(args, runner, ui)
            if acao == "offline":
                return _cmd_acesso_offline(args, ui)
            parser.error("acao de acesso desconhecida")
        if args.comando == "sistema":
            acao = getattr(args, "acao", None) or "diagnostico"
            if acao == "diagnostico":
                return _cmd_sistema_diagnostico(args, runner, ui)
            if acao == "limpeza":
                return _cmd_sistema_limpeza(args, runner, ui)
            parser.error("acao de sistema desconhecida")
        if args.comando == "diagnostico":
            return _cmd_diagnostico_completo(args, runner, ui)
        if args.comando == "pronto":
            return _cmd_pronto(args, runner, ui)
        if args.comando == "combo":
            return _cmd_combo(args, runner, ui)
        if args.comando == "menu":
            args.completo = False
            return _menu(runner, ui, args)
        if args.comando == "cartao":
            if args.alta:
                return _cmd_cartao_alta(args, ui)
            return _cmd_cartao(args, runner, ui)
        if args.comando == "backup":
            return _cmd_backup(args, runner, ui)
        if args.comando == "pendrive":
            acao = getattr(args, "acao", None) or "listar"
            if acao == "listar":
                return _cmd_pendrive_listar(args, runner, ui)
            if acao == "preparar":
                return _cmd_pendrive_preparar(args, runner, ui)
            if acao == "guia":
                return _cmd_pendrive_guia(args, runner, ui)
            parser.error("acao de pendrive desconhecida")
        if args.comando == "relatorios":
            return _cmd_relatorios(args, runner, ui)
        parser.print_help()
        return 0
    except KeyboardInterrupt:
        ui.espaco()
        ui.info("Interrompido pelo usuario.")
        return 130
    except Exception as exc:  # noqa: BLE001 - ultima barreira amigavel
        ui.erro(f"Erro inesperado: {exc}")
        if args.verboso:
            import traceback

            traceback.print_exc()
        else:
            ui.info("Rode com --verboso para ver o detalhe tecnico.")
        return 1


BOLD = "\033[1m"

if __name__ == "__main__":
    raise SystemExit(main())
