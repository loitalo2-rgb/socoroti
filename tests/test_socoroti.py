"""Testes do SocorroTI (sem rede, sem privilegios)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from socoroti import access, backup, monitor, net, pendrive, playbooks, ports, report, route, system
from socoroti.model import SEVERIDADE
from socoroti.runner import Runner


# --------------------------------------------------------------------------- amostras
PING_PT_2 = """
Disparando 1.1.1.1 com 32 bytes de dados:
Resposta de 1.1.1.1: bytes=32 tempo=9ms TTL=59
Resposta de 1.1.1.1: bytes=32 tempo=12ms TTL=59

Estatisticas do Ping para 1.1.1.1:
    Pacotes: Enviados = 2, Recebidos = 2, Perdidos = 0 (0% de perda),
Aproximar um numero redondo de vezes em milissegundos:
    Minimo = 9ms, Maximo = 12ms, Media = 10ms
"""

PING_PT_FALHA = """
Disparando 10.255.255.1 com 32 bytes de dados:
Esgotado o tempo limite do pedido.
Esgotado o tempo limite do pedido.

Estatisticas do Ping para 10.255.255.1:
    Pacotes: Enviados = 2, Recebidos = 0, Perdidos = 2 (100% de perda),
"""

PING_EN_LINUX = """
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=14.2 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=117 time=15.1 ms

--- 8.8.8.8 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 14.200/14.650/15.100/0.450 ms
"""

PING_SUB_MS = """
Disparando 192.168.0.1 com 32 bytes de dados:
Resposta de 192.168.0.1: bytes=32 tempo<1ms TTL=64
Resposta de 192.168.0.1: bytes=32 tempo<1ms TTL=64

Pacotes: Enviados = 2, Recebidos = 2, Perdidos = 0 (0% de perda)
"""


# --------------------------------------------------------------------------- helpers
def ping_ok(alvo: str = "x", media: float = 10.0) -> net.PingResult:
    return net.PingResult(alvo=alvo, ok=True, enviados=4, recebidos=4, perda=0.0,
                          rtt_min=media, rtt_avg=media, rtt_max=media)


def ping_falha(alvo: str = "x") -> net.PingResult:
    return net.PingResult(alvo=alvo, ok=False, enviados=4, recebidos=0, perda=100.0)


def info_ok(ip: str = "192.168.0.10/24", gw: str = "192.168.0.1") -> net.NetInfo:
    return net.NetInfo(
        interfaces=[
            net.Iface(nome="eth0", up=True, status="up", ips=[ip], gateway=gw, dns=["1.1.1.1"], dhcp=True),
        ],
        rotas=[net.Route(iface="eth0", gateway=gw)],
        dns=["1.1.1.1"],
        proxy={"enabled": False},
    )


def testes_ok() -> net.NetTests:
    return net.NetTests(
        pings={
            "gateway": ping_ok("192.168.0.1", 1.0),
            "internet": ping_ok("1.1.1.1", 12.0),
            "internet_alt": ping_ok("8.8.8.8", 18.0),
            "host": ping_ok("www.google.com", 15.0),
        },
        dns=[
            net.DnsResult(host="www.google.com", ok=True, ms=12.0, ips=["142.250.0.1"]),
            net.DnsResult(host="www.cloudflare.com", ok=True, ms=14.0, ips=["104.16.0.1"]),
        ],
        tcp=[net.TcpResult(host="1.1.1.1", porta=443, ok=True, ms=20.0)],
        http={"ok": True, "portal": False, "ms": 50.0},
    )


def rodar(info: net.NetInfo, testes: net.NetTests) -> "net.Diagnosis":
    return net.diagnosticar(Runner(), info=info, testes=testes)


# --------------------------------------------------------------------------- parsers
class TestPing(unittest.TestCase):
    def test_pt_br(self) -> None:
        p = net.parse_ping(PING_PT_2, 2)
        self.assertTrue(p.ok)
        self.assertEqual(p.recebidos, 2)
        self.assertEqual(p.perda, 0.0)
        self.assertAlmostEqual(p.rtt_avg or 0, 10.5, places=1)
        self.assertEqual(p.rtt_min, 9.0)
        self.assertEqual(p.rtt_max, 12.0)

    def test_pt_br_falha(self) -> None:
        p = net.parse_ping(PING_PT_FALHA, 2)
        self.assertFalse(p.ok)
        self.assertEqual(p.recebidos, 0)
        self.assertEqual(p.perda, 100.0)

    def test_linux(self) -> None:
        p = net.parse_ping(PING_EN_LINUX, 2)
        self.assertTrue(p.ok)
        self.assertEqual(p.recebidos, 2)
        self.assertAlmostEqual(p.rtt_avg or 0, 14.65, places=2)
        # A linha de resumo "rtt min/avg/max" nao pode ser contada como resposta.
        self.assertEqual(p.recebidos, 2)

    def test_sub_ms(self) -> None:
        p = net.parse_ping(PING_SUB_MS, 2)
        self.assertTrue(p.ok)
        self.assertEqual(p.recebidos, 2)
        self.assertEqual(p.perda, 0.0)

    def test_sem_resposta(self) -> None:
        p = net.parse_ping("", 3)
        self.assertFalse(p.ok)
        self.assertEqual(p.perda, 100.0)


# --------------------------------------------------------------------------- regras de rede
class TestRegrasRede(unittest.TestCase):
    def test_rede_ok(self) -> None:
        diag = rodar(info_ok(), testes_ok())
        ids = {f.id for f in diag.findings}
        self.assertIn("tudo_ok", ids)
        self.assertNotIn("dns_falha", ids)
        self.assertEqual(diag.pior, "ok")

    def test_sem_link(self) -> None:
        info = net.NetInfo(interfaces=[net.Iface(nome="eth0", up=False, status="Disconnected")])
        diag = rodar(info, net.NetTests())
        self.assertEqual(diag.findings[0].id, "sem_link")
        self.assertEqual(diag.pior, "critico")
        self.assertTrue(any(a.key == "verificar_cabo" for a in diag.actions))

    def test_dhcp_apipa(self) -> None:
        info = info_ok(ip="169.254.10.20/16")
        testes = testes_ok()
        testes.pings["gateway"] = ping_falha("192.168.0.1")
        testes.pings["internet"] = ping_falha("1.1.1.1")
        testes.pings["internet_alt"] = ping_falha("8.8.8.8")
        diag = rodar(info, testes)
        ids = {f.id for f in diag.findings}
        self.assertIn("dhcp_falhou", ids)
        self.assertIn("gateway_mudo", ids)
        self.assertTrue(any(a.key == "renovar_dhcp" for a in diag.actions))

    def test_sem_internet_mas_gateway_ok(self) -> None:
        info = info_ok()
        testes = testes_ok()
        testes.pings["internet"] = ping_falha("1.1.1.1")
        testes.pings["internet_alt"] = ping_falha("8.8.8.8")
        testes.pings["host"] = ping_falha("www.google.com")
        diag = rodar(info, testes)
        ids = {f.id for f in diag.findings}
        self.assertIn("sem_internet", ids)
        self.assertTrue(any(a.key == "reiniciar_roteador" for a in diag.actions))

    def test_dns_falha(self) -> None:
        info = info_ok()
        testes = testes_ok()
        testes.dns = [net.DnsResult(host=h, ok=False, erro="timeout") for h in
                      ("www.google.com", "www.cloudflare.com", "www.microsoft.com")]
        diag = rodar(info, testes)
        ids = {f.id for f in diag.findings}
        self.assertIn("dns_falha", ids)
        chaves = {a.key for a in diag.actions}
        self.assertIn("limpar_dns", chaves)
        self.assertIn("dns_publico", chaves)

    def test_perda_de_pacotes(self) -> None:
        info = info_ok()
        testes = testes_ok()
        testes.pings["internet"] = net.PingResult(alvo="1.1.1.1", ok=True, enviados=4, recebidos=3,
                                                  perda=25.0, rtt_avg=20.0)
        diag = rodar(info, testes)
        ids = {f.id for f in diag.findings}
        self.assertIn("perda_pacotes", ids)
        self.assertIn("verificar_cabo", {a.key for a in diag.actions})

    def test_proxy_nao_aparece_so_com_no_proxy(self) -> None:
        info = info_ok()
        info.proxy = {"enabled": False, "env": {"NO_PROXY": "localhost"}}
        diag = rodar(info, testes_ok())
        self.assertNotIn("proxy_ativo", {f.id for f in diag.findings})

    def test_ordenacao_por_gravidade(self) -> None:
        info = info_ok()
        testes = testes_ok()
        testes.pings["internet"] = ping_falha("1.1.1.1")
        testes.pings["internet_alt"] = ping_falha("8.8.8.8")
        diag = rodar(info, testes)
        valores = [SEVERIDADE[f.severity] for f in diag.findings]
        self.assertEqual(valores, sorted(valores, reverse=True))


# --------------------------------------------------------------------------- outros modulos
class TestUtilidades(unittest.TestCase):
    def test_bytes_legivel(self) -> None:
        self.assertEqual(system.bytes_legivel(0), "0 B")
        self.assertEqual(system.bytes_legivel(1024), "1.0 KB")
        self.assertEqual(system.bytes_legivel(1024 ** 3), "1.0 GB")

    def test_data_br(self) -> None:
        self.assertIsNotNone(access._data_br("2025-01-31"))
        self.assertIsNotNone(access._data_br("31/01/2025"))
        self.assertIsNone(access._data_br("nunca"))

    def test_sem_acento(self) -> None:
        self.assertEqual(net._sem_acento("Não há interface"), "nao ha interface")

    def test_relatorio_render(self) -> None:
        diag = rodar(info_ok(), testes_ok())
        texto = report.relatorio_diagnostico(diag).render()
        self.assertIn("# Diagnostico de rede", texto)
        self.assertIn("## Achados", texto)
        self.assertIn("Rede operacional", texto)

    def test_cartao(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            md, html = playbooks.gerar_cartao(destino=Path(tmp), dados={"empresa": "Cliente X"})
            self.assertTrue(md.exists())
            self.assertTrue(html.exists())
            self.assertIn("Cliente X", md.read_text(encoding="utf-8"))
            self.assertIn("init=/bin/bash", html.read_text(encoding="utf-8"))

    def test_playbook_markdown(self) -> None:
        pb = playbooks.obter("windows-boot")
        self.assertIsNotNone(pb)
        texto = playbooks.para_markdown(pb)  # type: ignore[arg-type]
        self.assertIn("bootrec", texto)
        self.assertIn("## Notas", texto)

    def test_todos_playbooks_tem_id_unico(self) -> None:
        ids = [pb.id for pb in playbooks.listar()]
        self.assertEqual(len(ids), len(set(ids)))


class TestExecucao(unittest.TestCase):
    class UI:
        def __init__(self) -> None:
            self.interactive = False

        def paint(self, texto: str, *estilos: str) -> str:
            return texto

        def escrever(self, texto: str = "") -> None:
            pass

        def espaco(self) -> None:
            pass

        def subsecao(self, texto: str) -> None:
            pass

        def paragrafo(self, texto: str, indent: int = 2) -> None:
            pass

        def item(self, texto: str, detalhe: str = "") -> None:
            pass

        def info(self, texto: str) -> None:
            pass

        def aviso(self, texto: str) -> None:
            pass

        def erro(self, texto: str) -> None:
            pass

        def codigo(self, texto: str) -> None:
            pass

        def confirmar(self, pergunta: str, padrao: bool = False) -> bool:
            return False

    def test_executa_acao_automatica(self) -> None:
        import sys

        acao = net.Action(
            key="teste", title="Teste", why="teste", risk="baixo",
            steps=[net.Step("rodar", argv=[sys.executable, "-c", "print('ok')"])],
        )
        resultados = net.executar_acoes(Runner(), [acao], self.UI(), auto=True)
        self.assertEqual(len(resultados), 1)
        self.assertTrue(resultados[0][1])

    def test_pula_risco_alto(self) -> None:
        acao = net.Action(key="perigosa", title="Reset", why="teste", risk="alto",
                          steps=[net.Step("nao rodar", argv=["echo", "x"])])
        resultados = net.executar_acoes(Runner(), [acao], self.UI(), auto=True)
        self.assertFalse(resultados[0][1])
        self.assertIn("risco alto", resultados[0][2])


class TestMonitor(unittest.TestCase):
    def _amostras(self, pares: list[tuple[bool, bool]], intervalo: float = 10.0) -> list[monitor.Amostra]:
        return [
            monitor.Amostra(
                instante=1000.0 + i * intervalo,
                gateway_testado=True,
                gateway_ok=gw,
                gateway_ms=2.0 if gw else None,
                alvo_ok=alvo,
                alvo_ms=15.0 if alvo else None,
            )
            for i, (gw, alvo) in enumerate(pares)
        ]

    def test_queda_local(self) -> None:
        amostras = self._amostras([(True, True), (True, True), (False, False), (False, False), (True, True)])
        resumo = monitor.analisar(amostras, 10.0, alvo="1.1.1.1", gateway="192.168.0.1")
        self.assertEqual(resumo["perda_alvo_pct"], 40.0)
        self.assertEqual(resumo["perda_gateway_pct"], 40.0)
        self.assertEqual(resumo["severidade"], "erro")
        self.assertEqual(len(resumo["quedas"]), 1)
        self.assertEqual(resumo["quedas"][0]["escopo"], "local")
        self.assertEqual(resumo["tempo_fora_s"], 20.0)
        self.assertIn("gateway", resumo["titulo"].lower())

    def test_queda_externa(self) -> None:
        amostras = self._amostras([(True, True), (True, False), (True, False), (True, True)])
        resumo = monitor.analisar(amostras, 10.0, gateway="192.168.0.1")
        self.assertEqual(resumo["perda_gateway_pct"], 0.0)
        self.assertEqual(resumo["quedas"][0]["escopo"], "externa")
        self.assertIn("provedor", resumo["conclusao"].lower())

    def test_estavel(self) -> None:
        resumo = monitor.analisar(self._amostras([(True, True)] * 5), 10.0, gateway="192.168.0.1")
        self.assertEqual(resumo["severidade"], "ok")
        self.assertEqual(resumo["quedas"], [])

    def test_latencia_alta(self) -> None:
        amostras = self._amostras([(True, True)] * 4)
        for a in amostras:
            a.alvo_ms = 250.0
        resumo = monitor.analisar(amostras, 10.0, gateway="192.168.0.1")
        self.assertEqual(resumo["severidade"], "aviso")

    def test_vazio(self) -> None:
        resumo = monitor.analisar([], 10.0)
        self.assertEqual(resumo["amostras"], 0)
        self.assertEqual(resumo["severidade"], "info")


class TestRota(unittest.TestCase):
    TRACERT = """
Rastreando a rota para 8.8.8.8 com no maximo 30 saltos

  1     1 ms     1 ms     1 ms  192.168.0.1
  2     *        *        *     Esgotado o tempo limite do pedido.
  3    10 ms    11 ms    10 ms  100.64.0.1
  4    20 ms    21 ms    20 ms  8.8.8.8

Rastreamento concluido.
"""

    TRACEROUTE = """
traceroute to 1.1.1.1 (1.1.1.1), 20 hops max, 60 byte packets
 1  192.168.0.1  1.234 ms  1.100 ms  1.050 ms
 2  * * *
 3  100.64.0.1  10.500 ms  10.200 ms  10.100 ms
"""

    def test_parse_tracert(self) -> None:
        hops = route.parse_rota(self.TRACERT)
        self.assertEqual([h.numero for h in hops], [1, 2, 3, 4])
        self.assertEqual(hops[0].ip, "192.168.0.1")
        self.assertEqual(hops[1].ip, "")
        self.assertEqual(hops[1].timeouts, 3)
        self.assertAlmostEqual(hops[2].ms or 0, 10.33, places=1)

    def test_parse_traceroute(self) -> None:
        hops = route.parse_rota(self.TRACEROUTE)
        self.assertEqual(len(hops), 3)
        self.assertEqual(hops[2].ip, "100.64.0.1")

    def test_alcancou_destino(self) -> None:
        hops = route.parse_rota(self.TRACERT)
        diag = route.analisar(hops, "8.8.8.8", "8.8.8.8")
        self.assertIn("rota_ok", {f.id for f in diag.findings})
        self.assertEqual(diag.pior, "ok")

    def test_parou_no_caminho(self) -> None:
        hops = route.parse_rota(self.TRACEROUTE)
        diag = route.analisar(hops, "1.1.1.1", "1.1.1.1")
        self.assertIn("rota_parcial", {f.id for f in diag.findings})
        self.assertIn("100.64.0.1", diag.summary)

    def test_sem_dados(self) -> None:
        diag = route.analisar([], "8.8.8.8")
        self.assertIn("rota_sem_dados", {f.id for f in diag.findings})


class TestPortas(unittest.TestCase):
    def test_parse_portas(self) -> None:
        self.assertEqual(ports.parse_portas("80,443, 1-3, 70000, abc"), [1, 2, 3, 80, 443])

    def test_parse_invertido(self) -> None:
        self.assertEqual(ports.parse_portas("5-3"), [3, 4, 5])

    def test_vazio(self) -> None:
        self.assertEqual(ports.parse_portas(""), [])

    def test_servico_conhecido(self) -> None:
        self.assertEqual(ports.SERVICOS[3389], "RDP")
        self.assertEqual(ports.SERVICOS[22], "SSH")


class TestBackup(unittest.TestCase):
    def _preparar(self, tmp: str) -> tuple[Path, Path]:
        raiz = Path(tmp)
        origem = raiz / "Documentos"
        origem.mkdir()
        (origem / "nota.txt").write_text("conteudo", encoding="utf-8")
        (origem / "sub").mkdir()
        (origem / "sub" / "foto.jpg").write_bytes(b"x" * 1024)
        (origem / "desktop.ini").write_text("lixo", encoding="utf-8")
        (origem / "~$contrato.docx").write_text("lixo", encoding="utf-8")
        destino = raiz / "pendrive"
        destino.mkdir()
        return origem, destino

    def test_copia_e_confere(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            origem, destino = self._preparar(tmp)
            resultado = backup.copiar([("Documentos", origem)], destino)
            base = Path(resultado["destino"])
            self.assertEqual(resultado["arquivos"], 2)
            self.assertEqual(resultado["bytes"], len("conteudo") + 1024)
            self.assertTrue((base / "Documentos" / "nota.txt").exists())
            self.assertTrue((base / "Documentos" / "sub" / "foto.jpg").exists())
            self.assertFalse((base / "Documentos" / "desktop.ini").exists())
            self.assertEqual(resultado["erros"], [])

    def test_simular_nao_cria_pasta(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            origem, destino = self._preparar(tmp)
            resultado = backup.copiar([("Documentos", origem)], destino, simular=True)
            self.assertTrue(resultado["simulado"])
            self.assertEqual(resultado["arquivos"], 2)
            self.assertFalse(Path(resultado["destino"]).exists())

    def test_limite_de_tamanho(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            origem, destino = self._preparar(tmp)
            resultado = backup.copiar([("Documentos", origem)], destino, limite_bytes=100)
            self.assertTrue(resultado["limite_atingido"])
            self.assertLessEqual(resultado["bytes"], 100)

    def test_destino_dentro_da_origem(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            origem, _ = self._preparar(tmp)
            with self.assertRaises(backup.BackupError):
                backup.copiar([("Documentos", origem)], origem / "backup")

    def test_medir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            origem, _ = self._preparar(tmp)
            plano = backup.medir([("Documentos", origem)])
            self.assertEqual(plano[0]["arquivos"], 2)
            self.assertEqual(plano[0]["bytes"], len("conteudo") + 1024)


class TestPendrive(unittest.TestCase):
    def test_tamanho_lsblk(self) -> None:
        self.assertEqual(pendrive._tamanho("16G"), 16 * 1024 ** 3)
        self.assertEqual(pendrive._tamanho("512M"), 512 * 1024 ** 2)
        self.assertEqual(pendrive._tamanho(""), 0)

    def test_preparar_copia_kit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            destino = Path(tmp) / "pendrive"
            destino.mkdir()
            resultado = pendrive.preparar(destino, forcar=True)
            self.assertTrue(resultado["arquivos"] > 10)
            kit = Path(resultado["destino"])
            self.assertTrue((kit / "socorro.sh").exists())
            self.assertTrue((kit / "socorro.py").exists())
            self.assertTrue((kit / "socoroti" / "cli.py").exists())
            self.assertTrue((kit / "INICIAR-AQUI.txt").exists())
            self.assertTrue((kit / "GUIA-BOOT.md").exists())
            self.assertIn("Ventoy", (kit / "INICIAR-AQUI.txt").read_text(encoding="utf-8"))

    def test_destino_dentro_do_kit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            origem = Path(tmp) / "kit"
            origem.mkdir()
            (origem / "socorro.py").write_text("x", encoding="utf-8")
            destino = origem / "backup"
            destino.mkdir()
            with self.assertRaises(pendrive.PendriveError):
                pendrive.preparar(destino, origem=origem, forcar=True)

    def test_guia_tem_opcoes_de_boot(self) -> None:
        texto = pendrive.gerar_guia().render()
        self.assertIn("Ventoy", texto)
        self.assertIn("Rufus", texto)
        self.assertIn("Windows PE", texto)
        self.assertIn("python-zip", texto)

    def test_python_embutido(self) -> None:
        import zipfile

        with tempfile.TemporaryDirectory() as tmp:
            zip_path = Path(tmp) / "python.zip"
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("python.exe", "fake")
                zf.writestr("python313._pth", "python313.zip\n.\n")
            destino = Path(tmp) / "pendrive"
            destino.mkdir()
            resultado = pendrive.preparar(destino, python_zip=zip_path, forcar=True)
            self.assertTrue(resultado["python_embutido"])
            kit = Path(resultado["destino"])
            self.assertTrue((kit / "python" / "python.exe").exists())
            self.assertTrue((kit / "socorro-pe.cmd").exists())
            pth = (kit / "python" / "python313._pth").read_text(encoding="utf-8")
            self.assertIn("..", pth.splitlines())


if __name__ == "__main__":
    unittest.main()
