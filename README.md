# SocorroTI

Kit portátil de **primeiros socorros para técnicos de TI**. Roda direto de um pendrive, sem instalação e sem dependências externas, em **Windows** e **Linux**.

A ideia é simples: o técnico chega no equipamento, roda **um comando** e recebe um diagnóstico em linguagem clara, com a causa provável e um plano de ação — em vez de sair testando tudo no escuro.

```
socorro rede diagnostico
socorro rede solucionar
socorro rede monitor          # quedas intermitentes: grava e prova
socorro acesso recuperar
socorro backup --destino E:\  # antes de formatar/reinstalar
socorro diagnostico           # rede + acesso + computador, com relatório para o chamado
socorro menu                  # modo plantão
```

> **Uso responsável:** as rotinas de recuperação de acesso assumem que você é o dono do equipamento ou tem autorização do responsável. O SocorroTI usa apenas canais administrativos legítimos (contas admin, WinRE, GRUB, chroot, RDP/SSH). Ele **não** burla autenticação remota nem instala backdoors.

## Baixar

- **Windows sem Python instalado:** baixe `socorro.exe` em [Releases](https://github.com/loitalo2-rgb/socoroti/releases/latest) e rode no terminal: `socorro.exe diagnostico`.
- **Código-fonte (Windows/Linux, precisa de Python 3.9+):**

```bash
git clone https://github.com/loitalo2-rgb/socoroti
cd socoroti
python -m socoroti diagnostico
```

- **Pendrive de resgate:** o guia completo de boot (Ventoy, Rufus e Windows PE) está em [`socorro pendrive guia`](#pendrive-de-boot).

---

## Índice

- [Por que ele é leve](#por-que-ele-é-leve)
- [Baixar](#baixar)
- [Instalação / uso no pendrive](#instalação--uso-no-pendrive)
- [Comandos](#comandos)
- [Recuperar senha em um comando](#recuperar-senha-em-um-comando)
- [Rede: como o diagnóstico funciona](#rede-como-o-diagnóstico-funciona)
- [Rede: correções automáticas e assistidas](#rede-correções-automáticas-e-assistidas)
- [Rede: monitor, rota e portas](#rede-monitor-rota-e-portas)
- [Backup de emergência](#backup-de-emergência)
- [Pendrive de boot](#pendrive-de-boot)
- [Acesso: contas, RDP/SSH, boot e recuperação](#acesso-contas-rdpssh-boot-e-recuperação)
- [Playbooks de recuperação](#playbooks-de-recuperação)
- [Cartão de recuperação](#cartão-de-recuperação)
- [Relatórios, JSON e códigos de saída](#relatórios-json-e-códigos-de-saída)
- [Onde ficam os dados](#onde-ficam-os-dados)
- [Testes](#testes)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Limitações e segurança](#limitações-e-segurança)
- [Solução de problemas](#solução-de-problemas)

---

## Por que ele é leve

- **Só Python padrão** — nenhuma biblioteca para instalar (`pip install` não é necessário).
- **Um pacote pequeno**, sem banco de dados, sem serviço em background e sem instalador.
- Pensado para **pendrive**: relatórios, cartões e roteiros são salvos na própria pasta `dados/` quando ela é gravável.
- Saída **legível para humano** e também **JSON** para automação.
- Funciona sem privilégios (com diagnóstico limitado) e aproveita admin/root quando disponível.

Requisito: **Python 3.9+**. No Linux ele já costuma estar presente. No Windows, instale uma vez marcando *Add Python to PATH* — ou use o pacote *embeddable* do Python no próprio pendrive.

---

## Instalação / uso no pendrive

Copie a pasta inteira para o pendrive. Ela deve ficar assim:

```
pendrive/
├─ socorro.cmd        ← Windows (clique duplo ou arraste para o terminal)
├─ socorro.sh         ← Linux
├─ socoroti/          ← programa
├─ tests/
├─ pyproject.toml
├─ dados/             ← criado automaticamente (relatórios)
└─ README.md
```

### Windows

```bat
socorro.cmd rede diagnostico
```

ou, no PowerShell/cmd dentro da pasta:

```powershell
python -m socoroti rede diagnostico
```

Dica: para ter o comando `socorro` em qualquer pasta, rode uma vez:

```powershell
pip install .
```

### Linux

```bash
chmod +x socorro.sh
./socorro.sh rede diagnostico
# ou
python3 -m socoroti rede diagnostico
```

Para instalar como comando do sistema:

```bash
pip3 install --user .
socorro rede diagnostico
```

### Ajuda

```bash
python -m socoroti --help
python -m socoroti rede --help
python -m socoroti acesso --help
```

Opções globais (antes do comando):

| Opção | Efeito |
|---|---|
| `--sem-cor` | desativa cores |
| `--ascii` | evita caracteres especiais |
| `--verboso` / `-v` | mostra cada comando executado |
| `--json` | saída JSON para automação |
| `--sem-relatorio` | não grava relatório em disco |
| `--elevar` | no Windows, reabre o programa como Administrador |
| `--versao` | mostra a versão |

---

## Comandos

| Comando | O que faz |
|---|---|
| `socorro rede diagnostico` | Analisa interfaces, gateway, internet, DNS, TCP, HTTP e (com `--completo`) MTU. Mostra causa provável e plano. |
| `socorro rede solucionar` | Diagnostica e aplica correções com confirmação; re-testa no final. |
| `socorro rede solucionar --auto` | Aplica correções de risco baixo/médio sem perguntar. |
| `socorro rede solucionar --simular` | Só mostra o que faria (não altera nada). |
| `socorro rede solucionar --tudo` | Inclui também ações de risco alto (reset de pilha, etc.). |
| `socorro rede ping 1.1.1.1` | Ping com gráfico de barras e resumo (min/média/max/perda). |
| `socorro rede ping 8.8.8.8 -n 100 --continuo` | Monitora até `Ctrl+C`. |
| `socorro rede monitor` | Acompanha quedas/latência por vários minutos (padrão 5 min), separa problema local × provedor e salva relatório/CSV. |
| `socorro rede rota 8.8.8.8` | Traceroute interpretado: mostra até qual salto a conexão chega e onde provavelmente para. |
| `socorro rede portas host 80,443,3389` | Testa portas TCP em paralelo: aberta, fechada (serviço parado) ou filtrada (firewall/rota). |
| `socorro backup --destino E:\` | Copia Documentos/Desktop/Downloads/etc. para o pendrive, confere o tamanho e não apaga nada. |
| `socorro senha` | **Recupera a senha em um comando:** lista contas, gera senha forte, redefine, ativa e desbloqueia. |
| `socorro pendrive listar` | Lista pendrives/volumes USB com letra, modelo, sistema de arquivos e espaço. |
| `socorro pendrive preparar --destino G:\` | Copia o kit para `G:\SocorroTI` e cria o `INICIAR-AQUI.txt` (sem apagar nada). |
| `socorro pendrive guia` | Gera o guia de boot (Ventoy, Rufus e Windows PE) em Markdown. |
| `socorro acesso diagnostico` | Contas, bloqueios, expiração de senha, RDP/SSH, firewall, WinRE, BitLocker/LUKS, disco e sessões. |
| `socorro acesso recuperar` | Diagnostica e abre um roteiro guiado de recuperação. |
| `socorro acesso remoto` | Foco em RDP/SSH: mostra o que está bloqueando e como liberar. `--aplicar` executa (com admin). |
| `socorro acesso playbooks` | Lista os roteiros; `socorro acesso playbooks windows-boot` abre um. |
| `socorro sistema diagnostico` | Disco, memória, CPU, saúde dos discos, temperatura e top processos. |
| `socorro sistema limpeza` | Mede caches/temporários e mostra os comandos de limpeza (não apaga nada). |
| `socorro diagnostico` | Tudo junto: rede + acesso + computador, com resumo geral e relatório único. |
| `socorro cartao` | Gera o cartão de recuperação em Markdown e HTML (imprimível). |
| `socorro relatorios` | Lista os relatórios salvos (`--abrir` abre o mais recente). |
| `socorro menu` | Menu interativo de plantão. |

### Exemplos rápidos

```bash
# "Caiu a internet"
socorro rede diagnostico
socorro rede solucionar --auto

# "Está lenta / perdendo pacotes"
socorro rede ping 1.1.1.1 -n 60 --continuo

# "Cai de vez em quando" (grava 10 min e gera prova para o provedor)
socorro rede monitor --duracao 600 --csv

# "O site/servidor não abre"
socorro rede portas meuservidor.com 80,443

# "Vou formatar, preciso salvar os arquivos"
socorro backup --destino E:\ --auto

# "Perdi o acesso ao computador" (na máquina)
socorro acesso recuperar

# "Perdi a senha" (um comando resolve)
socorro senha

# "Nem eu entro mais por RDP"
socorro acesso remoto

# "Vou abrir chamado / preciso documentar"
socorro diagnostico --completo

# "Deixar o cliente preparado para a próxima"
socorro cartao --interativo
```

---

## Recuperar senha em um comando

Perdeu a senha e não quer reinstalar nada? Rode:

```bash
socorro senha
```

O comando faz tudo em uma execução:

1. lista as contas locais e pergunta qual recuperar;
2. gera uma senha forte (14 caracteres, sem `0/O` nem `1/l/I`) ou usa a que você digitar;
3. redefine a senha, **ativa e desbloqueia** a conta;
4. mostra a senha uma única vez e salva um relatório **sem** a senha.

Para automação (sem perguntas):

```bash
socorro senha --usuario ana --gerar --auto
socorro senha -u ana -s "MinhaSenha1!" --auto
socorro --json senha -u ana --gerar --auto
```

### O que precisa

| Situação | Como funciona |
|---|---|
| Windows com outra conta admin | `socorro senha` pede o UAC e conclui sozinho. |
| Windows sem sessão admin | O comando oferece abrir a janela elevada (UAC) e continua nela. |
| Linux com acesso root | `sudo socorro senha -u ana` usa `chpasswd`. |
| Perdeu o **único** admin | Boot pelo Linux live, monte o disco do Windows e rode `sudo socorro senha --offline --usuario NOME`. |

### Modo offline (o clássico "perdi o único administrador")

```bash
# no Linux live, com o disco do Windows montado (automático se estiver em /mnt ou /media):
sudo socorro senha --offline --usuario NOME
# ou apontando a montagem:
sudo socorro senha --montagem /mnt/windows --usuario NOME
```

O modo offline usa o `chntpw` (ferramenta de resgate consolidada): ele **limpa** a senha, então você entra sem senha e cadastra uma nova no primeiro login. Antes de alterar, o SocorroTI copia `SAM`, `SYSTEM` e `SECURITY` para `.socoroti-backup/`. Se o `chntpw` não estiver instalado, o comando oferece `sudo apt install chntpw`.

> **Uso responsável:** redefinir senha só é legítimo no seu equipamento ou com autorização do responsável. O SocorroTI não cria backdoors, não contorna autenticação remota e não registra senhas em relatório.

---

## Rede: como o diagnóstico funciona

O SocorroTI coleta o estado real da máquina e roda testes em paralelo:

**1. Estado local**
- adaptadores ativos/inativos, IP, DHCP, gateway e DNS (Windows via `Get-Net*`; Linux via `ip -j` + `resolv.conf`);
- rota padrão e conflitos de rota (VPN/overlay, duas redes ao mesmo tempo);
- Wi-Fi: SSID, sinal (%) e taxa;
- proxy do sistema/ambiente e adaptadores virtuais.

**2. Testes de conectividade**
- ping para o gateway, `1.1.1.1`, `8.8.8.8` e `www.google.com` — em paralelo, com perda e latência;
- resolução DNS de três domínios diferentes;
- conexão TCP 443/53 (para diferenciar bloqueio de ICMP de bloqueio real);
- HTTP real com detecção de **portal cativo** (Wi-Fi de hotel/aeroporto);
- opcional (`--completo`): descoberta de MTU com pacote `DF`.

**3. Classificação por regras**

| Sintoma detectado | Interpretação |
|---|---|
| Nenhum adaptador ativo | Problema físico/local: cabo, Wi-Fi desligado, adaptador desabilitado |
| IP `169.254.x.x` | DHCP não respondeu |
| Sem rota padrão | Gateway ausente / configuração incompleta |
| Gateway não responde | Computador não chega nem ao roteador |
| Gateway OK, internet 100% perda | Link do provedor, modem, WAN ou bloqueio |
| Internet OK, DNS não resolve | DNS do provedor/roteador ou cache |
| HTTP redirecionado | Portal de autenticação |
| Ping OK, TCP 443 falha | Firewall/antivírus/proxy |
| Perda > 0% ou latência > 150 ms | Wi-Fi/cabo instável ou congestionamento |
| Pacote grande falha | MTU baixo (VPN/túnel) |

Cada achado recebe uma gravidade (`OK`, `INFO`, `ATENÇÃO`, `ERRO`, `CRÍTICO`) e vira uma linha do plano de ação — sem "achismo".

---

## Rede: correções automáticas e assistidas

O comando `solucionar` **sempre diagnostica antes** e só recomenda o que faz sentido para o caso. Correções executáveis pedem confirmação (ou usam `--auto`), têm nível de risco e são registradas no relatório.

| Correção | Windows | Linux | Risco |
|---|---|---|---|
| Renovar DHCP | `ipconfig /release` + `/renew` | `nmcli device reapply` | médio |
| Limpar cache DNS | `ipconfig /flushdns` | `resolvectl flush-caches` | baixo |
| Trocar DNS | `Set-DnsClientServerAddress` | `resolvectl dns` | médio |
| Reiniciar adaptador | `Restart-NetAdapter` | `ip link set down/up` | médio |
| Resetar pilha TCP/IP | `netsh winsock reset` + `netsh int ip reset` | — | alto |
| Reiniciar serviço DNS | `Restart-Service Dnscache` | — | médio |
| Desativar proxy | registro + `netsh winhttp` | remover variáveis | baixo |
| Reconectar Wi-Fi | `netsh wlan` | `nmcli` | baixo |

O que **não** é automatizado (por segurança ou por ser externo) aparece como ação assistida com o passo a passo: reiniciar roteador, testar cabo/porta, acionar provedor, conferir firewall, autenticar em portal, ajustar MTU, etc.

Ao final, o SocorroTI refaz os testes e mostra **antes × depois**.

> Ações que exigem administrador são executadas apenas se você estiver elevado. Caso contrário, o comando exato é exibido para você rodar como admin — ou use `socorro.cmd ... --elevar` no Windows.

---

## Rede: monitor, rota e portas

O diagnóstico comum é uma **foto** do momento. Para os casos que mais voltam ao plantão, o SocorroTI tem três ferramentas de acompanhamento.

### Monitor de estabilidade

```bash
socorro rede monitor
socorro rede monitor --duracao 600 --intervalo 2 --alvo 1.1.1.1
socorro rede monitor --duracao 1800 --sem-gateway --csv
```

A cada intervalo ele pinga o **gateway** (roteador) e o **alvo**. No fim (ou ao `Ctrl+C`), entrega:

- perda de pacotes para o alvo e para o gateway;
- número de quedas, horário de início/fim e tempo total fora;
- latência mínima/média/máxima e jitter;
- **conclusão**: se o gateway também caiu, o problema é local (cabo/Wi-Fi/roteador); se só a internet caiu, o problema é do provedor/rota externa.

Objetos importantes:

| Opção | Efeito |
|---|---|
| `--duracao` | duração total em segundos (padrão `300`) |
| `--intervalo` | segundos entre amostras (padrão `2`) |
| `--alvo` | host/IP de referência (padrão `1.1.1.1`) |
| `--sem-gateway` | não testa o gateway local |
| `--csv` | salva as amostras em CSV, além do relatório |

O relatório Markdown e o CSV ficam em `dados/relatorios/` — ótimos para anexar ao chamado e provar a queda ao provedor.

### Rota (traceroute)

```bash
socorro rede rota 8.8.8.8
socorro rede rota meuservidor.com --max 15
```

Usa `tracert` no Windows e `traceroute`, `tracepath` ou `mtr` no Linux. A saída mostra cada salto com IP e latência e responde: **até onde a conexão chega?** Se ela para no salto 1, o problema é local; nos primeiros saltos, é do provedor; mais adiante, é rota externa/destino. Saltos mudos isolados com saltos seguintes respondendo são marcados como normais (filtro de ICMP).

### Teste de portas

```bash
socorro rede portas meuservidor.com 80,443
socorro rede portas 192.168.0.10 3389
socorro rede portas 192.168.0.10 1-1024 --timeout 1
```

Testa em paralelo e classifica cada porta:

| Estado | Significado |
|---|---|
| **aberta** | algo está atendendo (serviço no ar) |
| **fechada** | o host respondeu e recusou (serviço parado ou porta diferente) |
| **filtrada** | sem resposta (firewall, host desligado ou IP errado) |
| **inacessível** | não há rota até o host |

É a forma rápida de separar "o servidor caiu" de "o firewall bloqueia" — e de conferir RDP/SSH sem abrir o sistema do outro lado.

---

## Backup de emergência

Antes de formatar, reinstalar ou trocar disco, salve os dados:

```bash
socorro backup --destino E:\ --auto
socorro backup --destino /media/pendrive --simular
socorro backup --destino E:\ --pastas Desktop,Documents --limite-gb 20
socorro backup --destino E:\ --incluir-chaves
```

O que ele faz:

- encontra as pastas comuns do usuário (Desktop, Documents, Downloads, Imagens, Vídeos, Músicas — inclusive as localizadas no Linux e as do OneDrive);
- mostra o **tamanho total** e o **espaço livre** no destino antes de copiar;
- copia para `SocorroTI-backup-HOST-DATA-HORA/`, preservando a estrutura;
- **confere o tamanho de cada arquivo** depois da cópia;
- ignora lixo (`desktop.ini`, `Thumbs.db`, arquivos temporários e travas `~$`) e **não segue links simbólicos**;
- nunca apaga nada da origem.

| Opção | Efeito |
|---|---|
| `--destino` | pasta/drive de destino (ex.: `E:\` ou `/media/pendrive`) |
| `--pastas` | pastas por nome ou caminho, separadas por vírgula |
| `--limite-gb` | limita o total copiado (`0` = sem limite) |
| `--simular` | só mede, não cria nada no destino |
| `--auto` | não pede confirmação (bom para script) |
| `--incluir-chaves` | inclui `.ssh`, `.gnupg` e `.aws` |

> O backup não substitui uma solução de backup contínua. Ele é o "salvar antes de mexer" do plantão. Depois da cópia, abra alguns arquivos no destino para confirmar.

---

## Pendrive de boot

Os arquivos do SocorroTI **não inicializam sozinhos**: para dar boot é preciso um carregador (Ventoy/Rufus) e um sistema vivo (Linux live ou Windows PE). O kit ajuda a preparar a pasta e explica cada caminho:

```bash
socorro pendrive listar
socorro pendrive preparar --destino G:\
socorro pendrive guia
socorro pendrive guia --mostrar
```

`preparar` copia o programa para `<pendrive>/SocorroTI/`, gera o `INICIAR-AQUI.txt` e **não apaga nada**. Ele se recusa a escrever na unidade do sistema (use `--forcar` só se souber o que está fazendo).

### Caminhos recomendados

| Caminho | Como funciona | Melhor para |
|---|---|---|
| **Ventoy** (recomendado) | Instala o carregador uma vez; depois é só copiar ISOs e a pasta `SocorroTI` para a partição de dados. | Ter Linux live + ISO do Windows + kit no mesmo pendrive, sem regravar. |
| **Rufus + Linux live** | Grava uma ISO (Ubuntu/Fedora) no pendrive; o kit roda pelo terminal do sistema live. | Quando já existe o pendrive e uma ISO. |
| **Windows PE / Hiren's** | Precisa de Python embutido ou de um `socorro.exe` gerado com PyInstaller. | Resgate em máquinas só Windows, sem Linux. |

Dentro do Linux live:

```bash
cd /media/$USER/Ventoy/SocorroTI
bash socorro.sh rede diagnostico
bash socorro.sh rede monitor --duracao 600 --csv
```

Para Windows PE, leve o Python embeddable junto:

```bash
socorro pendrive preparar --destino G:\ --python-zip python-3.13-embed-amd64.zip
```

Or gere um executável único no seu Windows:

```bash
pip install pyinstaller
pyinstaller --onefile --name socorro socorro.py
```

O `socorro.exe` gerado em `dist/` é copiado automaticamente por `socorro pendrive preparar`. Ele roda em Windows normal e em Windows PE/Hiren's **sem precisar de Python instalado**.

O guia completo (com cuidados, tabela do que funciona em cada ambiente e passo a passo do Ventoy/Rufus) é gerado por `socorro pendrive guia` e salvo em `dados/relatorios/`.

> Em resgate, confirme o disco certo antes de montar/copiar. BitLocker/LUKS sem a chave não tem recuperação legítima — o kit orienta, não burla.

---

## Acesso: contas, RDP/SSH, boot e recuperação

`socorro acesso diagnostico` responde perguntas como:

- Minha conta está **desativada, bloqueada ou com senha expirada**?
- Existe **outra conta administradora ativa** (essencial para recuperar)?
- O **RDP/SSH** está habilitado, o serviço está rodando, a porta está ouvindo e o firewall libera?
- O **WinRE** (Windows) está disponível? Secure Boot? BitLocker/LUKS?
- O disco do sistema tem espaço? Há sessões ativas de outro admin?
- A máquina está em domínio (quem recupera é o AD)?

Com isso ele monta um plano com ações seguras e roteiros. Exemplos:

```powershell
# Windows: habilitar RDP (como admin)
socorro acesso remoto --aplicar

# Reativar uma conta local desativada (com admin)
net user NOME /active:yes
```

```bash
# Linux: ligar SSH e conferir
sudo systemctl enable --now ssh
ss -ltn | grep ':22 '
```

As ações de redefinição de senha são **assistidas**: o comando é mostrado, mas a senha é digitada por você no prompt do sistema (ela não passa pelo SocorroTI nem vai para logs/relatórios).

---

## Playbooks de recuperação

Roteiros prontos, em português, para os cenários mais comuns:

| ID | Cenário |
|---|---|
| `windows-senha` | Perdi a senha / conta bloqueada no Windows |
| `windows-boot` | Windows não inicia, tela azul, erro de boot |
| `linux-senha` | Perdi a senha no Linux (acesso físico) |
| `linux-boot` | GRUB rescue, kernel panic, sistema não sobe |
| `windows-remoto` | RDP parou de entrar |
| `linux-remoto` | SSH parou de entrar |
| `bitlocker` | Tela de recuperação do BitLocker |
| `rede-local` | Ninguém na rede navega / sem DHCP |
| `prevencao` | Checklist para deixar o equipamento recuperável |

```bash
socorro acesso playbooks
socorro acesso playbooks windows-boot
socorro acesso recuperar --playbook linux-senha
```

Cada roteiro é salvo em Markdown em `dados/playbooks/` para anexar ao chamado ou imprimir.

---

## Cartão de recuperação

```bash
socorro cartao --interativo
socorro cartao --empresa "Cliente X" --modelo "Dell 7090" --rede "192.168.0.10 / AA:BB:..."
```

Gera:

- `dados/cartao/cartao-recuperacao-AAAAMMDD.md`
- `dados/cartao/cartao-recuperacao-AAAAMMDD.html` ← abra e imprima (A4)

O cartão traz campos de identificação, comandos de resgate do Windows e do Linux, acesso remoto e checklist. Por segurança, ele **não** imprime senhas nem a chave do BitLocker — apenas onde encontrá-las.

---

## Relatórios, JSON e códigos de saída

Todo diagnóstico salva um relatório Markdown em `dados/relatorios/` (exceto com `--sem-relatorio`):

- resumo em uma linha (bom para abrir chamado);
- tabela de achados com gravidade, detalhe e causa provável;
- plano de ação com comandos;
- dados técnicos coletados em JSON.

Para automação:

```bash
python -m socoroti --json rede diagnostico
python -m socoroti --json diagnostico --completo
```

Códigos de saída:

| Código | Significado |
|---|---|
| `0` | tudo OK ou apenas informativo |
| `1` | há aviso, erro ou crítico (ou falha na verificação) |
| `2` | erro de uso / falta de permissão para elevar |
| `130` | interrompido com `Ctrl+C` |

---

## Onde ficam os dados

Por padrão, ao lado da ferramenta (ideal para pendrive):

```
dados/
├─ relatorios/   *.md e *.csv
├─ playbooks/    *.md
└─ cartao/       *.md + *.html
```

Se a pasta não for gravável, o SocorroTI cai para:

- Windows: `%LOCALAPPDATA%\SocorroTI`
- Linux: `~/.local/share/socorro-ti`

Para escolher outro lugar:

```bash
SOCORRO_DADOS=/caminho/dados socorro diagnostico
```

> Relatórios contêm hostname, IP, MAC, contas e configuração. **Revise antes de enviar** para terceiros.

---

## Testes

O projeto tem testes de unidade para os parsers e para o motor de regras (sem tocar na rede):

```bash
python -m unittest discover -s tests -v
```

São 56 testes cobrindo:

- leitura de `ping` em português/inglês, perda total e `<1ms`;
- cenários de rede: tudo OK, sem link, APIPA/DHCP, sem internet, DNS, perda de pacotes, proxy;
- monitor de estabilidade: queda local × externa, latência alta e série vazia;
- parsers de `tracert`/`traceroute`, listas de portas com intervalos e backup (cópia, limite, simulação e destino inválido);
- preparação de pendrive, Python embutido e conteúdo do guia de boot;
- recuperação de senha: geração forte, escape de PowerShell, contas e modo offline;
- ordenação por gravidade e execução de ações (incluindo bloqueio de risco alto);
- relatório, cartão e playbooks;
- utilitários (bytes, datas, acentos).

---

## Estrutura do projeto

```
socoroti/
├─ cli.py            comandos, menu, JSON, relatórios
├─ net.py            coleta + testes + regras + correções de rede
├─ monitor.py        monitor de estabilidade (quedas ao longo do tempo)
├─ route.py          traceroute interpretado
├─ ports.py          teste de portas TCP
├─ backup.py         backup de emergência com verificação
├─ senha.py          recuperação de senha online e offline (um comando)
├─ pendrive.py       preparação do pendrive e guia de boot
├─ access.py         contas, RDP/SSH, boot, BitLocker/LUKS, ações
├─ system.py         disco, memória, CPU, saúde, limpeza
├─ playbooks.py      roteiros de recuperação + cartão imprimível
├─ model.py          Finding / Action / Diagnosis / gravidade
├─ runner.py         execução de comandos, timeout e encoding
├─ report.py         relatórios Markdown/JSON
├─ ui.py             cores, tabelas, ícones e perguntas
├─ platform_info.py  SO, admin, pastas portáteis
└─ __main__.py       python -m socoroti
```

Sem dependências externas. Sem threads além dos testes em paralelo. Um processo, um comando, um relatório.

---

## Limitações e segurança

- **ICMP bloqueado** por alguns provedores/empresas pode gerar falso "sem internet". O SocorroTI cruza com DNS, TCP e HTTP justamente para reduzir isso.
- **Saída localizada** de ferramentas do sistema é tratada por regex tolerante (pt/en/es/fr), mas versões muito diferentes podem exigir ajuste.
- **Traceroute** depende de ICMP/UDP; redes que bloqueiam esses pacotes podem mostrar saltos mudos mesmo com a conexão funcionando.
- **Monitor** usa amostras de 1 pacote; para laudos oficiais, use intervalos maiores e uma duração que cubra o horário das quedas.
- **Backup** copia apenas o que o usuário tem permissão de ler; arquivos abertos/bloqueados aparecem como erro no relatório. Ele não substitui backup corporativo.
- **Proxy obrigatório** pode fazer o teste HTTP direto falhar; o relatório mostra o proxy configurado.
- **BitLocker/LUKS**: sem a chave/passphrase não há recuperação legítima dos dados. O foco é documentar e prevenir.
- **Diagnóstico de contas Linux** de outros usuários exige root (`passwd -S`).
- **RDP exposto na internet é risco alto.** Prefira VPN/overlay (ZeroTier, Tailscale, WireGuard).
- O SocorroTI **não**:
  - captura ou exibe senhas;
  - substitui `utilman.exe`/`sethc.exe` ou aplica patches de SAM;
  - instala persistência/backdoor;
  - contorna autenticação de terceiros.

Use em equipamentos próprios ou com autorização formal. Em ambiente corporativo, siga a política da empresa.

---

## Solução de problemas

| Problema | Causa provável | Solução |
|---|---|---|
| `python` não encontrado (Windows) | Python fora do PATH | Reinstale marcando *Add Python to PATH* ou use `py -3` |
| `ping` não encontrado (Linux) | `iputils-ping` ausente | `sudo apt install iputils-ping` |
| `ip` não encontrado (Linux) | `iproute2` ausente | `sudo apt install iproute2` |
| Dados de RDP/WinRE limitados | sem admin/root | rode como Administrador ou `sudo` |
| Acentos estranhos no console | página de código antiga | use Windows Terminal/PowerShell 7 ou `--ascii` |
| Relatório não salva | pendrive somente leitura | use `SOCORRO_DADOS` para uma pasta gravável |

---

Feito para a mochila do técnico: **diagnosticar rápido, explicar a causa e recuperar o acesso** — com rastro documentado.
