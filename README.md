# FiveMGuard

Ferramenta em C++ para diagnosticar e preparar o **Windows Server 2012 R2 Datacenter x64**
para hospedar um servidor **FiveM/FXServer**.

O programa verifica o sistema, aplica ajustes de segurança, cria regras de firewall,
instala dependências, configura políticas de navegador e prepara a pasta do servidor.
Tudo em português, com log, relatório e backup para rollback.

> **Teste primeiro em uma máquina virtual ou snapshot.** Este programa altera registro,
> firewall, políticas de segurança e instala componentes. Uma aplicação em produção sem
> teste prévio pode deixar o servidor inacessível.

---

## Avisos importantes

### Windows Server 2012 R2 está fora do suporte

O Windows Server 2012 R2 teve o fim do suporte estendido da Microsoft em **10/10/2023**.
Ele não recebe mais atualizações de segurança gratuitas. Use este sistema apenas se
realmente for necessário, mantenha-o isolado, restrinja o acesso e planeje a migração
para uma versão suportada do Windows Server.

Este projeto **não torna o Windows Server 2012 R2 seguro ou suportado**. Ele apenas
automatiza configurações básicas de preparação.

### A chave de licença do FiveM é manual

O `server.cfg` gerado contém o marcador:

```text
COLE_SUA_CHAVE_DE_LICENCA
```

A chave é gratuita, individual e deve ser obtida em <https://portal.cfx.re>. O programa
**não** automatiza login, obtenção ou preenchimento da chave.

### O rollback é parcial

O rollback restaura o que foi registrado no backup:

- valores de registro alterados e chaves exportadas;
- regras de firewall criadas pelo FiveMGuard;
- estado anterior da conta Guest;
- política do Firefox;
- plano de energia ativo.

Ele **não** desinstala o VC++ Redistributable/.NET, não desinstala Chrome/Node/Git/7-Zip,
não apaga downloads, não remove
arquivos do servidor e não restaura o estado ligado/desligado dos perfis de firewall.
Para uma reversão completa, use snapshot da VM ou backup do sistema.

### Não exponha o txAdmin

Por padrão, a porta `40120/TCP` do txAdmin é liberada apenas nos perfis `domain` e
`private`, restrita a `LocalSubnet`. Não abra essa porta para a internet sem VPN,
túnel SSH, senha forte e proteção adicional.

---

## O que o programa faz

| Etapa | Ações principais |
|---|---|
| Diagnóstico | Sistema, hardware, discos, rede, portas, runtime VC++, .NET, PowerShell, firewall, SMB, TLS, RDP, IE ESC, navegadores e pasta do servidor |
| Segurança | TLS 1.2, desativação opcional de TLS 1.0/1.1, SSL 2.0/3.0, SMBv1, assinatura SMB, NLA no RDP, NTLMv2, Guest, AutoRun, exibição do último usuário, exclusões do Defender e plano de energia |
| Firewall | Regras TCP/UDP para a porta do jogo, txAdmin restrito, portas extras opcionais e regra de RDP preventiva |
| Dependências | VC++ Redistributable 2015-2022 14.29 (x64/x86), .NET Framework 4.8 opcional, verificação de assinatura Authenticode |
| Ferramentas extras | Chrome, Node.js, Git for Windows e 7-Zip (download + instalação silenciosa) |
| Navegadores | IE, Chrome, Edge e Firefox: página inicial, TLS mínimo, navegação segura e sites confiáveis |
| Servidor FiveM | Pastas, `server.cfg`, `server.cfg.example`, `start-server.cmd`, leia-me e download opcional do FXServer/cfx-server-data |
| Rollback | Registro, firewall, Guest, política do Firefox e plano de energia |

---

## Requisitos

### Para executar

- Windows Server 2012 R2 Datacenter **x64** (build 9600);
- sessão com privilégios de administrador;
- acesso à internet para downloads, consulta de IP público e obtenção dos artefatos do FiveM;
- PowerShell disponível (nativo no 2012 R2);
- espaço livre recomendado: pelo menos 2 GB para downloads e arquivos do servidor;
- snapshot ou backup do sistema antes da primeira aplicação.

### Para compilar

- Windows com PowerShell 5.1 ou superior para compilar (o executável roda no 2012 R2);
- **MinGW-w64 x64** com `g++.exe` e `windres.exe` no mesmo diretório. O projeto foi
  compilado com o [w64devkit](https://github.com/skeeto/w64devkit);
- não é necessário MSVC.

O build usa `_WIN32_WINNT=0x0603`, runtime C++ estático e manifesto administrativo,
para manter compatibilidade com Windows 8.1/Server 2012 R2.

---

## Compilação

No diretório do projeto:

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1 -Compiler "C:\w64devkit\bin\g++.exe"
```

O script gera:

- `FiveMGuard.exe` — versão de produção, com manifesto `requireAdministrator`;
- `FiveMGuard-teste.exe` — versão de teste, com manifesto `asInvoker`, para executar
  sem UAC em sessões não elevadas.

Opções do script:

```powershell
.\build.ps1 -Clean       # remove build/ e os executáveis gerados
.\build.ps1 -TestOnly    # compila apenas FiveMGuard.exe
.\build.ps1 -NoStrip     # mantém símbolos para depuração
```

Se o `g++` não estiver nos caminhos procurados pelo script, informe o caminho completo
com `-Compiler`. O `windres.exe` precisa estar ao lado dele.

**Não use `FiveMGuard-teste.exe` em produção.** Ele não solicita elevação e não deve
ser distribuído como versão final.

---

## Uso rápido

1. Copie `FiveMGuard.exe` para uma pasta gravável no servidor (por exemplo,
   `C:\FiveMGuard`). O `config.ini` é criado automaticamente na primeira execução.
2. Tire um snapshot da VM ou faça backup do sistema.
3. Execute o diagnóstico:

   ```bat
   FiveMGuard.exe --report
   ```

4. Revise o relatório em `reports\` e o log em `logs\`.
5. Simule a aplicação:

   ```bat
   FiveMGuard.exe --apply --dry-run --no-elevate
   ```

6. Aplique de verdade, confirmando o UAC:

   ```bat
   FiveMGuard.exe --apply
   ```

7. Edite `C:\FXServer\server-data\server.cfg` e substitua
   `COLE_SUA_CHAVE_DE_LICENCA` pela sua chave de licença.
8. Inicie o servidor:

   ```bat
   C:\FXServer\start-server.cmd
   ```

9. Abra o txAdmin no próprio servidor: `http://localhost:40120/`.

Também é possível executar sem argumentos para abrir o menu interativo.

---

## Ações da linha de comando

| Ação | Descrição |
|---|---|
| `--report` | Diagnóstico completo, somente leitura. Pode consultar o IP público. |
| `--apply` | Cria backup e aplica firewall, navegador, segurança, dependências, ferramentas extras e preparação do servidor. Exige administrador. |
| `--setup-server` | Prepara pastas, `server.cfg`, `start-server.cmd` e leia-me. |
| `--download-server` | Prepara o servidor e força o download dos artefatos do FXServer **e** do cfx-server-data. Define implicitamente `--setup-server`. |
| `--verify` | Executa o diagnóstico pós-ajustes e salva um relatório. |
| `--rollback` | Restaura o backup mais recente. Use `--backup-dir` para escolher outro. Exige administrador. |
| *(sem ação)* | Abre o menu interativo. |

### Opções

| Opção | Descrição |
|---|---|
| `--dry-run` | Simula a aplicação. Nenhuma alteração real é feita. |
| `--yes` | Não pede confirmação. |
| `--config <arquivo>` | Usa outro `config.ini`. |
| `--backup-dir <pasta>` | Backup específico para o rollback. |
| `--no-elevate` | Não solicita elevação. Útil apenas para leitura/simulação. |
| `--verbose` | Mostra mais detalhes no console e no log. |
| `--no-color` | Desativa cores no console. |
| `--help` | Mostra a ajuda. |
| `--version` | Mostra a versão. |

Exemplos:

```bat
FiveMGuard.exe --report --no-color
FiveMGuard.exe --apply --dry-run --yes --no-elevate
FiveMGuard.exe --apply --yes
FiveMGuard.exe --setup-server --download-server
FiveMGuard.exe --rollback --backup-dir backups\20261031-120000
```

### Códigos de saída

| Código | Significado |
|---|---|
| `0` | Sucesso ou operação cancelada pelo usuário. |
| `1` | Erro de argumento, configuração ou backup. |
| `2` | Aplicação/rollback concluído com falhas. |
| `3` | Privilégios de administrador ausentes. |
| `4` | Sistema não é o Server 2012 R2 alvo e `AllowUnsupportedOS=0`. |
| `5` | Falha ao iniciar o processo elevado. |

O diagnóstico (`--report`/`--verify`) sempre retorna `0`; verifique o resumo
`OK/Avisos/Erros` no console e no relatório.

---

## Configuração

O arquivo `config.ini` fica ao lado do executável e é criado com os valores padrão se
não existir. Ele é dividido nas seções abaixo.

### `[Geral]`

| Chave | Padrão | Descrição |
|---|---:|---|
| `AllowUnsupportedOS` | `0` | Permite aplicar em outro Windows. Não recomendado. |
| `CheckPublicIP` | `1` | Consulta o IP público durante o diagnóstico. |
| `ConfirmarAntesDeAplicar` | `1` | Pede confirmação antes de aplicar. |
| `VerifyAfterApply` | `1` | Executa verificação completa após aplicar. |

### `[Rede]`

| Chave | Padrão | Descrição |
|---|---|---|
| `GamePort` | `30120` | Porta principal do FXServer, liberada em TCP e UDP. |
| `OpenTxAdminPort` | `1` | Cria regra para o txAdmin. |
| `TxAdminPort` | `40120` | Porta TCP do painel txAdmin. |
| `ExtraTcpPorts` | vazio | Portas TCP extras, separadas por vírgula. |
| `ExtraUdpPorts` | vazio | Portas UDP extras, separadas por vírgula. |
| `FirewallProfiles` | `domain,private,public` | Perfis da regra do jogo. |
| `TxAdminProfiles` | `domain,private` | Perfis da regra do txAdmin. |
| `RemoteAddresses` | `*` | Endereços remotos permitidos na porta do jogo. |
| `TxAdminRemoteAddresses` | `LocalSubnet` | Restringe o txAdmin à rede local. |
| `EnsureFirewallEnabled` | `0` | Liga o firewall se estiver desligado. Cria regra de RDP antes. |
| `RdpRemoteAddresses` | `*` | Endereços permitidos na regra de RDP preventiva. |
| `EnableUPnP` | `0` | Tenta mapear portas no roteador via UPnP. |

> **Cuidado com `EnsureFirewallEnabled=1`.** Se o RDP estiver em uso, confirme que a
> regra de RDP está correta antes de ligar o firewall. Um erro pode bloquear o acesso
> remoto.

### `[Dependencias]`

| Chave | Padrão | Descrição |
|---|---:|---|
| `InstallVCRedist` | `1` | Instala o VC++ Redistributable se necessário. |
| `InstallVCRedistX86` | `1` | Instala também a versão x86. |
| `InstallDotNet48` | `0` | Instala o .NET Framework 4.8 (opcional). |
| `RequireSignedDependencies` | `1` | Recusa instaladores sem assinatura Authenticode válida. |
| `VCRedistX64Url` | URL | Origem do instalador x64 14.29. |
| `VCRedistX86Url` | URL | Origem do instalador x86 14.29. |
| `DotNet48Url` | URL | Origem do instalador do .NET 4.8. |
| `DepsDir` | `deps` | Pasta de downloads dos instaladores. |

O FiveMGuard verifica a assinatura digital e o editor antes de executar instaladores.
Não desative `RequireSignedDependencies` sem substituir as URLs por fontes confiáveis.

### `[Extras]`

Ferramentas básicas baixadas e instaladas durante o `--apply`. Todas exigem assinatura
Authenticode válida.

| Chave | Padrão | Descrição |
|---|---:|---|
| `InstallChrome` | `1` | Baixa e instala o Google Chrome (MSI Enterprise). |
| `ChromeUrl` | URL | Origem do instalador do Chrome. |
| `ChromeExpectedPublisher` | `Google LLC` | Editor esperado da assinatura (vazio = só Authenticode). |
| `InstallNodeJs` | `1` | Baixa e instala o Node.js (MSI). |
| `NodeJsUrl` | URL | Origem do instalador do Node.js. |
| `NodeJsExpectedPublisher` | `OpenJS Foundation` | Editor esperado da assinatura. |
| `InstallGit` | `0` | Baixa e instala o Git for Windows (EXE). |
| `GitUrl` | URL | Origem do instalador do Git. |
| `GitExpectedPublisher` | vazio | Editor esperado (vazio = só Authenticode). |
| `InstallSevenZip` | `0` | Baixa e instala o 7-Zip (EXE). |
| `SevenZipUrl` | URL | Origem do instalador do 7-Zip. |
| `SevenZipExpectedPublisher` | vazio | Editor esperado (vazio = só Authenticode). |

> **Compatibilidade com o Server 2012 R2:** o Google Chrome 109 foi a última versão
> compatível com o Windows 8.1/Server 2012 R2; o link padrão aponta para o MSI
> Enterprise mais recente (Windows 10+). No 2012 R2, aponte `ChromeUrl` para um MSI
> Chrome 109 assinado por Google LLC ou desative com `InstallChrome=0`. O Node.js 18.x
> é a última linha com suporte ao 2012 R2 (18.20.8 é o último LTS).

### `[Seguranca]`

| Chave | Padrão | Descrição |
|---|---:|---|
| `HardenTLS` | `1` | Habilita TLS 1.2 e desativa SSL 2.0/3.0. |
| `DisableLegacyTLS` | `0` | Desativa TLS 1.0/1.1. Pode quebrar aplicativos antigos. |
| `HardenSMB` | `1` | Desativa SMBv1 e exige assinatura SMB. Requer reinício. |
| `EnableRdpNLA` | `1` | Exige Network Level Authentication no RDP. |
| `SetRdpHighEncryption` | `1` | Criptografia alta no RDP. |
| `DisableRemoteAssistance` | `1` | Desativa Assistência Remota. |
| `DisableGuestAccount` | `1` | Desativa a conta Guest (ignorado em controlador de domínio). |
| `HardenNTLM` | `1` | NTLMv2, restrições anônimas e `NoLMHash`. |
| `DisableAutorun` | `1` | Desativa AutoRun para HKLM e HKCU. |
| `HideLastUserName` | `1` | Não exibe o último usuário na tela de logon. |
| `ConfigureDefenderExclusions` | `1` | Exclui a pasta do servidor e `FXServer.exe` do Defender. |
| `SetHighPerformance` | `1` | Ativa o plano de energia Alto Desempenho. |
| `EnablePowerShellScriptBlockLogging` | `0` | Ativa log de blocos de script do PowerShell. |

### `[Navegador]`

| Chave | Padrão | Descrição |
|---|---:|---|
| `ConfigureBrowsers` | `1` | Aplica políticas de navegador. |
| `DisableIEESC` | `1` | Desativa o IE Enhanced Security (administradores e usuários). Requer logoff/logon. Use `0` para manter ativo. |
| `SetIETls12` | `1` | Habilita TLS 1.2 no IE. |
| `IEProtocols` | `0xAA0` | Bitmask do IE: SSL 3.0 (`0x20`) + TLS 1.0 (`0x80`) + TLS 1.1 (`0x200`) + TLS 1.2 (`0x800`). |
| `IEHomePage` | vazio | Página inicial. Vazio usa `http://localhost:<TxAdminPort>/`. |
| `AddTrustedSites` | `1` | Adiciona domínios à zona confiável do IE. |
| `TrustedSites` | `cfx.re,fivem.net,runtime.fivem.net` | Sites confiáveis. |
| `ConfigureChrome` | `1` | Aplica políticas se o Chrome estiver instalado. |
| `ConfigureEdge` | `1` | Aplica políticas se o Edge estiver instalado. |
| `ConfigureFirefox` | `1` | Cria `distribution\policies.json` se o Firefox existir **e** o arquivo ainda não existir. |

### `[Servidor]`

| Chave | Padrão | Descrição |
|---|---:|---|
| `ServerRoot` | `C:\FXServer` | Raiz do servidor. |
| `ServerName` | `FiveM Server` | Nome exibido no `server.cfg`. |
| `MaxClients` | `32` | Slots do servidor (1 a 1024). |
| `PrepareServerFolders` | `1` | Cria a estrutura de pastas. |
| `CreateServerConfigExample` | `1` | Cria `server.cfg.example` se ainda não existir. |
| `CreateInitialServerCfg` | `1` | Cria `server.cfg` se ainda não existir. |
| `DownloadServerArtifacts` | `0` | Baixa o FXServer durante a preparação. |
| `DownloadServerData` | `0` | Baixa o cfx-server-data durante a preparação. |
| `OverwriteServerArtifacts` | `0` | Sobrescreve artefatos existentes ao baixar. |
| `OverwriteServerData` | `0` | Sobrescreve dados existentes ao baixar. |
| `ServerArtifactsApi` | URL | API de versões do FXServer. |
| `ServerDataUrl` | URL | Origem do cfx-server-data. |

Arquivos existentes são preservados por padrão. O programa **não** sobrescreve um
`server.cfg` já existente, mesmo que ele ainda contenha o marcador de licença; nesse
caso, apenas avisa.

---

## O que é alterado

### Segurança

- TLS 1.2 habilitado no Schannel (servidor e cliente), SSL 2.0/3.0 desativados;
- TLS 1.0/1.1 opcionalmente desativados (`DisableLegacyTLS=1`);
- .NET com `SchUseStrongCrypto` e `SystemDefaultTlsVersions`;
- WinHTTP com TLS 1.2;
- SMBv1 desativado no servidor e no cliente, assinatura SMB obrigatória;
- RDP com NLA e criptografia alta, quando o RDP está habilitado;
- Assistência Remota desativada;
- `NoLMHash`, NTLMv2 e restrições de sessão anônima (exceto em DC);
- conta Guest desativada (exceto em DC);
- AutoRun desativado;
- último usuário oculto na tela de logon;
- exclusões do Defender para a pasta do servidor, `server`, `server-data`, `deps` e
  `FXServer.exe`;
- plano de energia Alto Desempenho.

### Firewall

Regras criadas com o prefixo `FiveMGuard -`:

- `FiveMGuard - FiveM Game TCP <porta>` — porta do jogo, perfis configurados;
- `FiveMGuard - FiveM Game UDP <porta>` — idem, UDP;
- `FiveMGuard - txAdmin TCP <porta>` — restrita por perfil e endereço remoto;
- `FiveMGuard - Extra TCP` / `FiveMGuard - Extra UDP` — se configuradas;
- `FiveMGuard - RDP TCP 3389` — apenas quando `EnsureFirewallEnabled=1` e o RDP
  está habilitado.

O estado ligado/desligado dos perfis de firewall é preservado, a menos que
`EnsureFirewallEnabled=1`.

### Dependências

- VC++ Redistributable 2015-2022 **14.29** (x64 e, se configurado, x86). Versões mais
  novas do runtime não são compatíveis com o Server 2012 R2;
- .NET Framework 4.8 apenas se `InstallDotNet48=1`;
- instaladores baixados em `deps\` e verificados com Authenticode;
- logs dos instaladores em `deps\vc_redist.*.log` e `deps\ndp48*.log`.

### Ferramentas extras

- Google Chrome (MSI Enterprise) e Node.js (MSI), habilitados por padrão;
- Git for Windows e 7-Zip, desabilitados por padrão (ative em `[Extras]`);
- todos baixados em `deps\`, verificados com Authenticode e, quando configurado, com o
  editor esperado;
- instalados silenciosamente (MSI via `msiexec /qn`, EXE com argumentos próprios);
- detecção pós-instalação; se não detectado, um reinício pode ser necessário.

### Navegadores

- IE: página inicial, TLS 1.2, revogação de certificados, sites confiáveis e IE
  Enhanced Security desativado (administradores e usuários) por padrão;
- Chrome/Edge: página inicial, TLS mínimo 1.2, Safe Browsing ativo e modo segundo plano
  desativado;
- Firefox: `policies.json` com página inicial, TLS mínimo 1.2, telemetria desativada e
  oferta de salvar senhas desativada — somente se o arquivo ainda não existir.

---

## Servidor FiveM

Estrutura padrão:

```text
C:\FXServer\
├── server\                 ← FXServer.exe e artefatos
├── server-data\            ← server.cfg, resources e dados
├── logs\
├── downloads\
├── backups\
├── start-server.cmd
└── LEIA-ME-SERVIDOR.txt
```

### `server.cfg`

O modelo gerado inclui:

- `endpoint_add_tcp` e `endpoint_add_udp` na porta configurada;
- `sv_hostname`, `sv_projectName`, `sv_maxclients`;
- `sv_licenseKey "COLE_SUA_CHAVE_DE_LICENCA"`;
- `txAdminPort`;
- recursos básicos do cfx-server-data (`mapmanager`, `chat`, `spawnmanager`,
  `sessionmanager`, `fivem`, `hardcap`, `rconlog`, `scoreboard`).

**A chave de licença é obrigatória e gratuita.** Obtenha em <https://portal.cfx.re>.
O servidor não inicia sem ela.

### Download dos artefatos

```bat
FiveMGuard.exe --setup-server --download-server
```

ou, durante a aplicação, configure:

```ini
[Servidor]
DownloadServerArtifacts=1
DownloadServerData=1
```

O `--download-server` força o download dos dois componentes. O download usa a API de
versões do FXServer e o repositório oficial do cfx-server-data. Arquivos existentes
são preservados, a menos que `OverwriteServerArtifacts=1` ou `OverwriteServerData=1`.

### Início

```bat
C:\FXServer\start-server.cmd
```

O script verifica a existência de `FXServer.exe` e executa o servidor a partir de
`server-data`.

---

## Backup e rollback

Antes de aplicar, o FiveMGuard cria uma pasta em `backups\<data-hora>\` contendo:

- `registro\` com exports `.reg` das chaves afetadas;
- `registro.txt` com o manifesto das chaves;
- `valores-alterados.tsv` com valores individuais para restauração precisa;
- `firewall.txt` com as regras criadas;
- `estado.txt` com o estado da conta Guest;
- `energia.txt` com o GUID do plano de energia ativo;
- `firefox.txt` e `arquivos\firefox-policies.json`, quando aplicável;
- `config.ini` e `backup-info.txt`.

Para reverter:

```bat
FiveMGuard.exe --rollback
```

ou escolha um backup específico:

```bat
FiveMGuard.exe --rollback --backup-dir backups\20261031-120000
```

O rollback restaura registro, regras de firewall, Guest, política do Firefox e plano de
energia. Reinicie o Windows depois para aplicar alterações de SMB/TLS/RDP.

**Limitações:**

- instaladores, dependências e arquivos do servidor **não** são removidos;
- o estado dos perfis de firewall não é restaurado;
- se o programa for executado várias vezes, o backup mais recente pode já conter
  alterações anteriores; para voltar ao estado original, use um snapshot;
- o rollback não substitui um backup completo do sistema.

---

## Logs, relatórios e artefatos

| Caminho | Conteúdo |
|---|---|
| `logs\FiveMGuard-<data>-<hora>-<pid>.log` | Log detalhado da execução. |
| `reports\relatorio-<data>-<hora>-<pid>.txt` | Relatório de diagnóstico. |
| `backups\<data-hora>\` | Backup para rollback. |
| `deps\` | Instaladores baixados e logs de instalação. |
| `config.ini` | Configuração criada/editada pelo usuário. |
| `C:\FXServer\` | Arquivos do servidor FiveM. |

Os logs e relatórios podem conter nome do computador, usuário, IPs, portas e versões
instaladas. Revise antes de compartilhar.

---

## Testes recomendados

Execute sempre em uma VM limpa do Windows Server 2012 R2 com snapshot:

1. `FiveMGuard.exe --report` — confira avisos e erros.
2. `FiveMGuard.exe --apply --dry-run --no-elevate` — confira o plano simulado.
3. `FiveMGuard.exe --apply` — aplique e reinicie se solicitado.
4. `FiveMGuard.exe --verify` — confirme o estado pós-ajustes.
5. Teste o acesso ao RDP e ao txAdmin antes de fechar a sessão.
6. Inicie o FXServer e conecte um cliente FiveM.
7. Teste o rollback em um snapshot separado.
8. Só depois aplique no servidor de produção.

Checklist mínimo após aplicar:

- [ ] O servidor reiniciou sem erros.
- [ ] O RDP continua acessível (se usado).
- [ ] A porta `30120/TCP` e `30120/UDP` responde de fora.
- [ ] O txAdmin responde apenas na LAN.
- [ ] `server.cfg` contém a chave de licença.
- [ ] O FXServer inicia e aparece na lista do FiveM.
- [ ] O log não contém falhas de download/assinatura.

---

## Solução de problemas

### O programa pede UAC e não abre

`FiveMGuard.exe` exige administrador por manifesto. Aceite o UAC ou use
`FiveMGuard-teste.exe` apenas para diagnóstico/simulação com `--no-elevate`.

### "Este Windows não é o Server 2012 R2 alvo"

A aplicação real é bloqueada em outros sistemas. Para testes, use `--dry-run`; para
forçar (não recomendado), defina `AllowUnsupportedOS=1`.

### Falha no download ou assinatura inválida

Verifique internet, proxy, data e hora do sistema. O programa recusa instaladores sem
assinatura Authenticode válida. Não desative `RequireSignedDependencies` em produção.

### Falha ao instalar Chrome, Node.js, Git ou 7-Zip

- Confirme internet e a URL em `[Extras]`; o download e a assinatura são registrados no log.
- Se a assinatura for de editor diferente, ajuste `*ExpectedPublisher` ou deixe vazio
  (só Authenticode). O editor real é mostrado no log quando há divergência.
- No Server 2012 R2, o Chrome precisa ser a versão 109 (última compatível). Aponte
  `ChromeUrl` para um MSI Enterprise 109 assinado por Google LLC.
- Git e 7-Zip são desabilitados por padrão; ative e confirme a versão compatível.
- Após a instalação, um reinício pode ser necessário para que a detecção reconheça a
  ferramenta (o log avisa quando isso acontece).

### O firewall bloqueou o RDP

Use o console da VM/hypervisor para acessar o servidor, revise as regras
`FiveMGuard - RDP TCP 3389` e o perfil de firewall. Se necessário, restaure o backup
ou o snapshot. Evite `EnsureFirewallEnabled=1` sem acesso alternativo.

### O FXServer não inicia

Confirme:

- `C:\FXServer\server\FXServer.exe` existe;
- a chave em `server.cfg` foi substituída;
- o VC++ Redistributable 14.29 está instalado;
- a porta `30120` não está em uso por outro processo;
- o log do FXServer em `C:\FXServer\server-data\` não mostra erro de recurso.

### O txAdmin não abre em outra máquina

Isso é intencional: a regra padrão é restrita a `LocalSubnet` e aos perfis
`domain/private`. Use VPN/túnel SSH ou ajuste `TxAdminRemoteAddresses` com cautela.
Nunca exponha o txAdmin diretamente sem proteção.

### IE ESC ou políticas de navegador

`DisableIEESC=1` desativa o IE Enhanced Security para administradores e usuários;
faça logoff/logon para que a mudança tenha efeito. Para manter ativo, altere para `0`.
Políticas de Chrome/Edge/Firefox só são aplicadas se o navegador for detectado.

---

## Estrutura do projeto

```text
src\
├── Common.*        utilitários, log, registro, HTTP, downloads e Authenticode
├── Config.*        leitura/gravação do config.ini
├── SystemInfo.*    diagnóstico do sistema, rede, runtime e navegadores
├── Firewall.*      wrapper COM do Windows Firewall
├── Policies.*      políticas de segurança, navegador e firewall
├── Dependencies.*  VC++/.NET, ferramentas extras, downloads e extração de ZIP
├── ServerSetup.*   pastas, server.cfg e downloads do FiveM
└── main.cpp        CLI, menu, diagnóstico, aplicação e rollback
resources\
├── app.manifest          manifesto requireAdministrator
├── app-asinvoker.manifest manifesto de teste
└── app.rc                recursos de manifesto e versão
build.ps1                 compilação dos dois executáveis
config.ini                configuração (gerada automaticamente)
```

---

## Limitações conhecidas

- O alvo real é o Windows Server 2012 R2; outros sistemas não são oficialmente suportados.
- A aplicação real, downloads, instaladores e rollback ainda precisam ser validados em
  uma VM limpa com snapshot e privilégios administrativos.
- O diagnóstico de TLS considera chaves ausentes como padrão do Windows; em sistemas
  diferentes do alvo, o resultado pode variar.
- O programa não configura o roteador, não substitui uma VPN e não protege contra todos
  os ataques. Ele é uma ferramenta de preparação, não um hardening completo.
- O FiveM/FXServer e o cfx-server-data são projetos de terceiros; verifique licenças,
  termos e compatibilidade antes de usar em produção.
- O Windows Server 2012 R2 está fora do suporte da Microsoft. A migração para uma versão
  suportada é a recomendação principal.

---

## Licença

Este projeto é distribuído sob a **GNU General Public License v3.0**. Consulte
[`LICENSE`](LICENSE).

FiveM, FXServer, cfx-server-data e marcas relacionadas pertencem aos seus respectivos
titulares. Este projeto não é afiliado à Cfx.re ou à Rockstar Games.
