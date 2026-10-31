# FiveMGuard — leia-me rápido

Ferramenta para **diagnosticar e preparar o Windows Server 2012 R2 Datacenter x64**
para hospedar um servidor **FiveM/FXServer**.

> **Antes de tudo:** teste em uma máquina virtual ou snapshot. O programa altera
> registro, firewall, políticas de segurança e instala dependências.

---

## 1. Aviso importante

- O **Windows Server 2012 R2 está fora do suporte da Microsoft desde 10/10/2023**.
  Mantenha o servidor isolado, restrinja acessos e planeje a migração.
- A **chave de licença do FiveM é manual**. O `server.cfg` é gerado com
  `COLE_SUA_CHAVE_DE_LICENCA`; obtenha a sua em <https://portal.cfx.re>.
- O **rollback é parcial**: restaura registro, firewall, Guest, política do Firefox e
  plano de energia, mas não desinstala runtimes nem apaga arquivos do servidor.
- **Não exponha o txAdmin na internet.** A porta `40120/TCP` fica restrita à rede local
  por padrão.

Leia o [`README.md`](README.md) para todos os detalhes, opções e limitações.

---

## 2. Uso em 6 passos

1. Copie `FiveMGuard.exe` para uma pasta gravável no servidor.
2. Tire um snapshot da VM ou faça backup do sistema.
3. Diagnostique:

   ```bat
   FiveMGuard.exe --report
   ```

4. Simule:

   ```bat
   FiveMGuard.exe --apply --dry-run --no-elevate
   ```

5. Aplique (aceite o UAC):

   ```bat
   FiveMGuard.exe --apply
   ```

6. Edite `C:\FXServer\server-data\server.cfg`, troque
   `COLE_SUA_CHAVE_DE_LICENCA` pela chave e execute:

   ```bat
   C:\FXServer\start-server.cmd
   ```

O txAdmin abre no próprio servidor em `http://localhost:40120/`.

Sem argumentos, o programa abre o menu interativo.

---

## 3. Comandos principais

```bat
FiveMGuard.exe --report                  Diagnóstico (não altera nada)
FiveMGuard.exe --apply                   Aplica ajustes + cria backup
FiveMGuard.exe --setup-server            Prepara pastas e server.cfg
FiveMGuard.exe --setup-server --download-server
                                         Prepara e baixa FXServer + cfx-server-data
FiveMGuard.exe --verify                  Verifica o estado pós-ajustes
FiveMGuard.exe --rollback                Restaura o último backup
```

Opções úteis:

```bat
--dry-run          Simula sem alterar
--yes              Não pede confirmação
--config <file>    Usa outro config.ini
--backup-dir <dir> Escolhe o backup do rollback
--no-elevate       Não solicita UAC (somente leitura/simulação)
--verbose          Mais detalhes
--no-color         Sem cores no console
```

---

## 4. Padrões que você deve revisar

O `config.ini` é criado automaticamente ao lado do executável. Antes de aplicar,
revise principalmente:

- `[Rede] GamePort` — padrão `30120`;
- `[Rede] TxAdminPort` — padrão `40120`, restrito a `LocalSubnet`;
- `[Rede] EnsureFirewallEnabled` — padrão `0`; não ligue sem acesso alternativo ao RDP;
- `[Seguranca] DisableLegacyTLS` — padrão `0`; ativar pode quebrar aplicativos antigos;
- `[Navegador] DisableIEESC` — padrão `1`; desativa o IE ESC (administradores e usuários);
- `[Dependencias] InstallDotNet48` — padrão `0`;
- `[Extras] InstallChrome` / `InstallNodeJs` — padrão `1`; baixa e instala Chrome e Node.js;
- `[Extras] InstallGit` / `InstallSevenZip` — padrão `0`;
- `[Servidor] ServerRoot` — padrão `C:\FXServer`;
- `[Geral] AllowUnsupportedOS` — padrão `0`; não use em produção.

---

## 5. Compilar

Requisitos: PowerShell e MinGW-w64 x64 (`g++.exe` + `windres.exe`).

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1 -Compiler "C:\w64devkit\bin\g++.exe"
```

Gera:

- `FiveMGuard.exe` — produção, solicita administrador;
- `FiveMGuard-teste.exe` — teste sem UAC, **não usar em produção**.

---

## 6. Se algo der errado

- Consulte `logs\` e `reports\`.
- Use `FiveMGuard.exe --rollback` para o último backup.
- Se o RDP ou o firewall bloquearem o acesso, use o console da VM/hypervisor.
- Em caso de dúvida, restaure o snapshot.

**Licença:** GNU GPL v3. Consulte [`LICENSE`](LICENSE).
