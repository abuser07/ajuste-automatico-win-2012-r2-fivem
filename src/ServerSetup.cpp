// FiveMGuard - preparacao da pasta e dos arquivos do servidor FiveM
#include "ServerSetup.h"

#include "Dependencies.h"
#include "SystemInfo.h"

#include <windows.h>

#include <cstdio>
#include <string>
#include <vector>

namespace fg {

static const wchar_t* kLicensePlaceholder = L"COLE_SUA_CHAVE_DE_LICENCA";

ServerPaths GetServerPaths(const Config& cfg) {
    ServerPaths paths;
    paths.root = cfg.GetPath(L"Servidor", L"ServerRoot", L"C:\\FXServer");
    if (paths.root.empty()) paths.root = L"C:\\FXServer";
    paths.server = JoinPath(paths.root, L"server");
    paths.data = JoinPath(paths.root, L"server-data");
    paths.logs = JoinPath(paths.root, L"logs");
    paths.downloads = JoinPath(paths.root, L"downloads");
    return paths;
}

static std::wstring SafeCfgString(const std::wstring& value) {
    std::wstring out;
    for (wchar_t c : value) {
        if (c == L'"' || c == L'\r' || c == L'\n') out.push_back(L'\'');
        else out.push_back(c);
    }
    return out;
}

static std::wstring ServerConfigTemplate(const Config& cfg) {
    int gamePort = cfg.GetInt(L"Rede", L"GamePort", 30120);
    if (!IsValidPort(gamePort)) gamePort = 30120;
    int txPort = cfg.GetInt(L"Rede", L"TxAdminPort", 40120);
    if (!IsValidPort(txPort)) txPort = 40120;
    int maxClients = cfg.GetInt(L"Servidor", L"MaxClients", 32);
    if (maxClients < 1 || maxClients > 1024) maxClients = 32;
    std::wstring serverName = SafeCfgString(Trim(cfg.GetString(L"Servidor", L"ServerName",
                                                               L"FiveM Server")));
    if (serverName.empty()) serverName = L"FiveM Server";

    std::wstring text;
    text += L"# ============================================================================\r\n";
    text += L"# server.cfg gerado pelo FiveMGuard\r\n";
    text += L"#\r\n";
    text += L"# 1. Substitua " + std::wstring(kLicensePlaceholder) + L" pela chave de licenca\r\n";
    text += L"#    obtida em https://portal.cfx.re (gratuita).\r\n";
    text += L"# 2. Ajuste o nome, os slots e os recursos conforme o seu servidor.\r\n";
    text += L"# 3. A porta txAdmin (painel web) deve ficar acessivel apenas pela LAN.\r\n";
    text += L"# ============================================================================\r\n\r\n";

    text += L"endpoint_add_tcp \"0.0.0.0:" + IntToW(gamePort) + L"\"\r\n";
    text += L"endpoint_add_udp \"0.0.0.0:" + IntToW(gamePort) + L"\"\r\n\r\n";

    text += L"set sv_hostname \"" + serverName + L"\"\r\n";
    text += L"sets sv_projectName \"" + serverName + L"\"\r\n";
    text += L"sets sv_projectDesc \"Servidor FiveM preparado pelo FiveMGuard\"\r\n";
    text += L"set sv_maxclients " + IntToW(maxClients) + L"\r\n";
    text += L"set sv_licenseKey \"" + std::wstring(kLicensePlaceholder) + L"\"\r\n";
    text += L"set steam_webApiKey \"\"\r\n";
    text += L"set onesync on\r\n\r\n";

    text += L"# Painel txAdmin. Nao exponha esta porta na internet sem protecao adicional.\r\n";
    text += L"set txAdminPort " + IntToW(txPort) + L"\r\n\r\n";

    text += L"# Recursos basicos fornecidos pelo cfx-server-data.\r\n";
    text += L"ensure mapmanager\r\n";
    text += L"ensure chat\r\n";
    text += L"ensure spawnmanager\r\n";
    text += L"ensure sessionmanager\r\n";
    text += L"ensure fivem\r\n";
    text += L"ensure hardcap\r\n";
    text += L"ensure rconlog\r\n";
    text += L"ensure scoreboard\r\n";
    return text;
}

static bool WriteIfMissing(const std::wstring& path, const std::wstring& text,
                           const std::wstring& label, bool& created, std::wstring& error) {
    created = false;
    if (FileExists(path)) {
        g_log.Detail(L"Ja existe: " + label + L" (" + path + L")");
        return true;
    }
    if (g_log.DryRun()) {
        g_log.Step(L"Criaria " + label + L": " + path);
        return true;
    }
    if (!EnsureParentDir(path) || !WriteTextFile(path, text, true)) {
        error += L"Falha ao criar " + label + L" em " + path + L". ";
        g_log.Error(L"Falha ao criar " + label + L": " + path);
        return false;
    }
    created = true;
    g_log.Ok(label + L" criado: " + path);
    return true;
}

static std::wstring ServerReadme(const ServerPaths& paths, const Config& cfg) {
    int gamePort = cfg.GetInt(L"Rede", L"GamePort", 30120);
    int txPort = cfg.GetInt(L"Rede", L"TxAdminPort", 40120);
    std::wstring txRemote = cfg.GetString(L"Rede", L"TxAdminRemoteAddresses", L"LocalSubnet");
    std::wstring text;
    text += L"FiveMGuard - servidor FiveM\r\n";
    text += L"============================\r\n\r\n";
    text += L"Pasta do servidor: " + paths.root + L"\r\n";
    text += L"Binarios:          " + paths.server + L"\r\n";
    text += L"Dados/recursos:    " + paths.data + L"\r\n\r\n";
    text += L"PASSOS OBRIGATORIOS\r\n";
    text += L"1. Abra " + JoinPath(paths.data, L"server.cfg") + L"\r\n";
    text += L"2. Substitua " + std::wstring(kLicensePlaceholder) + L" pela chave obtida em\r\n";
    text += L"   https://portal.cfx.re (a chave e gratuita e obrigatoria).\r\n";
    text += L"3. Execute start-server.cmd nesta pasta.\r\n";
    text += L"4. Abra o txAdmin em http://localhost:" + IntToW(txPort) + L"/ no proprio servidor\r\n";
    text += L"   e conclua a configuracao inicial.\r\n\r\n";
    text += L"REDE\r\n";
    text += L"- Porta do jogo: " + IntToW(gamePort) + L" TCP e UDP (liberada para internet pelo FiveMGuard).\r\n";
    text += L"- txAdmin: porta " + IntToW(txPort) + L" TCP, restrita a " + txRemote + L".\r\n";
    text += L"  Para acessar o painel de outra maquina, use um tunel SSH/VPN ou uma regra\r\n";
    text += L"  de firewall restrita ao seu IP. Nunca exponha o txAdmin sem senha forte.\r\n\r\n";
    text += L"ATUALIZACAO\r\n";
    text += L"- Baixe novos artefatos com:\r\n";
    text += L"  FiveMGuard.exe --setup-server --download-server\r\n";
    text += L"- O arquivo server.cfg existente e preservado.\r\n\r\n";
    text += L"OBSERVACOES\r\n";
    text += L"- O Windows Server 2012 R2 esta fora do suporte da Microsoft. Isole este\r\n";
    text += L"  servidor e planeje a migracao para uma versao suportada.\r\n";
    text += L"- Nao abra a porta do txAdmin para a internet sem protecao adicional.\r\n";
    return text;
}

bool PrepareServerLayout(const Config& cfg, std::wstring& error) {
    error.clear();
    ServerPaths paths = GetServerPaths(cfg);

    if (g_log.DryRun()) {
        g_log.Step(L"Criaria a estrutura do servidor em " + paths.root +
                   L" (server, server-data, logs, downloads, backups)");
    } else {
        for (const auto& dir : {paths.root, paths.server, paths.data, paths.logs,
                                paths.downloads, JoinPath(paths.root, L"backups")}) {
            if (!EnsureDir(dir)) {
                error = L"nao foi possivel criar " + dir + L": " + FormatWinError(GetLastError());
                g_log.Error(error);
                return false;
            }
        }
        g_log.Ok(L"Pastas do servidor preparadas em " + paths.root);
    }

    bool created = false;
    const std::wstring configText = ServerConfigTemplate(cfg);
    const std::wstring examplePath = JoinPath(paths.data, L"server.cfg.example");
    const std::wstring configPath = JoinPath(paths.data, L"server.cfg");

    if (cfg.GetBool(L"Servidor", L"CreateServerConfigExample", true)) {
        if (!WriteIfMissing(examplePath, configText, L"server.cfg.example", created, error)) {
            return false;
        }
    }
    if (cfg.GetBool(L"Servidor", L"CreateInitialServerCfg", true)) {
        bool configCreated = false;
        if (!WriteIfMissing(configPath, configText, L"server.cfg", configCreated, error)) {
            return false;
        }
        if (configCreated) {
            g_log.Warn(L"Edite " + configPath + L" e informe a chave de licenca antes de iniciar.");
        }
    }

    std::wstring startCmd =
        L"@echo off\r\n"
        L"setlocal\r\n"
        L"title FiveM Server\r\n"
        L"cd /d \"%~dp0server-data\"\r\n"
        L"if not exist \"%~dp0server\\FXServer.exe\" (\r\n"
        L"  echo FXServer.exe nao encontrado.\r\n"
        L"  echo Baixe os artefatos com: FiveMGuard.exe --setup-server --download-server\r\n"
        L"  pause\r\n"
        L"  exit /b 1\r\n"
        L")\r\n"
        L"\"%~dp0server\\FXServer.exe\" +exec server.cfg\r\n"
        L"if errorlevel 1 pause\r\n";
    if (!WriteIfMissing(JoinPath(paths.root, L"start-server.cmd"), startCmd,
                        L"start-server.cmd", created, error)) {
        return false;
    }

    if (!WriteIfMissing(JoinPath(paths.root, L"LEIA-ME-SERVIDOR.txt"),
                        ServerReadme(paths, cfg), L"LEIA-ME-SERVIDOR.txt", created, error)) {
        return false;
    }

    if (!FileExists(JoinPath(paths.server, L"FXServer.exe"))) {
        if (cfg.GetBool(L"Servidor", L"DownloadServerArtifacts", false)) {
            g_log.Info(L"FXServer.exe ainda nao esta presente; sera baixado na etapa de downloads.");
        } else {
            g_log.Warn(L"FXServer.exe ainda nao esta presente. Use --download-server ou copie "
                       L"os artefatos manualmente.");
        }
    } else {
        g_log.Ok(L"FXServer.exe encontrado em " + paths.server);
    }

    // Aviso se o server.cfg existente ainda tem o marcador de licenca.
    std::wstring existing;
    if (FileExists(configPath) && ReadTextFile(configPath, existing) &&
        existing.find(kLicensePlaceholder) != std::wstring::npos) {
        g_log.Warn(L"A chave de licenca ainda nao foi configurada em " + configPath);
    }
    return true;
}

bool TryUPnPMapping(const Config& cfg, std::wstring& error) {
    error.clear();
    if (!cfg.GetBool(L"Rede", L"EnableUPnP", false)) return true;

    int gamePort = cfg.GetInt(L"Rede", L"GamePort", 30120);
    if (!IsValidPort(gamePort)) {
        error = L"GamePort invalida para UPnP.";
        return false;
    }

    std::vector<std::wstring> addresses = GetLocalIPv4List();
    if (addresses.empty()) {
        error = L"nenhum endereco IPv4 local encontrado para o UPnP.";
        return false;
    }
    std::wstring localIp = addresses.front();

    if (g_log.DryRun()) {
        g_log.Step(L"Mapearia via UPnP as portas TCP/UDP " + IntToW(gamePort) + L" para " + localIp);
        return true;
    }

    std::wstring powerShell = JoinPath(GetEnvVar(L"SystemRoot"),
                                       L"System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    if (!FileExists(powerShell)) {
        error = L"PowerShell nao encontrado para o mapeamento UPnP.";
        return false;
    }

    SetEnvironmentVariableW(L"FIVEMGUARD_LOCAL_IP", localIp.c_str());
    SetEnvironmentVariableW(L"FIVEMGUARD_GAME_PORT", IntToW(gamePort).c_str());

    std::wstring script =
        L"$ErrorActionPreference='Stop';"
        L"$nat=New-Object -ComObject HNetCfg.NATUPnP;"
        L"$map=$nat.StaticPortMappings;"
        L"if($null -eq $map){throw 'Nenhum roteador com UPnP encontrado'};"
        L"$port=[int]$env:FIVEMGUARD_GAME_PORT;"
        L"$ip=$env:FIVEMGUARD_LOCAL_IP;"
        L"foreach($proto in @('TCP','UDP')){"
        L"$exists=$false;"
        L"foreach($m in $map){if($m.ExternalPort -eq $port -and $m.Protocol -eq $proto){$exists=$true;break}};"
        L"if($exists){Write-Output ('Ja mapeado '+$proto+' '+$port)}"
        L"else{$map.Add($port,$proto,$port,$ip,$true,'FiveMGuard')|Out-Null;"
        L"Write-Output ('Mapeado '+$proto+' '+$port)}}";

    std::wstring command = QuoteArg(powerShell) +
                           L" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command " +
                           QuoteArg(script);
    ProcessResult result;
    bool started = RunProcess(command, ExeDir(), 120 * 1000, result);
    SetEnvironmentVariableW(L"FIVEMGUARD_LOCAL_IP", nullptr);
    SetEnvironmentVariableW(L"FIVEMGUARD_GAME_PORT", nullptr);

    if (!started) {
        error = L"nao foi possivel iniciar o PowerShell para UPnP: " + result.output;
        g_log.Warn(error + L" O servidor continua funcionando, mas o roteador precisara "
                            L"ser configurado manualmente.");
        return false;
    }
    if (result.timedOut || result.exitCode != 0) {
        error = L"mapeamento UPnP falhou";
        if (!result.output.empty()) error += L": " + result.output;
        g_log.Warn(error + L". Configure o redirecionamento de portas manualmente no roteador.");
        return false;
    }
    g_log.Ok(L"UPnP: portas TCP/UDP " + IntToW(gamePort) + L" mapeadas para " + localIp);
    if (!result.output.empty()) g_log.Detail(result.output);
    g_log.Info(L"O txAdmin nao e mapeado via UPnP por seguranca.");
    return true;
}

bool SetupFiveMServer(const Config& cfg, bool forceDownloads, std::wstring& error) {
    error.clear();
    if (!PrepareServerLayout(cfg, error)) return false;

    bool artifacts = forceDownloads ||
                     cfg.GetBool(L"Servidor", L"DownloadServerArtifacts", false);
    bool data = forceDownloads || cfg.GetBool(L"Servidor", L"DownloadServerData", false);
    if (artifacts || data) {
        if (!DownloadFiveMServerFiles(cfg, artifacts, data, error)) return false;
    } else {
        g_log.Info(L"DownloadServerArtifacts=0 e DownloadServerData=0: downloads ignorados.");
    }

    std::wstring upnpError;
    if (!TryUPnPMapping(cfg, upnpError)) {
        g_log.Warn(L"UPnP: " + upnpError);
        // UPnP e opcional; nao invalida a preparacao do servidor.
    }
    return true;
}

} // namespace fg
