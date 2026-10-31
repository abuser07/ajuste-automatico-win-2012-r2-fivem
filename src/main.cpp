// FiveMGuard - programa principal, menu, diagnostico, aplicacao e rollback
#include "Common.h"
#include "Config.h"
#include "SystemInfo.h"
#include "Firewall.h"
#include "Policies.h"
#include "Dependencies.h"
#include "ServerSetup.h"

#include <windows.h>
#include <lm.h>
#include <shellapi.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cwchar>
#include <cwctype>
#include <string>
#include <vector>

using namespace fg;

namespace {

// ------------------------------------------------------------------ opcoes
struct Options {
    bool report = false;
    bool apply = false;
    bool dryRun = false;
    bool yes = false;
    bool verify = false;
    bool setupServer = false;
    bool downloadServer = false;
    bool rollback = false;
    bool noElevate = false;
    bool verbose = false;
    bool noColor = false;
    bool help = false;
    bool version = false;
    bool interactive = false;
    std::wstring configPath;
    std::wstring backupPath;
};

Options g_opt;
int g_argc = 0;
wchar_t** g_argv = nullptr;

// ------------------------------------------------------------------ ajuda
void PrintUsage() {
    wprintf(L"\nFiveMGuard %ls\n", kAppVersion);
    wprintf(L"Preparacao e diagnostico do Windows Server 2012 R2 para FiveM (FXServer)\n\n");
    wprintf(L"USO:\n");
    wprintf(L"  FiveMGuard.exe [acao] [opcoes]\n\n");
    wprintf(L"ACOES:\n");
    wprintf(L"  --report              Diagnostico completo (nao altera nada)\n");
    wprintf(L"  --apply               Aplica seguranca, firewall, navegador, dependencias, extras e servidor\n");
    wprintf(L"  --setup-server        Prepara pastas, server.cfg, start-server.cmd e leia-me\n");
    wprintf(L"  --download-server     Prepara e baixa artefatos do FXServer + cfx-server-data\n");
    wprintf(L"  --verify              Verifica o estado atual (pos-ajustes)\n");
    wprintf(L"  --rollback            Restaura o ultimo backup (registro, firewall, Guest, energia e Firefox)\n");
    wprintf(L"  (sem acao)            Abre o menu interativo\n\n");
    wprintf(L"OPCOES:\n");
    wprintf(L"  --dry-run             Simula a aplicacao sem alterar o sistema\n");
    wprintf(L"  --yes                 Nao pede confirmacao\n");
    wprintf(L"  --config <arquivo>    Usa outro config.ini\n");
    wprintf(L"  --backup-dir <pasta>  Backup especifico para o rollback\n");
    wprintf(L"  --no-elevate          Nao solicita elevacao (somente leitura/simulacao)\n");
    wprintf(L"  --verbose             Mostra detalhes no console e no log\n");
    wprintf(L"  --no-color            Desativa cores no console\n");
    wprintf(L"  --help                Mostra esta ajuda\n");
    wprintf(L"  --version             Mostra a versao\n\n");
    wprintf(L"EXEMPLOS:\n");
    wprintf(L"  FiveMGuard.exe --report\n");
    wprintf(L"  FiveMGuard.exe --apply\n");
    wprintf(L"  FiveMGuard.exe --apply --dry-run --no-elevate\n");
    wprintf(L"  FiveMGuard.exe --setup-server --download-server\n");
    wprintf(L"  FiveMGuard.exe --rollback --backup-dir backups\\20261031-120000\n\n");
    wprintf(L"AVISO: teste em uma maquina virtual ou snapshot antes de aplicar em producao.\n");
    wprintf(L"Windows Server 2012 R2 esta fora do suporte da Microsoft desde 10/10/2023.\n\n");
}

// ------------------------------------------------------------------ argumentos
bool ParseArgs(int argc, wchar_t** argv, Options& opt, std::wstring& error) {
    error.clear();
    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        std::wstring lower = ToLower(arg);
        if (lower == L"--report") opt.report = true;
        else if (lower == L"--apply") opt.apply = true;
        else if (lower == L"--dry-run" || lower == L"--simular") opt.dryRun = true;
        else if (lower == L"--yes" || lower == L"-y") opt.yes = true;
        else if (lower == L"--verify" || lower == L"--verificar") opt.verify = true;
        else if (lower == L"--setup-server" || lower == L"--preparar-servidor") opt.setupServer = true;
        else if (lower == L"--download-server" || lower == L"--baixar-servidor") {
            opt.downloadServer = true;
            opt.setupServer = true;
        }
        else if (lower == L"--rollback" || lower == L"--restaurar") opt.rollback = true;
        else if (lower == L"--no-elevate") opt.noElevate = true;
        else if (lower == L"--verbose" || lower == L"-v") opt.verbose = true;
        else if (lower == L"--no-color" || lower == L"--sem-cor") opt.noColor = true;
        else if (lower == L"--help" || lower == L"-h" || lower == L"/?") opt.help = true;
        else if (lower == L"--version") opt.version = true;
        else if (lower == L"--config") {
            if (i + 1 >= argc) {
                error = L"--config exige um caminho.";
                return false;
            }
            opt.configPath = argv[++i];
        } else if (StartsWithI(lower, L"--config=")) {
            opt.configPath = arg.substr(std::wstring(L"--config=").size());
        } else if (lower == L"--backup-dir") {
            if (i + 1 >= argc) {
                error = L"--backup-dir exige um caminho.";
                return false;
            }
            opt.backupPath = argv[++i];
        } else if (StartsWithI(lower, L"--backup-dir=")) {
            opt.backupPath = arg.substr(std::wstring(L"--backup-dir=").size());
        } else {
            error = L"Opcao desconhecida: " + arg;
            return false;
        }
    }

    if (opt.downloadServer) opt.setupServer = true;
    bool anyAction = opt.report || opt.apply || opt.setupServer || opt.rollback || opt.verify;
    if (opt.dryRun && !anyAction) opt.apply = true;
    anyAction = opt.report || opt.apply || opt.setupServer || opt.rollback || opt.verify;
    if (!anyAction && !opt.help && !opt.version) opt.interactive = true;

    if (opt.rollback && (opt.apply || opt.setupServer || opt.report || opt.verify)) {
        error = L"--rollback nao pode ser combinado com --apply, --setup-server, --report ou --verify.";
        return false;
    }
    return true;
}

bool NeedsAdmin(const Options& opt) {
    if (opt.dryRun) return false;
    return opt.apply || opt.setupServer || opt.rollback;
}

bool LoadConfigFile(const Options& opt, std::wstring& path, std::wstring& error) {
    error.clear();
    path = opt.configPath.empty() ? JoinPath(ExeDir(), L"config.ini")
                                  : MakeAbsolute(ExpandEnv(opt.configPath), ExeDir());
    if (!g_cfg.Load(path, true)) {
        error = L"Nao foi possivel ler/criar " + path + L": " + FormatWinError(GetLastError());
        return false;
    }
    return true;
}

// ------------------------------------------------------------------ helpers
std::wstring BoolText(bool value) { return value ? L"sim" : L"nao"; }

std::wstring RootShortName(HKEY root) {
    if (root == HKEY_LOCAL_MACHINE) return L"HKLM";
    if (root == HKEY_CURRENT_USER) return L"HKCU";
    if (root == HKEY_CLASSES_ROOT) return L"HKCR";
    if (root == HKEY_USERS) return L"HKU";
    return L"HKLM";
}

bool RootFromName(const std::wstring& name, HKEY& root) {
    if (_wcsicmp(name.c_str(), L"HKLM") == 0 ||
        _wcsicmp(name.c_str(), L"HKEY_LOCAL_MACHINE") == 0) {
        root = HKEY_LOCAL_MACHINE;
        return true;
    }
    if (_wcsicmp(name.c_str(), L"HKCU") == 0 ||
        _wcsicmp(name.c_str(), L"HKEY_CURRENT_USER") == 0) {
        root = HKEY_CURRENT_USER;
        return true;
    }
    if (_wcsicmp(name.c_str(), L"HKCR") == 0 ||
        _wcsicmp(name.c_str(), L"HKEY_CLASSES_ROOT") == 0) {
        root = HKEY_CLASSES_ROOT;
        return true;
    }
    if (_wcsicmp(name.c_str(), L"HKU") == 0 ||
        _wcsicmp(name.c_str(), L"HKEY_USERS") == 0) {
        root = HKEY_USERS;
        return true;
    }
    return false;
}

bool SplitRegistryKey(const std::wstring& full, HKEY& root, std::wstring& subkey) {
    size_t pos = full.find(L'\\');
    if (pos == std::wstring::npos) return false;
    if (!RootFromName(full.substr(0, pos), root)) return false;
    subkey = full.substr(pos + 1);
    return !subkey.empty();
}

std::vector<std::wstring> SplitChar(const std::wstring& value, wchar_t separator) {
    std::vector<std::wstring> parts;
    std::wstring current;
    for (wchar_t c : value) {
        if (c == separator) {
            parts.push_back(current);
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    parts.push_back(current);
    return parts;
}

std::vector<std::wstring> ReadRawLines(const std::wstring& path) {
    std::vector<std::wstring> lines;
    std::wstring text;
    if (!ReadTextFile(path, text)) return lines;
    size_t start = 0;
    while (start <= text.size()) {
        size_t end = text.find(L'\n', start);
        std::wstring line = (end == std::wstring::npos) ? text.substr(start)
                                                        : text.substr(start, end - start);
        start = (end == std::wstring::npos) ? text.size() + 1 : end + 1;
        if (!line.empty() && line.back() == L'\r') line.pop_back();
        if (!line.empty()) lines.push_back(line);
    }
    return lines;
}

std::wstring ManifestValue(const std::vector<std::wstring>& lines, const std::wstring& key) {
    for (const auto& line : lines) {
        size_t eq = line.find(L'=');
        if (eq == std::wstring::npos) continue;
        if (_wcsicmp(Trim(line.substr(0, eq)).c_str(), key.c_str()) == 0) {
            return Trim(line.substr(eq + 1));
        }
    }
    return std::wstring();
}

std::vector<std::wstring> TokenizeCfgLine(const std::wstring& line) {
    std::vector<std::wstring> tokens;
    std::wstring current;
    bool quoted = false;
    for (wchar_t c : line) {
        if (c == L'"') {
            quoted = !quoted;
            continue;
        }
        if (!quoted && (c == L' ' || c == L'\t' || c == L'\r' || c == L'\n')) {
            if (!current.empty()) {
                tokens.push_back(current);
                current.clear();
            }
        } else {
            current.push_back(c);
        }
    }
    if (!current.empty()) tokens.push_back(current);
    return tokens;
}

std::wstring JoinTokens(const std::vector<std::wstring>& tokens, size_t start) {
    std::wstring result;
    for (size_t i = start; i < tokens.size(); ++i) {
        if (!result.empty()) result += L" ";
        result += tokens[i];
    }
    return result;
}

std::wstring FindCfgValue(const std::wstring& text, const std::wstring& directive) {
    size_t start = 0;
    while (start <= text.size()) {
        size_t end = text.find(L'\n', start);
        std::wstring line = (end == std::wstring::npos) ? text.substr(start)
                                                        : text.substr(start, end - start);
        start = (end == std::wstring::npos) ? text.size() + 1 : end + 1;
        line = Trim(line);
        if (line.empty() || line[0] == L'#' || line[0] == L';') continue;
        std::vector<std::wstring> tokens = TokenizeCfgLine(line);
        if (tokens.empty()) continue;
        if ((_wcsicmp(tokens[0].c_str(), L"set") == 0 ||
             _wcsicmp(tokens[0].c_str(), L"sets") == 0) &&
            tokens.size() >= 3 && _wcsicmp(tokens[1].c_str(), directive.c_str()) == 0) {
            return JoinTokens(tokens, 2);
        }
        if (_wcsicmp(tokens[0].c_str(), directive.c_str()) == 0 && tokens.size() >= 2) {
            return JoinTokens(tokens, 1);
        }
    }
    return std::wstring();
}

std::wstring GetIeVersion() {
    std::wstring version;
    if (RegGetString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Internet Explorer",
                     L"svcVersion", version) && !version.empty()) {
        return version;
    }
    if (RegGetString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Internet Explorer",
                     L"Version", version) && !version.empty()) {
        return version;
    }
    return L"nao detectado";
}

std::wstring ProfileName(int profile) {
    switch (profile) {
        case 1: return L"dominio";
        case 2: return L"privado";
        case 4: return L"publico";
        default: return IntToW(profile);
    }
}

// ------------------------------------------------------------------ regras esperadas
void ExpectedRuleNames(std::vector<std::wstring>& names) {
    names.clear();
    int gamePort = g_cfg.GetInt(L"Rede", L"GamePort", 30120);
    if (!IsValidPort(gamePort)) gamePort = 30120;
    names.push_back(L"FiveMGuard - FiveM Game TCP " + IntToW(gamePort));
    names.push_back(L"FiveMGuard - FiveM Game UDP " + IntToW(gamePort));

    if (g_cfg.GetBool(L"Rede", L"OpenTxAdminPort", true)) {
        int txPort = g_cfg.GetInt(L"Rede", L"TxAdminPort", 40120);
        if (IsValidPort(txPort)) {
            names.push_back(L"FiveMGuard - txAdmin TCP " + IntToW(txPort));
        }
    }
    if (!Trim(g_cfg.GetString(L"Rede", L"ExtraTcpPorts", L"")).empty()) {
        names.push_back(L"FiveMGuard - Extra TCP");
    }
    if (!Trim(g_cfg.GetString(L"Rede", L"ExtraUdpPorts", L"")).empty()) {
        names.push_back(L"FiveMGuard - Extra UDP");
    }
    if (g_cfg.GetBool(L"Rede", L"EnsureFirewallEnabled", false) && IsRdpEnabled()) {
        names.push_back(L"FiveMGuard - RDP TCP 3389");
    }
}

// ------------------------------------------------------------------ diagnostico
void CheckPort(Report& report, int port, bool tcp, const std::wstring& label) {
    PortOwner owner;
    std::wstring error;
    std::wstring proto = tcp ? L"TCP" : L"UDP";
    if (GetPortListener(port, tcp, owner, error)) {
        if (ContainsI(owner.process, L"FXServer")) {
            report.Ok(L"Porta " + IntToW(port) + L" " + proto + L" em uso pelo FXServer (" + label + L").");
        } else {
            report.Warn(L"Porta " + IntToW(port) + L" " + proto + L" em uso por " + owner.process +
                        L" (PID " + IntToW((unsigned)owner.pid) + L", " + label + L").");
        }
    } else if (!error.empty()) {
        report.Warn(L"Nao foi possivel verificar a porta " + IntToW(port) + L" " + proto + L": " + error);
    } else {
        report.Info(L"Porta " + IntToW(port) + L" " + proto + L": sem listener no momento (" + label + L").");
    }
}

void CheckBrowserPolicy(Report& report, const wchar_t* name, const std::wstring& exe,
                        const std::wstring& policyKey) {
    if (exe.empty()) {
        report.Info(std::wstring(name) + L" nao instalado.");
        return;
    }
    std::wstring home;
    if (RegGetString(HKEY_LOCAL_MACHINE, policyKey, L"HomepageLocation", home) && !home.empty()) {
        report.Ok(std::wstring(name) + L": politica de pagina inicial aplicada (" + home + L").");
    } else {
        report.Info(std::wstring(name) + L": instalado em " + exe +
                    L"; politica sera aplicada com --apply.");
    }
}

void CheckFirewallRule(Report& report, Firewall& fw, const std::wstring& name) {
    FwRuleInfo info;
    std::wstring error;
    if (!fw.GetRule(name, info, error)) {
        report.Warn(L"Nao foi possivel consultar a regra " + name + L": " + error);
        return;
    }
    if (!info.exists) {
        report.Info(L"Regra ausente (sera criada ao aplicar): " + name);
        return;
    }
    if (info.enabled && info.action == 1) {
        report.Ok(L"Regra de firewall presente: " + name);
    } else {
        report.Warn(L"Regra existe, mas esta desabilitada ou bloqueando: " + name);
    }
}

void RunDiagnostics(Report& report, bool postApply) {
    OsInfo os;
    GetOsInfo(os);

    report.Section(L"Sistema");
    report.Info(L"Computador: " + GetComputerNameStr() + L" | Usuario: " + GetUserNameStr());
    report.Info(L"Windows: " + os.productName + L" (build " + os.build + L", " + os.architecture + L")");
    if (os.isTarget2012R2) {
        report.Ok(L"Windows Server 2012 R2 detectado.");
    } else if (os.isServer) {
        report.Warn(L"Este Windows nao e o Server 2012 R2 alvo (build " + os.build + L").");
    } else {
        report.Warn(L"Este nao e um Windows Server; use apenas para diagnostico/teste.");
    }
    if (os.isDatacenter) {
        report.Ok(L"Edicao Datacenter detectada.");
    } else {
        report.Info(L"Edicao: " + (os.editionId.empty() ? os.productName : os.editionId));
    }
    if (os.isDomainController) {
        report.Warn(L"Controlador de dominio: ajustes de Guest/LSA serao parcialmente ignorados.");
    }
    report.Info(L"Tempo ligado: " + GetUptimeText());
    if (IsUserAdmin()) {
        report.Ok(L"Executando com privilegios de administrador.");
    } else {
        report.Warn(L"Sem elevacao: diagnostico e simulacao funcionam; aplicar exige administrador.");
    }
    if (IsPendingReboot()) {
        report.Warn(L"Ha um reinicio pendente. Reinicie antes de aplicar/validar.");
    } else {
        report.Ok(L"Sem reinicio pendente detectado.");
    }
    std::wstring psVersion = GetPowerShellVersion();
    if (psVersion == L"nao detectado") {
        report.Warn(L"PowerShell nao detectado; downloads e extracao de ZIP podem falhar.");
    } else {
        report.Info(L"PowerShell: " + psVersion);
    }
    if (os.isTarget2012R2) {
        report.Warn(L"Windows Server 2012 R2 esta fora do suporte desde 10/10/2023. "
                    L"Isole o servidor e planeje a atualizacao.");
    }

    report.Section(L"Hardware");
    report.Info(L"CPU: " + GetCpuName() + L" (" + IntToW(GetCpuCores()) + L" nucleos logicos)");
    uint64_t ramTotal = GetRamTotalMB();
    uint64_t ramFree = GetRamAvailableMB();
    report.Info(L"RAM: " + IntToW((long long)ramTotal) + L" MB total, " +
                IntToW((long long)ramFree) + L" MB disponivel");
    if (ramTotal < 4096) {
        report.Warn(L"Menos de 4 GB de RAM: o FiveM pode ficar instavel.");
    } else if (ramTotal < 8192) {
        report.Info(L"4-8 GB de RAM: suficiente para servidores pequenos.");
    } else {
        report.Ok(L"RAM adequada para o FiveM.");
    }

    std::wstring serverRoot = g_cfg.GetPath(L"Servidor", L"ServerRoot", L"C:\\FXServer");
    uint64_t diskFree = GetDiskFreeBytes(serverRoot);
    uint64_t diskTotal = GetDiskTotalBytes(serverRoot);
    if (diskTotal == 0) {
        report.Warn(L"Nao foi possivel obter o espaco em disco de " + GetDriveRoot(serverRoot) + L".");
    } else {
        report.Info(L"Disco " + GetDriveRoot(serverRoot) + L": " + FormatBytes(diskFree) +
                    L" livres de " + FormatBytes(diskTotal));
        if (diskFree < 5ull * 1024 * 1024 * 1024) {
            report.Error(L"Menos de 5 GB livres: insuficiente para artefatos, dados e logs.");
        } else if (diskFree < 10ull * 1024 * 1024 * 1024) {
            report.Warn(L"Menos de 10 GB livres: espaco apertado para o servidor FiveM.");
        } else {
            report.Ok(L"Espaco em disco suficiente.");
        }
    }

    report.Section(L"Rede");
    std::vector<std::wstring> addresses = GetLocalIPv4List();
    if (addresses.empty()) {
        report.Warn(L"Nenhum endereco IPv4 local detectado.");
    } else {
        for (const auto& address : addresses) report.Info(L"IPv4 local: " + address);
    }
    if (!postApply && g_cfg.GetBool(L"Geral", L"CheckPublicIP", true)) {
        std::wstring publicIp = GetPublicIP();
        if (publicIp.empty()) {
            report.Warn(L"Nao foi possivel consultar o IP publico (rede/TLS).");
        } else {
            report.Info(L"IP publico: " + publicIp);
        }
    }
    if (IsRdpEnabled()) {
        std::wstring client = GetRdpClientIP();
        report.Info(client.empty() ? L"RDP habilitado."
                                   : L"RDP habilitado; cliente atual: " + client);
    } else {
        report.Info(L"RDP desabilitado.");
    }

    int gamePort = g_cfg.GetInt(L"Rede", L"GamePort", 30120);
    if (IsValidPort(gamePort)) {
        CheckPort(report, gamePort, true, L"jogo");
        CheckPort(report, gamePort, false, L"jogo");
    } else {
        report.Error(L"GamePort invalida no config.ini: " + IntToW(gamePort));
    }
    int txPort = g_cfg.GetInt(L"Rede", L"TxAdminPort", 40120);
    if (g_cfg.GetBool(L"Rede", L"OpenTxAdminPort", true)) {
        if (IsValidPort(txPort)) CheckPort(report, txPort, true, L"txAdmin");
        else report.Error(L"TxAdminPort invalida no config.ini: " + IntToW(txPort));
    }

    report.Section(L"Dependencias");
    DependencyState dep;
    GetDependencyState(dep);
    if (dep.vcX64.installed && dep.vcX64.major == 14 && dep.vcX64.minor >= 29) {
        report.Ok(L"VC++ x64: " + dep.vcX64.version);
    } else if (dep.vcX64.installed) {
        report.Warn(L"VC++ x64 antigo (" + dep.vcX64.version + L"); o FXServer exige 14.29 ou superior.");
    } else {
        report.Error(L"VC++ x64 nao instalado (obrigatorio para o FXServer).");
    }
    if (dep.vcX86.installed) {
        report.Info(L"VC++ x86: " + dep.vcX86.version);
    } else {
        report.Info(L"VC++ x86 nao instalado (opcional para o FXServer).");
    }
    if (dep.dotNetRelease >= 528040) {
        report.Ok(L".NET Framework: " + dep.dotNetLabel);
    } else {
        report.Info(L".NET Framework: " + dep.dotNetLabel +
                    L" (4.8 e opcional; necessario apenas para recursos em C#).");
    }
    report.Info(L"Ferramentas extras: Chrome=" + BoolText(IsChromeInstalled()) +
                L", Node.js=" + BoolText(IsNodeInstalled()) +
                L", Git=" + BoolText(IsGitInstalled()) +
                L", 7-Zip=" + BoolText(IsSevenZipInstalled()) + L".");
    report.Info(L"Windows Defender: " + GetDefenderSummary());
    for (const wchar_t* service : {L"BFE", L"MpsSvc"}) {
        ServiceInfo info;
        if (GetServiceInfo(service, info) && info.running) {
            report.Ok(std::wstring(L"Servico de firewall em execucao: ") + service);
        } else {
            report.Warn(std::wstring(L"Servico de firewall parado/ausente: ") + service);
        }
    }

    report.Section(L"Firewall");
    Firewall fw;
    std::wstring fwError;
    if (!fw.Init(fwError)) {
        report.Warn(L"Nao foi possivel consultar o firewall: " + fwError);
    } else {
        for (int profile : {1, 2, 4}) {
            FwProfileInfo info;
            std::wstring profileError;
            if (!fw.GetProfileInfo(profile, info, profileError)) {
                report.Warn(L"Perfil " + ProfileName(profile) + L": " + profileError);
                continue;
            }
            std::wstring state = info.enabled ? L"ligado" : L"desligado";
            std::wstring inbound = info.defaultInbound == 0 ? L"permitir" : L"bloquear";
            report.Info(L"Perfil " + ProfileName(profile) + L": " + state +
                        L", entrada padrao: " + inbound);
            if (!info.enabled && g_cfg.GetBool(L"Rede", L"EnsureFirewallEnabled", false)) {
                report.Warn(L"Perfil " + ProfileName(profile) +
                            L" desligado; sera ligado ao aplicar (EnsureFirewallEnabled=1).");
            }
        }
        std::vector<std::wstring> rules;
        ExpectedRuleNames(rules);
        for (const auto& rule : rules) CheckFirewallRule(report, fw, rule);
        fw.Shutdown();
    }

    report.Section(L"Servidor FiveM");
    ServerPaths paths = GetServerPaths(g_cfg);
    report.Info(L"Pasta raiz: " + paths.root);
    if (FileExists(JoinPath(paths.server, L"FXServer.exe"))) {
        std::wstring version = GetFileVersionString(JoinPath(paths.server, L"FXServer.exe"));
        report.Ok(L"FXServer.exe presente" + (version.empty() ? L"." : L" (versao " + version + L")."));
    } else {
        report.Warn(L"FXServer.exe nao encontrado em " + paths.server + L".");
    }
    if (DirExists(paths.data)) {
        report.Ok(L"Pasta server-data presente: " + paths.data);
    } else {
        report.Warn(L"Pasta server-data nao encontrada: " + paths.data);
    }
    std::wstring cfgPath = JoinPath(paths.data, L"server.cfg");
    std::wstring cfgText;
    if (FileExists(cfgPath) && ReadTextFile(cfgPath, cfgText)) {
        report.Ok(L"server.cfg encontrado.");
        std::wstring license = FindCfgValue(cfgText, L"sv_licenseKey");
        if (license.empty()) {
            report.Warn(L"server.cfg sem sv_licenseKey.");
        } else if (ContainsI(license, L"COLE_SUA_CHAVE") || ContainsI(license, L"changeme") ||
                   license.size() < 16) {
            report.Warn(L"A chave de licenca ainda nao foi configurada corretamente.");
        } else {
            report.Ok(L"sv_licenseKey configurada (confirme se esta ativa no portal.cfx.re).");
        }
        std::wstring tcpEndpoint = FindCfgValue(cfgText, L"endpoint_add_tcp");
        std::wstring udpEndpoint = FindCfgValue(cfgText, L"endpoint_add_udp");
        if (ContainsI(tcpEndpoint, IntToW(gamePort))) {
            report.Ok(L"endpoint_add_tcp contem a porta " + IntToW(gamePort) + L".");
        } else {
            report.Warn(L"server.cfg nao declara endpoint_add_tcp na porta " + IntToW(gamePort) + L".");
        }
        if (ContainsI(udpEndpoint, IntToW(gamePort))) {
            report.Ok(L"endpoint_add_udp contem a porta " + IntToW(gamePort) + L".");
        } else {
            report.Warn(L"server.cfg nao declara endpoint_add_udp na porta " + IntToW(gamePort) + L".");
        }
        if (g_cfg.GetBool(L"Rede", L"OpenTxAdminPort", true)) {
            std::wstring txCfg = FindCfgValue(cfgText, L"txAdminPort");
            if (txCfg.empty()) {
                report.Info(L"txAdminPort nao declarado (padrao 40120).");
            } else if (ContainsI(txCfg, IntToW(txPort))) {
                report.Ok(L"txAdminPort configurado para " + IntToW(txPort) + L".");
            } else {
                report.Warn(L"txAdminPort no server.cfg difere da porta " + IntToW(txPort) + L".");
            }
        }
    } else {
        report.Warn(L"server.cfg nao encontrado em " + cfgPath + L".");
    }
    if (FileExists(JoinPath(paths.root, L"start-server.cmd"))) {
        report.Ok(L"start-server.cmd presente.");
    } else {
        report.Info(L"start-server.cmd sera criado ao preparar o servidor.");
    }

    report.Section(L"Seguranca");
    SmbInfo smb;
    GetSmbInfo(smb);
    if (smb.serverDisabled) report.Ok(L"SMBv1 desabilitado no servidor.");
    else report.Warn(L"SMBv1 habilitado no servidor.");
    if (smb.clientDisabled) report.Ok(L"Cliente SMBv1 desabilitado.");
    else report.Warn(L"Cliente SMBv1 habilitado.");
    if (smb.signingRequired) report.Ok(L"Assinatura SMB obrigatoria no servidor.");
    else report.Warn(L"Assinatura SMB nao obrigatoria no servidor.");

    TlsInfo tls;
    GetTlsInfo(tls);
    if (tls.tls12Server && tls.tls12Client) {
        report.Ok(L"TLS 1.2 habilitado (explicito ou padrao do Windows) no servidor e no cliente.");
    } else {
        report.Warn(L"TLS 1.2 incompleto (servidor=" + BoolText(tls.tls12Server) +
                    L", cliente=" + BoolText(tls.tls12Client) + L").");
    }
    if (tls.legacyDisabled) {
        report.Ok(L"TLS 1.0/1.1 desabilitados no servidor e no cliente.");
    } else if (tls.legacyServerDisabled || tls.legacyClientDisabled) {
        report.Info(L"TLS 1.0/1.1 parcialmente desabilitado (servidor=" +
                    BoolText(tls.legacyServerDisabled) + L", cliente=" +
                    BoolText(tls.legacyClientDisabled) + L").");
    } else {
        report.Info(L"TLS 1.0/1.1 habilitados (padrao do Windows ou DisableLegacyTLS=0).");
    }

    IeEscInfo esc;
    GetIeEscInfo(esc);
    report.Info(L"IE Enhanced Security: administradores=" + std::wstring(esc.admins ? L"ativo" : L"inativo") +
                L", usuarios=" + std::wstring(esc.users ? L"ativo" : L"inativo") + L".");
    if (g_cfg.GetBool(L"Navegador", L"DisableIEESC", true)) {
        if (esc.admins || esc.users) {
            report.Info(L"IE ESC ativo; sera desativado ao aplicar (requer logoff/logon).");
        } else {
            report.Ok(L"IE Enhanced Security desativado para administradores e usuarios.");
        }
    } else {
        report.Info(L"DisableIEESC=0: IE Enhanced Security sera mantido ativo.");
    }

    bool guestDisabled = false;
    if (GetGuestDisabled(guestDisabled)) {
        if (guestDisabled) report.Ok(L"Conta Guest desativada.");
        else report.Warn(L"Conta Guest ativa; sera desativada ao aplicar.");
    } else {
        report.Warn(L"Nao foi possivel consultar a conta Guest.");
    }

    if (IsRdpEnabled()) {
        DWORD nla = 0;
        if (RegGetDword(HKEY_LOCAL_MACHINE,
                        L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
                        L"UserAuthentication", nla)) {
            if (nla != 0) report.Ok(L"RDP: Network Level Authentication exigido.");
            else report.Warn(L"RDP: NLA desabilitado.");
        } else {
            report.Warn(L"RDP: UserAuthentication nao configurado (NLA desabilitado por padrao).");
        }
    }

    DWORD noLmHash = 0;
    if (RegGetDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
                    L"NoLMHash", noLmHash) && noLmHash != 0) {
        report.Ok(L"LSA: hash LM nao armazenado.");
    } else {
        report.Warn(L"LSA: NoLMHash nao habilitado.");
    }
    if (!IsDomainController()) {
        DWORD lmLevel = 0;
        if (RegGetDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
                        L"LmCompatibilityLevel", lmLevel) && lmLevel >= 3) {
            report.Ok(L"LSA: NTLMv2 exigido (nivel " + IntToW((unsigned)lmLevel) + L").");
        } else {
            report.Warn(L"LSA: LmCompatibilityLevel abaixo de 3.");
        }
    }

    DWORD autorun = 0;
    bool autorunOff = false;
    if (RegGetDword(HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                    L"NoDriveTypeAutoRun", autorun) && (autorun & 0xFF) == 0xFF) {
        autorunOff = true;
    }
    if (RegGetDword(HKEY_CURRENT_USER,
                    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                    L"NoDriveTypeAutoRun", autorun) && (autorun & 0xFF) == 0xFF) {
        autorunOff = true;
    }
    if (autorunOff) report.Ok(L"AutoRun/AutoPlay desativado por politica.");
    else report.Warn(L"AutoRun/AutoPlay nao desativado por politica.");

    if (g_cfg.GetBool(L"Seguranca", L"ConfigureDefenderExclusions", true)) {
        DWORD value = 0;
        if (RegGetDword(HKEY_LOCAL_MACHINE,
                        L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths",
                        serverRoot, value)) {
            report.Ok(L"Defender: exclusao configurada para " + serverRoot + L".");
        } else {
            report.Info(L"Defender: exclusao para " + serverRoot + L" sera criada ao aplicar.");
        }
    }

    report.Section(L"Navegadores");
    report.Info(L"Internet Explorer: " + GetIeVersion());
    std::wstring ieHome = GetIeHomePage();
    if (!ieHome.empty()) report.Info(L"IE: pagina inicial atual = " + ieHome);
    DWORD protocols = 0;
    if (GetIeSecureProtocols(protocols)) {
        if ((protocols & 0x800) != 0) report.Ok(L"IE: TLS 1.2 habilitado.");
        else report.Warn(L"IE: TLS 1.2 nao habilitado.");
    } else {
        report.Warn(L"IE: SecureProtocols nao configurado.");
    }
    CheckBrowserPolicy(report, L"Chrome", FindChromePath(), L"SOFTWARE\\Policies\\Google\\Chrome");
    CheckBrowserPolicy(report, L"Edge", FindEdgePath(), L"SOFTWARE\\Policies\\Microsoft\\Edge");
    std::wstring firefox = FindFirefoxPath();
    if (firefox.empty()) {
        report.Info(L"Firefox nao instalado.");
    } else {
        std::wstring policyFile = JoinPath(ParentDir(firefox), L"distribution\\policies.json");
        if (FileExists(policyFile)) report.Ok(L"Firefox: policies.json presente.");
        else report.Info(L"Firefox: policies.json sera criado ao aplicar.");
    }

    report.Summary();
}

bool SaveReport(const Report& report) {
    std::wstring dir = JoinPath(ExeDir(), L"reports");
    if (!EnsureDir(dir)) {
        g_log.Warn(L"Nao foi possivel criar a pasta de relatorios: " + dir);
        return false;
    }
    std::wstring path = JoinPath(dir, L"relatorio-" + NowStamp() + L"-" +
                                      IntToW((unsigned)GetCurrentProcessId()) + L".txt");
    std::wstring text;
    text += L"FiveMGuard " + std::wstring(kAppVersion) + L"\r\n";
    text += L"Relatorio gerado em " + NowReadable() + L"\r\n";
    text += L"Computador: " + GetComputerNameStr() + L"\r\n";
    text += L"Usuario: " + GetUserNameStr() + L"\r\n";
    text += L"Modo: " + std::wstring(g_log.DryRun() ? L"SIMULACAO" : L"REAL") + L"\r\n";
    text += L"Configuracao: " + g_cfg.Path() + L"\r\n";
    text += L"------------------------------------------------------------\r\n";

    std::wstring currentSection;
    for (const auto& item : report.Items()) {
        if (item.section != currentSection) {
            currentSection = item.section;
            text += L"\r\n[" + currentSection + L"]\r\n";
        }
        const wchar_t* tag = L"[INFO]";
        switch (item.status) {
            case Check::Ok: tag = L"[OK]"; break;
            case Check::Warn: tag = L"[AVISO]"; break;
            case Check::Error: tag = L"[ERRO]"; break;
            default: tag = L"[INFO]"; break;
        }
        text += std::wstring(tag) + L" " + item.text + L"\r\n";
    }
    text += L"\r\n------------------------------------------------------------\r\n";
    text += L"Resumo: OK=" + IntToW(report.Count(Check::Ok)) +
            L" Avisos=" + IntToW(report.Count(Check::Warn)) +
            L" Erros=" + IntToW(report.Count(Check::Error)) + L"\r\n";

    if (!WriteTextFile(path, text, true)) {
        g_log.Warn(L"Nao foi possivel gravar o relatorio em " + path);
        return false;
    }
    g_log.Ok(L"Relatorio salvo em " + path);
    return true;
}

// ------------------------------------------------------------------ backup
const wchar_t* kBackupKeys[] = {
    L"HKLM\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer",
    L"HKLM\\SOFTWARE\\Policies\\Google\\Chrome",
    L"HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge",
    L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
    L"HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
    L"HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\{A509B1A7-37EF-4B3F-8CFC-4F3A74704073}",
    L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL",
    L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
    L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10",
    L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
    L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
    L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
    L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
    L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
    L"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell",
    L"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
    L"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions",
    L"HKLM\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319",
    L"HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\.NETFramework\\v4.0.30319",
    L"HKCU\\Software\\Microsoft\\Internet Explorer\\Main",
    L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
};

bool ExportRegistryKey(const std::wstring& fullKey, const std::wstring& file,
                       std::wstring& error) {
    error.clear();
    std::wstring regExe = JoinPath(GetEnvVar(L"SystemRoot"), L"System32\\reg.exe");
    if (!FileExists(regExe)) {
        error = L"reg.exe nao encontrado em " + regExe;
        return false;
    }
    std::wstring command = QuoteArg(regExe) + L" export " + QuoteArg(fullKey) + L" " +
                           QuoteArg(file) + L" /y";
    ProcessResult result;
    if (!RunProcess(command, ExeDir(), 120 * 1000, result)) {
        error = L"falha ao iniciar reg export: " + result.output;
        return false;
    }
    if (result.exitCode != 0 || !FileExists(file) || FileSize(file) == 0) {
        error = L"reg export " + fullKey + L" falhou";
        if (!result.output.empty()) error += L": " + result.output;
        return false;
    }
    return true;
}

bool ImportRegistryKey(const std::wstring& file, std::wstring& error) {
    error.clear();
    std::wstring regExe = JoinPath(GetEnvVar(L"SystemRoot"), L"System32\\reg.exe");
    if (!FileExists(regExe)) {
        error = L"reg.exe nao encontrado em " + regExe;
        return false;
    }
    if (!FileExists(file)) {
        error = L"arquivo .reg nao encontrado: " + file;
        return false;
    }
    std::wstring command = QuoteArg(regExe) + L" import " + QuoteArg(file);
    ProcessResult result;
    if (!RunProcess(command, ExeDir(), 120 * 1000, result)) {
        error = L"falha ao iniciar reg import: " + result.output;
        return false;
    }
    if (result.exitCode != 0) {
        error = L"reg import falhou";
        if (!result.output.empty()) error += L": " + result.output;
        return false;
    }
    return true;
}

bool SetGuestDisabled(bool disabled, std::wstring& error) {
    error.clear();
    USER_INFO_1* info = nullptr;
    NET_API_STATUS status = NetUserGetInfo(nullptr, L"Guest", 1, (LPBYTE*)&info);
    if (status != NERR_Success || !info) {
        error = L"nao foi possivel consultar a conta Guest (codigo " +
                IntToW((long long)status) + L")";
        return false;
    }
    bool current = (info->usri1_flags & UF_ACCOUNTDISABLE) != 0;
    if (current == disabled) {
        NetApiBufferFree(info);
        return true;
    }
    if (disabled) info->usri1_flags |= UF_ACCOUNTDISABLE;
    else info->usri1_flags &= ~UF_ACCOUNTDISABLE;
    DWORD paramError = 0;
    status = NetUserSetInfo(nullptr, L"Guest", 1, (LPBYTE)info, &paramError);
    NetApiBufferFree(info);
    if (status != NERR_Success) {
        error = L"nao foi possivel alterar a conta Guest (codigo " +
                IntToW((long long)status) + L")";
        return false;
    }
    return true;
}

std::wstring GetOsInfoProductName();

std::wstring GetPowerCfgPath() {
    return JoinPath(GetEnvVar(L"SystemRoot"), L"System32\\powercfg.exe");
}

bool IsPowerGuid(const std::wstring& value) {
    if (value.size() != 36) return false;
    for (size_t i = 0; i < value.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != L'-') return false;
        } else if (!iswxdigit(value[i])) {
            return false;
        }
    }
    return true;
}

bool FindPowerGuid(const std::wstring& text, std::wstring& guid) {
    guid.clear();
    if (text.size() < 36) return false;
    for (size_t i = 0; i + 36 <= text.size(); ++i) {
        std::wstring candidate = text.substr(i, 36);
        if (IsPowerGuid(candidate)) {
            guid = candidate;
            return true;
        }
    }
    return false;
}

bool GetActivePowerScheme(std::wstring& guid) {
    guid.clear();
    std::wstring powercfg = GetPowerCfgPath();
    if (!FileExists(powercfg)) return false;
    ProcessResult result;
    if (!RunProcess(QuoteArg(powercfg) + L" /getactivescheme", ExeDir(), 30 * 1000, result) ||
        result.exitCode != 0) {
        return false;
    }
    return FindPowerGuid(result.output, guid);
}

bool CreateBackup(std::wstring& backupDir, std::wstring& error) {
    error.clear();
    backupDir.clear();
    std::wstring backupsRoot = JoinPath(ExeDir(), L"backups");
    if (!EnsureDir(backupsRoot)) {
        error = L"nao foi possivel criar " + backupsRoot;
        return false;
    }
    std::wstring stamp = NowStamp();
    backupDir = JoinPath(backupsRoot, stamp);
    int suffix = 1;
    while (DirExists(backupDir)) {
        backupDir = JoinPath(backupsRoot, stamp + L"-" + IntToW(suffix++));
    }
    std::wstring regDir = JoinPath(backupDir, L"registro");
    if (!EnsureDir(regDir)) {
        error = L"nao foi possivel criar " + regDir;
        return false;
    }

    if (!g_cfg.Path().empty() && FileExists(g_cfg.Path())) {
        if (!CopyFileSimple(g_cfg.Path(), JoinPath(backupDir, L"config.ini"), true)) {
            g_log.Warn(L"Nao foi possivel copiar o config.ini para o backup.");
        }
    }

    std::wstring registryManifest;
    int index = 0;
    for (const wchar_t* key : kBackupKeys) {
        HKEY root = nullptr;
        std::wstring subkey;
        if (!SplitRegistryKey(key, root, subkey)) continue;
        bool exists = RegKeyExists(root, subkey);
        std::wstring line = std::wstring(key) + L"|" + (exists ? L"1" : L"0") + L"|";
        if (exists) {
            wchar_t name[32];
            swprintf(name, 32, L"%03d.reg", ++index);
            std::wstring file = JoinPath(regDir, name);
            std::wstring exportError;
            if (!ExportRegistryKey(key, file, exportError)) {
                error = L"backup do registro falhou para " + std::wstring(key) + L": " + exportError;
                g_log.Error(error);
                return false;
            }
            line += L"registro\\" + std::wstring(name);
            g_log.Detail(L"Backup do registro: " + std::wstring(key));
        } else {
            g_log.Detail(L"Chave inexistente (sera removida no rollback): " + std::wstring(key));
        }
        registryManifest += line + L"\r\n";
    }
    if (!WriteTextFile(JoinPath(backupDir, L"registro.txt"), registryManifest, true)) {
        error = L"nao foi possivel gravar registro.txt";
        return false;
    }

    bool guestDisabled = false;
    bool guestKnown = GetGuestDisabled(guestDisabled);
    std::wstring state = L"guest-known=" + std::wstring(guestKnown ? L"1" : L"0") + L"\r\n";
    state += L"guest-disabled=" + std::wstring(guestDisabled ? L"1" : L"0") + L"\r\n";
    if (!WriteTextFile(JoinPath(backupDir, L"estado.txt"), state, true)) {
        error = L"nao foi possivel gravar estado.txt";
        return false;
    }

    std::wstring powerGuid;
    if (GetActivePowerScheme(powerGuid)) {
        if (!WriteTextFile(JoinPath(backupDir, L"energia.txt"), powerGuid + L"\r\n", true)) {
            g_log.Warn(L"Nao foi possivel gravar o plano de energia atual no backup.");
        }
    } else {
        g_log.Warn(L"Nao foi possivel consultar o plano de energia atual; "
                   L"ele nao sera restaurado pelo rollback.");
    }

    std::wstring ff = FindFirefoxPath();
    std::wstring firefoxInfo = L"installed=" + std::wstring(ff.empty() ? L"0" : L"1") + L"\r\n";
    if (!ff.empty()) {
        std::wstring policyPath = JoinPath(ParentDir(ff), L"distribution\\policies.json");
        firefoxInfo += L"path=" + policyPath + L"\r\n";
        bool existed = FileExists(policyPath);
        firefoxInfo += L"existed=" + std::wstring(existed ? L"1" : L"0") + L"\r\n";
        if (existed) {
            std::wstring backupFile = JoinPath(backupDir, L"arquivos\\firefox-policies.json");
            if (EnsureParentDir(backupFile) && CopyFileSimple(policyPath, backupFile, true)) {
                firefoxInfo += L"backup=arquivos\\firefox-policies.json\r\n";
            } else {
                g_log.Warn(L"Nao foi possivel copiar a politica do Firefox; "
                           L"o arquivo original sera preservado e nao alterado.");
                firefoxInfo += L"backup=\r\n";
            }
        }
    }
    if (!WriteTextFile(JoinPath(backupDir, L"firefox.txt"), firefoxInfo, true)) {
        error = L"nao foi possivel gravar firefox.txt";
        return false;
    }

    std::wstring info;
    info += L"FiveMGuard " + std::wstring(kAppVersion) + L"\r\n";
    info += L"Backup criado em " + NowReadable() + L"\r\n";
    info += L"Computador: " + GetComputerNameStr() + L"\r\n";
    info += L"Usuario: " + GetUserNameStr() + L"\r\n";
    info += L"Windows: " + GetOsInfoProductName() + L"\r\n";
    info += L"Configuracao: " + g_cfg.Path() + L"\r\n";
    info += L"\r\n";
    info += L"Este backup permite restaurar valores de registro, regras de firewall\r\n";
    info += L"criadas pelo FiveMGuard, a conta Guest, o plano de energia ativo\r\n";
    info += L"e a politica do Firefox.\r\n";
    info += L"Instaladores, dependencias e arquivos do servidor NAO sao removidos\r\n";
    info += L"pelo rollback.\r\n";
    if (!WriteTextFile(JoinPath(backupDir, L"backup-info.txt"), info, true)) {
        error = L"nao foi possivel gravar backup-info.txt";
        return false;
    }

    if (!WriteTextFile(JoinPath(backupsRoot, L"ultimo.txt"), backupDir, true)) {
        g_log.Warn(L"Nao foi possivel gravar backups\\ultimo.txt");
    }

    g_log.Ok(L"Backup criado em " + backupDir);
    return true;
}

// helper para backup-info (evita dependencia de SystemInfo no cabecalho)
std::wstring GetOsInfoProductName() {
    OsInfo os;
    GetOsInfo(os);
    return os.productName;
}

void SaveFirewallRules(const std::wstring& backupDir,
                       const std::vector<std::wstring>& rules) {
    if (backupDir.empty()) return;
    std::wstring text;
    for (const auto& rule : rules) text += rule + L"\r\n";
    if (!WriteTextFile(JoinPath(backupDir, L"firewall.txt"), text, true)) {
        g_log.Warn(L"Nao foi possivel gravar a lista de regras de firewall no backup.");
    }
}

// ------------------------------------------------------------------ rollback
bool FindLatestBackup(std::wstring& backupDir) {
    backupDir.clear();
    std::wstring root = JoinPath(ExeDir(), L"backups");
    std::wstring last;
    if (ReadTextFile(JoinPath(root, L"ultimo.txt"), last)) {
        last = Trim(last);
        if (!last.empty()) {
            std::wstring resolved = MakeAbsolute(last, ExeDir());
            if (DirExists(resolved)) {
                backupDir = resolved;
                return true;
            }
        }
    }
    std::wstring pattern = root;
    if (!pattern.empty() && pattern.back() != L'\\') pattern.push_back(L'\\');
    pattern += L"*";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return false;
    std::wstring best;
    do {
        std::wstring name = fd.cFileName;
        if (name == L"." || name == L"..") continue;
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (best.empty() || name > best) best = name;
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    if (best.empty()) return false;
    backupDir = JoinPath(root, best);
    return true;
}

std::wstring UnescapeJournal(const std::wstring& value) {
    std::wstring out;
    for (size_t i = 0; i < value.size(); ++i) {
        wchar_t c = value[i];
        if (c == L'\\' && i + 1 < value.size()) {
            wchar_t next = value[++i];
            switch (next) {
                case L'\\': out.push_back(L'\\'); break;
                case L't': out.push_back(L'\t'); break;
                case L'r': out.push_back(L'\r'); break;
                case L'n': out.push_back(L'\n'); break;
                default: out.push_back(next); break;
            }
        } else {
            out.push_back(c);
        }
    }
    return out;
}

struct JournalEntry {
    wchar_t kind = L'D';
    HKEY root = nullptr;
    std::wstring subkey;
    std::wstring name;
    std::wstring value;
    bool existed = false;
};

bool ParseJournalLine(const std::wstring& line, JournalEntry& entry) {
    std::vector<std::wstring> parts = SplitChar(line, L'\t');
    if (parts.size() < 6 || parts[0].empty()) return false;
    entry.kind = parts[0][0];
    if (!RootFromName(parts[1], entry.root)) return false;
    entry.subkey = UnescapeJournal(parts[2]);
    entry.name = UnescapeJournal(parts[3]);
    entry.existed = parts[4] == L"1";
    entry.value = UnescapeJournal(parts[5]);
    return true;
}

int RestoreJournal(const std::wstring& journalPath) {
    std::vector<std::wstring> lines = ReadRawLines(journalPath);
    std::vector<JournalEntry> entries;
    for (const auto& line : lines) {
        JournalEntry entry;
        if (ParseJournalLine(line, entry)) entries.push_back(entry);
    }
    if (entries.empty()) return 0;

    int failures = 0;
    for (const auto& entry : entries) {
        if (entry.existed) continue;
        if (g_log.DryRun()) {
            g_log.Step(L"Removeria valor de registro: " + entry.name);
            continue;
        }
        if (!RegDeleteValue(entry.root, entry.subkey, entry.name)) {
            ++failures;
            g_log.Warn(L"Nao foi possivel remover o valor " + entry.name);
        }
    }
    for (const auto& entry : entries) {
        if (!entry.existed) continue;
        if (g_log.DryRun()) {
            g_log.Step(L"Restauraria valor de registro: " + entry.name);
            continue;
        }
        bool ok = true;
        if (entry.kind == L'D') {
            wchar_t* end = nullptr;
            unsigned long parsed = wcstoul(entry.value.c_str(), &end, 0);
            if (end == entry.value.c_str()) {
                ok = false;
            } else {
                ok = RegSetDword(entry.root, entry.subkey, entry.name, (DWORD)parsed);
            }
        } else {
            ok = RegSetString(entry.root, entry.subkey, entry.name, entry.value);
        }
        if (!ok) {
            ++failures;
            g_log.Warn(L"Nao foi possivel restaurar o valor " + entry.name);
        }
    }
    return failures;
}

bool RestoreFirefox(const std::wstring& backupDir) {
    std::wstring path = JoinPath(backupDir, L"firefox.txt");
    if (!FileExists(path)) return true;
    std::vector<std::wstring> lines = ReadRawLines(path);
    if (ManifestValue(lines, L"installed") != L"1") return true;
    std::wstring policyPath = ManifestValue(lines, L"path");
    if (policyPath.empty()) return true;
    bool existed = ManifestValue(lines, L"existed") == L"1";
    if (g_log.DryRun()) {
        g_log.Step(existed ? L"Restauraria a politica do Firefox em " + policyPath
                           : L"Removeria a politica do Firefox criada em " + policyPath);
        return true;
    }
    if (existed) {
        std::wstring relative = ManifestValue(lines, L"backup");
        if (relative.empty()) {
            g_log.Info(L"Politica do Firefox original nao foi alterada; nada a restaurar.");
            return true;
        }
        std::wstring backupFile = JoinPath(backupDir, relative);
        if (!FileExists(backupFile)) {
            g_log.Warn(L"Arquivo de backup da politica do Firefox nao encontrado: " + backupFile);
            return false;
        }
        if (!CopyFileSimple(backupFile, policyPath, true)) {
            g_log.Warn(L"Nao foi possivel restaurar a politica do Firefox em " + policyPath);
            return false;
        }
        g_log.Ok(L"Politica do Firefox restaurada.");
    } else {
        if (FileExists(policyPath) && !RemoveFile(policyPath)) {
            g_log.Warn(L"Nao foi possivel remover a politica do Firefox em " + policyPath);
            return false;
        }
        if (!FileExists(policyPath)) g_log.Ok(L"Politica do Firefox removida.");
    }
    return true;
}

int Rollback(const Options& opt) {
    if (!opt.dryRun && !IsUserAdmin()) {
        g_log.Error(L"O rollback exige privilegios de administrador.");
        return 3;
    }

    std::wstring backupDir;
    if (!opt.backupPath.empty()) {
        backupDir = MakeAbsolute(ExpandEnv(opt.backupPath), ExeDir());
    } else if (!FindLatestBackup(backupDir)) {
        g_log.Error(L"Nenhum backup encontrado em " + JoinPath(ExeDir(), L"backups") +
                    L". Use --backup-dir para indicar uma pasta.");
        return 1;
    }
    if (!DirExists(backupDir)) {
        g_log.Error(L"Pasta de backup invalida: " + backupDir);
        return 1;
    }

    g_log.Section(L"Rollback");
    g_log.Info(L"Backup: " + backupDir);
    std::wstring infoText;
    if (ReadTextFile(JoinPath(backupDir, L"backup-info.txt"), infoText)) {
        g_log.Detail(Trim(infoText));
    }

    if (!opt.dryRun && !opt.yes) {
        if (!g_log.Confirm(L"Restaurar registro, firewall, Guest, plano de energia e politica do Firefox deste backup?",
                           false)) {
            g_log.Warn(L"Rollback cancelado.");
            return 0;
        }
    }

    int failures = 0;
    std::wstring error;

    std::vector<std::wstring> firewallRules;
    for (const auto& line : ReadRawLines(JoinPath(backupDir, L"firewall.txt"))) {
        std::wstring rule = Trim(line);
        if (!rule.empty()) firewallRules.push_back(rule);
    }
    if (!firewallRules.empty()) {
        Firewall fw;
        std::wstring fwError;
        if (!fw.Init(fwError)) {
            ++failures;
            g_log.Error(L"Nao foi possivel abrir o firewall para remover as regras: " + fwError);
        } else {
            for (const auto& rule : firewallRules) {
                if (opt.dryRun) {
                    g_log.Step(L"Removeria a regra de firewall: " + rule);
                    continue;
                }
                std::wstring removeError;
                if (!fw.RemoveRule(rule, removeError)) {
                    ++failures;
                    g_log.Warn(L"Falha ao remover a regra " + rule + L": " + removeError);
                } else {
                    g_log.Ok(L"Regra removida: " + rule);
                }
            }
            fw.Shutdown();
        }
    } else {
        g_log.Info(L"Nenhuma regra de firewall registrada no backup.");
    }

    struct RegEntry {
        std::wstring key;
        bool existed = false;
        std::wstring file;
    };
    std::vector<RegEntry> registry;
    for (const auto& line : ReadRawLines(JoinPath(backupDir, L"registro.txt"))) {
        std::vector<std::wstring> parts = SplitChar(line, L'|');
        if (parts.size() < 2) continue;
        RegEntry entry;
        entry.key = Trim(parts[0]);
        entry.existed = Trim(parts[1]) == L"1";
        if (parts.size() >= 3) entry.file = Trim(parts[2]);
        if (!entry.key.empty()) registry.push_back(entry);
    }

    for (const auto& entry : registry) {
        if (!entry.existed || entry.file.empty()) continue;
        std::wstring file = JoinPath(backupDir, entry.file);
        if (opt.dryRun) {
            g_log.Step(L"Importaria o registro: " + file);
            continue;
        }
        if (!ImportRegistryKey(file, error)) {
            ++failures;
            g_log.Warn(L"Falha ao restaurar " + entry.key + L": " + error);
        } else {
            g_log.Ok(L"Registro restaurado: " + entry.key);
        }
    }

    std::wstring journalPath = JoinPath(backupDir, L"valores-alterados.tsv");
    if (FileExists(journalPath)) {
        failures += RestoreJournal(journalPath);
    } else {
        g_log.Warn(L"Diario de valores alterados nao encontrado; "
                   L"alguns valores novos em chaves existentes podem permanecer.");
    }

    for (const auto& entry : registry) {
        if (entry.existed) continue;
        HKEY root = nullptr;
        std::wstring subkey;
        if (!SplitRegistryKey(entry.key, root, subkey)) continue;
        if (opt.dryRun) {
            g_log.Step(L"Removeria a chave de registro criada: " + entry.key);
            continue;
        }
        if (!RegDeleteKeyTree(root, subkey)) {
            ++failures;
            g_log.Warn(L"Nao foi possivel remover a chave " + entry.key);
        } else {
            g_log.Ok(L"Chave removida: " + entry.key);
        }
    }

    std::vector<std::wstring> state = ReadRawLines(JoinPath(backupDir, L"estado.txt"));
    bool guestKnown = ManifestValue(state, L"guest-known") == L"1";
    if (guestKnown) {
        bool wasDisabled = ManifestValue(state, L"guest-disabled") == L"1";
        if (IsDomainController()) {
            g_log.Info(L"Controlador de dominio: conta Guest nao sera alterada.");
        } else if (opt.dryRun) {
            g_log.Step(wasDisabled ? L"Manteria a conta Guest desativada."
                                   : L"Reativaria a conta Guest como estava antes.");
        } else if (!SetGuestDisabled(wasDisabled, error)) {
            ++failures;
            g_log.Warn(L"Falha ao restaurar a conta Guest: " + error);
        } else {
            g_log.Ok(wasDisabled ? L"Conta Guest restaurada (desativada)."
                                 : L"Conta Guest restaurada (ativada).");
        }
    }

    if (!RestoreFirefox(backupDir)) ++failures;

    std::wstring powerGuid;
    if (ReadTextFile(JoinPath(backupDir, L"energia.txt"), powerGuid)) {
        powerGuid = Trim(powerGuid);
        std::wstring powercfg = GetPowerCfgPath();
        if (!IsPowerGuid(powerGuid)) {
            ++failures;
            g_log.Warn(L"Plano de energia registrado no backup e invalido: " + powerGuid);
        } else if (!FileExists(powercfg)) {
            ++failures;
            g_log.Warn(L"powercfg.exe nao encontrado; plano de energia nao restaurado.");
        } else if (opt.dryRun) {
            g_log.Step(L"Restauraria o plano de energia: " + powerGuid);
        } else {
            ProcessResult result;
            std::wstring command = QuoteArg(powercfg) + L" /setactive " + QuoteArg(powerGuid);
            if (!RunProcess(command, ExeDir(), 30 * 1000, result) || result.exitCode != 0) {
                ++failures;
                g_log.Warn(L"Nao foi possivel restaurar o plano de energia " + powerGuid + L".");
            } else {
                g_log.Ok(L"Plano de energia restaurado: " + powerGuid);
            }
        }
    } else {
        g_log.Info(L"Plano de energia nao registrado neste backup; nada a restaurar.");
    }

    if (FileExists(JoinPath(backupDir, L"config.ini"))) {
        g_log.Info(L"Copia da configuracao antiga: " + JoinPath(backupDir, L"config.ini"));
    }

    g_log.Section(L"Resultado do rollback");
    if (failures == 0) {
        g_log.Ok(L"Rollback concluido sem erros.");
        g_log.Warn(L"Reinicie o servidor para aplicar alteracoes de SMB/TLS/RDP.");
    } else {
        g_log.Error(L"Rollback concluido com " + IntToW(failures) + L" falha(s).");
    }
    g_log.Info(L"Instaladores, dependencias e arquivos do servidor nao foram removidos.");
    return failures == 0 ? 0 : 2;
}

// ------------------------------------------------------------------ aplicacao
bool ValidateConfig(std::wstring& error) {
    error.clear();
    int gamePort = g_cfg.GetInt(L"Rede", L"GamePort", 30120);
    if (!IsValidPort(gamePort)) {
        error = L"GamePort invalida: " + IntToW(gamePort);
        return false;
    }
    if (g_cfg.GetBool(L"Rede", L"OpenTxAdminPort", true)) {
        int txPort = g_cfg.GetInt(L"Rede", L"TxAdminPort", 40120);
        if (!IsValidPort(txPort)) {
            error = L"TxAdminPort invalida: " + IntToW(txPort);
            return false;
        }
        if (txPort == gamePort) {
            error = L"TxAdminPort nao pode ser igual a GamePort.";
            return false;
        }
    }
    std::wstring root = g_cfg.GetPath(L"Servidor", L"ServerRoot", L"C:\\FXServer");
    if (root.empty()) {
        error = L"ServerRoot vazio.";
        return false;
    }
    if (root.size() == 3 && root[1] == L':' && root[2] == L'\\') {
        g_log.Warn(L"ServerRoot e a raiz do disco; as pastas serao criadas em " + root);
    }
    return true;
}

void PrintApplySummary() {
    int gamePort = g_cfg.GetInt(L"Rede", L"GamePort", 30120);
    int txPort = g_cfg.GetInt(L"Rede", L"TxAdminPort", 40120);
    long profiles = Firewall::ProfilesFromString(
        g_cfg.GetString(L"Rede", L"FirewallProfiles", L"domain,private,public"), 7);
    long txProfiles = Firewall::ProfilesFromString(
        g_cfg.GetString(L"Rede", L"TxAdminProfiles", L"domain,private"), 3);
    ServerPaths paths = GetServerPaths(g_cfg);

    g_log.Info(L"Porta do jogo: " + IntToW(gamePort) + L" TCP/UDP, perfis " +
               Firewall::ProfilesToString(profiles) + L", remoto " +
               g_cfg.GetString(L"Rede", L"RemoteAddresses", L"*"));
    if (g_cfg.GetBool(L"Rede", L"OpenTxAdminPort", true)) {
        g_log.Info(L"txAdmin: porta " + IntToW(txPort) + L" TCP, perfis " +
                   Firewall::ProfilesToString(txProfiles) + L", remoto " +
                   g_cfg.GetString(L"Rede", L"TxAdminRemoteAddresses", L"LocalSubnet"));
    } else {
        g_log.Info(L"txAdmin: regra de firewall desativada.");
    }
    g_log.Info(L"Firewall ligado a forca: " +
               BoolText(g_cfg.GetBool(L"Rede", L"EnsureFirewallEnabled", false)) +
               L" (regra de RDP e criada antes, se necessario).");
    g_log.Info(L"SMBv1/assinatura: " + BoolText(g_cfg.GetBool(L"Seguranca", L"HardenSMB", true)));
    g_log.Info(L"TLS 1.2: " + BoolText(g_cfg.GetBool(L"Seguranca", L"HardenTLS", true)) +
               L"; desabilitar TLS 1.0/1.1: " +
               BoolText(g_cfg.GetBool(L"Seguranca", L"DisableLegacyTLS", false)));
    g_log.Info(L"RDP NLA: " + BoolText(g_cfg.GetBool(L"Seguranca", L"EnableRdpNLA", true)));
    g_log.Info(L"Politicas de navegador: " +
               BoolText(g_cfg.GetBool(L"Navegador", L"ConfigureBrowsers", true)));
    g_log.Info(L"Dependencias: VC++=" +
               BoolText(g_cfg.GetBool(L"Dependencias", L"InstallVCRedist", true)) +
               L", .NET 4.8=" +
               BoolText(g_cfg.GetBool(L"Dependencias", L"InstallDotNet48", false)));
    g_log.Info(L"Extras: Chrome=" +
               BoolText(g_cfg.GetBool(L"Extras", L"InstallChrome", true)) +
               L", Node.js=" +
               BoolText(g_cfg.GetBool(L"Extras", L"InstallNodeJs", true)) +
               L", Git=" +
               BoolText(g_cfg.GetBool(L"Extras", L"InstallGit", false)) +
               L", 7-Zip=" +
               BoolText(g_cfg.GetBool(L"Extras", L"InstallSevenZip", false)));
    g_log.Info(L"Servidor: " + paths.root + L" (baixar artefatos=" +
               BoolText(g_cfg.GetBool(L"Servidor", L"DownloadServerArtifacts", false)) + L")");
    g_log.Warn(L"Um backup sera criado antes das alteracoes. E possivel reverter com --rollback.");
}

int ApplyAll(const Options& opt) {
    OsInfo os;
    GetOsInfo(os);
    if (!os.isTarget2012R2) {
        if (!g_cfg.GetBool(L"Geral", L"AllowUnsupportedOS", false)) {
            if (!opt.dryRun) {
                g_log.Error(L"Este Windows nao e o Server 2012 R2 alvo. "
                            L"Use AllowUnsupportedOS=1 no config.ini para forcar (nao recomendado).");
                return 4;
            }
            g_log.Warn(L"Sistema nao suportado; continuando apenas porque --dry-run foi usado.");
        } else {
            g_log.Warn(L"AllowUnsupportedOS=1: aplicando em sistema nao suportado.");
        }
    }
    if (!opt.dryRun && !IsUserAdmin()) {
        g_log.Error(L"Aplicar exige privilegios de administrador. "
                    L"Execute novamente como Administrador ou sem --no-elevate.");
        return 3;
    }
    std::wstring validation;
    if (!ValidateConfig(validation)) {
        g_log.Error(validation);
        return 1;
    }
    if (IsPendingReboot()) {
        g_log.Warn(L"Ha um reinicio pendente antes de aplicar. O resultado pode ser parcial.");
    }

    g_log.Section(L"Resumo da aplicacao");
    PrintApplySummary();
    if (!opt.dryRun && g_cfg.GetBool(L"Geral", L"ConfirmarAntesDeAplicar", true) && !opt.yes) {
        if (!g_log.Confirm(L"Continuar com a aplicacao?", false)) {
            g_log.Warn(L"Aplicacao cancelada pelo usuario.");
            return 0;
        }
    }

    std::wstring backupDir;
    g_log.Section(L"Backup");
    if (opt.dryRun) {
        g_log.Step(L"Criaria o backup em " + JoinPath(ExeDir(), L"backups\\<data-hora>"));
    } else {
        std::wstring backupError;
        if (!CreateBackup(backupDir, backupError)) {
            g_log.Error(L"Backup falhou; aplicacao abortada para nao deixar o sistema sem rollback: " +
                        backupError);
            return 1;
        }
        SetPolicyJournal(JoinPath(backupDir, L"valores-alterados.tsv"));
    }

    int failures = 0;
    bool reboot = false;
    std::wstring error;

    g_log.Section(L"1/7 Firewall");
    if (!opt.dryRun) {
        std::wstring serviceError;
        if (!EnsureFirewallServices(serviceError)) {
            g_log.Warn(L"Servicos de firewall: " + serviceError);
        }
    } else {
        g_log.Step(L"Iniciaria BFE/MpsSvc se necessario.");
    }
    {
        Firewall fw;
        std::wstring fwError;
        if (!fw.Init(fwError)) {
            ++failures;
            g_log.Error(L"Nao foi possivel gerenciar o firewall: " + fwError);
        } else {
            std::vector<std::wstring> rules;
            std::wstring ruleError;
            if (!ApplyFirewallRules(g_cfg, fw, rules, ruleError)) {
                ++failures;
                g_log.Error(L"Uma ou mais regras de firewall falharam. " + ruleError);
            }
            if (!opt.dryRun) SaveFirewallRules(backupDir, rules);
            fw.Shutdown();
        }
    }

    g_log.Section(L"2/7 Navegador");
    {
        std::wstring browserError;
        if (!ApplyBrowserPolicies(g_cfg, browserError)) {
            ++failures;
            g_log.Error(L"Falha ao aplicar politicas de navegador. " + browserError);
        }
    }

    g_log.Section(L"3/7 Seguranca");
    {
        bool securityReboot = false;
        std::wstring securityError;
        if (!ApplySecurityHardening(g_cfg, securityError, securityReboot)) {
            ++failures;
            g_log.Error(L"Falha em um ou mais ajustes de seguranca. " + securityError);
        }
        reboot = reboot || securityReboot;
    }

    g_log.Section(L"4/7 Dependencias");
    {
        bool depsReboot = false;
        std::wstring depsError;
        if (!InstallDependencies(g_cfg, depsReboot, depsError)) {
            ++failures;
            g_log.Error(L"Falha em uma ou mais dependencias. " + depsError);
        }
        reboot = reboot || depsReboot;
    }

    g_log.Section(L"5/7 Ferramentas extras");
    {
        bool extrasReboot = false;
        std::wstring extrasError;
        if (!InstallExtraTools(g_cfg, extrasReboot, extrasError)) {
            ++failures;
            g_log.Error(L"Falha em uma ou mais ferramentas extras. " + extrasError);
        }
        reboot = reboot || extrasReboot;
    }

    g_log.Section(L"6/7 Servidor FiveM");
    {
        bool prepareFolders = g_cfg.GetBool(L"Servidor", L"PrepareServerFolders", true);
        bool downloadConfigured =
            g_cfg.GetBool(L"Servidor", L"DownloadServerArtifacts", false) ||
            g_cfg.GetBool(L"Servidor", L"DownloadServerData", false);
        if (prepareFolders || downloadConfigured || opt.setupServer || opt.downloadServer) {
            std::wstring serverError;
            if (!SetupFiveMServer(g_cfg, opt.downloadServer, serverError)) {
                ++failures;
                g_log.Error(L"Falha ao preparar o servidor FiveM. " + serverError);
            }
        } else {
            g_log.Info(L"PrepareServerFolders=0: pastas do servidor nao serao preparadas.");
        }
    }

    if (!opt.dryRun && g_cfg.GetBool(L"Geral", L"VerifyAfterApply", true)) {
        g_log.Section(L"7/7 Verificacao");
        Report verify;
        RunDiagnostics(verify, true);
        SaveReport(verify);
        int verifyErrors = verify.Count(Check::Error);
        if (verifyErrors > 0) {
            g_log.Warn(L"A verificacao encontrou " + IntToW(verifyErrors) + L" erro(s).");
            if (failures == 0) failures = verifyErrors;
        }
    } else if (opt.dryRun) {
        g_log.Info(L"Verificacao pos-aplicacao ignorada no modo simulacao.");
    }

    if (!opt.dryRun) ClearPolicyJournal();

    g_log.Section(L"Resultado");
    if (failures == 0) {
        g_log.Ok(L"Aplicacao concluida sem erros.");
    } else {
        g_log.Error(L"Aplicacao concluida com " + IntToW(failures) + L" falha(s). "
                    L"Consulte o log e o relatorio.");
    }
    if (reboot) {
        g_log.Warn(L"Reinicie o Windows para concluir ajustes de SMB/TLS/RDP/dependencias.");
    }
    if (!backupDir.empty()) g_log.Info(L"Backup: " + backupDir);
    g_log.Info(L"Log: " + g_log.LogPath());

    ServerPaths paths = GetServerPaths(g_cfg);
    if (!FileExists(JoinPath(paths.server, L"FXServer.exe"))) {
        g_log.Warn(L"FXServer.exe ainda nao esta presente. Use --download-server ou copie "
                   L"os artefatos para " + paths.server + L".");
    }
    std::wstring serverCfgText;
    if (FileExists(JoinPath(paths.data, L"server.cfg")) &&
        ReadTextFile(JoinPath(paths.data, L"server.cfg"), serverCfgText) &&
        ContainsI(serverCfgText, L"COLE_SUA_CHAVE")) {
        g_log.Warn(L"Configure a chave de licenca em " +
                   JoinPath(paths.data, L"server.cfg") + L" antes de iniciar o servidor.");
    }
    return failures == 0 ? 0 : 2;
}

// ------------------------------------------------------------------ menu
void OpenFolder(const std::wstring& path) {
    if (!DirExists(path)) {
        g_log.Warn(L"Pasta nao encontrada: " + path);
        return;
    }
    ShellExecuteW(nullptr, L"open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

void InteractiveMenu() {
    for (;;) {
        g_log.Section(L"Menu principal");
        g_log.Plain(L"  1 - Diagnostico completo");
        g_log.Plain(L"  2 - Aplicar ajustes (cria backup)");
        g_log.Plain(L"  3 - Preparar servidor FiveM");
        g_log.Plain(L"  4 - Verificar pos-ajustes");
        g_log.Plain(L"  5 - Restaurar backup (rollback)");
        g_log.Plain(L"  6 - Abrir pasta de logs");
        g_log.Plain(L"  7 - Reiniciar como administrador");
        g_log.Plain(L"  0 - Sair");
        std::wstring choice = Trim(g_log.Ask(L"Escolha uma opcao: "));

        if (choice == L"0") {
            g_log.Pause(L"Pressione Enter para sair...");
            return;
        } else if (choice == L"1") {
            Report report;
            RunDiagnostics(report, false);
            SaveReport(report);
        } else if (choice == L"2") {
            if (!IsUserAdmin() && !g_opt.dryRun) {
                g_log.Warn(L"Sem privilegios de administrador. Use a opcao 7 primeiro.");
            } else {
                ApplyAll(g_opt);
            }
        } else if (choice == L"3") {
            if (!IsUserAdmin() && !g_opt.dryRun) {
                g_log.Warn(L"Sem privilegios de administrador. Use a opcao 7 primeiro.");
            } else {
                std::wstring error;
                if (!SetupFiveMServer(g_cfg, g_opt.downloadServer, error)) {
                    g_log.Error(L"Falha ao preparar o servidor: " + error);
                }
            }
        } else if (choice == L"4") {
            Report report;
            RunDiagnostics(report, true);
            SaveReport(report);
        } else if (choice == L"5") {
            if (!IsUserAdmin() && !g_opt.dryRun) {
                g_log.Warn(L"Sem privilegios de administrador. Use a opcao 7 primeiro.");
            } else {
                Rollback(g_opt);
            }
        } else if (choice == L"6") {
            OpenFolder(JoinPath(ExeDir(), L"logs"));
        } else if (choice == L"7") {
            if (IsUserAdmin()) {
                g_log.Ok(L"O processo ja esta elevado.");
                continue;
            }
            g_log.Info(L"Reiniciando o FiveMGuard como administrador...");
            int code = 0;
            if (!ElevateSelf(g_argc, g_argv, code)) {
                g_log.Warn(L"Nao foi possivel reiniciar como administrador.");
            } else {
                g_log.Info(L"Processo elevado finalizado com codigo " + IntToW(code) + L".");
                g_log.Pause(L"Pressione Enter para fechar...");
                return;
            }
        } else {
            g_log.Warn(L"Opcao invalida.");
        }
        if (choice != L"0") g_log.Pause();
    }
}

} // namespace

// ------------------------------------------------------------------ main
int wmain(int argc, wchar_t** argv) {
    SetConsoleTitleW(kAppTitle);

    Options opt;
    std::wstring parseError;
    if (!ParseArgs(argc, argv, opt, parseError)) {
        fwprintf(stderr, L"Erro: %ls\n", parseError.c_str());
        PrintUsage();
        return 1;
    }
    g_opt = opt;
    g_argc = argc;
    g_argv = argv;

    if (opt.help) {
        PrintUsage();
        return 0;
    }
    if (opt.version) {
        wprintf(L"FiveMGuard %ls\n", kAppVersion);
        return 0;
    }

    g_log.Init(ExeDir(), opt.noColor, opt.verbose);
    g_log.SetDryRun(opt.dryRun);
    g_log.Banner();

    std::wstring configPath;
    std::wstring configError;
    if (!LoadConfigFile(opt, configPath, configError)) {
        g_log.Warn(configError);
        g_log.Warn(L"Usando valores padrao em memoria. O arquivo config.ini pode nao ser gravavel.");
    } else {
        g_log.Info(L"Configuracao: " + configPath);
    }
    if (opt.dryRun) {
        g_log.Warn(L"Modo simulacao ativo: nenhuma alteracao real sera feita.");
    }

    if (NeedsAdmin(opt) && !IsUserAdmin()) {
        if (opt.noElevate) {
            g_log.Warn(L"--no-elevate informado sem privilegios de administrador. "
                       L"A acao provavelmente falhara.");
        } else {
            g_log.Warn(L"Privilegios de administrador necessarios. Solicitando elevacao...");
            int code = 0;
            bool elevated = ElevateSelf(argc, argv, code);
            g_log.Close();
            return elevated ? code : 5;
        }
    }

    if (opt.interactive && !IsUserAdmin()) {
        g_log.Warn(L"Menu sem privilegios: use a opcao 7 para reiniciar como administrador.");
    }

    int rc = 0;
    bool ran = false;

    if (opt.report) {
        Report report;
        RunDiagnostics(report, false);
        SaveReport(report);
        ran = true;
    }
    if (opt.apply) {
        int result = ApplyAll(opt);
        if (result != 0) rc = result;
        ran = true;
    }
    if (opt.setupServer && !opt.apply) {
        std::wstring error;
        if (!SetupFiveMServer(g_cfg, opt.downloadServer, error)) {
            g_log.Error(L"Falha ao preparar o servidor: " + error);
            rc = 2;
        }
        ran = true;
    }
    if (opt.verify && !opt.apply) {
        Report report;
        RunDiagnostics(report, true);
        SaveReport(report);
        ran = true;
    }
    if (opt.rollback) {
        int result = Rollback(opt);
        if (result != 0) rc = result;
        ran = true;
    }
    if (!ran) {
        InteractiveMenu();
    }

    g_log.Close();
    return rc;
}
