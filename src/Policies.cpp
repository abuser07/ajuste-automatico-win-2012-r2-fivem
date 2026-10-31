// FiveMGuard - politicas de navegador, endurecimento e firewall
#include "Policies.h"

#include "SystemInfo.h"

#include <windows.h>
#include <lm.h>
#include <netfw.h>

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

namespace fg {

static std::wstring HexDword(DWORD value) {
    wchar_t buffer[32];
    swprintf(buffer, 32, L"0x%08lX", (unsigned long)value);
    return buffer;
}

// ------------------------------------------------------------------ diario
static std::wstring g_journalPath;
static bool g_journalWarned = false;

void SetPolicyJournal(const std::wstring& path) {
    g_journalPath = path;
    g_journalWarned = false;
    if (!g_journalPath.empty()) RemoveFile(g_journalPath);
}

void ClearPolicyJournal() {
    g_journalPath.clear();
}

static std::wstring EscapeJournal(const std::wstring& value) {
    std::wstring out;
    out.reserve(value.size());
    for (wchar_t c : value) {
        switch (c) {
            case L'\\': out += L"\\\\"; break;
            case L'\t': out += L"\\t"; break;
            case L'\r': out += L"\\r"; break;
            case L'\n': out += L"\\n"; break;
            default: out.push_back(c); break;
        }
    }
    return out;
}

static bool AppendJournalLine(const std::wstring& line) {
    if (g_journalPath.empty() || g_log.DryRun()) return true;
    if (!EnsureParentDir(g_journalPath)) return false;
    HANDLE h = CreateFileW(g_journalPath.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    std::string bytes = WideToUtf8(line + L"\r\n");
    DWORD written = 0;
    BOOL ok = WriteFile(h, bytes.data(), (DWORD)bytes.size(), &written, nullptr);
    CloseHandle(h);
    if (!ok || written != bytes.size()) return false;
    return true;
}

static void JournalValue(wchar_t kind, HKEY root, const std::wstring& subkey,
                         const std::wstring& name, bool existed, const std::wstring& value) {
    if (g_journalPath.empty() || g_log.DryRun()) return;
    std::wstring line = std::wstring(1, kind) + L"\t" + RegRootName(root) + L"\t" +
                        EscapeJournal(subkey) + L"\t" + EscapeJournal(name) + L"\t" +
                        (existed ? L"1" : L"0") + L"\t" + EscapeJournal(value);
    if (!AppendJournalLine(line) && !g_journalWarned) {
        g_journalWarned = true;
        g_log.Warn(L"Nao foi possivel gravar o diario de rollback em " + g_journalPath);
    }
}

class RegWriter {
public:
    explicit RegWriter(std::wstring& error) : error_(error) {}

    bool Dword(HKEY root, const std::wstring& subkey, const std::wstring& name,
               DWORD value, const std::wstring& label) {
        DWORD old = 0;
        bool had = RegGetDword(root, subkey, name, old);
        if (had && old == value) {
            g_log.Detail(L"Ja configurado: " + label);
            return true;
        }
        if (g_log.DryRun()) {
            g_log.Step(L"Definiria " + label);
            return true;
        }
        JournalValue(L'D', root, subkey, name, had, had ? HexDword(old) : L"");
        if (!RegSetDword(root, subkey, name, value)) {
            Fail(label);
            return false;
        }
        g_log.Ok(label + (had ? L" (antes: " + HexDword(old) + L")" : L" (criado)"));
        return true;
    }

    bool Str(HKEY root, const std::wstring& subkey, const std::wstring& name,
             const std::wstring& value, const std::wstring& label, DWORD type = REG_SZ) {
        std::wstring old;
        bool had = RegGetString(root, subkey, name, old);
        if (had && old == value) {
            g_log.Detail(L"Ja configurado: " + label);
            return true;
        }
        if (g_log.DryRun()) {
            g_log.Step(L"Definiria " + label);
            return true;
        }
        JournalValue(L'S', root, subkey, name, had, had ? old : L"");
        if (!RegSetString(root, subkey, name, value, type)) {
            Fail(label);
            return false;
        }
        g_log.Ok(label + (had ? L" (antes: " + old + L")" : L" (criado)"));
        return true;
    }

    bool ok() const { return error_.empty(); }

private:
    void Fail(const std::wstring& label) {
        std::wstring text = L"Falha ao gravar registro: " + label;
        g_log.Error(text);
        if (!error_.empty()) error_ += L" ";
        error_ += text + L".";
    }

    std::wstring& error_;
};

static std::wstring AutoHomePage(const Config& cfg, int txAdminPort) {
    std::wstring configured = Trim(cfg.GetString(L"Navegador", L"IEHomePage", L""));
    if (!configured.empty()) return configured;
    return HttpUrlForLocalPort(txAdminPort);
}

static bool ApplyIEPolicies(const Config& cfg, RegWriter& writer, const std::wstring& homePage) {
    bool allOk = true;
    // Politicas de maquina e do usuario atual.
    allOk &= writer.Str(HKEY_LOCAL_MACHINE,
                        L"SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Main",
                        L"Start Page", homePage, L"IE: pagina inicial = " + homePage);
    allOk &= writer.Dword(HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Main",
                          L"DisableFirstRunCustomize", 1, L"IE: ignorar configuracao inicial");
    allOk &= writer.Str(HKEY_CURRENT_USER,
                        L"Software\\Microsoft\\Internet Explorer\\Main",
                        L"Start Page", homePage, L"IE (usuario): pagina inicial");
    allOk &= writer.Dword(HKEY_CURRENT_USER,
                          L"Software\\Microsoft\\Internet Explorer\\Main",
                          L"DisableFirstRunCustomize", 1, L"IE (usuario): ignorar primeira execucao");
    allOk &= writer.Dword(HKEY_CURRENT_USER,
                          L"Software\\Microsoft\\Internet Explorer\\Main",
                          L"RunOnceHasShown", 1, L"IE: RunOnceHasShown=1");
    allOk &= writer.Dword(HKEY_CURRENT_USER,
                          L"Software\\Microsoft\\Internet Explorer\\Main",
                          L"RunOnceComplete", 1, L"IE: RunOnceComplete=1");

    if (cfg.GetBool(L"Navegador", L"SetIETls12", true)) {
        DWORD protocols = cfg.GetDword(L"Navegador", L"IEProtocols", 0xA00);
        if ((protocols & 0x800) == 0) protocols |= 0x800;
        allOk &= writer.Dword(HKEY_CURRENT_USER,
                              L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                              L"SecureProtocols", protocols,
                              L"IE: protocolos seguros = " + HexDword(protocols));
        allOk &= writer.Dword(HKEY_LOCAL_MACHINE,
                              L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                              L"SecureProtocols", protocols,
                              L"IE (maquina): protocolos seguros");
        allOk &= writer.Dword(HKEY_CURRENT_USER,
                              L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                              L"CertificateRevocation", 1,
                              L"IE: verificar revogacao de certificados");
        allOk &= writer.Dword(HKEY_CURRENT_USER,
                              L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                              L"DisableCachingOfSSLPages", 1,
                              L"IE: nao armazenar paginas SSL em cache");
    }

    if (cfg.GetBool(L"Navegador", L"DisableIEESC", true)) {
        const wchar_t* adminGuid = L"{A509B1A7-37EF-4B3F-8CFC-4F3A74704073}";
        const wchar_t* usersGuid = L"{A509B1A8-37EF-4B3F-8CFC-4F3A74704073}";
        const std::wstring base = L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\";
        allOk &= writer.Dword(HKEY_LOCAL_MACHINE, base + adminGuid, L"IsInstalled", 0,
                              L"IE ESC: desativado para administradores (requer logoff)");
        allOk &= writer.Dword(HKEY_LOCAL_MACHINE, base + usersGuid, L"IsInstalled", 0,
                              L"IE ESC: desativado para usuarios (requer logoff)");
    } else {
        g_log.Info(L"DisableIEESC=0: IE Enhanced Security sera mantido ativo.");
    }

    if (cfg.GetBool(L"Navegador", L"AddTrustedSites", true)) {
        std::wstring sites = cfg.GetString(L"Navegador", L"TrustedSites",
                                           L"cfx.re,fivem.net,runtime.fivem.net");
        for (std::wstring site : SplitList(sites)) {
            site = ToLower(Trim(site));
            if (StartsWithI(site, L"https://")) site = site.substr(8);
            if (StartsWithI(site, L"http://")) site = site.substr(7);
            while (!site.empty() && (site.back() == L'/' || site.back() == L' ')) site.pop_back();
            if (site.empty()) continue;
            std::wstring sub = L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\" + site;
            allOk &= writer.Dword(HKEY_CURRENT_USER, sub, L"https", 2,
                                  L"IE: site confiavel " + site);
        }
    }
    return allOk;
}

static bool ApplyChromiumPolicies(const std::wstring& browserName, const std::wstring& policyRoot,
                                  const std::wstring& homePage, RegWriter& writer) {
    bool allOk = true;
    allOk &= writer.Str(HKEY_LOCAL_MACHINE, policyRoot, L"HomepageLocation", homePage,
                        browserName + L": pagina inicial");
    allOk &= writer.Dword(HKEY_LOCAL_MACHINE, policyRoot, L"HomepageIsNewTabPage", 0,
                          browserName + L": homepage nao e nova aba");
    allOk &= writer.Dword(HKEY_LOCAL_MACHINE, policyRoot, L"ShowHomeButton", 1,
                          browserName + L": mostrar botao Home");
    allOk &= writer.Dword(HKEY_LOCAL_MACHINE, policyRoot, L"RestoreOnStartup", 4,
                          browserName + L": abrir pagina inicial ao iniciar");
    allOk &= writer.Str(HKEY_LOCAL_MACHINE, policyRoot + L"\\RestoreOnStartupURLs",
                        L"1", homePage, browserName + L": URL inicial");
    allOk &= writer.Str(HKEY_LOCAL_MACHINE, policyRoot, L"SSLVersionMin", L"tls1.2",
                        browserName + L": TLS minimo 1.2");
    allOk &= writer.Dword(HKEY_LOCAL_MACHINE, policyRoot, L"SafeBrowsingEnabled", 1,
                          browserName + L": navegacao segura ativa");
    allOk &= writer.Dword(HKEY_LOCAL_MACHINE, policyRoot, L"BackgroundModeEnabled", 0,
                          browserName + L": modo segundo plano desativado");
    return allOk;
}

static bool ApplyFirefoxPolicies(const Config& cfg, const std::wstring& homePage,
                                 std::wstring& error) {
    std::wstring firefox = FindFirefoxPath();
    if (firefox.empty()) {
        g_log.Info(L"Firefox nao instalado; politicas do Firefox ignoradas.");
        return true;
    }
    if (!cfg.GetBool(L"Navegador", L"ConfigureFirefox", true)) {
        g_log.Info(L"Firefox detectado; ConfigureFirefox=0, politicas ignoradas.");
        return true;
    }
    std::wstring distribution = JoinPath(ParentDir(firefox), L"distribution");
    std::wstring policyFile = JoinPath(distribution, L"policies.json");
    if (FileExists(policyFile)) {
        g_log.Info(L"Firefox: policies.json existente preservado em " + policyFile);
        return true;
    }
    std::wstring json = L"{\n  \"policies\": {\n    \"Homepage\": {\n      \"URL\": \"" +
                        homePage + L"\",\n      \"StartPage\": \"homepage\"\n    },\n"
                        L"    \"SSLVersionMin\": \"tls1.2\",\n"
                        L"    \"DisableTelemetry\": true,\n"
                        L"    \"OfferToSaveLogins\": false\n  }\n}\n";
    if (g_log.DryRun()) {
        g_log.Step(L"Definiria politica do Firefox em " + policyFile);
        return true;
    }
    if (!EnsureDir(distribution) || !WriteTextFile(policyFile, json, false)) {
        error += L"Nao foi possivel gravar policies.json do Firefox. ";
        g_log.Warn(L"Falha ao gravar politica do Firefox em " + policyFile);
        return false;
    }
    g_log.Ok(L"Firefox: politica criada em " + policyFile);
    return true;
}

bool ApplyBrowserPolicies(const Config& cfg, std::wstring& error) {
    error.clear();
    if (!cfg.GetBool(L"Navegador", L"ConfigureBrowsers", true)) {
        g_log.Info(L"ConfigureBrowsers=0; politicas de navegador nao serao alteradas.");
        return true;
    }
    int txPort = cfg.GetInt(L"Rede", L"TxAdminPort", 40120);
    std::wstring homePage = AutoHomePage(cfg, txPort);
    RegWriter writer(error);
    g_log.Step(L"Aplicando politicas de navegador (IE/Chrome/Edge/Firefox)...");
    ApplyIEPolicies(cfg, writer, homePage);

    if (cfg.GetBool(L"Navegador", L"ConfigureChrome", true)) {
        std::wstring chrome = FindChromePath();
        if (!chrome.empty()) {
            g_log.Info(L"Chrome detectado: " + chrome);
            ApplyChromiumPolicies(L"Chrome", L"SOFTWARE\\Policies\\Google\\Chrome", homePage, writer);
        } else {
            g_log.Info(L"Chrome nao instalado; politicas do Chrome ignoradas.");
        }
    }
    if (cfg.GetBool(L"Navegador", L"ConfigureEdge", true)) {
        std::wstring edge = FindEdgePath();
        if (!edge.empty()) {
            g_log.Info(L"Edge detectado: " + edge);
            ApplyChromiumPolicies(L"Edge", L"SOFTWARE\\Policies\\Microsoft\\Edge", homePage, writer);
        } else {
            g_log.Info(L"Microsoft Edge nao instalado; politicas do Edge ignoradas.");
        }
    }
    ApplyFirefoxPolicies(cfg, homePage, error);
    return writer.ok() && error.empty();
}

static bool DisableGuestAccount(bool dry, std::wstring& error) {
    if (IsDomainController()) {
        g_log.Info(L"Controlador de dominio detectado: conta Guest do dominio nao sera alterada.");
        return true;
    }
    USER_INFO_1* info = nullptr;
    NET_API_STATUS status = NetUserGetInfo(nullptr, L"Guest", 1, (LPBYTE*)&info);
    if (status != NERR_Success || !info) {
        g_log.Warn(L"Nao foi possivel consultar a conta Guest; ignorando.");
        return false;
    }
    bool disabled = (info->usri1_flags & UF_ACCOUNTDISABLE) != 0;
    if (disabled) {
        g_log.Detail(L"Conta Guest ja esta desativada.");
        NetApiBufferFree(info);
        return true;
    }
    if (dry) {
        g_log.Step(L"Desativaria a conta Guest");
        NetApiBufferFree(info);
        return true;
    }
    info->usri1_flags |= UF_ACCOUNTDISABLE;
    DWORD paramError = 0;
    status = NetUserSetInfo(nullptr, L"Guest", 1, (LPBYTE)info, &paramError);
    NetApiBufferFree(info);
    if (status != NERR_Success) {
        std::wstring msg = L"Falha ao desativar Guest (codigo " + IntToW((long long)status) + L").";
        g_log.Warn(msg);
        return false;
    }
    g_log.Ok(L"Conta Guest desativada.");
    return true;
}

static bool ApplyTlsSecurity(const Config& cfg, RegWriter& writer) {
    bool allOk = true;
    const std::wstring protocolsRoot =
        L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\";
    if (cfg.GetBool(L"Seguranca", L"HardenTLS", true)) {
        const wchar_t* sides[] = {L"Server", L"Client"};
        for (const wchar_t* side : sides) {
            std::wstring tls12 = protocolsRoot + L"TLS 1.2\\" + side;
            allOk &= writer.Dword(HKEY_LOCAL_MACHINE, tls12, L"Enabled", 1,
                                  std::wstring(L"TLS 1.2 ") + side + L": habilitado");
            allOk &= writer.Dword(HKEY_LOCAL_MACHINE, tls12, L"DisabledByDefault", 0,
                                  std::wstring(L"TLS 1.2 ") + side + L": nao desabilitado");
            std::wstring ssl3 = protocolsRoot + L"SSL 3.0\\" + side;
            allOk &= writer.Dword(HKEY_LOCAL_MACHINE, ssl3, L"Enabled", 0,
                                  std::wstring(L"SSL 3.0 ") + side + L": desabilitado");
            allOk &= writer.Dword(HKEY_LOCAL_MACHINE, ssl3, L"DisabledByDefault", 1,
                                  std::wstring(L"SSL 3.0 ") + side + L": desabilitado por padrao");
            std::wstring ssl2 = protocolsRoot + L"SSL 2.0\\" + side;
            allOk &= writer.Dword(HKEY_LOCAL_MACHINE, ssl2, L"Enabled", 0,
                                  std::wstring(L"SSL 2.0 ") + side + L": desabilitado");
            allOk &= writer.Dword(HKEY_LOCAL_MACHINE, ssl2, L"DisabledByDefault", 1,
                                  std::wstring(L"SSL 2.0 ") + side + L": desabilitado por padrao");
            if (cfg.GetBool(L"Seguranca", L"DisableLegacyTLS", false)) {
                for (const wchar_t* version : {L"TLS 1.0", L"TLS 1.1"}) {
                    std::wstring path = protocolsRoot + version + L"\\" + side;
                    allOk &= writer.Dword(HKEY_LOCAL_MACHINE, path, L"Enabled", 0,
                                          std::wstring(version) + L" " + side + L": desabilitado");
                    allOk &= writer.Dword(HKEY_LOCAL_MACHINE, path, L"DisabledByDefault", 1,
                                          std::wstring(version) + L" " + side + L": desabilitado por padrao");
                }
            }
        }
        for (const wchar_t* sub : {L"SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319",
                                   L"SOFTWARE\\WOW6432Node\\Microsoft\\.NETFramework\\v4.0.30319"}) {
            allOk &= writer.Dword(HKEY_LOCAL_MACHINE, sub, L"SchUseStrongCrypto", 1,
                                  L".NET: SchUseStrongCrypto=1");
            allOk &= writer.Dword(HKEY_LOCAL_MACHINE, sub, L"SystemDefaultTlsVersions", 1,
                                  L".NET: SystemDefaultTlsVersions=1");
        }
        DWORD winhttpProtocols = cfg.GetBool(L"Seguranca", L"DisableLegacyTLS", false) ? 0x800 : 0xA00;
        for (const wchar_t* sub : {
                 L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\WinHttp",
                 L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\WinHttp"}) {
            allOk &= writer.Dword(HKEY_LOCAL_MACHINE, sub, L"DefaultSecureProtocols", winhttpProtocols,
                                  L"WinHTTP: TLS 1.2 habilitado");
        }
    }
    return allOk;
}

static bool ApplySmbSecurity(const Config& cfg, RegWriter& writer, bool& rebootRequired) {
    bool allOk = true;
    if (!cfg.GetBool(L"Seguranca", L"HardenSMB", true)) {
        g_log.Info(L"HardenSMB=0; SMBv1 e assinatura SMB nao serao alterados.");
        return true;
    }
    const std::wstring serverParams = L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters";
    allOk &= writer.Dword(HKEY_LOCAL_MACHINE, serverParams, L"SMB1", 0,
                          L"SMBv1: desabilitado no servidor");
    allOk &= writer.Dword(HKEY_LOCAL_MACHINE, serverParams, L"RequireSecuritySignature", 1,
                          L"SMB: assinatura obrigatoria no servidor");
    allOk &= writer.Dword(HKEY_LOCAL_MACHINE, serverParams, L"EnableSecuritySignature", 1,
                          L"SMB: assinatura habilitada no servidor");
    allOk &= writer.Dword(HKEY_LOCAL_MACHINE,
                          L"SYSTEM\\CurrentControlSet\\Services\\mrxsmb10", L"Start", 4,
                          L"SMBv1: cliente desabilitado");
    allOk &= writer.Dword(HKEY_LOCAL_MACHINE,
                          L"SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
                          L"EnableSecuritySignature", 1,
                          L"SMB: assinatura habilitada no cliente");
    allOk &= writer.Dword(HKEY_LOCAL_MACHINE,
                          L"SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
                          L"AllowInsecureGuestAuth", 0,
                          L"SMB: acesso guest inseguro bloqueado");
    rebootRequired = true;
    return allOk;
}

static bool ApplyRdpSecurity(const Config& cfg, RegWriter& writer) {
    bool allOk = true;
    if (!IsRdpEnabled()) {
        g_log.Info(L"RDP esta desabilitado neste servidor; ajustes de RDP serao ignorados.");
        return true;
    }
    if (cfg.GetBool(L"Seguranca", L"EnableRdpNLA", true)) {
        allOk &= writer.Dword(HKEY_LOCAL_MACHINE,
                              L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
                              L"UserAuthentication", 1, L"RDP: exigir NLA");
    }
    if (cfg.GetBool(L"Seguranca", L"SetRdpHighEncryption", true)) {
        allOk &= writer.Dword(HKEY_LOCAL_MACHINE,
                              L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
                              L"MinEncryptionLevel", 3, L"RDP: criptografia alta");
    }
    if (cfg.GetBool(L"Seguranca", L"DisableRemoteAssistance", true)) {
        allOk &= writer.Dword(HKEY_LOCAL_MACHINE,
                              L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
                              L"fAllowToGetHelp", 0, L"RDP: Assistencia Remota desativada");
    }
    return allOk;
}

static bool ApplyLsaSecurity(const Config& cfg, RegWriter& writer, std::wstring& error) {
    bool allOk = true;
    const std::wstring lsa = L"SYSTEM\\CurrentControlSet\\Control\\Lsa";
    allOk &= writer.Dword(HKEY_LOCAL_MACHINE, lsa, L"NoLMHash", 1, L"LSA: nao armazenar hash LM");
    if (cfg.GetBool(L"Seguranca", L"HardenNTLM", true) && !IsDomainController()) {
        allOk &= writer.Dword(HKEY_LOCAL_MACHINE, lsa, L"LmCompatibilityLevel", 5,
                              L"LSA: somente NTLMv2 (nivel 5)");
        allOk &= writer.Dword(HKEY_LOCAL_MACHINE, lsa, L"RestrictAnonymous", 1,
                              L"LSA: restringir sessao anonima");
        allOk &= writer.Dword(HKEY_LOCAL_MACHINE, lsa, L"RestrictAnonymousSAM", 1,
                              L"LSA: restringir enumeracao anonima");
    } else if (IsDomainController()) {
        g_log.Info(L"Controlador de dominio: LmCompatibilityLevel/RestrictAnonymous nao alterados.");
    }
    if (cfg.GetBool(L"Seguranca", L"DisableGuestAccount", true)) {
        DisableGuestAccount(g_log.DryRun(), error);
    }
    return allOk;
}

static bool ApplyExplorerSecurity(const Config& cfg, RegWriter& writer) {
    bool allOk = true;
    if (!cfg.GetBool(L"Seguranca", L"DisableAutorun", true)) return true;
    for (HKEY root : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER}) {
        allOk &= writer.Dword(root, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                              L"NoDriveTypeAutoRun", 0xFF, L"Explorer: AutoRun desativado");
        allOk &= writer.Dword(root, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                              L"NoAutorun", 1, L"Explorer: NoAutorun=1");
    }
    return allOk;
}

static bool ApplyDefenderExclusions(const Config& cfg, RegWriter& writer) {
    if (!cfg.GetBool(L"Seguranca", L"ConfigureDefenderExclusions", true)) return true;
    ServiceInfo defender;
    if (!GetServiceInfo(L"WinDefend", defender) || !defender.exists) {
        g_log.Info(L"Windows Defender nao instalado; exclusoes ignoradas.");
        return true;
    }
    bool allOk = true;
    std::wstring serverRoot = cfg.GetPath(L"Servidor", L"ServerRoot", L"C:\\FXServer");
    std::wstring deps = cfg.GetPath(L"Dependencias", L"DepsDir", L"deps");
    std::vector<std::wstring> paths = {
        serverRoot,
        JoinPath(serverRoot, L"server"),
        JoinPath(serverRoot, L"server-data"),
        deps,
    };
    for (const auto& path : paths) {
        allOk &= writer.Dword(HKEY_LOCAL_MACHINE,
                              L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths",
                              path, 0, L"Defender: exclusao de " + path);
    }
    allOk &= writer.Dword(HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes",
                          L"FXServer.exe", 0, L"Defender: exclusao do processo FXServer.exe");
    return allOk;
}

bool EnsureFirewallServices(std::wstring& error) {
    error.clear();
    for (const wchar_t* service : {L"BFE", L"MpsSvc"}) {
        ServiceInfo info;
        if (!GetServiceInfo(service, info)) {
            g_log.Warn(std::wstring(L"Servico de firewall ausente: ") + service);
            continue;
        }
        if (info.running) continue;
        if (g_log.DryRun()) {
            g_log.Step(std::wstring(L"Iniciaria o servico de firewall: ") + service);
            continue;
        }
        std::wstring startError;
        if (!StartServiceByName(service, startError)) {
            error += startError + L" ";
            g_log.Warn(L"Nao foi possivel iniciar " + std::wstring(service) + L": " + startError);
        } else {
            g_log.Ok(std::wstring(L"Servico iniciado: ") + service);
        }
    }
    return error.empty();
}

struct RuleSpec {
    std::wstring name;
    std::wstring description;
    bool tcp = true;
    std::wstring ports;
    long profiles = 7;
    std::wstring remote = L"*";
};

static bool NormalizePorts(const std::wstring& value) {
    if (value.empty()) return false;
    for (wchar_t c : value) {
        if (!(iswdigit(c) || c == L',' || c == L'-' || c == L' ')) return false;
    }
    return true;
}

static bool AddOrUpdateRule(Firewall& fw, const RuleSpec& spec, std::wstring& error) {
    FwRuleInfo existing;
    std::wstring getError;
    if (!fw.GetRule(spec.name, existing, getError)) {
        error += L"Falha ao consultar regra " + spec.name + L": " + getError + L" ";
        g_log.Warn(L"Falha ao consultar regra: " + spec.name);
        return false;
    }
    if (existing.exists) {
        bool same = existing.enabled && existing.action == NET_FW_ACTION_ALLOW &&
                    existing.protocol == (spec.tcp ? NET_FW_IP_PROTOCOL_TCP : NET_FW_IP_PROTOCOL_UDP) &&
                    existing.profiles == spec.profiles &&
                    Trim(existing.localPorts) == spec.ports &&
                    ToLower(Trim(existing.remoteAddresses)) == ToLower(Trim(spec.remote));
        if (same) {
            g_log.Detail(L"Regra ja correta: " + spec.name);
            return true;
        }
        g_log.Warn(L"Regra existente sera recriada com as configuracoes atuais: " + spec.name);
    }
    if (g_log.DryRun()) {
        g_log.Step(L"Criaria regra: " + spec.name + L" (" + (spec.tcp ? L"TCP" : L"UDP") +
                   L" " + spec.ports + L", perfis: " + Firewall::ProfilesToString(spec.profiles) +
                   L", remoto: " + spec.remote + L")");
        return true;
    }
    std::wstring addError;
    if (!fw.AddRule(spec.name, spec.description, spec.tcp, spec.ports, spec.profiles,
                    spec.remote, addError)) {
        error += addError + L" ";
        g_log.Error(L"Falha ao criar regra de firewall: " + spec.name);
        return false;
    }
    g_log.Ok(L"Regra de firewall criada: " + spec.name + L" (" +
             (spec.tcp ? L"TCP" : L"UDP") + L" " + spec.ports + L", " +
             Firewall::ProfilesToString(spec.profiles) + L")");
    return true;
}

bool ApplyFirewallRules(const Config& cfg, Firewall& fw, std::vector<std::wstring>& ruleNames,
                        std::wstring& error) {
    error.clear();
    int gamePort = cfg.GetInt(L"Rede", L"GamePort", 30120);
    if (!IsValidPort(gamePort)) {
        error = L"GamePort invalida: " + IntToW(gamePort);
        g_log.Error(error);
        return false;
    }
    long gameProfiles = Firewall::ProfilesFromString(
        cfg.GetString(L"Rede", L"FirewallProfiles", L"domain,private,public"), 7);
    std::wstring remote = Trim(cfg.GetString(L"Rede", L"RemoteAddresses", L"*"));
    if (remote.empty()) remote = L"*";

    std::vector<RuleSpec> specs;
    specs.push_back({L"FiveMGuard - FiveM Game TCP " + IntToW(gamePort),
                     L"FiveM: porta principal TCP " + IntToW(gamePort),
                     true, IntToW(gamePort), gameProfiles, remote});
    specs.push_back({L"FiveMGuard - FiveM Game UDP " + IntToW(gamePort),
                     L"FiveM: porta principal UDP " + IntToW(gamePort),
                     false, IntToW(gamePort), gameProfiles, remote});

    if (cfg.GetBool(L"Rede", L"OpenTxAdminPort", true)) {
        int txPort = cfg.GetInt(L"Rede", L"TxAdminPort", 40120);
        if (IsValidPort(txPort)) {
            long txProfiles = Firewall::ProfilesFromString(
                cfg.GetString(L"Rede", L"TxAdminProfiles", L"domain,private"), 3);
            std::wstring txRemote = Trim(cfg.GetString(L"Rede", L"TxAdminRemoteAddresses", L"LocalSubnet"));
            if (txRemote.empty()) txRemote = L"LocalSubnet";
            specs.push_back({L"FiveMGuard - txAdmin TCP " + IntToW(txPort),
                             L"FiveM: painel txAdmin (restrito por padrao)",
                             true, IntToW(txPort), txProfiles, txRemote});
        } else {
            g_log.Warn(L"TxAdminPort invalida; regra do txAdmin ignorada.");
        }
    }

    std::wstring extraTcp = Trim(cfg.GetString(L"Rede", L"ExtraTcpPorts", L""));
    if (!extraTcp.empty()) {
        if (NormalizePorts(extraTcp)) {
            specs.push_back({L"FiveMGuard - Extra TCP",
                             L"FiveM: portas TCP extras", true, extraTcp, gameProfiles, remote});
        } else {
            g_log.Warn(L"ExtraTcpPorts contem caracteres invalidos; ignorado.");
        }
    }
    std::wstring extraUdp = Trim(cfg.GetString(L"Rede", L"ExtraUdpPorts", L""));
    if (!extraUdp.empty()) {
        if (NormalizePorts(extraUdp)) {
            specs.push_back({L"FiveMGuard - Extra UDP",
                             L"FiveM: portas UDP extras", false, extraUdp, gameProfiles, remote});
        } else {
            g_log.Warn(L"ExtraUdpPorts contem caracteres invalidos; ignorado.");
        }
    }

    bool ensureFirewall = cfg.GetBool(L"Rede", L"EnsureFirewallEnabled", false);
    if (ensureFirewall && IsRdpEnabled()) {
        std::wstring rdpRemote = Trim(cfg.GetString(L"Rede", L"RdpRemoteAddresses", L"*"));
        if (rdpRemote.empty()) rdpRemote = L"*";
        specs.push_back({L"FiveMGuard - RDP TCP 3389",
                         L"RDP: regra de seguranca criada antes de ligar o firewall",
                         true, L"3389", gameProfiles, rdpRemote});
    }

    for (const auto& spec : specs) {
        if (!AddOrUpdateRule(fw, spec, error)) {
            // continua para tentar as demais regras
        }
        ruleNames.push_back(spec.name);
    }

    if (ensureFirewall) {
        for (int profile : {NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC}) {
            long bit = (profile == NET_FW_PROFILE2_DOMAIN) ? 1 : (profile == NET_FW_PROFILE2_PRIVATE ? 2 : 4);
            if ((gameProfiles & bit) == 0) continue;
            FwProfileInfo info;
            std::wstring profileError;
            if (!fw.GetProfileInfo(profile, info, profileError)) {
                g_log.Warn(L"Nao foi possivel consultar o perfil de firewall: " + profileError);
                continue;
            }
            if (info.enabled) continue;
            if (g_log.DryRun()) {
                g_log.Step(L"Ligaria o firewall no perfil " + IntToW(profile));
                continue;
            }
            if (!fw.SetProfileEnabled(profile, true, profileError)) {
                error += profileError + L" ";
                g_log.Error(L"Falha ao ligar o firewall no perfil " + IntToW(profile));
            } else {
                g_log.Ok(L"Firewall ligado no perfil " + IntToW(profile));
            }
        }
    } else {
        g_log.Info(L"EnsureFirewallEnabled=0: estado ligado/desligado do firewall preservado.");
    }
    return error.empty();
}

static bool ApplyPowerPlan(const Config& cfg) {
    if (!cfg.GetBool(L"Seguranca", L"SetHighPerformance", true)) {
        g_log.Info(L"SetHighPerformance=0: plano de energia preservado.");
        return true;
    }
    const wchar_t* highPerformanceGuid = L"8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c";
    std::wstring powercfg = JoinPath(GetEnvVar(L"SystemRoot"), L"System32\\powercfg.exe");
    if (!FileExists(powercfg)) {
        g_log.Warn(L"powercfg.exe nao encontrado; plano de energia nao alterado.");
        return false;
    }
    if (g_log.DryRun()) {
        g_log.Step(L"Ativaria o plano de energia Alto Desempenho");
        return true;
    }
    ProcessResult query;
    if (RunProcess(QuoteArg(powercfg) + L" /getactivescheme", ExeDir(), 30 * 1000, query) &&
        query.exitCode == 0 && ContainsI(query.output, highPerformanceGuid)) {
        g_log.Detail(L"Plano de energia Alto Desempenho ja esta ativo.");
        return true;
    }
    ProcessResult result;
    if (!RunProcess(QuoteArg(powercfg) + L" /setactive SCHEME_MIN", ExeDir(), 30 * 1000, result) ||
        result.exitCode != 0) {
        g_log.Warn(L"Nao foi possivel ativar o plano de energia Alto Desempenho.");
        return false;
    }
    g_log.Ok(L"Plano de energia definido como Alto Desempenho.");
    return true;
}

bool ApplySecurityHardening(const Config& cfg, std::wstring& error, bool& rebootRequired) {
    error.clear();
    rebootRequired = false;
    RegWriter writer(error);
    g_log.Step(L"Aplicando ajustes de seguranca (TLS, SMB, RDP, LSA e politicas locais)...");

    bool allOk = true;
    allOk &= ApplyTlsSecurity(cfg, writer);
    if (cfg.GetBool(L"Seguranca", L"HardenTLS", true)) rebootRequired = true;

    allOk &= ApplySmbSecurity(cfg, writer, rebootRequired);
    allOk &= ApplyRdpSecurity(cfg, writer);
    allOk &= ApplyLsaSecurity(cfg, writer, error);
    allOk &= ApplyExplorerSecurity(cfg, writer);
    allOk &= ApplyDefenderExclusions(cfg, writer);

    if (cfg.GetBool(L"Seguranca", L"HideLastUserName", true)) {
        allOk &= writer.Dword(HKEY_LOCAL_MACHINE,
                              L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                              L"DontDisplayLastUserName", 1,
                              L"Logon: nao exibir o ultimo usuario");
    }
    if (cfg.GetBool(L"Seguranca", L"EnablePowerShellScriptBlockLogging", false)) {
        allOk &= writer.Dword(HKEY_LOCAL_MACHINE,
                              L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
                              L"EnableScriptBlockLogging", 1,
                              L"PowerShell: log de blocos de script habilitado");
    }

    allOk &= ApplyPowerPlan(cfg);
    return allOk && writer.ok() && error.empty();
}

} // namespace fg
