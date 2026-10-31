// FiveMGuard - dependencias, downloads e extracao de artefatos
#include "Dependencies.h"

#include <windows.h>
#include <wincrypt.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cwctype>
#include <string>
#include <vector>

namespace fg {

// ------------------------------------------------------------------ ambiente
class ScopedEnv {
public:
    ScopedEnv(const wchar_t* name, const std::wstring& value) : name_(name) {
        DWORD needed = GetEnvironmentVariableW(name, nullptr, 0);
        if (needed > 0) {
            std::vector<wchar_t> buffer(needed + 1, L'\0');
            DWORD got = GetEnvironmentVariableW(name, buffer.data(), (DWORD)buffer.size());
            if (got > 0) {
                had_ = true;
                old_.assign(buffer.data(), got);
            }
        }
        SetEnvironmentVariableW(name, value.c_str());
    }
    ~ScopedEnv() {
        SetEnvironmentVariableW(name_, had_ ? old_.c_str() : nullptr);
    }

private:
    const wchar_t* name_;
    bool had_ = false;
    std::wstring old_;
};

// ------------------------------------------------------------------ estado
static std::wstring VCRuntimeText(const VCRuntimeInfo& info, bool x64) {
    std::wstring label = x64 ? L"VC++ x64" : L"VC++ x86";
    if (!info.installed) return label + L": nao instalado";
    return label + L": " + (info.version.empty() ? L"instalado" : info.version);
}

static bool VCRuntimeCurrent(const VCRuntimeInfo& info) {
    if (!info.installed) return false;
    if (info.major > 14) return true;
    return info.major == 14 && info.minor >= 29;
}

void GetDependencyState(DependencyState& state) {
    state = DependencyState();
    GetVCRuntime(true, state.vcX64);
    GetVCRuntime(false, state.vcX86);
    GetDotNetInfo(state.dotNetRelease, state.dotNetLabel);
}

// ------------------------------------------------------------------ assinatura
static bool GetSignaturePublisher(const std::wstring& path, std::wstring& publisher,
                                  std::wstring& error) {
    publisher.clear();
    error.clear();

    HCERTSTORE store = nullptr;
    HCRYPTMSG message = nullptr;
    DWORD encoding = 0, contentType = 0, formatType = 0;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, &contentType,
                          &formatType, &store, &message, nullptr)) {
        error = L"nao foi possivel ler a assinatura: " + FormatWinError(GetLastError());
        return false;
    }

    bool ok = false;
    DWORD signerSize = 0;
    if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerSize) && signerSize > 0) {
        std::vector<BYTE> buffer(signerSize);
        auto signer = (CMSG_SIGNER_INFO*)buffer.data();
        if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, signer, &signerSize)) {
            CERT_INFO certInfo = {};
            certInfo.Issuer = signer->Issuer;
            certInfo.SerialNumber = signer->SerialNumber;
            PCCERT_CONTEXT cert = CertFindCertificateInStore(
                store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT,
                &certInfo, nullptr);
            if (cert) {
                DWORD len = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr,
                                               nullptr, 0);
                if (len > 1) {
                    std::vector<wchar_t> name(len);
                    if (CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr,
                                           name.data(), len) > 1) {
                        publisher.assign(name.data());
                        ok = true;
                    }
                }
                CertFreeCertificateContext(cert);
            } else {
                error = L"certificado do assinante nao encontrado.";
            }
        }
    } else {
        error = L"assinatura sem informacoes do assinante.";
    }

    if (message) CryptMsgClose(message);
    if (store) CertCloseStore(store, 0);
    if (!ok && error.empty()) error = L"editor da assinatura nao identificado.";
    return ok;
}

static bool VerifyMicrosoftFile(const std::wstring& path, std::wstring& error) {
    error.clear();
    std::wstring signError;
    if (!VerifyAuthenticode(path, signError)) {
        error = L"assinatura Authenticode invalida ou ausente: " + signError;
        return false;
    }
    std::wstring publisher;
    if (!GetSignaturePublisher(path, publisher, signError)) {
        error = L"nao foi possivel identificar o editor: " + signError;
        return false;
    }
    if (!ContainsI(publisher, L"Microsoft")) {
        error = L"editor inesperado: " + publisher + L" (esperado Microsoft).";
        return false;
    }
    g_log.Detail(L"Assinatura valida. Editor: " + publisher);
    return true;
}

// ------------------------------------------------------------------ download
static bool ObtainInstaller(const Config& cfg, const std::wstring& url,
                            const std::wstring& destination, const std::wstring& label,
                            std::wstring& error) {
    bool requireSignature = cfg.GetBool(L"Dependencias", L"RequireSignedDependencies", true);

    if (FileExists(destination) && FileSize(destination) > 128 * 1024) {
        if (!requireSignature) {
            g_log.Info(L"Usando arquivo em cache: " + destination);
            return true;
        }
        std::wstring signError;
        if (VerifyMicrosoftFile(destination, signError)) {
            g_log.Info(L"Usando arquivo em cache assinado: " + destination);
            return true;
        }
        g_log.Warn(L"Arquivo em cache invalido; baixando novamente: " + signError);
        RemoveFile(destination);
    }

    g_log.Step(L"Baixando " + label + L"...");
    if (!DownloadFile(url, destination, error)) {
        error = L"falha ao baixar " + label + L": " + error;
        return false;
    }
    if (!FileExists(destination) || FileSize(destination) < 128 * 1024) {
        error = label + L": download suspeito (arquivo muito pequeno).";
        RemoveFile(destination);
        return false;
    }

    if (requireSignature) {
        std::wstring signError;
        if (!VerifyMicrosoftFile(destination, signError)) {
            error = label + L": " + signError;
            RemoveFile(destination);
            return false;
        }
    } else {
        g_log.Warn(L"RequireSignedDependencies=0: assinatura de " + label + L" nao exigida.");
    }

    g_log.Ok(label + L" baixado (" + FormatBytes(FileSize(destination)) + L").");
    return true;
}

// ------------------------------------------------------------------ VC++ / .NET
static bool InstallerExitOk(DWORD code) {
    return code == 0 || code == 3010 || code == 1641 || code == 1638 || code == 5100;
}

static bool InstallerWantsReboot(DWORD code) {
    return code == 3010 || code == 1641;
}

static void AppendError(std::wstring& error, const std::wstring& text) {
    if (!error.empty()) error += L" ";
    error += text;
}

static std::wstring Tail(const std::wstring& text, size_t maxLen) {
    if (text.size() <= maxLen) return text;
    return text.substr(text.size() - maxLen);
}

static bool InstallVCRedistOne(const Config& cfg, bool x64, bool& rebootRequired,
                               std::wstring& error) {
    VCRuntimeInfo info;
    GetVCRuntime(x64, info);
    std::wstring label = x64 ? L"Microsoft Visual C++ 2015-2022 Redistributable (x64)"
                             : L"Microsoft Visual C++ 2015-2022 Redistributable (x86)";

    if (VCRuntimeCurrent(info)) {
        g_log.Ok(VCRuntimeText(info, x64) + L" - compativel com o FXServer.");
        return true;
    }

    g_log.Warn(VCRuntimeText(info, x64) + L" - necessario instalar a versao 14.29.");
    if (g_log.DryRun()) {
        g_log.Step(L"Instalaria " + label + L" 14.29 silenciosamente.");
        return true;
    }
    if (!IsUserAdmin()) {
        AppendError(error, L"sem privilegios de administrador para instalar " + label + L".");
        g_log.Error(L"Sem privilegios para instalar " + label + L".");
        return false;
    }

    std::wstring url = cfg.GetString(L"Dependencias",
                                     x64 ? L"VCRedistX64Url" : L"VCRedistX86Url",
                                     x64 ? L"https://aka.ms/vs/16/release/vc_redist.x64.exe"
                                         : L"https://aka.ms/vs/16/release/vc_redist.x86.exe");
    std::wstring depsDir = cfg.GetPath(L"Dependencias", L"DepsDir", L"deps");
    if (depsDir.empty()) depsDir = JoinPath(ExeDir(), L"deps");
    if (!EnsureDir(depsDir)) {
        AppendError(error, L"nao foi possivel criar " + depsDir);
        return false;
    }

    std::wstring installer = JoinPath(depsDir, x64 ? L"vc_redist.x64.exe" : L"vc_redist.x86.exe");
    std::wstring downloadError;
    if (!ObtainInstaller(cfg, url, installer, label, downloadError)) {
        AppendError(error, downloadError);
        g_log.Error(downloadError);
        return false;
    }

    std::wstring installLog = JoinPath(depsDir, x64 ? L"vc_redist.x64.log" : L"vc_redist.x86.log");
    RemoveFile(installLog);
    std::wstring command = QuoteArg(installer) + L" /install /quiet /norestart /log " +
                           QuoteArg(installLog);
    g_log.Step(L"Instalando " + label + L" (pode levar alguns minutos)...");

    ProcessResult result;
    if (!RunProcess(command, depsDir, 20 * 60 * 1000, result)) {
        AppendError(error, L"nao foi possivel iniciar o instalador do VC++: " + result.output);
        g_log.Error(L"Falha ao iniciar o instalador do VC++.");
        return false;
    }
    if (result.timedOut) {
        AppendError(error, L"instalacao do VC++ excedeu o tempo limite.");
        g_log.Error(L"Instalacao do VC++ excedeu o tempo limite.");
        return false;
    }
    if (!InstallerExitOk(result.exitCode)) {
        wchar_t code[64];
        swprintf(code, 64, L"%lu", (unsigned long)result.exitCode);
        AppendError(error, L"instalador do VC++ retornou codigo " + std::wstring(code) + L".");
        g_log.Error(L"Instalador do VC++ retornou codigo " + std::wstring(code) + L".");
        if (!result.output.empty()) g_log.Detail(Tail(result.output, 800));
        return false;
    }

    if (InstallerWantsReboot(result.exitCode)) rebootRequired = true;
    VCRuntimeInfo after;
    GetVCRuntime(x64, after);
    if (VCRuntimeCurrent(after)) {
        g_log.Ok(label + L" instalado: " + (after.version.empty() ? L"ok" : after.version));
    } else {
        g_log.Warn(label + L" foi instalado, mas a versao ainda nao aparece no registro. "
                           L"Um reinicio pode ser necessario.");
    }
    return true;
}

static bool InstallDotNet48(const Config& cfg, bool& rebootRequired, std::wstring& error) {
    DWORD release = 0;
    std::wstring label;
    GetDotNetInfo(release, label);
    if (release >= 528040) {
        g_log.Ok(L".NET Framework 4.8 ou superior ja instalado: " + label);
        return true;
    }

    g_log.Warn(L".NET Framework 4.8 nao detectado (" + label + L").");
    if (g_log.DryRun()) {
        g_log.Step(L"Instalaria o .NET Framework 4.8 silenciosamente.");
        return true;
    }
    if (!IsUserAdmin()) {
        AppendError(error, L"sem privilegios de administrador para instalar o .NET Framework 4.8.");
        g_log.Error(L"Sem privilegios para instalar o .NET Framework 4.8.");
        return false;
    }

    std::wstring url = cfg.GetString(L"Dependencias", L"DotNet48Url",
                                     L"https://go.microsoft.com/fwlink/?linkid=2088631");
    std::wstring depsDir = cfg.GetPath(L"Dependencias", L"DepsDir", L"deps");
    if (depsDir.empty()) depsDir = JoinPath(ExeDir(), L"deps");
    if (!EnsureDir(depsDir)) {
        AppendError(error, L"nao foi possivel criar " + depsDir);
        return false;
    }

    std::wstring installer = JoinPath(depsDir, L"ndp48-x86-x64-allos-enu.exe");
    std::wstring downloadError;
    if (!ObtainInstaller(cfg, url, installer, L".NET Framework 4.8", downloadError)) {
        AppendError(error, downloadError);
        g_log.Error(downloadError);
        return false;
    }

    std::wstring installLog = JoinPath(depsDir, L"dotnet48-install.log");
    RemoveFile(installLog);
    std::wstring command = QuoteArg(installer) + L" /quiet /norestart /log " + QuoteArg(installLog);
    g_log.Step(L"Instalando .NET Framework 4.8 (pode levar varios minutos)...");

    ProcessResult result;
    if (!RunProcess(command, depsDir, 30 * 60 * 1000, result)) {
        AppendError(error, L"nao foi possivel iniciar o instalador do .NET: " + result.output);
        g_log.Error(L"Falha ao iniciar o instalador do .NET.");
        return false;
    }
    if (result.timedOut) {
        AppendError(error, L"instalacao do .NET excedeu o tempo limite.");
        g_log.Error(L"Instalacao do .NET excedeu o tempo limite.");
        return false;
    }
    if (!InstallerExitOk(result.exitCode)) {
        wchar_t code[64];
        swprintf(code, 64, L"%lu", (unsigned long)result.exitCode);
        AppendError(error, L"instalador do .NET retornou codigo " + std::wstring(code) + L".");
        g_log.Error(L"Instalador do .NET retornou codigo " + std::wstring(code) + L".");
        if (!result.output.empty()) g_log.Detail(Tail(result.output, 800));
        return false;
    }

    if (InstallerWantsReboot(result.exitCode)) rebootRequired = true;
    GetDotNetInfo(release, label);
    if (release >= 528040) {
        g_log.Ok(L".NET Framework 4.8 instalado: " + label);
    } else {
        g_log.Warn(L".NET foi instalado, mas a versao ainda nao aparece no registro. "
                   L"Um reinicio pode ser necessario.");
    }
    return true;
}

bool InstallDependencies(const Config& cfg, bool& rebootRequired, std::wstring& error) {
    error.clear();
    rebootRequired = false;
    bool ok = true;

    if (cfg.GetBool(L"Dependencias", L"InstallVCRedist", true)) {
        if (!InstallVCRedistOne(cfg, true, rebootRequired, error)) ok = false;
        if (cfg.GetBool(L"Dependencias", L"InstallVCRedistX86", true)) {
            if (!InstallVCRedistOne(cfg, false, rebootRequired, error)) ok = false;
        }
    } else {
        g_log.Info(L"InstallVCRedist=0: runtime VC++ nao sera instalado.");
    }

    if (cfg.GetBool(L"Dependencias", L"InstallDotNet48", false)) {
        if (!InstallDotNet48(cfg, rebootRequired, error)) ok = false;
    } else {
        g_log.Info(L"InstallDotNet48=0: .NET Framework 4.8 nao sera instalado.");
    }

    if (ok) g_log.Ok(L"Dependencias verificadas/instaladas.");
    return ok;
}

// ------------------------------------------------------------------ extras
bool IsChromeInstalled() { return !FindChromePath().empty(); }

bool IsNodeInstalled() {
    std::wstring path;
    if (RegGetString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Node.js", L"InstallPath", path) &&
        !path.empty()) {
        return FileExists(JoinPath(path, L"node.exe"));
    }
    std::wstring programFiles = GetEnvVar(L"ProgramFiles");
    return FileExists(JoinPath(programFiles, L"nodejs\\node.exe"));
}

bool IsGitInstalled() {
    std::wstring path;
    if (RegGetString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\GitForWindows", L"InstallPath", path) &&
        !path.empty()) {
        return FileExists(JoinPath(path, L"cmd\\git.exe")) ||
               FileExists(JoinPath(path, L"bin\\git.exe"));
    }
    std::wstring programFiles = GetEnvVar(L"ProgramFiles");
    return FileExists(JoinPath(programFiles, L"Git\\cmd\\git.exe"));
}

bool IsSevenZipInstalled() {
    std::wstring path;
    if (RegGetString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\7-Zip", L"Path", path) && !path.empty()) {
        return FileExists(JoinPath(path, L"7z.exe"));
    }
    std::wstring programFiles = GetEnvVar(L"ProgramFiles");
    return FileExists(JoinPath(programFiles, L"7-Zip\\7z.exe"));
}

static bool VerifyAnySignedFile(const std::wstring& path,
                                const std::wstring& expectedPublisher,
                                std::wstring& error) {
    error.clear();
    std::wstring signError;
    if (!VerifyAuthenticode(path, signError)) {
        error = L"assinatura Authenticode invalida ou ausente: " + signError;
        return false;
    }
    if (expectedPublisher.empty()) {
        g_log.Detail(L"Assinatura Authenticode valida (editor nao verificado).");
        return true;
    }
    std::wstring publisher;
    if (!GetSignaturePublisher(path, publisher, signError)) {
        error = L"nao foi possivel identificar o editor: " + signError;
        return false;
    }
    if (!ContainsI(publisher, expectedPublisher)) {
        error = L"editor inesperado: " + publisher + L" (esperado " + expectedPublisher +
                L"). Ajuste a chave correspondente no config.ini.";
        return false;
    }
    g_log.Detail(L"Assinatura valida. Editor: " + publisher);
    return true;
}

static bool ObtainSignedInstaller(const Config& cfg, const std::wstring& url,
                                  const std::wstring& destination,
                                  const std::wstring& label,
                                  const std::wstring& expectedPublisher,
                                  std::wstring& error) {
    bool requireSignature = cfg.GetBool(L"Dependencias", L"RequireSignedDependencies", true);

    if (FileExists(destination) && FileSize(destination) > 128 * 1024) {
        if (!requireSignature) {
            g_log.Info(L"Usando arquivo em cache: " + destination);
            return true;
        }
        std::wstring signError;
        if (VerifyAnySignedFile(destination, expectedPublisher, signError)) {
            g_log.Info(L"Usando arquivo em cache assinado: " + destination);
            return true;
        }
        g_log.Warn(L"Arquivo em cache invalido; baixando novamente: " + signError);
        RemoveFile(destination);
    }

    g_log.Step(L"Baixando " + label + L"...");
    if (!DownloadFile(url, destination, error)) {
        error = L"falha ao baixar " + label + L": " + error;
        return false;
    }
    if (!FileExists(destination) || FileSize(destination) < 128 * 1024) {
        error = label + L": download suspeito (arquivo muito pequeno).";
        RemoveFile(destination);
        return false;
    }

    if (requireSignature) {
        std::wstring signError;
        if (!VerifyAnySignedFile(destination, expectedPublisher, signError)) {
            error = label + L": " + signError;
            RemoveFile(destination);
            return false;
        }
    } else {
        g_log.Warn(L"RequireSignedDependencies=0: assinatura de " + label + L" nao exigida.");
    }

    g_log.Ok(label + L" baixado (" + FormatBytes(FileSize(destination)) + L").");
    return true;
}

struct ExtraTool {
    const wchar_t* enableKey;
    const wchar_t* urlKey;
    const wchar_t* publisherKey;
    const wchar_t* label;
    const wchar_t* fileName;
    const wchar_t* defaultUrl;
    const wchar_t* defaultPublisher;
    const wchar_t* note;
    bool msi;
    bool defaultEnabled;
    const wchar_t* exeArgs;
    bool (*installed)();
};

static bool InstallExtraTool(const Config& cfg, const ExtraTool& tool, bool& rebootRequired,
                             std::wstring& error) {
    if (tool.installed()) {
        g_log.Ok(std::wstring(tool.label) + L" ja instalado.");
        return true;
    }
    g_log.Warn(std::wstring(tool.label) + L" nao detectado.");
    if (tool.note) g_log.Warn(tool.note);

    if (g_log.DryRun()) {
        g_log.Step(std::wstring(L"Baixaria e instalaria ") + tool.label + L".");
        return true;
    }
    if (!IsUserAdmin()) {
        AppendError(error, L"sem privilegios de administrador para instalar " +
                               std::wstring(tool.label) + L".");
        g_log.Error(L"Sem privilegios para instalar " + std::wstring(tool.label) + L".");
        return false;
    }

    std::wstring url = cfg.GetString(L"Extras", tool.urlKey, tool.defaultUrl);
    if (url.empty()) {
        AppendError(error, std::wstring(tool.label) + L": URL nao configurada.");
        g_log.Error(std::wstring(tool.label) + L": URL nao configurada.");
        return false;
    }
    if (!StartsWithI(url, L"https://")) {
        AppendError(error, std::wstring(tool.label) + L": URL deve usar HTTPS.");
        g_log.Error(std::wstring(tool.label) + L": URL deve usar HTTPS.");
        return false;
    }

    std::wstring depsDir = cfg.GetPath(L"Dependencias", L"DepsDir", L"deps");
    if (depsDir.empty()) depsDir = JoinPath(ExeDir(), L"deps");
    if (!EnsureDir(depsDir)) {
        AppendError(error, L"nao foi possivel criar " + depsDir);
        return false;
    }

    std::wstring installer = JoinPath(depsDir, tool.fileName);
    std::wstring expectedPublisher = cfg.GetString(L"Extras", tool.publisherKey, tool.defaultPublisher);
    std::wstring downloadError;
    if (!ObtainSignedInstaller(cfg, url, installer, tool.label, expectedPublisher,
                               downloadError)) {
        AppendError(error, downloadError);
        g_log.Error(downloadError);
        return false;
    }

    std::wstring installLog = JoinPath(depsDir, std::wstring(tool.fileName) + L".log");
    RemoveFile(installLog);

    std::wstring command;
    if (tool.msi) {
        std::wstring msiexec = JoinPath(GetEnvVar(L"SystemRoot"), L"System32\\msiexec.exe");
        command = QuoteArg(msiexec) + L" /i " + QuoteArg(installer) +
                  L" /qn /norestart /log " + QuoteArg(installLog);
    } else {
        command = QuoteArg(installer) + L" " + (tool.exeArgs ? tool.exeArgs : L"");
    }
    g_log.Step(L"Instalando " + std::wstring(tool.label) + L" (pode levar alguns minutos)...");

    ProcessResult result;
    if (!RunProcess(command, depsDir, 20 * 60 * 1000, result)) {
        AppendError(error, L"nao foi possivel iniciar o instalador de " +
                               std::wstring(tool.label) + L": " + result.output);
        g_log.Error(L"Falha ao iniciar o instalador de " + std::wstring(tool.label) + L".");
        return false;
    }
    if (result.timedOut) {
        AppendError(error, L"instalacao de " + std::wstring(tool.label) + L" excedeu o tempo limite.");
        g_log.Error(L"Instalacao de " + std::wstring(tool.label) + L" excedeu o tempo limite.");
        return false;
    }
    if (!InstallerExitOk(result.exitCode)) {
        wchar_t code[64];
        swprintf(code, 64, L"%lu", (unsigned long)result.exitCode);
        AppendError(error, L"instalador de " + std::wstring(tool.label) + L" retornou codigo " +
                               std::wstring(code) + L".");
        g_log.Error(L"Instalador de " + std::wstring(tool.label) + L" retornou codigo " +
                    std::wstring(code) + L".");
        if (!result.output.empty()) g_log.Detail(Tail(result.output, 800));
        return false;
    }

    if (InstallerWantsReboot(result.exitCode)) rebootRequired = true;
    if (tool.installed()) {
        g_log.Ok(std::wstring(tool.label) + L" instalado com sucesso.");
    } else {
        g_log.Warn(std::wstring(tool.label) + L" foi instalado, mas ainda nao foi detectado. "
                   L"Um reinicio pode ser necessario.");
    }
    return true;
}

bool InstallExtraTools(const Config& cfg, bool& rebootRequired, std::wstring& error) {
    error.clear();
    rebootRequired = false;

    static const ExtraTool tools[] = {
        {L"InstallChrome", L"ChromeUrl", L"ChromeExpectedPublisher",
         L"Google Chrome", L"chrome-enterprise64.msi",
         L"https://dl.google.com/tag/s/dl/chrome/install/googlechromestandaloneenterprise64.msi",
         L"Google LLC",
         L"AVISO: o Chrome 109 foi a ultima versao compativel com o Server 2012 R2. "
         L"Se a instalacao falhar, aponte ChromeUrl para um MSI Enterprise 109 (assinado por Google LLC).",
         true, true, nullptr, IsChromeInstalled},
        {L"InstallNodeJs", L"NodeJsUrl", L"NodeJsExpectedPublisher",
         L"Node.js", L"node-x64.msi",
         L"https://nodejs.org/dist/v18.20.8/node-v18.20.8-x64.msi",
         L"OpenJS Foundation",
         L"Node 18.x e a ultima linha com suporte ao Server 2012 R2.",
         true, true, nullptr, IsNodeInstalled},
        {L"InstallGit", L"GitUrl", L"GitExpectedPublisher",
         L"Git for Windows", L"Git-64-bit.exe",
         L"https://github.com/git-for-windows/git/releases/download/v2.42.0.windows.2/Git-2.42.0.2-64-bit.exe",
         L"",
         L"Verifique a versao do Git compativel com o Server 2012 R2 antes de ativar.",
         false, false, L"/VERYSILENT /NORESTART /NOCANCEL /SP-", IsGitInstalled},
        {L"InstallSevenZip", L"SevenZipUrl", L"SevenZipExpectedPublisher",
         L"7-Zip", L"7z-x64.exe",
         L"https://www.7-zip.org/a/7z2301-x64.exe",
         L"",
         nullptr,
         false, false, L"/S", IsSevenZipInstalled},
    };

    bool ok = true;
    bool any = false;
    for (const auto& tool : tools) {
        if (!cfg.GetBool(L"Extras", tool.enableKey, tool.defaultEnabled)) {
            g_log.Info(std::wstring(tool.enableKey) + L"=0: " + tool.label +
                       L" nao sera instalado.");
            continue;
        }
        any = true;
        if (!InstallExtraTool(cfg, tool, rebootRequired, error)) ok = false;
    }

    if (!any) {
        g_log.Info(L"Nenhuma ferramenta extra habilitada no config.ini.");
    } else if (ok) {
        g_log.Ok(L"Ferramentas extras verificadas/instaladas.");
    }
    return ok;
}

// ------------------------------------------------------------------ JSON
static bool JsonFindString(const std::string& json, const std::string& key, std::string& out) {
    out.clear();
    std::string needle = "\"" + key + "\"";
    size_t pos = 0;
    while ((pos = json.find(needle, pos)) != std::string::npos) {
        size_t i = pos + needle.size();
        while (i < json.size() && std::isspace((unsigned char)json[i])) ++i;
        if (i >= json.size() || json[i] != ':') {
            pos = i;
            continue;
        }
        ++i;
        while (i < json.size() && std::isspace((unsigned char)json[i])) ++i;
        if (i >= json.size() || json[i] != '"') {
            pos = i;
            continue;
        }
        ++i;
        std::string value;
        bool closed = false;
        while (i < json.size()) {
            char c = json[i++];
            if (c == '"') {
                closed = true;
                break;
            }
            if (c == '\\' && i < json.size()) {
                char esc = json[i++];
                switch (esc) {
                    case '"': value.push_back('"'); break;
                    case '\\': value.push_back('\\'); break;
                    case '/': value.push_back('/'); break;
                    case 'b': value.push_back('\b'); break;
                    case 'f': value.push_back('\f'); break;
                    case 'n': value.push_back('\n'); break;
                    case 'r': value.push_back('\r'); break;
                    case 't': value.push_back('\t'); break;
                    case 'u': {
                        if (i + 4 <= json.size()) {
                            unsigned code = 0;
                            bool valid = true;
                            for (int k = 0; k < 4; ++k) {
                                char h = json[i++];
                                code <<= 4;
                                if (h >= '0' && h <= '9') code |= (unsigned)(h - '0');
                                else if (h >= 'a' && h <= 'f') code |= (unsigned)(h - 'a' + 10);
                                else if (h >= 'A' && h <= 'F') code |= (unsigned)(h - 'A' + 10);
                                else { valid = false; break; }
                            }
                            if (valid) {
                                if (code < 0x80) {
                                    value.push_back((char)code);
                                } else if (code < 0x800) {
                                    value.push_back((char)(0xC0 | (code >> 6)));
                                    value.push_back((char)(0x80 | (code & 0x3F)));
                                } else {
                                    value.push_back((char)(0xE0 | (code >> 12)));
                                    value.push_back((char)(0x80 | ((code >> 6) & 0x3F)));
                                    value.push_back((char)(0x80 | (code & 0x3F)));
                                }
                            }
                        }
                        break;
                    }
                    default: value.push_back(esc); break;
                }
            } else {
                value.push_back(c);
            }
        }
        if (closed) {
            out = value;
            return true;
        }
        pos = i;
    }
    return false;
}

bool QueryFiveMServerBuild(const Config& cfg, FiveMServerBuild& build, std::wstring& error) {
    build = FiveMServerBuild();
    error.clear();
    std::wstring url = cfg.GetString(
        L"Servidor", L"ServerArtifactsApi",
        L"https://changelogs-live.fivem.net/api/changelog/versions/win32/server");

    std::string body;
    std::wstring httpError;
    if (!HttpGetString(url, body, httpError)) {
        error = L"falha ao consultar a API de artefatos do FiveM: " + httpError;
        return false;
    }
    if (body.empty()) {
        error = L"a API de artefatos do FiveM retornou uma resposta vazia.";
        return false;
    }

    std::string version, recommended, optional;
    bool hasVersion = JsonFindString(body, "version", version);
    bool hasRecommended = JsonFindString(body, "recommended_download", recommended);
    JsonFindString(body, "optional_download", optional);

    if (!hasVersion || version.empty()) {
        error = L"resposta inesperada da API de artefatos (campo version ausente).";
        return false;
    }
    if (!hasRecommended || recommended.empty()) recommended = optional;
    if (recommended.empty()) {
        error = L"resposta inesperada da API de artefatos (download ausente).";
        return false;
    }

    build.version = Utf8ToWide(version);
    build.recommendedUrl = Utf8ToWide(recommended);
    build.optionalUrl = Utf8ToWide(optional);

    if (!StartsWithI(build.recommendedUrl, L"https://")) {
        error = L"a API retornou uma URL de download sem HTTPS: " + build.recommendedUrl;
        return false;
    }
    if (!ContainsI(build.recommendedUrl, L".zip")) {
        error = L"a API retornou uma URL que nao parece ser um ZIP: " + build.recommendedUrl;
        return false;
    }
    return true;
}

// ------------------------------------------------------------------ arquivos
static std::wstring SanitizeFileName(const std::wstring& value) {
    std::wstring out;
    for (wchar_t c : value) {
        if (iswalnum(c) || c == L'.' || c == L'-' || c == L'_') out.push_back(c);
        else out.push_back(L'_');
    }
    if (out.empty()) out = L"desconhecida";
    return out;
}

static std::wstring FindContentRoot(const std::wstring& staging, const std::wstring& marker) {
    auto hasMarker = [&](const std::wstring& dir) {
        return FileExists(JoinPath(dir, marker)) || DirExists(JoinPath(dir, marker));
    };
    if (hasMarker(staging)) return staging;

    std::wstring pattern = staging;
    if (!pattern.empty() && pattern.back() != L'\\') pattern.push_back(L'\\');
    pattern += L"*";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return staging;

    std::vector<std::wstring> dirs;
    bool hasFiles = false;
    do {
        std::wstring name = fd.cFileName;
        if (name == L"." || name == L"..") continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) dirs.push_back(name);
        else hasFiles = true;
    } while (FindNextFileW(h, &fd));
    FindClose(h);

    for (const auto& dir : dirs) {
        std::wstring child = JoinPath(staging, dir);
        if (hasMarker(child)) return child;
    }
    if (dirs.size() == 1 && !hasFiles) return JoinPath(staging, dirs[0]);
    return staging;
}

static bool MergeDirectory(const std::wstring& source, const std::wstring& dest,
                           bool overwrite, const std::vector<std::wstring>& protect,
                           std::wstring& error) {
    if (!EnsureDir(dest)) {
        AppendError(error, L"nao foi possivel criar " + dest);
        return false;
    }

    std::wstring pattern = source;
    if (!pattern.empty() && pattern.back() != L'\\') pattern.push_back(L'\\');
    pattern += L"*";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err != ERROR_FILE_NOT_FOUND) {
            AppendError(error, L"nao foi possivel listar " + source + L": " + FormatWinError(err));
            return false;
        }
        return true;
    }

    bool ok = true;
    do {
        std::wstring name = fd.cFileName;
        if (name == L"." || name == L"..") continue;

        bool protectedName = false;
        for (const auto& item : protect) {
            if (_wcsicmp(item.c_str(), name.c_str()) == 0) {
                protectedName = true;
                break;
            }
        }
        if (protectedName) {
            g_log.Detail(L"Arquivo preservado: " + JoinPath(dest, name));
            continue;
        }

        std::wstring src = JoinPath(source, name);
        std::wstring dst = JoinPath(dest, name);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (FileExists(dst)) {
                g_log.Warn(L"Conflito: arquivo existente impede a pasta " + dst);
                ok = false;
                continue;
            }
            if (!MergeDirectory(src, dst, overwrite, {}, error)) ok = false;
            continue;
        }

        if (DirExists(dst)) {
            g_log.Warn(L"Conflito: pasta existente impede o arquivo " + dst);
            ok = false;
            continue;
        }
        if (FileExists(dst) && !overwrite) {
            g_log.Detail(L"Arquivo existente mantido: " + dst);
            continue;
        }
        if (!MoveFileExW(src.c_str(), dst.c_str(), MOVEFILE_REPLACE_EXISTING)) {
            DWORD err = GetLastError();
            if (err == ERROR_NOT_SAME_DEVICE || err == ERROR_ACCESS_DENIED) {
                if (!CopyFileSimple(src, dst, overwrite)) {
                    AppendError(error, L"falha ao copiar " + src + L" para " + dst + L": " +
                                          FormatWinError(GetLastError()));
                    ok = false;
                    continue;
                }
                RemoveFile(src);
            } else {
                AppendError(error, L"falha ao mover " + src + L" para " + dst + L": " +
                                      FormatWinError(err));
                ok = false;
            }
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return ok;
}

bool ExtractZipArchive(const std::wstring& zipPath, const std::wstring& destDir,
                       std::wstring& error) {
    error.clear();
    if (!FileExists(zipPath)) {
        error = L"arquivo ZIP nao encontrado: " + zipPath;
        return false;
    }
    if (!EnsureDir(destDir)) {
        error = L"nao foi possivel criar a pasta de extracao: " + destDir;
        return false;
    }

    std::wstring powerShell = JoinPath(GetEnvVar(L"SystemRoot"),
                                       L"System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    if (!FileExists(powerShell)) {
        error = L"PowerShell nao encontrado em " + powerShell;
        return false;
    }

    ScopedEnv zipEnv(L"FIVEMGUARD_ZIP", zipPath);
    ScopedEnv destEnv(L"FIVEMGUARD_DEST", destDir);

    std::wstring script =
        L"$ErrorActionPreference='Stop';"
        L"Add-Type -AssemblyName System.IO.Compression.FileSystem;"
        L"$dest=[IO.Path]::GetFullPath($env:FIVEMGUARD_DEST);"
        L"$sep=[string][IO.Path]::DirectorySeparatorChar;"
        L"$destRoot=$dest;"
        L"if(-not $destRoot.EndsWith($sep)){$destRoot+=$sep};"
        L"$zip=[IO.Compression.ZipFile]::OpenRead([IO.Path]::GetFullPath($env:FIVEMGUARD_ZIP));"
        L"try{foreach($e in $zip.Entries){"
        L"$target=[IO.Path]::GetFullPath([IO.Path]::Combine($dest,$e.FullName));"
        L"if(-not $target.StartsWith($destRoot,[StringComparison]::OrdinalIgnoreCase)){"
        L"throw ('Entrada ZIP insegura: '+$e.FullName)};"
        L"if([string]::IsNullOrEmpty($e.Name)){[IO.Directory]::CreateDirectory($target)|Out-Null}"
        L"else{$parent=[IO.Path]::GetDirectoryName($target);"
        L"if(-not [string]::IsNullOrEmpty($parent)){[IO.Directory]::CreateDirectory($parent)|Out-Null};"
        L"[IO.Compression.ZipFileExtensions]::ExtractToFile($e,$target,$true)}}}"
        L"finally{$zip.Dispose()};"
        L"Write-Output 'ZIP_OK'";

    std::wstring command = QuoteArg(powerShell) +
                           L" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command " +
                           QuoteArg(script);
    ProcessResult result;
    if (!RunProcess(command, destDir, 15 * 60 * 1000, result)) {
        error = L"nao foi possivel iniciar o PowerShell: " + result.output;
        return false;
    }
    if (result.timedOut) {
        error = L"extracao do ZIP excedeu o tempo limite.";
        return false;
    }
    if (result.exitCode != 0) {
        error = L"falha ao extrair " + zipPath + L": " + Tail(result.output, 800);
        return false;
    }
    return true;
}

bool DownloadFiveMServerFiles(const Config& cfg, bool artifacts, bool data,
                              std::wstring& error) {
    error.clear();
    if (!artifacts && !data) return true;

    std::wstring root = cfg.GetPath(L"Servidor", L"ServerRoot", L"C:\\FXServer");
    if (root.empty()) root = L"C:\\FXServer";

    if (g_log.DryRun()) {
        if (artifacts) {
            g_log.Step(L"Consultaria " + cfg.GetString(L"Servidor", L"ServerArtifactsApi",
                                                       L"https://changelogs-live.fivem.net/api/changelog/versions/win32/server") +
                       L" e baixaria os artefatos para " + JoinPath(root, L"server"));
        }
        if (data) {
            g_log.Step(L"Baixaria o cfx-server-data para " + JoinPath(root, L"server-data"));
        }
        return true;
    }

    uint64_t freeBytes = GetDiskFreeBytes(root);
    if (freeBytes > 0 && freeBytes < 2ull * 1024 * 1024 * 1024) {
        error = L"espaco livre insuficiente em " + root + L": " + FormatBytes(freeBytes) +
                L" (minimo recomendado: 2 GB).";
        return false;
    }
    if (!EnsureDir(root)) {
        error = L"nao foi possivel criar a pasta do servidor: " + root;
        return false;
    }
    std::wstring downloads = JoinPath(root, L"downloads");
    if (!EnsureDir(downloads)) {
        error = L"nao foi possivel criar a pasta de downloads: " + downloads;
        return false;
    }

    bool ok = true;
    if (artifacts) {
        FiveMServerBuild build;
        std::wstring buildError;
        if (!QueryFiveMServerBuild(cfg, build, buildError)) {
            AppendError(error, buildError);
            g_log.Error(buildError);
            return false;
        }
        g_log.Info(L"Artefatos do FXServer: versao " + build.version);

        std::wstring archive = JoinPath(downloads,
                                        L"server-" + SanitizeFileName(build.version) + L".zip");
        if (FileExists(archive) && FileSize(archive) > 1024 * 1024) {
            g_log.Info(L"Usando artefatos em cache: " + archive);
        } else {
            g_log.Step(L"Baixando artefatos do FXServer...");
            std::wstring downloadError;
            if (!DownloadFile(build.recommendedUrl, archive, downloadError)) {
                error = L"falha ao baixar os artefatos: " + downloadError;
                return false;
            }
            if (FileSize(archive) < 1024 * 1024) {
                error = L"o ZIP dos artefatos parece invalido (muito pequeno).";
                return false;
            }
            g_log.Ok(L"Artefatos baixados: " + FormatBytes(FileSize(archive)));
        }

        std::wstring staging = JoinPath(root, L".staging-server-" + SanitizeFileName(build.version));
        RemoveDirRecursive(staging);
        if (!EnsureDir(staging)) {
            error = L"nao foi possivel criar a pasta temporaria " + staging;
            return false;
        }
        g_log.Step(L"Extraindo artefatos...");
        if (!ExtractZipArchive(archive, staging, error)) {
            g_log.Error(error);
            return false;
        }
        std::wstring source = FindContentRoot(staging, L"FXServer.exe");
        if (!FileExists(JoinPath(source, L"FXServer.exe"))) {
            error = L"o ZIP dos artefatos nao contem FXServer.exe.";
            return false;
        }
        std::wstring serverDir = JoinPath(root, L"server");
        bool overwrite = cfg.GetBool(L"Servidor", L"OverwriteServerArtifacts", false);
        if (!MergeDirectory(source, serverDir, overwrite,
                            {L"server.cfg", L"server.cfg.example"}, error)) {
            g_log.Error(L"Falha ao instalar os artefatos.");
            ok = false;
        } else {
            g_log.Ok(L"Artefatos instalados em " + serverDir);
        }
        RemoveDirRecursive(staging);
    }

    if (data) {
        std::wstring url = cfg.GetString(
            L"Servidor", L"ServerDataUrl",
            L"https://github.com/citizenfx/cfx-server-data/archive/refs/heads/master.zip");
        if (!StartsWithI(url, L"https://")) {
            error = L"ServerDataUrl deve usar HTTPS: " + url;
            return false;
        }
        std::wstring archive = JoinPath(downloads, L"cfx-server-data.zip");
        if (FileExists(archive) && FileSize(archive) > 256 * 1024) {
            g_log.Info(L"Usando cfx-server-data em cache: " + archive);
        } else {
            g_log.Step(L"Baixando cfx-server-data...");
            std::wstring downloadError;
            if (!DownloadFile(url, archive, downloadError)) {
                error = L"falha ao baixar cfx-server-data: " + downloadError;
                return false;
            }
            g_log.Ok(L"cfx-server-data baixado: " + FormatBytes(FileSize(archive)));
        }

        std::wstring staging = JoinPath(root, L".staging-data");
        RemoveDirRecursive(staging);
        if (!EnsureDir(staging)) {
            error = L"nao foi possivel criar a pasta temporaria " + staging;
            return false;
        }
        g_log.Step(L"Extraindo cfx-server-data...");
        if (!ExtractZipArchive(archive, staging, error)) {
            g_log.Error(error);
            return false;
        }
        std::wstring source = FindContentRoot(staging, L"resources");
        if (!DirExists(JoinPath(source, L"resources"))) {
            error = L"o cfx-server-data nao contem a pasta resources.";
            return false;
        }
        std::wstring dataDir = JoinPath(root, L"server-data");
        bool overwrite = cfg.GetBool(L"Servidor", L"OverwriteServerData", false);
        if (!MergeDirectory(source, dataDir, overwrite, {L"server.cfg"}, error)) {
            g_log.Error(L"Falha ao instalar o cfx-server-data.");
            ok = false;
        } else {
            g_log.Ok(L"cfx-server-data instalado em " + dataDir);
        }
        RemoveDirRecursive(staging);
    }

    return ok;
}

} // namespace fg
