// FiveMGuard - leitura e gravacao do config.ini
#include "Config.h"

#include <algorithm>
#include <cwctype>
#include <sstream>

namespace fg {

Config g_cfg;

const wchar_t* DefaultConfigText() {
    return LR"(; ============================================================================
; FiveMGuard - configuracao
; Windows Server 2012 R2 Datacenter + FiveM (FXServer)
; Edite com Notepad e execute o FiveMGuard.exe como Administrador.
; ============================================================================

[Geral]
; Permite aplicar ajustes em outro Windows (nao recomendado).
AllowUnsupportedOS=0
; Consulta o IP publico na internet durante o diagnostico.
CheckPublicIP=1
; Pede confirmacao antes de aplicar (recomendado).
ConfirmarAntesDeAplicar=1
; Executa uma verificacao completa depois de aplicar.
VerifyAfterApply=1

[Rede]
; Porta principal do FXServer (TCP e UDP).
GamePort=30120
; Cria regra para o painel txAdmin. Por seguranca, so LAN/dominio por padrao.
OpenTxAdminPort=1
TxAdminPort=40120
; Portas extras opcionais, separadas por virgula (ex.: 30110,30130).
ExtraTcpPorts=
ExtraUdpPorts=
; Perfis do firewall para a porta do jogo: domain,private,public ou all.
FirewallProfiles=domain,private,public
; Perfis para o txAdmin. Deixe apenas domain/private para nao expor o painel.
TxAdminProfiles=domain,private
; Enderecos remotos permitidos na porta do jogo. "*" libera a internet.
RemoteAddresses=*
; Restringe o txAdmin a rede local.
TxAdminRemoteAddresses=LocalSubnet
; Liga o firewall se ele estiver desligado. Use 1 somente se tiver certeza de que
; o RDP continuara acessivel (uma regra de RDP e criada automaticamente).
EnsureFirewallEnabled=0
; Endereco remoto permitido na regra de RDP criada quando EnsureFirewallEnabled=1.
RdpRemoteAddresses=*
; Tenta mapear as portas no roteador via UPnP. Normalmente nao e necessario em VPS.
EnableUPnP=0

[Dependencias]
; Runtime exigido pelo FXServer. Instala a versao 14.29 (VS2019), compativel com
; Windows Server 2012 R2. A versao mais nova do runtime nao suporta 2012 R2.
InstallVCRedist=1
InstallVCRedistX86=1
; .NET Framework 4.8 e opcional para o FXServer; ative se usar recursos em C#.
InstallDotNet48=0
; Recusa executar instaladores sem assinatura digital valida.
RequireSignedDependencies=1
VCRedistX64Url=https://aka.ms/vs/16/release/vc_redist.x64.exe
VCRedistX86Url=https://aka.ms/vs/16/release/vc_redist.x86.exe
DotNet48Url=https://go.microsoft.com/fwlink/?linkid=2088631
DepsDir=deps

[Seguranca]
; Habilita TLS 1.2 para Schannel, .NET e WinHTTP.
HardenTLS=1
; Desabilita TLS 1.0/1.1. Pode quebrar aplicativos antigos; avalie antes.
DisableLegacyTLS=0
; Desabilita SMBv1 e exige assinatura SMB no servidor. Requer reinicio.
HardenSMB=1
; Exige Network Level Authentication no RDP.
EnableRdpNLA=1
SetRdpHighEncryption=1
DisableRemoteAssistance=1
DisableGuestAccount=1
HardenNTLM=1
DisableAutorun=1
HideLastUserName=1
; Adiciona exclusoes do Windows Defender para a pasta do servidor.
ConfigureDefenderExclusions=1
; Coloca o plano de energia em Alto Desempenho.
SetHighPerformance=1
; Log de blocos de script do PowerShell (opcional; gera mais logs).
EnablePowerShellScriptBlockLogging=0

[Navegador]
ConfigureBrowsers=1
; Desativar o IE Enhanced Security e uma decisao de usabilidade; 0 = manter seguro.
DisableIEESC=0
SetIETls12=1
; Bitmask do IE: TLS1.1=0x200, TLS1.2=0x800. 0xA00 = TLS1.1 + TLS1.2.
IEProtocols=0xA00
; Deixe vazio para usar http://localhost:<TxAdminPort>/
IEHomePage=
AddTrustedSites=1
TrustedSites=cfx.re,fivem.net,runtime.fivem.net
ConfigureChrome=1
ConfigureEdge=1
ConfigureFirefox=1

[Servidor]
ServerRoot=C:\FXServer
; Nome exibido no server.cfg gerado.
ServerName=FiveM Server
MaxClients=32
PrepareServerFolders=1
CreateServerConfigExample=1
; Cria server.cfg a partir do modelo se ele ainda nao existir.
CreateInitialServerCfg=1
; O menu "Preparar servidor" tambem pode baixar os arquivos sob demanda.
DownloadServerArtifacts=0
DownloadServerData=0
; Sobrescrever arquivos existentes ao baixar/atualizar. 0 = preservar.
OverwriteServerArtifacts=0
OverwriteServerData=0
ServerArtifactsApi=https://changelogs-live.fivem.net/api/changelog/versions/win32/server
ServerDataUrl=https://github.com/citizenfx/cfx-server-data/archive/refs/heads/master.zip
)";
}

static std::wstring Normalize(const std::wstring& s) { return ToLower(Trim(s)); }

bool Config::SaveDefault(const std::wstring& path) const {
    return WriteTextFile(path, DefaultConfigText(), true);
}

bool Config::Load(const std::wstring& path, bool createIfMissing) {
    path_ = path;
    entries_.clear();
    if (!FileExists(path)) {
        if (!createIfMissing) return false;
        if (!SaveDefault(path)) return false;
    }
    std::wstring text;
    if (!ReadTextFile(path, text)) return false;
    if (!text.empty() && text[0] == 0xFEFF) text.erase(0, 1);

    std::wstring section;
    size_t start = 0;
    while (start <= text.size()) {
        size_t end = text.find(L'\n', start);
        std::wstring line = (end == std::wstring::npos) ? text.substr(start) : text.substr(start, end - start);
        start = (end == std::wstring::npos) ? text.size() + 1 : end + 1;
        line = Trim(line);
        if (line.empty() || line[0] == L';' || line[0] == L'#') continue;
        if (line.front() == L'[') {
            size_t close = line.find(L']');
            if (close != std::wstring::npos) section = Normalize(line.substr(1, close - 1));
            continue;
        }
        size_t eq = line.find(L'=');
        if (eq == std::wstring::npos) continue;
        std::wstring key = Normalize(line.substr(0, eq));
        std::wstring value = Trim(line.substr(eq + 1));
        if (value.size() >= 2 && ((value.front() == L'"' && value.back() == L'"') ||
                                  (value.front() == L'\'' && value.back() == L'\''))) {
            value = value.substr(1, value.size() - 2);
        }
        entries_.push_back({section, key, value});
    }
    return true;
}

std::wstring Config::GetString(const std::wstring& section, const std::wstring& key,
                               const std::wstring& defaultValue) const {
    std::wstring sec = Normalize(section);
    std::wstring k = Normalize(key);
    for (auto it = entries_.rbegin(); it != entries_.rend(); ++it) {
        if (it->section == sec && it->key == k) return it->value;
    }
    return defaultValue;
}

int Config::GetInt(const std::wstring& section, const std::wstring& key, int defaultValue) const {
    return ParseInt(GetString(section, key), defaultValue, 10);
}

DWORD Config::GetDword(const std::wstring& section, const std::wstring& key, DWORD defaultValue) const {
    return ParseDword(GetString(section, key), defaultValue);
}

bool Config::GetBool(const std::wstring& section, const std::wstring& key, bool defaultValue) const {
    std::wstring value = GetString(section, key);
    return value.empty() ? defaultValue : ParseBool(value, defaultValue);
}

std::wstring Config::GetPath(const std::wstring& section, const std::wstring& key,
                             const std::wstring& defaultValue) const {
    std::wstring value = GetString(section, key, defaultValue);
    value = ExpandEnv(value);
    return MakeAbsolute(value, ExeDir());
}

} // namespace fg
