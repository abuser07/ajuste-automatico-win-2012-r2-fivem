// FiveMGuard - diagnostico do Windows, rede, runtime e navegadores
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include "SystemInfo.h"

#include <windows.h>
#include <lm.h>
#include <wtsapi32.h>

#include <algorithm>
#include <cstring>
#include <sstream>
#include <vector>

#ifndef MIB_TCP_STATE_LISTEN
#define MIB_TCP_STATE_LISTEN 2
#endif

namespace fg {

static bool ValueExists(HKEY root, const std::wstring& subkey, const std::wstring& name) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
        return false;
    DWORD type = 0, size = 0;
    LONG rc = RegQueryValueExW(key, name.c_str(), nullptr, &type, nullptr, &size);
    RegCloseKey(key);
    return rc == ERROR_SUCCESS;
}

static std::wstring OsArchitecture() {
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: return L"x64";
        case PROCESSOR_ARCHITECTURE_INTEL: return L"x86";
        case PROCESSOR_ARCHITECTURE_ARM64: return L"ARM64";
        default: return L"desconhecida";
    }
}

bool GetOsInfo(OsInfo& info) {
    info = OsInfo();
    std::wstring current = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    RegGetString(HKEY_LOCAL_MACHINE, current, L"ProductName", info.productName);
    RegGetString(HKEY_LOCAL_MACHINE, current, L"EditionID", info.editionId);
    RegGetString(HKEY_LOCAL_MACHINE, current, L"CurrentBuildNumber", info.build);
    RegGetString(HKEY_LOCAL_MACHINE, current, L"CurrentVersion", info.version);

    OSVERSIONINFOW vi = {};
    vi.dwOSVersionInfoSize = sizeof(vi);
    using RtlGetVersionFn = LONG(WINAPI*)(OSVERSIONINFOW*);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        auto fn = (RtlGetVersionFn)GetProcAddress(ntdll, "RtlGetVersion");
        if (fn) fn(&vi);
    }
    info.major = vi.dwMajorVersion;
    info.minor = vi.dwMinorVersion;
    info.buildNumber = vi.dwBuildNumber;
    if (info.build.empty() && info.buildNumber) info.build = IntToW((long long)info.buildNumber);
    info.architecture = OsArchitecture();
    info.productType = WindowsProductType();
    info.isServer = IsWindowsServer();
    info.isDatacenter = ContainsI(info.productName, L"Datacenter") ||
                        _wcsicmp(info.editionId.c_str(), L"ServerDatacenter") == 0;
    info.isTarget2012R2 = info.isServer && info.buildNumber == 9600 &&
                          ContainsI(info.productName, L"2012 R2");
    info.isDomainController = _wcsicmp(info.productType.c_str(), L"LanmanNT") == 0;
    return !info.productName.empty();
}

std::wstring GetComputerNameStr() {
    wchar_t buffer[256] = {};
    DWORD size = 256;
    if (GetComputerNameExW(ComputerNameDnsHostname, buffer, &size)) return buffer;
    size = 256;
    if (GetComputerNameW(buffer, &size)) return buffer;
    return L"desconhecido";
}

std::wstring GetUserNameStr() {
    DWORD size = 0;
    GetUserNameW(nullptr, &size);
    if (size == 0) return L"desconhecido";
    std::vector<wchar_t> buffer(size + 1);
    if (!GetUserNameW(buffer.data(), &size)) return L"desconhecido";
    return buffer.data();
}

std::wstring GetCpuName() {
    std::wstring name;
    if (!RegGetString(HKEY_LOCAL_MACHINE,
                      L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                      L"ProcessorNameString", name) || name.empty()) {
        name = L"CPU desconhecida";
    }
    return Trim(name);
}

int GetCpuCores() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (int)si.dwNumberOfProcessors;
}

uint64_t GetRamTotalMB() {
    MEMORYSTATUSEX ms = {};
    ms.dwLength = sizeof(ms);
    if (!GlobalMemoryStatusEx(&ms)) return 0;
    return ms.ullTotalPhys / (1024ull * 1024ull);
}

uint64_t GetRamAvailableMB() {
    MEMORYSTATUSEX ms = {};
    ms.dwLength = sizeof(ms);
    if (!GlobalMemoryStatusEx(&ms)) return 0;
    return ms.ullAvailPhys / (1024ull * 1024ull);
}

std::wstring GetUptimeText() {
    ULONGLONG ticks = GetTickCount64();
    ULONGLONG totalMinutes = ticks / 60000ULL;
    ULONGLONG days = totalMinutes / (60 * 24);
    ULONGLONG hours = (totalMinutes / 60) % 24;
    ULONGLONG minutes = totalMinutes % 60;
    wchar_t buffer[128];
    swprintf(buffer, 128, L"%llu dia(s), %llu hora(s), %llu minuto(s)",
             (unsigned long long)days, (unsigned long long)hours, (unsigned long long)minutes);
    return buffer;
}

std::wstring GetDriveRoot(const std::wstring& path) {
    if (path.size() >= 2 && path[1] == L':') return path.substr(0, 3);
    if (path.size() >= 2 && path[0] == L'\\' && path[1] == L'\\') return L"C:\\";
    return L"C:\\";
}

uint64_t GetDiskFreeBytes(const std::wstring& path) {
    ULARGE_INTEGER freeBytes = {}, total = {}, totalFree = {};
    if (!GetDiskFreeSpaceExW(GetDriveRoot(path).c_str(), &freeBytes, &total, &totalFree)) return 0;
    return freeBytes.QuadPart;
}

uint64_t GetDiskTotalBytes(const std::wstring& path) {
    ULARGE_INTEGER freeBytes = {}, total = {}, totalFree = {};
    if (!GetDiskFreeSpaceExW(GetDriveRoot(path).c_str(), &freeBytes, &total, &totalFree)) return 0;
    return total.QuadPart;
}

bool GetDotNetInfo(DWORD& release, std::wstring& label) {
    release = 0;
    bool found = RegGetDword(HKEY_LOCAL_MACHINE,
                             L"SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full",
                             L"Release", release);
    if (!found) {
        found = RegGetDword(HKEY_LOCAL_MACHINE,
                            L"SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Client",
                            L"Release", release);
    }
    if (!found) {
        label = L"nao detectado";
        return false;
    }
    if (release >= 533320) label = L"4.8.1 ou superior";
    else if (release >= 528040) label = L"4.8 ou superior";
    else if (release >= 461808) label = L"4.7.2";
    else if (release >= 460798) label = L"4.7";
    else if (release >= 394802) label = L"4.6.2";
    else if (release >= 393295) label = L"4.6";
    else if (release >= 379893) label = L"4.5.2";
    else if (release >= 378675) label = L"4.5.1";
    else if (release >= 378389) label = L"4.5";
    else label = L"4.x";
    label += L" (Release " + IntToW((long long)release) + L")";
    return true;
}

std::wstring GetPowerShellVersion() {
    std::wstring path = JoinPath(GetEnvVar(L"SystemRoot"),
                                 L"System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    std::wstring version = GetFileVersionString(path);
    return version.empty() ? L"nao detectado" : version;
}

static bool ParseVCRuntimeKey(const std::wstring& subkey, VCRuntimeInfo& info) {
    info = VCRuntimeInfo();
    DWORD installed = 0;
    if (!RegGetDword(HKEY_LOCAL_MACHINE, subkey, L"Installed", installed) || installed == 0)
        return false;
    RegGetString(HKEY_LOCAL_MACHINE, subkey, L"Version", info.version);
    std::wstring value = info.version;
    if (!value.empty() && (value[0] == L'v' || value[0] == L'V')) value.erase(0, 1);
    unsigned major = 0, minor = 0, build = 0;
    swscanf(value.c_str(), L"%u.%u.%u", &major, &minor, &build);
    info.major = (int)major;
    info.minor = (int)minor;
    info.build = (int)build;
    info.installed = true;
    return true;
}

bool GetVCRuntime(bool x64, VCRuntimeInfo& info) {
    std::wstring subkey = x64
        ? L"SOFTWARE\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes\\x64"
        : L"SOFTWARE\\WOW6432Node\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes\\x86";
    return ParseVCRuntimeKey(subkey, info);
}

bool IsPendingReboot() {
    if (RegKeyExists(HKEY_LOCAL_MACHINE,
                     L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending"))
        return true;
    if (RegKeyExists(HKEY_LOCAL_MACHINE,
                     L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired"))
        return true;
    if (ValueExists(HKEY_LOCAL_MACHINE,
                    L"SYSTEM\\CurrentControlSet\\Control\\Session Manager",
                    L"PendingFileRenameOperations"))
        return true;
    return false;
}

bool GetServiceInfo(const std::wstring& name, ServiceInfo& info) {
    info = ServiceInfo();
    info.name = name;
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE service = OpenServiceW(scm, name.c_str(), SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (!service) {
        CloseServiceHandle(scm);
        return false;
    }
    info.exists = true;
    SERVICE_STATUS_PROCESS status = {};
    DWORD needed = 0;
    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(status), &needed)) {
        info.state = status.dwCurrentState;
        info.running = status.dwCurrentState == SERVICE_RUNNING;
    }
    DWORD configSize = 0;
    QueryServiceConfigW(service, nullptr, 0, &configSize);
    if (configSize > 0) {
        std::vector<BYTE> buffer(configSize);
        auto config = (LPQUERY_SERVICE_CONFIGW)buffer.data();
        if (QueryServiceConfigW(service, config, configSize, &configSize)) {
            info.startType = config->dwStartType;
        }
    }
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
}

bool StartServiceByName(const std::wstring& name, std::wstring& error) {
    error.clear();
    ServiceInfo info;
    if (!GetServiceInfo(name, info)) {
        error = L"servico nao encontrado: " + name;
        return false;
    }
    if (info.running) return true;
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        error = L"OpenSCManager: " + FormatWinError(GetLastError());
        return false;
    }
    SC_HANDLE service = OpenServiceW(scm, name.c_str(), SERVICE_START | SERVICE_QUERY_STATUS);
    if (!service) {
        error = L"OpenService: " + FormatWinError(GetLastError());
        CloseServiceHandle(scm);
        return false;
    }
    if (!StartServiceW(service, 0, nullptr)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            error = L"StartService: " + FormatWinError(err);
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return false;
        }
    }
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    for (int i = 0; i < 20; ++i) {
        if (GetServiceInfo(name, info) && info.running) return true;
        Sleep(500);
    }
    error = L"servico nao iniciou a tempo: " + name;
    return false;
}

std::wstring GetDefenderSummary() {
    ServiceInfo info;
    if (!GetServiceInfo(L"WinDefend", info) || !info.exists) return L"nao instalado";
    if (!info.running) return L"parado";
    DWORD disabled = 0;
    if (RegGetDword(HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
                    L"DisableRealtimeMonitoring", disabled) && disabled != 0) {
        return L"ativo, tempo real desativado";
    }
    return L"ativo";
}

bool IsDefenderRunning() {
    ServiceInfo info;
    return GetServiceInfo(L"WinDefend", info) && info.exists && info.running;
}

bool GetGuestDisabled(bool& disabled) {
    disabled = false;
    USER_INFO_1* info = nullptr;
    NET_API_STATUS status = NetUserGetInfo(nullptr, L"Guest", 1, (LPBYTE*)&info);
    if (status != NERR_Success || !info) return false;
    disabled = (info->usri1_flags & UF_ACCOUNTDISABLE) != 0;
    NetApiBufferFree(info);
    return true;
}

static std::wstring ProcessNameForPid(DWORD pid) {
    if (pid == 0) return L"System Idle";
    if (pid == 4) return L"System";
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return L"PID " + IntToW((unsigned)pid);
    wchar_t path[1024];
    DWORD size = 1024;
    std::wstring name = L"PID " + IntToW((unsigned)pid);
    if (QueryFullProcessImageNameW(process, 0, path, &size)) {
        name = FileNameOf(path);
    }
    CloseHandle(process);
    return name;
}

static bool TcpTable(std::vector<MIB_TCPROW_OWNER_PID>& rows, std::wstring& error) {
    DWORD size = 0;
    DWORD rc = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER && rc != ERROR_SUCCESS) {
        error = L"GetExtendedTcpTable: " + FormatWinError(rc);
        return false;
    }
    std::vector<BYTE> buffer(size);
    rc = GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc != ERROR_SUCCESS) {
        error = L"GetExtendedTcpTable: " + FormatWinError(rc);
        return false;
    }
    auto table = (PMIB_TCPTABLE_OWNER_PID)buffer.data();
    rows.assign(table->table, table->table + table->dwNumEntries);
    return true;
}

static bool UdpTable(std::vector<MIB_UDPROW_OWNER_PID>& rows, std::wstring& error) {
    DWORD size = 0;
    DWORD rc = GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER && rc != ERROR_SUCCESS) {
        error = L"GetExtendedUdpTable: " + FormatWinError(rc);
        return false;
    }
    std::vector<BYTE> buffer(size);
    rc = GetExtendedUdpTable(buffer.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (rc != ERROR_SUCCESS) {
        error = L"GetExtendedUdpTable: " + FormatWinError(rc);
        return false;
    }
    auto table = (PMIB_UDPTABLE_OWNER_PID)buffer.data();
    rows.assign(table->table, table->table + table->dwNumEntries);
    return true;
}

bool GetPortListener(int port, bool tcp, PortOwner& owner, std::wstring& error) {
    owner = PortOwner();
    owner.port = port;
    owner.tcp = tcp;
    error.clear();
    if (tcp) {
        std::vector<MIB_TCPROW_OWNER_PID> rows;
        if (!TcpTable(rows, error)) return false;
        for (const auto& row : rows) {
            if (row.dwState != MIB_TCP_STATE_LISTEN) continue;
            if ((int)ntohs((u_short)row.dwLocalPort) != port) continue;
            owner.pid = row.dwOwningPid;
            owner.process = ProcessNameForPid(row.dwOwningPid);
            IN_ADDR addr;
            addr.S_un.S_addr = row.dwLocalAddr;
            wchar_t text[64] = {};
            InetNtopW(AF_INET, &addr, text, 64);
            owner.localAddress = text;
            return true;
        }
    } else {
        std::vector<MIB_UDPROW_OWNER_PID> rows;
        if (!UdpTable(rows, error)) return false;
        for (const auto& row : rows) {
            if ((int)ntohs((u_short)row.dwLocalPort) != port) continue;
            owner.pid = row.dwOwningPid;
            owner.process = ProcessNameForPid(row.dwOwningPid);
            IN_ADDR addr;
            addr.S_un.S_addr = row.dwLocalAddr;
            wchar_t text[64] = {};
            InetNtopW(AF_INET, &addr, text, 64);
            owner.localAddress = text;
            return true;
        }
    }
    return false;
}

bool IsPortInUseByOther(int port, bool tcp, const std::wstring& allowedProcess,
                        PortOwner& owner) {
    std::wstring error;
    if (!GetPortListener(port, tcp, owner, error)) return false;
    if (allowedProcess.empty()) return true;
    return _wcsicmp(owner.process.c_str(), allowedProcess.c_str()) != 0;
}

std::vector<std::wstring> GetLocalIPv4List() {
    std::vector<std::wstring> result;
    ULONG size = 16 * 1024;
    std::vector<BYTE> buffer(size);
    ULONG rc = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 4; ++attempt) {
        rc = GetAdaptersAddresses(AF_INET,
                                  GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                      GAA_FLAG_SKIP_DNS_SERVER,
                                  nullptr, (PIP_ADAPTER_ADDRESSES)buffer.data(), &size);
        if (rc != ERROR_BUFFER_OVERFLOW) break;
        buffer.resize(size);
    }
    if (rc != ERROR_SUCCESS) return result;
    auto adapters = (PIP_ADAPTER_ADDRESSES)buffer.data();
    for (auto adapter = adapters; adapter; adapter = adapter->Next) {
        for (auto ua = adapter->FirstUnicastAddress; ua; ua = ua->Next) {
            if (!ua->Address.lpSockaddr || ua->Address.lpSockaddr->sa_family != AF_INET) continue;
            auto sin = (sockaddr_in*)ua->Address.lpSockaddr;
            DWORD addr = ntohl(sin->sin_addr.S_un.S_addr);
            if ((addr >> 24) == 127) continue;
            if ((addr >> 16) == 0xA9FE) continue;
            wchar_t text[64] = {};
            if (!InetNtopW(AF_INET, &sin->sin_addr, text, 64)) continue;
            std::wstring value = text;
            if (std::find(result.begin(), result.end(), value) == result.end()) result.push_back(value);
        }
    }
    return result;
}

std::wstring GetPublicIP() {
    std::string body;
    std::wstring error;
    if (!HttpGetString(L"https://api.ipify.org", body, error)) return std::wstring();
    std::wstring value = Trim(Utf8ToWide(body));
    if (value.empty() || value.size() > 64) return std::wstring();
    for (wchar_t c : value) {
        if (!(iswdigit(c) || c == L'.' || c == L':' || (c >= L'a' && c <= L'f') ||
              (c >= L'A' && c <= L'F'))) {
            return std::wstring();
        }
    }
    return value;
}

std::wstring GetRdpClientIP() {
    PWTS_CLIENT_ADDRESS address = nullptr;
    DWORD bytes = 0;
    std::wstring result;
    if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION,
                                    WTSClientAddress, (LPWSTR*)&address, &bytes) &&
        address) {
        if (address->AddressFamily == AF_INET) {
            IN_ADDR ip;
            memcpy(&ip, address->Address + 2, sizeof(ip));
            wchar_t text[64] = {};
            if (InetNtopW(AF_INET, &ip, text, 64)) result = text;
        }
        WTSFreeMemory(address);
    }
    return result;
}

bool IsRdpEnabled() {
    DWORD deny = 0;
    if (RegGetDword(HKEY_LOCAL_MACHINE,
                    L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
                    L"fDenyTSConnections", deny)) {
        return deny == 0;
    }
    return true;
}

bool GetSmbInfo(SmbInfo& info) {
    info = SmbInfo();
    DWORD value = 0;
    if (RegGetDword(HKEY_LOCAL_MACHINE,
                    L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                    L"SMB1", value)) {
        info.serverDisabled = value == 0;
    }
    if (RegGetDword(HKEY_LOCAL_MACHINE,
                    L"SYSTEM\\CurrentControlSet\\Services\\mrxsmb10",
                    L"Start", value)) {
        info.clientDisabled = value == 4;
    }
    if (RegGetDword(HKEY_LOCAL_MACHINE,
                    L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                    L"RequireSecuritySignature", value)) {
        info.signingRequired = value != 0;
    }
    return true;
}

static bool TlsProtocolDisabled(const std::wstring& version, const std::wstring& side) {
    std::wstring base = L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\" +
                        version + L"\\" + side;
    DWORD value = 0;
    if (RegGetDword(HKEY_LOCAL_MACHINE, base, L"Enabled", value)) {
        return value == 0;
    }
    if (RegGetDword(HKEY_LOCAL_MACHINE, base, L"DisabledByDefault", value)) {
        return value != 0;
    }
    // Sem chaves explicitas vale o padrao do Windows. No Server 2012 R2,
    // TLS 1.0, 1.1 e 1.2 sao habilitados por padrao.
    return false;
}

static bool TlsSideDisabled(const std::wstring& side) {
    return TlsProtocolDisabled(L"TLS 1.0", side) &&
           TlsProtocolDisabled(L"TLS 1.1", side);
}

bool GetTlsInfo(TlsInfo& info) {
    info = TlsInfo();
    // "Desabilitado" aqui significa desabilitado de forma explicita (Enabled=0
    // ou DisabledByDefault=1). Chaves ausentes usam o padrao do sistema, que no
    // alvo (Windows Server 2012 R2) mantem TLS 1.2 habilitado.
    info.tls12Server = !TlsProtocolDisabled(L"TLS 1.2", L"Server");
    info.tls12Client = !TlsProtocolDisabled(L"TLS 1.2", L"Client");
    info.legacyServerDisabled = TlsSideDisabled(L"Server");
    info.legacyClientDisabled = TlsSideDisabled(L"Client");
    info.legacyDisabled = info.legacyServerDisabled && info.legacyClientDisabled;
    return true;
}

static bool ReadIsInstalled(const std::wstring& guid, bool defaultValue) {
    DWORD value = 0;
    if (RegGetDword(HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\" + guid,
                    L"IsInstalled", value)) {
        return value != 0;
    }
    return defaultValue;
}

bool GetIeEscInfo(IeEscInfo& info) {
    info.admins = ReadIsInstalled(L"{A509B1A7-37EF-4B3F-8CFC-4F3A74704073}", true);
    info.users = ReadIsInstalled(L"{A509B1A8-37EF-4B3F-8CFC-4F3A74704073}", true);
    return true;
}

bool GetIeSecureProtocols(DWORD& protocols) {
    if (RegGetDword(HKEY_CURRENT_USER,
                    L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                    L"SecureProtocols", protocols)) return true;
    if (RegGetDword(HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                    L"SecureProtocols", protocols)) return true;
    protocols = 0;
    return false;
}

std::wstring GetIeHomePage() {
    std::wstring page;
    if (RegGetString(HKEY_CURRENT_USER,
                     L"Software\\Microsoft\\Internet Explorer\\Main",
                     L"Start Page", page) && !page.empty()) return page;
    if (RegGetString(HKEY_LOCAL_MACHINE,
                     L"SOFTWARE\\Microsoft\\Internet Explorer\\Main",
                     L"Start Page", page) && !page.empty()) return page;
    return std::wstring();
}

static std::wstring FindBrowser(const std::vector<std::wstring>& candidates) {
    for (const auto& path : candidates) {
        std::wstring expanded = ExpandEnv(path);
        if (FileExists(expanded)) return expanded;
    }
    return std::wstring();
}

std::wstring FindChromePath() {
    return FindBrowser({
        L"%ProgramFiles%\\Google\\Chrome\\Application\\chrome.exe",
        L"%ProgramFiles(x86)%\\Google\\Chrome\\Application\\chrome.exe",
        L"%LocalAppData%\\Google\\Chrome\\Application\\chrome.exe",
    });
}

std::wstring FindEdgePath() {
    return FindBrowser({
        L"%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe",
        L"%ProgramFiles%\\Microsoft\\Edge\\Application\\msedge.exe",
    });
}

std::wstring FindFirefoxPath() {
    return FindBrowser({
        L"%ProgramFiles%\\Mozilla Firefox\\firefox.exe",
        L"%ProgramFiles(x86)%\\Mozilla Firefox\\firefox.exe",
    });
}

} // namespace fg
