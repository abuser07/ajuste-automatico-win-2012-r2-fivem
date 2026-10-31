// FiveMGuard - diagnostico do Windows e do ambiente FiveM
#pragma once

#include "Common.h"

#include <string>
#include <vector>

namespace fg {

struct OsInfo {
    std::wstring productName;
    std::wstring editionId;
    std::wstring build;
    std::wstring version;
    std::wstring architecture;
    std::wstring productType;
    DWORD major = 0;
    DWORD minor = 0;
    DWORD buildNumber = 0;
    bool isServer = false;
    bool isDatacenter = false;
    bool isTarget2012R2 = false;
    bool isDomainController = false;
};

struct VCRuntimeInfo {
    bool installed = false;
    int major = 0;
    int minor = 0;
    int build = 0;
    std::wstring version;
};

struct ServiceInfo {
    bool exists = false;
    bool running = false;
    DWORD state = 0;
    DWORD startType = 0;
    std::wstring name;
};

struct PortOwner {
    int port = 0;
    bool tcp = true;
    DWORD pid = 0;
    std::wstring process;
    std::wstring localAddress;
};

struct SmbInfo {
    bool serverDisabled = false;
    bool clientDisabled = false;
    bool signingRequired = false;
};

struct TlsInfo {
    bool tls12Server = true;
    bool tls12Client = true;
    bool legacyServerDisabled = false;
    bool legacyClientDisabled = false;
    bool legacyDisabled = false;
};

struct IeEscInfo {
    bool admins = true;
    bool users = true;
};

bool GetOsInfo(OsInfo& info);
std::wstring GetComputerNameStr();
std::wstring GetUserNameStr();
std::wstring GetCpuName();
int GetCpuCores();
uint64_t GetRamTotalMB();
uint64_t GetRamAvailableMB();
std::wstring GetUptimeText();
std::wstring GetDriveRoot(const std::wstring& path);
uint64_t GetDiskFreeBytes(const std::wstring& path);
uint64_t GetDiskTotalBytes(const std::wstring& path);

bool GetDotNetInfo(DWORD& release, std::wstring& label);
std::wstring GetPowerShellVersion();
bool GetVCRuntime(bool x64, VCRuntimeInfo& info);
bool IsPendingReboot();
bool GetServiceInfo(const std::wstring& name, ServiceInfo& info);
bool StartServiceByName(const std::wstring& name, std::wstring& error);
std::wstring GetDefenderSummary();
bool IsDefenderRunning();
bool GetGuestDisabled(bool& disabled);

bool GetPortListener(int port, bool tcp, PortOwner& owner, std::wstring& error);
std::vector<std::wstring> GetLocalIPv4List();
std::wstring GetPublicIP();
std::wstring GetRdpClientIP();
bool IsRdpEnabled();

bool GetSmbInfo(SmbInfo& info);
bool GetTlsInfo(TlsInfo& info);
bool GetIeEscInfo(IeEscInfo& info);
bool GetIeSecureProtocols(DWORD& protocols);
std::wstring GetIeHomePage();

std::wstring FindChromePath();
std::wstring FindEdgePath();
std::wstring FindFirefoxPath();
bool IsPortInUseByOther(int port, bool tcp, const std::wstring& allowedProcess,
                        PortOwner& owner);

} // namespace fg
