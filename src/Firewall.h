// FiveMGuard - API nativa do Windows Firewall (INetFwPolicy2)
#pragma once

#include "Common.h"

#include <string>

struct INetFwPolicy2;
struct INetFwRules;

namespace fg {

struct FwProfileInfo {
    bool known = false;
    bool enabled = false;
    int defaultInbound = 0; // 0 = permitir, 1 = bloquear
};

struct FwRuleInfo {
    bool exists = false;
    bool enabled = false;
    int action = 0;      // NET_FW_ACTION
    int protocol = 0;    // 6 = TCP, 17 = UDP
    long profiles = 0;
    std::wstring localPorts;
    std::wstring remoteAddresses;
};

class Firewall {
public:
    Firewall();
    ~Firewall();
    Firewall(const Firewall&) = delete;
    Firewall& operator=(const Firewall&) = delete;

    bool Init(std::wstring& error);
    void Shutdown();
    bool Available() const { return available_; }

    bool GetProfileInfo(int profile, FwProfileInfo& info, std::wstring& error);
    bool GetRule(const std::wstring& name, FwRuleInfo& info, std::wstring& error);
    bool AddRule(const std::wstring& name, const std::wstring& description, bool tcp,
                 const std::wstring& ports, long profiles, const std::wstring& remoteAddresses,
                 std::wstring& error);
    bool RemoveRule(const std::wstring& name, std::wstring& error);
    bool SetProfileEnabled(int profile, bool enabled, std::wstring& error);

    static int ProfilesFromString(const std::wstring& value, int defaultValue = 7);
    static std::wstring ProfilesToString(long profiles);

private:
    INetFwPolicy2* policy_ = nullptr;
    INetFwRules* rules_ = nullptr;
    bool comInitialized_ = false;
    bool available_ = false;
};

std::wstring HResultText(long hr);

} // namespace fg
