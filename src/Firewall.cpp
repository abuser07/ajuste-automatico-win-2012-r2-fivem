// FiveMGuard - implementacao do Windows Firewall
#include "Firewall.h"

#include <initguid.h>
#include <netfw.h>

#include <cstdio>
#include <vector>

namespace fg {

std::wstring HResultText(long hr) {
    wchar_t buffer[64];
    swprintf(buffer, 64, L"HRESULT 0x%08lX", (unsigned long)hr);
    std::wstring text = buffer;
    std::wstring detail = FormatWinError((DWORD)hr);
    if (!detail.empty()) text += L" (" + detail + L")";
    return text;
}

static std::wstring BstrToString(BSTR value) {
    if (!value) return std::wstring();
    return std::wstring(value, SysStringLen(value));
}

Firewall::Firewall() = default;
Firewall::~Firewall() { Shutdown(); }

bool Firewall::Init(std::wstring& error) {
    error.clear();
    if (available_) return true;
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (SUCCEEDED(hr)) comInitialized_ = true;
    else if (hr == RPC_E_CHANGED_MODE) comInitialized_ = false;
    // Se CoInitialize falhar por outro motivo, ainda tentamos usar o COM ja inicializado.

    hr = CoCreateInstance(CLSID_NetFwPolicy2, nullptr, CLSCTX_INPROC_SERVER,
                          IID_INetFwPolicy2, (void**)&policy_);
    if (FAILED(hr) || !policy_) {
        error = L"CoCreateInstance(NetFwPolicy2): " + HResultText(hr);
        return false;
    }
    hr = policy_->get_Rules(&rules_);
    if (FAILED(hr) || !rules_) {
        error = L"INetFwPolicy2::get_Rules: " + HResultText(hr);
        policy_->Release();
        policy_ = nullptr;
        return false;
    }
    available_ = true;
    return true;
}

void Firewall::Shutdown() {
    if (rules_) {
        rules_->Release();
        rules_ = nullptr;
    }
    if (policy_) {
        policy_->Release();
        policy_ = nullptr;
    }
    if (comInitialized_) {
        CoUninitialize();
        comInitialized_ = false;
    }
    available_ = false;
}

bool Firewall::GetProfileInfo(int profile, FwProfileInfo& info, std::wstring& error) {
    info = FwProfileInfo();
    error.clear();
    if (!available_ || !policy_) {
        error = L"Firewall COM nao inicializado.";
        return false;
    }
    VARIANT_BOOL enabled = VARIANT_FALSE;
    HRESULT hr = policy_->get_FirewallEnabled((NET_FW_PROFILE_TYPE2)profile, &enabled);
    if (FAILED(hr)) {
        error = L"get_FirewallEnabled: " + HResultText(hr);
        return false;
    }
    NET_FW_ACTION inbound = NET_FW_ACTION_BLOCK;
    hr = policy_->get_DefaultInboundAction((NET_FW_PROFILE_TYPE2)profile, &inbound);
    if (FAILED(hr)) {
        error = L"get_DefaultInboundAction: " + HResultText(hr);
        return false;
    }
    info.known = true;
    info.enabled = enabled != VARIANT_FALSE;
    info.defaultInbound = (int)inbound;
    return true;
}

bool Firewall::GetRule(const std::wstring& name, FwRuleInfo& info, std::wstring& error) {
    info = FwRuleInfo();
    error.clear();
    if (!available_ || !rules_) {
        error = L"Firewall COM nao inicializado.";
        return false;
    }
    BSTR bstrName = SysAllocString(name.c_str());
    INetFwRule* rule = nullptr;
    HRESULT hr = rules_->Item(bstrName, &rule);
    SysFreeString(bstrName);
    if (FAILED(hr) || !rule) {
        return true; // nao existe
    }
    VARIANT_BOOL enabled = VARIANT_FALSE;
    NET_FW_ACTION action = NET_FW_ACTION_BLOCK;
    NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIR_IN;
    LONG protocol = 0;
    LONG profiles = 0;
    BSTR ports = nullptr;
    BSTR remote = nullptr;
    rule->get_Enabled(&enabled);
    rule->get_Action(&action);
    rule->get_Direction(&direction);
    rule->get_Protocol(&protocol);
    rule->get_Profiles(&profiles);
    rule->get_LocalPorts(&ports);
    rule->get_RemoteAddresses(&remote);
    info.exists = true;
    info.enabled = enabled != VARIANT_FALSE;
    info.action = (int)action;
    info.protocol = (int)protocol;
    info.profiles = profiles;
    info.localPorts = BstrToString(ports);
    info.remoteAddresses = BstrToString(remote);
    if (ports) SysFreeString(ports);
    if (remote) SysFreeString(remote);
    rule->Release();
    return true;
}

bool Firewall::AddRule(const std::wstring& name, const std::wstring& description, bool tcp,
                       const std::wstring& ports, long profiles, const std::wstring& remoteAddresses,
                       std::wstring& error) {
    error.clear();
    if (!available_ || !rules_) {
        error = L"Firewall COM nao inicializado.";
        return false;
    }
    // Remove uma regra anterior com o mesmo nome para garantir as configuracoes atuais.
    std::wstring removeError;
    RemoveRule(name, removeError);

    INetFwRule* rule = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_NetFwRule, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_INetFwRule, (void**)&rule);
    if (FAILED(hr) || !rule) {
        error = L"CoCreateInstance(NetFwRule): " + HResultText(hr);
        return false;
    }

    BSTR bName = SysAllocString(name.c_str());
    BSTR bDesc = SysAllocString(description.c_str());
    BSTR bGroup = SysAllocString(L"FiveMGuard");
    BSTR bPorts = SysAllocString(ports.c_str());
    BSTR bRemote = SysAllocString(remoteAddresses.c_str());

    rule->put_Name(bName);
    rule->put_Description(bDesc);
    rule->put_Grouping(bGroup);
    rule->put_Direction(NET_FW_RULE_DIR_IN);
    rule->put_Action(NET_FW_ACTION_ALLOW);
    rule->put_Enabled(VARIANT_TRUE);
    rule->put_Protocol(tcp ? NET_FW_IP_PROTOCOL_TCP : NET_FW_IP_PROTOCOL_UDP);
    rule->put_LocalPorts(bPorts);
    rule->put_Profiles(profiles);
    rule->put_RemoteAddresses(bRemote);
    rule->put_EdgeTraversal(VARIANT_FALSE);

    hr = rules_->Add(rule);
    if (FAILED(hr)) {
        error = L"INetFwRules::Add(" + name + L"): " + HResultText(hr);
    }

    if (bName) SysFreeString(bName);
    if (bDesc) SysFreeString(bDesc);
    if (bGroup) SysFreeString(bGroup);
    if (bPorts) SysFreeString(bPorts);
    if (bRemote) SysFreeString(bRemote);
    rule->Release();
    return SUCCEEDED(hr);
}

bool Firewall::RemoveRule(const std::wstring& name, std::wstring& error) {
    error.clear();
    if (!available_ || !rules_) {
        error = L"Firewall COM nao inicializado.";
        return false;
    }
    BSTR bName = SysAllocString(name.c_str());
    HRESULT hr = rules_->Remove(bName);
    SysFreeString(bName);
    if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
        error = L"INetFwRules::Remove(" + name + L"): " + HResultText(hr);
        return false;
    }
    return true;
}

bool Firewall::SetProfileEnabled(int profile, bool enabled, std::wstring& error) {
    error.clear();
    if (!available_ || !policy_) {
        error = L"Firewall COM nao inicializado.";
        return false;
    }
    HRESULT hr = policy_->put_FirewallEnabled((NET_FW_PROFILE_TYPE2)profile,
                                              enabled ? VARIANT_TRUE : VARIANT_FALSE);
    if (FAILED(hr)) {
        error = L"put_FirewallEnabled: " + HResultText(hr);
        return false;
    }
    return true;
}

int Firewall::ProfilesFromString(const std::wstring& value, int defaultValue) {
    std::wstring lower = ToLower(Trim(value));
    if (lower.empty()) return defaultValue;
    if (lower == L"all" || lower == L"todos" || lower == L"*") return 7;
    int mask = 0;
    for (const auto& item : SplitList(lower)) {
        if (item == L"domain" || item == L"dominio" || item == L"domínio") mask |= 1;
        else if (item == L"private" || item == L"privado") mask |= 2;
        else if (item == L"public" || item == L"publico" || item == L"público") mask |= 4;
    }
    return mask ? mask : defaultValue;
}

std::wstring Firewall::ProfilesToString(long profiles) {
    std::wstring result;
    auto add = [&](const wchar_t* text) {
        if (!result.empty()) result += L", ";
        result += text;
    };
    if (profiles & 1) add(L"dominio");
    if (profiles & 2) add(L"privado");
    if (profiles & 4) add(L"publico");
    if (result.empty()) result = L"nenhum";
    return result;
}

} // namespace fg
