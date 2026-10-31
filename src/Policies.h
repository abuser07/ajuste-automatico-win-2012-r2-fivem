// FiveMGuard - politicas de navegador, endurecimento e regras de firewall
#pragma once

#include "Common.h"
#include "Config.h"
#include "Firewall.h"

#include <string>
#include <vector>

namespace fg {

bool ApplyBrowserPolicies(const Config& cfg, std::wstring& error);
bool ApplySecurityHardening(const Config& cfg, std::wstring& error, bool& rebootRequired);
bool ApplyFirewallRules(const Config& cfg, Firewall& fw, std::vector<std::wstring>& ruleNames,
                        std::wstring& error);
bool EnsureFirewallServices(std::wstring& error);

// Diario de valores de registro alterados, usado pelo rollback.
void SetPolicyJournal(const std::wstring& path);
void ClearPolicyJournal();

} // namespace fg
