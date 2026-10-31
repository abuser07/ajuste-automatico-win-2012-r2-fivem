// FiveMGuard - preparacao da pasta e dos arquivos do servidor FiveM
#pragma once

#include "Common.h"
#include "Config.h"

#include <string>

namespace fg {

struct ServerPaths {
    std::wstring root;
    std::wstring server;
    std::wstring data;
    std::wstring logs;
    std::wstring downloads;
};

ServerPaths GetServerPaths(const Config& cfg);

bool PrepareServerLayout(const Config& cfg, std::wstring& error);
bool SetupFiveMServer(const Config& cfg, bool forceDownloads, std::wstring& error);
bool TryUPnPMapping(const Config& cfg, std::wstring& error);

} // namespace fg
