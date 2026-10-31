// FiveMGuard - dependencias, downloads e extracao de artefatos
#pragma once

#include "Common.h"
#include "Config.h"
#include "SystemInfo.h"

#include <string>

namespace fg {

struct DependencyState {
    VCRuntimeInfo vcX64;
    VCRuntimeInfo vcX86;
    DWORD dotNetRelease = 0;
    std::wstring dotNetLabel;
};

void GetDependencyState(DependencyState& state);

// Instala o runtime VC++ 14.29 (x64/x86) e, se configurado, o .NET Framework 4.8.
bool InstallDependencies(const Config& cfg, bool& rebootRequired, std::wstring& error);

// Deteccao de ferramentas extras (usada no diagnostico e na instalacao).
bool IsChromeInstalled();
bool IsNodeInstalled();
bool IsGitInstalled();
bool IsSevenZipInstalled();

// Instala ferramentas basicas (Chrome, Node.js, Git, 7-Zip) conforme o config.ini.
bool InstallExtraTools(const Config& cfg, bool& rebootRequired, std::wstring& error);

struct FiveMServerBuild {
    std::wstring version;
    std::wstring recommendedUrl;
    std::wstring optionalUrl;
};

bool QueryFiveMServerBuild(const Config& cfg, FiveMServerBuild& build, std::wstring& error);

// Baixa e instala os artefatos do FXServer e/ou o cfx-server-data.
bool DownloadFiveMServerFiles(const Config& cfg, bool artifacts, bool data,
                              std::wstring& error);

// Extrator ZIP via .NET/PowerShell, com protecao contra Zip Slip.
bool ExtractZipArchive(const std::wstring& zipPath, const std::wstring& destDir,
                       std::wstring& error);

} // namespace fg
