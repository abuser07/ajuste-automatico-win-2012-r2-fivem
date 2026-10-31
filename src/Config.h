// FiveMGuard - configuracao INI
#pragma once

#include "Common.h"

#include <string>
#include <vector>

namespace fg {

class Config {
public:
    bool Load(const std::wstring& path, bool createIfMissing);
    bool SaveDefault(const std::wstring& path) const;
    std::wstring GetString(const std::wstring& section, const std::wstring& key,
                           const std::wstring& defaultValue = L"") const;
    int GetInt(const std::wstring& section, const std::wstring& key, int defaultValue) const;
    DWORD GetDword(const std::wstring& section, const std::wstring& key, DWORD defaultValue) const;
    bool GetBool(const std::wstring& section, const std::wstring& key, bool defaultValue) const;
    std::wstring GetPath(const std::wstring& section, const std::wstring& key,
                         const std::wstring& defaultValue) const;
    const std::wstring& Path() const { return path_; }

private:
    struct Entry {
        std::wstring section;
        std::wstring key;
        std::wstring value;
    };
    std::wstring path_;
    std::vector<Entry> entries_;
};

extern Config g_cfg;

const wchar_t* DefaultConfigText();

} // namespace fg
