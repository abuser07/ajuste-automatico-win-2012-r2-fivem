// FiveMGuard - implementacao de utilitarios, log, processos, registry e HTTP
#include "Common.h"

#include <windows.h>
#include <shellapi.h>
#include <winhttp.h>
#include <wintrust.h>
#include <softpub.h>
#include <winver.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace fg {

const wchar_t* kAppName = L"FiveMGuard";
const wchar_t* kAppVersion = L"1.0.0";
const wchar_t* kAppTitle = L"FiveMGuard - Preparacao do Windows Server 2012 R2 para FiveM";

Logger g_log;

// ---------------------------------------------------------------- conversao
std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), (int)s.size(), nullptr, 0);
    UINT cp = CP_UTF8;
    DWORD flags = MB_ERR_INVALID_CHARS;
    if (len <= 0) {
        cp = CP_ACP;
        flags = 0;
        len = MultiByteToWideChar(cp, flags, s.data(), (int)s.size(), nullptr, 0);
    }
    if (len <= 0) return std::wstring();
    std::wstring out((size_t)len, L'\0');
    MultiByteToWideChar(cp, flags, s.data(), (int)s.size(), &out[0], len);
    return out;
}

std::string WideToUtf8(const std::wstring& s) {
    if (s.empty()) return std::string();
    int len = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    if (len <= 0) return std::string();
    std::string out((size_t)len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), &out[0], len, nullptr, nullptr);
    return out;
}

std::wstring ToLower(std::wstring s) {
    for (wchar_t& c : s) c = (wchar_t)std::towlower(c);
    return s;
}

std::wstring Trim(const std::wstring& s) {
    size_t b = 0, e = s.size();
    while (b < e && iswspace(s[b])) ++b;
    while (e > b && iswspace(s[e - 1])) --e;
    return s.substr(b, e - b);
}

bool StartsWithI(const std::wstring& s, const std::wstring& prefix) {
    if (prefix.size() > s.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (std::towlower(s[i]) != std::towlower(prefix[i])) return false;
    }
    return true;
}

bool ContainsI(const std::wstring& haystack, const std::wstring& needle) {
    if (needle.empty()) return true;
    std::wstring h = ToLower(haystack);
    std::wstring n = ToLower(needle);
    return h.find(n) != std::wstring::npos;
}

std::vector<std::wstring> SplitList(const std::wstring& s) {
    std::vector<std::wstring> out;
    std::wstring current;
    for (wchar_t c : s) {
        if (c == L',' || c == L';' || c == L' ' || c == L'\t' || c == L'\r' || c == L'\n') {
            std::wstring item = Trim(current);
            if (!item.empty()) out.push_back(item);
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    std::wstring item = Trim(current);
    if (!item.empty()) out.push_back(item);
    return out;
}

std::wstring JoinPath(const std::wstring& a, const std::wstring& b) {
    if (a.empty()) return b;
    if (b.empty()) return a;
    if (b.size() >= 2 && b[1] == L':' && std::iswalpha(b[0])) return b;
    if (b.size() >= 2 && b[0] == L'\\' && b[1] == L'\\') return b;
    if (b[0] == L'\\') return b;
    std::wstring result = a;
    if (result.back() != L'\\' && result.back() != L'/') result.push_back(L'\\');
    result += b;
    return result;
}

std::wstring ExePath() {
    std::vector<wchar_t> buffer(512);
    for (;;) {
        DWORD len = GetModuleFileNameW(nullptr, buffer.data(), (DWORD)buffer.size());
        if (len == 0) return std::wstring();
        if (len < buffer.size() - 1) {
            buffer.resize(len);
            return std::wstring(buffer.data(), len);
        }
        buffer.resize(buffer.size() * 2);
    }
}

std::wstring ExeDir() {
    std::wstring path = ExePath();
    size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return L".";
    return path.substr(0, pos);
}

std::wstring FileNameOf(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    return pos == std::wstring::npos ? path : path.substr(pos + 1);
}

std::wstring ParentDir(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return L".";
    if (pos == 2 && path.size() > 2 && path[1] == L':') return path.substr(0, 3);
    return path.substr(0, pos);
}

std::wstring MakeAbsolute(const std::wstring& path, const std::wstring& base) {
    if (path.empty()) return path;
    if ((path.size() >= 2 && path[1] == L':') ||
        (path.size() >= 2 && path[0] == L'\\' && path[1] == L'\\') ||
        (!path.empty() && path[0] == L'\\')) {
        return path;
    }
    return JoinPath(base, path);
}

std::wstring ExpandEnv(const std::wstring& value) {
    if (value.empty()) return value;
    DWORD needed = ExpandEnvironmentStringsW(value.c_str(), nullptr, 0);
    if (needed == 0) return value;
    std::vector<wchar_t> buffer(needed + 1);
    DWORD got = ExpandEnvironmentStringsW(value.c_str(), buffer.data(), (DWORD)buffer.size());
    if (got == 0) return value;
    return std::wstring(buffer.data());
}

std::wstring QuoteArg(const std::wstring& arg) {
    if (arg.empty()) return L"\"\"";
    if (arg.find_first_of(L" \t\"") == std::wstring::npos) return arg;
    std::wstring out = L"\"";
    size_t backslashes = 0;
    for (wchar_t c : arg) {
        if (c == L'\\') {
            ++backslashes;
        } else if (c == L'"') {
            out.append(backslashes * 2 + 1, L'\\');
            out.push_back(L'"');
            backslashes = 0;
        } else {
            out.append(backslashes, L'\\');
            backslashes = 0;
            out.push_back(c);
        }
    }
    out.append(backslashes * 2, L'\\');
    out.push_back(L'"');
    return out;
}

std::wstring GetEnvVar(const wchar_t* name) {
    DWORD needed = GetEnvironmentVariableW(name, nullptr, 0);
    if (needed == 0) return std::wstring();
    std::vector<wchar_t> buffer(needed + 1);
    DWORD got = GetEnvironmentVariableW(name, buffer.data(), (DWORD)buffer.size());
    if (got == 0) return std::wstring();
    return std::wstring(buffer.data(), got);
}

std::wstring FormatWinError(DWORD code) {
    if (code == 0) return L"sem erro";
    wchar_t* buffer = nullptr;
    DWORD len = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                   FORMAT_MESSAGE_IGNORE_INSERTS,
                               nullptr, code, 0, (LPWSTR)&buffer, 0, nullptr);
    std::wstring result;
    if (len && buffer) {
        result.assign(buffer, len);
        while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n' || result.back() == L' '))
            result.pop_back();
    }
    if (buffer) LocalFree(buffer);
    if (result.empty()) {
        wchar_t buf[64];
        swprintf(buf, 64, L"erro %lu (0x%08lX)", (unsigned long)code, (unsigned long)code);
        result = buf;
    } else {
        wchar_t suffix[64];
        swprintf(suffix, 64, L" (erro %lu)", (unsigned long)code);
        result += suffix;
    }
    return result;
}

std::wstring NowStamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buf[64];
    swprintf(buf, 64, L"%04d%02d%02d-%02d%02d%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

std::wstring NowReadable() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buf[64];
    swprintf(buf, 64, L"%02d/%02d/%04d %02d:%02d:%02d",
             st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

std::wstring FormatBytes(uint64_t bytes) {
    wchar_t buf[64];
    if (bytes >= (uint64_t)1024 * 1024 * 1024) {
        swprintf(buf, 64, L"%.1f GB", (double)bytes / (1024.0 * 1024.0 * 1024.0));
    } else if (bytes >= 1024 * 1024) {
        swprintf(buf, 64, L"%.1f MB", (double)bytes / (1024.0 * 1024.0));
    } else if (bytes >= 1024) {
        swprintf(buf, 64, L"%.1f KB", (double)bytes / 1024.0);
    } else {
        swprintf(buf, 64, L"%llu bytes", (unsigned long long)bytes);
    }
    return buf;
}

std::wstring IntToW(int value) { return std::to_wstring(value); }
std::wstring IntToW(unsigned int value) { return std::to_wstring(value); }
std::wstring IntToW(long long value) { return std::to_wstring(value); }

// ---------------------------------------------------------------- arquivos
bool FileExists(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

bool DirExists(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY);
}

bool EnsureDir(const std::wstring& path) {
    if (path.empty()) return false;
    if (DirExists(path)) return true;
    size_t pos = path.find_last_of(L"\\/");
    if (pos != std::wstring::npos && pos > 2) {
        std::wstring parent = path.substr(0, pos);
        if (!parent.empty() && parent != path) EnsureDir(parent);
    }
    if (CreateDirectoryW(path.c_str(), nullptr)) return true;
    DWORD err = GetLastError();
    if (err == ERROR_ALREADY_EXISTS && DirExists(path)) return true;
    return false;
}

bool EnsureParentDir(const std::wstring& filePath) {
    std::wstring parent = ParentDir(filePath);
    if (parent.empty() || parent == L".") return true;
    return EnsureDir(parent);
}

bool ReadWholeFile(const std::wstring& path, std::string& out) {
    out.clear();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    char buf[65536];
    DWORD read = 0;
    for (;;) {
        if (!ReadFile(h, buf, sizeof(buf), &read, nullptr)) {
            CloseHandle(h);
            return false;
        }
        if (read == 0) break;
        out.append(buf, read);
        if (out.size() > 32ull * 1024 * 1024) break;
    }
    CloseHandle(h);
    return true;
}

bool ReadTextFile(const std::wstring& path, std::wstring& out) {
    std::string bytes;
    if (!ReadWholeFile(path, bytes)) return false;
    size_t offset = 0;
    if (bytes.size() >= 3 && (unsigned char)bytes[0] == 0xEF &&
        (unsigned char)bytes[1] == 0xBB && (unsigned char)bytes[2] == 0xBF) {
        offset = 3;
    }
    std::string text = bytes.substr(offset);
    if (text.empty()) {
        out.clear();
        return true;
    }
    int len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), (int)text.size(), nullptr, 0);
    UINT cp = CP_UTF8;
    DWORD flags = MB_ERR_INVALID_CHARS;
    if (len <= 0) {
        cp = CP_ACP;
        flags = 0;
        len = MultiByteToWideChar(cp, flags, text.data(), (int)text.size(), nullptr, 0);
    }
    if (len <= 0) return false;
    out.assign((size_t)len, L'\0');
    MultiByteToWideChar(cp, flags, text.data(), (int)text.size(), &out[0], len);
    return true;
}

bool WriteWholeFile(const std::wstring& path, const std::string& data, bool utf8Bom) {
    if (!EnsureParentDir(path)) return false;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    bool ok = true;
    if (utf8Bom) {
        const unsigned char bom[3] = {0xEF, 0xBB, 0xBF};
        DWORD written = 0;
        if (!WriteFile(h, bom, 3, &written, nullptr) || written != 3) ok = false;
    }
    if (ok && !data.empty()) {
        size_t offset = 0;
        while (offset < data.size()) {
            DWORD chunk = (DWORD)std::min<size_t>(data.size() - offset, 1024 * 1024);
            DWORD written = 0;
            if (!WriteFile(h, data.data() + offset, chunk, &written, nullptr) || written == 0) {
                ok = false;
                break;
            }
            offset += written;
        }
    }
    CloseHandle(h);
    return ok;
}

bool WriteTextFile(const std::wstring& path, const std::wstring& text, bool utf8Bom) {
    return WriteWholeFile(path, WideToUtf8(text), utf8Bom);
}

bool RemoveFile(const std::wstring& path) {
    if (!FileExists(path)) return true;
    SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);
    return DeleteFileW(path.c_str()) != FALSE;
}

bool RemoveDirRecursive(const std::wstring& path) {
    if (!DirExists(path)) return true;
    WIN32_FIND_DATAW fd;
    std::wstring pattern = path;
    if (!pattern.empty() && pattern.back() != L'\\') pattern.push_back(L'\\');
    pattern += L"*";
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            std::wstring name = fd.cFileName;
            if (name == L"." || name == L"..") continue;
            std::wstring child = path + L"\\" + name;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                RemoveDirRecursive(child);
            } else {
                SetFileAttributesW(child.c_str(), FILE_ATTRIBUTE_NORMAL);
                DeleteFileW(child.c_str());
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    return RemoveDirectoryW(path.c_str()) != FALSE;
}

bool CopyFileSimple(const std::wstring& from, const std::wstring& to, bool overwrite) {
    if (!EnsureParentDir(to)) return false;
    return CopyFileW(from.c_str(), to.c_str(), overwrite ? FALSE : TRUE) != FALSE;
}

std::wstring GetFileVersionString(const std::wstring& path) {
    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeW(path.c_str(), &handle);
    if (size == 0) return std::wstring();
    std::vector<unsigned char> data(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, data.data())) return std::wstring();
    VS_FIXEDFILEINFO* info = nullptr;
    UINT infoSize = 0;
    if (!VerQueryValueW(data.data(), L"\\", (LPVOID*)&info, &infoSize) || !info) return std::wstring();
    wchar_t buf[64];
    swprintf(buf, 64, L"%u.%u.%u.%u",
             (unsigned)(info->dwFileVersionMS >> 16), (unsigned)(info->dwFileVersionMS & 0xFFFF),
             (unsigned)(info->dwFileVersionLS >> 16), (unsigned)(info->dwFileVersionLS & 0xFFFF));
    return buf;
}

uint64_t FileSize(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA data;
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) return 0;
    ULARGE_INTEGER size;
    size.HighPart = data.nFileSizeHigh;
    size.LowPart = data.nFileSizeLow;
    return size.QuadPart;
}

// ---------------------------------------------------------------- registry
std::wstring RegRootName(HKEY root) {
    if (root == HKEY_LOCAL_MACHINE) return L"HKLM";
    if (root == HKEY_CURRENT_USER) return L"HKCU";
    if (root == HKEY_CLASSES_ROOT) return L"HKCR";
    if (root == HKEY_USERS) return L"HKU";
    if (root == HKEY_CURRENT_CONFIG) return L"HKCC";
    return L"HKEY";
}

bool RegGetString(HKEY root, const std::wstring& subkey, const std::wstring& name, std::wstring& out) {
    out.clear();
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return false;
    DWORD type = 0, size = 0;
    LONG rc = RegQueryValueExW(key, name.c_str(), nullptr, &type, nullptr, &size);
    if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
        RegCloseKey(key);
        return false;
    }
    std::vector<wchar_t> buffer(size / sizeof(wchar_t) + 2, L'\0');
    rc = RegQueryValueExW(key, name.c_str(), nullptr, &type, (LPBYTE)buffer.data(), &size);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS) return false;
    size_t len = size / sizeof(wchar_t);
    while (len > 0 && buffer[len - 1] == L'\0') --len;
    out.assign(buffer.data(), len);
    return true;
}

bool RegGetDword(HKEY root, const std::wstring& subkey, const std::wstring& name, DWORD& out) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return false;
    DWORD type = 0, size = sizeof(DWORD), value = 0;
    LONG rc = RegQueryValueExW(key, name.c_str(), nullptr, &type, (LPBYTE)&value, &size);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS || type != REG_DWORD || size != sizeof(DWORD)) return false;
    out = value;
    return true;
}

bool RegSetDword(HKEY root, const std::wstring& subkey, const std::wstring& name, DWORD value) {
    HKEY key = nullptr;
    DWORD disp = 0;
    LONG rc = RegCreateKeyExW(root, subkey.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
                              KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &key, &disp);
    if (rc != ERROR_SUCCESS) return false;
    rc = RegSetValueExW(key, name.c_str(), 0, REG_DWORD, (const BYTE*)&value, sizeof(value));
    RegCloseKey(key);
    return rc == ERROR_SUCCESS;
}

bool RegSetString(HKEY root, const std::wstring& subkey, const std::wstring& name,
                  const std::wstring& value, DWORD type) {
    HKEY key = nullptr;
    DWORD disp = 0;
    LONG rc = RegCreateKeyExW(root, subkey.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
                              KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &key, &disp);
    if (rc != ERROR_SUCCESS) return false;
    const std::wstring& data = value;
    rc = RegSetValueExW(key, name.c_str(), 0, type, (const BYTE*)data.c_str(),
                        (DWORD)((data.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(key);
    return rc == ERROR_SUCCESS;
}

bool RegDeleteValue(HKEY root, const std::wstring& subkey, const std::wstring& name) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
        return true;
    LONG rc = RegDeleteValueW(key, name.c_str());
    RegCloseKey(key);
    return rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND;
}

bool RegKeyExists(HKEY root, const std::wstring& subkey) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
        return false;
    RegCloseKey(key);
    return true;
}

bool RegDeleteKeyTree(HKEY root, const std::wstring& subkey) {
    if (!RegKeyExists(root, subkey)) return true;
    LONG rc = RegDeleteTreeW(root, subkey.c_str());
    if (rc != ERROR_SUCCESS) return false;
    rc = RegDeleteKeyW(root, subkey.c_str());
    return rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND;
}

// ---------------------------------------------------------------- privilegios
bool IsUserAdmin() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID adminGroup = nullptr;
    if (AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

bool ElevateSelf(int argc, wchar_t** argv, int& exitCode) {
    std::wstring exe = ExePath();
    std::wstring params;
    for (int i = 1; i < argc; ++i) {
        if (!params.empty()) params += L" ";
        params += QuoteArg(argv[i]);
    }
    SHELLEXECUTEINFOW sei = {};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = exe.c_str();
    sei.lpParameters = params.empty() ? nullptr : params.c_str();
    sei.lpDirectory = ExeDir().c_str();
    sei.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&sei)) {
        DWORD err = GetLastError();
        if (err == ERROR_CANCELLED) {
            g_log.Warn(L"Elevacao de privilegios cancelada pelo usuario.");
        } else {
            g_log.Error(L"Nao foi possivel solicitar elevacao: " + FormatWinError(err));
        }
        exitCode = 5;
        return false;
    }
    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, INFINITE);
        DWORD code = 1;
        GetExitCodeProcess(sei.hProcess, &code);
        CloseHandle(sei.hProcess);
        exitCode = (int)code;
    } else {
        exitCode = 0;
    }
    return true;
}

bool IsWindowsServer() {
    std::wstring productType = WindowsProductType();
    if (_wcsicmp(productType.c_str(), L"WinNT") != 0) return true;
    std::wstring productName;
    if (RegGetString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                     L"ProductName", productName)) {
        return ContainsI(productName, L"Server");
    }
    return false;
}

bool IsDomainController() {
    return _wcsicmp(WindowsProductType().c_str(), L"LanmanNT") == 0;
}

std::wstring WindowsProductType() {
    std::wstring value;
    if (RegGetString(HKEY_LOCAL_MACHINE,
                     L"SYSTEM\\CurrentControlSet\\Control\\ProductOptions", L"ProductType", value)) {
        return value;
    }
    return L"WinNT";
}

bool IsTargetOS() {
    std::wstring productName, build;
    RegGetString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                 L"ProductName", productName);
    RegGetString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                 L"CurrentBuildNumber", build);
    return IsWindowsServer() && Trim(build) == L"9600" && ContainsI(productName, L"2012 R2");
}

// ---------------------------------------------------------------- processo
static std::wstring ReadTempOutput(HANDLE h) {
    std::wstring result;
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    SetFilePointerEx(h, zero, nullptr, FILE_BEGIN);
    std::string bytes;
    char buf[8192];
    DWORD read = 0;
    while (bytes.size() < 1024 * 1024 && ReadFile(h, buf, sizeof(buf), &read, nullptr) && read > 0) {
        bytes.append(buf, read);
    }
    if (bytes.empty()) return result;
    int len = MultiByteToWideChar(CP_OEMCP, 0, bytes.data(), (int)bytes.size(), nullptr, 0);
    UINT cp = CP_OEMCP;
    if (len <= 0) {
        cp = CP_ACP;
        len = MultiByteToWideChar(cp, 0, bytes.data(), (int)bytes.size(), nullptr, 0);
    }
    if (len <= 0) return result;
    result.assign((size_t)len, L'\0');
    MultiByteToWideChar(cp, 0, bytes.data(), (int)bytes.size(), &result[0], len);
    return Trim(result);
}

bool RunProcess(const std::wstring& commandLine, const std::wstring& workDir,
                DWORD timeoutMs, ProcessResult& result) {
    result = ProcessResult();
    if (commandLine.empty()) return false;

    wchar_t tempPath[MAX_PATH + 1] = {};
    wchar_t tempFile[MAX_PATH + 1] = {};
    if (GetTempPathW(MAX_PATH, tempPath) == 0) return false;
    if (GetTempFileNameW(tempPath, L"fmg", 0, tempFile) == 0) return false;

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE output = CreateFileW(tempFile, GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (output == INVALID_HANDLE_VALUE) return false;

    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE nul = INVALID_HANDLE_VALUE;
    if (input == INVALID_HANDLE_VALUE || input == nullptr) {
        nul = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        input = nul;
    }

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = output;
    si.hStdError = output;
    si.hStdInput = input;

    PROCESS_INFORMATION pi = {};
    std::vector<wchar_t> cmd(commandLine.begin(), commandLine.end());
    cmd.push_back(L'\0');

    BOOL created = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE,
                                  CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, nullptr,
                                  workDir.empty() ? nullptr : workDir.c_str(), &si, &pi);
    if (!created) {
        DWORD err = GetLastError();
        result.started = false;
        result.output = FormatWinError(err);
        CloseHandle(output);
        if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
        DeleteFileW(tempFile);
        return false;
    }

    result.started = true;
    DWORD wait = WaitForSingleObject(pi.hProcess, timeoutMs == 0 ? INFINITE : timeoutMs);
    if (wait == WAIT_TIMEOUT) {
        result.timedOut = true;
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 5000);
    }
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    result.exitCode = exitCode;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    result.output = ReadTempOutput(output);
    CloseHandle(output);
    if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
    DeleteFileW(tempFile);
    return true;
}

bool RunCommandLogged(const std::wstring& commandLine, const std::wstring& workDir,
                      DWORD timeoutMs, ProcessResult& result) {
    if (g_log.Verbose()) g_log.Detail(L"Comando: " + commandLine);
    bool ok = RunProcess(commandLine, workDir, timeoutMs, result);
    if (!ok) {
        g_log.Detail(L"Falha ao iniciar comando: " + result.output);
        return false;
    }
    if (result.timedOut) {
        g_log.Warn(L"Comando excedeu o tempo limite: " + commandLine);
    }
    if (!result.output.empty()) {
        std::wstring output = result.output;
        if (output.size() > 1200) output = output.substr(output.size() - 1200);
        g_log.Detail(L"Saida: " + output);
    }
    return result.exitCode == 0;
}

// ---------------------------------------------------------------- HTTP
static bool HttpRequest(const std::wstring& url, const std::wstring& destination,
                        std::string& body, std::wstring& error, bool progress) {
    error.clear();
    body.clear();

    URL_COMPONENTS uc = {};
    uc.dwStructSize = sizeof(uc);
    uc.dwSchemeLength = (DWORD)-1;
    uc.dwHostNameLength = (DWORD)-1;
    uc.dwUrlPathLength = (DWORD)-1;
    uc.dwExtraInfoLength = (DWORD)-1;
    uc.dwUserNameLength = (DWORD)-1;
    uc.dwPasswordLength = (DWORD)-1;
    if (!WinHttpCrackUrl(url.c_str(), (DWORD)url.size(), 0, &uc)) {
        error = L"URL invalida: " + url;
        return false;
    }
    if (!uc.lpszHostName || uc.dwHostNameLength == 0) {
        error = L"URL sem host: " + url;
        return false;
    }

    std::wstring host(uc.lpszHostName, uc.dwHostNameLength);
    std::wstring path;
    if (uc.lpszUrlPath && uc.dwUrlPathLength) path.assign(uc.lpszUrlPath, uc.dwUrlPathLength);
    if (uc.lpszExtraInfo && uc.dwExtraInfoLength) path.append(uc.lpszExtraInfo, uc.dwExtraInfoLength);
    if (path.empty()) path = L"/";
    bool secure = uc.nScheme == INTERNET_SCHEME_HTTPS;

    HINTERNET session = WinHttpOpen(L"FiveMGuard/1.0 (Windows Server 2012 R2)",
                                    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        error = L"WinHttpOpen: " + FormatWinError(GetLastError());
        return false;
    }
    WinHttpSetTimeouts(session, 15000, 30000, 60000, 60000);
    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
    WinHttpSetOption(session, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));

    HINTERNET connect = WinHttpConnect(session, host.c_str(), uc.nPort, 0);
    if (!connect) {
        error = L"WinHttpConnect: " + FormatWinError(GetLastError());
        WinHttpCloseHandle(session);
        return false;
    }

    HINTERNET request = WinHttpOpenRequest(connect, L"GET", path.c_str(), nullptr,
                                           WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           secure ? WINHTTP_FLAG_SECURE : 0);
    if (!request) {
        error = L"WinHttpOpenRequest: " + FormatWinError(GetLastError());
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return false;
    }
    WinHttpAddRequestHeaders(request, L"Accept: */*\r\n", (DWORD)-1L,
                             WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(request, nullptr)) {
        DWORD err = GetLastError();
        error = L"Falha de rede/TLS: " + FormatWinError(err);
        if (err == ERROR_WINHTTP_SECURE_FAILURE) {
            error += L" Verifique atualizacoes do Windows, raizes de certificados e suporte a TLS 1.2.";
        }
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return false;
    }

    DWORD status = 0;
    DWORD statusSize = sizeof(status);
    WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX);
    if (status < 200 || status >= 300) {
        wchar_t buf[128];
        swprintf(buf, 128, L"servidor retornou HTTP %lu", (unsigned long)status);
        error = buf;
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return false;
    }

    DWORD contentLength = 0;
    DWORD lengthSize = sizeof(contentLength);
    WinHttpQueryHeaders(request, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &contentLength, &lengthSize, WINHTTP_NO_HEADER_INDEX);

    HANDLE file = INVALID_HANDLE_VALUE;
    if (!destination.empty()) {
        EnsureParentDir(destination);
        file = CreateFileW(destination.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            error = L"Nao foi possivel criar " + destination + L": " + FormatWinError(GetLastError());
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return false;
        }
    }

    std::vector<char> buffer(65536);
    uint64_t total = 0;
    uint64_t nextProgress = 0;
    bool ok = true;
    for (;;) {
        DWORD read = 0;
        if (!WinHttpReadData(request, buffer.data(), (DWORD)buffer.size(), &read)) {
            error = L"Falha ao ler dados: " + FormatWinError(GetLastError());
            ok = false;
            break;
        }
        if (read == 0) break;
        total += read;
        if (file != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            if (!WriteFile(file, buffer.data(), read, &written, nullptr) || written != read) {
                error = L"Falha ao gravar arquivo: " + FormatWinError(GetLastError());
                ok = false;
                break;
            }
        } else {
            if (body.size() + read > 8ull * 1024 * 1024) {
                error = L"Resposta grande demais.";
                ok = false;
                break;
            }
            body.append(buffer.data(), read);
        }
        if (file != INVALID_HANDLE_VALUE && progress && total >= nextProgress) {
            std::wstring text = L"Baixando... " + FormatBytes(total);
            if (contentLength > 0) {
                text += L" de " + FormatBytes(contentLength);
            }
            g_log.Progress(text);
            nextProgress = total + 2ull * 1024 * 1024;
        }
    }
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    if (progress) g_log.ProgressEnd();

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);

    if (ok && file != INVALID_HANDLE_VALUE && total == 0) {
        error = L"Download vazio.";
        ok = false;
    }
    return ok;
}

bool DownloadFile(const std::wstring& url, const std::wstring& destination, std::wstring& error) {
    error.clear();
    std::wstring part = destination + L".part";
    RemoveFile(part);
    std::string body;
    if (!HttpRequest(url, part, body, error, true)) {
        RemoveFile(part);
        return false;
    }
    if (!FileExists(part) || FileSize(part) == 0) {
        error = L"Download nao gerou arquivo valido.";
        RemoveFile(part);
        return false;
    }
    if (!MoveFileExW(part.c_str(), destination.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        error = L"Nao foi possivel finalizar o download: " + FormatWinError(GetLastError());
        RemoveFile(part);
        return false;
    }
    return true;
}

bool HttpGetString(const std::wstring& url, std::string& body, std::wstring& error) {
    return HttpRequest(url, std::wstring(), body, error, false);
}

bool VerifyAuthenticode(const std::wstring& path, std::wstring& error) {
    error.clear();
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();
    fileInfo.hFile = nullptr;
    fileInfo.pgKnownSubject = nullptr;

    WINTRUST_DATA data = {};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fileInfo;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = 0;

    static GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &action, &data);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &data);
    if (status != ERROR_SUCCESS) {
        error = L"assinatura digital invalida/ausente: " + FormatWinError((DWORD)status);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------- logger
static void WriteToHandle(HANDLE h, const std::wstring& text, WORD attr, bool useColor) {
    if (h == INVALID_HANDLE_VALUE || h == nullptr) return;
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode)) {
        if (useColor) SetConsoleTextAttribute(h, attr);
        DWORD written = 0;
        WriteConsoleW(h, text.c_str(), (DWORD)text.size(), &written, nullptr);
        if (useColor) SetConsoleTextAttribute(h, 7);
    } else {
        std::string bytes = WideToUtf8(text);
        DWORD written = 0;
        WriteFile(h, bytes.data(), (DWORD)bytes.size(), &written, nullptr);
    }
}

bool Logger::Init(const std::wstring& baseDir, bool noColor, bool verbose) {
    color_ = !noColor;
    verbose_ = verbose;
    out_ = GetStdHandle(STD_OUTPUT_HANDLE);
    std::wstring logDir = JoinPath(baseDir, L"logs");
    EnsureDir(logDir);
    logPath_ = JoinPath(logDir, std::wstring(L"FiveMGuard-") + NowStamp() + L"-" +
                                   IntToW((unsigned)GetCurrentProcessId()) + L".log");
    log_ = CreateFileW(logPath_.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ,
                       nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (log_ != INVALID_HANDLE_VALUE) {
        WriteFileLine(LogKind::Plain, std::wstring(L"FiveMGuard ") + kAppVersion +
                                           L" - inicio em " + NowReadable());
    }
    return log_ != INVALID_HANDLE_VALUE;
}

void Logger::Close() {
    if (log_ != INVALID_HANDLE_VALUE) {
        WriteFileLine(LogKind::Plain, std::wstring(L"Fim em ") + NowReadable());
        CloseHandle(log_);
        log_ = INVALID_HANDLE_VALUE;
    }
}

void Logger::WriteFileLine(LogKind kind, const std::wstring& text) {
    if (log_ == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t time[64];
    swprintf(time, 64, L"%04d-%02d-%02d %02d:%02d:%02d ", st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);
    const wchar_t* tag = L"";
    switch (kind) {
        case LogKind::Ok: tag = L"[OK] "; break;
        case LogKind::Warn: tag = L"[AVISO] "; break;
        case LogKind::Error: tag = L"[ERRO] "; break;
        case LogKind::Step: tag = L"[ETAPA] "; break;
        case LogKind::Info: tag = L"[INFO] "; break;
        case LogKind::Detail: tag = L"[DETALHE] "; break;
        default: break;
    }
    std::wstring line = time;
    line += tag;
    line += text;
    line += L"\r\n";
    std::string bytes = WideToUtf8(line);
    DWORD written = 0;
    WriteFile(log_, bytes.data(), (DWORD)bytes.size(), &written, nullptr);
}

static WORD AttrFor(LogKind kind) {
    switch (kind) {
        case LogKind::Ok: return 10;
        case LogKind::Warn: return 14;
        case LogKind::Error: return 12;
        case LogKind::Step: return 11;
        case LogKind::Detail: return 8;
        default: return 7;
    }
}

void Logger::Emit(LogKind kind, const std::wstring& text, WORD attr) {
    if (kind == LogKind::Detail && !verbose_) {
        WriteFileLine(kind, text);
        return;
    }
    if (dry_ && (kind == LogKind::Step)) {
        WriteToHandle(out_, L"[SIMULACAO] ", 14, color_);
        WriteToHandle(out_, text + L"\n", 7, color_);
        WriteFileLine(LogKind::Step, L"[SIMULACAO] " + text);
        return;
    }
    const wchar_t* tag = L"";
    switch (kind) {
        case LogKind::Ok: tag = L"[OK] "; break;
        case LogKind::Warn: tag = L"[AVISO] "; break;
        case LogKind::Error: tag = L"[ERRO] "; break;
        case LogKind::Step: tag = L"[ETAPA] "; break;
        case LogKind::Info: tag = L"[INFO] "; break;
        case LogKind::Detail: tag = L"[DETALHE] "; break;
        default: break;
    }
    if (!color_) attr = 7;
    if (*tag) WriteToHandle(out_, tag, attr, color_);
    WriteToHandle(out_, text + L"\n", attr, color_);
    WriteFileLine(kind, text);
}

void Logger::Banner() {
    Raw(L"\n", 7);
    Raw(L"  ______ _            __  __  _____                     _ \n", 11);
    Raw(L" |  ____(_)          |  \\/  |/ ____|                   | |\n", 11);
    Raw(L" | |__   ___   _____ | \\  / | |  __ _   _  __ _ _ __ __| |\n", 11);
    Raw(L" |  __| | \\ \\ / / _ \\| |\\/| | | |_ | | | |/ _` | '__/ _` |\n", 11);
    Raw(L" | |    | |\\ V /  __/| |  | | |__| | |_| | (_| | | | (_| |\n", 11);
    Raw(L" |_|    |_| \\_/ \\___||_|  |_|\\_____|\\__,_|\\__,_|_|  \\__,_|\n", 11);
    Raw(std::wstring(L"  FiveMGuard v") + kAppVersion + L"  |  Windows Server 2012 R2 + FiveM\n\n", 8);
}

void Logger::Section(const std::wstring& title) {
    std::wstring line = L"\n=== " + title + L" ===";
    Raw(line + L"\n", 11);
    WriteFileLine(LogKind::Plain, line);
}

void Logger::Info(const std::wstring& text) { Emit(LogKind::Info, text, 7); }
void Logger::Ok(const std::wstring& text) { Emit(LogKind::Ok, text, 10); }
void Logger::Warn(const std::wstring& text) { Emit(LogKind::Warn, text, 14); }
void Logger::Error(const std::wstring& text) { Emit(LogKind::Error, text, 12); }
void Logger::Step(const std::wstring& text) { Emit(LogKind::Step, text, 11); }
void Logger::Detail(const std::wstring& text) { Emit(LogKind::Detail, text, 8); }
void Logger::Plain(const std::wstring& text) {
    WriteToHandle(out_, text + L"\n", 7, false);
    WriteFileLine(LogKind::Plain, text);
}

void Logger::Raw(const std::wstring& text, WORD attr) {
    WriteToHandle(out_, text, attr, color_);
}

void Logger::Progress(const std::wstring& text) {
    DWORD mode = 0;
    if (out_ != INVALID_HANDLE_VALUE && GetConsoleMode(out_, &mode)) {
        std::wstring line = L"\r" + text + L"          ";
        WriteToHandle(out_, line, 8, color_);
    }
}

void Logger::ProgressEnd() {
    DWORD mode = 0;
    if (out_ != INVALID_HANDLE_VALUE && GetConsoleMode(out_, &mode)) {
        WriteToHandle(out_, L"\r", 7, color_);
    }
}

static std::wstring ReadInputLine() {
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if (input != INVALID_HANDLE_VALUE && GetConsoleMode(input, &mode)) {
        wchar_t buffer[2048];
        DWORD read = 0;
        if (ReadConsoleW(input, buffer, 2047, &read, nullptr)) {
            std::wstring line(buffer, read);
            while (!line.empty() && (line.back() == L'\r' || line.back() == L'\n')) line.pop_back();
            return line;
        }
        return std::wstring();
    }
    std::string bytes;
    if (!std::getline(std::cin, bytes)) return std::wstring();
    return Utf8ToWide(bytes);
}

std::wstring Logger::Ask(const std::wstring& prompt) {
    Raw(prompt, 7);
    return ReadInputLine();
}

bool Logger::Confirm(const std::wstring& prompt, bool defaultYes) {
    std::wstring suffix = defaultYes ? L" [S/n]: " : L" [s/N]: ";
    for (;;) {
        std::wstring answer = Trim(ToLower(Ask(prompt + suffix)));
        if (answer.empty()) return defaultYes;
        if (answer == L"s" || answer == L"sim" || answer == L"y" || answer == L"yes" ||
            answer == L"1") return true;
        if (answer == L"n" || answer == L"nao" || answer == L"não" || answer == L"no" ||
            answer == L"0") return false;
        Raw(L"Responda S ou N.\n", 14);
    }
}

void Logger::Pause(const std::wstring& prompt) {
    Ask(prompt + L" ");
}

// ---------------------------------------------------------------- relatorio
void Report::Section(const std::wstring& title) {
    section_ = title;
    g_log.Section(title);
}

void Report::Add(Check status, const std::wstring& text) {
    items_.push_back({status, section_, text});
    switch (status) {
        case Check::Ok: g_log.Ok(text); break;
        case Check::Warn: g_log.Warn(text); break;
        case Check::Error: g_log.Error(text); break;
        default: g_log.Info(text); break;
    }
}

void Report::Ok(const std::wstring& text) { Add(Check::Ok, text); }
void Report::Warn(const std::wstring& text) { Add(Check::Warn, text); }
void Report::Error(const std::wstring& text) { Add(Check::Error, text); }
void Report::Info(const std::wstring& text) { Add(Check::Info, text); }

int Report::Count(Check status) const {
    int count = 0;
    for (const auto& item : items_) if (item.status == status) ++count;
    return count;
}

void Report::Summary() const {
    int ok = Count(Check::Ok);
    int warn = Count(Check::Warn);
    int err = Count(Check::Error);
    g_log.Section(L"Resumo do diagnostico");
    std::wstring line = L"OK: " + IntToW(ok) + L"   Avisos: " + IntToW(warn) +
                        L"   Erros: " + IntToW(err);
    if (err > 0) g_log.Error(line);
    else if (warn > 0) g_log.Warn(line);
    else g_log.Ok(line);
    if (err == 0 && warn == 0) g_log.Ok(L"Nenhum problema critico encontrado.");
}

// ---------------------------------------------------------------- helpers
bool ParseBool(const std::wstring& value, bool defaultValue) {
    std::wstring v = ToLower(Trim(value));
    if (v.empty()) return defaultValue;
    if (v == L"1" || v == L"true" || v == L"sim" || v == L"s" || v == L"yes" || v == L"y" ||
        v == L"on" || v == L"ligado") return true;
    if (v == L"0" || v == L"false" || v == L"nao" || v == L"não" || v == L"n" || v == L"no" ||
        v == L"off" || v == L"desligado") return false;
    return defaultValue;
}

int ParseInt(const std::wstring& value, int defaultValue, int base) {
    std::wstring v = Trim(value);
    if (v.empty()) return defaultValue;
    wchar_t* end = nullptr;
    errno = 0;
    long parsed = wcstol(v.c_str(), &end, base);
    if (errno != 0 || end == v.c_str()) return defaultValue;
    return (int)parsed;
}

DWORD ParseDword(const std::wstring& value, DWORD defaultValue) {
    std::wstring v = Trim(value);
    if (v.empty()) return defaultValue;
    wchar_t* end = nullptr;
    errno = 0;
    unsigned long parsed = wcstoul(v.c_str(), &end, 0);
    if (errno != 0 || end == v.c_str()) return defaultValue;
    return (DWORD)parsed;
}

bool IsNumeric(const std::wstring& value) {
    if (value.empty()) return false;
    for (wchar_t c : value) if (!iswdigit(c)) return false;
    return true;
}

bool IsValidPort(int port) { return port > 0 && port <= 65535; }

std::wstring HttpUrlForLocalPort(int port) {
    return L"http://localhost:" + IntToW(port) + L"/";
}

} // namespace fg
