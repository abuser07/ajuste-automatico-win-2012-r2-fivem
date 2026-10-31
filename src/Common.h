// FiveMGuard - utilitarios comuns
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace fg {

extern const wchar_t* kAppName;
extern const wchar_t* kAppVersion;
extern const wchar_t* kAppTitle;

// ------------------------------- texto / caminhos ---------------------------
std::wstring Utf8ToWide(const std::string& s);
std::string  WideToUtf8(const std::wstring& s);
std::wstring ToLower(std::wstring s);
std::wstring Trim(const std::wstring& s);
bool         StartsWithI(const std::wstring& s, const std::wstring& prefix);
bool         ContainsI(const std::wstring& haystack, const std::wstring& needle);
std::vector<std::wstring> SplitList(const std::wstring& s);
std::wstring JoinPath(const std::wstring& a, const std::wstring& b);
std::wstring ExePath();
std::wstring ExeDir();
std::wstring FileNameOf(const std::wstring& path);
std::wstring ParentDir(const std::wstring& path);
std::wstring MakeAbsolute(const std::wstring& path, const std::wstring& base);
std::wstring ExpandEnv(const std::wstring& value);
std::wstring QuoteArg(const std::wstring& arg);
std::wstring GetEnvVar(const wchar_t* name);
std::wstring FormatWinError(DWORD code);
std::wstring NowStamp();
std::wstring NowReadable();
std::wstring FormatBytes(uint64_t bytes);
std::wstring IntToW(int value);
std::wstring IntToW(unsigned int value);
std::wstring IntToW(long long value);

// ------------------------------- arquivos -----------------------------------
bool FileExists(const std::wstring& path);
bool DirExists(const std::wstring& path);
bool EnsureDir(const std::wstring& path);
bool EnsureParentDir(const std::wstring& filePath);
bool ReadWholeFile(const std::wstring& path, std::string& out);
bool ReadTextFile(const std::wstring& path, std::wstring& out);
bool WriteWholeFile(const std::wstring& path, const std::string& data, bool utf8Bom = false);
bool WriteTextFile(const std::wstring& path, const std::wstring& text, bool utf8Bom = false);
bool RemoveDirRecursive(const std::wstring& path);
bool RemoveFile(const std::wstring& path);
bool CopyFileSimple(const std::wstring& from, const std::wstring& to, bool overwrite);
std::wstring GetFileVersionString(const std::wstring& path);
uint64_t FileSize(const std::wstring& path);

// ------------------------------- registry -----------------------------------
bool RegGetString(HKEY root, const std::wstring& subkey, const std::wstring& name, std::wstring& out);
bool RegGetDword(HKEY root, const std::wstring& subkey, const std::wstring& name, DWORD& out);
bool RegSetDword(HKEY root, const std::wstring& subkey, const std::wstring& name, DWORD value);
bool RegSetString(HKEY root, const std::wstring& subkey, const std::wstring& name,
                  const std::wstring& value, DWORD type = REG_SZ);
bool RegDeleteValue(HKEY root, const std::wstring& subkey, const std::wstring& name);
bool RegKeyExists(HKEY root, const std::wstring& subkey);
bool RegDeleteKeyTree(HKEY root, const std::wstring& subkey);
std::wstring RegRootName(HKEY root);

// ------------------------------- privilegios --------------------------------
bool IsUserAdmin();
bool ElevateSelf(int argc, wchar_t** argv, int& exitCode);
bool IsTargetOS();
bool IsWindowsServer();
bool IsDomainController();
std::wstring WindowsProductType();

// ------------------------------- processos ----------------------------------
struct ProcessResult {
    bool        started = false;
    bool        timedOut = false;
    DWORD       exitCode = 0;
    std::wstring output;
};

bool RunProcess(const std::wstring& commandLine, const std::wstring& workDir,
                DWORD timeoutMs, ProcessResult& result);
bool RunCommandLogged(const std::wstring& commandLine, const std::wstring& workDir,
                      DWORD timeoutMs, ProcessResult& result);

// ------------------------------- rede / HTTP --------------------------------
bool DownloadFile(const std::wstring& url, const std::wstring& destination, std::wstring& error);
bool HttpGetString(const std::wstring& url, std::string& body, std::wstring& error);
bool VerifyAuthenticode(const std::wstring& path, std::wstring& error);

// ------------------------------- log / relatorio ----------------------------
enum class LogKind { Info, Ok, Warn, Error, Step, Detail, Plain };

class Logger {
public:
    bool Init(const std::wstring& baseDir, bool noColor, bool verbose);
    void Close();
    void SetDryRun(bool value) { dry_ = value; }
    bool DryRun() const { return dry_; }
    bool Verbose() const { return verbose_; }

    void Banner();
    void Section(const std::wstring& title);
    void Info(const std::wstring& text);
    void Ok(const std::wstring& text);
    void Warn(const std::wstring& text);
    void Error(const std::wstring& text);
    void Step(const std::wstring& text);
    void Detail(const std::wstring& text);
    void Plain(const std::wstring& text);
    void Raw(const std::wstring& text, WORD attr = 7);
    void Progress(const std::wstring& text);
    void ProgressEnd();

    std::wstring Ask(const std::wstring& prompt);
    bool Confirm(const std::wstring& prompt, bool defaultYes = false);
    void Pause(const std::wstring& prompt = L"Pressione Enter para continuar...");
    const std::wstring& LogPath() const { return logPath_; }

private:
    void Emit(LogKind kind, const std::wstring& text, WORD attr);
    void WriteFileLine(LogKind kind, const std::wstring& text);
    HANDLE out_ = INVALID_HANDLE_VALUE;
    HANDLE log_ = INVALID_HANDLE_VALUE;
    bool color_ = true;
    bool verbose_ = false;
    bool dry_ = false;
    std::wstring logPath_;
};

extern Logger g_log;

enum class Check { Ok, Warn, Error, Info };

struct CheckItem {
    Check status;
    std::wstring section;
    std::wstring text;
};

class Report {
public:
    void Section(const std::wstring& title);
    void Ok(const std::wstring& text);
    void Warn(const std::wstring& text);
    void Error(const std::wstring& text);
    void Info(const std::wstring& text);
    int Count(Check status) const;
    void Summary() const;
    const std::vector<CheckItem>& Items() const { return items_; }

private:
    void Add(Check status, const std::wstring& text);
    std::wstring section_;
    std::vector<CheckItem> items_;
};

// ------------------------------- pequenos helpers ---------------------------
bool ParseBool(const std::wstring& value, bool defaultValue);
int ParseInt(const std::wstring& value, int defaultValue, int base = 10);
DWORD ParseDword(const std::wstring& value, DWORD defaultValue);
bool IsNumeric(const std::wstring& value);
bool IsValidPort(int port);
std::wstring HttpUrlForLocalPort(int port);

} // namespace fg
