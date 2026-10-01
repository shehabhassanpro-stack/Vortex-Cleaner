#pragma once

#include "../security/pe_signature_verifier.hpp"
#include "../core/logger.hpp"
#include "../core/scoped_resource.hpp"
#include <windows.h>
#include <shlobj.h>
#include <filesystem>
#include <vector>
#include <string>
#include <fstream>
#include <algorithm>

namespace WinTracePurge::Storage {

    namespace fs = std::filesystem;

    struct DiscoveredArtifact {
        fs::path Path;
        std::wstring Category; // L"Driver", L"ServiceExecutable", L"PlatformSetup", L"ResidualData"
        uint64_t ByteSize = 0;
    };

    class CPlatformLibraryResolver {
    public:
        // Returns all physical fixed logical drives (e.g. C:\, D:\, E:\)
        static std::vector<std::wstring> GetFixedDrives() {
            std::vector<std::wstring> drives;
            WCHAR driveStrings[512] = {};
            DWORD len = ::GetLogicalDriveStringsW(511, driveStrings);
            if (len == 0 || len > 511) {
                drives.push_back(L"C:\\");
                return drives;
            }

            LPCWSTR pDrive = driveStrings;
            while (*pDrive) {
                if (::GetDriveTypeW(pDrive) == DRIVE_FIXED) {
                    drives.push_back(pDrive);
                }
                pDrive += wcslen(pDrive) + 1;
            }
            return drives;
        }

        // Resolves all Steam library paths across all drives
        static std::vector<fs::path> GetSteamLibraryPaths() {
            std::vector<fs::path> libraries;

            // 1. Query Steam Install Path
            WCHAR szSteamPath[MAX_PATH] = {};
            DWORD dwSize = sizeof(szSteamPath);
            Core::ScopedHKey hSteamKey;
            if (::RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Valve\\Steam", 0, KEY_READ, hSteamKey.Put()) == ERROR_SUCCESS) {
                if (::RegQueryValueExW(hSteamKey.Get(), L"SteamPath", NULL, NULL, reinterpret_cast<LPBYTE>(szSteamPath), &dwSize) == ERROR_SUCCESS) {
                    libraries.push_back(fs::path(szSteamPath));
                }
            }

            // 2. Parse libraryfolders.vdf
            for (const auto& steamBase : libraries) {
                fs::path vdfPath = steamBase / L"steamapps" / L"libraryfolders.vdf";
                std::error_code ec;
                if (fs::exists(vdfPath, ec)) {
                    std::ifstream vdfFile(vdfPath);
                    if (vdfFile.is_open()) {
                        std::string line;
                        while (std::getline(vdfFile, line)) {
                            size_t pathKeyPos = line.find("\"path\"");
                            if (pathKeyPos != std::string::npos) {
                                size_t firstQuote = line.find('"', pathKeyPos + 6);
                                if (firstQuote != std::string::npos) {
                                    size_t secondQuote = line.find('"', firstQuote + 1);
                                    if (secondQuote != std::string::npos) {
                                        std::string rawPath = line.substr(firstQuote + 1, secondQuote - firstQuote - 1);
                                        std::string normalized;
                                        for (size_t i = 0; i < rawPath.length(); ++i) {
                                            if (rawPath[i] == '\\' && i + 1 < rawPath.length() && rawPath[i + 1] == '\\') {
                                                continue;
                                            }
                                            normalized += rawPath[i];
                                        }
                                        fs::path libPath(normalized);
                                        if (std::find(libraries.begin(), libraries.end(), libPath) == libraries.end()) {
                                            libraries.push_back(libPath);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Check standard drives fallback
            auto fixedDrives = GetFixedDrives();
            for (const auto& d : fixedDrives) {
                fs::path p1 = fs::path(d) / L"SteamLibrary";
                fs::path p2 = fs::path(d) / L"Program Files (x86)" / L"Steam";
                std::error_code ec;
                if (fs::exists(p1, ec) && std::find(libraries.begin(), libraries.end(), p1) == libraries.end()) {
                    libraries.push_back(p1);
                }
                if (fs::exists(p2, ec) && std::find(libraries.begin(), libraries.end(), p2) == libraries.end()) {
                    libraries.push_back(p2);
                }
            }

            return libraries;
        }

        // Dynamically scans all drives, platform manifests, and common folders for anti-cheat artifacts
        static std::vector<DiscoveredArtifact> DiscoverAllAntiCheatArtifacts() {
            std::vector<DiscoveredArtifact> results;
            std::error_code ec;

            auto AddTarget = [&](const fs::path& p, const std::wstring& cat) {
                if (fs::exists(p, ec)) {
                    uint64_t sz = 0;
                    if (fs::is_regular_file(p, ec)) {
                        sz = fs::file_size(p, ec);
                    } else if (fs::is_directory(p, ec)) {
                        for (auto it = fs::recursive_directory_iterator(p, fs::directory_options::skip_permission_denied, ec);
                             it != fs::recursive_directory_iterator(); ++it) {
                            if (it->is_regular_file(ec)) sz += it->file_size(ec);
                        }
                    }
                    results.push_back({ p, cat, sz });
                }
            };

            // 1. Core Windows Driver Files
            WCHAR szWinDir[MAX_PATH];
            if (::GetWindowsDirectoryW(szWinDir, MAX_PATH) > 0) {
                fs::path drvDir = fs::path(szWinDir) / L"System32" / L"drivers";
                const wchar_t* sysFiles[] = {
                    L"vgk.sys", L"easyanticheat.sys", L"easyanticheat_eos.sys", L"bedrive.sys", L"beservice.sys"
                };
                for (auto* f : sysFiles) {
                    AddTarget(drvDir / f, L"Kernel Driver");
                }
            }

            // 2. Multi-Drive Steam Libraries Common Folders
            auto steamLibs = GetSteamLibraryPaths();
            for (const auto& lib : steamLibs) {
                fs::path common = lib / L"steamapps" / L"common";
                if (fs::exists(common, ec) && fs::is_directory(common, ec)) {
                    for (auto it = fs::directory_iterator(common, fs::directory_options::skip_permission_denied, ec);
                         it != fs::directory_iterator(); ++it) {
                        if (it->is_directory(ec)) {
                            fs::path eacDir = it->path() / L"EasyAntiCheat";
                            fs::path beDir = it->path() / L"BattlEye";
                            if (fs::exists(eacDir, ec)) AddTarget(eacDir, L"Game EAC SDK");
                            if (fs::exists(beDir, ec)) AddTarget(beDir, L"Game BattlEye SDK");
                        }
                    }
                }
            }

            // 3. ProgramData & AppData Global Residuals
            const auto fixedDrives = GetFixedDrives();
            for (const auto& d : fixedDrives) {
                AddTarget(fs::path(d) / L"Program Files" / L"Riot Vanguard", L"Vanguard Engine");
                AddTarget(fs::path(d) / L"Program Files (x86)" / L"EasyAntiCheat", L"EAC Core");
                AddTarget(fs::path(d) / L"Program Files (x86)" / L"EasyAntiCheat_EOS", L"EAC EOS Core");
                AddTarget(fs::path(d) / L"Program Files (x86)" / L"Common Files" / L"BattlEye", L"BattlEye Core");
                AddTarget(fs::path(d) / L"ProgramData" / L"Riot Games", L"Riot Data");
                AddTarget(fs::path(d) / L"ProgramData" / L"EasyAntiCheat", L"EAC Data");
                AddTarget(fs::path(d) / L"ProgramData" / L"BattlEye", L"BattlEye Data");
            }

            // User AppData
            PWSTR pLocalApp = NULL;
            if (SUCCEEDED(::SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &pLocalApp))) {
                fs::path localApp(pLocalApp);
                ::CoTaskMemFree(pLocalApp);
                AddTarget(localApp / L"Riot Games", L"Riot User Data");
                AddTarget(localApp / L"BattlEye", L"BattlEye User Data");
            }

            PWSTR pRoamApp = NULL;
            if (SUCCEEDED(::SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &pRoamApp))) {
                fs::path roamApp(pRoamApp);
                ::CoTaskMemFree(pRoamApp);
                AddTarget(roamApp / L"EasyAntiCheat", L"EAC Roaming Data");
                AddTarget(roamApp / L"EasyAntiCheat_EOS", L"EAC EOS Roaming Data");
            }

            return results;
        }
    };

} // namespace WinTracePurge::Storage
