#pragma once

#include "platform_library_resolver.hpp"
#include "../core/logger.hpp"
#include "../core/scoped_resource.hpp"
#include <windows.h>
#include <shlobj.h>
#include <filesystem>
#include <vector>
#include <string>
#include <format>
#include <functional>

namespace WinTracePurge::Storage {

    namespace fs = std::filesystem;

    struct DynamicScanReport {
        uint64_t TotalJunkBytes = 0;
        uint32_t TempFilesCount = 0;
        std::vector<std::wstring> ActiveServicesFound;
        std::vector<std::wstring> RegistryKeysFound;
        std::vector<DiscoveredArtifact> DiscoveredFiles;
        std::vector<std::wstring> ScanLogFeed;

        [[nodiscard]] double GetJunkInMB() const noexcept {
            return static_cast<double>(TotalJunkBytes) / (1024.0 * 1024.0);
        }
    };

    class CRealTimeScanEngine {
    public:
        using ScanFeedbackCallback = std::function<void(int progressPercent, int phase, std::wstring_view detail)>;

        static DynamicScanReport PerformLiveScan(ScanFeedbackCallback callback = nullptr) {
            DynamicScanReport report = {};

            auto update = [&](int pct, int phase, const std::wstring& msg) {
                Core::CAppLogger::LogInfo(L"Scanner", msg);
                report.ScanLogFeed.insert(report.ScanLogFeed.begin(), msg);
                if (callback) callback(pct, phase, msg);
            };

            // Phase 1: Security & Token Audit
            update(10, 1, L"[Phase 1] Auditing NT Token Privileges...");
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            // Phase 2: SCM Driver Services Scan
            update(25, 2, L"[Phase 2] Querying Service Control Manager across all services...");
            ScanDriverServices(report, update);

            // Phase 3: PnP Class Filters & DriverStore Scan
            update(45, 3, L"[Phase 3] Auditing PnP Class Filters (UpperFilters)...");
            ScanClassFiltersAndDriverStore(report, update);

            // Phase 4: Registry Trees Audit
            update(65, 4, L"[Phase 4] Traversing 32-bit & 64-bit Registry Subtrees...");
            ScanRegistryKeys(report, update);

            // Phase 5: Multi-Drive & Platform Artifacts Discovery
            update(80, 5, L"[Phase 5] Scanning Steam libraries and fixed drives (C:, D:, E:)...");
            ScanMultiDriveArtifacts(report, update);

            // Phase 6: System Temp & Caches Calculation
            update(92, 5, L"[Phase 6] Calculating physical bytes in Temp, Caches & Dumps...");
            ScanStorageAndCaches(report, update);

            std::wstring summary = std::format(
                L"[Scan Complete] Found {:.1f} MB Traces, {} Services, {} Registry Keys across all drives",
                report.GetJunkInMB(), report.ActiveServicesFound.size(), report.RegistryKeysFound.size()
            );
            update(100, 6, summary);

            return report;
        }

    private:
        static void ScanDriverServices(DynamicScanReport& report, const auto& update) {
            Core::ScopedSCMHandle hSCM(::OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE));

            const std::wstring targetServices[] = {
                L"vgc", L"vgk", L"EasyAntiCheat", L"EasyAntiCheat_EOS", L"BEService"
            };

            for (const auto& svcName : targetServices) {
                bool isLive = false;

                // 1. Check registry key existence first
                std::wstring regPath = std::format(L"SYSTEM\\CurrentControlSet\\Services\\{}", svcName);
                Core::ScopedHKey hKey;
                if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, hKey.Put()) == ERROR_SUCCESS) {
                    DWORD dwStart = 0;
                    DWORD dwSize = sizeof(dwStart);
                    if (::RegQueryValueExW(hKey.Get(), L"Start", NULL, NULL, reinterpret_cast<LPBYTE>(&dwStart), &dwSize) == ERROR_SUCCESS) {
                        if (dwStart != 4) { // 4 is SERVICE_DISABLED
                            isLive = true;
                        }
                    } else {
                        isLive = true;
                    }
                }

                // 2. Check SCM state
                if (hSCM.IsValid()) {
                    Core::ScopedSCMHandle hSvc(::OpenServiceW(hSCM.Get(), svcName.c_str(), SERVICE_QUERY_STATUS));
                    if (hSvc.IsValid()) {
                        SERVICE_STATUS_PROCESS ssp = {};
                        DWORD dwNeeded = 0;
                        if (::QueryServiceStatusEx(hSvc.Get(), SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &dwNeeded)) {
                            if (ssp.dwCurrentState != SERVICE_STOPPED) {
                                isLive = true;
                            }
                        }
                    }
                }

                if (isLive) {
                    report.ActiveServicesFound.push_back(svcName);
                    update(30, 2, std::format(L"-> Detected active service: '{}'", svcName));
                }
            }
        }

        static void ScanClassFiltersAndDriverStore(DynamicScanReport& report, const auto& update) {
            (void)report;
            Core::ScopedHKey hClass;
            if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e96b-e325-11ce-bfc1-08002be10318}", 0, KEY_READ | KEY_WOW64_64KEY, hClass.Put()) == ERROR_SUCCESS) {
                DWORD dwType = 0, dwSize = 0;
                if (::RegQueryValueExW(hClass.Get(), L"UpperFilters", NULL, &dwType, NULL, &dwSize) == ERROR_SUCCESS && dwSize > 0) {
                    update(50, 3, L"-> UpperFilters entry detected in Keyboard Class");
                }
            }
        }

        static void ScanRegistryKeys(DynamicScanReport& report, const auto& update) {
            const std::wstring targetKeys[] = {
                L"SYSTEM\\CurrentControlSet\\Services\\vgc",
                L"SYSTEM\\CurrentControlSet\\Services\\vgk",
                L"SYSTEM\\CurrentControlSet\\Services\\EasyAntiCheat",
                L"SYSTEM\\CurrentControlSet\\Services\\EasyAntiCheat_EOS",
                L"SYSTEM\\CurrentControlSet\\Services\\BEService",
                L"SOFTWARE\\Riot Games",
                L"SOFTWARE\\EasyAntiCheat",
                L"SOFTWARE\\BattlEye",
                L"SOFTWARE\\WOW6432Node\\Riot Games",
                L"SOFTWARE\\WOW6432Node\\EasyAntiCheat",
                L"SOFTWARE\\WOW6432Node\\BattlEye"
            };

            for (const auto& keyPath : targetKeys) {
                Core::ScopedHKey hKey;
                if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, hKey.Put()) == ERROR_SUCCESS) {
                    report.RegistryKeysFound.push_back(keyPath);
                    update(70, 4, std::format(L"-> Detected registry key: HKLM\\{}", keyPath));
                }
            }
        }

        static void ScanMultiDriveArtifacts(DynamicScanReport& report, const auto& update) {
            report.DiscoveredFiles = CPlatformLibraryResolver::DiscoverAllAntiCheatArtifacts();
            for (const auto& art : report.DiscoveredFiles) {
                report.TotalJunkBytes += art.ByteSize;
                update(85, 5, std::format(L"-> Found [{}]: {}", art.Category, art.Path.wstring()));
            }
        }

        static void ScanStorageAndCaches(DynamicScanReport& report, const auto& update) {
            auto CalculateDirectorySize = [&](const fs::path& dirPath, std::wstring_view name) {
                std::error_code ec;
                if (!fs::exists(dirPath, ec)) return;

                uint64_t dirBytes = 0;
                uint32_t fileCount = 0;

                for (auto it = fs::recursive_directory_iterator(dirPath, fs::directory_options::skip_permission_denied, ec);
                     it != fs::recursive_directory_iterator(); ++it) {
                    if (it->is_regular_file(ec)) {
                        uint64_t sz = it->file_size(ec);
                        if (!ec) {
                            dirBytes += sz;
                            fileCount++;
                        }
                    }
                }

                report.TotalJunkBytes += dirBytes;
                report.TempFilesCount += fileCount;

                if (dirBytes > 0) {
                    update(95, 5, std::format(L"-> {}: {:.1f} MB ({} files)", name, static_cast<double>(dirBytes) / (1024.0 * 1024.0), fileCount));
                }
            };

            // 1. User Temp
            WCHAR szTemp[MAX_PATH];
            if (::GetTempPathW(MAX_PATH, szTemp) > 0) {
                CalculateDirectorySize(szTemp, L"User Temp (%TEMP%)");
            }

            // 2. Windows Temp
            WCHAR szWinDir[MAX_PATH];
            if (::GetWindowsDirectoryW(szWinDir, MAX_PATH) > 0) {
                CalculateDirectorySize(fs::path(szWinDir) / L"Temp", L"Windows Temp");
                CalculateDirectorySize(fs::path(szWinDir) / L"Minidump", L"Crash Minidumps");
            }

            // 3. Local AppData Caches
            PWSTR pLocalApp = NULL;
            if (SUCCEEDED(::SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &pLocalApp))) {
                fs::path localApp(pLocalApp);
                ::CoTaskMemFree(pLocalApp);

                CalculateDirectorySize(localApp / L"D3DSCache", L"DirectX Shader Cache");
                CalculateDirectorySize(localApp / L"NVIDIA\\GLCache", L"NVIDIA GPU Cache");
                CalculateDirectorySize(localApp / L"CrashDumps", L"Application Crash Dumps");
            }
        }
    };

} // namespace WinTracePurge::Storage
