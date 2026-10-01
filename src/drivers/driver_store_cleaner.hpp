#pragma once

#include "../core/interfaces.hpp"
#include "../core/result.hpp"
#include "../core/logger.hpp"
#include "../core/scoped_resource.hpp"
#include "../core/zstring_view.hpp"
#include <windows.h>
#include <setupapi.h>
#include <newdev.h>
#include <string>
#include <string_view>
#include <vector>
#include <algorithm>
#include <format>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "newdev.lib")

namespace WinTracePurge::Drivers {

    /// @brief DriverStore package cleaner implementing a Two-Phase Transactional Model.
    /// Strictly resolves VTX-SYS-007 by separating discovery enumeration from in-place deletion,
    /// eliminating the index-shifting package skipping bug in SetupAPI.
    /// Implements the full C++23 Core::ICleanerModule contract.
    class CDriverStoreCleaner : public Core::ICleanerModule {
    public:
        [[nodiscard]] Core::zstring_view GetModuleName() const noexcept override {
            return L"DriverStoreCleaner";
        }

        [[nodiscard]] Core::Result<std::vector<Core::ResourceItem>> Scan(const Core::CleanupContext& ctx) override {
            (void)ctx;
            std::vector<Core::ResourceItem> items;

            constexpr std::wstring_view kTargetMatches[] = {
                L"Riot Games", L"EasyAntiCheat", L"BattlEye"
            };

            for (const auto& match : kTargetMatches) {
                auto candidates = DiscoverMatchingOemInfs(match);
                for (const auto& inf : candidates) {
                    items.push_back(Core::ResourceItem{
                        .Type = Core::TargetType::DriverStorePackage,
                        .PathOrIdentifier = inf,
                        .Description = std::format(L"OEM DriverStore Package (Matches '{}')", match)
                    });
                }
            }

            return items;
        }

        [[nodiscard]] Core::Result<Core::PurgeStats> Purge(const Core::CleanupContext& ctx, bool dryRun) override {
            (void)ctx;
            Core::PurgeStats stats{};

            constexpr std::wstring_view kTargetMatches[] = {
                L"Riot Games", L"EasyAntiCheat", L"BattlEye"
            };

            for (const auto& match : kTargetMatches) {
                auto candidates = DiscoverMatchingOemInfs(match);
                stats.ItemsScanned += static_cast<uint32_t>(candidates.size());

                if (!dryRun) {
                    for (const auto& oemInf : candidates) {
                        BOOL bNeedReboot = FALSE;
                        ::DiUninstallDriverW(nullptr, oemInf.c_str(), 0, &bNeedReboot);
                        if (::SetupUninstallOEMInfW(oemInf.c_str(), SUOI_FORCEDELETE, nullptr)) {
                            stats.ItemsPurged++;
                            Core::CAppLogger::LogInfo(L"DriverStore", std::format(L"Successfully uninstalled and purged OEM package '{}'", oemInf));
                        } else {
                            DWORD err = ::GetLastError();
                            Core::CAppLogger::LogWarn(L"DriverStore", std::format(L"SetupUninstallOEMInfW failed for '{}' (Code 0x{:08X})", oemInf, err), err);
                        }
                    }
                }
            }

            return stats;
        }

        /// @brief Two-Phase transactional purge of OEM packages matching a driver provider or string.
        /// Resolves VTX-SYS-007 by taking a snapshot prior to invoking any mutating deletion APIs.
        static Core::Result<bool> PurgeOemDriverPackage(std::wstring_view targetDriverSysOrProvider) {
            // Phase 1: Snapshot Discovery (Zero Mutations)
            auto candidates = DiscoverMatchingOemInfs(targetDriverSysOrProvider);
            if (candidates.empty()) {
                return true;
            }

            Core::CAppLogger::LogInfo(L"DriverStore", 
                std::format(L"Discovered {} OEM package candidate(s) for target '{}'", candidates.size(), targetDriverSysOrProvider));

            // Phase 2: Transactional Purge Execution
            for (const auto& oemInf : candidates) {
                BOOL bNeedReboot = FALSE;
                ::DiUninstallDriverW(nullptr, oemInf.c_str(), 0, &bNeedReboot);

                if (::SetupUninstallOEMInfW(oemInf.c_str(), SUOI_FORCEDELETE, nullptr)) {
                    Core::CAppLogger::LogInfo(L"DriverStore", std::format(L"Purged OEM driver package: '{}'", oemInf));
                } else {
                    DWORD err = ::GetLastError();
                    Core::CAppLogger::LogWarn(L"DriverStore", 
                        std::format(L"Failed to force-delete OEM package '{}' (Code 0x{:08X})", oemInf, err), err);
                }
            }

            return true;
        }

    private:
        /// @brief Phase 1 Discovery: Enumerates published OEM INF packages into a detached snapshot list.
        static std::vector<std::wstring> DiscoverMatchingOemInfs(std::wstring_view targetMatch) {
            std::vector<std::wstring> candidates;

            HMODULE hSetupApi = ::GetModuleHandleW(L"setupapi.dll");
            Core::ScopedModule hLoadedSetupApi;
            if (!hSetupApi) {
                hLoadedSetupApi.Reset(::LoadLibraryW(L"setupapi.dll"));
                hSetupApi = hLoadedSetupApi.Get();
            }
            if (!hSetupApi) return candidates;

            typedef BOOL(WINAPI* PFN_SetupEnumPublishedOEMInfW)(DWORD, PWSTR, DWORD, PDWORD);
            auto pfnSetupEnumPublishedOEMInfW = reinterpret_cast<PFN_SetupEnumPublishedOEMInfW>(
                ::GetProcAddress(hSetupApi, "SetupEnumPublishedOEMInfW"));

            if (!pfnSetupEnumPublishedOEMInfW) return candidates;

            DWORD dwIndex = 0;
            WCHAR szOemInf[MAX_PATH];
            DWORD dwSize = 0;

            // Strictly resolve VTX-SYS-007: Pure discovery snapshot without in-place mutations
            while (pfnSetupEnumPublishedOEMInfW(dwIndex++, szOemInf, ARRAYSIZE(szOemInf), &dwSize)) {
                if (IsMatchingDriverPackage(szOemInf, targetMatch)) {
                    candidates.emplace_back(szOemInf);
                }
            }

            return candidates;
        }

        static bool ContainsIgnoreCase(std::wstring_view haystack, std::wstring_view needle) noexcept {
            if (needle.empty()) return true;
            if (haystack.size() < needle.size()) return false;
            auto toLower = [](wchar_t c) noexcept {
                return (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c + (L'a' - L'A')) : c;
            };
            auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
                [&](wchar_t c1, wchar_t c2) noexcept { return toLower(c1) == toLower(c2); });
            return it != haystack.end();
        }

        static bool IsMatchingDriverPackage(LPCWSTR pwszInfName, std::wstring_view targetMatch) {
            WCHAR szInfPath[MAX_PATH];
            if (::GetWindowsDirectoryW(szInfPath, MAX_PATH) == 0) return false;

            wcscat_s(szInfPath, L"\\INF\\");
            wcscat_s(szInfPath, pwszInfName);

            HINF hInf = ::SetupOpenInfFileW(szInfPath, nullptr, INF_STYLE_WIN4, nullptr);
            if (hInf == INVALID_HANDLE_VALUE) return false;

            INFCONTEXT context{};
            bool matched = false;

            if (::SetupFindFirstLineW(hInf, L"Strings", nullptr, &context)) {
                WCHAR szLine[512];
                do {
                    if (::SetupGetStringFieldW(&context, 1, szLine, ARRAYSIZE(szLine), nullptr)) {
                        if (ContainsIgnoreCase(szLine, targetMatch)) {
                            matched = true;
                            break;
                        }
                    }
                } while (::SetupFindNextLine(&context, &context));
            }

            ::SetupCloseInfFile(hInf);
            return matched;
        }
    };

} // namespace WinTracePurge::Drivers
