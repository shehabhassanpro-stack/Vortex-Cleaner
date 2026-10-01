#pragma once

#include "../core/interfaces.hpp"
#include "../core/result.hpp"
#include "../core/scoped_resource.hpp"
#include "../core/logger.hpp"
#include "../core/zstring_view.hpp"
#include "../security/registry_dacl_manager.hpp"
#include "../security/binary_trust_evaluator.hpp"
#include "../storage/nist_sanitizer.hpp"
#include <windows.h>
#include <string>
#include <string_view>
#include <vector>
#include <chrono>
#include <thread>
#include <filesystem>
#include <format>

namespace WinTracePurge::Drivers {

    /// @brief Capability-aware kernel driver service controller and canonical image path purger.
    /// Strictly resolves VTX-SYS-008 by querying service stop capabilities and bypassing deadlocks on un-stoppable drivers.
    /// Strictly resolves VTX-SYS-009 by resolving authoritative binary image paths via QueryServiceConfigW.
    /// Implements the full C++23 Core::ICleanerModule contract.
    class CRobustServiceController : public Core::ICleanerModule {
    public:
        [[nodiscard]] Core::zstring_view GetModuleName() const noexcept override {
            return L"ServiceController";
        }

        [[nodiscard]] Core::Result<std::vector<Core::ResourceItem>> Scan(const Core::CleanupContext& ctx) override {
            (void)ctx;
            std::vector<Core::ResourceItem> items;

            Core::ScopedSCMHandle hSCM(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE));
            if (!hSCM.IsValid()) {
                return items;
            }

            constexpr std::wstring_view kTargetServices[] = {
                L"vgc", L"vgk", L"EasyAntiCheat", L"EasyAntiCheat_EOS", L"BEService"
            };

            for (const auto& svcName : kTargetServices) {
                Core::ScopedSCMHandle hService(::OpenServiceW(hSCM.Get(), svcName.data(), SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG));
                if (hService.IsValid()) {
                    std::wstring desc = L"Active Kernel Driver Service";
                    auto pathRes = ResolveCanonicalImagePath(hService.Get());
                    if (pathRes) {
                        desc = std::format(L"Image: {}", pathRes->wstring());
                    }

                    items.push_back(Core::ResourceItem{
                        .Type = Core::TargetType::DriverService,
                        .PathOrIdentifier = std::wstring(svcName),
                        .Description = desc,
                        .IsLocked = true
                    });
                }
            }

            return items;
        }

        [[nodiscard]] Core::Result<Core::PurgeStats> Purge(const Core::CleanupContext& ctx, bool dryRun) override {
            (void)ctx;
            Core::PurgeStats stats{};

            constexpr std::wstring_view kTargetServices[] = {
                L"vgc", L"vgk", L"EasyAntiCheat", L"EasyAntiCheat_EOS", L"BEService"
            };

            for (const auto& svc : kTargetServices) {
                if (!dryRun) {
                    auto res = StopAndPurgeService(svc);
                    if (res && *res) {
                        stats.ItemsPurged++;
                    }
                }
                stats.ItemsScanned++;
            }

            return stats;
        }

        /// @brief Authoritatively resolves the canonical disk binary path from the SCM service configuration.
        /// Strictly resolves VTX-SYS-009 by normalizing NT namespace prefixes (\??\) and expanding %SystemRoot%.
        [[nodiscard]] static Core::Result<std::filesystem::path> ResolveCanonicalImagePath(SC_HANDLE hService) noexcept {
            DWORD bytesNeeded = 0;
            ::QueryServiceConfigW(hService, nullptr, 0, &bytesNeeded);
            if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytesNeeded == 0) {
                return std::unexpected(Core::SystemError::FromLastError(L"QueryServiceConfigW size query failed"));
            }

            std::vector<BYTE> buffer(bytesNeeded);
            auto* pConfig = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buffer.data());
            if (!::QueryServiceConfigW(hService, pConfig, bytesNeeded, &bytesNeeded)) {
                return std::unexpected(Core::SystemError::FromLastError(L"QueryServiceConfigW failed"));
            }

            if (!pConfig->lpBinaryPathName || wcslen(pConfig->lpBinaryPathName) == 0) {
                return std::unexpected(Core::SystemError(Core::ErrorCode::PathNotFound, 0, L"Empty service binary path"));
            }

            std::wstring rawPath = pConfig->lpBinaryPathName;

            // Handle quoted executable paths: "C:\Program Files\Riot\vgc.exe" -service
            std::wstring cleanPath;
            if (rawPath.front() == L'\"') {
                size_t secondQuote = rawPath.find(L'\"', 1);
                cleanPath = (secondQuote != std::wstring::npos) ? rawPath.substr(1, secondQuote - 1) : rawPath.substr(1);
            } else {
                size_t firstSpace = rawPath.find(L' ');
                cleanPath = (firstSpace != std::wstring::npos) ? rawPath.substr(0, firstSpace) : rawPath;
            }

            // Strip NT object manager namespace prefix: \??\C:\... -> C:\...
            if (cleanPath.starts_with(L"\\??\\")) {
                cleanPath = cleanPath.substr(4);
            } else if (cleanPath.starts_with(L"\\SystemRoot\\")) {
                WCHAR szWinDir[MAX_PATH];
                if (::GetWindowsDirectoryW(szWinDir, MAX_PATH) > 0) {
                    cleanPath = std::wstring(szWinDir) + cleanPath.substr(11);
                }
            }

            // Expand environment variables (e.g. %SystemRoot%\System32\...)
            WCHAR szExpanded[MAX_PATH];
            if (::ExpandEnvironmentStringsW(cleanPath.c_str(), szExpanded, MAX_PATH) > 0) {
                cleanPath = szExpanded;
            }

            return std::filesystem::path(cleanPath);
        }

        /// @brief Surgical teardown of a kernel driver service and associated disk binary.
        /// Resolves VTX-SYS-008 by bypassing stop deadlocks on un-stoppable drivers.
        static Core::Result<bool> StopAndPurgeService(std::wstring_view serviceName, DWORD timeoutMs = 5000) {
            std::wstring sName(serviceName);
            Core::CAppLogger::LogInfo(L"SCM", std::format(L"Initiating capability-aware teardown of service '{}'", sName));

            std::filesystem::path resolvedBinaryPath;

            Core::ScopedSCMHandle hSCM(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
            if (!hSCM.IsValid()) {
                hSCM = Core::ScopedSCMHandle(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE));
            }

            if (hSCM.IsValid()) {
                Core::ScopedSCMHandle hService(::OpenServiceW(
                    hSCM.Get(),
                    sName.c_str(),
                    SERVICE_STOP | SERVICE_CHANGE_CONFIG | DELETE | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG
                ));

                if (hService.IsValid()) {
                    // Step 1: Authoritatively resolve binary disk path (VTX-SYS-009)
                    auto pathRes = ResolveCanonicalImagePath(hService.Get());
                    if (pathRes) {
                        resolvedBinaryPath = *pathRes;
                        Core::CAppLogger::LogTrace(L"SCM", std::format(L"Resolved canonical binary path: '{}'", resolvedBinaryPath.wstring()));
                    }

                    // Step 2: Stop dependent child services first
                    StopDependentServices(hSCM.Get(), hService.Get(), timeoutMs);

                    // Step 3: Query driver capabilities (VTX-SYS-008)
                    SERVICE_STATUS_PROCESS ssp{};
                    DWORD dwBytesNeeded = 0;
                    if (::QueryServiceStatusEx(hService.Get(), SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &dwBytesNeeded)) {
                        bool canAcceptStop = (ssp.dwControlsAccepted & SERVICE_ACCEPT_STOP) != 0;

                        if (!canAcceptStop) {
                            // STRICT RESOLUTION FOR VTX-SYS-008:
                            // Tier-1 anti-cheat drivers (vgk.sys) intentionally omit DriverUnload routines.
                            // Calling ControlService will deadlock or fail; bypass the 5-second polling loop immediately!
                            Core::CAppLogger::LogInfo(L"SCM", std::format(
                                L"Driver service '{}' does NOT advertise SERVICE_ACCEPT_STOP. Bypassing stop polling; scheduling boot eviction.", sName));
                        } else {
                            if (ssp.dwCurrentState != SERVICE_STOPPED && ssp.dwCurrentState != SERVICE_STOP_PENDING) {
                                SERVICE_STATUS status{};
                                ::ControlService(hService.Get(), SERVICE_CONTROL_STOP, &status);
                            }

                            auto startTime = std::chrono::steady_clock::now();
                            while (ssp.dwCurrentState != SERVICE_STOPPED) {
                                DWORD sleepTime = (ssp.dwWaitHint / 10 == 0) ? 100 : (ssp.dwWaitHint / 10);
                                if (sleepTime > 500) sleepTime = 500;
                                std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));

                                if (!::QueryServiceStatusEx(hService.Get(), SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &dwBytesNeeded)) {
                                    break;
                                }

                                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startTime).count();
                                if (elapsed > timeoutMs) break;
                            }
                        }
                    }

                    // Step 4: Force start configuration to DISABLED
                    ::ChangeServiceConfigW(
                        hService.Get(),
                        SERVICE_NO_CHANGE,
                        SERVICE_DISABLED,
                        SERVICE_NO_CHANGE,
                        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr
                    );

                    // Step 5: Mark service for deletion
                    if (::DeleteService(hService.Get())) {
                        Core::CAppLogger::LogInfo(L"SCM", std::format(L"DeleteService succeeded for '{}'", sName));
                    } else {
                        DWORD err = ::GetLastError();
                        Core::CAppLogger::LogWarn(L"SCM", std::format(L"DeleteService marked for reboot (Code 0x{:08X})", err), err);
                    }
                }
            }

            // Step 6: Forceful Registry DACL Seizure & Key Wipe Fallback
            Security::CRegistryDaclManager::ForceDeleteServiceKey(sName);

            // Step 7: Sanitize and Purge the authoritative binary (VTX-SYS-009)
            if (!resolvedBinaryPath.empty()) {
                (void)Storage::CNistSanitizer::SanitizeAndPurgeFile(resolvedBinaryPath);
            } else {
                // Fallback check in System32\drivers
                WCHAR szWinDir[MAX_PATH];
                if (::GetWindowsDirectoryW(szWinDir, MAX_PATH) > 0) {
                    std::filesystem::path sysFallback = std::filesystem::path(szWinDir) / L"System32" / L"drivers" / (sName + L".sys");
                    (void)Storage::CNistSanitizer::SanitizeAndPurgeFile(sysFallback);
                }
            }

            return true;
        }

    private:
        static void StopDependentServices(SC_HANDLE hSCM, SC_HANDLE hService, DWORD timeoutMs) {
            DWORD dwBytesNeeded = 0;
            DWORD dwCount = 0;

            if (!::EnumDependentServicesW(hService, SERVICE_ACTIVE, nullptr, 0, &dwBytesNeeded, &dwCount)) {
                if (::GetLastError() != ERROR_MORE_DATA) return;
            }

            if (dwBytesNeeded == 0) return;

            std::vector<BYTE> buffer(dwBytesNeeded);
            auto* lpDeps = reinterpret_cast<LPENUM_SERVICE_STATUSW>(buffer.data());

            if (::EnumDependentServicesW(hService, SERVICE_ACTIVE, lpDeps, dwBytesNeeded, &dwBytesNeeded, &dwCount)) {
                for (DWORD i = 0; i < dwCount; ++i) {
                    // Strictly resolve VTX-AUDIT-011: Gate dependent service teardown via binary verification
                    // Prevent accidental collateral damage or purging of legitimate shared system services
                    bool isTarget = false;
                    Core::ScopedSCMHandle hDep(::OpenServiceW(hSCM, lpDeps[i].lpServiceName, SERVICE_QUERY_CONFIG));
                    if (hDep.IsValid()) {
                        auto pathRes = ResolveCanonicalImagePath(hDep.Get());
                        if (pathRes && Security::CBinaryTrustEvaluator::IsTargetAntiCheatBinary(*pathRes)) {
                            isTarget = true;
                        }
                    }

                    if (isTarget) {
                        (void)StopAndPurgeService(lpDeps[i].lpServiceName, timeoutMs);
                    } else {
                        Core::CAppLogger::LogInfo(L"SCM", std::format(
                            L"Dependent service '{}' is NOT a verified target component; skipping teardown to preserve system integrity.",
                            lpDeps[i].lpServiceName));
                    }
                }
            }
        }
    };

} // namespace WinTracePurge::Drivers
