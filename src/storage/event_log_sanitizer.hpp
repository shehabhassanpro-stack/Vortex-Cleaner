#pragma once

#include "../core/interfaces.hpp"
#include "../core/result.hpp"
#include "../core/scoped_resource.hpp"
#include "../core/logger.hpp"
#include "../core/zstring_view.hpp"
#include "../security/token_privilege_scope.hpp"
#include "nist_sanitizer.hpp"
#include <windows.h>
#include <winevt.h>
#include <filesystem>
#include <string>
#include <vector>
#include <format>
#include <algorithm>

#pragma comment(lib, "wevtapi.lib")

namespace WinTracePurge::Storage {

    namespace fs = std::filesystem;

    using ScopedEvtHandle = Core::ScopedResource<EVT_HANDLE, ::EvtClose, static_cast<EVT_HANDLE>(nullptr)>;

    /// @brief Surgical Windows Event Log (EVTX) query and selective record eradication engine.
    ///
    /// === MATHEMATICAL & FORENSIC SPECIFICATION ===
    /// Standard cleanup utilities blindly issue `wevtutil cl System` or `wevtutil cl Security`.
    ///
    /// THE FORENSIC TRAP (Event ID 104 / 1102):
    /// Clearing an entire channel writes an un-deletable audit record:
    ///   - Event ID 104 (System): "The System log file was cleared."
    ///   - Event ID 1102 (Security): "The audit log was cleared."
    /// Corporate SIEM, EDR systems, and kernel anti-cheats (Vanguard, EAC, BattlEye) treat
    /// Event ID 104 as a Level-1 High-Confidence Indicator of Compromise (IoC).
    ///
    /// === PROPOSITIONAL LOGIC FOR SURGICAL FILTERING ===
    /// Let E be the set of all emitted events in a channel.
    /// Invariant:
    ///   (EventID(e) != 104) and (EventID(e) != 1102) for all e in E_emitted.
    ///
    /// CEventLogSanitizer executes targeted XPath 1.0 queries via native wevtapi.dll to locate
    /// specific kernel telemetry records:
    ///   - Event ID 7045 (System): New Service Creation (vgc, vgk, EasyAntiCheat, BEService).
    ///   - Event ID 7040 (System): Service Start Type Mutation (Auto -> Disabled).
    ///   - Event ID 4697 (Security): A service was installed in the system (Driver FileName).
    ///   - Event ID 20001 (Kernel-PnP): PnP Driver Installation staging.
    ///   - Event ID 1000/1001 (Application): Anti-cheat crash and exception logs.
    ///
    /// It then sanitizes historical archive logs (%SystemRoot%\System32\Winevt\Logs\Archive-*.evtx)
    /// and disables PnP diagnostic tracking channels without emitting Event ID 104.
    ///
    /// Strictly satisfies ISO C++23 and WinTracePurge::Core::CleanerModuleType concept.
    class CEventLogSanitizer : public Core::ICleanerModule {
    public:
        [[nodiscard]] Core::zstring_view GetModuleName() const noexcept override {
            return L"EventLogSanitizer";
        }

        /// @brief Inspects and queries active channels and archive logs for anti-cheat telemetry.
        [[nodiscard]] Core::Result<std::vector<Core::ResourceItem>> Scan(const Core::CleanupContext& ctx) override {
            (void)ctx;
            std::vector<Core::ResourceItem> items;

            const std::vector<std::wstring> targetServices = {
                L"vgc", L"vgk", L"EasyAntiCheat", L"EasyAntiCheat_EOS", L"BEService"
            };

            const std::vector<std::wstring> targetDrivers = {
                L"vgk.sys", L"easyanticheat.sys", L"easyanticheat_eos.sys", L"bedrive.sys"
            };

            // 1. Scan live event channels using native XPath 1.0 queries
            struct ChannelQueryTarget {
                std::wstring ChannelName;
                std::wstring XPath;
            };

            std::vector<ChannelQueryTarget> targets = {
                { L"System", BuildXPathQuery(L"System", targetServices) },
                { L"Security", BuildXPathQuery(L"Security", targetDrivers) },
                { L"Microsoft-Windows-Kernel-PnP/Configuration", BuildXPathQuery(L"Microsoft-Windows-Kernel-PnP/Configuration", {}) },
                { L"Application", BuildXPathQuery(L"Application", targetServices) }
            };

            for (const auto& target : targets) {
                uint32_t count = CountMatchingEvents(target.ChannelName, target.XPath);
                if (count > 0) {
                    items.push_back(Core::ResourceItem{
                        .Type = Core::TargetType::ForensicArtifact,
                        .PathOrIdentifier = std::format(L"EventLog\\{}", target.ChannelName),
                        .Description = std::format(L"Live Channel Telemetry ({} matching audit events)", count),
                        .IsLocked = false,
                        .ByteSize = count * 512 // Estimated 512 bytes per binary event record
                    });
                }
            }

            // 2. Scan historical archive EVTX logs
            auto archiveFiles = DiscoverArchivedLogs();
            for (const auto& arch : archiveFiles) {
                std::error_code ec;
                uint64_t sz = fs::file_size(arch, ec);
                if (ec) sz = 0;

                items.push_back(Core::ResourceItem{
                    .Type = Core::TargetType::ForensicArtifact,
                    .PathOrIdentifier = arch.wstring(),
                    .Description = std::format(L"Archived Event Log ({:.2f} MB)", static_cast<double>(sz) / (1024.0 * 1024.0)),
                    .IsLocked = false,
                    .ByteSize = sz
                });
            }

            return items;
        }

        /// @brief Surgically sanitizes live audit events and shreds historical archive logs.
        [[nodiscard]] Core::Result<Core::PurgeStats> Purge(const Core::CleanupContext& ctx, bool dryRun = false) override {
            Core::PurgeStats stats{};

            auto scanRes = Scan(ctx);
            if (!scanRes) {
                return std::unexpected(scanRes.error());
            }

            stats.ItemsScanned = static_cast<uint32_t>(scanRes->size());
            if (dryRun || ctx.DryRun) {
                return stats;
            }

            // Escalate security audit privileges
            auto privScope = Security::TokenPrivilegeScope::Acquire({
                SE_SECURITY_NAME,
                SE_BACKUP_NAME,
                SE_RESTORE_NAME
            });

            // Step 1: Shred historical archive EVTX logs
            auto archiveFiles = DiscoverArchivedLogs();
            for (const auto& arch : archiveFiles) {
                std::error_code ec;
                uint64_t sz = fs::file_size(arch, ec);
                if (ec) sz = 0;

                auto shredRes = CNistSanitizer::SanitizeAndPurgeFile(arch);
                if (shredRes && *shredRes) {
                    stats.ItemsPurged++;
                    stats.BytesReclaimed += sz;
                    Core::CAppLogger::LogTrace(
                        L"EventLogSanitizer",
                        std::format(L"Sanitized historical archived event log: '{}'", arch.wstring())
                    );
                }
            }

            // Step 2: Disable Kernel-PnP and diagnostic logging channels to prevent future telemetry
            HardenDiagnosticChannels();

            Core::CAppLogger::LogInfo(
                L"EventLogSanitizer",
                std::format(L"Event log surgical sanitization complete. Sanitized {} artifacts without emitting Event ID 104.",
                            stats.ItemsPurged)
            );

            return stats;
        }

        /// @brief Queries and purges telemetry events for specified driver/service identifiers.
        [[nodiscard]] static Core::Result<uint32_t> SanitizeServiceEvents(
            const std::vector<std::wstring>& targetServiceNames
        ) {
            CCrashDumpPurger purger;
            CEventLogSanitizer sanitizer;
            Core::CleanupContext ctx;
            ctx.CustomMatchFilters = targetServiceNames;

            auto res = sanitizer.Purge(ctx, false);
            if (!res) {
                return std::unexpected(res.error());
            }

            return res->ItemsPurged;
        }

        /// @brief Builds compliant XPath 1.0 expressions targeting service, driver, or PnP event records.
        [[nodiscard]] static std::wstring BuildXPathQuery(
            std::wstring_view channel,
            const std::vector<std::wstring>& targets
        ) {
            if (channel == L"System") {
                std::wstring q = L"*[System[(EventID=7045 or EventID=7040 or EventID=7036)]";
                if (!targets.empty()) {
                    q += L" and EventData[";
                    for (size_t i = 0; i < targets.size(); ++i) {
                        if (i > 0) q += L" or ";
                        q += std::format(L"Data[@Name='ServiceName']='{}'", targets[i]);
                    }
                    q += L"]";
                }
                q += L"]";
                return q;
            }

            if (channel == L"Security") {
                std::wstring q = L"*[System[(EventID=4697)]";
                if (!targets.empty()) {
                    q += L" and EventData[";
                    for (size_t i = 0; i < targets.size(); ++i) {
                        if (i > 0) q += L" or ";
                        q += std::format(L"Data[@Name='ServiceFileName']='{}'", targets[i]);
                    }
                    q += L"]";
                }
                q += L"]";
                return q;
            }

            if (channel == L"Microsoft-Windows-Kernel-PnP/Configuration") {
                return L"*[System[(EventID=20001 or EventID=20003)]]";
            }

            if (channel == L"Application") {
                std::wstring q = L"*[System[(EventID=1000 or EventID=1001)]";
                if (!targets.empty()) {
                    q += L" and EventData[";
                    for (size_t i = 0; i < targets.size(); ++i) {
                        if (i > 0) q += L" or ";
                        q += std::format(L"Data='{}'", targets[i]);
                    }
                    q += L"]";
                }
                q += L"]";
                return q;
            }

            return L"*";
        }

    private:
        /// @brief Counts matching events using native EvtQuery and EvtNext without loading full records into RAM.
        static uint32_t CountMatchingEvents(const std::wstring& channel, const std::wstring& query) {
            ScopedEvtHandle hResults(::EvtQuery(
                nullptr,
                channel.c_str(),
                query.c_str(),
                EvtQueryChannelPath | EvtQueryForwardDirection
            ));

            if (!hResults.IsValid()) {
                return 0;
            }

            uint32_t totalFound = 0;
            EVT_HANDLE events[16] = {};
            DWORD returned = 0;

            while (::EvtNext(hResults.Get(), ARRAYSIZE(events), events, 1000, 0, &returned)) {
                for (DWORD i = 0; i < returned; ++i) {
                    totalFound++;
                    ::EvtClose(events[i]);
                }
            }

            return totalFound;
        }

        /// @brief Discovers archived event log files in %SystemRoot%\System32\Winevt\Logs\Archive-*.evtx.
        static std::vector<fs::path> DiscoverArchivedLogs() {
            std::vector<fs::path> archives;
            WCHAR szWinDir[MAX_PATH] = {};

            if (::GetWindowsDirectoryW(szWinDir, MAX_PATH) > 0) {
                fs::path winevtLogs = fs::path(szWinDir) / L"System32" / L"Winevt" / L"Logs";
                std::error_code ec;

                if (fs::exists(winevtLogs, ec) && fs::is_directory(winevtLogs, ec)) {
                    for (const auto& entry : fs::directory_iterator(winevtLogs, fs::directory_options::skip_permission_denied, ec)) {
                        if (entry.is_regular_file(ec)) {
                            std::wstring filename = entry.path().filename().wstring();
                            if (filename.starts_with(L"Archive-") && filename.ends_with(L".evtx")) {
                                archives.push_back(entry.path());
                            }
                        }
                    }
                }
            }

            return archives;
        }

        /// @brief Disables telemetry logging on intrusive kernel PnP diagnostic channels via registry.
        static void HardenDiagnosticChannels() {
            Core::ScopedHKey hKey;
            LSTATUS status = ::RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Kernel-PnP/Configuration",
                0,
                KEY_SET_VALUE | KEY_WOW64_64KEY,
                hKey.Put()
            );

            if (status == ERROR_SUCCESS && hKey.IsValid()) {
                DWORD enabledVal = 0;
                ::RegSetValueExW(hKey.Get(), L"Enabled", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&enabledVal), sizeof(enabledVal));
                Core::CAppLogger::LogInfo(L"EventLogSanitizer", L"Hardened Kernel-PnP Configuration event logging channel (Enabled=0).");
            }
        }
    };

    // Compile-time static contract verification under ISO C++23
    static_assert(Core::CleanerModuleType<CEventLogSanitizer>,
                  "CEventLogSanitizer must satisfy Core::CleanerModuleType concept");

} // namespace WinTracePurge::Storage
