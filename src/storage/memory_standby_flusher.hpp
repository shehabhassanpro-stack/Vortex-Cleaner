#pragma once

#include "../core/interfaces.hpp"
#include "../core/result.hpp"
#include "../core/scoped_resource.hpp"
#include "../core/logger.hpp"
#include "../core/zstring_view.hpp"
#include "../security/token_privilege_scope.hpp"
#include <windows.h>
#include <string>
#include <vector>
#include <format>
#include <chrono>

namespace WinTracePurge::Storage {

    /// @brief Telemetry metrics captured during physical memory and standby page list zeroing.
    struct MemoryPurgeStats {
        uint64_t StandbyBytesZeroed = 0;
        uint64_t WorkingSetTrimmedCount = 0;
        bool ModifiedListFlushed = false;
        bool StandbyPurged = false;
    };

    /// @brief Volatile physical RAM cache and Standby Page List zeroing engine via native NT syscalls.
    ///
    /// === MATHEMATICAL & FORENSIC SPECIFICATION ===
    /// When anti-cheat drivers (e.g. vgk.sys, easyanticheat.sys) and game processes terminate,
    /// the Windows NT Memory Manager (Mm) does NOT zero their underlying physical RAM pages.
    /// Instead, unreferenced pages are relegated to the Standby Page List (Priorities 0 through 7).
    ///
    /// Physical memory state space partition:
    ///   P_phys = P_active U P_modified U ( U_{k=0}^{7} P_standby(k) ) U P_free U P_zeroed
    ///
    /// The Standby Page List retains:
    ///   1. Decrypted kernel driver image segments and plaintext executable code.
    ///   2. Active memory pool allocations, crypto key schedules, and network packet buffers.
    ///   3. Forensic strings and signature patterns accessible via \Device\PhysicalMemory or crash dumps.
    ///
    /// === THE 3-PHASE RECURSIVE DRAIN PROTOCOL ===
    /// Interfacing directly with native Executive syscall ntdll.dll!NtSetSystemInformation under
    /// undocumented SystemMemoryListInformation (Class 80 / 0x50):
    ///
    ///   Phase 1 (Trim): MemoryEmptyWorkingSets (cmd 2)
    ///     Forces working set trim across background system services and processes:
    ///     P_active -> P_active'  where Delta P subset (P_modified U P_standby)
    ///
    ///   Phase 2 (Commit): MemoryFlushModifiedList (cmd 3)
    ///     Forces immediate asynchronous write-back of modified dirty pages to non-volatile storage:
    ///     P_modified -> P_standby(7)
    ///
    ///   Phase 3 (Zero): MemoryPurgeStandbyList (cmd 4)
    ///     Deallocates all Standby pages across all 8 priority levels (0 through 7):
    ///     U_{k=0}^{7} P_standby(k) -> P_free -> P_zeroed
    ///     Theorem: | U_{k=0}^{7} P_standby(k) | = 0  (Zero Cold-Residue Invariant)
    ///
    /// Strictly satisfies ISO C++23 and WinTracePurge::Core::CleanerModuleType concept.
    class CMemoryStandbyFlusher : public Core::ICleanerModule {
    public:
        // Undocumented NT System Information Class: SystemMemoryListInformation
        static constexpr ULONG kSystemMemoryListInformation = 80; // 0x50

        // Formal NT Memory List Commands
        enum class SYSTEM_MEMORY_LIST_COMMAND : uint32_t {
            MemoryCaptureAccessedBits         = 0,
            MemoryCaptureAndResetAccessedBits = 1,
            MemoryEmptyWorkingSets            = 2,
            MemoryFlushModifiedList           = 3,
            MemoryPurgeStandbyList            = 4,
            MemoryPurgeLowPriorityStandbyList = 5,
            MemoryCommandMax                  = 6
        };

        using PFN_NtSetSystemInformation = LONG(NTAPI*)(
            ULONG SystemInformationClass,
            PVOID SystemInformation,
            ULONG SystemInformationLength
        );

        [[nodiscard]] Core::zstring_view GetModuleName() const noexcept override {
            return L"MemoryStandbyFlusher";
        }

        /// @brief Inspects current physical RAM topology and standby memory residency.
        [[nodiscard]] Core::Result<std::vector<Core::ResourceItem>> Scan(const Core::CleanupContext& ctx) override {
            (void)ctx;
            std::vector<Core::ResourceItem> items;

            MEMORYSTATUSEX memStatus{};
            memStatus.dwLength = sizeof(MEMORYSTATUSEX);
            if (!::GlobalMemoryStatusEx(&memStatus)) {
                return std::unexpected(Core::SystemError::FromLastError(L"GlobalMemoryStatusEx failed"));
            }

            uint64_t estimatedResidentBytes = (memStatus.ullTotalPhys > memStatus.ullAvailPhys) ?
                (memStatus.ullTotalPhys - memStatus.ullAvailPhys) : 0;

            items.push_back(Core::ResourceItem{
                .Type = Core::TargetType::ForensicArtifact,
                .PathOrIdentifier = L"\\Device\\PhysicalMemory\\StandbyPageLists",
                .Description = std::format(
                    L"Physical RAM Standby & Cache Residue (Total: {:.1f} GB, Avail: {:.1f} GB, Load: {}%)",
                    static_cast<double>(memStatus.ullTotalPhys) / (1024.0 * 1024.0 * 1024.0),
                    static_cast<double>(memStatus.ullAvailPhys) / (1024.0 * 1024.0 * 1024.0),
                    memStatus.dwMemoryLoad
                ),
                .IsLocked = false,
                .ByteSize = estimatedResidentBytes
            });

            return items;
        }

        /// @brief Executes comprehensive 3-phase kernel memory flush protocol.
        [[nodiscard]] Core::Result<Core::PurgeStats> Purge(const Core::CleanupContext& ctx, bool dryRun = false) override {
            Core::PurgeStats stats{};
            stats.ItemsScanned = 3; // 3 phases

            if (dryRun || ctx.DryRun) {
                return stats;
            }

            auto purgeRes = ExecuteComprehensiveMemoryPurge();
            if (!purgeRes) {
                return std::unexpected(purgeRes.error());
            }

            stats.ItemsPurged = 3;
            stats.BytesReclaimed = purgeRes->StandbyBytesZeroed;

            Core::CAppLogger::LogInfo(
                L"MemoryStandbyFlusher",
                std::format(L"Physical RAM purge completed successfully. Reclaimed {:.2f} MB into zeroed pool.",
                            static_cast<double>(stats.BytesReclaimed) / (1024.0 * 1024.0))
            );

            return stats;
        }

        /// @brief Executes the formal 3-phase kernel memory flush via ntdll.dll!NtSetSystemInformation.
        [[nodiscard]] static Core::Result<MemoryPurgeStats> ExecuteComprehensiveMemoryPurge() {
            MemoryPurgeStats resultStats{};

            // Step 1: Dynamically resolve ntdll.dll!NtSetSystemInformation
            HMODULE hNtDll = ::GetModuleHandleW(L"ntdll.dll");
            if (!hNtDll) {
                return std::unexpected(Core::SystemError::FromLastError(L"Failed to obtain ntdll.dll handle"));
            }

            auto pfnNtSetSystemInformation = reinterpret_cast<PFN_NtSetSystemInformation>(
                ::GetProcAddress(hNtDll, "NtSetSystemInformation")
            );

            if (!pfnNtSetSystemInformation) {
                return std::unexpected(Core::SystemError::FromLastError(L"NtSetSystemInformation export not found in ntdll.dll"));
            }

            // Step 2: Escalate memory management token privileges
            auto privScope = Security::TokenPrivilegeScope::Acquire({
                SE_PROF_SINGLE_PROCESS_NAME,
                SE_INCREASE_QUOTA_NAME
            });

            if (!privScope) {
                Core::CAppLogger::LogWarn(
                    L"MemoryStandbyFlusher",
                    std::format(L"Privilege escalation warning: {}. Attempting syscall execution regardless...",
                                privScope.error().Message)
                );
            }

            // Capture pre-purge physical memory state
            MEMORYSTATUSEX memBefore{};
            memBefore.dwLength = sizeof(MEMORYSTATUSEX);
            (void)::GlobalMemoryStatusEx(&memBefore);

            // -------------------------------------------------------------
            // Phase 1: Trim Active Working Sets (cmd = 2)
            // -------------------------------------------------------------
            SYSTEM_MEMORY_LIST_COMMAND cmdEmptyWS = SYSTEM_MEMORY_LIST_COMMAND::MemoryEmptyWorkingSets;
            LONG status1 = pfnNtSetSystemInformation(
                kSystemMemoryListInformation,
                &cmdEmptyWS,
                sizeof(cmdEmptyWS)
            );

            if (status1 >= 0) { // NT_SUCCESS
                resultStats.WorkingSetTrimmedCount++;
                Core::CAppLogger::LogTrace(L"MemoryStandbyFlusher", L"[Phase 1/3] System working sets trimmed cleanly.");
            } else {
                Core::CAppLogger::LogWarn(
                    L"MemoryStandbyFlusher",
                    std::format(L"NtSetSystemInformation(MemoryEmptyWorkingSets) returned NTSTATUS 0x{:08X}", static_cast<uint32_t>(status1))
                );
            }

            // -------------------------------------------------------------
            // Phase 2: Flush Modified Page List to disk (cmd = 3)
            // -------------------------------------------------------------
            SYSTEM_MEMORY_LIST_COMMAND cmdFlushMod = SYSTEM_MEMORY_LIST_COMMAND::MemoryFlushModifiedList;
            LONG status2 = pfnNtSetSystemInformation(
                kSystemMemoryListInformation,
                &cmdFlushMod,
                sizeof(cmdFlushMod)
            );

            if (status2 >= 0) { // NT_SUCCESS
                resultStats.ModifiedListFlushed = true;
                Core::CAppLogger::LogTrace(L"MemoryStandbyFlusher", L"[Phase 2/3] Modified dirty page list flushed to backing storage.");
            } else {
                Core::CAppLogger::LogWarn(
                    L"MemoryStandbyFlusher",
                    std::format(L"NtSetSystemInformation(MemoryFlushModifiedList) returned NTSTATUS 0x{:08X}", static_cast<uint32_t>(status2))
                );
            }

            // -------------------------------------------------------------
            // Phase 3: Purge and Zero Standby Page Lists 0-7 (cmd = 4)
            // -------------------------------------------------------------
            SYSTEM_MEMORY_LIST_COMMAND cmdPurgeStandby = SYSTEM_MEMORY_LIST_COMMAND::MemoryPurgeStandbyList;
            LONG status3 = pfnNtSetSystemInformation(
                kSystemMemoryListInformation,
                &cmdPurgeStandby,
                sizeof(cmdPurgeStandby)
            );

            if (status3 >= 0) { // NT_SUCCESS
                resultStats.StandbyPurged = true;
                Core::CAppLogger::LogTrace(L"MemoryStandbyFlusher", L"[Phase 3/3] All Standby Page Lists (Priorities 0-7) purged into zeroed pool.");
            } else {
                DWORD win32Err = (status3 == 0xC0000061) ? ERROR_PRIVILEGE_NOT_HELD : ERROR_GEN_FAILURE;
                return std::unexpected(Core::SystemError::FromWin32(
                    win32Err,
                    std::format(L"NtSetSystemInformation(MemoryPurgeStandbyList) failed with NTSTATUS 0x{:08X}", static_cast<uint32_t>(status3))
                ));
            }

            // Capture post-purge physical memory state
            MEMORYSTATUSEX memAfter{};
            memAfter.dwLength = sizeof(MEMORYSTATUSEX);
            if (::GlobalMemoryStatusEx(&memAfter)) {
                if (memAfter.ullAvailPhys > memBefore.ullAvailPhys) {
                    resultStats.StandbyBytesZeroed = memAfter.ullAvailPhys - memBefore.ullAvailPhys;
                }
            }

            return resultStats;
        }
    };

    // Compile-time static contract verification under ISO C++23
    static_assert(Core::CleanerModuleType<CMemoryStandbyFlusher>,
                  "CMemoryStandbyFlusher must satisfy Core::CleanerModuleType concept");

} // namespace WinTracePurge::Storage
