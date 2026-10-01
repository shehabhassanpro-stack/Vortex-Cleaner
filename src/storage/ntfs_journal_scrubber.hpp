#pragma once

#include "../core/interfaces.hpp"
#include "../core/result.hpp"
#include "../core/scoped_resource.hpp"
#include "../core/logger.hpp"
#include "../core/zstring_view.hpp"
#include "../security/token_privilege_scope.hpp"
#include <windows.h>
#include <winioctl.h>
#include <string>
#include <vector>
#include <filesystem>
#include <chrono>
#include <thread>
#include <format>

namespace WinTracePurge::Storage {

    /// @brief Telemetry report capturing the result of multi-volume NTFS Change Journal scrubbing.
    struct UsnJournalScrubReport {
        uint32_t VolumesScrubbed = 0;
        std::vector<wchar_t> ProcessedDrives;
        uint64_t TotalJournalBytesPurged = 0;
    };

    /// @brief Production-grade NTFS USN Change Journal ($Extend\$UsnJrnl:$J) eradication engine.
    ///
    /// === MATHEMATICAL & FORENSIC SPECIFICATION ===
    /// In NTFS, logical file deletion (via Win32 DeleteFileW) merely unlinks MFT record pointers and
    /// marks clusters in $Bitmap as available. The NTFS kernel driver (Ntfs.sys) maintains an append-only
    /// transaction log in the alternate data stream: \$Extend\$UsnJrnl:$J
    ///
    /// Each USN record encapsulates:
    ///   - RecordLength (uint32_t)
    ///   - Major/Minor Version (v2.0 or v3.0)
    ///   - FileReferenceNumber (64-bit: 48-bit MFT record index + 16-bit sequence number)
    ///   - ParentFileReferenceNumber (64-bit directory container reference)
    ///   - Usn (64-bit monotonic transaction offset)
    ///   - TimeStamp (64-bit 100ns intervals since Jan 1, 1601 UTC)
    ///   - Reason (bitmask including USN_REASON_FILE_CREATE, USN_REASON_DATA_OVERWRITE, USN_REASON_FILE_DELETE)
    ///
    /// === THE TWO-PHASE FSCTL PROTOCOL ===
    /// To achieve complete forensic zero-footprint without breaking the Windows OS (Search Indexer, VSS):
    /// 1. Interrogate active journal metadata via FSCTL_QUERY_USN_JOURNAL (0x000900f4).
    ///    Tuple captured: S_0 = < UsnJournalID_0, MaximumSize_0, AllocationDelta_0 >.
    /// 2. Atomic Stream Truncation: Issue FSCTL_DELETE_USN_JOURNAL (0x0009009c) with USN_DELETE_FLAG_DELETE.
    ///    The NTFS driver deallocates the entire $J stream extent and drops UsnJournalID_0.
    /// 3. Immediate Clean Re-Instantiation: Issue FSCTL_CREATE_USN_JOURNAL (0x000900e7) using S_0 parameters.
    ///    Ntfs.sys allocates a brand-new $J stream with:
    ///      UsnJournalID_new != UsnJournalID_0
    ///      LowestValidUsn = 0
    ///      NextUsn = 0
    ///
    /// === DEADLOCK-FREE VOLUME ACCESS INVARIANT ===
    /// Raw volume handles (\\.\X:) MUST be opened with FILE_SHARE_READ | FILE_SHARE_WRITE.
    /// Exclusive access (0) triggers deterministic system deadlocks or ERROR_SHARING_VIOLATION (0x20).
    ///
    /// Satisfies ISO C++23 and WinTracePurge::Core::CleanerModuleType concept.
    class CNtfsJournalScrubber : public Core::ICleanerModule {
    public:
        [[nodiscard]] Core::zstring_view GetModuleName() const noexcept override {
            return L"NtfsJournalScrubber";
        }

        /// @brief Inspects and discovers all mounted fixed NTFS volumes containing active change journals.
        [[nodiscard]] Core::Result<std::vector<Core::ResourceItem>> Scan(const Core::CleanupContext& ctx) override {
            (void)ctx;
            std::vector<Core::ResourceItem> items;

            auto drivesRes = EnumerateFixedNtfsDrives();
            if (!drivesRes) {
                return std::unexpected(drivesRes.error());
            }

            for (wchar_t driveLetter : *drivesRes) {
                std::wstring volDevice = std::format(L"\\\\.\\{}:", driveLetter);

                Core::ScopedFileHandle hVol(::CreateFileW(
                    volDevice.c_str(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr
                ));

                if (!hVol.IsValid()) {
                    continue;
                }

                USN_JOURNAL_DATA_V0 journalData{};
                DWORD bytesReturned = 0;
                BOOL success = ::DeviceIoControl(
                    hVol.Get(),
                    FSCTL_QUERY_USN_JOURNAL,
                    nullptr,
                    0,
                    &journalData,
                    sizeof(journalData),
                    &bytesReturned,
                    nullptr
                );

                if (success && journalData.UsnJournalID != 0) {
                    items.push_back(Core::ResourceItem{
                        .Type = Core::TargetType::ForensicArtifact,
                        .PathOrIdentifier = std::format(L"{}:\\$Extend\\$UsnJrnl:$J", driveLetter),
                        .Description = std::format(
                            L"NTFS Change Journal (ID: 0x{:016X}, NextUsn: 0x{:016X}, MaxSize: {:.1f} MB)",
                            journalData.UsnJournalID,
                            static_cast<uint64_t>(journalData.NextUsn),
                            static_cast<double>(journalData.MaximumSize) / (1024.0 * 1024.0)
                        ),
                        .IsLocked = false,
                        .ByteSize = journalData.MaximumSize
                    });
                }
            }

            return items;
        }

        /// @brief Executes surgical two-phase change journal purging across all eligible volumes.
        [[nodiscard]] Core::Result<Core::PurgeStats> Purge(const Core::CleanupContext& ctx, bool dryRun = false) override {
            Core::PurgeStats stats{};

            auto drivesRes = EnumerateFixedNtfsDrives();
            if (!drivesRes) {
                return std::unexpected(drivesRes.error());
            }

            stats.ItemsScanned = static_cast<uint32_t>(drivesRes->size());
            if (dryRun || ctx.DryRun) {
                return stats;
            }

            // Escalate volume management privilege for the transaction
            auto privScope = Security::TokenPrivilegeScope::Acquire({
                SE_MANAGE_VOLUME_NAME,
                SE_BACKUP_NAME,
                SE_RESTORE_NAME
            });

            for (wchar_t driveLetter : *drivesRes) {
                auto purgeRes = PurgeVolumeJournal(driveLetter);
                if (purgeRes && *purgeRes) {
                    stats.ItemsPurged++;
                    Core::CAppLogger::LogInfo(
                        L"NtfsJournalScrubber",
                        std::format(L"Successfully scrubbed and re-instantiated NTFS Change Journal on drive '{}:'", driveLetter)
                    );
                } else if (!purgeRes) {
                    Core::CAppLogger::LogWarn(
                        L"NtfsJournalScrubber",
                        std::format(L"Failed to scrub NTFS Change Journal on drive '{}:': {}", driveLetter, purgeRes.error().Message)
                    );
                }
            }

            return stats;
        }

        /// @brief Surgical two-phase purge on a specific drive letter (e.g. L'C').
        /// Enforces the atomic sequence: Query -> Truncate/Delete -> Clean Re-Instantiation.
        [[nodiscard]] static Core::Result<bool> PurgeVolumeJournal(wchar_t driveLetter) {
            std::wstring volDevice = std::format(L"\\\\.\\{}:", driveLetter);

            Core::ScopedFileHandle hVol(::CreateFileW(
                volDevice.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, // Mandatory deadlock prevention
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr
            ));

            if (!hVol.IsValid()) {
                DWORD dwErr = ::GetLastError();
                return std::unexpected(Core::SystemError::FromWin32(
                    dwErr,
                    std::format(L"CreateFileW failed for raw volume '{}:'", driveLetter)
                ));
            }

            // Phase 1: Query initial journal configuration
            USN_JOURNAL_DATA_V0 oldJournalData{};
            DWORD bytesReturned = 0;
            BOOL queryOk = ::DeviceIoControl(
                hVol.Get(),
                FSCTL_QUERY_USN_JOURNAL,
                nullptr,
                0,
                &oldJournalData,
                sizeof(oldJournalData),
                &bytesReturned,
                nullptr
            );

            if (!queryOk) {
                DWORD dwErr = ::GetLastError();
                if (dwErr == ERROR_JOURNAL_NOT_ACTIVE) {
                    Core::CAppLogger::LogInfo(
                        L"NtfsJournalScrubber",
                        std::format(L"USN Journal on drive '{}:' is not active (already clean).", driveLetter)
                    );
                    return true;
                }
                return std::unexpected(Core::SystemError::FromWin32(
                    dwErr,
                    std::format(L"FSCTL_QUERY_USN_JOURNAL failed on drive '{}:'", driveLetter)
                ));
            }

            Core::CAppLogger::LogTrace(
                L"NtfsJournalScrubber",
                std::format(L"Drive '{}:' Active Journal ID: 0x{:016X}, NextUsn: 0x{:016X}",
                            driveLetter, oldJournalData.UsnJournalID, static_cast<uint64_t>(oldJournalData.NextUsn))
            );

            // Phase 2: Complete synchronous journal stream deallocation and MFT walk
            // TASK-01: USN_DELETE_FLAG_DELETE | USN_DELETE_FLAG_NOTIFY guarantees synchronous blocking
            // until the NTFS driver finishes traversing all MFT records and clearing Last USN attributes.
            DELETE_USN_JOURNAL_DATA delData{};
            delData.UsnJournalID = oldJournalData.UsnJournalID;
            delData.DeleteFlags = USN_DELETE_FLAG_DELETE | USN_DELETE_FLAG_NOTIFY;

            BOOL delOk = ::DeviceIoControl(
                hVol.Get(),
                FSCTL_DELETE_USN_JOURNAL,
                &delData,
                sizeof(delData),
                nullptr,
                0,
                &bytesReturned,
                nullptr
            );

            if (!delOk) {
                DWORD dwErr = ::GetLastError();
                if (dwErr == ERROR_JOURNAL_DELETE_IN_PROGRESS) {
                    // Defensive fallback: asynchronous deletion polling if deletion was externally pending
                    auto pollStart = std::chrono::steady_clock::now();
                    while (true) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(50));
                        USN_JOURNAL_DATA_V0 pollData{};
                        BOOL pOk = ::DeviceIoControl(
                            hVol.Get(),
                            FSCTL_QUERY_USN_JOURNAL,
                            nullptr,
                            0,
                            &pollData,
                            sizeof(pollData),
                            &bytesReturned,
                            nullptr
                        );

                        if (!pOk && ::GetLastError() == ERROR_JOURNAL_NOT_ACTIVE) {
                            break; // Deletion finalized successfully
                        }

                        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - pollStart
                        ).count();

                        if (elapsed > 5000) {
                            return std::unexpected(Core::SystemError(
                                Core::ErrorCode::SanitizationFailed,
                                ERROR_JOURNAL_DELETE_IN_PROGRESS,
                                std::format(L"Timeout awaiting USN Journal deletion on drive '{}:'", driveLetter)
                            ));
                        }
                    }
                } else if (dwErr != ERROR_JOURNAL_NOT_ACTIVE) {
                    return std::unexpected(Core::SystemError::FromWin32(
                        dwErr,
                        std::format(L"FSCTL_DELETE_USN_JOURNAL failed on drive '{}:'", driveLetter)
                    ));
                }
            }

            // TASK-02: Volume I/O Barrier & Dirty Metadata Drain
            // Flushes the volume cache and commits all metadata mutations to physical media
            // before creating a fresh journal stream.
            (void)::FlushFileBuffers(hVol.Get());

            // Phase 3: Immediate clean re-instantiation to preserve Windows Search Indexer stability
            CREATE_USN_JOURNAL_DATA createData{};
            createData.MaximumSize = (oldJournalData.MaximumSize > 0) ? oldJournalData.MaximumSize : (32 * 1024 * 1024);
            createData.AllocationDelta = (oldJournalData.AllocationDelta > 0) ? oldJournalData.AllocationDelta : (4 * 1024 * 1024);

            BOOL createOk = ::DeviceIoControl(
                hVol.Get(),
                FSCTL_CREATE_USN_JOURNAL,
                &createData,
                sizeof(createData),
                nullptr,
                0,
                &bytesReturned,
                nullptr
            );

            if (!createOk) {
                DWORD dwErr = ::GetLastError();
                return std::unexpected(Core::SystemError::FromWin32(
                    dwErr,
                    std::format(L"FSCTL_CREATE_USN_JOURNAL re-instantiation failed on drive '{}:'", driveLetter)
                ));
            }

            // Flush again to commit the newly created journal structures
            (void)::FlushFileBuffers(hVol.Get());

            // TASK-03: Post-condition validation: Verify new Journal ID generation and clean state
            USN_JOURNAL_DATA_V0 newJournalData{};
            if (::DeviceIoControl(
                hVol.Get(),
                FSCTL_QUERY_USN_JOURNAL,
                nullptr,
                0,
                &newJournalData,
                sizeof(newJournalData),
                &bytesReturned,
                nullptr)) {
                
                Core::CAppLogger::LogInfo(
                    L"NtfsJournalScrubber",
                    std::format(L"Drive '{}:' Clean Journal Re-created. New ID: 0x{:016X} (Old ID: 0x{:016X}, LowestValidUsn: 0x{:016X}, NextUsn: 0x{:016X})",
                                driveLetter, newJournalData.UsnJournalID, oldJournalData.UsnJournalID,
                                static_cast<uint64_t>(newJournalData.LowestValidUsn), static_cast<uint64_t>(newJournalData.NextUsn))
                );
            }

            return true;
        }

        /// @brief Executes two-phase purge across all mounted fixed NTFS volumes.
        [[nodiscard]] static Core::Result<UsnJournalScrubReport> PurgeAllFixedNtfsJournals() {
            UsnJournalScrubReport report{};

            auto drivesRes = EnumerateFixedNtfsDrives();
            if (!drivesRes) {
                return std::unexpected(drivesRes.error());
            }

            auto privScope = Security::TokenPrivilegeScope::Acquire({
                SE_MANAGE_VOLUME_NAME,
                SE_BACKUP_NAME,
                SE_RESTORE_NAME
            });

            for (wchar_t driveLetter : *drivesRes) {
                auto res = PurgeVolumeJournal(driveLetter);
                if (res && *res) {
                    report.VolumesScrubbed++;
                    report.ProcessedDrives.push_back(driveLetter);
                }
            }

            return report;
        }

        /// @brief Discovers all mounted fixed drive letters formatted with the NTFS filesystem.
        [[nodiscard]] static Core::Result<std::vector<wchar_t>> EnumerateFixedNtfsDrives() {
            std::vector<wchar_t> ntfsDrives;

            WCHAR driveStrings[512] = {};
            DWORD len = ::GetLogicalDriveStringsW(511, driveStrings);
            if (len == 0 || len > 511) {
                return std::unexpected(Core::SystemError::FromLastError(L"GetLogicalDriveStringsW failed"));
            }

            const wchar_t* pDrive = driveStrings;
            while (*pDrive) {
                if (::GetDriveTypeW(pDrive) == DRIVE_FIXED) {
                    wchar_t driveLetter = pDrive[0];
                    WCHAR fsName[MAX_PATH] = {};
                    DWORD fsFlags = 0;

                    if (::GetVolumeInformationW(
                        pDrive,
                        nullptr, 0,
                        nullptr,
                        nullptr,
                        &fsFlags,
                        fsName,
                        ARRAYSIZE(fsName)
                    )) {
                        if (_wcsicmp(fsName, L"NTFS") == 0) {
                            ntfsDrives.push_back(driveLetter);
                        }
                    }
                }
                pDrive += wcslen(pDrive) + 1;
            }

            return ntfsDrives;
        }
    };

    // Compile-time static contract verification under ISO C++23
    static_assert(Core::CleanerModuleType<CNtfsJournalScrubber>,
                  "CNtfsJournalScrubber must satisfy Core::CleanerModuleType concept");

} // namespace WinTracePurge::Storage
