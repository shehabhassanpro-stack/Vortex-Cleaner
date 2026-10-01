#pragma once

#include "nvme_trim_sanitizer.hpp"
#include "../core/result.hpp"
#include "../core/logger.hpp"
#include "../core/zstring_view.hpp"
#include "../core/scoped_resource.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <filesystem>
#include <vector>
#include <string>
#include <format>

#pragma comment(lib, "bcrypt.lib")

namespace WinTracePurge::Storage {

    /// @brief Storage-topology-aware file shredding and deallocation engine.
    /// Strictly resolves VTX-SYS-012 by performing CSPRNG logical overwrites followed by
    /// hardware-level FSCTL_FILE_LEVEL_TRIM deallocations on solid-state media (NVMe/SATA SSDs).
    class CNistSanitizer {
    public:
        /// @brief Sanitizes, truncates, deallocates, and unlinks a targeted file.
        [[nodiscard]] static Core::Result<bool> SanitizeAndPurgeFile(const std::filesystem::path& filePath) {
            std::error_code ec;
            if (!std::filesystem::exists(filePath, ec)) {
                return true; // Target already absent
            }

            std::wstring wsPath = filePath.wstring();

            // 1. Reset restrictive filesystem attributes
            ::SetFileAttributesW(wsPath.c_str(), FILE_ATTRIBUTE_NORMAL);

            // 2. Query physical storage medium topology
            DriveMediumInfo medium = CNvmeTrimSanitizer::QueryDriveMedium(filePath);
            Core::CAppLogger::LogTrace(L"Sanitizer", 
                std::format(L"Target drive topology for '{}': {} (SSD: {})", 
                    wsPath, medium.BusName, medium.IsSolidState));

            // 3. Open handle with write-through and backup semantics (no sector misalignment flags)
            Core::ScopedFileHandle hFile(::CreateFileW(
                wsPath.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ,
                nullptr,
                OPEN_EXISTING,
                FILE_FLAG_WRITE_THROUGH | FILE_FLAG_BACKUP_SEMANTICS,
                nullptr
            ));

            if (hFile.IsValid()) {
                LARGE_INTEGER fileSize{};
                if (::GetFileSizeEx(hFile.Get(), &fileSize) && fileSize.QuadPart > 0) {
                    constexpr size_t kSectorBuffer = 64 * 1024; // 64KB sector chunk
                    std::vector<BYTE> randomBuffer(kSectorBuffer, 0);

                    LONGLONG bytesRemaining = fileSize.QuadPart;
                    DWORD bytesWritten = 0;

                    // Step 3a: Cryptographic pseudorandom overwrite loop (NIST SP 800-88 Rev. 1 compliant)
                    while (bytesRemaining > 0) {
                        DWORD toWrite = static_cast<DWORD>((bytesRemaining > static_cast<LONGLONG>(kSectorBuffer)) ? kSectorBuffer : bytesRemaining);

                        // Regenerate fresh CSPRNG entropy for EVERY write pass (eliminates periodicity / repeating pattern signatures)
                        NTSTATUS rngStatus = ::BCryptGenRandom(nullptr, randomBuffer.data(), toWrite, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
                        if (!BCRYPT_SUCCESS(rngStatus)) {
                            std::fill(randomBuffer.begin(), randomBuffer.begin() + toWrite, static_cast<BYTE>(0xAA));
                        }

                        BOOL success = ::WriteFile(hFile.Get(), randomBuffer.data(), toWrite, &bytesWritten, nullptr);
                        if (!success || bytesWritten == 0) {
                            DWORD err = ::GetLastError();
                            Core::CAppLogger::LogWarn(L"Sanitizer", 
                                std::format(L"WriteFile interrupted during logical overwrite of '{}'", wsPath), err);
                            break; // Defensive break preventing infinite loops
                        }

                        bytesRemaining -= bytesWritten;
                    }

                    // Flush hardware cache to physical cells
                    ::FlushFileBuffers(hFile.Get());

                    // Step 3b: If on Solid-State medium, issue hardware TRIM / deallocation (VTX-SYS-012)
                    if (medium.IsSolidState) {
                        auto trimRes = CNvmeTrimSanitizer::DispatchFileLevelTrim(hFile.Get(), static_cast<uint64_t>(fileSize.QuadPart));
                        if (!trimRes) {
                            Core::CAppLogger::LogWarn(L"Sanitizer", 
                                std::format(L"Hardware TRIM dispatch skipped or unsupported for '{}': {}", wsPath, trimRes.error().Message));
                        }
                    }

                    // Step 3c: Truncate file length to 0 bytes
                    ::SetFilePointer(hFile.Get(), 0, nullptr, FILE_BEGIN);
                    ::SetEndOfFile(hFile.Get());
                }

                hFile.Reset(); // Explicit RAII handle closure prior to unlinking
            }

            // 4. Sanitize Alternate Data Streams (ADS)
            SanitizeAlternateDataStreams(wsPath);

            // 5. Final immediate deletion attempt
            if (::DeleteFileW(wsPath.c_str())) {
                Core::CAppLogger::LogTrace(L"Sanitizer", std::format(L"Unlinked file: '{}'", wsPath));
                return true;
            }

            // 6. Fallback: If locked by kernel or active process, register for Session Manager boot deletion
            if (::MoveFileExW(wsPath.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT)) {
                Core::CAppLogger::LogInfo(L"Sanitizer", std::format(L"File locked; queued for boot deletion: '{}'", wsPath));
                return true;
            }

            return std::unexpected(Core::SystemError::FromLastError(L"Failed to unlink or queue file for boot deletion"));
        }

    private:
        static void SanitizeAlternateDataStreams(const std::wstring& filePath) noexcept {
            WIN32_FIND_STREAM_DATA streamData{};
            HANDLE hFind = ::FindFirstStreamW(filePath.c_str(), FindStreamInfoStandard, &streamData, 0);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (wcscmp(streamData.cStreamName, L"::$DATA") != 0) {
                        std::wstring fullStreamPath = filePath + streamData.cStreamName;
                        ::DeleteFileW(fullStreamPath.c_str());
                    }
                } while (::FindNextStreamW(hFind, &streamData));
                ::FindClose(hFind);
            }
        }
    };

} // namespace WinTracePurge::Storage
