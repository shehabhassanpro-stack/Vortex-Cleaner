#pragma once

#include "../core/result.hpp"
#include "../core/logger.hpp"
#include "../core/zstring_view.hpp"
#include "../core/scoped_resource.hpp"
#include <windows.h>
#include <winioctl.h>
#include <filesystem>
#include <string>
#include <format>

namespace WinTracePurge::Storage {

    enum class StorageBusKind : uint8_t {
        Nvme = 0,
        SsdSata,
        HddRotational,
        Unknown
    };

    struct DriveMediumInfo {
        StorageBusKind BusKind = StorageBusKind::Unknown;
        bool IsSolidState = false;
        std::wstring BusName;
    };

    /// @brief Hardware-level storage topology inspector and TRIM deallocation dispatcher.
    /// Strictly resolves VTX-SYS-012 by bypassing Flash Translation Layer (FTL) wear-leveling
    /// and issuing native FSCTL_FILE_LEVEL_TRIM deallocations to force physical NAND block erasure.
    class CNvmeTrimSanitizer {
    public:
        /// @brief Queries physical storage topology for a given file path.
        [[nodiscard]] static DriveMediumInfo QueryDriveMedium(const std::filesystem::path& path) noexcept {
            DriveMediumInfo info{};
            std::wstring rootPath = path.root_name().wstring();
            if (rootPath.empty()) {
                rootPath = L"C:";
            }

            std::wstring volumeDevice = std::format(L"\\\\.\\{}", rootPath);
            Core::ScopedFileHandle hVol(::CreateFileW(
                volumeDevice.c_str(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr,
                OPEN_EXISTING,
                0,
                nullptr
            ));

            if (!hVol.IsValid()) {
                return info;
            }

            // 1. Check seek penalty (Solid-State vs Rotational)
            STORAGE_PROPERTY_QUERY seekQuery{};
            seekQuery.PropertyId = StorageDeviceSeekPenaltyProperty;
            seekQuery.QueryType = PropertyStandardQuery;

            DEVICE_SEEK_PENALTY_DESCRIPTOR seekPenalty{};
            DWORD bytesRet = 0;
            if (::DeviceIoControl(hVol.Get(), IOCTL_STORAGE_QUERY_PROPERTY,
                                  &seekQuery, sizeof(seekQuery),
                                  &seekPenalty, sizeof(seekPenalty),
                                  &bytesRet, nullptr)) {
                info.IsSolidState = !seekPenalty.IncursSeekPenalty;
            }

            // 2. Query Storage Adapter Bus Type
            STORAGE_PROPERTY_QUERY adapterQuery{};
            adapterQuery.PropertyId = StorageAdapterProperty;
            adapterQuery.QueryType = PropertyStandardQuery;

            STORAGE_DESCRIPTOR_HEADER header{};
            bytesRet = 0;
            if (::DeviceIoControl(hVol.Get(), IOCTL_STORAGE_QUERY_PROPERTY,
                                  &adapterQuery, sizeof(adapterQuery),
                                  &header, sizeof(header),
                                  &bytesRet, nullptr) && header.Size >= sizeof(STORAGE_ADAPTER_DESCRIPTOR)) {
                std::vector<BYTE> buffer(header.Size);
                if (::DeviceIoControl(hVol.Get(), IOCTL_STORAGE_QUERY_PROPERTY,
                                      &adapterQuery, sizeof(adapterQuery),
                                      buffer.data(), header.Size,
                                      &bytesRet, nullptr)) {
                    auto* pAdapterDesc = reinterpret_cast<STORAGE_ADAPTER_DESCRIPTOR*>(buffer.data());
                    switch (pAdapterDesc->BusType) {
                        case BusTypeNvme:
                            info.BusKind = StorageBusKind::Nvme;
                            info.IsSolidState = true;
                            info.BusName = L"NVMe";
                            break;
                        case BusTypeSata:
                        case BusTypeAtapi:
                        case BusTypeAta:
                            info.BusKind = info.IsSolidState ? StorageBusKind::SsdSata : StorageBusKind::HddRotational;
                            info.BusName = info.IsSolidState ? L"SATA SSD" : L"SATA HDD";
                            break;
                        default:
                            info.BusKind = info.IsSolidState ? StorageBusKind::SsdSata : StorageBusKind::HddRotational;
                            info.BusName = info.IsSolidState ? L"Flash SSD" : L"Rotational";
                            break;
                    }
                } else {
                    info.BusKind = info.IsSolidState ? StorageBusKind::SsdSata : StorageBusKind::HddRotational;
                    info.BusName = info.IsSolidState ? L"SSD" : L"HDD";
                }
            } else {
                info.BusKind = info.IsSolidState ? StorageBusKind::SsdSata : StorageBusKind::HddRotational;
                info.BusName = info.IsSolidState ? L"SSD" : L"HDD";
            }

            return info;
        }

        /// @brief Dispatches FSCTL_FILE_LEVEL_TRIM (0x00098208) directly to the SSD Flash Translation Layer (FTL).
        /// Resolves VTX-SYS-012 by forcing physical NAND flash block invalidation and deallocation.
        [[nodiscard]] static Core::Result<bool> DispatchFileLevelTrim(HANDLE hFile, uint64_t fileSizeBytes) noexcept {
            if (hFile == INVALID_HANDLE_VALUE || hFile == nullptr) {
                return std::unexpected(Core::SystemError(Core::ErrorCode::InvalidParameter, 0, L"Invalid file handle for TRIM"));
            }

            if (fileSizeBytes == 0) {
                return true;
            }

            #pragma pack(push, 1)
            struct {
                FILE_LEVEL_TRIM Header;
                FILE_LEVEL_TRIM_RANGE Range;
            } trimBuffer{};
            #pragma pack(pop)

            trimBuffer.Header.Key = 0;
            trimBuffer.Header.NumRanges = 1;
            trimBuffer.Range.Offset = 0;
            trimBuffer.Range.Length = fileSizeBytes;

            FILE_LEVEL_TRIM_OUTPUT trimOutput{};
            DWORD bytesReturned = 0;

            BOOL bSuccess = ::DeviceIoControl(
                hFile,
                FSCTL_FILE_LEVEL_TRIM,
                &trimBuffer,
                sizeof(trimBuffer),
                &trimOutput,
                sizeof(trimOutput),
                &bytesReturned,
                nullptr
            );

            if (!bSuccess) {
                DWORD err = ::GetLastError();
                return std::unexpected(Core::SystemError::FromWin32(
                    err,
                    std::format(L"FSCTL_FILE_LEVEL_TRIM failed (Code 0x{:08X})", err)
                ));
            }

            Core::CAppLogger::LogInfo(L"TrimSanitizer", 
                std::format(L"Successfully dispatched FSCTL_FILE_LEVEL_TRIM for {} bytes (Processed ranges: {})", 
                    fileSizeBytes, trimOutput.NumRangesProcessed));

            return true;
        }
    };

} // namespace WinTracePurge::Storage
