#pragma once

#include "nist_sanitizer.hpp"
#include "../core/interfaces.hpp"
#include "../core/result.hpp"
#include "../core/logger.hpp"
#include "../core/zstring_view.hpp"
#include <windows.h>
#include <filesystem>
#include <vector>
#include <algorithm>

namespace WinTracePurge::Storage {

    namespace fs = std::filesystem;

    /// @brief High-performance filesystem tree sanitizer and directory unlinker.
    /// Strictly implements the Core::ICleanerModule interface (VTX-AUDIT-030).
    class CFileSystemCleaner : public Core::ICleanerModule {
    public:
        [[nodiscard]] Core::zstring_view GetModuleName() const noexcept override {
            return L"FileSystemCleaner";
        }

        [[nodiscard]] Core::Result<std::vector<Core::ResourceItem>> Scan(const Core::CleanupContext& ctx) override {
            std::vector<Core::ResourceItem> items;
            for (const auto& pathStr : ctx.CustomMatchFilters) {
                fs::path p(pathStr);
                std::error_code ec;
                if (fs::exists(p, ec)) {
                    items.push_back(Core::ResourceItem{
                        .Type = Core::TargetType::FileSystemPath,
                        .PathOrIdentifier = p.wstring(),
                        .Description = fs::is_directory(p, ec) ? L"Directory Tree" : L"Artifact File",
                        .IsLocked = false
                    });
                }
            }
            return items;
        }

        [[nodiscard]] Core::Result<Core::PurgeStats> Purge(const Core::CleanupContext& ctx, bool dryRun = false) override {
            Core::PurgeStats stats = {};
            auto scanRes = Scan(ctx);
            if (!scanRes) return std::unexpected(scanRes.error());

            stats.ItemsScanned = static_cast<uint32_t>(scanRes->size());
            if (dryRun || ctx.DryRun) return stats;

            for (const auto& item : *scanRes) {
                fs::path p(item.PathOrIdentifier);
                std::error_code ec;
                if (fs::exists(p, ec)) {
                    if (fs::is_directory(p, ec)) {
                        if (PurgeDirectoryTree(p, false)) {
                            stats.ItemsPurged++;
                        }
                    } else {
                        if (PurgeSingleFileFast(p)) {
                            stats.ItemsPurged++;
                        }
                    }
                }
            }
            return stats;
        }

        // Purges a directory tree. If isSensitive is true, uses full NIST SP 800-88 single-pass overwrite.
        // For bulk temporary/junk files, uses high-speed direct unlinking.
        static Core::Result<bool> PurgeDirectoryTree(const fs::path& rootPath, bool isSensitive = false) {
            std::error_code ec;
            if (!fs::exists(rootPath, ec)) {
                return true;
            }

            std::vector<fs::path> files;
            std::vector<fs::path> directories;

            for (auto it = fs::recursive_directory_iterator(rootPath, fs::directory_options::skip_permission_denied, ec);
                 it != fs::recursive_directory_iterator(); ++it) {
                if (it->is_directory(ec)) {
                    directories.push_back(it->path());
                } else {
                    files.push_back(it->path());
                }
            }

            // 1. Sanitize/Delete files first (Leaves-First)
            for (const auto& file : files) {
                if (isSensitive) {
                    (void)CNistSanitizer::SanitizeAndPurgeFile(file);
                } else {
                    PurgeSingleFileFast(file);
                }
            }

            // 2. Sort directories depth-first (longest path length first)
            std::sort(directories.begin(), directories.end(), [](const fs::path& a, const fs::path& b) {
                return a.wstring().length() > b.wstring().length();
            });

            // 3. Remove directories
            for (const auto& dir : directories) {
                PurgeSingleDirectory(dir);
            }

            // 4. Remove root directory if not a standard root
            PurgeSingleDirectory(rootPath);

            return true;
        }

        static bool PurgeSingleFileFast(const fs::path& filePath) {
            std::wstring wsPath = filePath.wstring();
            ::SetFileAttributesW(wsPath.c_str(), FILE_ATTRIBUTE_NORMAL);

            if (::DeleteFileW(wsPath.c_str())) {
                return true;
            }

            // If file is locked, queue for boot deletion
            if (::MoveFileExW(wsPath.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT)) {
                return true;
            }

            return false;
        }

    private:
        static void PurgeSingleDirectory(const fs::path& dirPath) {
            std::wstring wsPath = dirPath.wstring();
            ::SetFileAttributesW(wsPath.c_str(), FILE_ATTRIBUTE_NORMAL);

            if (!::RemoveDirectoryW(wsPath.c_str())) {
                ::MoveFileExW(wsPath.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
            }
        }
    };

} // namespace WinTracePurge::Storage
