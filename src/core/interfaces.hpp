#pragma once

#include "result.hpp"
#include "zstring_view.hpp"
#include <string>
#include <vector>
#include <memory>
#include <concepts>
#include <cstdint>

namespace WinTracePurge::Core {

    enum class TargetType : uint8_t {
        DriverService = 0,
        DriverStorePackage,
        RegistryKey,
        FileSystemPath,
        ClassFilter,
        TemporaryDirectory,
        ForensicArtifact
    };

    struct ResourceItem {
        TargetType Type = TargetType::FileSystemPath;
        std::wstring PathOrIdentifier;
        std::wstring Description;
        bool IsLocked = false;
        uint64_t ByteSize = 0;
    };

    struct CleanupContext {
        bool DryRun = false;
        bool ForceRebootQueue = true;
        bool DeepForensicScan = true;
        std::vector<std::wstring> CustomMatchFilters;
    };

    struct PurgeStats {
        uint32_t ItemsScanned = 0;
        uint32_t ItemsPurged = 0;
        uint32_t ItemsQueuedForReboot = 0;
        uint64_t BytesReclaimed = 0;

        PurgeStats& operator+=(const PurgeStats& other) noexcept {
            ItemsScanned += other.ItemsScanned;
            ItemsPurged += other.ItemsPurged;
            ItemsQueuedForReboot += other.ItemsQueuedForReboot;
            BytesReclaimed += other.BytesReclaimed;
            return *this;
        }
    };

    /// @brief Pure abstract contract for all concrete kernel, registry, and storage cleaner modules.
    class ICleanerModule {
    public:
        virtual ~ICleanerModule() = default;

        /// @brief Returns the authoritative identifier of the cleaner module.
        [[nodiscard]] virtual zstring_view GetModuleName() const noexcept = 0;

        /// @brief Inspects and discovers all target artifacts matching the cleanup context.
        [[nodiscard]] virtual Result<std::vector<ResourceItem>> Scan(const CleanupContext& ctx) = 0;

        /// @brief Executes surgical neutralization and purging of discovered artifacts.
        [[nodiscard]] virtual Result<PurgeStats> Purge(const CleanupContext& ctx, bool dryRun = false) = 0;
    };

    /// @brief C++23 compile-time concept constraining cleaner module implementations.
    template <typename T>
    concept CleanerModuleType = std::derived_from<T, ICleanerModule> && requires(T module, const CleanupContext& ctx) {
        { module.GetModuleName() } -> std::same_as<zstring_view>;
        { module.Scan(ctx) }       -> std::same_as<Result<std::vector<ResourceItem>>>;
        { module.Purge(ctx, false) } -> std::same_as<Result<PurgeStats>>;
    };

} // namespace WinTracePurge::Core
