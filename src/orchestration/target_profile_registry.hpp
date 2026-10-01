#pragma once

#include "../security/vss_safety_manager.hpp"
#include "../storage/platform_library_resolver.hpp"
#include <string>
#include <string_view>
#include <vector>

namespace WinTracePurge::Orchestration {

    namespace TargetConstants {
        inline constexpr std::wstring_view VanguardDriver = L"vgk.sys";
        inline constexpr std::wstring_view EasyAntiCheatDriver = L"easyanticheat.sys";
        inline constexpr std::wstring_view EasyAntiCheatEosDriver = L"easyanticheat_eos.sys";
        inline constexpr std::wstring_view BattlEyeDriver = L"bedrive.sys"; // Strictly resolves VTX-AUDIT-005: bedisy.sys -> bedrive.sys
    }

    /// @brief Declarative sanitization and cleanup profile categories.
    enum class ProfileKind : uint8_t {
        AntiCheatStandard = 0,     ///< Standard anti-cheat teardown with safety restore point.
        DeepForensicZeroTrace = 1, ///< Comprehensive teardown with DirectMaintenance and telemetry reset.
        RoutineSystemOptimizer = 2 ///< Standard temporary file and diagnostic junk cleanup.
    };

    /// @brief Target configuration structure consumed by CPurgePipelineOrchestrator.
    struct CleanupTargetConfig {
        std::vector<std::wstring> ServiceNames;
        std::vector<std::wstring> DriverFilenames;
        std::vector<std::wstring> DriverStoreMatches;
        std::vector<std::wstring> RegistrySubtrees;
        std::vector<Storage::DiscoveredArtifact> DiscoveredArtifacts;
        Security::VssOperationProfile VssProfile = Security::VssOperationProfile::SafeMaintenance;
        bool DeepForensicTelemetry = false;
        bool PurgeTempFiles = true;
    };

    /// @brief Declarative target profile registry isolating domain targets from execution logic.
    /// Strictly resolves VTX-ARCH-003 and VTX-AUDIT-035 by decoupling hardcoded target lists from presentation
    /// and eliminating redundancy via a canonical base profile builder.
    class CTargetProfileRegistry {
    public:
        [[nodiscard]] static CleanupTargetConfig GetConfigForProfile(ProfileKind kind) {
            switch (kind) {
            case ProfileKind::AntiCheatStandard: {
                CleanupTargetConfig config = CreateBaseAntiCheatConfig();
                config.VssProfile = Security::VssOperationProfile::SafeMaintenance;
                config.DeepForensicTelemetry = false;
                return config;
            }

            case ProfileKind::DeepForensicZeroTrace: {
                CleanupTargetConfig config = CreateBaseAntiCheatConfig();
                config.VssProfile = Security::VssOperationProfile::DirectMaintenance;
                config.DeepForensicTelemetry = true;
                return config;
            }

            case ProfileKind::RoutineSystemOptimizer: {
                CleanupTargetConfig config;
                config.VssProfile = Security::VssOperationProfile::SafeMaintenance;
                config.DeepForensicTelemetry = false;
                config.PurgeTempFiles = true;
                return config;
            }
            }

            return CreateBaseAntiCheatConfig();
        }

    private:
        static CleanupTargetConfig CreateBaseAntiCheatConfig() {
            CleanupTargetConfig config;
            config.ServiceNames = {
                L"vgc", L"vgk", L"EasyAntiCheat", L"EasyAntiCheat_EOS", L"BEService"
            };
            config.DriverFilenames = {
                std::wstring(TargetConstants::VanguardDriver),
                std::wstring(TargetConstants::EasyAntiCheatDriver),
                std::wstring(TargetConstants::EasyAntiCheatEosDriver),
                std::wstring(TargetConstants::BattlEyeDriver)
            };
            config.DriverStoreMatches = {
                L"Riot Games", L"EasyAntiCheat", L"BattlEye"
            };
            config.RegistrySubtrees = {
                L"SYSTEM\\CurrentControlSet\\Services\\vgc",
                L"SYSTEM\\CurrentControlSet\\Services\\vgk",
                L"SYSTEM\\CurrentControlSet\\Services\\EasyAntiCheat",
                L"SYSTEM\\CurrentControlSet\\Services\\EasyAntiCheat_EOS",
                L"SYSTEM\\CurrentControlSet\\Services\\BEService",
                L"SOFTWARE\\Riot Games",
                L"SOFTWARE\\EasyAntiCheat",
                L"SOFTWARE\\BattlEye"
            };
            config.PurgeTempFiles = true;
            return config;
        }
    };

} // namespace WinTracePurge::Orchestration
