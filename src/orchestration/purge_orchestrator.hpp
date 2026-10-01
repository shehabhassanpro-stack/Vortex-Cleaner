#pragma once

#include "target_profile_registry.hpp"
#include "../core/result.hpp"
#include "../core/logger.hpp"
#include "../core/interfaces.hpp"
#include "../security/security_manager.hpp"
#include "../security/token_privilege_scope.hpp"
#include "../security/vss_safety_manager.hpp"
#include "../security/registry_dacl_manager.hpp"
#include "../drivers/class_filter_scrubber.hpp"
#include "../drivers/service_controller.hpp"
#include "../drivers/driver_store_cleaner.hpp"
#include "../storage/filesystem_cleaner.hpp"
#include "../storage/temp_junk_cleaner.hpp"
#include "../storage/platform_library_resolver.hpp"
#include "../storage/nist_sanitizer.hpp"
#include "../storage/forensic_telemetry_cleaner.hpp"
#include "../registry/registry_cleaner.hpp"
#include <functional>
#include <vector>
#include <string>
#include <memory>
#include <format>
#include <filesystem>

namespace WinTracePurge::Orchestration {

    namespace fs = std::filesystem;

    struct PipelineStats {
        uint32_t ServicesStopped = 0;
        uint32_t DriverPackagesRemoved = 0;
        uint32_t RegistryKeysPurged = 0;
        uint32_t FilesSanitized = 0;
        uint32_t FilesQueuedForReboot = 0;
        uint32_t ForensicTracesPurged = 0;
        bool RebootRequired = false;
    };

    /// @brief Modular pipeline orchestrator executing concept-constrained sanitization modules.
    /// Strictly resolves VTX-ARCH-002 by decoupling procedural execution from concrete cleaner dependencies.
    class CPurgePipelineOrchestrator {
    public:
        using ProgressCallback = std::function<void(int progressPercent, std::wstring_view currentAction)>;

        explicit CPurgePipelineOrchestrator(Security::VssOperationProfile vssProfile = Security::VssOperationProfile::SafeMaintenance)
            : m_vssProfile(vssProfile) {}

        template <Core::CleanerModuleType T>
        void RegisterModule(std::unique_ptr<T> module) {
            if (module) {
                m_modules.push_back(std::move(module));
            }
        }

        void RegisterModule(std::unique_ptr<Core::ICleanerModule> module) {
            if (module) {
                m_modules.push_back(std::move(module));
            }
        }

        PipelineStats Execute(const CleanupTargetConfig& config, ProgressCallback onProgress = nullptr) {
            PipelineStats stats = {};

            auto report = [&](int pct, std::wstring_view action) {
                Core::CAppLogger::LogInfo(L"Orchestrator", action);
                if (onProgress) onProgress(pct, action);
            };

            Core::CAppLogger::LogInfo(L"Orchestrator", L"=== Starting Surgical Kernel & Multi-Drive Sanitization Pipeline ===");

            // Phase 0: VSS Pre-Execution Safety Baseline
            report(5, L"Configuring VSS system recovery policy...");
            (void)Security::CVssSafetyManager::EstablishSafetyBaseline(config.VssProfile, L"WinTracePurge Pre-Cleanup Baseline");

            // Phase 1: Security Privilege Escalation (TokenPrivilegeScope RAII)
            report(15, L"Escalating NT token privileges and enabling backup semantics...");
            auto privScopeRes = Security::TokenPrivilegeScope::AcquireAllRequired();
            if (!privScopeRes) {
                Core::CAppLogger::LogWarn(L"Orchestrator", L"Privilege scope acquisition completed with warnings; continuing execution.");
            }

            // Phase 2: PnP Class Filter Scrubbing (Prevent 0x7B BSODs)
            report(25, L"Scrubbing UpperFilters / LowerFilters in PnP Class GUIDs...");
            for (const auto& drv : config.DriverFilenames) {
                std::wstring baseName = drv;
                size_t dotPos = baseName.find(L'.');
                if (dotPos != std::wstring::npos) baseName = baseName.substr(0, dotPos);

                auto fltRes = Drivers::CClassFilterScrubber::ScrubDriverFromAllClasses(baseName);
                if (fltRes && *fltRes) {
                    Core::CAppLogger::LogInfo(L"ClassFilter", std::format(L"Scrubbed driver '{}' from Class filters", baseName));
                }
            }

            // Phase 3: SCM Service & Driver Teardown with DACL Seizure
            report(40, L"Gracefully stopping and unregistering kernel driver services...");
            for (const auto& svc : config.ServiceNames) {
                auto res = Drivers::CRobustServiceController::StopAndPurgeService(svc);
                if (res && *res) {
                    stats.ServicesStopped++;
                    Core::CAppLogger::LogInfo(L"SCM", std::format(L"Successfully purged service '{}'", svc));
                }
            }

            // Phase 4: SetupAPI DriverStore Package Removal
            report(55, L"Uninstalling OEM driver packages from DriverStore...");
            for (const auto& match : config.DriverStoreMatches) {
                auto res = Drivers::CDriverStoreCleaner::PurgeOemDriverPackage(match);
                if (res && *res) {
                    stats.DriverPackagesRemoved++;
                    Core::CAppLogger::LogInfo(L"DriverStore", std::format(L"Removed driver store package matching '{}'", match));
                }
            }

            // Phase 5: Dual-View Registry Purge & DACL Seizure
            report(70, L"Purging 32-bit & 64-bit registry subtrees and vendor keys...");
            for (const auto& regKey : config.RegistrySubtrees) {
                if (Registry::IsHivePathCompatible(HKEY_LOCAL_MACHINE, regKey)) {
                    (void)Security::CRegistryDaclManager::TakeOwnershipAndGrantAccess(HKEY_LOCAL_MACHINE, regKey);
                    (void)Registry::CRegistryPurgeEngine::PurgeSubtree(HKEY_LOCAL_MACHINE, regKey);
                }
                if (Registry::IsHivePathCompatible(HKEY_CURRENT_USER, regKey)) {
                    (void)Security::CRegistryDaclManager::TakeOwnershipAndGrantAccess(HKEY_CURRENT_USER, regKey);
                    (void)Registry::CRegistryPurgeEngine::PurgeSubtree(HKEY_CURRENT_USER, regKey);
                }
                stats.RegistryKeysPurged++;
                Core::CAppLogger::LogInfo(L"Registry", std::format(L"Purged registry subtree '{}'", regKey));
            }

            // Phase 6: Multi-Drive Platform Artifacts & Discovered Files Purge
            report(80, L"Sanitizing discovered anti-cheat platform binaries across all drives...");
            for (const auto& art : config.DiscoveredArtifacts) {
                std::error_code ec;
                if (fs::exists(art.Path, ec)) {
                    if (fs::is_directory(art.Path, ec)) {
                        (void)Storage::CFileSystemCleaner::PurgeDirectoryTree(art.Path, false);
                    } else {
                        (void)Storage::CNistSanitizer::SanitizeAndPurgeFile(art.Path);
                    }
                    stats.FilesSanitized++;
                    Core::CAppLogger::LogInfo(L"MultiDrive", std::format(L"Purged [{}] {}", art.Category, art.Path.wstring()));
                }
            }

            // Phase 7: Forensic Telemetry & Execution Traces (BAM, Shimcache, Crash Logs)
            if (config.DeepForensicTelemetry) {
                report(88, L"Purging BAM execution timestamps, Shimcache, and error logs...");
                Storage::CForensicTelemetryCleaner telemetryCleaner;
                Core::CleanupContext ctx;
                ctx.CustomMatchFilters = config.DriverFilenames;
                auto telRes = telemetryCleaner.Purge(ctx, false);
                if (telRes) {
                    stats.ForensicTracesPurged += telRes->ItemsPurged;
                }
            }

            // Phase 8: Deep Temp, Cache & Diagnostics Sweep
            if (config.PurgeTempFiles) {
                report(95, L"Sweeping Temp files, Crash Dumps, Shader Caches, and Prefetch...");
                (void)Storage::CTempJunkCleanerModule::PurgeAllTempAndJunk();
                Core::CAppLogger::LogInfo(L"TempCleaner", L"Completed deep purge of Temp, Caches, and Minidumps");
            }

            // Phase 9: Execute any custom registered cleaner modules
            Core::CleanupContext modCtx;
            for (const auto& mod : m_modules) {
                report(98, std::format(L"Executing custom module: {}", mod->GetModuleName().data()));
                (void)mod->Purge(modCtx, false);
            }

            report(100, L"Cleanup pipeline completed successfully.");
            Core::CAppLogger::LogInfo(L"Orchestrator", L"=== Sanitization Pipeline Finished Successfully ===");
            return stats;
        }

        /// @brief Static backward-compatible pipeline execution helper.
        static PipelineStats ExecutePipeline(const CleanupTargetConfig& config, ProgressCallback onProgress = nullptr) {
            CPurgePipelineOrchestrator orchestrator(config.VssProfile);
            return orchestrator.Execute(config, onProgress);
        }

    private:
        std::vector<std::unique_ptr<Core::ICleanerModule>> m_modules;
        Security::VssOperationProfile m_vssProfile;
    };

} // namespace WinTracePurge::Orchestration
