#pragma once

#include "gui_types.hpp"
#include "ui_events.hpp"
#include "ui_theme.hpp"
#include "../storage/real_time_scanner.hpp"
#include "../orchestration/purge_orchestrator.hpp"
#include "../orchestration/target_profile_registry.hpp"
#include <windows.h>
#include <memory>
#include <thread>
#include <stop_token>
#include <string>
#include <vector>
#include <format>

namespace WinTracePurge::Gui {

    /// @brief Abstract view contract decoupling UI presentation from state orchestration.
    /// Strictly resolves VTX-ARCH-001 by implementing MVP (Model-View-Presenter).
    class ILuxuryView {
    public:
        virtual ~ILuxuryView() = default;
        virtual void InvalidateArea(const UIRect* rect = nullptr) = 0;
        virtual void SetTimerFrequency(UINT intervalMs) = 0;
        [[nodiscard]] virtual HWND GetHwnd() const noexcept = 0;
    };

    /// @brief Decoupled presenter managing GUI states and dispatching worker jobs.
    /// Resolves VTX-SYS-001, VTX-SYS-002, VTX-CONC-001, and VTX-CONC-002 through
    /// message-driven state updates and cooperative std::jthread worker lifetimes.
    class CLuxuryWindowPresenter {
    public:
        explicit CLuxuryWindowPresenter(ILuxuryView* pView = nullptr)
            : m_pView(pView), m_state(ViewState::Dashboard) {}

        ~CLuxuryWindowPresenter() {
            CancelWorkers();
        }

        CLuxuryWindowPresenter(const CLuxuryWindowPresenter&) = delete;
        CLuxuryWindowPresenter& operator=(const CLuxuryWindowPresenter&) = delete;

        void SetView(ILuxuryView* pView) noexcept {
            m_pView = pView;
        }

        void CancelWorkers() {
            if (m_workerThread.joinable()) {
                m_workerThread.request_stop();
                m_workerThread.join();
            }
        }

        void RequestScan() {
            if (m_state == ViewState::Scanning || m_state == ViewState::Purging || !m_pView) {
                return;
            }

            CancelWorkers();

            m_state = ViewState::Scanning;
            m_scanProgress = 0;
            m_activeScanPhase = 1;
            m_liveScanDetail = L"Initializing security token audit...";
            m_liveScanLogs.clear();

            // 60Hz (16ms) timer for smooth scanner rotation
            m_pView->SetTimerFrequency(16);
            m_pView->InvalidateArea(nullptr);

            HWND hWnd = m_pView->GetHwnd();
            m_workerThread = std::jthread([hWnd](std::stop_token st) {
                auto onFeedback = [hWnd, &st](int pct, int phase, [[maybe_unused]] std::wstring_view detail) {
                    if (st.stop_requested()) return;
                    ::PostMessageW(hWnd, WM_APP_SCAN_PROGRESS, static_cast<WPARAM>(pct), static_cast<LPARAM>(phase));
                };

                auto report = std::make_unique<Storage::DynamicScanReport>(
                    Storage::CRealTimeScanEngine::PerformLiveScan(onFeedback)
                );

                if (!st.stop_requested()) {
                    ::PostMessageW(hWnd, WM_APP_SCAN_COMPLETE, 0, reinterpret_cast<LPARAM>(report.release()));
                }
            });
        }

        void RequestPurge() {
            if (m_state == ViewState::Scanning || m_state == ViewState::Purging || !m_pView) {
                return;
            }

            CancelWorkers();

            m_state = ViewState::Purging;
            m_scanProgress = 0;
            m_activePurgePhase = 1;
            m_livePurgeDetail = L"Initializing surgical purge...";

            // 60Hz (16ms) timer for smooth purge spinner animation
            m_pView->SetTimerFrequency(16);
            m_pView->InvalidateArea(nullptr);

            // Bind to CTargetProfileRegistry (Resolves VTX-AUDIT-036)
            auto config = Orchestration::CTargetProfileRegistry::GetConfigForProfile(
                Orchestration::ProfileKind::AntiCheatStandard
            );

            if (!m_currentScanReport.RegistryKeysFound.empty()) {
                config.RegistrySubtrees = m_currentScanReport.RegistryKeysFound;
            }
            config.DiscoveredArtifacts = m_currentScanReport.DiscoveredFiles;

            HWND hWnd = m_pView->GetHwnd();
            m_workerThread = std::jthread([hWnd, config](std::stop_token st) {
                auto onProgress = [hWnd, &st](int pct, [[maybe_unused]] std::wstring_view action) {
                    if (st.stop_requested()) return;
                    int phase = 1;
                    if (pct <= 10) phase = 1;
                    else if (pct <= 20) phase = 2;
                    else if (pct <= 32) phase = 3;
                    else if (pct <= 45) phase = 4;
                    else if (pct <= 58) phase = 5;
                    else if (pct <= 70) phase = 6;
                    else if (pct <= 78) phase = 7;
                    else if (pct <= 84) phase = 8;
                    else if (pct <= 89) phase = 9;
                    else if (pct <= 93) phase = 10;
                    else if (pct <= 96) phase = 11;
                    else if (pct < 100) phase = 12;
                    else phase = 13;

                    ::PostMessageW(hWnd, WM_APP_PURGE_PROGRESS, static_cast<WPARAM>(pct), static_cast<LPARAM>(phase));
                };

                auto stats = std::make_unique<Orchestration::PipelineStats>(
                    Orchestration::CPurgePipelineOrchestrator::ExecutePipeline(config, onProgress)
                );

                if (!st.stop_requested()) {
                    ::PostMessageW(hWnd, WM_APP_PURGE_COMPLETE, 0, reinterpret_cast<LPARAM>(stats.release()));
                }
            });
        }

        void HandleScanProgress(int pct, int phase) {
            m_scanProgress = pct;
            m_activeScanPhase = phase;
            if (m_pView) {
                m_pView->InvalidateArea(nullptr);
            }
        }

        void HandleScanCompleted(std::unique_ptr<Storage::DynamicScanReport> pReport) {
            if (pReport) {
                m_currentScanReport = std::move(*pReport);
            }
            m_state = ViewState::ScanResults;
            m_hasScannedOnce = true;
            if (m_pView) {
                // Adaptive 15Hz (66ms) idle timer to conserve CPU
                m_pView->SetTimerFrequency(66);
                m_pView->InvalidateArea(nullptr);
            }
        }

        void HandlePurgeProgress(int pct, int phase) {
            m_scanProgress = pct;
            m_activePurgePhase = phase;
            if (pct >= 96 && pct < 99) {
                m_livePurgeDetail = L"Synchronizing filesystem cache and filter contexts...";
            } else if (pct >= 99 && pct < 100) {
                m_livePurgeDetail = L"Zeroing physical RAM Standby Page Lists (P0-P4)...";
            } else if (pct >= 100) {
                m_livePurgeDetail = L"Surgical purge completed successfully.";
            } else {
                m_livePurgeDetail = L"Sanitizing Multi-Drive Artifacts & Kernel Services...";
            }
            if (m_pView) {
                m_pView->InvalidateArea(nullptr);
            }
        }

        void HandlePurgeCompleted(std::unique_ptr<Orchestration::PipelineStats> pStats) {
            if (pStats) {
                m_lastPurgeStats = *pStats;
            }
            m_livePurgeDetail = L"Surgical purge completed successfully.";
            m_currentScanReport.TotalJunkBytes = 0;
            m_currentScanReport.TempFilesCount = 0;
            m_currentScanReport.ActiveServicesFound.clear();
            m_currentScanReport.RegistryKeysFound.clear();
            m_currentScanReport.DiscoveredFiles.clear();

            m_hasPurgedOnce = true;
            m_hasScannedOnce = true;
            m_state = ViewState::PurgeComplete;
            if (m_pView) {
                // Adaptive 15Hz (66ms) idle timer to conserve CPU
                m_pView->SetTimerFrequency(66);
                m_pView->InvalidateArea(nullptr);
            }
        }

        void OnTimerTick() {
            m_animAngle += 2.5f;
            if (m_animAngle >= 360.0f) {
                m_animAngle -= 360.0f;
            }
            if (m_pView) {
                m_pView->InvalidateArea(nullptr);
            }
        }

        void UpdateHover(int px, int py) {
            int prevHover = m_hoveredBtn;

            if (Theme::Metrics::BtnMin.Contains(px, py)) {
                m_hoveredBtn = 10;
            } else if (Theme::Metrics::BtnClose.Contains(px, py)) {
                m_hoveredBtn = 11;
            } else if (m_state == ViewState::Dashboard) {
                if (Theme::Metrics::BtnScan.Contains(px, py)) m_hoveredBtn = 0;
                else if (Theme::Metrics::BtnOptimize.Contains(px, py)) m_hoveredBtn = 1;
                else if (Theme::Metrics::BtnClean.Contains(px, py)) m_hoveredBtn = 2;
                else m_hoveredBtn = -1;
            } else if (m_state == ViewState::Scanning && Theme::Metrics::BtnCancelScan.Contains(px, py)) {
                m_hoveredBtn = 3;
            } else if (m_state == ViewState::ScanResults) {
                if (Theme::Metrics::BtnPurgeAll.Contains(px, py)) m_hoveredBtn = 4;
                else if (Theme::Metrics::BtnBackDash.Contains(px, py)) m_hoveredBtn = 5;
                else m_hoveredBtn = -1;
            } else if (m_state == ViewState::PurgeComplete && Theme::Metrics::BtnDone.Contains(px, py)) {
                m_hoveredBtn = 6;
            } else {
                m_hoveredBtn = -1;
            }

            if (prevHover != m_hoveredBtn && m_pView) {
                m_pView->InvalidateArea(nullptr);
            }
        }

        void HandleClick(int px, int py) {
            if (m_state == ViewState::Dashboard) {
                if (Theme::Metrics::BtnScan.Contains(px, py) ||
                    Theme::Metrics::BtnOptimize.Contains(px, py) ||
                    Theme::Metrics::BtnClean.Contains(px, py)) {
                    RequestScan();
                }
            } else if (m_state == ViewState::Scanning) {
                if (Theme::Metrics::BtnCancelScan.Contains(px, py)) {
                    CancelWorkers();
                    m_state = ViewState::Dashboard;
                    if (m_pView) {
                        m_pView->SetTimerFrequency(66);
                        m_pView->InvalidateArea(nullptr);
                    }
                }
            } else if (m_state == ViewState::ScanResults) {
                if (Theme::Metrics::BtnPurgeAll.Contains(px, py)) {
                    RequestPurge();
                } else if (Theme::Metrics::BtnBackDash.Contains(px, py)) {
                    m_state = ViewState::Dashboard;
                    if (m_pView) {
                        m_pView->SetTimerFrequency(66);
                        m_pView->InvalidateArea(nullptr);
                    }
                }
            } else if (m_state == ViewState::PurgeComplete) {
                if (Theme::Metrics::BtnDone.Contains(px, py)) {
                    m_state = ViewState::Dashboard;
                    if (m_pView) {
                        m_pView->SetTimerFrequency(66);
                        m_pView->InvalidateArea(nullptr);
                    }
                }
            }
        }

        [[nodiscard]] int CalculateSystemCleanlinessScore() const noexcept {
            if (m_hasPurgedOnce) return 100;
            if (!m_hasScannedOnce) return 0;

            int penalty = 0;
            penalty += static_cast<int>(m_currentScanReport.ActiveServicesFound.size() * 15);
            penalty += static_cast<int>(m_currentScanReport.RegistryKeysFound.size() * 2);
            penalty += static_cast<int>(m_currentScanReport.DiscoveredFiles.size() * 2);
            penalty += static_cast<int>(m_currentScanReport.GetJunkInMB() / 100.0);

            int score = 100 - penalty;
            if (score < 10) score = 10;
            if (score > 100) score = 100;
            return score;
        }

        // State & Data Accessors
        [[nodiscard]] ViewState GetCurrentState() const noexcept { return m_state; }
        [[nodiscard]] const Storage::DynamicScanReport& GetScanReport() const noexcept { return m_currentScanReport; }
        [[nodiscard]] const Orchestration::PipelineStats& GetPurgeStats() const noexcept { return m_lastPurgeStats; }
        [[nodiscard]] bool HasScannedOnce() const noexcept { return m_hasScannedOnce; }
        [[nodiscard]] bool HasPurgedOnce() const noexcept { return m_hasPurgedOnce; }
        [[nodiscard]] int GetScanProgress() const noexcept { return m_scanProgress; }
        [[nodiscard]] int GetActiveScanPhase() const noexcept { return m_activeScanPhase; }
        [[nodiscard]] int GetActivePurgePhase() const noexcept { return m_activePurgePhase; }
        [[nodiscard]] const std::wstring& GetLivePurgeDetail() const noexcept { return m_livePurgeDetail; }
        [[nodiscard]] float GetAnimAngle() const noexcept { return m_animAngle; }
        [[nodiscard]] int GetHoveredButton() const noexcept { return m_hoveredBtn; }

    private:
        ILuxuryView* m_pView = nullptr;
        ViewState m_state = ViewState::Dashboard;
        Storage::DynamicScanReport m_currentScanReport = {};
        Orchestration::PipelineStats m_lastPurgeStats = {};
        bool m_hasScannedOnce = false;
        bool m_hasPurgedOnce = false;
        int m_scanProgress = 0;
        int m_activeScanPhase = 1;
        int m_activePurgePhase = 1;
        std::wstring m_liveScanDetail = L"Ready to scan.";
        std::wstring m_livePurgeDetail = L"Ready to purge.";
        std::vector<std::wstring> m_liveScanLogs;
        float m_animAngle = 0.0f;
        int m_hoveredBtn = -1;
        std::jthread m_workerThread;
    };

} // namespace WinTracePurge::Gui
