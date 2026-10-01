#pragma once

#include "gui_types.hpp"
#include "ui_theme.hpp"
#include "ui_events.hpp"
#include "luxury_window_presenter.hpp"
#include "d3d11_renderer.hpp"
#include "../core/logger.hpp"
#include <windows.h>
#include <windowsx.h>
#include <dwmapi.h>
#include <memory>

#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "msimg32.lib")

namespace WinTracePurge::Gui {

    /// @brief Top-level window frame implementing the View contract of the MVP architecture.
    /// Manages window creation, message routing, DWM decoration, and signed multi-monitor input.
    /// Strictly resolves VTX-ARCH-001, VTX-AUDIT-009, VTX-AUDIT-019, and VTX-AUDIT-046.
    class CWindowFrame : public ILuxuryView {
    public:
        CWindowFrame() : m_presenter(this) {}

        ~CWindowFrame() override {
            m_presenter.CancelWorkers();
            if (m_hWnd && ::IsWindow(m_hWnd)) {
                ::KillTimer(m_hWnd, 1);
            }
        }

        CWindowFrame(const CWindowFrame&) = delete;
        CWindowFrame& operator=(const CWindowFrame&) = delete;

        // ILuxuryView interface implementation
        void InvalidateArea(const UIRect* rect = nullptr) override {
            if (m_hWnd) {
                if (rect) {
                    RECT r = { rect->x, rect->y, rect->x + rect->w, rect->y + rect->h };
                    ::InvalidateRect(m_hWnd, &r, FALSE);
                } else {
                    ::InvalidateRect(m_hWnd, NULL, FALSE);
                }
            }
        }

        void SetTimerFrequency(UINT intervalMs) override {
            if (m_hWnd) {
                ::SetTimer(m_hWnd, 1, intervalMs, NULL);
            }
        }

        [[nodiscard]] HWND GetHwnd() const noexcept override {
            return m_hWnd;
        }

        [[nodiscard]] CLuxuryWindowPresenter& GetPresenter() noexcept {
            return m_presenter;
        }

        /// @brief Static factory method creating and initializing the luxury window frame.
        static HWND CreateLuxuryWindow(HINSTANCE hInstance, int width = 1000, int height = 620) {
            Core::CAppLogger::Initialize();
            Core::CAppLogger::LogInfo(L"WindowFrame", L"Registering and initializing Luxury Window Frame");

            const wchar_t* CLASS_NAME = L"VortexCleaner_Luxury_Engine_Window";

            WNDCLASSEXW wc = {};
            wc.cbSize = sizeof(WNDCLASSEXW);
            wc.style = CS_HREDRAW | CS_VREDRAW;
            wc.lpfnWndProc = StaticWindowProc;
            wc.hInstance = hInstance;
            wc.hCursor = ::LoadCursor(NULL, IDC_ARROW);
            wc.hbrBackground = NULL;
            wc.lpszClassName = CLASS_NAME;

            // Check return value of RegisterClassExW (Resolves VTX-AUDIT-019)
            ATOM classAtom = ::RegisterClassExW(&wc);
            if (!classAtom && ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
                Core::CAppLogger::LogError(L"WindowFrame", L"Failed to register Win32 window class");
                return nullptr;
            }

            s_frameInstance = std::make_unique<CWindowFrame>();

            HWND hWnd = ::CreateWindowExW(
                WS_EX_APPWINDOW,
                CLASS_NAME,
                L"Vortex Cleaner Ultra | Kernel Purger",
                WS_POPUP | WS_VISIBLE | WS_MINIMIZEBOX,
                (GetSystemMetrics(SM_CXSCREEN) - width) / 2,
                (GetSystemMetrics(SM_CYSCREEN) - height) / 2,
                width,
                height,
                NULL,
                NULL,
                hInstance,
                s_frameInstance.get()
            );

            if (hWnd) {
                s_frameInstance->m_hWnd = hWnd;

                // Configure modern Windows 11 DWM attributes
                BOOL darkMode = TRUE;
                ::DwmSetWindowAttribute(hWnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &darkMode, sizeof(darkMode));

                DWM_WINDOW_CORNER_PREFERENCE corner = DWMWCP_ROUND;
                ::DwmSetWindowAttribute(hWnd, DWMWA_WINDOW_CORNER_PREFERENCE, &corner, sizeof(corner));

                // Initialize 15Hz (66ms) idle timer for smooth ambient radar rotation with < 0.1% CPU
                s_frameInstance->SetTimerFrequency(66);
            }

            return hWnd;
        }

    private:
        HWND m_hWnd = nullptr;
        CLuxuryWindowPresenter m_presenter;
        inline static std::unique_ptr<CWindowFrame> s_frameInstance;

        static LRESULT CALLBACK StaticWindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
            CWindowFrame* pFrame = nullptr;

            if (uMsg == WM_NCCREATE) {
                auto* pCreate = reinterpret_cast<CREATESTRUCTW*>(lParam);
                pFrame = reinterpret_cast<CWindowFrame*>(pCreate->lpCreateParams);
                ::SetWindowLongPtrW(hWnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pFrame));
            } else {
                pFrame = reinterpret_cast<CWindowFrame*>(::GetWindowLongPtrW(hWnd, GWLP_USERDATA));
            }

            if (pFrame) {
                return pFrame->HandleMessage(hWnd, uMsg, wParam, lParam);
            }

            return ::DefWindowProcW(hWnd, uMsg, wParam, lParam);
        }

        LRESULT HandleMessage(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
            switch (uMsg) {
                case WM_PAINT: {
                    PAINTSTRUCT ps;
                    HDC hdc = ::BeginPaint(hWnd, &ps);
                    CLuxuryViewRenderer::RenderDashboard(hWnd, hdc, m_presenter);
                    ::EndPaint(hWnd, &ps);
                    return 0;
                }

                case WM_SIZE: {
                    if (wParam == SIZE_MINIMIZED) {
                        ::KillTimer(hWnd, 1);
                    } else {
                        // Restore appropriate timer frequency based on active presenter state
                        if (m_presenter.GetCurrentState() == ViewState::Scanning ||
                            m_presenter.GetCurrentState() == ViewState::Purging) {
                            SetTimerFrequency(16);
                        } else {
                            SetTimerFrequency(66);
                        }
                    }
                    return 0;
                }

                case WM_APP_SCAN_PROGRESS: {
                    m_presenter.HandleScanProgress(static_cast<int>(wParam), static_cast<int>(lParam));
                    return 0;
                }

                case WM_APP_SCAN_COMPLETE: {
                    std::unique_ptr<Storage::DynamicScanReport> pReport(
                        reinterpret_cast<Storage::DynamicScanReport*>(lParam)
                    );
                    m_presenter.HandleScanCompleted(std::move(pReport));
                    return 0;
                }

                case WM_APP_PURGE_PROGRESS: {
                    m_presenter.HandlePurgeProgress(static_cast<int>(wParam), static_cast<int>(lParam));
                    return 0;
                }

                case WM_APP_PURGE_COMPLETE: {
                    std::unique_ptr<Orchestration::PipelineStats> pStats(
                        reinterpret_cast<Orchestration::PipelineStats*>(lParam)
                    );
                    m_presenter.HandlePurgeCompleted(std::move(pStats));
                    return 0;
                }

                case WM_MOUSEMOVE: {
                    // Use GET_X_LPARAM / GET_Y_LPARAM for signed multi-monitor coordinates (Resolves VTX-AUDIT-009)
                    int px = GET_X_LPARAM(lParam);
                    int py = GET_Y_LPARAM(lParam);
                    m_presenter.UpdateHover(px, py);
                    return 0;
                }

                case WM_TIMER: {
                    m_presenter.OnTimerTick();
                    return 0;
                }

                case WM_LBUTTONDOWN: {
                    // Use GET_X_LPARAM / GET_Y_LPARAM for signed multi-monitor coordinates (Resolves VTX-AUDIT-009)
                    int px = GET_X_LPARAM(lParam);
                    int py = GET_Y_LPARAM(lParam);

                    // Check titlebar controls
                    if (Theme::Metrics::BtnClose.Contains(px, py)) {
                        ::PostMessageW(hWnd, WM_CLOSE, 0, 0);
                        return 0;
                    }
                    if (Theme::Metrics::BtnMin.Contains(px, py)) {
                        ::ShowWindow(hWnd, SW_MINIMIZE);
                        return 0;
                    }

                    // Forward to presenter for action dispatching
                    m_presenter.HandleClick(px, py);

                    // Enable window dragging on titlebar area
                    if (py < Theme::Metrics::TitlebarHeight) {
                        ::ReleaseCapture();
                        ::SendMessageW(hWnd, WM_NCLBUTTONDOWN, HTCAPTION, 0);
                    }
                    return 0;
                }

                case WM_CLOSE: {
                    // Explicit graceful shutdown handling with worker cancellation and log flushing (Resolves VTX-AUDIT-046)
                    ::KillTimer(hWnd, 1);
                    m_presenter.CancelWorkers();
                    Core::CAppLogger::LogInfo(L"WindowFrame", L"Window closed gracefully; background workers stopped.");
                    ::DestroyWindow(hWnd);
                    return 0;
                }

                case WM_DESTROY: {
                    ::PostQuitMessage(0);
                    return 0;
                }
            }

            return ::DefWindowProcW(hWnd, uMsg, wParam, lParam);
        }
    };

    /// @brief Backward-compatible adapter for CLuxuryWindowRenderer callers.
    class CLuxuryWindowRenderer {
    public:
        static HWND CreateLuxuryWindow(HINSTANCE hInstance, int width = 1000, int height = 620) {
            return CWindowFrame::CreateLuxuryWindow(hInstance, width, height);
        }
    };

} // namespace WinTracePurge::Gui
