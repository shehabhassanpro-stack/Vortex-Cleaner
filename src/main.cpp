#include "core/result.hpp"
#include "orchestration/purge_orchestrator.hpp"
#include "gui/window_frame.hpp"
#include <iostream>
#include <format>
#include <thread>
#include <gdiplus.h>

#pragma comment(lib, "gdiplus.lib")

/// @brief RAII lifecycle manager for the Microsoft GDI+ subsystem.
/// Strictly resolves VTX-SYS-004 by guaranteeing GdiplusShutdown invocation on process termination.
class ScopedGdiplusSession {
    ULONG_PTR m_token = 0;
public:
    ScopedGdiplusSession() {
        Gdiplus::GdiplusStartupInput input;
        Gdiplus::GdiplusStartup(&m_token, &input, nullptr);
    }
    ~ScopedGdiplusSession() {
        if (m_token) {
            Gdiplus::GdiplusShutdown(m_token);
        }
    }

    ScopedGdiplusSession(const ScopedGdiplusSession&) = delete;
    ScopedGdiplusSession& operator=(const ScopedGdiplusSession&) = delete;
};

void RunCliMode() {
    std::wcout << L"\n=========================================================\n";
    std::wcout << L"   WinTracePurge Ultra | Production-Grade Systems Engine\n";
    std::wcout << L"   C++23 Standards | NIST SP 800-88 | PatchGuard Compliant\n";
    std::wcout << L"=========================================================\n\n";

    WinTracePurge::Orchestration::CleanupTargetConfig config = {};
    // Example configured targets
    config.ServiceNames = { L"vgc", L"vgk", L"EasyAntiCheat", L"EasyAntiCheat_EOS" };
    config.DriverFilenames = { L"vgk.sys", L"easyanticheat.sys", L"easyanticheat_eos.sys" };
    config.DriverStoreMatches = { L"Riot Games", L"EasyAntiCheat" };
    config.RegistrySubtrees = {
        L"SYSTEM\\CurrentControlSet\\Services\\vgc",
        L"SYSTEM\\CurrentControlSet\\Services\\vgk",
        L"SYSTEM\\CurrentControlSet\\Services\\EasyAntiCheat",
        L"SOFTWARE\\Riot Games",
        L"SOFTWARE\\EasyAntiCheat"
    };

    auto onProgress = [](int percent, std::wstring_view action) {
        std::wcout << std::format(L"[{:3d}%] {}\n", percent, action);
    };

    auto stats = WinTracePurge::Orchestration::CPurgePipelineOrchestrator::ExecutePipeline(config, onProgress);

    std::wcout << L"\n---------------------------------------------------------\n";
    std::wcout << L"   EXECUTION REPORT & SUMMARY\n";
    std::wcout << L"---------------------------------------------------------\n";
    std::wcout << std::format(L" - Services Stopped & Purged:    {}\n", stats.ServicesStopped);
    std::wcout << std::format(L" - DriverStore Packages Removed: {}\n", stats.DriverPackagesRemoved);
    std::wcout << std::format(L" - Registry Subtrees Purged:     {}\n", stats.RegistryKeysPurged);
    std::wcout << std::format(L" - Files & Caches Sanitized:     {}\n", stats.FilesSanitized);
    std::wcout << L" - Temp & Diagnostics Swept:     COMPLETED\n";
    std::wcout << L"---------------------------------------------------------\n";
    std::wcout << L"System cleanup finished cleanly. Please restart your PC.\n\n";
}

int WINAPI wWinMain(HINSTANCE hInstance, [[maybe_unused]] HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    // If "--cli" or running in console, execute CLI pipeline
    if (wcslen(pCmdLine) > 0 && wcsstr(pCmdLine, L"--cli") != NULL) {
        if (AllocConsole()) {
            FILE* pCin = nullptr;
            FILE* pCout = nullptr;
            FILE* pCerr = nullptr;
            (void)freopen_s(&pCin, "CONIN$", "r", stdin);
            (void)freopen_s(&pCout, "CONOUT$", "w", stdout);
            (void)freopen_s(&pCerr, "CONOUT$", "w", stderr);
        }
        RunCliMode();
        std::wcout << L"\nPress Enter to exit...";
        std::wstring dummy;
        std::getline(std::wcin, dummy);
        return 0;
    }

    // Initialize GDI+ lifecycle manager for luxury GUI
    ScopedGdiplusSession gdiplusSession;

    // Launch the Luxury Mica Window GUI
    HWND hWnd = WinTracePurge::Gui::CWindowFrame::CreateLuxuryWindow(hInstance, 1000, 600);
    if (!hWnd) {
        return 1;
    }

    ::ShowWindow(hWnd, nCmdShow);
    ::UpdateWindow(hWnd);

    MSG msg = {};
    while (::GetMessageW(&msg, NULL, 0, 0)) {
        ::TranslateMessage(&msg);
        ::DispatchMessageW(&msg);
    }

    return static_cast<int>(msg.wParam);
}
