#pragma once

#include <windows.h>

namespace WinTracePurge::Gui {

    /// @brief Application-specific window messages for race-free worker-to-UI thread communication.
    /// Strictly resolves VTX-SYS-001 by serializing background thread scan and purge results through the message queue.
    constexpr UINT WM_APP_SCAN_PROGRESS   = WM_APP + 101;
    constexpr UINT WM_APP_SCAN_COMPLETE   = WM_APP + 102;
    constexpr UINT WM_APP_PURGE_PROGRESS  = WM_APP + 103;
    constexpr UINT WM_APP_PURGE_COMPLETE  = WM_APP + 104;

} // namespace WinTracePurge::Gui
