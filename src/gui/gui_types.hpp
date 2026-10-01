#pragma once

#include <cstdint>

namespace WinTracePurge::Gui {

    /// @brief UI Presentation states for the luxury interface state machine.
    enum class ViewState : uint8_t {
        Dashboard = 0,
        Scanning,
        ScanResults,
        Purging,
        PurgeComplete
    };

    /// @brief Geometric bounding box representing a clickable or paintable UI element.
    struct UIRect {
        int x = 0;
        int y = 0;
        int w = 0;
        int h = 0;

        [[nodiscard]] constexpr bool Contains(int px, int py) const noexcept {
            return px >= x && px <= (x + w) && py >= y && py <= (y + h);
        }
    };

} // namespace WinTracePurge::Gui
