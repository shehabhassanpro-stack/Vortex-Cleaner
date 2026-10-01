#pragma once

#include "gui_types.hpp"
#include <windows.h>
#include <gdiplus.h>

namespace WinTracePurge::Gui::Theme {

    // Centralized Luxury Neon Holographic Palette
    namespace Colors {
        inline const Gdiplus::Color Background{ 255, 7, 9, 14 };
        inline const Gdiplus::Color CardTop{ 245, 14, 18, 28 };
        inline const Gdiplus::Color CardBottom{ 245, 9, 11, 18 };
        inline const Gdiplus::Color CardBorder{ 120, 0, 242, 254 };

        inline const Gdiplus::Color NeonCyan{ 255, 0, 242, 254 };
        inline const Gdiplus::Color NeonGreen{ 255, 0, 230, 150 };
        inline const Gdiplus::Color NeonOrange{ 255, 255, 170, 0 };
        inline const Gdiplus::Color NeonViolet{ 255, 140, 0, 255 };
        inline const Gdiplus::Color NeonCrimson{ 220, 230, 45, 65 };

        inline const Gdiplus::Color TextWhite{ 255, 240, 246, 255 };
        inline const Gdiplus::Color TextGray{ 255, 120, 140, 170 };
        inline const Gdiplus::Color TextMuted{ 255, 80, 95, 120 };
        inline const Gdiplus::Color Separator{ 35, 255, 255, 255 };

        inline const Gdiplus::Color TrackDim{ 40, 0, 242, 254 };
        inline const Gdiplus::Color ButtonHoverWhite{ 40, 255, 255, 255 };
    }

    // Centralized Typography
    namespace Fonts {
        inline constexpr const wchar_t* FontFamily = L"Segoe UI";
    }

    // Standard Window & Component Metrics
    namespace Metrics {
        inline constexpr int DefaultWindowWidth = 1000;
        inline constexpr int DefaultWindowHeight = 620;
        inline constexpr int TitlebarHeight = 45;

        inline constexpr int CardCornerRadius = 8;
        inline constexpr int ButtonCornerRadius = 6;

        // Radar & Gauge Geometry
        inline constexpr int GaugeCenterX = 500;
        inline constexpr int GaugeCenterY = 250;
        inline constexpr int GaugeRadius = 135;

        // Titlebar Controls
        inline constexpr UIRect BtnMin{ 900, 12, 40, 30 };
        inline constexpr UIRect BtnClose{ 946, 12, 40, 30 };

        // Dashboard Buttons
        inline constexpr UIRect BtnScan{ 220, 500, 160, 44 };
        inline constexpr UIRect BtnOptimize{ 420, 500, 160, 44 };
        inline constexpr UIRect BtnClean{ 620, 500, 160, 44 };

        // Scan & Results Buttons
        inline constexpr UIRect BtnCancelScan{ 420, 530, 160, 40 };
        inline constexpr UIRect BtnPurgeAll{ 360, 485, 280, 46 };
        inline constexpr UIRect BtnBackDash{ 40, 530, 180, 40 };
        inline constexpr UIRect BtnDone{ 360, 485, 280, 46 };

        // Cards Bounds
        inline constexpr UIRect CardHardware{ 24, 60, 230, 200 };
        inline constexpr UIRect CardDriver{ 24, 276, 230, 200 };
        inline constexpr UIRect CardCleaner{ 746, 60, 230, 200 };
        inline constexpr UIRect CardRegistry{ 746, 276, 230, 200 };
    }

} // namespace WinTracePurge::Gui::Theme
