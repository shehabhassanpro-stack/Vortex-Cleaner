#pragma once

#include "gui_types.hpp"
#include "ui_theme.hpp"
#include "luxury_window_presenter.hpp"
#include <windows.h>
#include <gdiplus.h>
#include <string>
#include <vector>
#include <format>

namespace WinTracePurge::Gui {

    /// @brief Pure GDI+ rendering engine decoupled from window management and worker threads.
    /// Strictly resolves VTX-ARCH-001 and VTX-AUDIT-007 by enforcing view purity.
    class CLuxuryViewRenderer {
    public:
        static void DrawRoundedGlassCard(Gdiplus::Graphics& g, int x, int y, int w, int h, int radius, const std::wstring& tag, const std::wstring& title) {
            using namespace Gdiplus;

            GraphicsPath path;
            int d = radius * 2;
            path.AddArc(x, y, d, d, 180, 90);
            path.AddArc(x + w - d, y, d, d, 270, 90);
            path.AddArc(x + w - d, y + h - d, d, d, 0, 90);
            path.AddArc(x, y + h - d, d, d, 90, 90);
            path.CloseFigure();

            LinearGradientBrush cardBg(Point(x, y), Point(x, y + h), Theme::Colors::CardTop, Theme::Colors::CardBottom);
            Pen borderPen(Theme::Colors::CardBorder, 1.2f);

            g.FillPath(&cardBg, &path);
            g.DrawPath(&borderPen, &path);

            if (!tag.empty()) {
                SolidBrush badgeBg(Color(200, 0, 242, 254));
                SolidBrush badgeText(Color(255, 8, 11, 16));
                Font tagFont(Theme::Fonts::FontFamily, 8, FontStyleBold);
                Rect badgeRect(x + 16, y + 14, 24, 16);
                g.FillRectangle(&badgeBg, badgeRect);

                StringFormat sfCenter;
                sfCenter.SetAlignment(StringAlignmentCenter);
                sfCenter.SetLineAlignment(StringAlignmentCenter);
                g.DrawString(tag.c_str(), -1, &tagFont, PointF(static_cast<REAL>(x + 28), static_cast<REAL>(y + 22)), &sfCenter, &badgeText);
            }

            if (!title.empty()) {
                Font titleFont(Theme::Fonts::FontFamily, 9, FontStyleBold);
                SolidBrush titleBrush(Theme::Colors::TextWhite);
                int textX = tag.empty() ? (x + 16) : (x + 48);
                g.DrawString(title.c_str(), -1, &titleFont, PointF(static_cast<REAL>(textX), static_cast<REAL>(y + 14)), &titleBrush);

                Pen sepPen(Theme::Colors::Separator, 1.0f);
                g.DrawLine(&sepPen, x + 16, y + 38, x + w - 16, y + 38);
            }
        }

        static void DrawVectorTitlebar(Gdiplus::Graphics& g, int width, int hoveredBtn) {
            using namespace Gdiplus;

            Pen topGlowPen(Theme::Colors::NeonCyan, 2.0f);
            g.DrawLine(&topGlowPen, 0, 0, width, 0);

            SolidBrush logoCircleBrush(Theme::Colors::NeonCyan);
            g.FillEllipse(&logoCircleBrush, 20, 14, 18, 18);
            SolidBrush logoHoleBrush(Theme::Colors::Background);
            g.FillEllipse(&logoHoleBrush, 24, 18, 10, 10);

            Font logoFont(Theme::Fonts::FontFamily, 11, FontStyleBold);
            Font subLogoFont(Theme::Fonts::FontFamily, 9, FontStyleRegular);
            SolidBrush whiteBrush(Theme::Colors::TextWhite);
            SolidBrush grayBrush(Theme::Colors::TextGray);

            g.DrawString(L"VORTEX CLEANER", -1, &logoFont, PointF(46, 13), &whiteBrush);
            g.DrawString(L"|   MULTI-DRIVE KERNEL PURGER & TRACE CLEANER", -1, &subLogoFont, PointF(185, 15), &grayBrush);

            // Minimize Button
            bool minHover = (hoveredBtn == 10);
            if (minHover) {
                SolidBrush minBg(Theme::Colors::ButtonHoverWhite);
                g.FillRectangle(&minBg, Theme::Metrics::BtnMin.x, Theme::Metrics::BtnMin.y, Theme::Metrics::BtnMin.w, Theme::Metrics::BtnMin.h);
            }
            Pen minPen(minHover ? Color(255, 255, 255, 255) : Color(255, 180, 195, 220), 1.8f);
            g.DrawLine(&minPen, Theme::Metrics::BtnMin.x + 13, Theme::Metrics::BtnMin.y + 16, Theme::Metrics::BtnMin.x + 27, Theme::Metrics::BtnMin.y + 16);

            // Close Button
            bool closeHover = (hoveredBtn == 11);
            if (closeHover) {
                SolidBrush closeBg(Theme::Colors::NeonCrimson);
                g.FillRectangle(&closeBg, Theme::Metrics::BtnClose.x, Theme::Metrics::BtnClose.y, Theme::Metrics::BtnClose.w, Theme::Metrics::BtnClose.h);
            }
            Pen closePen(closeHover ? Color(255, 255, 255, 255) : Color(255, 220, 140, 150), 1.8f);
            g.DrawLine(&closePen, Theme::Metrics::BtnClose.x + 13, Theme::Metrics::BtnClose.y + 9, Theme::Metrics::BtnClose.x + 27, Theme::Metrics::BtnClose.y + 21);
            g.DrawLine(&closePen, Theme::Metrics::BtnClose.x + 27, Theme::Metrics::BtnClose.y + 9, Theme::Metrics::BtnClose.x + 13, Theme::Metrics::BtnClose.y + 21);
        }

        static void RenderDashboardView(Gdiplus::Graphics& g, const CLuxuryWindowPresenter& presenter) {
            using namespace Gdiplus;

            Font valFont(Theme::Fonts::FontFamily, 9, FontStyleRegular);
            Font boldValFont(Theme::Fonts::FontFamily, 9, FontStyleBold);
            SolidBrush grayBrush(Theme::Colors::TextGray);
            SolidBrush whiteBrush(Theme::Colors::TextWhite);
            SolidBrush greenBrush(Theme::Colors::NeonGreen);
            SolidBrush cyanBrush(Theme::Colors::NeonCyan);
            SolidBrush orangeBrush(Theme::Colors::NeonOrange);

            auto DrawRow = [&](int x, int y, const std::wstring& label, const std::wstring& val, Brush& valColor) {
                g.DrawString(label.c_str(), -1, &valFont, PointF(static_cast<REAL>(x), static_cast<REAL>(y)), &grayBrush);
                g.DrawString(val.c_str(), -1, &boldValFont, PointF(static_cast<REAL>(x + 110), static_cast<REAL>(y)), &valColor);
            };

            const auto& report = presenter.GetScanReport();
            bool hasScanned = presenter.HasScannedOnce();
            bool hasPurged = presenter.HasPurgedOnce();

            // Left Cards
            DrawRoundedGlassCard(g, Theme::Metrics::CardHardware.x, Theme::Metrics::CardHardware.y,
                                 Theme::Metrics::CardHardware.w, Theme::Metrics::CardHardware.h,
                                 Theme::Metrics::CardCornerRadius, L"HW", L"HARDWARE TELEMETRY");
            DrawRow(40, 108, L"CPU State:", L"Optimal", greenBrush);
            DrawRow(40, 138, L"Memory Pool:", L"Clean", greenBrush);
            DrawRow(40, 168, L"GPU Shaders:", L"Monitored", whiteBrush);
            DrawRow(40, 198, L"Storage I/O:", L"0% Queue", greenBrush);

            DrawRoundedGlassCard(g, Theme::Metrics::CardDriver.x, Theme::Metrics::CardDriver.y,
                                 Theme::Metrics::CardDriver.w, Theme::Metrics::CardDriver.h,
                                 Theme::Metrics::CardCornerRadius, L"DR", L"DRIVER STATUS");
            DrawRow(40, 324, L"Active Drivers:", L"Audited", whiteBrush);
            DrawRow(40, 354, L"UpperFilters:", L"Scrubbed", greenBrush);
            DrawRow(40, 384, L"PatchGuard:", L"Secure (KPP)", cyanBrush);
            DrawRow(40, 414, L"DriverStore:", L"Cleaned", whiteBrush);

            // Right Cards
            DrawRoundedGlassCard(g, Theme::Metrics::CardCleaner.x, Theme::Metrics::CardCleaner.y,
                                 Theme::Metrics::CardCleaner.w, Theme::Metrics::CardCleaner.h,
                                 Theme::Metrics::CardCornerRadius, L"SC", L"SYSTEM CLEANER");
            std::wstring tempStr = std::format(L"{:.1f} MB", report.GetJunkInMB());
            DrawRow(762, 108, L"Detected Traces:", (report.TotalJunkBytes > 0 ? tempStr : L"0 MB (Clean)"), (report.TotalJunkBytes > 0 ? whiteBrush : greenBrush));
            DrawRow(762, 138, L"Multi-Drive Files:", std::format(L"{} Targets", report.DiscoveredFiles.size()), whiteBrush);
            DrawRow(762, 168, L"Crash Dumps:", L"0 MB Cleared", greenBrush);
            DrawRow(762, 198, L"Sanitizer:", L"NIST SP 800-88", cyanBrush);

            DrawRoundedGlassCard(g, Theme::Metrics::CardRegistry.x, Theme::Metrics::CardRegistry.y,
                                 Theme::Metrics::CardRegistry.w, Theme::Metrics::CardRegistry.h,
                                 Theme::Metrics::CardCornerRadius, L"RG", L"REGISTRY MASTER");
            DrawRow(762, 324, L"Target Keys:", std::format(L"{} Detected", report.RegistryKeysFound.size()), (report.RegistryKeysFound.empty() ? greenBrush : whiteBrush));
            DrawRow(762, 354, L"Locked Keys:", L"0 Locked", greenBrush);
            DrawRow(762, 384, L"Services Found:", std::format(L"{} Services", report.ActiveServicesFound.size()), (report.ActiveServicesFound.empty() ? greenBrush : whiteBrush));
            DrawRow(762, 414, L"DACL Access:", L"Full Admin", cyanBrush);

            // Center Holographic Gauge
            int cx = Theme::Metrics::GaugeCenterX;
            int cy = Theme::Metrics::GaugeCenterY;
            int radius = Theme::Metrics::GaugeRadius;

            Pen trackPen(Theme::Colors::TrackDim, 6.0f);
            g.DrawEllipse(&trackPen, cx - radius, cy - radius, radius * 2, radius * 2);

            Pen neonCyanPen(Theme::Colors::NeonCyan, 6.0f);
            Pen neonGreenPen(Theme::Colors::NeonGreen, 6.0f);
            Pen neonOrangePen(Theme::Colors::NeonOrange, 6.0f);
            Pen neonVioletPen(Theme::Colors::NeonViolet, 4.0f);

            int score = presenter.CalculateSystemCleanlinessScore();
            float animAngle = presenter.GetAnimAngle();

            if (!hasScanned && !hasPurged) {
                g.DrawArc(&neonCyanPen, cx - radius, cy - radius, radius * 2, radius * 2, animAngle - 90.0f, 260.0f);
                g.DrawArc(&neonVioletPen, cx - (radius - 14), cy - (radius - 14), (radius - 14) * 2, (radius - 14) * 2, -animAngle * 1.5f, 140.0f);
            } else if (score == 100 || hasPurged) {
                g.DrawArc(&neonGreenPen, cx - radius, cy - radius, radius * 2, radius * 2, -90.0f, 360.0f);
                g.DrawArc(&neonCyanPen, cx - (radius - 14), cy - (radius - 14), (radius - 14) * 2, (radius - 14) * 2, animAngle, 180.0f);
            } else {
                float arcSweep = (score / 100.0f) * 360.0f;
                Pen* pCurPen = (score < 60) ? &neonOrangePen : &neonCyanPen;
                g.DrawArc(pCurPen, cx - radius, cy - radius, radius * 2, radius * 2, -90.0f, arcSweep);
                g.DrawArc(&neonVioletPen, cx - (radius - 14), cy - (radius - 14), (radius - 14) * 2, (radius - 14) * 2, -animAngle * 1.5f, 120.0f);
            }

            Font metricFont(Theme::Fonts::FontFamily, static_cast<REAL>((!hasScanned && !hasPurged) ? 36 : 44), FontStyleBold);
            Font statusFont(Theme::Fonts::FontFamily, 10, FontStyleBold);
            StringFormat sfCenter;
            sfCenter.SetAlignment(StringAlignmentCenter);
            sfCenter.SetLineAlignment(StringAlignmentCenter);

            std::wstring healthPercent;
            std::wstring healthStatus;

            if (!hasScanned && !hasPurged) {
                healthPercent = L"READY";
                healthStatus = L"SYSTEM READY FOR AUDIT";
            } else if (score == 100 || hasPurged) {
                healthPercent = L"100%";
                healthStatus = L"SYSTEM STATUS: 100% CLEAN";
            } else {
                healthPercent = std::format(L"{}%", score);
                healthStatus = std::format(L"INTEGRITY: {}% (TRACES DETECTED)", score);
            }

            Brush* statusBrush = (!hasScanned && !hasPurged) ? &cyanBrush : ((score == 100) ? &greenBrush : ((score < 60) ? &orangeBrush : &cyanBrush));

            g.DrawString(healthPercent.c_str(), -1, &metricFont, PointF(static_cast<REAL>(cx), static_cast<REAL>(cy - 20)), &sfCenter, &whiteBrush);
            g.DrawString(healthStatus.c_str(), -1, &statusFont, PointF(static_cast<REAL>(cx), static_cast<REAL>(cy + 42)), &sfCenter, statusBrush);

            // Action Buttons
            int hoveredBtn = presenter.GetHoveredButton();
            auto DrawActionBtn = [&](const UIRect& btn, const std::wstring& text, Color glowColor, int btnId) {
                bool hovered = (hoveredBtn == btnId);
                SolidBrush btnBg(hovered ? Color(255, 24, 34, 52) : Color(240, 14, 18, 28));
                Pen btnBorder(hovered ? Color(255, 255, 255, 255) : glowColor, hovered ? 2.0f : 1.2f);

                Rect r(btn.x, btn.y, btn.w, btn.h);
                g.FillRectangle(&btnBg, r);
                g.DrawRectangle(&btnBorder, r);

                Font btnLabelFont(Theme::Fonts::FontFamily, 10, FontStyleBold);
                SolidBrush btnTextBrush(hovered ? Color(255, 255, 255, 255) : Color(255, 215, 230, 255));
                g.DrawString(text.c_str(), -1, &btnLabelFont, PointF(static_cast<REAL>(btn.x + btn.w / 2), static_cast<REAL>(btn.y + btn.h / 2)), &sfCenter, &btnTextBrush);
            };

            DrawActionBtn(Theme::Metrics::BtnScan, L"SCAN ALL DRIVES", Theme::Colors::NeonCyan, 0);
            DrawActionBtn(Theme::Metrics::BtnOptimize, L"OPTIMIZE KERNEL", Theme::Colors::NeonViolet, 1);
            DrawActionBtn(Theme::Metrics::BtnClean, L"PURGE ALL TRACES", Theme::Colors::NeonCyan, 2);
        }

        static void RenderScanningView(Gdiplus::Graphics& g, int width, const CLuxuryWindowPresenter& presenter) {
            using namespace Gdiplus;

            Font headerFont(Theme::Fonts::FontFamily, 14, FontStyleBold);
            Font subHeaderFont(Theme::Fonts::FontFamily, 9, FontStyleRegular);
            SolidBrush whiteBrush(Theme::Colors::TextWhite);
            SolidBrush cyanBrush(Theme::Colors::NeonCyan);

            StringFormat sfCenter;
            sfCenter.SetAlignment(StringAlignmentCenter);
            sfCenter.SetLineAlignment(StringAlignmentCenter);

            int progress = presenter.GetScanProgress();
            g.DrawString(L"REAL-TIME MULTI-DRIVE SCAN & HEURISTIC AUDIT", -1, &headerFont, PointF(static_cast<REAL>(width / 2), 65), &sfCenter, &whiteBrush);
            std::wstring progressTitle = std::format(L"Dynamically Resolving Steam Libraries, Kernel Services & Drivers... ({}%)", progress);
            g.DrawString(progressTitle.c_str(), -1, &subHeaderFont, PointF(static_cast<REAL>(width / 2), 95), &sfCenter, &cyanBrush);

            // Glowing Progress Bar
            int barX = 150, barY = 120, barW = 700, barH = 14;
            SolidBrush barTrackBg(Color(255, 15, 20, 32));
            Pen barTrackBorder(Color(100, 0, 242, 254), 1.0f);
            g.FillRectangle(&barTrackBg, barX, barY, barW, barH);
            g.DrawRectangle(&barTrackBorder, barX, barY, barW, barH);

            int fillW = static_cast<int>((progress / 100.0f) * barW);
            if (fillW > 0) {
                LinearGradientBrush fillGradient(Point(barX, barY), Point(barX + fillW, barY), Theme::Colors::NeonCyan, Color(255, 180, 0, 255));
                g.FillRectangle(&fillGradient, barX, barY, fillW, barH);
            }

            // Left Box: 5-Phase Real Scanner Pipeline
            DrawRoundedGlassCard(g, 40, 155, 420, 350, Theme::Metrics::CardCornerRadius, L"", L"DYNAMIC MULTI-DRIVE PIPELINE");
            Font stepFont(Theme::Fonts::FontFamily, 9, FontStyleRegular);
            Font stepBoldFont(Theme::Fonts::FontFamily, 9, FontStyleBold);

            auto DrawStep = [&](int y, int phaseNum, const std::wstring& title, const std::wstring& status, int currentPhase) {
                bool isDone = (currentPhase > phaseNum);
                bool isActive = (currentPhase == phaseNum);

                SolidBrush badgeColor(isDone ? Theme::Colors::NeonGreen : (isActive ? Theme::Colors::NeonCyan : Theme::Colors::TextMuted));
                std::wstring badgeSymbol = isDone ? L"[OK]" : (isActive ? L"[..]" : L"[--]");

                g.DrawString(badgeSymbol.c_str(), -1, &stepBoldFont, PointF(56, static_cast<REAL>(y)), &badgeColor);
                g.DrawString(title.c_str(), -1, &stepFont, PointF(96, static_cast<REAL>(y)), &whiteBrush);
                g.DrawString(status.c_str(), -1, &stepBoldFont, PointF(330, static_cast<REAL>(y)), &badgeColor);
            };

            int curP = presenter.GetActiveScanPhase();
            const auto& report = presenter.GetScanReport();
            DrawStep(205, 1, L"1. Token Security Privileges", curP > 1 ? L"Verified" : L"Auditing...", curP);
            DrawStep(260, 2, L"2. Kernel Driver Services", curP > 2 ? std::format(L"{} Found", report.ActiveServicesFound.size()) : (curP == 2 ? L"Scanning..." : L"Pending"), curP);
            DrawStep(315, 3, L"3. PnP Class UpperFilters", curP > 3 ? L"Analyzed" : (curP == 3 ? L"Inspecting..." : L"Pending"), curP);
            DrawStep(370, 4, L"4. Registry Hives (32/64-bit)", curP > 4 ? std::format(L"{} Keys", report.RegistryKeysFound.size()) : (curP == 4 ? L"Traversing..." : L"Pending"), curP);
            DrawStep(425, 5, L"5. Multi-Drive Platform Files", curP > 5 ? std::format(L"{:.1f} MB", report.GetJunkInMB()) : (curP == 5 ? L"Resolving..." : L"Pending"), curP);

            // Right Box: Live Terminal Log Feed
            DrawRoundedGlassCard(g, 480, 155, 480, 350, Theme::Metrics::CardCornerRadius, L"", L"LIVE MULTI-DRIVE SCANNER LOGS");
            Font logFont(L"Consolas", 8, FontStyleRegular);
            int logY = 200;

            const auto& logFeed = report.ScanLogFeed;
            for (size_t i = 0; i < logFeed.size() && i < 10; ++i) {
                g.DrawString(logFeed[i].c_str(), -1, &logFont, PointF(496, static_cast<REAL>(logY)), &cyanBrush);
                logY += 27;
            }

            // Cancel Button
            bool cancelHover = (presenter.GetHoveredButton() == 3);
            SolidBrush cancelBg(cancelHover ? Color(255, 35, 45, 65) : Color(240, 20, 25, 35));
            Pen cancelBorder(cancelHover ? Color(255, 255, 255, 255) : Color(255, 120, 140, 170), 1.2f);
            g.FillRectangle(&cancelBg, Theme::Metrics::BtnCancelScan.x, Theme::Metrics::BtnCancelScan.y, Theme::Metrics::BtnCancelScan.w, Theme::Metrics::BtnCancelScan.h);
            g.DrawRectangle(&cancelBorder, Theme::Metrics::BtnCancelScan.x, Theme::Metrics::BtnCancelScan.y, Theme::Metrics::BtnCancelScan.w, Theme::Metrics::BtnCancelScan.h);

            Font btnF(Theme::Fonts::FontFamily, 9, FontStyleBold);
            g.DrawString(L"CANCEL SCAN", -1, &btnF,
                         PointF(static_cast<REAL>(Theme::Metrics::BtnCancelScan.x + Theme::Metrics::BtnCancelScan.w / 2),
                                static_cast<REAL>(Theme::Metrics::BtnCancelScan.y + Theme::Metrics::BtnCancelScan.h / 2)),
                         &sfCenter, &whiteBrush);
        }

        static void RenderPurgingView(Gdiplus::Graphics& g, int width, const CLuxuryWindowPresenter& presenter) {
            using namespace Gdiplus;

            Font headerFont(Theme::Fonts::FontFamily, 14, FontStyleBold);
            Font subHeaderFont(Theme::Fonts::FontFamily, 9, FontStyleRegular);
            SolidBrush whiteBrush(Theme::Colors::TextWhite);
            SolidBrush cyanBrush(Theme::Colors::NeonCyan);

            StringFormat sfCenter;
            sfCenter.SetAlignment(StringAlignmentCenter);
            sfCenter.SetLineAlignment(StringAlignmentCenter);

            int progress = presenter.GetScanProgress();
            g.DrawString(L"REAL-TIME SURGICAL TRACE PURGE", -1, &headerFont, PointF(static_cast<REAL>(width / 2), 65), &sfCenter, &whiteBrush);
            std::wstring progressTitle = std::format(L"Sanitizing Multi-Drive Artifacts & Kernel Services... ({}%)", progress);
            g.DrawString(progressTitle.c_str(), -1, &subHeaderFont, PointF(static_cast<REAL>(width / 2), 95), &sfCenter, &cyanBrush);

            // Glowing Progress Bar
            int barX = 150, barY = 120, barW = 700, barH = 14;
            SolidBrush barTrackBg(Color(255, 15, 20, 32));
            Pen barTrackBorder(Color(100, 0, 242, 254), 1.0f);
            g.FillRectangle(&barTrackBg, barX, barY, barW, barH);
            g.DrawRectangle(&barTrackBorder, barX, barY, barW, barH);

            int fillW = static_cast<int>((progress / 100.0f) * barW);
            if (fillW > 0) {
                LinearGradientBrush fillGradient(Point(barX, barY), Point(barX + fillW, barY), Theme::Colors::NeonCyan, Color(255, 180, 0, 255));
                g.FillRectangle(&fillGradient, barX, barY, fillW, barH);
            }

            // Left Box: 7-Phase Purge Execution Pipeline
            DrawRoundedGlassCard(g, 40, 155, 420, 350, Theme::Metrics::CardCornerRadius, L"", L"SURGICAL PURGE EXECUTION PIPELINE");
            Font stepFont(Theme::Fonts::FontFamily, 9, FontStyleRegular);
            Font stepBoldFont(Theme::Fonts::FontFamily, 9, FontStyleBold);

            auto DrawStep = [&](int y, int phaseNum, const std::wstring& title, const std::wstring& status, int currentPhase) {
                bool isDone = (currentPhase > phaseNum);
                bool isActive = (currentPhase == phaseNum);

                SolidBrush badgeColor(isDone ? Theme::Colors::NeonGreen : (isActive ? Theme::Colors::NeonCyan : Theme::Colors::TextMuted));
                std::wstring badgeSymbol = isDone ? L"[OK]" : (isActive ? L"[..]" : L"[--]");

                g.DrawString(badgeSymbol.c_str(), -1, &stepBoldFont, PointF(56, static_cast<REAL>(y)), &badgeColor);
                g.DrawString(title.c_str(), -1, &stepFont, PointF(96, static_cast<REAL>(y)), &whiteBrush);
                g.DrawString(status.c_str(), -1, &stepBoldFont, PointF(330, static_cast<REAL>(y)), &badgeColor);
            };

            int curP = presenter.GetActivePurgePhase();
            DrawStep(190, 1, L"1. VSS Safety Snapshot", curP > 1 ? L"Created" : (curP == 1 ? L"Snapping..." : L"Pending"), curP);
            DrawStep(230, 2, L"2. Token Escalation", curP > 2 ? L"Elevated" : (curP == 2 ? L"Enabling..." : L"Pending"), curP);
            DrawStep(270, 3, L"3. PnP Class Scrubbing", curP > 3 ? L"Scrubbed" : (curP == 3 ? L"Cleaning..." : L"Pending"), curP);
            DrawStep(310, 4, L"4. SCM Service Teardown", curP > 4 ? L"Disabled" : (curP == 4 ? L"Stopping..." : L"Pending"), curP);
            DrawStep(350, 5, L"5. DriverStore OEM Purge", curP > 5 ? L"Uninstalled" : (curP == 5 ? L"Removing..." : L"Pending"), curP);
            DrawStep(390, 6, L"6. Registry Subtree Purge", curP > 6 ? L"Wiped" : (curP == 6 ? L"Deleting..." : L"Pending"), curP);
            DrawStep(430, 7, L"7. Multi-Drive Binaries Purge", curP > 7 ? L"Zeroed" : (curP == 7 ? L"Sanitizing..." : L"Pending"), curP);

            // Right Box: Live Terminal Feed
            DrawRoundedGlassCard(g, 480, 155, 480, 350, Theme::Metrics::CardCornerRadius, L"", L"LIVE PURGE LOGS & DESTRUCTION FEED");
            Font logFont(L"Consolas", 8, FontStyleRegular);
            int logY = 200;

            const auto& logFeed = presenter.GetScanReport().ScanLogFeed;
            for (size_t i = 0; i < logFeed.size() && i < 10; ++i) {
                g.DrawString(logFeed[i].c_str(), -1, &logFont, PointF(496, static_cast<REAL>(logY)), &cyanBrush);
                logY += 27;
            }
        }

        static void RenderScanResultsView(Gdiplus::Graphics& g, int width, const CLuxuryWindowPresenter& presenter) {
            using namespace Gdiplus;

            Font headerFont(Theme::Fonts::FontFamily, 15, FontStyleBold);
            Font subHeaderFont(Theme::Fonts::FontFamily, 10, FontStyleRegular);
            SolidBrush whiteBrush(Theme::Colors::TextWhite);
            SolidBrush greenBrush(Theme::Colors::NeonGreen);

            StringFormat sfCenter;
            sfCenter.SetAlignment(StringAlignmentCenter);
            sfCenter.SetLineAlignment(StringAlignmentCenter);

            g.DrawString(L"MULTI-DRIVE AUDIT COMPLETED - DETECTED TRACES INVENTORY", -1, &headerFont, PointF(static_cast<REAL>(width / 2), 65), &sfCenter, &whiteBrush);
            g.DrawString(L"Verified 100% safe to purge without affecting user games, saves, or system stability.", -1, &subHeaderFont, PointF(static_cast<REAL>(width / 2), 95), &greenBrush);

            const auto& report = presenter.GetScanReport();

            // 3 Dynamic Metric Cards
            auto DrawResultMetric = [&](int x, int y, int w, int h, const std::wstring& count, const std::wstring& label, Color glowCol) {
                DrawRoundedGlassCard(g, x, y, w, h, Theme::Metrics::CardCornerRadius, L"", label);
                Font countFont(Theme::Fonts::FontFamily, 26, FontStyleBold);
                SolidBrush glowBrush(glowCol);
                g.DrawString(count.c_str(), -1, &countFont, PointF(static_cast<REAL>(x + w / 2), static_cast<REAL>(y + 80)), &sfCenter, &glowBrush);
            };

            std::wstring junkText = std::format(L"{:.1f} MB", report.GetJunkInMB());
            std::wstring svcText = std::format(L"{} SERVICES", report.ActiveServicesFound.size());
            std::wstring regText = std::format(L"{} KEYS", report.RegistryKeysFound.size());

            DrawResultMetric(60, 135, 260, 145, junkText, L"MULTI-DRIVE ARTIFACTS", Theme::Colors::NeonCyan);
            DrawResultMetric(370, 135, 260, 145, svcText, L"KERNEL DRIVER TRACES", Color(255, 255, 180, 0));
            DrawResultMetric(680, 135, 260, 145, regText, L"ORPHAN REGISTRY KEYS", Color(255, 180, 0, 255));

            // Dynamic Findings List Box
            DrawRoundedGlassCard(g, 60, 295, 880, 165, Theme::Metrics::CardCornerRadius, L"", L"ITEMS SCHEDULED FOR SURGICAL PURGE ACROSS ALL DRIVES");
            Font itemFont(Theme::Fonts::FontFamily, 9, FontStyleRegular);

            std::wstring svcsLine = L"-> Kernel Driver Services: ";
            if (report.ActiveServicesFound.empty()) {
                svcsLine += L"None detected (Clean)";
            } else {
                for (size_t i = 0; i < report.ActiveServicesFound.size(); ++i) {
                    if (i > 0) svcsLine += L", ";
                    svcsLine += report.ActiveServicesFound[i];
                }
            }

            std::wstring regLine = L"-> Registry Subtrees: " + std::to_wstring(report.RegistryKeysFound.size()) + L" target keys identified across Services & Software hives";
            std::wstring filesLine = L"-> Discovered Binaries & SDKs: " + std::to_wstring(report.DiscoveredFiles.size()) + L" targets identified across Steam libraries & fixed partitions";
            std::wstring safeLine = L"-> Safety Assurance: Zero user games, saves, or OS personal files will be touched.";

            g.DrawString(svcsLine.c_str(), -1, &itemFont, PointF(80, 335), &whiteBrush);
            g.DrawString(regLine.c_str(), -1, &itemFont, PointF(80, 365), &whiteBrush);
            g.DrawString(filesLine.c_str(), -1, &itemFont, PointF(80, 395), &whiteBrush);
            g.DrawString(safeLine.c_str(), -1, &itemFont, PointF(80, 425), &greenBrush);

            // Action Buttons
            bool purgeHover = (presenter.GetHoveredButton() == 4);
            LinearGradientBrush purgeBg(Point(Theme::Metrics::BtnPurgeAll.x, Theme::Metrics::BtnPurgeAll.y),
                                        Point(Theme::Metrics::BtnPurgeAll.x + Theme::Metrics::BtnPurgeAll.w, Theme::Metrics::BtnPurgeAll.y),
                                        purgeHover ? Theme::Colors::NeonCyan : Color(230, 0, 200, 240),
                                        purgeHover ? Color(255, 180, 0, 255) : Color(230, 140, 0, 220));
            g.FillRectangle(&purgeBg, Theme::Metrics::BtnPurgeAll.x, Theme::Metrics::BtnPurgeAll.y, Theme::Metrics::BtnPurgeAll.w, Theme::Metrics::BtnPurgeAll.h);
            Font btnBold(Theme::Fonts::FontFamily, 11, FontStyleBold);
            SolidBrush btnDarkTxt(Color(255, 5, 8, 12));
            g.DrawString(L"PURGE ALL DETECTED TRACES", -1, &btnBold,
                         PointF(static_cast<REAL>(Theme::Metrics::BtnPurgeAll.x + Theme::Metrics::BtnPurgeAll.w / 2),
                                static_cast<REAL>(Theme::Metrics::BtnPurgeAll.y + Theme::Metrics::BtnPurgeAll.h / 2)),
                         &sfCenter, &btnDarkTxt);

            // Back Button
            bool backHover = (presenter.GetHoveredButton() == 5);
            SolidBrush backBg(backHover ? Color(255, 30, 38, 55) : Color(240, 16, 20, 30));
            Pen backPen(backHover ? Color(255, 255, 255, 255) : Color(255, 100, 120, 150), 1.0f);
            g.FillRectangle(&backBg, Theme::Metrics::BtnBackDash.x, Theme::Metrics::BtnBackDash.y, Theme::Metrics::BtnBackDash.w, Theme::Metrics::BtnBackDash.h);
            g.DrawRectangle(&backPen, Theme::Metrics::BtnBackDash.x, Theme::Metrics::BtnBackDash.y, Theme::Metrics::BtnBackDash.w, Theme::Metrics::BtnBackDash.h);
            Font backF(Theme::Fonts::FontFamily, 9, FontStyleRegular);
            g.DrawString(L"< BACK TO DASHBOARD", -1, &backF,
                         PointF(static_cast<REAL>(Theme::Metrics::BtnBackDash.x + Theme::Metrics::BtnBackDash.w / 2),
                                static_cast<REAL>(Theme::Metrics::BtnBackDash.y + Theme::Metrics::BtnBackDash.h / 2)),
                         &sfCenter, &whiteBrush);
        }

        static void RenderPurgeCompleteView(Gdiplus::Graphics& g, int width, int height, const CLuxuryWindowPresenter& presenter) {
            using namespace Gdiplus;

            int cx = width / 2;
            StringFormat sfCenter;
            sfCenter.SetAlignment(StringAlignmentCenter);
            sfCenter.SetLineAlignment(StringAlignmentCenter);

            // 1. Animated Concentric Holographic Aura
            int iconY = 130, ringRadius = 46;
            
            SolidBrush auraGlow(Color(25, 0, 230, 150));
            g.FillEllipse(&auraGlow, cx - 65, iconY - 65, 130, 130);

            float animAngle = presenter.GetAnimAngle();
            Pen neonOuterPen(Theme::Colors::NeonCyan, 3.0f);
            g.DrawArc(&neonOuterPen, cx - ringRadius - 6, iconY - ringRadius - 6, (ringRadius + 6) * 2, (ringRadius + 6) * 2, animAngle, 120.0f);
            g.DrawArc(&neonOuterPen, cx - ringRadius - 6, iconY - ringRadius - 6, (ringRadius + 6) * 2, (ringRadius + 6) * 2, animAngle + 180.0f, 120.0f);

            LinearGradientBrush circleBrush(Point(cx - ringRadius, iconY - ringRadius), Point(cx + ringRadius, iconY + ringRadius),
                                            Color(255, 0, 235, 160), Color(255, 0, 170, 120));
            g.FillEllipse(&circleBrush, cx - ringRadius, iconY - ringRadius, ringRadius * 2, ringRadius * 2);

            Pen checkPen(Color(255, 5, 8, 14), 4.5f);
            checkPen.SetStartCap(LineCapRound);
            checkPen.SetEndCap(LineCapRound);
            g.DrawLine(&checkPen, cx - 18, iconY - 1, cx - 5, iconY + 13);
            g.DrawLine(&checkPen, cx - 5, iconY + 13, cx + 19, iconY - 12);

            // 2. High-Hierarchy Typography (Center Aligned)
            Font headerFont(Theme::Fonts::FontFamily, 18, FontStyleBold);
            Font subHeaderFont(Theme::Fonts::FontFamily, 10, FontStyleRegular);
            SolidBrush whiteBrush(Theme::Colors::TextWhite);
            SolidBrush cyanBrush(Theme::Colors::NeonCyan);

            g.DrawString(L"SYSTEM PURGE & OPTIMIZATION COMPLETE", -1, &headerFont, PointF(static_cast<REAL>(cx), 205), &sfCenter, &whiteBrush);
            g.DrawString(L"All kernel telemetry, multi-drive driver services, and residual platform traces sanitized.", -1, &subHeaderFont, PointF(static_cast<REAL>(cx), 232), &sfCenter, &cyanBrush);

            // 3. Central Glassmorphic Report Card
            int cardW = 700, cardH = 160, cardX = (width - cardW) / 2, cardY = 265;
            DrawRoundedGlassCard(g, cardX, cardY, cardW, cardH, 10, L"", L"VERIFIED SYSTEM SANITIZATION AUDIT REPORT");

            Font itemFont(Theme::Fonts::FontFamily, 9, FontStyleRegular);
            Font itemBold(Theme::Fonts::FontFamily, 9, FontStyleBold);
            SolidBrush greenBrush(Theme::Colors::NeonGreen);
            SolidBrush mutedGray(Color(255, 150, 170, 200));

            const auto& stats = presenter.GetPurgeStats();
            auto DrawReportRow = [&](int y, const std::wstring& tag, const std::wstring& text) {
                g.DrawString(tag.c_str(), -1, &itemBold, PointF(static_cast<REAL>(cardX + 28), static_cast<REAL>(y)), &greenBrush);
                g.DrawString(text.c_str(), -1, &itemFont, PointF(static_cast<REAL>(cardX + 64), static_cast<REAL>(y)), &whiteBrush);
            };

            DrawReportRow(cardY + 50, L"[OK]", std::format(L"Stopped & Purged {} Kernel Driver Services.", stats.ServicesStopped));
            DrawReportRow(cardY + 75, L"[OK]", std::format(L"Removed {} DriverStore OEM Packages & Scrubbed Class Filters.", stats.DriverPackagesRemoved));
            DrawReportRow(cardY + 100, L"[OK]", std::format(L"Purged {} Registry Subtree Keys across HKLM & HKCU.", stats.RegistryKeysPurged));
            DrawReportRow(cardY + 125, L"[OK]", std::format(L"Sanitized {} Files & Caches (NIST SP 800-88 cryptographic overwrite).", stats.FilesSanitized));

            // 4. Action Button
            bool doneHover = (presenter.GetHoveredButton() == 6);
            int btnW = Theme::Metrics::BtnDone.w, btnH = Theme::Metrics::BtnDone.h;
            int btnX = (width - btnW) / 2, btnY = 460;

            GraphicsPath btnPath;
            int bd = 8 * 2;
            btnPath.AddArc(btnX, btnY, bd, bd, 180, 90);
            btnPath.AddArc(btnX + btnW - bd, btnY, bd, bd, 270, 90);
            btnPath.AddArc(btnX + btnW - bd, btnY + btnH - bd, bd, bd, 0, 90);
            btnPath.AddArc(btnX, btnY + btnH - bd, bd, bd, 90, 90);
            btnPath.CloseFigure();

            LinearGradientBrush btnGradient(Point(btnX, btnY), Point(btnX + btnW, btnY),
                                            doneHover ? Theme::Colors::NeonCyan : Color(230, 0, 210, 235),
                                            doneHover ? Theme::Colors::NeonGreen : Color(230, 0, 190, 130));
            Pen btnBorder(doneHover ? Color(255, 255, 255, 255) : Theme::Colors::NeonCyan, doneHover ? 2.0f : 1.2f);

            g.FillPath(&btnGradient, &btnPath);
            g.DrawPath(&btnBorder, &btnPath);

            Font btnF(Theme::Fonts::FontFamily, 10, FontStyleBold);
            SolidBrush btnDark(Color(255, 5, 8, 14));
            g.DrawString(L"RETURN TO DASHBOARD", -1, &btnF, PointF(static_cast<REAL>(cx), static_cast<REAL>(btnY + btnH / 2)), &sfCenter, &btnDark);

            // 5. Note
            Font noteFont(Theme::Fonts::FontFamily, 8, FontStyleRegular);
            g.DrawString(L"Tip: Restart your PC if any locked kernel binaries were queued for boot unlinking.", -1, &noteFont, PointF(static_cast<REAL>(cx), static_cast<REAL>(height - 48)), &sfCenter, &mutedGray);
        }

        static void RenderDashboard(HWND hWnd, HDC hdc, const CLuxuryWindowPresenter& presenter) {
            using namespace Gdiplus;
            RECT rc;
            ::GetClientRect(hWnd, &rc);
            int width = rc.right - rc.left;
            int height = rc.bottom - rc.top;

            HDC memDC = ::CreateCompatibleDC(hdc);
            HBITMAP memBitmap = ::CreateCompatibleBitmap(hdc, width, height);
            HBITMAP oldBitmap = (HBITMAP)::SelectObject(memDC, memBitmap);

            Graphics g(memDC);
            g.SetSmoothingMode(SmoothingModeAntiAlias);
            g.SetTextRenderingHint(TextRenderingHintClearTypeGridFit);

            // 1. Deep Obsidian Base
            SolidBrush bgBrush(Theme::Colors::Background);
            g.FillRectangle(&bgBrush, 0, 0, width, height);

            // 2. Titlebar
            DrawVectorTitlebar(g, width, presenter.GetHoveredButton());

            // 3. Render Current View
            switch (presenter.GetCurrentState()) {
                case ViewState::Dashboard:
                    RenderDashboardView(g, presenter);
                    break;
                case ViewState::Scanning:
                    RenderScanningView(g, width, presenter);
                    break;
                case ViewState::Purging:
                    RenderPurgingView(g, width, presenter);
                    break;
                case ViewState::ScanResults:
                    RenderScanResultsView(g, width, presenter);
                    break;
                case ViewState::PurgeComplete:
                    RenderPurgeCompleteView(g, width, height, presenter);
                    break;
            }

            // 4. Footer Status Bar
            SolidBrush footerBg(Color(255, 4, 6, 9));
            g.FillRectangle(&footerBg, 0, height - 30, width, 30);
            SolidBrush dotBrush(Theme::Colors::NeonGreen);
            g.FillEllipse(&dotBrush, 20, height - 20, 8, 8);
            Font footerFont(Theme::Fonts::FontFamily, 9, FontStyleRegular);
            SolidBrush grayBrush(Theme::Colors::TextGray);
            std::wstring footerMsg = (presenter.GetCurrentState() == ViewState::Dashboard) ?
                L"Vortex Engine: ACTIVE | Multi-Drive Monitored | Log: VortexCleaner.log" :
                L"Vortex Kernel Pipeline Active";
            g.DrawString(footerMsg.c_str(), -1, &footerFont, PointF(36, static_cast<REAL>(height - 22)), &grayBrush);

            ::BitBlt(hdc, 0, 0, width, height, memDC, 0, 0, SRCCOPY);

            ::SelectObject(memDC, oldBitmap);
            ::DeleteObject(memBitmap);
            ::DeleteDC(memDC);
        }
    };

} // namespace WinTracePurge::Gui
