#pragma once

#include "async_logger.hpp"
#include "zstring_view.hpp"
#include <string_view>
#include <vector>
#include <string>

namespace WinTracePurge::Core {

    /// @brief High-performance facade for asynchronous application logging.
    /// Routes all logging calls directly to CAsyncLogBackend, ensuring zero disk I/O stalls on caller threads.
    class CAppLogger {
    public:
        static void Initialize(zstring_view logFilename = L"VortexCleaner.log") {
            CAsyncLogBackend::Initialize(logFilename);
        }

        static void Shutdown() noexcept {
            CAsyncLogBackend::Shutdown();
        }

        template <typename T>
        requires std::same_as<std::remove_cvref_t<T>, std::wstring>
        static void Log(LogLevel level, zstring_view subsystem, T&& message, DWORD win32Error = 0) noexcept {
            CAsyncLogBackend::PostLog(level, subsystem, std::forward<T>(message), win32Error);
        }

        static void Log(LogLevel level, zstring_view subsystem, std::wstring_view message, DWORD win32Error = 0) noexcept {
            CAsyncLogBackend::PostLog(level, subsystem, message, win32Error);
        }

        static void LogTrace(zstring_view subsystem, std::wstring_view message) noexcept {
            Log(LogLevel::Trace, subsystem, message);
        }

        static void LogDebug(zstring_view subsystem, std::wstring_view message) noexcept {
            Log(LogLevel::Debug, subsystem, message);
        }

        static void LogInfo(zstring_view subsystem, std::wstring_view message) noexcept {
            Log(LogLevel::Info, subsystem, message);
        }

        static void LogWarn(zstring_view subsystem, std::wstring_view message, DWORD win32Error = 0) noexcept {
            Log(LogLevel::Warn, subsystem, message, win32Error);
        }

        static void LogError(zstring_view subsystem, std::wstring_view message, DWORD win32Error = 0) noexcept {
            Log(LogLevel::Error, subsystem, message, win32Error);
        }

        static void LogCritical(zstring_view subsystem, std::wstring_view message, DWORD win32Error = 0) noexcept {
            Log(LogLevel::Critical, subsystem, message, win32Error);
        }

        [[nodiscard]] static std::vector<std::wstring> GetRecentLogs() {
            return CAsyncLogBackend::GetRecentLogsSnapshot();
        }
    };

} // namespace WinTracePurge::Core
