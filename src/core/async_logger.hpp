#pragma once

#include "zstring_view.hpp"
#include <windows.h>
#include <string>
#include <vector>
#include <deque>
#include <fstream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <format>
#include <memory>

namespace WinTracePurge::Core {

    enum class LogLevel : uint8_t {
        Trace = 0,
        Debug,
        Info,
        Warn,
        Error,
        Critical
    };

    struct LogMessage {
        LogLevel Level = LogLevel::Info;
        DWORD ThreadId = 0;
        std::chrono::system_clock::time_point Timestamp = std::chrono::system_clock::now();
        std::wstring Subsystem;
        std::wstring Text;
        DWORD Win32Error = 0;
    };

    /// @brief Production-grade asynchronous logger backend.
    /// Completely decouples storage I/O from execution worker threads using an MPSC batching queue.
    /// Performs direct binary UTF-8 writes without Windows locale/codecvt runtime stalls.
    /// Maintains an in-memory O(1) circular buffer for thread-safe UI terminal consumption.
    class CAsyncLogBackend {
    public:
        static void Initialize(zstring_view logFilePath = L"VortexCleaner.log") {
            std::call_once(s_InitFlag, [path = std::wstring(logFilePath.c_str())] {
                s_LogFilePath = path;
                s_Running.store(true, std::memory_order_release);
                s_WorkerThread = std::jthread(WorkerThreadProc);

                // Emit session start record
                PostLogInternal(LogLevel::Info, L"Logger", L"=== Vortex Cleaner Asynchronous Logging Engine Initialized ===");
            });
        }

        static void Shutdown() noexcept {
            {
                std::lock_guard<std::mutex> lock(s_QueueMutex);
                if (!s_Running.load(std::memory_order_relaxed)) {
                    return;
                }
                s_Running.store(false, std::memory_order_release);
            }
            s_CV.notify_all();

            if (s_WorkerThread.joinable()) {
                s_WorkerThread.join();
            }
        }

        template <typename T>
        requires std::same_as<std::remove_cvref_t<T>, std::wstring>
        static void PostLog(LogLevel level, zstring_view subsystem, T&& message, DWORD win32Error = 0) noexcept {
            if (!s_Running.load(std::memory_order_relaxed)) {
                Initialize();
            }
            PostLogInternal(level, subsystem, std::forward<T>(message), win32Error);
        }

        static void PostLog(LogLevel level, zstring_view subsystem, std::wstring_view message, DWORD win32Error = 0) noexcept {
            PostLog(level, subsystem, std::wstring(message), win32Error);
        }

        /// @brief Thread-safe snapshot retrieval for presentation layer / GUI terminal feed.
        [[nodiscard]] static std::vector<std::wstring> GetRecentLogsSnapshot() {
            std::lock_guard<std::mutex> lock(s_SnapshotMutex);
            return std::vector<std::wstring>(s_RecentLogs.begin(), s_RecentLogs.end());
        }

    private:
        static constexpr size_t kMaxQueueCapacity = 10000;
        static constexpr size_t kMaxRecentLogs = 50;

        inline static std::once_flag s_InitFlag;
        inline static std::mutex s_QueueMutex;
        inline static std::mutex s_SnapshotMutex;
        inline static std::condition_variable s_CV;
        inline static std::atomic<bool> s_Running{false};
        inline static std::atomic<uint64_t> s_DroppedRecords{0};

        inline static std::wstring s_LogFilePath;
        inline static std::vector<LogMessage> s_IncomingQueue;
        inline static std::deque<std::wstring> s_RecentLogs;
        inline static std::jthread s_WorkerThread;

        static void PostLogInternal(LogLevel level, zstring_view subsystem, std::wstring message, DWORD win32Error = 0) noexcept {
            LogMessage msg{
                .Level = level,
                .ThreadId = ::GetCurrentThreadId(),
                .Timestamp = std::chrono::system_clock::now(),
                .Subsystem = std::wstring(subsystem),
                .Text = std::move(message),
                .Win32Error = win32Error
            };

            {
                std::lock_guard<std::mutex> lock(s_QueueMutex);
                // Bounded queue: discard if overloaded under catastrophic disk stall
                if (s_IncomingQueue.size() < kMaxQueueCapacity) {
                    s_IncomingQueue.push_back(std::move(msg));
                } else {
                    s_DroppedRecords.fetch_add(1, std::memory_order_relaxed);
                }
            }
            s_CV.notify_one();
        }

        static std::string WideToUtf8(std::wstring_view wstr) noexcept {
            if (wstr.empty()) return {};
            int len = ::WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
            if (len <= 0) return {};
            std::string utf8(len, '\0');
            ::WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), utf8.data(), len, nullptr, nullptr);
            return utf8;
        }

        static void WorkerThreadProc() {
            std::ofstream logFile;
            logFile.open(s_LogFilePath, std::ios::out | std::ios::binary | std::ios::app);
            if (!logFile.is_open()) {
                ::OutputDebugStringW(L"[CAsyncLogBackend] Primary log file open failed; attempting %TEMP% fallback...\n");
                WCHAR tempPath[MAX_PATH];
                if (::GetTempPathW(MAX_PATH, tempPath) > 0) {
                    std::wstring fallbackPath = std::wstring(tempPath) + L"VortexCleaner_Fallback.log";
                    logFile.open(fallbackPath, std::ios::out | std::ios::binary | std::ios::app);
                    if (logFile.is_open()) {
                        ::OutputDebugStringW(L"[CAsyncLogBackend] Fallback log file opened successfully in %TEMP%.\n");
                    }
                }
            }

            std::vector<LogMessage> processingQueue;
            processingQueue.reserve(256);

            while (s_Running.load(std::memory_order_acquire)) {
                {
                    std::unique_lock<std::mutex> lock(s_QueueMutex);
                    s_CV.wait_for(lock, std::chrono::milliseconds(100), [] {
                        return !s_IncomingQueue.empty() || !s_Running.load(std::memory_order_relaxed);
                    });

                    if (s_IncomingQueue.empty() && !s_Running.load(std::memory_order_relaxed)) {
                        break;
                    }

                    processingQueue.swap(s_IncomingQueue);
                }

                if (!processingQueue.empty()) {
                    ProcessLogBatch(processingQueue, logFile);
                    processingQueue.clear();
                }
            }

            // Drain remaining queued records on shutdown
            {
                std::lock_guard<std::mutex> lock(s_QueueMutex);
                processingQueue.swap(s_IncomingQueue);
            }
            if (!processingQueue.empty()) {
                ProcessLogBatch(processingQueue, logFile);
            }

            if (logFile.is_open()) {
                logFile.flush();
                logFile.close();
            }
        }

        static void ProcessLogBatch(const std::vector<LogMessage>& batch, std::ofstream& file) {
            bool requiresFlush = false;

            for (const auto& msg : batch) {
                auto timeT = std::chrono::system_clock::to_time_t(msg.Timestamp);
                auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(msg.Timestamp.time_since_epoch()) % 1000;

                tm localTime{};
                localtime_s(&localTime, &timeT);

                const wchar_t* levelStr = L"INFO";
                switch (msg.Level) {
                    case LogLevel::Trace:    levelStr = L"TRACE"; break;
                    case LogLevel::Debug:    levelStr = L"DEBUG"; break;
                    case LogLevel::Info:     levelStr = L"INFO";  break;
                    case LogLevel::Warn:     levelStr = L"WARN";  break;
                    case LogLevel::Error:    levelStr = L"ERROR"; requiresFlush = true; break;
                    case LogLevel::Critical: levelStr = L"CRIT";  requiresFlush = true; break;
                }

                std::wstring formattedLog;
                if (msg.Win32Error != 0) {
                    formattedLog = std::format(
                        L"[{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}.{:03d}] [{}] [TID:{:05d}] [{}] {} (Win32 Error: 0x{:08X})",
                        localTime.tm_year + 1900, localTime.tm_mon + 1, localTime.tm_mday,
                        localTime.tm_hour, localTime.tm_min, localTime.tm_sec, ms.count(),
                        levelStr, msg.ThreadId, msg.Subsystem, msg.Text, msg.Win32Error
                    );
                } else {
                    formattedLog = std::format(
                        L"[{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}.{:03d}] [{}] [TID:{:05d}] [{}] {}",
                        localTime.tm_year + 1900, localTime.tm_mon + 1, localTime.tm_mday,
                        localTime.tm_hour, localTime.tm_min, localTime.tm_sec, ms.count(),
                        levelStr, msg.ThreadId, msg.Subsystem, msg.Text
                    );
                }

                // 1. Write binary UTF-8 line to file
                if (file.is_open()) {
                    std::string utf8Line = WideToUtf8(formattedLog) + "\r\n";
                    file.write(utf8Line.data(), utf8Line.size());
                }

                // 2. Update UI circular buffer with O(1) front push and back pop
                {
                    std::lock_guard<std::mutex> lock(s_SnapshotMutex);
                    s_RecentLogs.push_front(formattedLog);
                    if (s_RecentLogs.size() > kMaxRecentLogs) {
                        s_RecentLogs.pop_back();
                    }
                }
            }

            if (requiresFlush && file.is_open()) {
                file.flush();
            }
        }
    };

} // namespace WinTracePurge::Core
