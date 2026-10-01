#pragma once

#include <string>
#include <string_view>
#include <expected>
#include <system_error>
#include <windows.h>
#include <format>

namespace WinTracePurge::Core {

    enum class ErrorCode {
        Success = 0,
        AccessDenied,
        SharingViolation,
        PathNotFound,
        ServiceNotFound,
        ServiceStopTimeout,
        DriverStoreFailed,
        RegistryFailed,
        SanitizationFailed,
        VssSnapshotFailed,
        InvalidParameter,
        UnknownError
    };

    struct SystemError {
        ErrorCode Code = ErrorCode::UnknownError;
        DWORD Win32Error = 0;
        std::wstring Message;

        SystemError(ErrorCode code, DWORD win32Error = 0, std::wstring_view message = L"")
            : Code(code), Win32Error(win32Error), Message(message) {}

        static SystemError FromWin32(DWORD dwError, std::wstring_view context = L"") {
            ErrorCode code = ErrorCode::UnknownError;
            switch (dwError) {
                case ERROR_SUCCESS:
                    code = ErrorCode::Success;
                    break;
                case ERROR_ACCESS_DENIED:
                case ERROR_PRIVILEGE_NOT_HELD:
                    code = ErrorCode::AccessDenied;
                    break;
                case ERROR_SHARING_VIOLATION:
                case ERROR_LOCK_VIOLATION:
                    code = ErrorCode::SharingViolation;
                    break;
                case ERROR_FILE_NOT_FOUND:
                case ERROR_PATH_NOT_FOUND:
                    code = ErrorCode::PathNotFound;
                    break;
                case ERROR_SERVICE_DOES_NOT_EXIST:
                    code = ErrorCode::ServiceNotFound;
                    break;
                default:
                    code = ErrorCode::UnknownError;
                    break;
            }

            std::wstring msg;
            if (!context.empty()) {
                msg = std::format(L"{} (Win32 Error: 0x{:08X})", context, dwError);
            } else {
                msg = std::format(L"Win32 Error: 0x{:08X}", dwError);
            }

            return SystemError(code, dwError, msg);
        }

        static SystemError FromLastError(std::wstring_view context = L"") {
            const DWORD dwError = ::GetLastError();
            return FromWin32(dwError, context);
        }
    };

    template <typename T>
    using Result = std::expected<T, SystemError>;

} // namespace WinTracePurge::Core
