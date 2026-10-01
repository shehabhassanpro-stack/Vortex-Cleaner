#pragma once

#include "token_privilege_scope.hpp"
#include "../core/result.hpp"
#include "../core/scoped_resource.hpp"
#include "../core/zstring_view.hpp"
#include <windows.h>
#include <aclapi.h>
#include <vector>
#include <string_view>
#include <format>

#include "authorization_engine.hpp"

namespace WinTracePurge::Security {

    class CSecurityManager {
    public:
        static Core::Result<bool> EnablePrivilege(Core::zstring_view privilegeName) {
            Core::ScopedHandle hToken;
            if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, hToken.Put())) {
                return std::unexpected(Core::SystemError::FromLastError(L"Failed to open process token"));
            }

            LUID luid{};
            if (!::LookupPrivilegeValueW(nullptr, privilegeName.c_str(), &luid)) {
                return std::unexpected(Core::SystemError::FromLastError(
                    std::format(L"LookupPrivilegeValue failed for '{}'", privilegeName.c_str())));
            }

            TOKEN_PRIVILEGES tp{};
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            // Strictly resolve VTX-SYS-011: Clear last error before invocation
            ::SetLastError(ERROR_SUCCESS);
            BOOL bRet = ::AdjustTokenPrivileges(hToken.Get(), FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
            DWORD dwErr = ::GetLastError();

            if (!bRet || dwErr != ERROR_SUCCESS) {
                return std::unexpected(Core::SystemError(
                    Core::ErrorCode::AccessDenied,
                    dwErr != ERROR_SUCCESS ? dwErr : ERROR_ACCESS_DENIED,
                    std::format(L"Privilege '{}' not assigned to token", privilegeName.c_str())
                ));
            }

            return true;
        }

        /// @brief Acquires all required kernel/storage privileges wrapped in an ephemeral RAII scope.
        /// Resolves VTX-AUDIT-014 by eliminating the persistent static token scope leak.
        static Core::Result<TokenPrivilegeScope> EnableAllRequiredPrivileges() {
            return TokenPrivilegeScope::AcquireAllRequired();
        }

        /// @brief Delegates to centralized CAuthorizationEngine (VTX-AUDIT-020).
        static Core::Result<bool> TakeOwnershipAndGrantAccess(Core::zstring_view targetPath, SE_OBJECT_TYPE objectType) {
            return CAuthorizationEngine::TakeOwnershipAndGrantAccess(targetPath, objectType);
        }
    };

} // namespace WinTracePurge::Security
