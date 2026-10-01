#pragma once

#include "../core/result.hpp"
#include "../core/zstring_view.hpp"
#include "../core/scoped_resource.hpp"
#include <windows.h>
#include <vector>
#include <span>
#include <initializer_list>
#include <string_view>
#include <format>

namespace WinTracePurge::Security {

    /// @brief RAII manager for Windows NT Token Privileges.
    /// Strictly resolves VTX-SYS-011 by calling ::SetLastError(ERROR_SUCCESS) prior to ::AdjustTokenPrivileges
    /// and deterministically validating privilege assignment. Automatically restores original token state upon destruction.
    class TokenPrivilegeScope {
    public:
        struct RestorablePrivilege {
            LUID Luid{};
            DWORD PreviousAttributes = 0;
        };

        TokenPrivilegeScope() noexcept = default;

        ~TokenPrivilegeScope() noexcept {
            Restore();
        }

        TokenPrivilegeScope(const TokenPrivilegeScope&) = delete;
        TokenPrivilegeScope& operator=(const TokenPrivilegeScope&) = delete;

        TokenPrivilegeScope(TokenPrivilegeScope&& other) noexcept 
            : m_hToken(std::move(other.m_hToken)),
              m_restorablePrivileges(std::move(other.m_restorablePrivileges)) {}

        TokenPrivilegeScope& operator=(TokenPrivilegeScope&& other) noexcept {
            if (this != &other) {
                Restore();
                m_hToken = std::move(other.m_hToken);
                m_restorablePrivileges = std::move(other.m_restorablePrivileges);
            }
            return *this;
        }

        /// @brief Acquires and elevates an initializer list of requested privileges.
        [[nodiscard]] static Core::Result<TokenPrivilegeScope> Acquire(std::initializer_list<Core::zstring_view> privileges) {
            return Acquire(std::span<const Core::zstring_view>(privileges.begin(), privileges.size()));
        }

        /// @brief Acquires and elevates a span of requested privileges, caching previous states.
        [[nodiscard]] static Core::Result<TokenPrivilegeScope> Acquire(std::span<const Core::zstring_view> privileges) {
            TokenPrivilegeScope scope;

            if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, scope.m_hToken.Put())) {
                return std::unexpected(Core::SystemError::FromLastError(L"OpenProcessToken failed"));
            }

            scope.m_restorablePrivileges.reserve(privileges.size());

            for (const auto& privName : privileges) {
                LUID luid{};
                if (!::LookupPrivilegeValueW(nullptr, privName.c_str(), &luid)) {
                    return std::unexpected(Core::SystemError::FromLastError(
                        std::format(L"LookupPrivilegeValueW failed for '{}'", privName.c_str())));
                }

                TOKEN_PRIVILEGES tp{};
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                TOKEN_PRIVILEGES prevTp{};
                DWORD returnLength = sizeof(prevTp);

                // STRICT RESOLUTION FOR VTX-SYS-011:
                // AdjustTokenPrivileges returns TRUE even if privileges were not assigned.
                // We MUST set last error to ERROR_SUCCESS prior to calling it and check afterwards.
                ::SetLastError(ERROR_SUCCESS);
                BOOL bRet = ::AdjustTokenPrivileges(
                    scope.m_hToken.Get(),
                    FALSE,
                    &tp,
                    sizeof(tp),
                    &prevTp,
                    &returnLength
                );

                DWORD dwErr = ::GetLastError();
                if (!bRet || dwErr != ERROR_SUCCESS) {
                    return std::unexpected(Core::SystemError::FromWin32(
                        dwErr != ERROR_SUCCESS ? dwErr : ERROR_ACCESS_DENIED,
                        std::format(L"Failed to enable token privilege '{}'", privName.c_str())
                    ));
                }

                if (prevTp.PrivilegeCount > 0) {
                    scope.m_restorablePrivileges.push_back(RestorablePrivilege{
                        .Luid = prevTp.Privileges[0].Luid,
                        .PreviousAttributes = prevTp.Privileges[0].Attributes
                    });
                }
            }

            return scope;
        }

        /// @brief Convenience helper to acquire all five critical kernel and storage privileges.
        [[nodiscard]] static Core::Result<TokenPrivilegeScope> AcquireAllRequired() {
            constexpr Core::zstring_view kRequiredPrivileges[] = {
                SE_DEBUG_NAME,
                SE_TAKE_OWNERSHIP_NAME,
                SE_RESTORE_NAME,
                SE_BACKUP_NAME,
                SE_SECURITY_NAME
            };
            return Acquire(kRequiredPrivileges);
        }

    private:
        Core::ScopedHandle m_hToken;
        std::vector<RestorablePrivilege> m_restorablePrivileges;

        void Restore() noexcept {
            if (!m_hToken.IsValid() || m_restorablePrivileges.empty()) {
                return;
            }

            for (const auto& item : m_restorablePrivileges) {
                TOKEN_PRIVILEGES tp{};
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Luid = item.Luid;
                tp.Privileges[0].Attributes = item.PreviousAttributes;

                ::AdjustTokenPrivileges(m_hToken.Get(), FALSE, &tp, sizeof(tp), nullptr, nullptr);
            }

            m_restorablePrivileges.clear();
        }
    };

} // namespace WinTracePurge::Security
