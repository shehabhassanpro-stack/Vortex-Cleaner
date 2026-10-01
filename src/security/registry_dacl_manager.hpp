#pragma once

#include "../core/result.hpp"
#include "../core/logger.hpp"
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <string>
#include <string_view>
#include <vector>
#include <format>

#pragma comment(lib, "advapi32.lib")

#include "authorization_engine.hpp"

namespace WinTracePurge::Security {

    /// @brief Backward-compatibility facade delegating to CAuthorizationEngine.
    class CRegistryDaclManager {
    public:
        // Seizes ownership of a protected registry key and grants Full Control (KEY_ALL_ACCESS) to Administrators
        static Core::Result<bool> TakeOwnershipAndGrantAccess(HKEY hRootKey, std::wstring_view subKeyPath) {
            return CAuthorizationEngine::TakeOwnershipAndGrantRegistryAccess(hRootKey, subKeyPath);
        }

        // Forcefully unhooks and wipes a service key from the registry
        static bool ForceDeleteServiceKey(std::wstring_view serviceName) {
            return CAuthorizationEngine::ForceDeleteServiceKey(serviceName);
        }
    };

} // namespace WinTracePurge::Security
