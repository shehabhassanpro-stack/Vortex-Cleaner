#pragma once

#include "../core/result.hpp"
#include "../core/logger.hpp"
#include "../core/scoped_resource.hpp"
#include "../core/zstring_view.hpp"
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <string>
#include <string_view>
#include <vector>
#include <format>

#pragma comment(lib, "advapi32.lib")

namespace WinTracePurge::Security {

    /// @brief Centralized Windows NT Security, Ownership Seizure, and DACL Authorization Engine.
    /// Strictly resolves VTX-AUDIT-003 and VTX-AUDIT-020 by unifying ownership escalation and DACL construction
    /// with zero resource leaks using RAII ScopedSid and ScopedAcl wrappers.
    class CAuthorizationEngine {
    public:
        /// @brief Seizes ownership of any securable Windows NT object and grants Full Control to Administrators & SYSTEM.
        static Core::Result<bool> TakeOwnershipAndGrantAccess(
            Core::zstring_view targetPath,
            SE_OBJECT_TYPE objectType = SE_REGISTRY_KEY) {

            // 1. Allocate Builtin Administrators SID with verified return check (VTX-AUDIT-003)
            Core::ScopedSid pAdminSid;
            SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
            if (!::AllocateAndInitializeSid(
                &ntAuthority, 2,
                SECURITY_BUILTIN_DOMAIN_RID,
                DOMAIN_ALIAS_RID_ADMINS,
                0, 0, 0, 0, 0, 0,
                pAdminSid.Put())) {
                return std::unexpected(Core::SystemError::FromLastError(L"AllocateAndInitializeSid (Admins) failed"));
            }

            // 2. Seize Ownership of the targeted object
            DWORD dwRes = ::SetNamedSecurityInfoW(
                const_cast<LPWSTR>(targetPath.c_str()),
                objectType,
                OWNER_SECURITY_INFORMATION,
                pAdminSid.Get(),
                nullptr, nullptr, nullptr
            );

            if (dwRes != ERROR_SUCCESS) {
                Core::CAppLogger::LogWarn(L"AuthEngine",
                    std::format(L"SetNamedSecurityInfoW (Owner) for '{}' returned: 0x{:08X}", targetPath.c_str(), dwRes), dwRes);
            }

            // 3. Allocate Local SYSTEM SID with verified return check (VTX-AUDIT-003)
            Core::ScopedSid pSystemSid;
            if (!::AllocateAndInitializeSid(
                &ntAuthority, 1,
                SECURITY_LOCAL_SYSTEM_RID,
                0, 0, 0, 0, 0, 0, 0,
                pSystemSid.Put())) {
                return std::unexpected(Core::SystemError::FromLastError(L"AllocateAndInitializeSid (SYSTEM) failed"));
            }

            // 4. Construct Explicit Access Entries for Administrators and SYSTEM
            EXPLICIT_ACCESS_W ea[2] = {};

            // Administrators: Full Control
            ea[0].grfAccessPermissions = (objectType == SE_REGISTRY_KEY) ? (KEY_ALL_ACCESS | GENERIC_ALL) : GENERIC_ALL;
            ea[0].grfAccessMode = SET_ACCESS;
            ea[0].grfInheritance = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
            ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
            ea[0].Trustee.ptstrName = reinterpret_cast<LPWSTR>(pAdminSid.Get());

            // SYSTEM: Full Control
            ea[1].grfAccessPermissions = (objectType == SE_REGISTRY_KEY) ? (KEY_ALL_ACCESS | GENERIC_ALL) : GENERIC_ALL;
            ea[1].grfAccessMode = SET_ACCESS;
            ea[1].grfInheritance = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
            ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
            ea[1].Trustee.ptstrName = reinterpret_cast<LPWSTR>(pSystemSid.Get());

            Core::ScopedAcl pNewDacl;
            dwRes = ::SetEntriesInAclW(2, ea, nullptr, pNewDacl.Put());
            if (dwRes != ERROR_SUCCESS || !pNewDacl.IsValid()) {
                return std::unexpected(Core::SystemError::FromWin32(dwRes, L"SetEntriesInAclW failed"));
            }

            // 5. Apply the protective DACL to the target object
            dwRes = ::SetNamedSecurityInfoW(
                const_cast<LPWSTR>(targetPath.c_str()),
                objectType,
                DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                nullptr, nullptr, pNewDacl.Get(), nullptr
            );

            if (dwRes != ERROR_SUCCESS) {
                return std::unexpected(Core::SystemError::FromWin32(dwRes, L"SetNamedSecurityInfoW (DACL) failed"));
            }

            return true;
        }

        /// @brief Standardized registry subkey ownership seizure supporting root hives.
        static Core::Result<bool> TakeOwnershipAndGrantRegistryAccess(HKEY hRootKey, std::wstring_view subKeyPath) {
            std::wstring fullPath;
            if (hRootKey == HKEY_LOCAL_MACHINE) {
                fullPath = L"MACHINE\\" + std::wstring(subKeyPath);
            } else if (hRootKey == HKEY_CURRENT_USER) {
                fullPath = L"CURRENT_USER\\" + std::wstring(subKeyPath);
            } else if (hRootKey == HKEY_CLASSES_ROOT) {
                fullPath = L"CLASSES_ROOT\\" + std::wstring(subKeyPath);
            } else {
                fullPath = std::wstring(subKeyPath);
            }

            return TakeOwnershipAndGrantAccess(Core::zstring_view(fullPath), SE_REGISTRY_KEY);
        }

        /// @brief Forcefully unhooks, disables, and deletes a protected service key across CurrentControlSet and ControlSet001.
        static bool ForceDeleteServiceKey(std::wstring_view serviceName) {
            std::wstring ccsPath = std::format(L"SYSTEM\\CurrentControlSet\\Services\\{}", serviceName);
            std::wstring cs001Path = std::format(L"SYSTEM\\ControlSet001\\Services\\{}", serviceName);

            // 1. CurrentControlSet
            (void)TakeOwnershipAndGrantRegistryAccess(HKEY_LOCAL_MACHINE, ccsPath);
            Core::ScopedHKey hKey;
            if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, ccsPath.c_str(), 0, KEY_SET_VALUE | KEY_WOW64_64KEY, hKey.Put()) == ERROR_SUCCESS) {
                DWORD disabledVal = 4; // SERVICE_DISABLED
                ::RegSetValueExW(hKey.Get(), L"Start", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&disabledVal), sizeof(disabledVal));
                hKey.Reset();
            }
            (void)::RegDeleteTreeW(HKEY_LOCAL_MACHINE, ccsPath.c_str());

            // 2. ControlSet001
            (void)TakeOwnershipAndGrantRegistryAccess(HKEY_LOCAL_MACHINE, cs001Path);
            (void)::RegDeleteTreeW(HKEY_LOCAL_MACHINE, cs001Path.c_str());

            Core::CAppLogger::LogInfo(L"AuthEngine", std::format(L"Force-wiped service registry key for '{}'", serviceName));
            return true;
        }
    };

} // namespace WinTracePurge::Security
