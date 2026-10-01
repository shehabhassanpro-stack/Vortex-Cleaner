#pragma once

#include "../core/interfaces.hpp"
#include "../core/result.hpp"
#include "../core/scoped_resource.hpp"
#include "../core/logger.hpp"
#include "../core/zstring_view.hpp"
#include "../security/registry_dacl_manager.hpp"
#include <windows.h>
#include <string>
#include <string_view>
#include <vector>
#include <cwctype>
#include <format>
#include <algorithm>
#include <span>

namespace WinTracePurge::Registry {

    /// @brief Target configuration for registry subtree eradication.
    struct RegistryTarget {
        HKEY RootHive = HKEY_LOCAL_MACHINE;
        std::wstring SubKey;
        bool TargetBothViews = true;
    };

    /// @brief Hive validation helper to prevent cross-hive query pollution.
    /// Strictly resolves VTX-SYS-010 by ensuring machine paths are never queried in user hives.
    [[nodiscard]] inline bool IsHivePathCompatible(HKEY hRoot, std::wstring_view subKey) noexcept {
        auto isRootTokenOrPrefix = [](std::wstring_view str, std::wstring_view token) noexcept -> bool {
            if (str.size() < token.size()) return false;
            for (size_t i = 0; i < token.size(); ++i) {
                auto toUpper = [](wchar_t c) noexcept {
                    return (c >= L'a' && c <= L'z') ? static_cast<wchar_t>(c - (L'a' - L'A')) : c;
                };
                if (toUpper(str[i]) != toUpper(token[i])) {
                    return false;
                }
            }
            if (str.size() == token.size()) return true;
            return (str[token.size()] == L'\\' || str[token.size()] == L'/');
        };

        if (hRoot == HKEY_CURRENT_USER || hRoot == HKEY_CLASSES_ROOT) {
            if (isRootTokenOrPrefix(subKey, L"SYSTEM") ||
                isRootTokenOrPrefix(subKey, L"MACHINE") ||
                isRootTokenOrPrefix(subKey, L"SAM") ||
                isRootTokenOrPrefix(subKey, L"SECURITY") ||
                isRootTokenOrPrefix(subKey, L"HARDWARE")) {
                return false;
            }
        }

        if (hRoot == HKEY_LOCAL_MACHINE) {
            if (isRootTokenOrPrefix(subKey, L"CURRENT_USER") ||
                isRootTokenOrPrefix(subKey, L"USERS")) {
                return false;
            }
        }

        return true;
    }

    /// @brief Production-grade hive-aware dual-bitness recursive registry purge engine.
    /// Strictly resolves VTX-SYS-010 by using native handle-based enumeration and explicit RegDeleteKeyExW view flags.
    /// Fully implements the C++23 Core::ICleanerModule contract.
    class CRegistryPurgeEngine : public Core::ICleanerModule {
    private:
        std::vector<RegistryTarget> m_targets;

        /// @brief Helper to delete a leaf key from its immediate parent, handling multi-slash paths safely.
        static LSTATUS DeleteLeafKey(HKEY hRoot, const std::wstring& subKeyStr, DWORD viewFlag) {
            size_t lastSlash = subKeyStr.find_last_of(L"\\/");
            if (lastSlash != std::wstring::npos) {
                std::wstring parentPath = subKeyStr.substr(0, lastSlash);
                std::wstring leafName = subKeyStr.substr(lastSlash + 1);

                Core::ScopedHKey hParent;
                LSTATUS pStatus = ::RegOpenKeyExW(
                    hRoot,
                    parentPath.c_str(),
                    0,
                    KEY_READ | KEY_WRITE | DELETE | viewFlag,
                    hParent.Put()
                );
                if (pStatus == ERROR_SUCCESS) {
                    return ::RegDeleteKeyExW(hParent.Get(), leafName.c_str(), viewFlag, 0);
                }
            }
            return ::RegDeleteKeyExW(hRoot, subKeyStr.c_str(), viewFlag, 0);
        }

        /// @brief Recursively traverses and deletes all child subkeys of an already open parent key.
        static Core::Result<bool> DeleteChildrenInternal(HKEY hParent, DWORD viewFlag) {
            std::vector<std::wstring> childNames;
            DWORD dwIndex = 0;
            WCHAR szName[256];
            DWORD dwNameLen = ARRAYSIZE(szName);

            // Collect all subkey names first to prevent iteration shifting during deletion
            while (true) {
                dwNameLen = ARRAYSIZE(szName);
                LSTATUS enumStatus = ::RegEnumKeyExW(hParent, dwIndex, szName, &dwNameLen, nullptr, nullptr, nullptr, nullptr);
                if (enumStatus == ERROR_SUCCESS) {
                    childNames.emplace_back(szName, dwNameLen);
                    ++dwIndex;
                } else if (enumStatus == ERROR_MORE_DATA) {
                    std::vector<WCHAR> dynBuf(1024);
                    DWORD dynLen = static_cast<DWORD>(dynBuf.size());
                    if (::RegEnumKeyExW(hParent, dwIndex, dynBuf.data(), &dynLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                        childNames.emplace_back(dynBuf.data(), dynLen);
                    }
                    ++dwIndex;
                } else {
                    break;
                }
            }

            for (const auto& childName : childNames) {
                Core::ScopedHKey hChild;
                LSTATUS status = ::RegOpenKeyExW(
                    hParent,
                    childName.c_str(),
                    0,
                    DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_SET_VALUE | viewFlag,
                    hChild.Put()
                );
                if (status == ERROR_SUCCESS) {
                    (void)DeleteChildrenInternal(hChild.Get(), viewFlag);
                    hChild.Reset();
                }

                LSTATUS delStatus = ::RegDeleteKeyExW(hParent, childName.c_str(), viewFlag, 0);
                if (delStatus != ERROR_SUCCESS && delStatus != ERROR_FILE_NOT_FOUND) {
                    Core::CAppLogger::LogWarn(L"Registry", std::format(L"Failed to delete child key '{}' with status {}", childName, delStatus), delStatus);
                }
            }

            return true;
        }

    public:
        CRegistryPurgeEngine() {
            m_targets = {
                { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vgc", true },
                { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vgk", true },
                { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\EasyAntiCheat", true },
                { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\EasyAntiCheat_EOS", true },
                { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\BEService", true },
                { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Riot Games", true },
                { HKEY_CURRENT_USER,  L"Software\\Riot Games", true }
            };
        }

        explicit CRegistryPurgeEngine(std::vector<RegistryTarget> targets)
            : m_targets(std::move(targets)) {}

        [[nodiscard]] Core::zstring_view GetModuleName() const noexcept override {
            return L"RegistryPurgeEngine";
        }

        void AddTarget(HKEY rootHive, std::wstring subKey, bool targetBothViews = true) {
            m_targets.push_back(RegistryTarget{ rootHive, std::move(subKey), targetBothViews });
        }

        void SetTargets(std::vector<RegistryTarget> targets) {
            m_targets = std::move(targets);
        }

        void ClearTargets() noexcept {
            m_targets.clear();
        }

        /// @brief Surgical recursive deletion of a registry subkey respecting explicit bitness view.
        static Core::Result<bool> DeleteSubtreeRecursive(HKEY hRoot, std::wstring_view subKey, DWORD viewFlag) {
            if (subKey.empty()) {
                return std::unexpected(Core::SystemError::FromWin32(ERROR_INVALID_PARAMETER, L"Subkey path cannot be empty"));
            }

            if (!IsHivePathCompatible(hRoot, subKey)) {
                Core::CAppLogger::LogTrace(L"Registry", std::format(L"Skipping incompatible hive path '{}'", subKey));
                return true;
            }

            std::wstring subKeyStr(subKey);
            while (!subKeyStr.empty() && (subKeyStr.front() == L'\\' || subKeyStr.front() == L'/')) {
                subKeyStr.erase(0, 1);
            }
            while (!subKeyStr.empty() && (subKeyStr.back() == L'\\' || subKeyStr.back() == L'/')) {
                subKeyStr.pop_back();
            }
            if (subKeyStr.empty()) {
                return std::unexpected(Core::SystemError::FromWin32(ERROR_INVALID_PARAMETER, L"Subkey path resolved to root"));
            }

            Core::ScopedHKey hKey;
            LSTATUS status = ::RegOpenKeyExW(
                hRoot,
                subKeyStr.c_str(),
                0,
                DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_SET_VALUE | viewFlag,
                hKey.Put()
            );

            if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) {
                return true; // Already absent in this architectural view
            }

            if (status == ERROR_ACCESS_DENIED) {
                (void)Security::CRegistryDaclManager::TakeOwnershipAndGrantAccess(hRoot, subKeyStr);
                status = ::RegOpenKeyExW(
                    hRoot,
                    subKeyStr.c_str(),
                    0,
                    DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_SET_VALUE | viewFlag,
                    hKey.Put()
                );
            }

            if (status != ERROR_SUCCESS) {
                // If opening for enumeration failed, attempt direct deletion of leaf
                LSTATUS delStatus = DeleteLeafKey(hRoot, subKeyStr, viewFlag);
                if (delStatus == ERROR_SUCCESS || delStatus == ERROR_FILE_NOT_FOUND) {
                    return true;
                }
                return std::unexpected(Core::SystemError::FromWin32(status, L"Failed to open registry key for recursive purge"));
            }

            // 1. Delete all nested children
            auto childRes = DeleteChildrenInternal(hKey.Get(), viewFlag);
            if (!childRes) {
                return childRes;
            }

            // 2. Close open handle to key before final deletion
            hKey.Reset();

            // 3. Delete the target key itself
            LSTATUS delStatus = DeleteLeafKey(hRoot, subKeyStr, viewFlag);
            if (delStatus == ERROR_ACCESS_DENIED) {
                (void)Security::CRegistryDaclManager::TakeOwnershipAndGrantAccess(hRoot, subKeyStr);
                delStatus = DeleteLeafKey(hRoot, subKeyStr, viewFlag);
            }

            if (delStatus != ERROR_SUCCESS && delStatus != ERROR_FILE_NOT_FOUND) {
                return std::unexpected(Core::SystemError::FromWin32(delStatus, L"Failed to delete registry key"));
            }

            return true;
        }

        /// @brief Purges subtree across both 64-bit and 32-bit WOW64 registry views.
        static Core::Result<bool> PurgeSubtree(HKEY hRoot, std::wstring_view subKey) {
            if (!IsHivePathCompatible(hRoot, subKey)) {
                return true;
            }

            bool overallSuccess = true;
            for (DWORD viewFlag : { KEY_WOW64_64KEY, KEY_WOW64_32KEY }) {
                auto res = DeleteSubtreeRecursive(hRoot, subKey, viewFlag);
                if (!res) {
                    overallSuccess = false;
                }
            }
            return overallSuccess;
        }

        /// @brief Surgical removal of specific values within a target subkey across views.
        static Core::Result<bool> PurgeKeyValues(HKEY hRoot, std::wstring_view subKey, const std::vector<std::wstring>& valueNames) {
            if (!IsHivePathCompatible(hRoot, subKey)) {
                return true;
            }

            std::wstring subKeyStr(subKey);
            for (DWORD viewFlag : { KEY_WOW64_64KEY, KEY_WOW64_32KEY }) {
                Core::ScopedHKey hKey;
                LSTATUS status = ::RegOpenKeyExW(
                    hRoot,
                    subKeyStr.c_str(),
                    0,
                    KEY_SET_VALUE | KEY_QUERY_VALUE | viewFlag,
                    hKey.Put()
                );
                if (status == ERROR_ACCESS_DENIED) {
                    (void)Security::CRegistryDaclManager::TakeOwnershipAndGrantAccess(hRoot, subKeyStr);
                    status = ::RegOpenKeyExW(
                        hRoot,
                        subKeyStr.c_str(),
                        0,
                        KEY_SET_VALUE | KEY_QUERY_VALUE | viewFlag,
                        hKey.Put()
                    );
                }
                if (status == ERROR_SUCCESS) {
                    for (const auto& val : valueNames) {
                        ::RegDeleteValueW(hKey.Get(), val.c_str());
                    }
                }
            }
            return true;
        }

        [[nodiscard]] Core::Result<std::vector<Core::ResourceItem>> Scan(const Core::CleanupContext& ctx) override {
            (void)ctx;
            std::vector<Core::ResourceItem> items;

            for (const auto& target : m_targets) {
                if (!IsHivePathCompatible(target.RootHive, target.SubKey)) {
                    continue;
                }
                std::vector<DWORD> views;
                if (target.TargetBothViews) {
                    views = { KEY_WOW64_64KEY, KEY_WOW64_32KEY };
                } else {
                    views = { KEY_WOW64_64KEY };
                }

                for (DWORD viewFlag : views) {
                    Core::ScopedHKey hKey;
                    if (::RegOpenKeyExW(target.RootHive, target.SubKey.c_str(), 0, KEY_READ | viewFlag, hKey.Put()) == ERROR_SUCCESS) {
                        std::wstring hiveName = (target.RootHive == HKEY_LOCAL_MACHINE) ? L"HKLM" : L"HKCU";
                        std::wstring viewStr = (viewFlag == KEY_WOW64_64KEY) ? L"[64-bit]" : L"[32-bit]";
                        items.push_back(Core::ResourceItem{
                            .Type = Core::TargetType::RegistryKey,
                            .PathOrIdentifier = std::format(L"{}\\{} {}", hiveName, target.SubKey, viewStr),
                            .Description = L"Active Target Registry Subtree",
                            .IsLocked = false
                        });
                    }
                }
            }

            for (const auto& filter : ctx.CustomMatchFilters) {
                if (!IsHivePathCompatible(HKEY_LOCAL_MACHINE, filter)) continue;
                Core::ScopedHKey hKey;
                if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, filter.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, hKey.Put()) == ERROR_SUCCESS) {
                    items.push_back(Core::ResourceItem{
                        .Type = Core::TargetType::RegistryKey,
                        .PathOrIdentifier = std::format(L"HKLM\\{} [64-bit]", filter),
                        .Description = L"Custom Filter Registry Target",
                        .IsLocked = false
                    });
                }
            }

            return items;
        }

        [[nodiscard]] Core::Result<Core::PurgeStats> Purge(const Core::CleanupContext& ctx, bool dryRun = false) override {
            Core::PurgeStats stats = {};

            auto scanRes = Scan(ctx);
            if (!scanRes) {
                return std::unexpected(scanRes.error());
            }

            stats.ItemsScanned = static_cast<uint32_t>(scanRes->size());

            if (dryRun || ctx.DryRun) {
                return stats;
            }

            for (const auto& target : m_targets) {
                if (target.TargetBothViews) {
                    auto res = PurgeSubtree(target.RootHive, target.SubKey);
                    if (res && *res) {
                        stats.ItemsPurged++;
                    }
                } else {
                    auto res = DeleteSubtreeRecursive(target.RootHive, target.SubKey, KEY_WOW64_64KEY);
                    if (res && *res) {
                        stats.ItemsPurged++;
                    }
                }
            }

            for (const auto& filter : ctx.CustomMatchFilters) {
                auto res = PurgeSubtree(HKEY_LOCAL_MACHINE, filter);
                if (res && *res) {
                    stats.ItemsPurged++;
                }
            }

            return stats;
        }
    };

} // namespace WinTracePurge::Registry
