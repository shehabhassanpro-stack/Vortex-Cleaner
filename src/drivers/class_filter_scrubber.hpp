#pragma once

#include "../core/interfaces.hpp"
#include "../core/result.hpp"
#include "../core/scoped_resource.hpp"
#include "../core/logger.hpp"
#include "../core/zstring_view.hpp"
#include <windows.h>
#include <vector>
#include <span>
#include <string>
#include <string_view>
#include <algorithm>
#include <format>

namespace WinTracePurge::Drivers {

    /// @brief Memory-bounded PnP Class Filter scrubber protecting against 0x7B BSODs.
    /// Strictly resolves VTX-SYS-006 by implementing SafeUnpackMultiString using bounded std::span iteration.
    /// Implements the full C++23 Core::ICleanerModule contract.
    class CClassFilterScrubber : public Core::ICleanerModule {
    public:
        [[nodiscard]] Core::zstring_view GetModuleName() const noexcept override {
            return L"ClassFilterScrubber";
        }

        [[nodiscard]] Core::Result<std::vector<Core::ResourceItem>> Scan(const Core::CleanupContext& ctx) override {
            (void)ctx;
            std::vector<Core::ResourceItem> items;

            Core::ScopedHKey hClassRoot;
            LSTATUS status = ::RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\Class",
                0,
                KEY_READ | KEY_WOW64_64KEY,
                hClassRoot.Put()
            );

            if (status != ERROR_SUCCESS) {
                return std::unexpected(Core::SystemError::FromWin32(status, L"Failed to open Control\\Class"));
            }

            DWORD dwIndex = 0;
            WCHAR szSubKeyName[256];
            DWORD dwSubKeyLen = ARRAYSIZE(szSubKeyName);

            while (::RegEnumKeyExW(hClassRoot.Get(), dwIndex++, szSubKeyName, &dwSubKeyLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                dwSubKeyLen = ARRAYSIZE(szSubKeyName);

                Core::ScopedHKey hSubKey;
                if (::RegOpenKeyExW(hClassRoot.Get(), szSubKeyName, 0, KEY_READ | KEY_WOW64_64KEY, hSubKey.Put()) == ERROR_SUCCESS) {
                    InspectFilterForScan(hSubKey.Get(), szSubKeyName, L"UpperFilters", items);
                    InspectFilterForScan(hSubKey.Get(), szSubKeyName, L"LowerFilters", items);
                }
            }

            return items;
        }

        [[nodiscard]] Core::Result<Core::PurgeStats> Purge(const Core::CleanupContext& ctx, bool dryRun) override {
            (void)ctx;
            Core::PurgeStats stats{};

            constexpr std::wstring_view kTargetDrivers[] = {
                L"vgk", L"easyanticheat", L"easyanticheat_eos", L"bedrive"
            };

            for (const auto& drv : kTargetDrivers) {
                if (!dryRun) {
                    auto res = ScrubDriverFromAllClasses(drv);
                    if (res && *res) {
                        stats.ItemsPurged++;
                    }
                }
                stats.ItemsScanned++;
            }

            return stats;
        }

        /// @brief Bounded, exception-safe parser for REG_MULTI_SZ registry buffers.
        /// Strictly resolves VTX-SYS-006 by bounding every pointer advance against the explicit end of the span.
        [[nodiscard]] static std::vector<std::wstring> SafeUnpackMultiString(std::span<const wchar_t> data) noexcept {
            std::vector<std::wstring> result;
            if (data.empty()) return result;

            const wchar_t* curr = data.data();
            const wchar_t* const end = data.data() + data.size();

            while (curr < end && *curr != L'\0') {
                size_t maxLen = static_cast<size_t>(end - curr);
                size_t len = ::wcsnlen(curr, maxLen);
                if (len == 0) break;

                result.emplace_back(curr, len);
                curr += len + 1; // Safely advance past the terminating null character
            }

            return result;
        }

        /// @brief Safely scrubs a targeted driver from UpperFilters and LowerFilters across all device classes.
        static Core::Result<bool> ScrubDriverFromAllClasses(std::wstring_view targetDriverName) {
            Core::ScopedHKey hClassRoot;
            LSTATUS status = ::RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\Class",
                0,
                KEY_READ | KEY_WRITE | KEY_WOW64_64KEY,
                hClassRoot.Put()
            );

            if (status != ERROR_SUCCESS) {
                return std::unexpected(Core::SystemError::FromWin32(status, L"Failed to open Control\\Class"));
            }

            DWORD dwIndex = 0;
            WCHAR szSubKeyName[256];
            DWORD dwSubKeyLen = ARRAYSIZE(szSubKeyName);

            while (::RegEnumKeyExW(hClassRoot.Get(), dwIndex++, szSubKeyName, &dwSubKeyLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                dwSubKeyLen = ARRAYSIZE(szSubKeyName);

                Core::ScopedHKey hSubKey;
                if (::RegOpenKeyExW(hClassRoot.Get(), szSubKeyName, 0, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, hSubKey.Put()) == ERROR_SUCCESS) {
                    ScrubFilterValue(hSubKey.Get(), L"UpperFilters", targetDriverName);
                    ScrubFilterValue(hSubKey.Get(), L"LowerFilters", targetDriverName);
                }
            }

            return true;
        }

    private:
        static void InspectFilterForScan(HKEY hKey, LPCWSTR classGuid, LPCWSTR valueName, std::vector<Core::ResourceItem>& items) {
            DWORD dwType = 0;
            DWORD dwBytes = 0;
            if (::RegQueryValueExW(hKey, valueName, nullptr, &dwType, nullptr, &dwBytes) != ERROR_SUCCESS ||
                dwType != REG_MULTI_SZ || dwBytes < sizeof(wchar_t)) {
                return;
            }

            std::vector<wchar_t> buffer(dwBytes / sizeof(wchar_t));
            if (::RegQueryValueExW(hKey, valueName, nullptr, &dwType, reinterpret_cast<LPBYTE>(buffer.data()), &dwBytes) == ERROR_SUCCESS) {
                auto filters = SafeUnpackMultiString(buffer);
                for (const auto& filter : filters) {
                    if (IsKnownTargetFilter(filter)) {
                        items.push_back(Core::ResourceItem{
                            .Type = Core::TargetType::ClassFilter,
                            .PathOrIdentifier = std::format(L"Class\\{}\\{}: {}", classGuid, valueName, filter),
                            .Description = L"Device Class Filter Driver Hook"
                        });
                    }
                }
            }
        }

        static constexpr wchar_t ToAsciiLower(wchar_t c) noexcept {
            return (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c + (L'a' - L'A')) : c;
        }

        static bool EqualsIgnoreCase(std::wstring_view s1, std::wstring_view s2) noexcept {
            if (s1.size() != s2.size()) return false;
            return std::ranges::equal(s1, s2, [](wchar_t a, wchar_t b) noexcept {
                return ToAsciiLower(a) == ToAsciiLower(b);
            });
        }

        static bool IsKnownTargetFilter(std::wstring_view filter) noexcept {
            constexpr std::wstring_view kTargets[] = { L"vgk", L"easyanticheat", L"easyanticheat_eos", L"bedrive" };
            for (const auto& t : kTargets) {
                if (EqualsIgnoreCase(filter, t)) return true;
            }
            return false;
        }

        static void ScrubFilterValue(HKEY hKey, LPCWSTR valueName, std::wstring_view targetDriver) {
            DWORD dwType = 0;
            DWORD dwBytes = 0;

            if (::RegQueryValueExW(hKey, valueName, nullptr, &dwType, nullptr, &dwBytes) != ERROR_SUCCESS ||
                dwType != REG_MULTI_SZ || dwBytes < sizeof(wchar_t)) {
                return;
            }

            std::vector<wchar_t> buffer(dwBytes / sizeof(wchar_t));
            if (::RegQueryValueExW(hKey, valueName, nullptr, &dwType, reinterpret_cast<LPBYTE>(buffer.data()), &dwBytes) != ERROR_SUCCESS) {
                return;
            }

            // Strictly resolve VTX-SYS-006: Safe bounded multi-string unpacking
            auto filters = SafeUnpackMultiString(buffer);

            bool modified = false;
            std::vector<std::wstring> cleanFilters;
            cleanFilters.reserve(filters.size());

            for (const auto& f : filters) {
                if (EqualsIgnoreCase(f, targetDriver)) {
                    modified = true;
                    Core::CAppLogger::LogInfo(L"ClassFilter", std::format(L"Scrubbed target driver filter '{}' from '{}'", f, valueName));
                } else {
                    cleanFilters.push_back(f);
                }
            }

            if (!modified) return;

            if (cleanFilters.empty()) {
                ::RegDeleteValueW(hKey, valueName);
            } else {
                std::vector<wchar_t> newBuffer;
                for (const auto& f : cleanFilters) {
                    newBuffer.insert(newBuffer.end(), f.begin(), f.end());
                    newBuffer.push_back(L'\0');
                }
                newBuffer.push_back(L'\0'); // Mandatory double-null termination

                ::RegSetValueExW(
                    hKey,
                    valueName,
                    0,
                    REG_MULTI_SZ,
                    reinterpret_cast<const BYTE*>(newBuffer.data()),
                    static_cast<DWORD>(newBuffer.size() * sizeof(wchar_t))
                );
            }
        }
    };

} // namespace WinTracePurge::Drivers
