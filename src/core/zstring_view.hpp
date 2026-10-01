#pragma once

#include <string_view>
#include <string>
#include <concepts>
#include <cstddef>
#include <format>
#include <compare>

namespace WinTracePurge::Core {

    /// @brief Compile-time and runtime enforced null-terminated wide-string view.
    /// Inherits from std::wstring_view while strictly guaranteeing null-termination (c_str()).
    /// Eliminates undefined behavior and memory boundary violations when passing views to Win32 LPCWSTR C-APIs.
    class zstring_view : public std::wstring_view {
    public:
        // Construct from compile-time string literals (guaranteed null-terminated)
        template <size_t N>
        constexpr zstring_view(const wchar_t (&str)[N]) noexcept 
            : std::wstring_view(str, N > 0 ? N - 1 : 0) {}

        // Construct from standard null-terminated C-style wide strings
        constexpr explicit zstring_view(const wchar_t* str) noexcept 
            : std::wstring_view(str ? str : L"") {}

        // Construct from standard heap-allocated wide string (guaranteed null-terminated)
        constexpr zstring_view(const std::wstring& str) noexcept 
            : std::wstring_view(str.data(), str.size()) {}

        // Construct default empty string (points to static null wide-character)
        constexpr zstring_view() noexcept 
            : std::wstring_view(L"") {}

        // STRICTLY PROHIBIT construction from arbitrary sliced string_views that lose null-termination guarantees
        zstring_view(std::wstring_view) = delete;

        // Prohibit construction from nullptr
        zstring_view(std::nullptr_t) = delete;

        /// @brief Returns a guaranteed null-terminated wide-string pointer.
        [[nodiscard]] constexpr const wchar_t* c_str() const noexcept {
            return data();
        }

        /// @brief Explicit conversion to const wchar_t* for safe Win32 API interoperability.
        [[nodiscard]] constexpr explicit operator const wchar_t*() const noexcept {
            return data();
        }
    };

} // namespace WinTracePurge::Core

// Enable seamless std::format / std::wformat support
template <>
struct std::formatter<WinTracePurge::Core::zstring_view, wchar_t> : std::formatter<std::wstring_view, wchar_t> {
    auto format(const WinTracePurge::Core::zstring_view& zsv, std::wformat_context& ctx) const {
        return std::formatter<std::wstring_view, wchar_t>::format(static_cast<std::wstring_view>(zsv), ctx);
    }
};
