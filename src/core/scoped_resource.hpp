#pragma once

#include <windows.h>
#include <concepts>
#include <utility>
#include <type_traits>

namespace WinTracePurge::Core {

    template <typename HandleType, auto CloseFunction, HandleType InvalidValue = {}>
    class ScopedResource {
    public:
        using RawHandle = HandleType;

        constexpr ScopedResource() noexcept : m_handle(InvalidValue) {}
        explicit ScopedResource(HandleType h) noexcept : m_handle(h) {}

        ~ScopedResource() noexcept {
            Reset();
        }

        ScopedResource(const ScopedResource&) = delete;
        ScopedResource& operator=(const ScopedResource&) = delete;

        ScopedResource(ScopedResource&& other) noexcept : m_handle(other.m_handle) {
            other.m_handle = InvalidValue;
        }

        ScopedResource& operator=(ScopedResource&& other) noexcept {
            if (this != &other) {
                Reset();
                m_handle = other.m_handle;
                other.m_handle = InvalidValue;
            }
            return *this;
        }

        void Reset(HandleType h = InvalidValue) noexcept {
            if (IsValid()) {
                CloseFunction(m_handle);
            }
            m_handle = h;
        }

        [[nodiscard]] HandleType Get() const noexcept { return m_handle; }
        [[nodiscard]] HandleType* Put() noexcept { Reset(); return &m_handle; }
        [[nodiscard]] HandleType Release() noexcept {
            HandleType temp = m_handle;
            m_handle = InvalidValue;
            return temp;
        }

        [[nodiscard]] constexpr bool IsValid() const noexcept {
            if constexpr (std::is_same_v<HandleType, HANDLE>) {
                if constexpr (InvalidValue == INVALID_HANDLE_VALUE) {
                    return m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr;
                } else {
                    return m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE;
                }
            } else {
                return m_handle != InvalidValue;
            }
        }

        explicit operator bool() const noexcept { return IsValid(); }
        explicit operator HandleType() const noexcept { return m_handle; }

    private:
        HandleType m_handle;
    };

    // Standard Win32 RAII aliases
    using ScopedHKey       = ScopedResource<HKEY, ::RegCloseKey, static_cast<HKEY>(NULL)>;
    using ScopedSCMHandle  = ScopedResource<SC_HANDLE, ::CloseServiceHandle, static_cast<SC_HANDLE>(NULL)>;
    using ScopedHandle     = ScopedResource<HANDLE, ::CloseHandle, static_cast<HANDLE>(NULL)>;
    using ScopedFileHandle = ScopedResource<HANDLE, ::CloseHandle, INVALID_HANDLE_VALUE>;
    using ScopedSid        = ScopedResource<PSID, ::FreeSid, static_cast<PSID>(nullptr)>;
    using ScopedAcl        = ScopedResource<PACL, ::LocalFree, static_cast<PACL>(nullptr)>;
    using ScopedModule     = ScopedResource<HMODULE, ::FreeLibrary, static_cast<HMODULE>(nullptr)>;

} // namespace WinTracePurge::Core
