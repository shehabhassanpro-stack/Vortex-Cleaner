#pragma once

#include "authenticode_verifier.hpp"
#include "../core/zstring_view.hpp"
#include <windows.h>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>
#include <algorithm>
#include <span>

namespace WinTracePurge::Security {

    namespace fs = std::filesystem;

    /// @brief Production-grade multi-factor binary classifier.
    /// Strictly resolves VTX-SYS-015 by mandating at least two independent validation criteria
    /// before identifying a target, combined with strict exclusion guards to protect user games,
    /// Unreal Engine installations, and the Epic Games Launcher.
    /// Implements locale-invariant ASCII case folding (VTX-AUDIT-022, VTX-AUDIT-023).
    class CBinaryTrustEvaluator {
    public:
        struct TargetRule {
            std::wstring TargetFileName;
            std::wstring RequiredPathSubstring;
            std::vector<std::wstring> ValidSignerCNs;
        };

        /// @brief Multi-factor evaluation of target anti-cheat binaries.
        [[nodiscard]] static bool IsTargetAntiCheatBinary(const fs::path& filePath) noexcept {
            std::error_code ec;
            if (!fs::exists(filePath, ec) || !fs::is_regular_file(filePath, ec)) {
                return false;
            }

            // 1. HARD MANDATORY EXCLUSION GUARD: Protect legitimate user tools and game engines
            if (IsExplicitlyExcluded(filePath)) {
                return false;
            }

            std::wstring fileName = filePath.filename().wstring();
            std::wstring fullPath = filePath.wstring();

            // Factor 1: Filename Heuristic Check
            bool factor1_FileNameMatch = IsKnownTargetFileName(fileName);

            // Factor 2: Target Path Enclosure Check
            bool factor2_PathMatch = IsKnownTargetPath(fullPath);

            // Factor 3: Cryptographic Authenticode Signer CN Inspection (VTX-SYS-016)
            auto sigInfo = CAuthenticodeVerifier::InspectSignature(filePath);
            bool factor3_SignerMatch = false;

            if (sigInfo.IsSigned && !sigInfo.SignerCommonName.empty()) {
                factor3_SignerMatch = IsKnownTargetSigner(sigInfo.SignerCommonName);
            }

            // MULTI-FACTOR DECISION CONSTRAINT:
            // A binary is confirmed as a target anti-cheat component ONLY IF it satisfies at least
            // TWO independent criteria. Single-factor matches (such as a generic company name) are REJECTED.
            int matchCount = (factor1_FileNameMatch ? 1 : 0) + 
                             (factor2_PathMatch ? 1 : 0) + 
                             (factor3_SignerMatch ? 1 : 0);

            return (matchCount >= 2);
        }

    private:
        static constexpr wchar_t ToAsciiLower(wchar_t ch) noexcept {
            return (ch >= L'A' && ch <= L'Z') ? static_cast<wchar_t>(ch + (L'a' - L'A')) : ch;
        }

        static bool ContainsIgnoreCase(std::wstring_view haystack, std::wstring_view needle) noexcept {
            if (needle.empty()) return true;
            if (haystack.size() < needle.size()) return false;
            auto it = std::search(
                haystack.begin(), haystack.end(),
                needle.begin(), needle.end(),
                [](wchar_t c1, wchar_t c2) noexcept { return ToAsciiLower(c1) == ToAsciiLower(c2); }
            );
            return (it != haystack.end());
        }

        static bool EqualsIgnoreCase(std::wstring_view s1, std::wstring_view s2) noexcept {
            if (s1.size() != s2.size()) return false;
            return std::ranges::equal(s1, s2, [](wchar_t c1, wchar_t c2) noexcept {
                return ToAsciiLower(c1) == ToAsciiLower(c2);
            });
        }

        static bool IsExplicitlyExcluded(const fs::path& filePath) noexcept {
            std::wstring pathStr = filePath.wstring();

            // Strict protection for Unreal Engine, Epic Games Launcher, and game executables
            constexpr std::wstring_view kExclusionSubstrings[] = {
                L"unrealengine",
                L"unreal engine",
                L"epicgameslauncher",
                L"epic games\\launcher",
                L"fortniteclient",
                L"shipping.exe",
                L"engine\\binaries",
                L"engine\\plugins",
                L"steamapps\\common\\unreal",
                L"unrealeditor.exe",
                L"crashreportclient.exe"
            };

            for (const auto& excl : kExclusionSubstrings) {
                if (ContainsIgnoreCase(pathStr, excl)) {
                    return true;
                }
            }

            return false;
        }

        static bool IsKnownTargetFileName(std::wstring_view fileName) noexcept {
            constexpr std::wstring_view kTargetFiles[] = {
                L"vgk.sys",
                L"vgc.exe",
                L"easyanticheat.sys",
                L"easyanticheat_eos.sys",
                L"easyanticheat.exe",
                L"easyanticheat_eos.exe",
                L"bedrive.sys",
                L"beservice.exe",
                L"beservice_x64.exe"
            };

            for (const auto& tf : kTargetFiles) {
                if (EqualsIgnoreCase(fileName, tf)) return true;
            }
            return false;
        }

        static bool IsKnownTargetPath(std::wstring_view fullPath) noexcept {
            constexpr std::wstring_view kTargetPaths[] = {
                L"\\riot vanguard\\",
                L"\\program files\\riot vanguard\\",
                L"\\easyanticheat\\",
                L"\\easyanticheat_eos\\",
                L"\\battleye\\",
                L"\\common files\\battleye\\",
                L"\\system32\\drivers\\vgk.sys",
                L"\\system32\\drivers\\easyanticheat.sys",
                L"\\system32\\drivers\\easyanticheat_eos.sys",
                L"\\system32\\drivers\\bedrive.sys"
            };

            for (const auto& tp : kTargetPaths) {
                if (ContainsIgnoreCase(fullPath, tp)) return true;
            }
            return false;
        }

        static bool IsKnownTargetSigner(std::wstring_view signerCN) noexcept {
            constexpr std::wstring_view kTargetSigners[] = {
                L"riot games",
                L"easyanticheat",
                L"battleye",
                L"epic games" // Note: only matches if paired with a target filename or target path!
            };

            for (const auto& ts : kTargetSigners) {
                if (ContainsIgnoreCase(signerCN, ts)) return true;
            }
            return false;
        }
    };

} // namespace WinTracePurge::Security
