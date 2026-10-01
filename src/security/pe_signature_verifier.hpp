#pragma once

#include "binary_trust_evaluator.hpp"
#include <filesystem>

namespace WinTracePurge::Security {

    /// @brief Backward-compatibility adapter routing legacy PE verification to the modern multi-factor CBinaryTrustEvaluator.
    class CPeSignatureVerifier {
    public:
        [[nodiscard]] static bool IsAntiCheatBinary(const std::filesystem::path& filePath) noexcept {
            return CBinaryTrustEvaluator::IsTargetAntiCheatBinary(filePath);
        }
    };

} // namespace WinTracePurge::Security
