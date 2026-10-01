#pragma once

#include "../core/result.hpp"
#include "../core/zstring_view.hpp"
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <filesystem>
#include <string>
#include <vector>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace WinTracePurge::Security {

    /// @brief Enterprise-grade cryptographic Authenticode verification engine.
    /// Resolves VTX-SYS-016 by invoking WinVerifyTrust (WINTRUST_ACTION_GENERIC_VERIFY_V2)
    /// and parsing the embedded PKCS#7 signed certificate chain to extract the authoritative Signer Common Name (CN).
    class CAuthenticodeVerifier {
    public:
        struct SignatureInfo {
            bool IsSigned = false;
            bool IsSignatureValid = false;
            std::wstring SignerCommonName;
            std::wstring IssuerName;
        };

        /// @brief Cryptographically verifies the embedded Authenticode signature of a PE file.
        [[nodiscard]] static bool VerifySignature(const std::filesystem::path& filePath) noexcept {
            std::wstring wsPath = filePath.wstring();

            WINTRUST_FILE_INFO fileInfo{};
            fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
            fileInfo.pcwszFilePath = wsPath.c_str();

            GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

            WINTRUST_DATA trustData{};
            trustData.cbStruct = sizeof(WINTRUST_DATA);
            trustData.dwUIChoice = WTD_UI_NONE;
            trustData.fdwRevocationChecks = WTD_REVOKE_NONE; // Avoid network stalls during offline inspection
            trustData.dwUnionChoice = WTD_CHOICE_FILE;
            trustData.pFile = &fileInfo;
            trustData.dwStateAction = WTD_STATEACTION_VERIFY;
            trustData.dwProvFlags = WTD_SAFER_FLAG;

            LONG lStatus = ::WinVerifyTrust(nullptr, &actionGuid, &trustData);

            // Mandatory state teardown
            trustData.dwStateAction = WTD_STATEACTION_CLOSE;
            ::WinVerifyTrust(nullptr, &actionGuid, &trustData);

            return (lStatus == ERROR_SUCCESS);
        }

        /// @brief Extracts the PKCS#7 certificate chain and retrieves the Signer Common Name (CN).
        [[nodiscard]] static SignatureInfo InspectSignature(const std::filesystem::path& filePath) noexcept {
            SignatureInfo info{};
            std::wstring wsPath = filePath.wstring();

            HCERTSTORE hStore = nullptr;
            HCRYPTMSG hMsg = nullptr;
            DWORD dwEncoding = 0;
            DWORD dwContentType = 0;
            DWORD dwFormatType = 0;

            BOOL bQuery = ::CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                wsPath.c_str(),
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                &dwEncoding,
                &dwContentType,
                &dwFormatType,
                &hStore,
                &hMsg,
                nullptr
            );

            if (!bQuery || !hMsg || !hStore) {
                if (hStore) ::CertCloseStore(hStore, 0);
                if (hMsg) ::CryptMsgClose(hMsg);
                return info;
            }

            info.IsSigned = true;
            info.IsSignatureValid = VerifySignature(filePath);

            DWORD dwSignerInfoSize = 0;
            if (::CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &dwSignerInfoSize) && dwSignerInfoSize > 0) {
                std::vector<BYTE> signerInfoBuffer(dwSignerInfoSize);
                if (::CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, signerInfoBuffer.data(), &dwSignerInfoSize)) {
                    auto* pSignerInfo = reinterpret_cast<PCMSG_SIGNER_INFO>(signerInfoBuffer.data());

                    CERT_INFO certInfo{};
                    certInfo.Issuer = pSignerInfo->Issuer;
                    certInfo.SerialNumber = pSignerInfo->SerialNumber;

                    PCCERT_CONTEXT pCertContext = ::CertFindCertificateInStore(
                        hStore,
                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                        0,
                        CERT_FIND_SUBJECT_CERT,
                        &certInfo,
                        nullptr
                    );

                    if (pCertContext) {
                        // Extract Signer Common Name (Subject)
                        DWORD dwNameSize = ::CertGetNameStringW(
                            pCertContext,
                            CERT_NAME_SIMPLE_DISPLAY_TYPE,
                            0,
                            nullptr,
                            nullptr,
                            0
                        );
                        if (dwNameSize > 1) {
                            std::vector<wchar_t> nameBuf(dwNameSize);
                            ::CertGetNameStringW(
                                pCertContext,
                                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                0,
                                nullptr,
                                nameBuf.data(),
                                dwNameSize
                            );
                            info.SignerCommonName = nameBuf.data();
                        }

                        // Extract Issuer Name
                        DWORD dwIssuerSize = ::CertGetNameStringW(
                            pCertContext,
                            CERT_NAME_SIMPLE_DISPLAY_TYPE,
                            CERT_NAME_ISSUER_FLAG,
                            nullptr,
                            nullptr,
                            0
                        );
                        if (dwIssuerSize > 1) {
                            std::vector<wchar_t> issuerBuf(dwIssuerSize);
                            ::CertGetNameStringW(
                                pCertContext,
                                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                CERT_NAME_ISSUER_FLAG,
                                nullptr,
                                issuerBuf.data(),
                                dwIssuerSize
                            );
                            info.IssuerName = issuerBuf.data();
                        }

                        ::CertFreeCertificateContext(pCertContext);
                    }
                }
            }

            if (hStore) ::CertCloseStore(hStore, 0);
            if (hMsg) ::CryptMsgClose(hMsg);

            return info;
        }
    };

} // namespace WinTracePurge::Security
