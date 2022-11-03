#include <windows.h>
#include <wincrypt.h>

typedef PVOID BCRYPT_ALG_HANDLE;

#define STATUS_SUCCESS 0x00000000
#define STATUS_FILE_NOT_AVAILABLE 0xC0000467
#define STATUS_UNSUCCESSFUL 0xC0000001

static NTSTATUS GLE_NTStatus(BOOL result)
{
    if (result)
        return STATUS_SUCCESS;

    switch (GetLastError())
    {
        case ERROR_SUCCESS:
            return STATUS_SUCCESS;
        case ERROR_FILE_NOT_FOUND:
            return STATUS_FILE_NOT_AVAILABLE;
        case ERROR_INVALID_HANDLE:
            return STATUS_INVALID_HANDLE;
        case ERROR_NOT_ENOUGH_MEMORY:
            return STATUS_NO_MEMORY;
        case ERROR_INVALID_PARAMETER:
            return STATUS_INVALID_PARAMETER;
        default:
            return STATUS_UNSUCCESSFUL;
    }
}

NTSTATUS BCryptGenRandomXP(
    BCRYPT_ALG_HANDLE hAlgorithm,
    PUCHAR            pbBuffer,
    ULONG             cbBuffer,
    ULONG             dwFlags
)
{
    return GLE_NTStatus(CryptGenRandom((HCRYPTPROV)hAlgorithm, (DWORD)cbBuffer, (char *)pbBuffer));
}

NTSTATUS BCryptOpenAlgorithmProviderXP(
    BCRYPT_ALG_HANDLE *phAlgorithm,
    LPCWSTR           pszAlgId,
    LPCWSTR           pszImplementation,
    ULONG             dwFlags
)
{
    return GLE_NTStatus(CryptAcquireContextW((HCRYPTPROV *)phAlgorithm, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT|CRYPT_SILENT));
}

NTSTATUS BCryptCloseAlgorithmProviderXP(
    BCRYPT_ALG_HANDLE hAlgorithm,
    ULONG             dwFlags
)
{
    return GLE_NTStatus(CryptReleaseContext((HCRYPTPROV)hAlgorithm, 0));
}