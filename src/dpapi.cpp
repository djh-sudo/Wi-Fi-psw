#include <string>
#include "dpapi.h"
#include "wow64.hpp"
#include "CipherHelper.h"


BOOL ReadMasterKeyFile(IN LPCWSTR lpFileName, OUT LPBYTE *output, OUT LPDWORD szOutput) {
	BOOL status = FALSE;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	{
		zl::WinUtils::ZLWow64Guard guard;
		hFile = CreateFileW(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	}
	DWORD szFile = 0;

	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	do {
		szFile = GetFileSize(hFile, NULL);
		if (szFile == 0) {
			break;
		}
		*output = new BYTE[szFile + 1];
		if (!(*output)) {
			break;
		}
		memset(*output, 0, szFile + 1);
		status = ReadFile(hFile, *output, szFile, &szFile, NULL);
		if (status == FALSE) {
			delete[] * output;
			break;
		}
		*szOutput = szFile;
		status = TRUE;

	} while (FALSE);
	CloseHandle(hFile);
	return status;
}

BOOL MemoryVerify(IN LPVOID masterKey, IN DWORD szKey, IN LPVOID shaDerivedKey, IN DWORD szShaKey) {
	if (masterKey == NULL || shaDerivedKey == NULL) {
		return FALSE;
	}
	BOOL status = FALSE;
	BYTE salt[16] = { 0 };
	BYTE savedHash[64] = { 0 };
	memcpy(salt, masterKey, 16);
	memcpy(savedHash, (PBYTE)masterKey + 16, 64);
	PBYTE masterKeys = (PBYTE)masterKey + 80;
	std::string hmac1 = SSLHelper::HMAC_SHA512(shaDerivedKey, szShaKey, salt, 16);
	std::string hmac2 = SSLHelper::HMAC_SHA512(hmac1.c_str(), SHA512_DIGEST_LENGTH, masterKeys, szKey - 80);
	// savedHash == hmac2 maybe unsafe, because 0 truncation
	status = (memcmp(savedHash, hmac2.c_str(), SHA512_DIGEST_LENGTH) == 0);
	return status;
}