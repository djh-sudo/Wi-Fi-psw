#pragma once
#include <Windows.h>
#include "CipherHelper.h"
#include "wow64.hpp"


#define SYSKEY_LENGTH  16
#define LAZY_NT6_IV_SIZE 32
#define AES_256_KEY_SIZE (256 >> 3)

/*
* Only support NT6+
* Also See 
* https://github.com/gentilkiwi/mimikatz [kuhl_m_lsadump.h]
*/

typedef struct _NT6_SYSTEM_KEY{
	/* Off[DEC] Description */
	/* 00 */   GUID KeyId;
	/* 16 */   DWORD KeyType;
	/* 20 */   DWORD KeySize;
	/* 24 */   BYTE Key[ANYSIZE_ARRAY];
} NT6_SYSTEM_KEY, *P_NT6_SYSTEM_KEY;

typedef struct _NT6_STREAM_KEYS {
	/* Off[DEC] Description */
	/* 00 */    DWORD unkType0;
	/* 04 */    GUID CurrentKeyID;
	/* 20 */    DWORD unkType1;
	/* 24 */    DWORD nbKeys;
	/* 28 */    NT6_SYSTEM_KEY Keys[ANYSIZE_ARRAY];
} NT6_SYSTEM_KEYS, *P_NT6_SYSTEM_KEYS;

/*
* Policy Version structure
*/
typedef struct _POL_REVISION {
	/* Off[DEC] Description */
	/* 00 */    USHORT Minor;
	/* 02 */    USHORT Major;
} POL_REVISION, *P_POL_REVISION;

/*
* NT 6 clear secret structure
*/
typedef struct _NT6_CLEAR_SECRET {
	/* Off[DEC] Description */
	/* 00 */    DWORD SecretSize;
	/* 04 */    DWORD unk0;
	/* 08 */    DWORD unk1;
	/* 12 */    DWORD unk2;
	/* 16 */    BYTE  Secret[ANYSIZE_ARRAY];
} NT6_CLEAR_SECRET, *P_NT6_CLEAR_SECRET;

/*
* NT 6 Secret Header
*/
typedef struct _NT6_HARD_SECRET {
	/* Off[DEC] Description */
	/* 00 */    DWORD version;
	/* 04 */    GUID KeyId;
	/* 20 */    DWORD algorithm;
	/* 24 */    DWORD flag;
	/* 28 */    BYTE lazyiv[LAZY_NT6_IV_SIZE];
	/* 60 */    
	union {
		BYTE encryptedSecret[ANYSIZE_ARRAY];
		NT6_CLEAR_SECRET clearSecret;
	};

} NT6_HARD_SECRET, *P_NT6_HARD_SECRET;

bool DecryptAESSec(P_NT6_HARD_SECRET hardSecretBlob,
	               DWORD szHardSecretBlob,
	               P_NT6_SYSTEM_KEYS lsaKeysStream,
	               CONST PBYTE sysKey) {
	BOOL status  = FALSE;
	PBYTE pKey = NULL;
	BYTE keyBuffer[AES_256_KEY_SIZE] = { 0 };
	P_NT6_SYSTEM_KEYS nt6keysStream = NULL;
	P_NT6_SYSTEM_KEY lsaKey = NULL;
	DWORD offset = 0,szNeeded = 0;
	if (lsaKeysStream) {
		for (DWORD i = 0; i < lsaKeysStream->nbKeys; ++i) {
			lsaKey = (P_NT6_SYSTEM_KEY)((PBYTE)lsaKeysStream->Keys + offset);
			if (!memcmp(&hardSecretBlob->KeyId, &lsaKey->KeyId, sizeof(GUID))) {
				pKey = lsaKey->Key;
				szNeeded = lsaKey->KeySize;
				break;
			}
			offset += FIELD_OFFSET(NT6_SYSTEM_KEY, Key) + lsaKey->KeySize;
		}
	}
	else if (sysKey) {
		pKey = sysKey;
		szNeeded = SYSKEY_LENGTH;
	}
	if (!pKey) {
		return FALSE;
	}

	StramSHA256 hash;
	hash.Update((char *)pKey, szNeeded);

	for (DWORD i = 0; i < 1000; ++i) {
		hash.Update((const char*)(hardSecretBlob->lazyiv), LAZY_NT6_IV_SIZE);
	}
	memcpy(keyBuffer, hash.GetValue(), AES_256_KEY_SIZE);
	szNeeded = szHardSecretBlob - FIELD_OFFSET(NT6_HARD_SECRET, encryptedSecret);
	std::string buffer =  SSLHelper::AesECBDecrypt(hardSecretBlob->encryptedSecret, szNeeded, keyBuffer, AES_256_KEY_SIZE);
	status = (buffer != "");
	if (status) {
		memcpy(hardSecretBlob->encryptedSecret, buffer.c_str(), szNeeded);
	}

	return (status != FALSE) ? true: false;
}


/*
* This header file is about WINDOWS DPAPI
* Keywords: MASTER KEY
* Also See
* https://github.com/gentilkiwi/mimikatz
*/

typedef struct _DPAPI_MASTERKEY_CREDHIST {
	/* Off[DEC] Description */
	/* 00 */    DWORD dwVersion;
	/* 04 */    GUID guid;
} DPAPI_MASTERKEY_CREDHIST, * P_DPAPI_MASTERKEY_CREDHIST;

typedef struct _DPAPI_MASTERKEY_DOMAINKEY {
	/* Off[DEC] Description */
	/* 00 */    DWORD dwVersion;
	/* 04 */    DWORD dwSecretLen;
	/* 08 */    DWORD dwAccesscheckLen;
	/* 12 */    GUID guidMasterKey;
	/* 28 */    PBYTE pbSecret;
	/* 32 */    PBYTE pbAccesscheck;
} DPAPI_MASTERKEY_DOMAINKEY, * P_DPAPI_MASTERKEY_DOMAINKEY;

typedef struct _DPAPI_MASTERKEY {
	/* Off[DEC] Description */
	/* 00 */    DWORD dwVersion;
	/* 04 */    BYTE salt[16];
	/* 20 */    DWORD rounds;
	/* 24 */    ALG_ID algHash;
	/* 28 */    ALG_ID algCrypt;
	/* 32 */    BYTE pbKey[ANYSIZE_ARRAY];
} DPAPI_MASTERKEY, * P_DPAPI_MASTERKEY;

typedef struct _DPAPI_MASTERKEYS {
	/* Off[DEC] Description */
	/* 000 */   DWORD dwVersion;
	/* 004 */   DWORD unk0;
	/* 008 */   DWORD unk1;
	/* 012 */   WCHAR szGuid[36];
	/* 048 */   DWORD unk2;
	/* 052 */   DWORD unk3;
	/* 056 */   DWORD dwFlags;
	/* 060 */   DWORD64 dwMasterKeyLen;
	/* 068 */   DWORD64 dwBackupKeyLen;
	/* 076 */   DWORD64 dwCredHistLen;
	/* 084 */   DWORD64 dwDomainKeyLen;
	/* 092 */   P_DPAPI_MASTERKEY MasterKey;
	/* 096 */   P_DPAPI_MASTERKEY BackupKey;
	/* 100 */   P_DPAPI_MASTERKEY_CREDHIST CredHist;
	/* 104 */   P_DPAPI_MASTERKEY_DOMAINKEY DomainKey;
} DPAPI_MASTERKEYS, *P_DPAPI_MASTERKEYS;

typedef struct _DPAPI_BLOB {
	/* Off[DEC]  Description */
	/* acc is unfixed length accumulated! */
	/*   00   */ DWORD dwVersion;
	/*   04   */ GUID guidProvider;
	/*   20   */ DWORD dwMasterKeyVersion;
	/*   24   */ GUID guidMasterKey;
	/*   40   */ DWORD dwFlags;
	/*   44   */ DWORD dwDescriptionLen;
	/* acc+48 */ WCHAR szDescription[ANYSIZE_ARRAY];
	/* acc+48 */ ALG_ID algCrypt;
	/* acc+52 */ DWORD dwAlgCryptLen;
	/* acc+56 */ DWORD dwSaltLen;
	/* acc+60 */ BYTE pbSalt[ANYSIZE_ARRAY];
	/* acc+60 */ DWORD dwHmacKeyLen;
	/* acc+64 */ BYTE pbHmackKey[ANYSIZE_ARRAY];
	/* acc+64 */ ALG_ID algHash;
	/* acc+68 */ DWORD dwAlgHashLen;
	/* acc+72 */ DWORD dwHmac2KeyLen;
	/* acc+76 */ BYTE pbHmack2Key[ANYSIZE_ARRAY];
	/* acc+76 */ DWORD dwDataLen;
	/* acc+80 */ BYTE pbData[ANYSIZE_ARRAY];
	/* acc+80 */ DWORD dwSignLen;
	/* acc+84 */ BYTE pbSign[ANYSIZE_ARRAY];
} DPAPI_BLOB, *P_DPAPI_BLOB;

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