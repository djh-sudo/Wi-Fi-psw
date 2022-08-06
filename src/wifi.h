#pragma once
#include <iostream>
#include <string>
#include "HIVE.h"
#include "CipherHelper.h"

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


class WIFI_PASSWORD {

public:
	/* Get system key from Register dump file */
	BOOL GetSysKey(LPCWSTR lpFileName) {
		BOOL status = FALSE;
		HKEY hCurrentControlSet, hComputerNameOrLSA;

		HANDLE hfile = CreateFileW(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (hfile == INVALID_HANDLE_VALUE) {
			return FALSE;
		}
		
		do {
			status = OpenRegistry(hfile, &m_hSecurity);
			if (status == FALSE) {
				break;
			}
			status = GetCurrentControlSet(m_hSecurity, &hCurrentControlSet);
			if (status == FALSE) {
				break;
			}
			status = OpenRegistryKey(m_hSecurity, hCurrentControlSet,  L"Control\\LSA", 0, KEY_READ, &hComputerNameOrLSA);
			if (status == FALSE) {
				break;
			}
			status = GetLSASyskey(m_hSecurity, hComputerNameOrLSA, sysKey);

		}while(FALSE);
		
		CloseHandle(hfile);
		return status;
	}
	/*Get LSA Key from Register dump file*/
	BOOL GetLSAKeyAndSecrete(LPCWSTR lpFileName) {
		BOOL status = FALSE;
		P_HIVE_HANDLE hSecurity;
		P_NT6_SYSTEM_KEYS nt6keysStream = NULL;
		HKEY hPolicy;
		LPVOID buffer = NULL;
		DWORD szNeeded = 0;
		P_POL_REVISION plVersion;

		HANDLE hFile = CreateFileW(lpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			return false;
		}

		do {
			status = OpenRegistry(hFile, &hSecurity);
			if (status == FALSE) {
				break;
			}
			status = OpenRegistryKey(hSecurity, NULL, L"Policy", 0, KEY_READ, &hPolicy);
			if (status == FALSE) {
				break;
			}
			status = OpenAndQueryWithAlloc(hSecurity, hPolicy, L"PolRevision", NULL, NULL, (LPVOID *) &plVersion, NULL);
			if (status == FALSE) {
				break;
			}
			if (plVersion->Minor <= 9) {
				// This is NT 5!
				delete[] plVersion;
				break;
			}
			delete[] plVersion;
			//
			status = OpenAndQueryWithAlloc(hSecurity, hPolicy, L"PolEKList", NULL, NULL, &buffer, &szNeeded);
			if(status == FALSE){
				break;
			}
			status = DecryptSec((P_NT6_HARD_SECRET) buffer, szNeeded, sysKey);
			if (status == FALSE) {
				break;
			}
			//


		}while(FALSE);
		
		CloseHandle(hFile);
	}

	BOOL DecryptSec(IN OUT P_NT6_HARD_SECRET hardSecretBlob, IN DWORD szHardSecretBlob, IN PBYTE sysKey) {
		BOOL status  = FALSE;
		PBYTE pKey = sysKey;
		BYTE keyBuffer[AES_256_KEY_SIZE] = { 0 };
		P_NT6_SYSTEM_KEYS nt6keysStream = NULL;

		StramSHA256 hash;
		hash.Update((char *) sysKey, SYSKEY_LENGTH);
		
		for (DWORD i = 0; i < 1000; ++i) {
			hash.Update((const char*)(hardSecretBlob->lazyiv), LAZY_NT6_IV_SIZE);
		}
		memcpy(keyBuffer, hash.GetValue(), AES_256_KEY_SIZE);
		int szNeeded = szHardSecretBlob - FIELD_OFFSET(NT6_HARD_SECRET, encryptedSecret);
		std::string buffer =  SSLHelper::AesECBDecrypt(hardSecretBlob->encryptedSecret, szNeeded, keyBuffer, AES_256_KEY_SIZE);
		status = (buffer != "");
		if (status) {
			memcpy(hardSecretBlob->encryptedSecret, buffer.c_str(), szNeeded);
		}

		return status;
	}

	BOOL GetSecrete(IN P_HIVE_HANDLE hSecurity, IN HKEY hPolicyBase, IN P_HIVE_HANDLE hSystem, IN P_NT6_SYSTEM_KEYS lsaKeysStream) {
		BOOL status = FALSE;
		HKEY hSecrets, hSecret, hCurrentControlSet, hServiceBase;
		DWORD nbSubKeys = 0, szMaxSubKeyLen = 0, szSecretName = 0;
		wchar_t * secretName = NULL;

		do {
			status = OpenRegistryKey(hSecurity, hPolicyBase, L"Secrets", 0, KEY_READ, &hSecrets);
			if (status == FALSE) {
				break;
			}
			status = GetCurrentControlSet(hSecurity, &hCurrentControlSet);
			if (status == FALSE) {
				break;
			}
			status = OpenRegistryKey(hSecurity, hCurrentControlSet, L"services", 0, KEY_READ, &hServiceBase);
			if (status == FALSE) {
				break;
			}
			status = QueryInfoKey(hSecurity, hSecrets, NULL, NULL, NULL, &nbSubKeys, &szMaxSubKeyLen);
			if (status == FALSE) {
				break;
			}
			++szMaxSubKeyLen;
			secretName = new wchar_t[szMaxSubKeyLen + 1];
			if (secretName == NULL) {
				break;
			}
			memset(secretName, 0, (szMaxSubKeyLen + 1) * sizeof(wchar_t));
			for (DWORD i = 0; i < nbSubKeys; ++i) {
				status = GetRegistryEnumKey(hSecurity, hSecrets, i, secretName, &szSecretName, NULL, NULL, NULL);
				if (status == FALSE) {
					continue;
				}
				status = (OpenRegistryKey(hSecurity, hSecrets, secretName, 0, KEY_READ, &hSecret));
				if (status == FALSE) {
					continue;
				}
				// TODO ...
			}

		}while(FALSE);
		if (secretName) {
			delete[] secretName;
		}
		return status;
	}

	WIFI_PASSWORD() {
		memset(sysKey, 0, SYSKEY_LENGTH);
		m_hSecurity = NULL;
	}

	~WIFI_PASSWORD() = default;

private:
	BYTE sysKey[SYSKEY_LENGTH];
	P_HIVE_HANDLE m_hSecurity;
};
