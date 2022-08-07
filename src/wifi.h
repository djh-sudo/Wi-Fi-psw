#pragma once
#include <iostream>
#include <string>
#include "HIVE.h"
#include "dpapi.h"
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
			status = GetLSASyskey(m_hSecurity, hComputerNameOrLSA, m_sysKey);

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
			return FALSE;
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
			status = OpenAndQueryWithAlloc(hSecurity, hPolicy, L"PolEKList", NULL, NULL, &buffer, &szNeeded);
			if(status == FALSE){
				break;
			}
			status = DecryptAESSec((P_NT6_HARD_SECRET) buffer, szNeeded, NULL, m_sysKey);
			if (status == FALSE) {
				break;
			}
			nt6keysStream = (P_NT6_SYSTEM_KEYS) new BYTE[((P_NT6_HARD_SECRET)buffer)->clearSecret.SecretSize];
			if (nt6keysStream == NULL) {
				break;
			}
			memcpy(nt6keysStream, ((P_NT6_HARD_SECRET)buffer)->clearSecret.Secret, ((P_NT6_HARD_SECRET)buffer)->clearSecret.SecretSize);

			status = GetSecrete(hSecurity, hPolicy, m_hSecurity, nt6keysStream);
			if (status == FALSE) {
				delete[] nt6keysStream;
				break;
			}


		}while(FALSE);
		
		CloseHandle(hFile);
	}

	BOOL DecryptAESSec(IN OUT P_NT6_HARD_SECRET hardSecretBlob, IN DWORD szHardSecretBlob, IN P_NT6_SYSTEM_KEYS lsaKeysStream, IN PBYTE sysKey) {
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

		return status;
	}

	BOOL DecryptSecrect(IN P_HIVE_HANDLE hSecurity,
		                IN HKEY hSecret,
		                IN const LPCWSTR KeyName,
		                IN P_NT6_SYSTEM_KEYS lsaKeysStream,
		                IN PVOID* pBufferOut,
		                IN PDWORD pSzBufferOut) {

		BOOL status = FALSE;
		DWORD szSecret = 0;
		PVOID secret = NULL;
		do {
			status = OpenAndQueryWithAlloc(hSecurity, hSecret, KeyName, NULL, NULL, &secret, &szSecret);
			if (status == FALSE) {
				break;
			}
			status = DecryptAESSec((P_NT6_HARD_SECRET)secret, szSecret, lsaKeysStream, NULL);
			if (status == FALSE) {
				break;
			}
			*pSzBufferOut = ((P_NT6_HARD_SECRET)secret)->clearSecret.SecretSize;
			*pBufferOut = new BYTE[*pSzBufferOut];
			if (!(*pBufferOut)) {
				break;
			}
			status = TRUE;
			memcpy(*pBufferOut, ((P_NT6_HARD_SECRET)secret)->clearSecret.Secret, *pSzBufferOut);
			delete[] secret;

		} while (FALSE);
		
		return status;
	}

	BOOL GetSecrete(IN P_HIVE_HANDLE hSecurity, IN HKEY hPolicyBase, IN P_HIVE_HANDLE hSystem, IN P_NT6_SYSTEM_KEYS lsaKeysStream) {
		BOOL status = FALSE;
		HKEY hSecrets, hSecret, hCurrentControlSet, hServiceBase;
		DWORD nbSubKeys = 0, szMaxSubKeyLen = 0, szSecretName = 0, szSecret = 0;
		PVOID pSecret = NULL;
		wchar_t * secretName = NULL;

		do {
			status = OpenRegistryKey(hSecurity, hPolicyBase, L"Secrets", 0, KEY_READ, &hSecrets);
			if (status == FALSE) {
				break;
			}
			status = GetCurrentControlSet(hSystem, &hCurrentControlSet);
			if (status == FALSE) {
				break;
			}
			status = OpenRegistryKey(hSystem, hCurrentControlSet, L"services", 0, KEY_READ, &hServiceBase);
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

			for (DWORD i = 0; i < nbSubKeys; ++i) {
				memset(secretName, 0, (szMaxSubKeyLen + 1) * sizeof(wchar_t));
				szSecretName = szMaxSubKeyLen;
				status = GetRegistryEnumKey(hSecurity, hSecrets, i, secretName, &szSecretName, NULL, NULL, NULL);
				if (status == FALSE) {
					continue;
				}
				status = (OpenRegistryKey(hSecurity, hSecrets, secretName, 0, KEY_READ, &hSecret));
				if (status == FALSE) {
					continue;
				}
				status = DecryptSecrect(hSecurity, hSecret, L"CurrVal", lsaKeysStream, &pSecret, &szSecret);
				if (status == FALSE) {
					continue;
				}
				else {
					status = (_wcsicmp(secretName, L"DPAPI_SYSTEM") == 0) && (szSecret == sizeof(DWORD) + 2 * SHA_DIGEST_LENGTH);
					if (status == FALSE) {
						
						delete[] pSecret;
						pSecret = NULL;
						continue;
					}
					memcpy(m_secret, (PBYTE)pSecret + sizeof(DWORD) + SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH);
					delete[] pSecret;
					pSecret = NULL;
					break;
				}
				
			}

			if (secretName != NULL) {
				delete[] secretName;
				secretName = NULL;
			}

		}while(FALSE);
		
		return status;
	}

	BOOL GetEncMasterKey(LPCWSTR lpFileName) {
		BOOL status = FALSE;
		LPBYTE buffer = NULL;
		DWORD szBuffer = 0;

		status = ReadMasterKeyFile(lpFileName, &buffer, &szBuffer);
		do {
			if (status == FALSE) {
				break;
			}
			m_pMasterKeys = (P_DPAPI_MASTERKEYS)new BYTE[sizeof(DPAPI_MASTERKEYS)];
			
			if (m_pMasterKeys == NULL) {
				break;
			}
			memset(m_pMasterKeys, 0, sizeof(DPAPI_MASTERKEYS));
			memcpy(m_pMasterKeys, buffer, FIELD_OFFSET(DPAPI_MASTERKEYS, MasterKey));

			szBuffer = m_pMasterKeys->dwMasterKeyLen;
			m_pMasterKeys->MasterKey = (P_DPAPI_MASTERKEY)new BYTE[szBuffer];
			if (m_pMasterKeys->MasterKey == NULL) {
				break;
			}
			memcpy(m_pMasterKeys->MasterKey, buffer + FIELD_OFFSET(DPAPI_MASTERKEYS, MasterKey), szBuffer);

		} while (FALSE);
		if (buffer) {
			delete[] buffer;
			buffer = NULL;
		}
		return status;
	}

	BOOL DecryptMasterKey() {
		BOOL status = FALSE;
		DWORD keyLen = m_pMasterKeys->dwMasterKeyLen - FIELD_OFFSET(DPAPI_MASTERKEY, pbKey);
		if (m_pMasterKeys == NULL) {
			return FALSE;
		}
		do {
			std::string HMACHash = SSLHelper::PBKDF2_SHA512(
				      /*password*/ m_secret, 20,
				      /*  salt  */ m_pMasterKeys->MasterKey->salt, 16,
				      /* rounds */ m_pMasterKeys->MasterKey->rounds,48);

			std::string key = HMACHash.substr(0, 32);
			std::string iv = HMACHash.substr(32, 16);
			std::string plain = SSLHelper::AesCBCDecrypt(m_pMasterKeys->MasterKey->pbKey, keyLen, key.c_str(), 32, iv.c_str());
			status = MemoryVerify((char *)plain.c_str(), keyLen, m_secret, 20);
		} while (FALSE);
		// TODO ...
		return status;
	}

	WIFI_PASSWORD() {
		memset(m_sysKey, 0, SYSKEY_LENGTH);
		memset(m_secret, 0, SHA_DIGEST_LENGTH);
		m_hSecurity = NULL;
		m_pMasterKeys = NULL;
	}

	~WIFI_PASSWORD() = default;

private:
	BYTE m_sysKey[SYSKEY_LENGTH];
	BYTE m_secret[SHA_DIGEST_LENGTH];
	P_HIVE_HANDLE m_hSecurity;
	P_DPAPI_MASTERKEYS m_pMasterKeys;
};
