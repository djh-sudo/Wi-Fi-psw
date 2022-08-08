#pragma once
#include <iostream>
#include <string>
#include "HIVE.h"
#include "dpapi.h"
#include "CipherHelper.h"
#include "tinyxml2.h"
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


class WIFI_PASSWORD {

public:
	/* Get system key from Register dump file */
	BOOL GetSysKey(LPCWSTR lpFileName) {
		BOOL status = FALSE;
		HKEY hCurrentControlSet, hComputerNameOrLSA;

		HANDLE hfile = INVALID_HANDLE_VALUE;
		{
			zl::WinUtils::ZLWow64Guard guard;
			hfile = CreateFileW(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		}
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
	/*Get LSA Key from Register dump file */
	BOOL GetLSAKeyAndSecrete(LPCWSTR lpFileName) {
		BOOL status = FALSE;
		P_HIVE_HANDLE hSecurity;
		P_NT6_SYSTEM_KEYS nt6keysStream = NULL;
		HKEY hPolicy;
		LPVOID buffer = NULL;
		DWORD szNeeded = 0;
		P_POL_REVISION plVersion;
		
		HANDLE hFile = INVALID_HANDLE_VALUE;
		{
			// Wow64RevertWow64FsRedirection
			/*
			* If it's a 32-bit app running on a 64-bit OS, 
			* then calling Wow64DisableWow64FsRedirection() 
			* before your call to CreateFile will read from "C:\Windows\System32" 
			* instead of "C:\Windows\Syswow64",
			*/
			zl::WinUtils::ZLWow64Guard guard;
			hFile = CreateFileW(lpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
		}
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
		return status;
	}

	/*Get WiFi enc-password from XML file */
	BOOL GetWiFiXMLInfo(LPCWSTR lpFileName) {
		BOOL status = FALSE;
		tinyxml2::XMLDocument doc;
		char path[MAX_PATH] = { 0 };
		PBYTE WiFiBlob = NULL;
		status = WideCharToMultiByte(CP_ACP, 0, lpFileName, -1, path, MAX_PATH, NULL, NULL);
		do {
			if (status == FALSE) {
				break;
			}
			status = doc.LoadFile(path) == 0;
			if (status == FALSE) {
				break;
			}
			tinyxml2::XMLElement* root = doc.RootElement();
			if (root == NULL) {
				break;
			}

			tinyxml2::XMLElement *key = root->FirstChildElement("MSM")
				                        ->FirstChildElement("security")
				                        ->FirstChildElement("sharedKey")
				                        ->FirstChildElement("keyMaterial");
			tinyxml2::XMLElement *name = root->FirstChildElement("SSIDConfig")
				                         ->FirstChildElement("SSID")
				                         ->FirstChildElement("name");
			if (key == NULL) {
				break;
			}
			std::string blob = key->GetText();

			if (name == NULL) {
				break;
			}

			std::string nameId = name->GetText();
			m_szUserId = nameId.size() + 1;
			m_userId = new BYTE[m_szUserId];
			if (m_userId == NULL) {
				break;
			}
			memset(m_userId, 0 ,m_szUserId);
			memcpy(m_userId, nameId.c_str(), m_szUserId);
			DWORD szWiFiBlob = blob.size() >> 1;
			WiFiBlob = new BYTE[szWiFiBlob];
			memset(WiFiBlob, 0, szWiFiBlob);
			memcpy(WiFiBlob, SSLHelper::convert_ASCII(blob).c_str(), szWiFiBlob);
			memcpy(&m_guidMasterKey, &((P_DPAPI_BLOB)WiFiBlob)->guidMasterKey, sizeof(GUID));

			DWORD acc = ((P_DPAPI_BLOB)WiFiBlob)->dwDescriptionLen; 
			m_szpbSalt = *(PDWORD)(WiFiBlob + acc + 56);
			m_pSalt = new BYTE[m_szpbSalt];
			if (m_pSalt == NULL) {
				break;
			}
			memset(m_pSalt, 0, m_szpbSalt);
			memcpy(m_pSalt, WiFiBlob + acc + 60, m_szpbSalt);
			acc += m_szpbSalt;

			acc += *(PDWORD)(WiFiBlob + acc + 60);
			acc += *(PDWORD)(WiFiBlob + acc + 72);

			m_szpbData = *(PDWORD)(WiFiBlob + acc + 76);
			m_pbData = new BYTE[m_szpbData];
			if (m_pbData == NULL) {
				break;
			}
			memset(m_pbData, 0, m_szpbData);
			memcpy(m_pbData, WiFiBlob + acc + 80, m_szpbData);
			
			acc += m_szpbData;
			acc += *(PDWORD)(WiFiBlob + acc + 80);
			if (acc + 84 != szWiFiBlob) {
				break;
			}
			status = TRUE;

		}while(FALSE);

		if (WiFiBlob != NULL) {
			delete[] WiFiBlob;
			WiFiBlob = NULL;
		}
		return status;
	}

	BOOL DecryptAESSec(IN OUT P_NT6_HARD_SECRET hardSecretBlob,
		               IN DWORD szHardSecretBlob,
		               IN P_NT6_SYSTEM_KEYS lsaKeysStream,
		               IN PBYTE sysKey) {
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

	BOOL GetSecrete(IN P_HIVE_HANDLE hSecurity,
		            IN HKEY hPolicyBase,
		            IN P_HIVE_HANDLE hSystem,
		            IN P_NT6_SYSTEM_KEYS lsaKeysStream) {
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

	BOOL GetMasterKeyPath(LPCWSTR lpFileName) {
		BOOL status = FALSE;
		WCHAR wbuf[64] = { 0 };
		StringFromGUID2(m_guidMasterKey, wbuf, _countof(wbuf));
		status = _wcslwr_s(wbuf) == 0;
		if (status == FALSE) {
			return FALSE;
		}
		wchar_t *basePath = L"C:\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User\\";
		wcscpy((wchar_t *)lpFileName, basePath);
		lstrcatW((LPWSTR)lpFileName, wbuf + 1);
		DWORD len = wcslen(lpFileName);
		*((wchar_t *)lpFileName + len - 1) = L'\0';
		status = TRUE;
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
		if (m_pMasterKeys == NULL) {
			return FALSE;
		}
		DWORD keyLen = m_pMasterKeys->dwMasterKeyLen - FIELD_OFFSET(DPAPI_MASTERKEY, pbKey);
		
		do {
			std::string HMACHash = SSLHelper::PBKDF2_SHA512(
				      /*password*/ m_secret, 20,
				      /*  salt  */ m_pMasterKeys->MasterKey->salt, 16,
				      /* rounds */ m_pMasterKeys->MasterKey->rounds,48);

			std::string key = HMACHash.substr(0, 32);
			std::string iv = HMACHash.substr(32, 16);
			std::string plain = SSLHelper::AesCBCDecrypt(m_pMasterKeys->MasterKey->pbKey, keyLen, key.c_str(), 32, iv.c_str());
			status = MemoryVerify((char *)plain.c_str(), keyLen, m_secret, 20);
			if (status == FALSE) {
				break;
			}
			m_szMasterKey = keyLen - 80;
			if (m_szMasterKey <= 0) {
				status = FALSE;
				break;
			}
			m_masterKey = new BYTE[m_szMasterKey];
			if (m_masterKey == NULL) {
				status = FALSE;
				break;
			}
			memcpy(m_masterKey, (char*)plain.c_str() + 80, m_szMasterKey);
		} while (FALSE);

		return status;
	}

	BOOL DecryptWiFiPassword() {
		BOOL status = FALSE;
		do {
			if (m_masterKey == NULL || m_szMasterKey <= 0) {
				break;
			}
			std::string sha1Key = SSLHelper::sha1(m_masterKey, m_szMasterKey);

			if (m_pSalt == NULL || m_szpbSalt <= 0) {
				break;
			}
			std::string outKey = SSLHelper::HMAC_SHA512(sha1Key.c_str(), SHA_DIGEST_LENGTH, m_pSalt, m_szpbSalt);
			if (m_pbData == NULL || m_szpbData <= 0) {
				break;
			}
			char iv[16] = { 0 };
			std::string psw = SSLHelper::AesCBCDecrypt(m_pbData, m_szpbData, outKey.substr(0, 32).c_str(), 32, iv);
			m_szPassword = psw.size();
			if (psw[m_szPassword - 1] >= 0 && psw[m_szPassword - 1] <= 0x10) {
				m_szPassword -= psw[m_szPassword - 1];
			}
			m_password = new BYTE[m_szPassword];
			if (m_password == NULL) {
				break;
			}
			memcpy(m_password, psw.c_str(), m_szPassword);
			status = TRUE;
		}while(FALSE);

		return status;
	}

	BOOL CopyInfo(std::string& id, std::string& psw) {
		if (m_password == NULL || m_userId == NULL) {
			return FALSE;
		}
		id = std::string((char *)m_userId, m_szUserId);
		psw = std::string((char *)m_password, m_szPassword);
		return TRUE;
	}

	WIFI_PASSWORD() {
		memset(m_sysKey, 0, SYSKEY_LENGTH);
		memset(m_secret, 0, SHA_DIGEST_LENGTH);
		memset(&m_guidMasterKey, 0, sizeof(GUID));
		m_hSecurity = NULL;
		m_pMasterKeys = NULL;

		m_masterKey = NULL;
		m_szMasterKey = 0;

		m_pSalt = NULL;
		m_szpbSalt = 0;
		
		m_pSalt = NULL;
		m_szpbSalt = 0;

		m_password = NULL;
		m_szPassword = 0;

		m_userId = NULL;
		m_szUserId = 0;
	}

	virtual ~WIFI_PASSWORD() {
		if (m_pMasterKeys != NULL) {
			delete[] m_pMasterKeys;
			m_pMasterKeys = NULL;
		}
		if (m_masterKey != NULL) {
			delete[] m_masterKey;
			m_masterKey = NULL;
		}
		if (m_pbData != NULL) {
			delete[] m_pbData;
			m_pbData = NULL;
		}
		if (m_pSalt != NULL) {
			delete[] m_pSalt;
			m_pSalt = NULL;
		}
		if (m_password != NULL) {
			delete[] m_password;
			m_password = NULL;
		}
		if (m_userId != NULL) {
			delete[] m_userId;
			m_userId = NULL;
		}
	};

private:
	BYTE m_sysKey[SYSKEY_LENGTH];
	BYTE m_secret[SHA_DIGEST_LENGTH];
	GUID m_guidMasterKey;
	P_HIVE_HANDLE m_hSecurity;
	P_DPAPI_MASTERKEYS m_pMasterKeys;
	PBYTE m_masterKey;
	DWORD m_szMasterKey;

	PBYTE m_pbData;
	DWORD m_szpbData;

	PBYTE m_pSalt;
	DWORD m_szpbSalt;

	PBYTE m_password;
	DWORD m_szPassword;

	PBYTE m_userId;
	DWORD m_szUserId;
};

class WiFi {
public:
	
	std::string GetPassword() {
		return m_password;
	};

	std::string GetNameId() {
		return m_nameId;
	}
	bool Init(LPCWSTR lpSystemBkup, LPCWSTR lpSECURITY, LPCWSTR lpXmlPath) {
		BOOL status = FALSE;
		LPCWSTR lpFileName = NULL;
		do {
			lpFileName = new wchar_t[MAX_PATH];
			if (lpFileName == NULL) {
				break;
			}
			memset((char *)lpFileName, 0, MAX_PATH * sizeof(wchar_t));
			status = m_meta.GetSysKey(lpSystemBkup);
			if (status ==FALSE) {
				break;
			}

			status = m_meta.GetLSAKeyAndSecrete(lpSECURITY);
			if (status ==FALSE) {
				break;
			}

			status = m_meta.GetWiFiXMLInfo(lpXmlPath);
			if (status ==FALSE) {
				break;
			}

			status = m_meta.GetMasterKeyPath(lpFileName);
			if (status ==FALSE) {
				break;
			}

			status = m_meta.GetEncMasterKey(lpFileName);
			if (status ==FALSE) {
				break;
			}

			status = m_meta.DecryptMasterKey();
			if (status ==FALSE) {
				break;
			}
			
			status = m_meta.DecryptWiFiPassword();
			if (status ==FALSE) {
				break;
			}
			status = m_meta.CopyInfo(m_nameId, m_password);
		}while(FALSE);
		
		if (lpFileName != NULL) {
			delete[] lpFileName;
			lpFileName = NULL;
		}
		return status;
	}

	WiFi() = default;
	virtual ~WiFi() = default;

private:
	WIFI_PASSWORD m_meta;
	std::string m_password;
	std::string m_nameId;
};