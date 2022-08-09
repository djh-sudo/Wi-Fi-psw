#pragma once
#include <Windows.h>
#include <string>
#include "dpapi.h"
#include "tinyxml2.h"


class WIFI_MODULE {

public:
	/*
	* From SYSTEM\\ControlSet001\\ read the SYSKEY_NAMES keys Infomation, 
	* SYSKEY_NAMES keys is ["JD", "Skew1", "GBG", "Data"], and then
	* Call RegQueryInfoKey, read 8 byte each time, convert it to ASCII(4), 
	* then get the 16 bytes parameter vector!
	* Lastly, using permutation box to obfuscate the vector, then get the syskey!
	* permutation box like the following vector
	* [11, 6, 7, 1, 8, 10, 14, 0, 3, 5, 2, 15, 13, 9, 12, 4]
	*/
	bool GetParameter1(char * bufferKey) {
		BOOL status = TRUE;
		HKEY hCurrentControlSet, hComputerNameOrLSA, hKey;
		std::string currentControlSet = "SYSTEM\\ControlSet001\\";
		const char * SYSKEY_NAMES[] = {"JD", "Skew1", "GBG", "Data"};
		
		wchar_t buffer[8 + 1] = { 0 };
		DWORD szNeeded = 0;
 		do {
			if (bufferKey == NULL) {
				break;
			}

			status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, currentControlSet.c_str(), 0, KEY_READ | KEY_QUERY_VALUE, &hCurrentControlSet);
			if (status != ERROR_SUCCESS) {
				break;
			}
			
			status = RegOpenKeyA(hCurrentControlSet, "Control\\LSA", &hComputerNameOrLSA);
			if (status != ERROR_SUCCESS) {
				break;
			}

			for (int i = 0; i < ARRAYSIZE(SYSKEY_NAMES) && !status; ++i) {
				status = RegOpenKeyA(hComputerNameOrLSA, SYSKEY_NAMES[i], &hKey);
				if (status != ERROR_SUCCESS) {
					break;
				}

				memset(buffer, 0, 9);
				szNeeded = 9;
				status = RegQueryInfoKeyW(hKey, buffer, &szNeeded, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
				if (status != ERROR_SUCCESS) {
					break;
				}
				status = (swscanf(buffer, L"%x", (DWORD *) &bufferKey[i * sizeof(DWORD)]) == -1);
				RegCloseKey(hKey);
			}
			if (status != ERROR_SUCCESS) {
				break;
			}
		}while(FALSE);
		
		RegCloseKey(hComputerNameOrLSA);
		RegCloseKey(hCurrentControlSet);
		return (status == ERROR_SUCCESS) ? true : false;
	}

	bool GetSyskey() {
		const BYTE SYSKEY_PERMUT[] = {11, 6, 7, 1, 8, 10, 14, 0, 3, 5, 2, 15, 13, 9, 12, 4};
		char bufferKey[SYSKEY_LENGTH] = { 0 };
		if (GetParameter1(bufferKey)) {
			for (int i = 0; i < SYSKEY_LENGTH; ++i) {
				m_sysKey[i] = bufferKey[SYSKEY_PERMUT[i]];
			}
			return true;
		}
		else {
			return false;
		}
	}

	bool GetParameter2(char ** buffer, int* szBuffer) {
		BOOL status = FALSE;
		std::string policy = "SECURITY\\Policy\\";
		HKEY hPolicy, hKey;
		DWORD szNeeded;
		do {
			status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, policy.c_str(), 0, KEY_READ | KEY_QUERY_VALUE, &hPolicy);
			if (status != ERROR_SUCCESS) {
				break;
			}
			status = RegOpenKeyA(hPolicy, "PolEKList", &hKey);
			if (status != ERROR_SUCCESS) {
				break;
			}
			status = RegQueryValueExA(hKey, NULL, NULL, NULL, NULL, &szNeeded);
			if (status != ERROR_SUCCESS) {
				break;
			}
			*buffer = new char[szNeeded];
			if (*buffer == NULL) {
				break;
			}
			memset(*buffer, 0, szNeeded);
			status = RegQueryValueExA(hKey, NULL, NULL, NULL, (LPBYTE)*buffer, &szNeeded);
			if (status != ERROR_SUCCESS) {
				break;
			}
			*szBuffer = szNeeded;

		}while(false);

		if (status != ERROR_SUCCESS && *buffer == NULL) {
			delete[] *buffer;
			*buffer = NULL;
		}
		RegCloseKey(hPolicy);
		RegCloseKey(hKey);
		return (status == ERROR_SUCCESS) ? true : false;
	}

	bool GetParameter3(char ** buffer, int* szBuffer) {
		BOOL status = FALSE;
		std::string policy = "SECURITY\\Policy\\";
		HKEY hPolicy, hKey, hSecret, hResult;
		DWORD szNeeded, nbSubKeys = 0, szMaxSubKeyLen = 0 ,szSecretName = 0;
		char * secretName = NULL;
		do {
			status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, policy.c_str(), 0, KEY_READ | KEY_QUERY_VALUE, &hPolicy);
			if (status != ERROR_SUCCESS) {
				break;
			}
			status = RegOpenKeyA(hPolicy, "Secrets", &hKey);
			if (status != ERROR_SUCCESS) {
				break;
			}
			status = RegQueryInfoKeyW(hKey, NULL, NULL, NULL, &nbSubKeys, &szMaxSubKeyLen, NULL, NULL, NULL, NULL, NULL, NULL);
			if (status != ERROR_SUCCESS) {
				break;
			}
			++szMaxSubKeyLen;
			secretName = new char[szMaxSubKeyLen + 1];
			if (secretName == NULL) {
				break;
			}
			for (int i = 0; i < nbSubKeys; ++i) {
				memset(secretName, 0, szMaxSubKeyLen + 1);
				szSecretName = szMaxSubKeyLen;
				status = RegEnumKeyExA(hKey, i, secretName, &szSecretName, 0, NULL, NULL, NULL);
				if (status != ERROR_SUCCESS) {
					continue;
				}
				status = RegOpenKeyExA(hKey, secretName, 0, KEY_READ, &hSecret);
				if (status != ERROR_SUCCESS) {
					continue;
				}
				status = (strcmp(secretName, "DPAPI_SYSTEM") == 0);
				if (status == FALSE) {
					continue;
				}
				status = RegOpenKeyA(hSecret, "CurrVal", &hResult);
				if (status != ERROR_SUCCESS) {
					continue;
				}
				status = RegQueryValueExA(hResult, NULL, NULL, NULL, NULL, &szNeeded);
				if (status != ERROR_SUCCESS) {
					continue;
				}
				*buffer = new char[szNeeded];
				if (*buffer == NULL) {
					break;
				}
				memset(*buffer, 0, szNeeded);
				status = RegQueryValueExA(hResult, NULL, NULL, NULL, (LPBYTE)*buffer, &szNeeded);
				if (status != ERROR_SUCCESS) {
					break;
				}
				*szBuffer = szNeeded;
				if (status != ERROR_SUCCESS && *buffer != NULL) {
					delete[] *buffer;
					*buffer = NULL;
				}
				break;
			}
		}while(false);
		if (secretName != NULL) {
			delete[] secretName;
			secretName = NULL;
		}
		RegCloseKey(hResult);
		RegCloseKey(hSecret);
		RegCloseKey(hKey);
		RegCloseKey(hPolicy);

		return (status == ERROR_SUCCESS) ? true : false;
	}
	/*
	* From HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM\CurrVal, 
	* reading secret, which length is 20 bytes
	*/
	bool GetSecrete() {
		char *secret = NULL, *buffer = NULL;
		bool status = false;
		int szSecret = 0, szBuffer = 0;
		P_NT6_SYSTEM_KEYS nt6keysStream = NULL;

		if (GetParameter2(&secret, &szSecret) && secret != NULL) {
			do {
				status = DecryptAESSec((P_NT6_HARD_SECRET) secret, szSecret, NULL, (PBYTE)m_sysKey);
				if (status == false) {
					break;
				}
				nt6keysStream = (P_NT6_SYSTEM_KEYS) new BYTE[((P_NT6_HARD_SECRET)secret)->clearSecret.SecretSize];
				if (nt6keysStream == NULL) {
					break;
				}
				memcpy(nt6keysStream, ((P_NT6_HARD_SECRET)secret)->clearSecret.Secret, ((P_NT6_HARD_SECRET)secret)->clearSecret.SecretSize);
				
				status = GetParameter3(&buffer, &szBuffer);
				if (status == false || buffer == NULL) {
					break;
				}
				
				status = DecryptAESSec((P_NT6_HARD_SECRET)buffer, szBuffer, nt6keysStream, NULL);
				if (status == false) {
					break;
				}
				int szTmpBuffer = ((P_NT6_HARD_SECRET)buffer)->clearSecret.SecretSize;
				char *tmpBuffer = new char[szTmpBuffer];
				if (tmpBuffer == NULL) {
					break;
				}
				memset(tmpBuffer, 0, szTmpBuffer);
				memcpy(tmpBuffer, ((P_NT6_HARD_SECRET)buffer)->clearSecret.Secret, szTmpBuffer);
				status = (szTmpBuffer == sizeof(DWORD) + 2 * SHA_DIGEST_LENGTH);
				if (status == false) {
					delete[] tmpBuffer;
					tmpBuffer = NULL;
					break;
				}

				memcpy(m_secret, (PBYTE)tmpBuffer + sizeof(DWORD) + SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH);
				delete[] tmpBuffer;
				tmpBuffer = NULL;

			}while(false);
			// Ending free Memory
			if (nt6keysStream != NULL) {
				delete[] nt6keysStream;
				nt6keysStream = NULL;
			}
			if (buffer != NULL) {
				delete[] buffer;
				buffer = NULL;
			}
			if (secret != NULL) {
				delete[] secret;
				secret = NULL;
			}
			return status;
		}
		else {
			return false;
		}
	}

	/*Get WiFi enc-password from XML file */
	bool GetWiFiXMLInfo(std::wstring lpFileName) {
		BOOL status = FALSE;
		tinyxml2::XMLDocument doc;
		char path[MAX_PATH] = { 0 };
		PBYTE WiFiBlob = NULL;
		status = WideCharToMultiByte(CP_ACP, 0, lpFileName.c_str(), -1, path, MAX_PATH, NULL, NULL);
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

			m_userId = name->GetText();

			DWORD szWiFiBlob = blob.size() >> 1;
			WiFiBlob = new BYTE[szWiFiBlob];
			memset(WiFiBlob, 0, szWiFiBlob);
			memcpy(WiFiBlob, SSLHelper::convert_ASCII(blob).c_str(), szWiFiBlob);
			memcpy(&m_guidMasterKey, &((P_DPAPI_BLOB)WiFiBlob)->guidMasterKey, sizeof(GUID));

			DWORD acc = ((P_DPAPI_BLOB)WiFiBlob)->dwDescriptionLen; 
			m_szpbSalt = *(PDWORD)(WiFiBlob + acc + 56);
			m_pSalt = new char[m_szpbSalt];
			if (m_pSalt == NULL) {
				break;
			}
			memset(m_pSalt, 0, m_szpbSalt);
			memcpy(m_pSalt, WiFiBlob + acc + 60, m_szpbSalt);
			acc += m_szpbSalt;

			acc += *(PDWORD)(WiFiBlob + acc + 60);
			acc += *(PDWORD)(WiFiBlob + acc + 72);

			m_szpbData = *(PDWORD)(WiFiBlob + acc + 76);
			m_pbData = new char[m_szpbData];
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
		return (status == TRUE) ? true : false;
	}

	void GetMasterKeyPath() {
		WCHAR wbuf[64] = { 0 };
		StringFromGUID2(m_guidMasterKey, wbuf, _countof(wbuf));
		_wcslwr_s(wbuf) == 0;
		m_masterKeyPath = L"C:\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User\\" + std::wstring(wbuf).replace(0, 1, L"");
		m_masterKeyPath.replace(m_masterKeyPath.size() - 1, 1, L"");
	}

	bool GetEncMasterKey() {
		BOOL status = FALSE;
		LPBYTE buffer = NULL;
		DWORD szBuffer = 0;

		status = ReadMasterKeyFile(m_masterKeyPath.c_str(), &buffer, &szBuffer);
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

	bool DecryptMasterKey() {
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
			m_masterKey = new char[m_szMasterKey];
			if (m_masterKey == NULL) {
				status = FALSE;
				break;
			}
			memcpy(m_masterKey, (char*)plain.c_str() + 80, m_szMasterKey);
		} while (FALSE);

		return (status == TRUE) ? true : false;
	}

	bool DecryptWiFiPassword() {
		bool status = false;
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
			m_password = SSLHelper::AesCBCDecrypt(m_pbData, m_szpbData, outKey.substr(0, 32).c_str(), 32, iv);
			if (m_password.back() >= 0 && m_password.back() <= 0x10) {
				int tmp = m_password.back();
				m_password = m_password.substr(0, m_password.length() - tmp);
			}
			status = true;
		}while(false);

		return status;
	}

	bool CopyInfo(std::string& id, std::string& psw) {
		if (m_password == "" || m_userId == "") {
			return false;
		}
		id = m_userId;
		psw = m_password;
		return true;
	}


	WIFI_MODULE() {
		m_phCurrentControlSet = NULL;
		memset(m_sysKey, 0, SYSKEY_LENGTH);
		memset(m_secret, 0, SHA_DIGEST_LENGTH);

		m_pSalt = NULL;
		m_szpbSalt = 0;

		m_pbData = NULL;
		m_szpbData = 0;

		m_pMasterKeys = NULL;

		m_masterKey = NULL;
		m_szMasterKey = 0;
	}

	~WIFI_MODULE() {
		if (m_pSalt) {
			delete[] m_pSalt;
			m_pSalt = NULL;
		}
		if (m_pbData) {
			delete[] m_pbData;
			m_pbData = NULL;
		}
		if (m_masterKey) {
			delete[] m_masterKey;
			m_masterKey = NULL;
		}
	}

private:
	PHKEY m_phCurrentControlSet;
	char m_sysKey[SYSKEY_LENGTH];
	char m_secret[SHA_DIGEST_LENGTH];

	P_DPAPI_MASTERKEYS m_pMasterKeys;
	GUID m_guidMasterKey;

	char* m_pSalt;
	int m_szpbSalt;

	char* m_pbData;
	int m_szpbData;

	char* m_masterKey;
	int m_szMasterKey;

	std::string m_userId;
	std::string m_password;

	std::wstring m_masterKeyPath;

};

class WiFi {

public:
	std::string GetPassword() {
		return m_password;
	};

	std::string GetNameId() {
		return m_nameId;
	}
	bool Init(std::wstring lpXmlPath) {
		bool status = false;
		do {
			if (m_meta.GetSyskey() == false) {
				break;
			}
			if (m_meta.GetSecrete() == false) {
				break;
			}
			if (m_meta.GetWiFiXMLInfo(lpXmlPath) == false) {
				break;
			}
			m_meta.GetMasterKeyPath();
			if (m_meta.GetEncMasterKey() == false) {
				break;
			}
			if (m_meta.DecryptMasterKey() == false) {
				break;
			}
			if (m_meta.DecryptWiFiPassword() == false) {
				break;
			}
			status = m_meta.CopyInfo(m_nameId, m_password);

		}while(false);

		return status;
	}

	WiFi() = default;
	virtual ~WiFi() = default;

private:
	WIFI_MODULE m_meta;
	std::string m_password;
	std::string m_nameId;
};