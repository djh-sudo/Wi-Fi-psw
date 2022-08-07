#pragma once
#include <Windows.h>
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


BOOL ReadMasterKeyFile(IN LPCWSTR lpFileName, OUT LPBYTE* output, OUT LPDWORD szOutput);

BOOL MemoryVerify(IN LPVOID masterKey, IN DWORD szKey, IN LPVOID shaDerivedKey, IN DWORD szShaKey);