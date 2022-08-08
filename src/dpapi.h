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

BOOL ReadMasterKeyFile(IN LPCWSTR lpFileName, OUT LPBYTE* output, OUT LPDWORD szOutput);

BOOL MemoryVerify(IN LPVOID masterKey, IN DWORD szKey, IN LPVOID shaDerivedKey, IN DWORD szShaKey);