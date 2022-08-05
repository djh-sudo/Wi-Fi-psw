#pragma once
#include <Windows.h>


#define HIVE_KEY_NAMED_FLAG_ROOT		0x0004
#define HIVE_KEY_NAMED_FLAG_LOCKED		0x0008
#define HIVE_KEY_NAMED_FLAG_ASCII_NAME	0x0020
#define HIVE_VALUE_KEY_FLAG_ASCII_NAME	0x0001

/*
* HIVE.h Created by djh in 2022-08-05
* About Register Analysis
* File Header steal from mimicatz almostly!
* Also See
* https://github.com/gentilkiwi/mimikatz
*/

/*
* Base Block, which size is 4096 bytes
*/
typedef struct _REGISTRY_HIVE_HEADER {
	/* Off[DEC]  Description */
	/* 000 */   DWORD tag;
	/* 004 */   DWORD seqPrime;
	/* 008 */   DWORD seqSecond;
	/* 012 */   FILETIME lastModification;
	/* 020 */   DWORD versionMajor;
	/* 024 */   DWORD versionMonor;
	/* 028 */   DWORD fileType;
	/* 032 */   DWORD fileFormat;
	/* 036 */   LONG offsetRootKey;
	/* 040 */   DWORD szData;
	/* 044 */   DWORD factorFactor;
	/* 048 */   BYTE fileName[64];
	/* 112 */   BYTE reserved[396];
	/* 508 */   DWORD checksum;
	/* 512 */   BYTE padding[3584];
}HIVE_HEADER, *P_HIVE_HEADER;

/*
* Key Node structure
*/
typedef struct _REGISTRY_HIVE_KEY_NAMED {
	/* Off[DEC] Description */
	/* 00 */  LONG szCell;
	/* 04 */  WORD tag;
	/* 06 */  WORD flags;
	/* 08 */  FILETIME lastModification;
	/* 16 */  DWORD AccBit;
	/* 20 */  DWORD offsetParentKey;
	/* 24 */  DWORD nbSubKeys;
	/* 28 */  DWORD nbVolatileSubKeys;
	/* 32 */  LONG offsetSubKeys;
	/* 36 */  LONG offsetVolatileSubkeys;
	/* 40 */  DWORD nbValues;
	/* 44 */  LONG offsetValues;
	/* 48 */  LONG offsetSecurityKey;
	/* 52 */  LONG offsetClassName;
	/* 56 */  DWORD szMaxSubKeyName;
	/* 60 */  DWORD szMaxSubKeyClassName;
	/* 64 */  DWORD szMaxValueName;
	/* 68 */  DWORD szMaxValueData;
	/* 72 */  DWORD workVar;
	/* 76 */  WORD szKeyName;
	/* 80 */  WORD szClassName;
	/* 84 */  BYTE keyName[ANYSIZE_ARRAY];
}HKEY_NAMED, *P_HKEY_NAMED;

/*
* HBIN Header structure, which size is 32 bytes
*/
typedef struct _REGISTRY_HIVE_BIN_HEADER {
	/* Off[DEC] Description */
	/* 00 */    DWORD tag;
	/* 04 */    LONG offsetHiveBin;
	/* 08 */    DWORD szHiveBin;
	/* 12 */    DWORD reserved0;
	/* 16 */    DWORD reserved1;
	/* 20 */    FILETIME timestamp;
	/* 28 */    DWORD reserved;
}HBIN_HEADER, *P_HBIN_HEADER;

/*
* CELL, which fills HBIN CELL.
* CELL size is adjustable
*/
typedef struct _REGISTRY_HIVE_BIN_CELL {
	/* Off[DEC] Description */
	/* 00 */    LONG szCell;
	union {
		WORD tag;
		BYTE data[ANYSIZE_ARRAY];
	};
}HBIN_CELL, *P_HBIN_CELL;

/*
* Fast Leaf / Hash Leaf elements
*/
typedef struct _REGISTRY_HIVE_LF_LH_ELEMENT {
	/* Off[DEC] Description */
	/* 00 */    LONG offsetNamedKey;
	/* 04 */    DWORD hash;
}HIVE_LF_LH_ELEMENT, *P_HIVE_LF_LH_ELEMENT;

/*
* Fast Leaf / Hash Leaf
*/
typedef struct _REGISTRY_HIVE_LF_LH {
	/* Off[DEC] Description */
	/* 00 */    LONG szCell;
	/* 04 */    WORD tag;
	/* 06 */    WORD nbElements;
	/* 08 */    HIVE_LF_LH_ELEMENT elements[ANYSIZE_ARRAY];
}HIVE_LF_LH, *P_HIVE_LF_LH;

/*
* Key Value structure
*/
typedef struct _REGISTRY_HIVE_VALUE_KEY{
	/* Off[DEC] Description */
	/* 00 */    LONG szCell;
	/* 04 */    WORD tag;
	/* 06 */    WORD szValueName;
	/* 08 */    DWORD szData;
	/* 12 */    LONG offsetData;
	/* 16 */    DWORD typeData;
	/* 20 */    WORD flags;
	/* 22 */    WORD padding;
	/* 24 */    BYTE valueName[ANYSIZE_ARRAY];
}HIVE_VALUE_KEY, *P_HIVE_VALUE_KEY;

/*
* value list
*/
typedef struct _REGISTRY_HIVE_VALUE_LIST {
	LONG szCell;
	LONG offsetValue[ANYSIZE_ARRAY];
}HIVE_VALUE_LIST, *P_HIVE_VALUE_LIST;

/*
* HIVE Handle
*/
typedef struct _REGISTRY_HIVE_HANDLE {
	HANDLE hFileMapping;
	LPVOID pMapVirewOfFile;
	PBYTE pStartOf;
	HKEY_NAMED* pRootNamedKey;
}HIVE_HANDLE, *P_HIVE_HANDLE;

/*
* Base Function (utils)
*/
wchar_t * String2Unicode(const char *ansi, size_t szStr);

/*
* Function related HIVE
*/
BOOL OpenRegistry(IN const HANDLE HAny, OUT P_HIVE_HANDLE *hRegistry);

BOOL GetCurrentControlSet(IN P_HIVE_HANDLE hRegistry, PHKEY phCurrentControlSet);

BOOL OpenRegistryKey(IN P_HIVE_HANDLE hRegistry,
	                 IN HKEY hKey,
	                 IN OPTIONAL LPCWSTR lpSubKey,
	                 IN DWORD options, 
	                 IN REGSAM samDesired,
	                 OUT PHKEY phkResult);

P_HKEY_NAMED SearchKey(IN P_HIVE_HANDLE hRegistry, IN P_HBIN_CELL pHbC, IN LPCWSTR lpSubKey);

BOOL QueryValue(IN P_HIVE_HANDLE hRegistry, 
	            IN HKEY hKey,
	            IN OPTIONAL LPCWSTR lpValueName,
	            IN LPDWORD lpReserved,
	            OUT OPTIONAL LPDWORD lpType,
	            OUT OPTIONAL LPBYTE lpData,
	            IN OUT OPTIONAL LPDWORD lpcbData);


P_HIVE_VALUE_KEY SearchValue(IN P_HIVE_HANDLE hRegistry, IN HKEY hKey, IN OPTIONAL LPCWSTR lpValueName);

