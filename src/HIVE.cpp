#include <cstdio>
#include "HIVE.h"


wchar_t * String2Unicode(const char *ansi, size_t szStr) {
	wchar_t *buffer = NULL;
	if (ansi && szStr) {
		buffer = new wchar_t[(szStr + 1)];
		memset(buffer, 0, (szStr + 1) * sizeof(wchar_t));
		if (buffer) {
			for (size_t i = 0; i < szStr; ++i) {
				buffer[i] = ansi[i];
			}
		}
	}
	return  buffer;
}

BOOL OpenRegistry(IN const HANDLE HAny, OUT P_HIVE_HANDLE *hRegistry) {
	P_HIVE_HEADER pFilehdead;
	P_HBIN_HEADER pBinHead;
	BOOL status = FALSE;
	do {
		*hRegistry = (P_HIVE_HANDLE)new BYTE[sizeof(HIVE_HANDLE)];
		if (!(*hRegistry)) {
			break;
		}

		(*hRegistry)->hFileMapping = CreateFileMappingW(HAny, NULL, PAGE_READONLY, 0, 0, NULL);
		if (!((*hRegistry)->hFileMapping)) {
			CloseHandle((*hRegistry)->hFileMapping);
			break;
		}

		(*hRegistry)->pMapVirewOfFile = MapViewOfFile((*hRegistry)->hFileMapping, FILE_MAP_READ, 0, 0, 0);
		pFilehdead = (P_HIVE_HEADER)(*hRegistry)->pMapVirewOfFile;
		if (pFilehdead) {
			if ((pFilehdead->tag == 'fger') && (pFilehdead->fileType == 0)) {
				pBinHead = (P_HBIN_HEADER)((PBYTE)pFilehdead + sizeof(HIVE_HEADER));
				(*hRegistry)->pStartOf = (PBYTE) pBinHead;
				(*hRegistry)->pRootNamedKey = (P_HKEY_NAMED)((PBYTE)pBinHead + sizeof(HBIN_HEADER) + pBinHead->offsetHiveBin);
				status = ((*hRegistry)->pRootNamedKey->tag == 'kn' && 
					     ((*hRegistry)->pRootNamedKey->flags & 
					     (HIVE_KEY_NAMED_FLAG_ROOT | HIVE_KEY_NAMED_FLAG_LOCKED)));
			}
		}

		if (status == FALSE) {
			UnmapViewOfFile((*hRegistry)->pMapVirewOfFile);
			CloseHandle((*hRegistry)->hFileMapping);
		}
		
	}while(FALSE);

	if (status == FALSE) {
		delete[] (*hRegistry);
	}

	return status;
}

BOOL GetCurrentControlSet(IN P_HIVE_HANDLE hRegistry, PHKEY phCurrentControlSet) {
	wchar_t currentControlSet[] = L"ControlSet000";
	const wchar_t * CONTROLSET_SOURCES[] = {L"Current", L"Default"};

	BOOL status = FALSE;
	HKEY hSelect;
	DWORD szNeeded = sizeof(DWORD), controlSet; 
	if (OpenRegistryKey(hRegistry, NULL, L"Select", 0, KEY_READ, &hSelect)) {
		for (DWORD i = 0; !status && (i < ARRAYSIZE(CONTROLSET_SOURCES)); ++i) {
			szNeeded = sizeof(DWORD);
			status = QueryValue(hRegistry, hSelect, CONTROLSET_SOURCES[i], NULL, NULL, (LPBYTE) &controlSet, &szNeeded);
		}
		if (status) {
			status = FALSE;
			if (swprintf(currentControlSet + 10, 4, L"%03u", controlSet) != -1) {
				status = OpenRegistryKey(hRegistry, NULL, currentControlSet, 0, KEY_READ, phCurrentControlSet);
			}
		}
	}
	return status;
}

BOOL OpenRegistryKey(IN P_HIVE_HANDLE hRegistry,
	                 IN HKEY hKey,
	                 IN OPTIONAL const LPCWSTR lpSubKey,
	                 IN DWORD options,
	                 IN REGSAM samDesired,
	                 OUT PHKEY phkResult) {
	BOOL status = FALSE;
	P_HKEY_NAMED pKeyNamed = hKey ? (P_HKEY_NAMED)hKey : hRegistry->pRootNamedKey;
	P_HBIN_CELL pHiveBinCell = NULL;
	*phkResult = 0;
	wchar_t *ptrF, *buffer;
	do {
		if (pKeyNamed->tag != 'kn') {
			break;
		}
		if (lpSubKey == NULL) {
			*phkResult = (HKEY) pKeyNamed;
			break;
		}
		if (!pKeyNamed->nbSubKeys || (pKeyNamed->offsetSubKeys == -1)) {
			break;
		}

		pHiveBinCell = (P_HBIN_CELL)(hRegistry->pStartOf + pKeyNamed->offsetSubKeys);
		ptrF = (wchar_t *)wcschr(lpSubKey, L'\\');
		if (!ptrF) {
			*phkResult = (HKEY)SearchKey(hRegistry, pHiveBinCell, lpSubKey);
			break;
		}
		buffer = new wchar_t[(ptrF - lpSubKey + 1)];
		if (!buffer) {
			break;
		}
		memset(buffer, 0, (ptrF - lpSubKey + 1) * sizeof(wchar_t));
		memcpy(buffer, lpSubKey, (ptrF - lpSubKey) * sizeof(wchar_t));
		*phkResult = (HKEY)SearchKey(hRegistry, pHiveBinCell, buffer);
		if (*phkResult) {
			OpenRegistryKey(hRegistry, *phkResult, ptrF + 1, options, samDesired, phkResult);
		}
		delete[] buffer;

	} while (FALSE);

	status = (*phkResult != 0);
	return status;
}

P_HKEY_NAMED SearchKey(IN P_HIVE_HANDLE hRegistry, IN P_HBIN_CELL pHbC, IN LPCWSTR lpSubKey) {
	BOOL status = FALSE;
	P_HKEY_NAMED pKn, result = NULL;
	
	wchar_t * buffer = NULL;
	if (pHbC->tag != 'fl' && pHbC->tag != 'hl') {
		return result;
	}

	P_HIVE_LF_LH pLfLh = (P_HIVE_LF_LH)pHbC;
	for (DWORD i = 0; i < pLfLh->nbElements && !result; ++i) {
		pKn = P_HKEY_NAMED(hRegistry->pStartOf + pLfLh->elements[i].offsetNamedKey);
		if (pKn->tag == 'kn') {
			if (pKn->flags & HIVE_KEY_NAMED_FLAG_ASCII_NAME) {
				buffer = String2Unicode((char *) pKn->keyName, pKn->szKeyName);
			}
			else if(buffer = new wchar_t[pKn->szKeyName + sizeof(wchar_t)]){
				memset(pKn->keyName, 0, pKn->szKeyName);
				memcpy(buffer, pKn->keyName, pKn->szKeyName);
			}

			if (buffer) {
				if(wcsicmp(lpSubKey, buffer) == 0) result = pKn;
				
				delete[] buffer;
			}
		}
	}
	return result;
}

P_HIVE_VALUE_KEY SearchValue(IN P_HIVE_HANDLE hRegistry, IN HKEY hKey, IN OPTIONAL LPCWSTR lpValueName) {
	P_HKEY_NAMED pKn;
	P_HIVE_VALUE_LIST pVl;
	P_HIVE_VALUE_KEY pVk, pFvk = NULL;
	wchar_t * buffer;

	pKn = (P_HKEY_NAMED) hKey;
	do {
		if (pKn->tag != 'kn') {
			break;
		}
		if (!pKn->nbValues || pKn->offsetValues == -1) {
			break;
		}

		pVl = (P_HIVE_VALUE_LIST)(hRegistry->pStartOf + pKn->offsetValues);
		for (DWORD i = 0; i < pKn->nbValues && !pFvk; ++i) {
			pVk =  (P_HIVE_VALUE_KEY)(hRegistry->pStartOf + pVl->offsetValue[i]);
			if (pVk->tag != 'kv')  continue;
			if (lpValueName) {
				if(!pVk->szValueName) continue;
				if (pVk->flags & HIVE_VALUE_KEY_FLAG_ASCII_NAME) {
					buffer = String2Unicode((char *) pVk->valueName, pVk->szValueName);
				}
				else if (buffer = new wchar_t[pVk->szValueName + sizeof(wchar_t)]) {
					memcpy(buffer, pVk->valueName, pVk->szValueName);
				}

				if (buffer) {
					if (wcscmp(lpValueName, buffer) == 0){
						pFvk = pVk;
					}
					delete[] buffer;
				}
			}
			else if (!pVk->szValueName) {
				pFvk = pVk;
			}
		}
	}while(FALSE);
	
	return pFvk;
}

BOOL QueryValue(IN P_HIVE_HANDLE hRegistry,
	            IN HKEY hKey,
	            IN OPTIONAL LPCWSTR lpValueName,
	            IN LPDWORD lpReserved,
	            OUT OPTIONAL LPDWORD lpType,
	            OUT OPTIONAL LPBYTE lpData,
	            IN OUT OPTIONAL LPDWORD lpcbData) {
	BOOL status = FALSE;
	DWORD szData;
	PVOID dataLoc;
	P_HIVE_VALUE_KEY pFvk = SearchValue(hRegistry, hKey, lpValueName);
	status = (pFvk != NULL);
	do {
		if (status == FALSE) {
			break;
		}
		szData = pFvk->szData & (~0x80000000);
		if (lpType) {
			*lpType = pFvk->typeData;
		}
		if (!lpcbData) {
			break;
		}
		if (lpData) {
			status = (*lpcbData >= szData);
			if (status) {
				dataLoc = (pFvk->szData & 0x80000000) ? &pFvk->offsetData : (PVOID) &(((P_HBIN_CELL) (hRegistry->pStartOf + pFvk->offsetData))->data);
				memcpy(lpData, dataLoc, szData);
			}
		}
		*lpcbData = szData;

	}while(FALSE);
	return status;
}

BOOL QueryInfoKey(IN P_HIVE_HANDLE hRegistry,
	              IN HKEY hKey,
	              OUT OPTIONAL LPWSTR lpClass,
	              IN OUT OPTIONAL LPDWORD lpcClass,
	              IN OPTIONAL LPDWORD lpReserved,
	              OUT OPTIONAL LPDWORD lpcSubKeys,
	              OUT OPTIONAL LPDWORD lpcMaxSubKeyLen) {
	
	BOOL status = FALSE;
	P_HKEY_NAMED pKn;
	DWORD szInCar;
	pKn = hKey ? (P_HKEY_NAMED) hKey : hRegistry->pRootNamedKey;
	do {
		status = (pKn->tag == 'kn');
		if (status == FALSE) {
			break;
		}

		if(lpcSubKeys)
			*lpcSubKeys = pKn->nbSubKeys;

		if(lpcMaxSubKeyLen)
			*lpcMaxSubKeyLen = pKn->szMaxSubKeyName / sizeof(wchar_t);

		if (!lpcClass) {
			break;
		}
		szInCar = pKn->szClassName / sizeof(wchar_t);
		if (!lpClass) {
			*lpcClass = szInCar;
			break;
		}
		status = (*lpcClass > szInCar);
		if (status == FALSE) {
			*lpcClass = szInCar;
			break;
		}

		memcpy(lpClass, &((P_HBIN_CELL) (hRegistry->pStartOf + pKn->offsetClassName))->data , pKn->szClassName);
		lpClass[szInCar] = L'\0';
		*lpcClass = szInCar;
	}while(FALSE);

	return status;
}

BOOL GetLSASyskey(IN P_HIVE_HANDLE hRegistry, HKEY hLSA, LPBYTE sysKey) {
	const wchar_t * SYSKEY_NAMES[] = {L"JD", L"Skew1", L"GBG", L"Data"};
	const BYTE SYSKEY_PERMUT[] = {11, 6, 7, 1, 8, 10, 14, 0, 3, 5, 2, 15, 13, 9, 12, 4};
	
	BOOL status = TRUE;
	BYTE buffKey[SYSKEY_LENGTH] = { 0 };
	wchar_t buffer[8 + 1] = { 0 };
	DWORD szBuffer = 9;

	HKEY hKey;
	
	for (DWORD i = 0; i < ARRAYSIZE(SYSKEY_NAMES) && status; ++i) {
		status = FALSE;
		if (OpenRegistryKey(hRegistry, hLSA, SYSKEY_NAMES[i], 0, KEY_READ, &hKey)) {
			szBuffer = 8 + 1;
			if (QueryInfoKey(hRegistry, hKey, buffer, &szBuffer, NULL, NULL, NULL)) {
				status = (swscanf(buffer, L"%x", (DWORD *) &buffKey[i * sizeof(DWORD)]) != -1);
			}
		}
		else {
			break;
		}
	}
	
	if (status) {
		for (DWORD i = 0; i < SYSKEY_LENGTH; ++i) {
			sysKey[i] = buffKey[SYSKEY_PERMUT[i]];
		}
	}

	return status;			
}

BOOL QueryWithAlloc(IN P_HIVE_HANDLE hRegistry,
	                IN HKEY hKey,
	                IN OPTIONAL LPCWSTR lpValueName,
	                OUT OPTIONAL LPDWORD lpType,
	                OUT OPTIONAL LPVOID *lpData,
	                IN OUT OPTIONAL LPDWORD lpcbData) {
	BOOL status = FALSE;
	DWORD szNeeded  = 0;
	if (QueryValue(hRegistry, hKey, lpValueName, NULL, lpType, NULL, &szNeeded)) {
		do {
			if (!szNeeded) {
				break;
			}
			*lpData = new BYTE[szNeeded];
			if (*lpData == NULL) {
				break;
			}
			memset(*lpData, 0, szNeeded);
			status = QueryValue(hRegistry, hKey, lpValueName, NULL, lpType,  (LPBYTE) *lpData, &szNeeded);
			if (status == FALSE) {
				delete[] (*lpData);
				*lpData = NULL;
				break;
			}
			if (!lpcbData) {
				break;
			}
			*lpcbData = szNeeded;

		}while(FALSE);
	}

	return status;
}

BOOL OpenAndQueryWithAlloc(IN P_HIVE_HANDLE hRegistry,
	                       IN HKEY hKey,
	                       IN OPTIONAL LPCWSTR lpSubKey,
	                       IN OPTIONAL LPCWSTR lpValueName,
	                       OUT OPTIONAL LPDWORD lpType,
	                       OUT OPTIONAL LPVOID *lpData,
	                       IN OUT OPTIONAL LPDWORD lpcbData){
	BOOL status = FALSE;
	HKEY hResult;
	if (OpenRegistryKey(hRegistry, hKey, lpSubKey, 0, KEY_READ, &hResult)) {
		status = QueryWithAlloc(hRegistry, hResult, lpValueName, lpType, lpData, lpcbData);
	}
	return status;
}

BOOL GetRegistryEnumKey(IN P_HIVE_HANDLE hRegistry,
	                    IN HKEY hKey,
	                    IN DWORD dwIndex,
	                    OUT LPWSTR lpName,
	                    IN OUT LPDWORD lpcName,
	                    IN LPDWORD lpReserved,
	                    OUT OPTIONAL LPWSTR lpClass,
	                    IN OUT OPTIONAL LPDWORD lpcClass) {

	BOOL status = FALSE;
	DWORD szInCar = 0;
	P_HKEY_NAMED pKn = NULL, pCandidateKn = NULL;
	P_HBIN_CELL pHbC = NULL;
	P_HIVE_LF_LH pLfLh = NULL;
	wchar_t * buffer = NULL;

	pKn = (P_HKEY_NAMED) hKey;
	do {
		if (!pKn->nbSubKeys || (dwIndex >= pKn->nbSubKeys) || (pKn->offsetSubKeys == -1)) {
			break;
		}
		pHbC = (P_HBIN_CELL)(hRegistry->pStartOf + pKn->offsetSubKeys);
		if (pHbC->tag != 'fl' && pHbC->tag != 'hl') {
			break;
		}
		pLfLh = (P_HIVE_LF_LH)pHbC;
		if (!pLfLh->nbElements || (dwIndex >= pLfLh->nbElements)) {
			break;
		}
		pCandidateKn = (P_HKEY_NAMED)(hRegistry->pStartOf + pLfLh->elements[dwIndex].offsetNamedKey);
		do {
			if (pCandidateKn->flags & HIVE_KEY_NAMED_FLAG_ASCII_NAME) {
				szInCar = pCandidateKn->szKeyName;
				status = (*lpcName > szInCar);
				if (status == FALSE) {
					break;
				}
				buffer = String2Unicode((char *)pCandidateKn->keyName,szInCar);
				if (buffer == NULL) {
					break;
				}
				memcpy(lpName, buffer, szInCar * sizeof(wchar_t));
				delete[] buffer;
			}
			else {
				szInCar = pCandidateKn->szClassName / sizeof(wchar_t);
				status = (*lpcName > szInCar);
				if (status == FALSE) {
					break;
				}
				memcpy(lpName, pCandidateKn->keyName, pKn->szKeyName);
			}
		}while(FALSE);

		if(status)
			lpName[szInCar] = L'\0';
		*lpcName = szInCar;

		if (lpcClass){
			szInCar = pCandidateKn->szClassName / sizeof(wchar_t);
			if(lpClass)
			{
				if(status = (*lpcClass > szInCar))
				{
					memcpy(lpClass, &((P_HBIN_CELL) (hRegistry->pStartOf + pCandidateKn->offsetClassName))->data , pCandidateKn->szClassName);
					lpClass[szInCar] = L'\0';
				}
			}
			*lpcClass = szInCar;
		}
		
	}while(FALSE);
	return status;
}

