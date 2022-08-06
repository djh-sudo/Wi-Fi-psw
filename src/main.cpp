#include "wifi.h"


int main() {
	WIFI_PASSWORD obj;
	obj.GetSysKey(L"./test/SystemBkup.hiv");
	obj.GetLSAKeyAndSecrete(L"./test/SECURITY.hiv");
	
	return 0;
}
