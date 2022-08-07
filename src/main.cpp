#include "wifi.h"


int main() {
	WIFI_PASSWORD obj;
	obj.GetSysKey(L"../test/SystemBkup.hiv");
	obj.GetLSAKeyAndSecrete(L"../test/SECURITY.hiv");
	obj.GetEncMasterKey(L"../test/b20d3049-84c5-47cd-98f2-7a9884d172c3");
	obj.DecryptMasterKey();
	return 0;
}
