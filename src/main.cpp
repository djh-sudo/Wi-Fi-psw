#include "wifi.h"


int main() {
	WIFI_PASSWORD obj;
	obj.GetSysKey(L"./test/SystemBkup.hiv");
	return 0;
}
