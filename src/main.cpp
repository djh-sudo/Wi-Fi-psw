#include <iostream>
#include "wifi.h"

/*
* To acquire SystemBkup.hiv file, excute cmd
* `reg save reg save HKLM\SYSTEM SystemBkup.hiv`
* To acquire SECURITY.hiv file, excute cmd
* `reg save HKLM\SECURITY SECURITY.hiv`
* Wifi info store at following folder:
* C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces
* Master key file store at Protectd folder:
* C:\Windows\System32\Microsoft\Protect\S-1-5-18\User
*/
int main() {
	WiFi obj;
	if (obj.Init(L"./test/SystemBkup.hiv", L"./test/SECURITY.hiv", L"./test/{4115A409-E5FB-411E-9B2F-25158202C04C}.xml")) {
		std::cout<<"WiFi Name:" << obj.GetNameId() << std::endl;
		std::cout << "WiFi Password:" << obj.GetPassword() << std::endl; 
	}
	system("pause");
	return 0;
}
