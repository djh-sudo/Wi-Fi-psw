#include <iostream>
#include "WiFiAnalyse.h"


int main() {
	WiFi obj;
	if (obj.Init(L"./test/{4115A409-E5FB-411E-9B2F-25158202C04C}.xml")) {
		std::cout<<"WiFi Name:" << obj.GetNameId() << std::endl;
		std::cout << "WiFi Password:" << obj.GetPassword() << std::endl; 
	}
	system("pause");
	return 0;
}