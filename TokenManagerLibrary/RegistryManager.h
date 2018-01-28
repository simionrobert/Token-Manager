#ifndef REGISTRY_MANAGER
#define REGISTRY_MANAGER

#include "defined_tkn_mgr_header.h"


class TKN_API RegistryManager {
private:
	HKEY openRegistryKey(HKEY hKeyRoot,const char* keyName);
	BOOL RegDelnodeRecurse(HKEY hKeyRoot, LPTSTR lpSubKey);
public:
	int readValueFromRegistry(HKEY hKeyRoot, const char* keyName, const char* valueName, TCHAR*& valueData, DWORD& valueLenght);
	int deleteRegistryKey(HKEY hKeyRoot, LPTSTR lpSubKey);
	int createRegistryKey(HKEY hKeyRoot, const char* keyName);
	int setRegistryValue(HKEY hKeyRoot, const char * keyName, char* valueName, const unsigned char* valueData, int valueDataLenght);
};


#endif