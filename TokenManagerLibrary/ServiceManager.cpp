#include "stdafx.h"
#define EXPORTING_DLL
#include "ServiceManager.h"
#include "RegistryManager.h"

void ServiceManager::setServiceActivityStatus(bool status)
{
	RegistryManager* manager = new RegistryManager();
	unsigned char value[2];

	if (status == true) {
		value[0] = '1';
		value[1] = '\0';
	}
	else {
		value[0] = '0';
		value[1] = '\0';
	}
		
	manager->createRegistryKey(HKEY_LOCAL_MACHINE, "Software\\TokenManager");
	manager->setRegistryValue(HKEY_LOCAL_MACHINE, "Software\\TokenManager", "Service", value, sizeof(value));
}
