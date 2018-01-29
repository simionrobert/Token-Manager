#include "stdafx.h"
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
		
	manager->createRegistryKey(HKEY_LOCAL_MACHINE, "Software\\Wow6432Node\\TokenManager\\SubKeyOne\\SubKeyTwo");
	manager->setRegistryValue(HKEY_LOCAL_MACHINE, "Software\\Wow6432Node\\TokenManager\\SubKeyOne\\SubKeyTwo", "Service", value, sizeof(value));
}
