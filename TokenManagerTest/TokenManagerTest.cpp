// TokenManagerTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "TokenManagerLibrary.h" 
#include "cToken.h"


int main()
{
	int rv;
	PKCS11Library*	library = new PKCS11Library(); //cryptoki library
	rv = library->incarcaLibrarie("eTPKCS11.dll");
	TokenSlot*		tokenSlot = new TokenSlot(library);
	TokenSession *	tokenSession = new TokenSession(library, tokenSlot);
	TokenManager*	tokenManager = new TokenManager(library, tokenSlot, tokenSession); //format/change pin


																					   //ServiceManager* serviceManager = new ServiceManager();
																					   //serviceManager->setServiceActivityStatus(false);


	tokenSlot->getSlotList();
	cToken **tokenList = tokenSlot->getTokens();

	for (int i = 0; i < tokenSlot->getTokensCount(); i++)
	{
		//printf("\nToken %d", i);
		//tokenList[i]->printInfo();
	}

	tokenSession->authentificateAsUser("123qwe!@#QWE",0);
	tokenManager->retrieveTokenObjects();
	//tokenManager->retrieveTokenObjects();
	ObjectCertificate**list = tokenManager->getCertificates();

	for (int i = 0; i < tokenManager->getCertificatesCount(); i++)
	{
		printf("\nObject:%d", i);

		printf("\Issuer:%s", list[i]->getIssuer());

	}
	//tokenManager->deleteCertificate(list[0]->getObjectId());
	
	

	ObjectPrivateKey **keyList = tokenManager->getKeys();
	ObjectSymmetricKey **symmetricKeyList = tokenManager->getSymmetricKeys();

	for (int i = 0; i < tokenManager->getKeysCount(); i++) {

		//printf("\nKey:%s Size:%s", keyList[i]->getLabel(), keyList[i]->getSize());

	}


	if (rv != 0)
		goto free;


	//tokenManager->getPFXfromFile("C:\\Users\\Baal\\Downloads\\Token\\Token\\cert.pfx","parola");


	/*
	while (1) {
		tokenManager->final();
	}
	*/












	//*************************************************************
	//
	//  setServiceActivityStatus()
	//
	//  Purpose:    Start/Stop Service
	//
	//  Parameters: status    -   Bool
	// 
	//  Set:	   TRUE to start functionality
	//             TRUE to stop functionality
	//
	//*************************************************************

	//ServiceManager* serviceManager = new ServiceManager();
	//serviceManager->setServiceActivityStatus(false);



	//*********************************************************
	// Manageriere registrii Windows 

	/*RegistryManager* manager = new RegistryManager();
	const unsigned char value[] = "1";
	TCHAR* valueRead = 0;
	DWORD valueReadLenght = 0;

	manager->createRegistryKey(HKEY_LOCAL_MACHINE, "Software\\Wow6432Node\\TokenManager\\SubKeyOne\\SubKeyTwo");
	manager->setRegistryValue(HKEY_LOCAL_MACHINE, "Software\\Wow6432Node\\TokenManager\\SubKeyOne\\SubKeyTwo","Service",value,sizeof(value));
	//manager->readValueFromRegistry(HKEY_LOCAL_MACHINE, "Software\\Wow6432Node\\TokenManager\\SubKeyOne\\SubKeyTwo", "Service", valueRead, valueReadLenght);
	//manager->deleteRegistryKey(HKEY_CURRENT_USER, "Software\\Wow6432Node\\TokenManager");



	//*********************************************************
	// Import cheie privata RSA format PKCS1/PKCS8 pe token

	/*
	int rv;
	PKCS11Library*	library = new PKCS11Library(); //cryptoki library
	rv = library->incarcaLibrarie("eTPKCS11.dll");
	TokenSlot*		tokenSlot = new TokenSlot(library);
	TokenSession *	tokenSession = new TokenSession(library, tokenSlot);
	TokenManager*	tokenManager = new TokenManager(library, tokenSlot, tokenSession); //format/change pin

	CK_SLOT_ID_PTR slots = tokenSlot->getSlotList();
	if(slots == NULL)
	goto free;*/

	//rv = tokenSession->openSession(0);
	//if (rv != 0)
	//	goto free;

	//rv = tokenSession->authentificateAsUser("123qwe!@#QWE");
	//if (rv != 0)
	//	goto free;

	//tokenManager->changePINasUSER();

	//TokenKey* keyManager = new TokenKey(library, tokenSession);
	//rv = keyManager->importKeyOnToken("C:\\Users\\Baal\\Documents\\Visual Studio 2017\\Projects\\TokenManager\\TokenManagerLibrary\\privateU.pem", "parola");
	//if (rv != 0)
	//	goto free;


	
free:
	tokenSession->closeSession();
	tokenSlot->freeTokenSlot();
	//library->freeLibrarie();
	return 0;
}