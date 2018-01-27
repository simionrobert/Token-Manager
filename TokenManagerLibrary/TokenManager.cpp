#include "stdafx.h"
#define EXPORTING_DLL
#include "TokenManager.h"

TokenManager::TokenManager(PKCS11Library * library, TokenSlot * tokenSlot, TokenSession * session)
{
	this->library = library;
	this->tokenSlot = tokenSlot;
	this->tokenSession = session;
	this->pFunctionList = library->getFunctionList();
}


int TokenManager::formatToken()
{
	//return CKR_OK if ok; else return sth !=CKR_OK
	this->initializeToken("test");
	this->tokenSession->openSession();
	this->tokenSession->authentificateAsSO("test");
	this->initializePIN("test");
	return 1;
}

int TokenManager::changePINasUSER()
{
	//return CKR_OK if ok; else return sth !=CKR_OK
	this->tokenSession->openSession();
	this->tokenSession->authentificateAsUser("test");
	this->ChangePINAsUser("test","Test");
	return 1;
}

int TokenManager::changePINasSO()
{
	//return CKR_OK if ok; else return sth !=CKR_OK
	this->tokenSession->openSession();
	this->tokenSession->authentificateAsSO("test");
	this->ChangePINAsSO("test", "Test");
	return 1;
}

int TokenManager::unblockPIN()
{
	//return CKR_OK if ok; else return sth !=CKR_OK
	this->tokenSession->openSession();
	this->tokenSession->authentificateAsSO("test");
	this->initializePIN("test");
	return 1;
}

int TokenManager::initializeToken(char *p11PinCodeSO)
{
	CK_SLOT_ID_PTR pSlotList = tokenSlot->getSlotList();
	printf("\nInitializare token.......... ");
	int rv;
	char*label = "new TOKEN";
	char* PIN = "123qwe!@#QWE";
	USHORT pinLen = strlen(PIN);
	rv = pFunctionList->C_InitToken(pSlotList[0], (CK_CHAR_PTR)PIN, pinLen, (CK_UTF8CHAR_PTR)label);
	if (rv != CKR_OK)
	{
		printf(" EROARE (status = 0x%08X)", rv);
		return 0;
	}
	printf("	OK");
	return 1;
}

int TokenManager::initializePIN(char * NEWp11PinCode)
{
	//sa fiu logat ca so intai
	int rv;
	char* PIN = "123qwe!@#";
	printf("\nInitializare PIN dupa initializarea tokenului..........");
	USHORT pinLen = strlen(PIN);
	rv = pFunctionList->C_InitPIN(this->tokenSession->getSession(), (CK_CHAR_PTR)PIN, pinLen);
	if (rv != CKR_OK)
	{
		printf("EROARE  (status = 0x%08X)", rv);
		return 0;
	}
	printf("	OK");
	return 1;
}

int TokenManager::ChangePINAsUser(char * OLDp11PinCode, char * NEWp11PinCode)
{
	int rv;
	printf("\nSchimbare pin.............ca utilizator");
	char*PIN = "123qwe!@#QWE";
	char *newPIN = "1234567890";
	USHORT oldPinLen = strlen(PIN);


	USHORT newPinLen = strlen(newPIN);

	rv = (pFunctionList)->C_SetPIN(this->tokenSession->getSession(), (CK_CHAR_PTR)PIN, oldPinLen, (CK_CHAR_PTR)newPIN, newPinLen);
	if (rv != CKR_OK) {
		printf("EROARE la schibmare pin");
		return 0;
	}
	printf("OK");
	return 1;

}

int TokenManager::ChangePINAsSO(char * OLDp11PinCode, char * NEWp11PinCode)
{
	int rv;
	printf("\nSchimbare pin.............ca SO ");
	char*PIN = "123qwe!@#QWE";
	char *newPIN = "1234567890";
	USHORT oldPinLen = strlen(PIN);


	USHORT newPinLen = strlen(newPIN);

	rv = (pFunctionList)->C_SetPIN(this->tokenSession->getSession(), (CK_CHAR_PTR)PIN, oldPinLen, (CK_CHAR_PTR)newPIN, newPinLen);
	if (rv != CKR_OK) {
		printf("EROARE la schibmare pin");
		return 0;
	}
	printf("OK");
	return 1;
}