#include "stdafx.h"
#define EXPORTING_DLL
#include "TokenManager.h"

TokenManager::TokenManager(PKCS11Library * library, TokenSlot * tokenSlot, TokenSession * session)
{
	this->library = library;
	this->tokenSlot = tokenSlot;
	this->tokenSession = session;
}


int TokenManager::formatToken(char*PINSO,char* label,char* newPIN)
{
	//return CKR_OK if ok; else return sth !=CKR_OK
	this->initializeToken(PINSO,label);
	this->tokenSession->openSession();
	this->tokenSession->authentificateAsSO(PINSO);
	this->initializePIN(newPIN);
	return 1;
}

int TokenManager::changePINasUSER(char* oldPin,char* newPin)
{
	//return CKR_OK if ok; else return sth !=CKR_OK
	this->tokenSession->openSession();
	this->tokenSession->authentificateAsUser(oldPin);
	this->ChangePINAsUser(oldPin, newPin);
	return 1;
}

int TokenManager::changePINasSO(char* oldPINSO,char* newPINSO)
{
	//return CKR_OK if ok; else return sth !=CKR_OK
	this->tokenSession->openSession();
	this->tokenSession->authentificateAsSO(oldPINSO);
	this->ChangePINAsSO(oldPINSO, newPINSO);
	return 1;
}

int TokenManager::unblockPIN(char* PINSO,char* newPIN)
{
	//return CKR_OK if ok; else return sth !=CKR_OK
	this->tokenSession->openSession();
	this->tokenSession->authentificateAsSO(PINSO);
	this->initializePIN(newPIN);
	return 1;
}

int TokenManager::initializeToken(char *p11PinCodeSO,char* label)
{
	CK_SLOT_ID_PTR pSlotList = tokenSlot->getSlotList();
	USHORT pinLen = strlen(p11PinCodeSO);
	printf("\nInitializare token.......... ");
	int rv;
	rv = this->library->getFunctionList()->C_InitToken(pSlotList[0], (CK_CHAR_PTR)p11PinCodeSO, pinLen, (CK_UTF8CHAR_PTR)label);
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
	printf("\nInitializare PIN dupa initializarea tokenului..........");
	USHORT pinLen = strlen(NEWp11PinCode);
	rv = this->library->getFunctionList()->C_InitPIN(this->tokenSession->getSession(), (CK_CHAR_PTR)NEWp11PinCode, pinLen);
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
	printf("\nSchimbare pin.............ca utilizator ");
	USHORT oldPinLen = strlen(OLDp11PinCode);
	USHORT newPinLen = strlen(NEWp11PinCode);

	rv = this->library->getFunctionList()->C_SetPIN(this->tokenSession->getSession(), (CK_CHAR_PTR)OLDp11PinCode, oldPinLen, (CK_CHAR_PTR)NEWp11PinCode, newPinLen);
	if (rv != CKR_OK) {
		printf("EROARE la schibmare pin (0x%08X)", rv);
		return 0;
	}
	printf("OK");
	return 1;

}

int TokenManager::ChangePINAsSO(char * OLDp11PinCode, char * NEWp11PinCode)
{
	int rv;
	printf("\nSchimbare pin.............ca SO ");
	USHORT oldPinLen = strlen(OLDp11PinCode);
	USHORT newPinLen = strlen(NEWp11PinCode);
	
	rv = this->library->getFunctionList()->C_SetPIN(this->tokenSession->getSession(), (CK_CHAR_PTR)OLDp11PinCode, oldPinLen, (CK_CHAR_PTR)NEWp11PinCode, newPinLen);
	if (rv != CKR_OK) {
		printf("EROARE la schibmare pin (0x%08X)", rv);
		return 0;
	}
	printf("OK");
	return 1;
}