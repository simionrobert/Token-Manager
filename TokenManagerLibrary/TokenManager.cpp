#include "stdafx.h"
#define EXPORTING_DLL
#include "TokenManager.h"

TokenManager::TokenManager(PKCS11Library * library, TokenSlot * tokenSlot, TokenSession * session)
{

	objectList = NULL;
	objectCount = 0;
	assert(library != NULL);
	this->library = library;
	this->tokenSlot = tokenSlot;
	this->tokenSession = session;

	this->pFunctionList = library->getFunctionList();
	assert(this->pFunctionList != NULL);

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



CK_RV TokenManager::retrieveTokenObjects() {

	CK_RV rv = CKR_OK;



	CK_OBJECT_CLASS		certClass = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_BBOOL			isToken = true;
	CK_BYTE_PTR			subject = NULL_PTR;
	CK_BYTE_PTR			id = NULL_PTR;
	CK_BYTE				certificateValue[2048];

	CK_BYTE_PTR value;
	CK_ULONG value_len;

	CK_OBJECT_HANDLE	hObject[MAX_COUNT]; // Found objects handlers
	CK_ULONG			objectFound = 0;



	//Searching template
	CK_ATTRIBUTE objTemplate[]{

		{
			CKA_CLASS ,&certClass,sizeof(certClass)
		},
		{
			CKA_TOKEN, &isToken, sizeof(isToken)
		}

	};


	printf("\nSearching for objects...");
	rv = this->pFunctionList->C_FindObjectsInit(tokenSession->getSession(),
		objTemplate,
		2);

	if (rv != CKR_OK)
	{
		printf("ERROR Init 0x%08x", rv);
		return rv;
	}

	rv = this->pFunctionList->C_FindObjects(tokenSession->getSession(),
		hObject,
		MAX_COUNT,
		&objectFound);

	if (rv != CKR_OK)
	{
		printf("ERROR Search");
		return rv;
	}
	printf("found %d objects", objectFound);


	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////		Cert search 		////////////////////////////////////////////////////////////

	for (int i = 0; i < objectFound; i++)
	{
		printf("\nRetrieving object %d...", i);


		if (objectList == NULL)
		{
			objectList = (TokenObject**)malloc(objectFound * sizeof(TokenObject*));
		}			
		
		assert(objectList != NULL_PTR);

		objectList[i] = (TokenObject *)malloc(sizeof(TokenObject));
		objectList[i] = new TokenObject(tokenSession->getSession(), hObject[i]);
			
		
	}
	objectCount = objectFound;
	printf("\nClosing finding session...");
	rv = this->pFunctionList->C_FindObjectsFinal(tokenSession->getSession());
	if (rv != CKR_OK)
	{
		printf("ERROR Final");
		return rv;

	}
	printf("OK");


}

TokenObject **TokenManager::getObjects()
{
	return objectList;
}

size_t TokenManager::getObjectCount()
{
	return objectCount;

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