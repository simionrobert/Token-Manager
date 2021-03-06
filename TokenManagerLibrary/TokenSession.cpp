#include "stdafx.h"
#define EXPORTING_DLL
#include "TokenSession.h"
#include "TokenSlot.h"


TokenSession::TokenSession(PKCS11Library * library, TokenSlot* tokenSlot)
{
	this->library = library;
	this->tokenSlot = tokenSlot;
	this->hSession = NULL;
}

int TokenSession::openSession(int tokenSlotNumber)
{
	if(hSession!=NULL){
		return hSession;
	}

	// deschid o sesiune PKCS11 de lucru cu tokenul (read-write)
	CK_RV rv;
	CK_FUNCTION_LIST_PTR pFunctionList = library->getFunctionList();
	CK_SLOT_ID_PTR pSlotList =  tokenSlot->getSlotList();

	if ((pSlotList == NULL ) || (pFunctionList == NULL))
		return CKR_DATA_INVALID;
	
	printf("\nDeschidere sesiune PKCS11 de lucru pe token.....");
	rv = pFunctionList->C_OpenSession(pSlotList[tokenSlotNumber], CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
	if (rv != CKR_OK)
	{
		printf("EROARE");
		return rv;
	}
	printf("OK");
	return rv;
}

int TokenSession::closeSession()
{
	if (hSession != -1) {
		CK_FUNCTION_LIST_PTR pFunctionList = library->getFunctionList();

		printf("\nInchidere sesiune PKCS#11.....");
		pFunctionList->C_Logout(hSession);
		pFunctionList->C_CloseSession(hSession);
		printf("OK");
		hSession = NULL;
	}

	return CKR_OK;
}

int TokenSession::authentificateAsUser(char *p11PinCode,int tokenNumber)
{

	CK_RV	rv;
	CK_FUNCTION_LIST_PTR pFunctionList = library->getFunctionList();

	if (hSession == NULL) {
		this->openSession(tokenNumber);
	}

	if (pFunctionList == NULL) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}


	printf("\nAutentificare.............");
	if (p11PinCode != NULL)
	{
		rv = (pFunctionList)->C_Login(hSession, CKU_USER, (CK_CHAR_PTR)p11PinCode, (USHORT)strlen(p11PinCode));
		if ((rv != CKR_OK) && (rv != CKR_USER_ALREADY_LOGGED_IN))
		{
			printf(" Eroare (0x%08X)",rv);
			return rv;
		}
		printf("OK");
		rv = CKR_OK;
		return rv;
	}

	return CKR_ARGUMENTS_BAD;
}

int TokenSession::authentificateAsSO(char *p11PinCode,int tokenNumber) {
	int rv;
	
	if (hSession == NULL) {
		this->openSession(tokenNumber);
	}
	CK_FUNCTION_LIST_PTR pFunctionList = library->getFunctionList();

	if (pFunctionList == NULL) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	printf("\nAutentificare.............ca SO ");
	
	
	USHORT pinLen = strlen(p11PinCode);

	rv = (pFunctionList)->C_Login(hSession, CKU_SO, (CK_CHAR_PTR)p11PinCode, pinLen);
	if (rv != CKR_OK && (rv != CKR_USER_ALREADY_LOGGED_IN)) {
		printf("  EROARE (0x%08X)");
		return 0;
	}
	printf("OK");
	return 1;
}

CK_SESSION_HANDLE TokenSession::getSession()
{
	return hSession;
}
