#include "stdafx.h"
#define EXPORTING_DLL
#include "TokenSession.h"


TokenSession::TokenSession(PKCS11Library * library, TokenSlot* tokenSlot)
{
	this->library = library;
	this->tokenSlot = tokenSlot;

}

int TokenSession::openSession()
{
	// deschid o sesiune PKCS11 de lucru cu tokenul (read-write)
	CK_RV rv;
	CK_FUNCTION_LIST_PTR pFunctionList = library->getFunctionList();
	CK_SLOT_ID_PTR pSlotList =  tokenSlot->getSlotList();

	if ((pSlotList == NULL ) || (pFunctionList == NULL))
		return CKR_DATA_INVALID;
	
	printf("\nDeschidere sesiune PKCS11 de lucru pe token.....");
	rv = pFunctionList->C_OpenSession(pSlotList[0], CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
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
	}

	return CKR_OK;
}

int TokenSession::authentificate(char *p11PinCode)
{
	// loghez sesiunea(dau codul PIN)
	CK_RV	rv;
	CK_FUNCTION_LIST_PTR pFunctionList = library->getFunctionList();

	if (pFunctionList == NULL) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}


	printf("\nAutentificare.............");
	if (p11PinCode != NULL)
	{
		rv = (pFunctionList)->C_Login(hSession, CKU_USER, (CK_CHAR_PTR)p11PinCode, (USHORT)strlen(p11PinCode));
		if ((rv != CKR_OK) && (rv != CKR_USER_ALREADY_LOGGED_IN))
		{
			printf("Eroare");
			return rv;
		}
		printf("OK");
		rv = CKR_OK;
		return rv;
	}

	return CKR_ARGUMENTS_BAD;
}

CK_SESSION_HANDLE TokenSession::getSession()
{
	return hSession;
}
