#include "stdafx.h"
#define EXPORTING_DLL
#include"PKCS11Library.h"


void PKCS11Library::incarcaLibrarie(char * numeLibrarie)
{
	CK_RV rv;

	//incarcare librarie dinamica si obtin adresa functiei C_GetFunctionList (functie disponibila in DLL)
	printf("\nIncarcare DLL de PKCS#11.....");
	hDll = LoadLibrary(numeLibrarie);
	if (!hDll)
	{
		printf("EROARE");
		rv = E_PKCS11_TEST_LIBRARY_NOT_FOUND;

		return;
	}
	printf("OK");


	pC_GetFunctionList = (CK_C_GetFunctionList)GetProcAddress(hDll, "C_GetFunctionList");
	if (pC_GetFunctionList == NULL)
	{
		printf("\nEROARE adresare C_GetFunctionList");
		rv = E_PKCS11_TEST_CRYPTOKIFUNCTIONS;

		return;
	}


	// obtin adresele celorlalte functii din API -ul de p11
	printf("\nIncarcare lista de functii PKCS#11.....");
	rv = (*pC_GetFunctionList)(&pFunctionList);
	if (rv != CKR_OK)
	{
		printf("EROARE");
		return;
	}
	printf("OK");

	// initializare librarie pkcs11
	printf("\nInitializare biblioteca de PKCS#11.....");
	rv = pFunctionList->C_Initialize(NULL);
	if ((rv != CKR_OK) && (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED))
	{
		printf("EROARE");
		return;
	}
	printf("OK\n");
}

void PKCS11Library::freeLibrarie()
{
	printf("\nInchidere lucru cu biblioteca PKCS#11.....");
	pFunctionList->C_Finalize(NULL);
	pFunctionList = NULL;
	printf("OK");

	FreeLibrary(hDll);
	hDll = NULL;
}

CK_FUNCTION_LIST_PTR PKCS11Library::getFunctionList()
{
	if(this->pFunctionList != NULL)
		return this->pFunctionList;
	return NULL;
}

