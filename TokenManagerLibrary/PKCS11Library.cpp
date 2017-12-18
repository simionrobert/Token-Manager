#include "stdafx.h"
#define EXPORTING_DLL
#include"PKCS11Library.h"


CK_RV PKCS11Library::init(char * p11Library)
{
	CK_RV rv = CKR_OK;
	while (rv == CKR_OK) {

		rv = loadLibrary(p11Library);
		rv = loadDllFunctions();
		rv = getDllFunctions();
		rv = initPKCS11Library();
		break;

	}
	return rv;
}

int PKCS11Library::incarcaLibrarie(char* numeLibrarie)
{
	CK_RV rv;

	//incarcare librarie dinamica si obtin adresa functiei C_GetFunctionList (functie disponibila in DLL)
	printf("\nIncarcare DLL de PKCS#11.....");
	hDll = LoadLibrary(numeLibrarie);
	if (!hDll)
	{
		printf("EROARE");
		rv = E_PKCS11_TEST_LIBRARY_NOT_FOUND;

		return rv;
	}
	printf("OK");


	pC_GetFunctionList = (CK_C_GetFunctionList)GetProcAddress(hDll, "C_GetFunctionList");
	if (pC_GetFunctionList == NULL)
	{
		printf("\nEROARE adresare C_GetFunctionList");
		rv = E_PKCS11_TEST_CRYPTOKIFUNCTIONS;

		return rv;
	}


	// obtin adresele celorlalte functii din API -ul de p11
	printf("\nIncarcare lista de functii PKCS#11.....");
	rv = (*pC_GetFunctionList)(&pFunctionList);
	if (rv != CKR_OK)
	{
		printf("EROARE");
		return rv;
	}
	printf("OK");

	// initializare librarie pkcs11
	printf("\nInitializare biblioteca de PKCS#11.....");
	rv = pFunctionList->C_Initialize(NULL);
	if ((rv != CKR_OK) && (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED))
	{
		printf("EROARE");
		return rv;
	}
	printf("OK\n");

	return CKR_OK;
}

int PKCS11Library::freeLibrarie()
{
	printf("\nFinishing library work...");
	if (pFunctionList != NULL) {		
		pFunctionList->C_Finalize(NULL);
		pFunctionList = NULL;
		printf("OK");
	}
	

	if(hDll != NULL){
		FreeLibrary(hDll);
		hDll = NULL;
	}

	return CKR_OK;
}

CK_FUNCTION_LIST_PTR PKCS11Library::getFunctionList()
{
	if(this->pFunctionList != NULL)
		return this->pFunctionList;
	return NULL;
}

HINSTANCE PKCS11Library::hDll = NULL;

CK_RV PKCS11Library::loadLibrary(char *p11Library) {

	CK_RV rv = CKR_OK;

	//Loading pkcs11 library - TEST - safenet library
	printf("\nLoading pkcs11 library...");
	//pkcs11 library handler
	//C:/Windows/System32/eTPKCS11.dll

	hDll = LoadLibrary(p11Library);
	if (!hDll)
	{
		printf("ERROR");
		rv = ERR_PKCS11_DLL_NOT_FOUND;

	}
	printf("OK");
	return rv;
}

CK_RV PKCS11Library::loadDllFunctions()
{
	CK_RV rv = CKR_OK;
	//In order to use the functions from the specified dll
	//it is required to load the functions from the dll 
	// **** DO NOT USE THE FUNCTIONS DEFINED IN cryptoki.h ****

	pC_GetFunctionList = (CK_C_GetFunctionList)GetProcAddress(hDll, "C_GetFunctionList"); //this should return a pointer to the C_GetFunctionList
																						  //from the specified dll
	if (pC_GetFunctionList == NULL)
	{
		printf("\nERROR Fetching function list from dll");
		rv = ERR_CRYPTOKIFUNCTION_NOT_FOUND_IN_DLL;

	}
	return rv;
}

CK_RV PKCS11Library::getDllFunctions() {
	CK_RV rv = CKR_OK;
	//pC_GetFunctionList returns a list of the cryptoki functions from the specified dll

	printf("\nLoading PKCS11 functions...");
	rv = (*pC_GetFunctionList)(&pFunctionList);
	if (rv != CKR_OK) {
		printf("ERROR");
	}

	printf("OK");
	return rv;

}

CK_RV PKCS11Library::initPKCS11Library() {

	CK_RV rv = CKR_OK;
	printf("\nInitializing PKCS11 library...");
	rv = pFunctionList->C_Initialize(NULL); //passing NULL because the application does not support/use multi threads
	if (!rv == CKR_OK) {
		printf("ERROR");
		rv = ERR_LIBRARY_LOAD;
	}
	printf("OK");
	return rv;
}




