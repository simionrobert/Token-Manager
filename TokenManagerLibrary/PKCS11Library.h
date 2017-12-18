#ifndef PKCS11_LIB
#define PKCS11_LIB

#include "stdafx.h"
#include "cryptoki.h"
#include "defined_tkn_mgr_header.h"


class TKN_API PKCS11Library {
private:

	HINSTANCE				static hDll;
	CK_FUNCTION_LIST_PTR	pFunctionList = NULL;
	CK_C_GetFunctionList	pC_GetFunctionList = NULL; 


	CK_RV init(char *p11Library);

	CK_RV loadLibrary(char *p11Library);

	CK_RV loadDllFunctions();

	CK_RV getDllFunctions();

	CK_RV initPKCS11Library();



public:
	int incarcaLibrarie(char* numeLibrarie);
	int freeLibrarie();
	CK_FUNCTION_LIST_PTR getFunctionList();



	//////////////////////////////////////////////////////////////////////////
	/////////////////////////////////ded//////////////////////////////////////
	

	//PKCS11Library();
	PKCS11Library(char *p11Library) {

		CK_RV rv = CKR_OK;
		printf("\n\tInitializing library...");
		rv = init(p11Library);
		if (!rv == CKR_OK)
		{
			printf("\n\tInitializing failed");
			delete this;
		}
		printf("\n\tInitializing succeeded...");
	}

	CK_FUNCTION_LIST_PTR getFunctions() {
		return this->pFunctionList;
	}
	CK_VOID_PTR static getFunction(LPCSTR functionName)
	{
		return GetProcAddress(hDll, functionName);

	}


};


#endif