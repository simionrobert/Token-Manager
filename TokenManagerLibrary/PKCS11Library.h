#ifndef PKCS11_LIB
#define PKCS11_LIB

#include "defined_tkn_mgr_header.h"
#include "cryptoki.h"



class TKN_API PKCS11Library {
private:

	HINSTANCE static		hDll;
	CK_FUNCTION_LIST_PTR	pFunctionList = NULL;
	CK_C_GetFunctionList	pC_GetFunctionList = NULL; 

public:

	int incarcaLibrarie(char* numeLibrarie);
	int freeLibrarie();
	CK_FUNCTION_LIST_PTR getFunctionList();
	CK_VOID_PTR static getFunction(LPCSTR functionName);
	
};


#endif