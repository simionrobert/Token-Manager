#ifndef PKCS11_LIB
#define PKCS11_LIB

#include "cryptoki.h"
#include "defined_tkn_mgr_header.h"


class TKN_API PKCS11Library {
private:
    HINSTANCE				hDll;

    CK_FUNCTION_LIST_PTR	pFunctionList;
    CK_C_GetFunctionList	pC_GetFunctionList ;

public:
	int incarcaLibrarie(char* numeLibrarie);
	int freeLibrarie();
	CK_FUNCTION_LIST_PTR getFunctionList();
};


#endif
