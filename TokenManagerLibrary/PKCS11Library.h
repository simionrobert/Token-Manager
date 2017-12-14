#ifndef PKCS11_LIB
#define PKCS11_LIB

#include "cryptoki.h"
#include "defined_tkn_mgr_header.h"

#define MAX_COUNT 20

#define E_BASE 0x200
#define E_PKCS11_TEST_LIBRARY_NOT_FOUND E_BASE+1
#define E_PKCS11_TEST_CRYPTOKIFUNCTIONS E_BASE+2
#define E_PKCS11_TEST_NO_TOKENS_PRESENT E_BASE+3
#define E_PKCS11_TEST_ALLOC				E_BASE+4
#define E_PKCS11_TEST_NOT_FOUND			E_BASE+5
#define E_PKCS11_TEST_IO				E_BASE+6

class TKN_API PKCS11Library {
private:
	HINSTANCE				hDll;
	CK_FUNCTION_LIST_PTR	pFunctionList = NULL;
	CK_C_GetFunctionList	pC_GetFunctionList = NULL;

public:
	void incarcaLibrarie(char* numeLibrarie);
	void freeLibrarie();
	CK_FUNCTION_LIST_PTR getFunctionList();
};


#endif