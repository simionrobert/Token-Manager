// TokenManagerTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "TokenManagerLibrary.h"


void test_simion()
{
	PKCS11Library*	library = new PKCS11Library("C:/Windows/System32/eTPKCS11.dll");
	TokenSlot*		tokenSlot = new TokenSlot(library);
	TokenSession *	tokenSession = new TokenSession(library, tokenSlot);
	TokenManager*	tokenManager = new TokenManager(library, tokenSlot, tokenSession);
	CK_SLOT_ID_PTR slots;
	int rv;

	rv = library->incarcaLibrarie("eTPKCS11.dll");
	if (rv != 0)
		goto free;

	slots = tokenSlot->getSlotList();
	if (slots == NULL)
		goto free;

	//tokenSlot->asteaptaToken();

	rv = tokenSession->openSession();
	if (rv != 0)
		goto free;

	rv = tokenSession->authentificate("1234");
	if (rv != 0)
		goto free;

free:
	tokenSession->closeSession();
	tokenSlot->freeTokenSlot();
	library->freeLibrarie();
	getchar();
}
	

//////////////////////////////////////////////////////////////////////////
/////////////////////////////////ded//////////////////////////////////////


PKCS11Library* test_init_library()
{
	PKCS11Library *lib = new PKCS11Library("C:/Windows/System32/eTPKCS11.dll");
	assert(lib != NULL && "\nInit test failed");
	return lib;
}



int main()
{
	CK_RV rv;
	PKCS11Library *lib = test_init_library();
	/*cSlotManager *sm = new cSlotManager();
	sm->listTokensInfo();
	cToken *tk = new cToken();
	tk->startSession();
	tk->login("123456");
	tk->listPubObjects();*/

free:
	lib->freeLibrarie();

}