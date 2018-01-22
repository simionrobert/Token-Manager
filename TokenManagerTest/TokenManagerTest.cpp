// TokenManagerTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "TokenManagerLibrary.h" 



int main()
{
	PKCS11Library*	library = new PKCS11Library(); //cryptoki library
	TokenSlot*		tokenSlot = new TokenSlot(library); 
	TokenSession *	tokenSession = new TokenSession(library, tokenSlot);
	TokenManager*	tokenManager = new TokenManager(library, tokenSlot, tokenSession); //format/change pin

	int rv;

	rv =  library->incarcaLibrarie("eTPKCS11.dll");
	if (rv != 0)
		goto free;

	/*CK_SLOT_ID_PTR slots = tokenSlot->getSlotList();
	if(slots == NULL)
		goto free;*/

	rv = tokenSession->openSession();
	if (rv != 0)
		goto free;

	rv = tokenSession->authentificate("123qwe!@#QWE");
	if (rv != 0)
		goto free;


	TokenKey* keyManager = new TokenKey(library, tokenSession);
	rv = keyManager->importKeyOnToken("C:\\Users\\Baal\\Documents\\Visual Studio 2017\\Projects\\TokenManager\\TokenManagerLibrary\\privateU.pem","parola");
	if (rv != 0)
		goto free;
free: 	
	tokenSession->closeSession();
	tokenSlot->freeTokenSlot();
	library->freeLibrarie();
	getchar();
	
	return 0;
}