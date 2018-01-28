#ifndef TKN_MANAGER
#define TKN_MANAGER

#include "cryptoki.h"
#include "defined_tkn_mgr_header.h"
#include "PKCS11Library.h"
#include "TokenSession.h"
#include "TokenObject.h"
/*
Pentru tudor
*/

class TKN_API TokenManager { 

private:
	// Put here only services which this class uses (maybe not all 3)
	PKCS11Library*	library;
	TokenSlot*		tokenSlot;
	TokenSession*	tokenSession;
	CK_FUNCTION_LIST_PTR pFunctionList;


	/*
	Certs
	*/

	TokenObject **objectList = NULL;
	size_t objectCount = 0;

public:
	TokenManager(PKCS11Library* library, TokenSlot* tokenSlot, TokenSession* session);

	int ChangePINAsUser(char *OLDp11PinCode, char *NEWp11PinCode);
	int ChangePINAsSO(char *OLDp11PinCode, char *NEWp11PinCode);
	int formatToken();
	int changePINasUSER();
	int changePINasSO();
	int unblockPIN();
	int initializeToken(char *p11PinCodeSO);
	int initializePIN(char *NEWp11PinCode);


	//////////////////////////////////////////////////////////////////////////
	///////////////////////////ded//////////////////////////////////////////

	CK_RV retrieveTokenObjects();
	TokenObject** getObjects();
	size_t getObjectCount();

};


#endif