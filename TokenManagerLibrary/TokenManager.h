#ifndef TKN_MANAGER
#define TKN_MANAGER

#include "cryptoki.h"
#include "defined_tkn_mgr_header.h"

#include "PKCS11Library.h"
#include "TokenSlot.h"
#include "TokenSession.h"

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

public:
	TokenManager(PKCS11Library* library, TokenSlot* tokenSlot, TokenSession* session);

	int ChangePINAsUser(char *OLDp11PinCode, char *NEWp11PinCode);
	int ChangePINAsSO(char *OLDp11PinCode, char *NEWp11PinCode);
	int formatToken(char*,char*,char*);
	int changePINasUSER(char*,char*);
	int changePINasSO(char*,char*);
	int unblockPIN(char*,char*);
	int initializeToken(char *p11PinCodeSO,char* label);
	int initializePIN(char *NEWp11PinCode);
};


#endif