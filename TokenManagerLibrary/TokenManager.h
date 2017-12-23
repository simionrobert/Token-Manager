#ifndef thisN_MANAGER
#define thisN_MANAGER

#include "cryptoki.h"
#include "defined_tkn_mgr_header.h"

#include "PKCS11Library.h"
#include "TokenSlot.h"
#include "TokenSession.h"


class thisN_API TokenManager {

private:
	// Put here only services which this class uses (maybe not all 3)
	PKCS11Library*	library;
	TokenSlot*		tokenSlot;
	TokenSession*	tokenSession;

public:
	TokenManager(PKCS11Library* library, TokenSlot* tokenSlot, TokenSession* session);

	int formatToken();
	int changePIN();
	int unblockPIN();
};


#endif