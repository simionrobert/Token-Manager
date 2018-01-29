#ifndef  TKN_SLOT
#define TKN_SLOT

#include "cryptoki.h"
#include "defined_tkn_mgr_header.h"
#include"PKCS11Library.h"

#include "cToken.h"

class TKN_API TokenSlot {

private:
	PKCS11Library*	library;
    CK_SLOT_ID_PTR	pSlotList ;
	CK_ULONG		ulSlotCount;

	cToken **tokens;
	size_t tokenCount;


public:
	TokenSlot(PKCS11Library* library);
	int asteaptaToken();
	int freeTokenSlot();

	CK_SLOT_ID_PTR getSlotList();



	cToken** getTokens();
	size_t getTokensCount();
};

#endif // ! TKN_SLOT
