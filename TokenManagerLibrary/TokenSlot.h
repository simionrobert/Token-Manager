#ifndef  TKN_SLOT
#define TKN_SLOT

#include "cryptoki.h"
#include "defined_tkn_mgr_header.h"

#include"PKCS11Library.h"


class TKN_API TokenSlot {

private:
	PKCS11Library*	library;
	CK_SLOT_ID_PTR	pSlotList = NULL;
	CK_ULONG		ulSlotCount;




public:
	TokenSlot(PKCS11Library* library);
	int asteaptaToken();
	int freeTokenSlot();

	CK_SLOT_ID_PTR getSlotList();
};

#endif // ! TKN_SLOT
