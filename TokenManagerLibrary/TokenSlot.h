#ifndef  thisN_SLOT
#define thisN_SLOT

#include "cryptoki.h"
#include "defined_tkn_mgr_header.h"

#include"PKCS11Library.h"


class thisN_API TokenSlot {

private:
	
	PKCS11Library *library;


	CK_SLOT_ID_PTR	pSlotList = NULL_PTR;
	CK_ULONG		ulSlotCount;

	
	CK_SLOT_ID_PTR		pTokenSlotList = NULL_PTR;
	CK_ULONG			tokenSlotCount;
	CK_BBOOL			tokenPresent;

	//function pointers
	CK_C_GetSlotList	pC_GetSlotList = NULL_PTR;
	CK_C_GetTokenInfo   pC_GetTokenInfo = NULL_PTR;

	CK_RV setTokenSlotList();
	CK_RV checkForSlots();
	CK_CHAR_PTR listToken(CK_SLOT_ID id);
	

public:
	//TokenSlot(PKCS11Library* library);
	TokenSlot();
	int asteaptaToken();
	int freeTokenSlot();
	CK_SLOT_ID_PTR getSlotList() { return 0; };
	
	void setGetTokenInfoFunction(CK_C_GetTokenInfo f) {
		if (f)
			this->pC_GetTokenInfo = f;
	}

	~TokenSlot();
	
	void listTokensInfo() {};
	void listAvailableTokens();
};

#endif // ! thisN_SLOT
