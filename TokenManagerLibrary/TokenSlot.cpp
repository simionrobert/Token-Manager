#include "stdafx.h"
#define EXPORTING_DLL
#include "TokenSlot.h"
#include "cryptoki.h"

TokenSlot::TokenSlot(PKCS11Library* library)
{
	tokens = NULL;
	tokenCount = -1;
	this->library = library;
	this->TokenSlotNumber = 0;
}

int TokenSlot::asteaptaToken()
{
	CK_RV	rv;
		CK_FLAGS flags = 0;
		CK_SLOT_ID slotID;
		CK_SLOT_INFO slotInfo;
		CK_FUNCTION_LIST_PTR	pFunctionList = library->getFunctionList();

		if (pFunctionList == NULL) {
			return CKR_CRYPTOKI_NOT_INITIALIZED;
		}

		while (1)
		{
			rv = pFunctionList->C_WaitForSlotEvent(NULL, &slotID, NULL_PTR);
			if (rv == CKR_OK)
			{
				rv = pFunctionList->C_GetSlotInfo(slotID, &slotInfo);
				if (slotInfo.flags & CKF_TOKEN_PRESENT)
				{
					printf("BAGA\n");
					printf((char*)slotInfo.manufacturerID);
					//cautaObiecte(slotID);
				}
				else
				{
					printf("SCOATE");
				}

			}
			printf("\n");
		}

}

int TokenSlot::freeTokenSlot()
{
	if (pSlotList != NULL)
	{
		free(pSlotList);
		pSlotList = NULL;
	}

	return CKR_OK;
}

void TokenSlot::set_tokenSlotNumber(int slot)
{
	this->TokenSlotNumber = slot;
}

int TokenSlot::get_token_slot_selected()
{
	if (this->TokenSlotNumber == -1) {
		return 0;
	}
	else {
		return this->TokenSlotNumber;
	}
}

CK_SLOT_ID_PTR TokenSlot::getSlotList()
{
	CK_RV					rv;
	CK_FUNCTION_LIST_PTR	pFunctionList = library->getFunctionList();

	if (pFunctionList == NULL) {
		return NULL;
	}

	// obtin nr de sloturi (ocupate cu tokenuri)
	printf("\nObtinere lista sloturi de PKCS#11.....");
	rv = pFunctionList->C_GetSlotList(TRUE, NULL, &ulSlotCount);
	if (rv != CKR_OK)
	{
		printf("EROARE");
		return NULL;
	}

	if (ulSlotCount == 0)
	{
		printf("%d slot(uri)", ulSlotCount);
		rv = E_PKCS11_TEST_NO_TOKENS_PRESENT;
		return NULL;
	}


	//obtin lista de sloturi (doar cele cu tokenuri)	
	pSlotList = (CK_SLOT_ID_PTR)malloc(ulSlotCount * sizeof(CK_SLOT_ID));
	if (pSlotList == 0)
	{
		printf("EROARE");
		rv = E_PKCS11_TEST_ALLOC;
		return NULL;
		
	}
	rv = pFunctionList->C_GetSlotList(TRUE, pSlotList, &ulSlotCount);
	if (rv)
	{
		printf("EROARE");
		return NULL;
		
	}
	printf("gasit %d slot(uri)", ulSlotCount);


	if (ulSlotCount == 0)
	{
		rv = E_PKCS11_TEST_NO_TOKENS_PRESENT;
		return NULL;
	}

	CK_TOKEN_INFO *tokenInfo = (CK_TOKEN_INFO*)malloc(ulSlotCount * sizeof(CK_TOKEN_INFO));

	for (unsigned int i = 0; i < ulSlotCount; i++)
	{
		pFunctionList->C_GetTokenInfo(pSlotList[i], &tokenInfo[i]);

		if (tokens == NULL)
		{
			tokens = (cToken**)malloc(ulSlotCount * sizeof(cToken));

		}
		tokens[i] = (cToken*)malloc(sizeof(cToken));
		tokens[i] = new cToken(*tokenInfo);

		//		printf("%s", listToken(tokenInfo));

	}
	tokenCount = ulSlotCount;
	return pSlotList;
}

cToken ** TokenSlot::getTokens()
{
	return tokens;
}

size_t TokenSlot::getTokensCount()
{
	return tokenCount;
}


