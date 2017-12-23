#include "stdafx.h"
#define EXPORTING_DLL
#include "TokenSlot.h"
#include "cToken.h"


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


//CK_SLOT_ID_PTR TokenSlot::getSlotList()
//{
//	CK_RV					rv;
//	CK_FUNCTION_LIST_PTR	pFunctionList = library->getFunctionList();
//
//	if (pFunctionList == NULL) {
//		return NULL;
//	}
//
//	// obtin nr de sloturi (ocupate cu tokenuri)
//	printf("\nObtinere lista sloturi de PKCS#11.....");
//	rv = pFunctionList->C_GetSlotList(TRUE, NULL, &ulSlotCount);
//	if (rv != CKR_OK)
//	{
//		printf("EROARE");
//		return NULL;
//	}
//
//	if (ulSlotCount == 0)
//	{
//		printf("%d slot(uri)", ulSlotCount);
//		rv = E_PKCS11_TEST_NO_TOKENS_PRESENT;
//		return NULL;
//	}
//
//
//	//obtin lista de sloturi (doar cele cu tokenuri)	
//	pSlotList = (CK_SLOT_ID_PTR)malloc(ulSlotCount * sizeof(CK_SLOT_ID));
//	if (pSlotList == 0)
//	{
//		printf("EROARE");
//		rv = E_PKCS11_TEST_ALLOC;
//		return NULL;
//		
//	}
//	rv = pFunctionList->C_GetSlotList(TRUE, pSlotList, &ulSlotCount);
//	if (rv)
//	{
//		printf("EROARE");
//		return NULL;
//		
//	}
//	printf("gasit %d slot(uri)", ulSlotCount);
//
//
//	if (ulSlotCount == 0)
//	{
//		rv = E_PKCS11_TEST_NO_TOKENS_PRESENT;
//		return NULL;
//	}
//
//	return pSlotList;
//}


/////////////////////////////////////////////////////////////////////////
//////////////////////////////////ded////////////////////////////////////

CK_RV TokenSlot::setTokenSlotList()
{
	CK_RV rv = CKR_OK;
	//There are available slots. 
	//Allocate memory for slot ids ( Slot list )
	this->pTokenSlotList = (CK_SLOT_ID_PTR)malloc(0);
	this->tokenSlotCount = 0;


	//Checking for available slots
	checkForSlots();

	printf("\nInitializing token slot list...");
	while (1)
	{
		rv = pC_GetSlotList(CK_TRUE, pTokenSlotList, &tokenSlotCount); // 1st argument let's us search for slots with tokens

		if (rv != CKR_BUFFER_TOO_SMALL)
			break;
		pTokenSlotList = (CK_SLOT_ID_PTR)realloc(pTokenSlotList, tokenSlotCount * sizeof(CK_SLOT_ID));

	}
	if (!rv == CKR_OK)
	{
		rv = ERR_SLOTS_INIT_LIST;
		printf("ERROR");
		return rv;

	}
	printf("OK\n\tFound %u slot(s) with token", tokenSlotCount);

	return rv;
}

CK_RV TokenSlot::checkForSlots()
{
	CK_RV rv = CKR_OK;

	//Checking for available slots
	CK_ULONG slotCount;

	printf("\nChecking for available slots...");
	rv = (*pC_GetSlotList)(CK_FALSE, NULL_PTR, &slotCount);


	if (!rv == CKR_OK) {


		rv = ERR_SLOTS_GET_COUNT;
		printf("ERROR");
		return rv;

	}
	printf("OK\n\tFound %u available slots", slotCount);
	return rv;
}

CK_CHAR_PTR TokenSlot::listToken(CK_SLOT_ID id) {
	//returns a char* with the token info
	CK_TOKEN_INFO tokenInfo;
	pC_GetTokenInfo(id, &tokenInfo);
	cToken *tk;
	tk = new cToken(tokenInfo);
	tk->printInfo();
	//CK_CHAR_PTR info = NULL;

	/*char buff[100];
	int newsize;
	int oldsize;

	

	
	newsize = strlen(buff);


	info = (CK_CHAR_PTR)realloc(info, newsize);
	strcpy((char*)info, buff);
	oldsize = strlen((const char*)info);

	
	newsize = strlen((const char*)info) + strlen(buff) + 1;
	info = (CK_CHAR_PTR)realloc(info, newsize);
	info[oldsize] = '\0';
	strcat((char*)info, buff);
	oldsize = strlen((const char*)info);

	tokenInfo.label[31] = '\0';
	
	newsize = strlen((const char*)info) + strlen(buff) + 1;
	info = (CK_CHAR_PTR)realloc(info, newsize);
	info[oldsize] = '\0';
	strcat((char*)info, buff);
	oldsize = strlen((const char*)info);


	tokenInfo.manufacturerID[31] = '\0';
	
	newsize = strlen((const char*)info) + strlen(buff) + 1;
	info = (CK_CHAR_PTR)realloc(info, newsize);
	info[oldsize] = '\0';
	strcat((char*)info, buff);
	oldsize = strlen((const char*)info);


	tokenInfo.model[15] = '\0';
	
	newsize = strlen((const char*)info) + strlen(buff) + 1;
	info = (CK_CHAR_PTR)realloc(info, newsize);
	info[oldsize] = '\0';
	strcat((char*)info, buff);
	oldsize = strlen((const char*)info);


	tokenInfo.serialNumber[15] = '\0';
	
	newsize = strlen((const char*)info) + strlen(buff) + 1;
	info = (CK_CHAR_PTR)realloc(info, newsize);
	info[oldsize] = '\0';
	strcat((char*)info, buff);
	oldsize = strlen((const char*)info);


	tokenInfo.utcTime[15] = '\0';
	
	newsize = strlen((const char*)info) + strlen(buff) + 1;
	info = (CK_CHAR_PTR)realloc(info, newsize);
	info[oldsize] = '\0';
	strcat((char*)info, buff);
	oldsize = strlen((const char*)info);

	return info;*/

	//printf("\n\tFirmware Version:%d.%d", tokenInfo.firmwareVersion.major, tokenInfo.firmwareVersion.minor);
	//printf("\n\tHardware Version:%d.%d", tokenInfo.hardwareVersion.major, tokenInfo.hardwareVersion.minor);
	//tokenInfo.label[31] = '\0';
	//printf("\n\tLabel:%s", tokenInfo.label);
	//tokenInfo.manufacturerID[31] = '\0';
	//printf("\n\tManufacturer ID:%s", tokenInfo.manufacturerID);
	//tokenInfo.model[15] = '\0';
	//printf("\n\tModel:%s",tokenInfo.model);
	//tokenInfo.serialNumber[15] = '\0';
	//printf("\n\tSerial No.:%s", tokenInfo.serialNumber);
	//tokenInfo.utcTime[15] = '\0';
	//printf("\n\tUTC Time:%s", tokenInfo.utcTime);	
	return NULL;
}

TokenSlot::TokenSlot()
{
	CK_RV rv = CKR_OK;
	printf("\nInitializing Slot Manager...");
	pC_GetSlotList = (CK_C_GetSlotList)PKCS11Library::getFunction("C_GetSlotList");
	pC_GetTokenInfo = (CK_C_GetTokenInfo)PKCS11Library::getFunction("C_GetTokenInfo");
	rv = setTokenSlotList();
	if (rv != CKR_OK)
	{
		printf("ERROR");
		return;
	}
	printf("OK");

}



void TokenSlot::listAvailableTokens()
{


	printf("\nAvailable tokens:");

	for (int i = 0; i < this->tokenSlotCount; i++)
	{
		printf("\n%d.", i);
		listToken(this->pTokenSlotList[i]);
	}

}

TokenSlot::~TokenSlot()
{
	if (pTokenSlotList)
		free(pTokenSlotList);

}


