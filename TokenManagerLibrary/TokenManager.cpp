#include "stdafx.h"
#define EXPORTING_DLL
#include "TokenManager.h"

TokenManager::TokenManager(PKCS11Library * library, TokenSlot * tokenSlot, TokenSession * session)
{
	this->library = library;
	this->tokenSlot = tokenSlot;
	this->tokenSession = session;
}

int TokenManager::formatToken()
{
	//return CKR_OK if ok; else return sth !=CKR_OK
	return CKR_OK;
}

int TokenManager::changePIN()
{
	//return CKR_OK if ok; else return sth !=CKR_OK
	return CKR_OK;
}

int TokenManager::unblockPIN()
{
	//return CKR_OK if ok; else return sth !=CKR_OK
	return CKR_OK;
}
