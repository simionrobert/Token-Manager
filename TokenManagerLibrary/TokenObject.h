
#ifndef TOKEN_H
#define TOKEN_H

#include "PKCS11Library.h"
#include "defined_tkn_mgr_header.h"
#include "cryptoki.h"
#include "ObjectCertificate.h"

class TKN_API TokenObject {


private:

	CK_SLOT_ID slotId;
	CK_TOKEN_INFO info;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hObject;

	//Function pointers
	CK_C_OpenSession pC_OpenSession;
	CK_C_Login pC_Login;
	CK_C_FindObjectsInit pC_FindObjectsInit;
	CK_C_FindObjects pC_FindObjects;
	CK_C_FindObjectsFinal pC_FindObjectsFinal;
	CK_C_GetAttributeValue pC_GetAttributeValue;
	CK_C_GenerateKeyPair pC_GenerateKeyPair;


	
	void listKey(CK_OBJECT_HANDLE hKey);
	CK_RV getCertObject();
	ObjectCertificate *cert;
public:


	TokenObject(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE);
	ObjectCertificate *getCertificate();
	void listPubObjects();
	CK_RV createKeyPair();
	void readKeys();
	


};


#endif