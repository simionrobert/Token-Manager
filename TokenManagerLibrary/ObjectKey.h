#ifndef KEYO_H
#define KEYO_H


#include "PKCS11Library.h"
#include "defined_tkn_mgr_header.h"
#include "cryptoki.h"

class TKN_API ObjectKey {


protected:
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hObject;
	CK_C_GetAttributeValue pC_GetAttributeValue;

	
public:
	ObjectKey(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj);

	CK_OBJECT_HANDLE getObjectId();
};

#endif