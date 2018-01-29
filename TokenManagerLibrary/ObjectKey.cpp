#include "stdafx.h"
#define EXPORTING_DLL
#include "ObjectKey.h"
#include "openssl/x509.h"
#include "openssl/evp.h"




ObjectKey::ObjectKey(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj)
{

	hSession = session;
	hObject = obj;

	pC_GetAttributeValue = (CK_C_GetAttributeValue)PKCS11Library::getFunction("C_GetAttributeValue");



	/*printf("\nPublic Exponent:%d", publicExponent);
	*/
}

CK_OBJECT_HANDLE ObjectKey::getObjectId()
{
	return hObject;
}
