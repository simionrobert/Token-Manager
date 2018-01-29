#include "stdafx.h"
#include "ObjectSymmetricKey.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/x509.h"


void tohexa(unsigned char* readbuf, void *writebuf, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		char *l = (char*)(2 * i + ((intptr_t)writebuf));
		sprintf(l, "%02x", readbuf[i]);
	}

}


ObjectSymmetricKey::ObjectSymmetricKey(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj) : ObjectKey(session,obj)
{
	
	CK_ATTRIBUTE valueTemplate[]{
		{
			CKA_VALUE,NULL,0
		}
	};


	CK_RV rv = CKR_OK;
	CK_BYTE_PTR value;
	CK_ULONG value_len;


	rv = pC_GetAttributeValue(this->hSession, this->hObject, &valueTemplate[0], sizeof(valueTemplate) / sizeof(CK_ATTRIBUTE));

	value_len = (CK_ULONG)valueTemplate[0].ulValueLen;
	value = new BYTE[value_len];
	valueTemplate[0].pValue = value;

	rv = pC_GetAttributeValue(this->hSession, this->hObject, &valueTemplate[0], sizeof(valueTemplate) / sizeof(CK_ATTRIBUTE));
	

	char *buffer = (char*)malloc(value_len * 2 + 1);

	tohexa(value, buffer, 2 * value_len + 1);

	//printf("%s", buffer);

	key = _strdup(buffer);
	size = value_len;

}

char * ObjectSymmetricKey::getSize()
{

	char *length = (char*)malloc(5);
	sprintf(length, "%d", size);
	return  length;
}

char * ObjectSymmetricKey::getKey()
{
	return key;
}
