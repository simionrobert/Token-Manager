#include "stdafx.h"
#include "ObjectPrivateKey.h"


void tohex(unsigned char* readbuf, void *writebuf, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		char *l = (char*)(2 * i + ((intptr_t)writebuf));
		sprintf(l, "%02x", readbuf[i]);
	}

}
ObjectPrivateKey::ObjectPrivateKey(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj) : ObjectKey(session,obj)
{

	CK_RV rv = CKR_OK;
	CK_UTF8CHAR *label = NULL_PTR;
	CK_BYTE *id = NULL_PTR;
	CK_BYTE *modulus = NULL_PTR;
	CK_BYTE *publicExponent = NULL_PTR;

	CK_ATTRIBUTE infoTemplate[] = {
		{ CKA_LABEL, NULL_PTR, 0 },
		{ CKA_ID, NULL_PTR, 0 },
		{ CKA_MODULUS,NULL_PTR, 0 },
		{ CKA_PUBLIC_EXPONENT, NULL_PTR, 0 }
		
	
	};


	rv = pC_GetAttributeValue(this->hSession, this->hObject, infoTemplate, sizeof(infoTemplate) / sizeof(CK_ATTRIBUTE));
	//assert(rv == CKR_OK);

	label = (CK_UTF8CHAR*)malloc(infoTemplate[0].ulValueLen * sizeof(CK_UTF8CHAR));
	infoTemplate[0].pValue = label;
	id = (CK_BYTE*)malloc(infoTemplate[1].ulValueLen * sizeof(CK_BYTE));
	infoTemplate[1].pValue = id;
	modulus = (CK_BYTE*)malloc(infoTemplate[2].ulValueLen * sizeof(CK_BYTE));
	infoTemplate[2].pValue = modulus;
	publicExponent = (CK_BYTE*)malloc(infoTemplate[3].ulValueLen * sizeof(CK_BYTE));
	infoTemplate[3].pValue = publicExponent;

	/*publicExponent= (CK_BYTE*)malloc(infoTemplate[2].ulValueLen * sizeof(CK_BYTE));
	infoTemplate[2].pValue = publicExponent;*/

	rv = pC_GetAttributeValue(this->hSession, this->hObject, infoTemplate, sizeof(infoTemplate) / sizeof(CK_ATTRIBUTE));

	//assert(rv == CKR_OK);

	label[infoTemplate[0].ulValueLen] = '\0';
	id[infoTemplate[1].ulValueLen] = '\0';


	/*printf("\nLabel:%s", label);
	printf("\nId:%x", id);*/
	this->label = _strdup((const char*)label);
	int len = infoTemplate[2].ulValueLen;
	modulus[infoTemplate[2].ulValueLen] = '\0';

	char * buffer = (char*)malloc((2 * len + 2) * sizeof(CK_BYTE));
	tohex(modulus, buffer, len);
	

	this->modulus = _strdup(buffer);


	//printf("\nModulus:%s\0", buffer);


	/*assert(publicExponent != NULL);
	free(buffer);
	len = infoTemplate[3].ulValueLen;
	publicExponent[len] = '\0';
	buffer = (char*)malloc(2 * (len + 1) * sizeof(CK_BYTE));
	tohex(publicExponent, buffer, len);
	printf("\Public Exponent:%s\0", buffer);*/
}

char * ObjectPrivateKey::getSize()
{
	char *length = (char*)malloc(5);
	sprintf(length, "%d", strlen(modulus));
	return  length;
}

char * ObjectPrivateKey::getLabel()
{
	return label;
}

char * ObjectPrivateKey::getModulus()
{
	return this->modulus;
}
