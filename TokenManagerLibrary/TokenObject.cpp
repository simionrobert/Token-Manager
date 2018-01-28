#include "stdafx.h"
#define EXPORTING_DLL

#include "TokenObject.h"
#include "openssl/x509.h"
#include "openssl/evp.h"


#define MAX_COUNT 100
#define SHA1LEN 20


TokenObject::TokenObject(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj)
{
	printf("\n\tInitializing token object...");

	pC_OpenSession = NULL_PTR;
	pC_Login = NULL_PTR;
	pC_FindObjectsInit = NULL_PTR;
	pC_FindObjects = NULL_PTR;
	pC_FindObjectsFinal = NULL_PTR;
	pC_GetAttributeValue = NULL_PTR;
	pC_GenerateKeyPair = NULL_PTR;


	pC_OpenSession = (CK_C_OpenSession)PKCS11Library::getFunction("C_OpenSession");
	pC_Login = (CK_C_Login)PKCS11Library::getFunction("C_Login");
	pC_FindObjectsInit = (CK_C_FindObjectsInit)PKCS11Library::getFunction("C_FindObjectsInit");
	pC_FindObjects = (CK_C_FindObjects)PKCS11Library::getFunction("C_FindObjects");
	pC_FindObjectsFinal = (CK_C_FindObjectsFinal)PKCS11Library::getFunction("C_FindObjectsFinal");
	pC_GetAttributeValue = (CK_C_GetAttributeValue)PKCS11Library::getFunction("C_GetAttributeValue");
	pC_GenerateKeyPair = (CK_C_GenerateKeyPair)PKCS11Library::getFunction("C_GenerateKeyPair");
	hSession = session;
	hObject = obj;
	

	getCertObject();

	printf("OK");
}
ObjectCertificate* TokenObject::getCertificate()
{
	return this->cert;
}
void TokenObject::listPubObjects()
{
}




//void TokenObject::listPubObjects()
//{
//	CK_RV rv = CKR_OK;
//	
//	CK_OBJECT_CLASS		certClass = CKO_CERTIFICATE;
//	CK_CERTIFICATE_TYPE certType = CKC_X_509;
//	CK_BBOOL			isToken = true;
//	CK_BYTE_PTR			subject = NULL_PTR;
//	CK_BYTE_PTR			id = NULL_PTR;
//	CK_BYTE				certificateValue[2048];
//
//	CK_BYTE_PTR value;
//	CK_ULONG value_len;
//
//	CK_OBJECT_HANDLE	hObject[MAX_COUNT]; // pt rezultatele cautarii 
//	CK_ULONG			objectFound = 0;
//
//
//	CK_ATTRIBUTE objTemplate[]{
//
//		{
//			CKA_CLASS ,&certClass,sizeof(certClass)
//		},
//		{
//			CKA_TOKEN, &isToken, sizeof(isToken)
//		}
//
//	};
//
//	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	/////////////////////////////////////		Cert search 		////////////////////////////////////////////////////////////
//	
//			//Certificate Data template
//				CK_ATTRIBUTE valueTemplate[]{
//					{
//						CKA_VALUE,NULL_PTR,0
//					}
//				};
//
//			value_len = (CK_ULONG)valueTemplate[0].ulValueLen;
//			value = new BYTE[value_len];
//			valueTemplate[0].pValue = value;
//
//			rv = pC_GetAttributeValue(this->hSession, hObject[i], &valueTemplate[0], sizeof(valueTemplate) / sizeof(CK_ATTRIBUTE));
//			
//
//			//////////////////////////////////////////////////////////////////////////unix asn1
//		
//			unsigned char * valueRawData = (unsigned char*)malloc(value_len * sizeof(unsigned char));
//			memcpy(valueRawData, value, value_len);
//			X509 *certX509 = d2i_X509(NULL, (const unsigned char**)&valueRawData, value_len);
//			//X509* certX509 = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
////
////			assert(certX509, NULL, "Could not write X509 cert");
////			
////						
////			
////
////
////
////
////			
////			
////			free(buf);
////
////
////			
////			printf("\nVersion: %d", version);
////
////
////			//Signature Algo
////
////			
//////			printf("\nPub key:%s\0", getPublicKey(certX509));
////			
////			printf("\nValidity:%s", getValidityPeriod(certX509));
//
//
//	//	}
//
//
//
//	//}
//	//printf("\nClosing sesssion...");
//	//rv = pC_FindObjectsFinal(this->hSession);
//	//if (rv != CKR_OK)
//	//{
//	//	printf("ERROR Final");
//	//	return;
//
//	//}
//	printf("OK");
//
//}
//
//



CK_RV TokenObject::getCertObject() {

	CK_RV rv = CKR_OK;
	CK_BYTE_PTR value;
	CK_ULONG value_len;

	CK_ATTRIBUTE valueTemplate[]{
		{
			CKA_VALUE,NULL,0
		}
	};
	rv = pC_GetAttributeValue(this->hSession, this->hObject, &valueTemplate[0], sizeof(valueTemplate) / sizeof(CK_ATTRIBUTE));

	value_len = (CK_ULONG)valueTemplate[0].ulValueLen;
	value = new BYTE[value_len];
	valueTemplate[0].pValue = value;

	rv = pC_GetAttributeValue(this->hSession, this->hObject, &valueTemplate[0], sizeof(valueTemplate) / sizeof(CK_ATTRIBUTE));


	//Decode Raw Cert Data to X509
	cert = new ObjectCertificate((char*)value, value_len);
	
	return CKR_OK;

}

void TokenObject::listKey(CK_OBJECT_HANDLE hKey)
{
	CK_RV rv = CKR_OK;
	CK_UTF8CHAR *label = NULL_PTR;
	CK_BYTE *id = NULL_PTR;
	CK_BYTE *publicExponent;
	CK_ATTRIBUTE infoTemplate[] = {
		{ CKA_ATTR_TYPES, NULL_PTR, 0 },
		{ CKA_ID, NULL_PTR, 0 }/*,
							   { CKA_PUBLIC_EXPONENT,NULL_PTR, 0}*/
	};


	rv = pC_GetAttributeValue(this->hSession, hKey, infoTemplate, sizeof(infoTemplate) / sizeof(CK_ATTRIBUTE));
	assert(rv == CKR_OK);

	label = (CK_UTF8CHAR*)malloc(infoTemplate[0].ulValueLen * sizeof(CK_UTF8CHAR));
	infoTemplate[0].pValue = label;
	id = (CK_BYTE*)malloc(infoTemplate[1].ulValueLen * sizeof(CK_BYTE));
	infoTemplate[1].pValue = id;

	/*publicExponent= (CK_BYTE*)malloc(infoTemplate[2].ulValueLen * sizeof(CK_BYTE));
	infoTemplate[2].pValue = publicExponent;*/

	rv = pC_GetAttributeValue(this->hSession, hKey, infoTemplate, sizeof(infoTemplate) / sizeof(CK_ATTRIBUTE));

	assert(rv == CKR_OK);

	label[infoTemplate[0].ulValueLen] = '\0';
	id[infoTemplate[1].ulValueLen] = '\0';


	printf("\nLabel:%s", label);
	printf("\nId:%x", id);
	/*printf("\nPublic Exponent:%d", publicExponent);
	*/


}


void TokenObject::readKeys() {

	CK_RV rv;
	CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) }
	};

	CK_ULONG objectCount;
	CK_OBJECT_HANDLE object[MAX_COUNT];
	rv = pC_FindObjectsInit(this->hSession, keyTemplate, 1);
	assert(rv == CKR_OK, "Find objects init");


	rv = pC_FindObjects(this->hSession, object, MAX_COUNT, &objectCount);
	assert(rv == CKR_OK, "Find first object");

	printf("\n\tFound %d keys...", objectCount);
	for (int i = 0; i < objectCount; i++)
	{
		//listKey(object[i]);
		//getAttributes(object[i]);
	}

	rv = pC_FindObjectsFinal(this->hSession);
	assert(rv == CKR_OK, "Find objects final");

}

CK_RV TokenObject::createKeyPair()
{
	CK_RV rv;

	CK_ULONG				modulusBits = 1024;
	CK_BYTE					publicExponent[] = { 3 };
	CK_BYTE					pubSubject[] = { "test_subiect_pub" };
	CK_BYTE					privSubject[] = { "test_subiect_priv" };
	CK_BYTE					id[] = { 123 };
	CK_OBJECT_HANDLE		hObject = NULL_PTR;
	CK_OBJECT_HANDLE		hPublicKey = NULL_PTR;
	CK_OBJECT_HANDLE		hPrivateKey = NULL_PTR;

	CK_OBJECT_CLASS			keyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE				keyType = CKK_RSA;
	CK_BBOOL				isTrue = CK_TRUE;


	CK_ATTRIBUTE publicKeyTemplate[] = {
		{ CKA_ENCRYPT,	&isTrue,	 sizeof(isTrue) },
		{ CKA_LABEL, pubSubject, 16 },
		{ CKA_VERIFY,	&isTrue,	 sizeof(isTrue) },
		{ CKA_WRAP,		&isTrue,	 sizeof(isTrue) },
		{ CKA_MODULUS_BITS,		&modulusBits, sizeof(modulusBits) },
		{ CKA_PUBLIC_EXPONENT,	publicExponent, sizeof(publicExponent) }
	};
	CK_ATTRIBUTE privateKeyTemplate[] = {
		{ CKA_TOKEN, &isTrue,		sizeof(isTrue) },
		{ CKA_LABEL, privSubject, 17 },
		{ CKA_PRIVATE, &isTrue,		sizeof(isTrue) },
		{ CKA_ID, id,				sizeof(id) },
		{ CKA_SENSITIVE, &isTrue,	sizeof(isTrue) },
		{ CKA_DECRYPT, &isTrue,		sizeof(isTrue) },
		{ CKA_SIGN, &isTrue,		sizeof(isTrue) },
		{ CKA_UNWRAP, &isTrue,		sizeof(isTrue) }
	};

	CK_MECHANISM keyPairMechanism = {
		CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
	};

	CK_ATTRIBUTE crTemplate[] = {
		{ CKA_PRIVATE, NULL_PTR, 0 },
		{ CKA_SUBJECT,NULL_PTR,0 }
	};

	printf("\nGenerating key pair...");
	rv = pC_GenerateKeyPair(
		this->hSession, &keyPairMechanism,
		publicKeyTemplate, 6,
		privateKeyTemplate, 8,
		&hPublicKey, &hPrivateKey
	);


	if (rv != CKR_OK) {
		printf("ERROR 0x%08x", rv);
		return rv;
	}
	else
	{
		printf("OK");


		printf("\nFetching public key...");
		rv = pC_GetAttributeValue(hSession, hPublicKey, crTemplate, 1);
		if (rv != CKR_OK)
		{
			printf("ERROR 0x%08x", rv);
			return rv;
		}
		else
		{
			printf("OK");
			CK_BYTE_PTR pkey = (CK_BYTE_PTR)malloc(crTemplate[0].ulValueLen * sizeof(CK_BYTE));
			crTemplate[0].pValue = pkey;
			CK_BYTE_PTR pkeySubject = (CK_BYTE_PTR)malloc(crTemplate[0].ulValueLen * sizeof(CK_BYTE));
			crTemplate[1].pValue = pkeySubject;
			rv = pC_GetAttributeValue(hSession, hPublicKey, crTemplate, 1);


			printf("\n0x%09x", crTemplate[0].pValue);
			printf("\n%s", (CK_CHAR_PTR)crTemplate[1].pValue);
		}

	}


	return rv;



}




/*
Get Certificates stored on token
*/
