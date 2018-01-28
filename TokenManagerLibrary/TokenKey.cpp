#include "stdafx.h"
#define EXPORTING_DLL
#include "TokenKey.h"
#include"openssl\rsa.h"
#include"openssl\pem.h"
#include"openssl\bn.h"


TokenKey::TokenKey(PKCS11Library*	library, TokenSession *	tokenSession)
{
	this->library = library;
	this->tokenSession = tokenSession;
}

void _hex_print(unsigned char *buffer, unsigned int len)
{
	fprintf(stdout, "\n");
	for (int i = 0; i < (int)len; i++)
		fprintf(stdout, "%02X ", buffer[i]);
	fprintf(stdout, "\n");
}

RSA * _readPrivateKeyPKCS1(const char * keyFile, bool isPublic, const char * password)
{
	/*Openssl generate public key in PKCS#8 format
	PEM_read_RSAPublicKey() reads as PKCS#1 format
	PEM_read_RSA_PUBKEY() reads PKCS#8*/

	RSA*key = NULL;
	FILE*fp = fopen(keyFile, "rt");	/***!!! p,q,e,d date-nu sunt random sunt in fisier. Ele au fost random la momentul generarii */

	if (isPublic)
		key = PEM_read_RSA_PUBKEY(fp, NULL, NULL, (void*)password); //always PKCS8 format
	else
		key = PEM_read_RSAPrivateKey(fp, NULL, NULL, (void*)password);
	fclose(fp);

	return key;
}
EVP_PKEY * _readPrivateKeyPKCS8(const char * keyFile, bool isPublic, const char * password)
{

	/*By default, open ssl generate public key in PKCS#8 format
	PEM_read_RSAPublicKey() reads as PKCS#1 format
	PEM_read_RSA_PUBKEY() reads PKCS#8*/

	/***Read Key*/
	EVP_PKEY*key = NULL;
	FILE*fp = fopen(keyFile, "rt");	/***!!! p,q,e,d date-nu sunt random sunt in fisier. Ele au fost random la momentul generarii */


	if (isPublic)
		key = PEM_read_PUBKEY(fp, NULL, NULL, (void*)password); //always PKCS8 format
	else
		key = PEM_read_PrivateKey(fp, NULL, NULL, (void*)password);	//n,e,d,p,q,dmp1,dmpq1,iqmp-partile cheii=>este si cheia publica este si cheia privata

	fclose(fp);

	return key;
}

int importRSAKeyToToken(PKCS11Library * library, TokenSession* tokenSession, EVP_PKEY* rsakey8) {

	BIGNUM* modulusBN = rsakey8->pkey.rsa->n;
	CK_BYTE modulus[2048 / 8];
	BN_bn2bin(modulusBN, modulus);
	_hex_print(modulus, 2048 / 8);

	BIGNUM* publicExponentBN = rsakey8->pkey.rsa->e;
	CK_BYTE publicExponent[2048 / 8];
	BN_bn2bin(publicExponentBN, publicExponent);
	_hex_print(publicExponent, 2048 / 8);

	BIGNUM* privateExponentBN = rsakey8->pkey.rsa->d;
	CK_BYTE privateExponent[2048 / 8];
	BN_bn2bin(privateExponentBN, privateExponent);

	BIGNUM* prime1BN = rsakey8->pkey.rsa->p;
	CK_BYTE prime1[2048 / 8];
	BN_bn2bin(prime1BN, prime1);

	BIGNUM* prime2BN = rsakey8->pkey.rsa->q;
	CK_BYTE prime2[2048 / 8];
	BN_bn2bin(prime2BN, prime2);

	BIGNUM* exponent1BN = rsakey8->pkey.rsa->dmp1;
	CK_BYTE exponent1[2048 / 8];
	BN_bn2bin(exponent1BN, exponent1);

	BIGNUM* exponent2BN = rsakey8->pkey.rsa->dmq1;
	CK_BYTE exponent2[2048 / 8];
	BN_bn2bin(exponent2BN, exponent2);

	BIGNUM* coefficientBN = rsakey8->pkey.rsa->iqmp;
	CK_BYTE coefficient[2048 / 8];
	BN_bn2bin(coefficientBN, coefficient);

	// Write key to token
	CK_OBJECT_HANDLE hKey;
	CK_OBJECT_CLASS kClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_UTF8CHAR label[] = "An RSA private key object";
	CK_BYTE subject[] = "No subject";
	CK_BYTE id[] = { 123 };
	CK_BBOOL fTrue = TRUE;

	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, &kClass, sizeof(kClass) }
		,
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
		,
		{ CKA_TOKEN, &fTrue, sizeof(fTrue) }
		,
		{ CKA_LABEL, label, sizeof(label) - 1 }
		,
		{ CKA_SUBJECT, subject, sizeof(subject) }
		,
		{ CKA_ID, id, sizeof(id) }
		,
		{ CKA_SENSITIVE, &fTrue, sizeof(fTrue) }
		,
		{ CKA_DECRYPT, &fTrue, sizeof(fTrue) }
		,
		{ CKA_SIGN, &fTrue, sizeof(fTrue) }
		,
		{ CKA_MODULUS, modulus, sizeof(CK_BYTE)*BN_num_bytes(modulusBN) }
		,
		{ CKA_PUBLIC_EXPONENT, publicExponent, sizeof(CK_BYTE)*BN_num_bytes(publicExponentBN) }
		,
		{ CKA_PRIVATE_EXPONENT, privateExponent, sizeof(CK_BYTE)*BN_num_bytes(privateExponentBN) }
		,
		{ CKA_PRIME_1, prime1, sizeof(CK_BYTE)*BN_num_bytes(prime1BN) }
		,
		{ CKA_PRIME_2, prime2, sizeof(CK_BYTE)*BN_num_bytes(prime2BN) }
		,
		{ CKA_EXPONENT_1, exponent1, sizeof(CK_BYTE)*BN_num_bytes(exponent1BN) }
		,
		{ CKA_EXPONENT_2, exponent2, sizeof(CK_BYTE)*BN_num_bytes(exponent2BN) }
		,
		{ CKA_COEFFICIENT, coefficient, sizeof(CK_BYTE)*BN_num_bytes(coefficientBN) }
	};

	/* Create an RSA public key object */
	CK_RV rv = 0;

	CK_FUNCTION_LIST_PTR pFunctionList = library->getFunctionList();
	CK_SESSION_HANDLE hSession = tokenSession->getSession();

	rv = pFunctionList->C_CreateObject(hSession, keyTemplate, 17, &hKey);

	return rv;
}

int TokenKey::importKeyOnToken(const char * fileName, const char*password)
{
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();

	EVP_PKEY* rsakey8 = _readPrivateKeyPKCS8(fileName, 0, password);
	CK_RV rv;

	// Decide what type of key is
	switch (EVP_PKEY_id(rsakey8))
	{
	case EVP_PKEY_RSA:
	{
		rv = importRSAKeyToToken(this->library, this->tokenSession, rsakey8);

		if (rv == CKR_OK) {
			printf("\nKey imported");
		}
		
		break;
	}
	default:
		break;
	}

	return rv;
}
