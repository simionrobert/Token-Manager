
#include "stdafx.h"
#define EXPORTING_DLL
#include "ObjectCertificate.h"
#include "openssl/x509.h"
#include "openssl/evp.h"
#include "openssl/pem.h"




char * ObjectCertificate::getPublicKey()
{
	return publicKey;
}

char * ObjectCertificate::getSubject()
{
	return subject;
}

char * ObjectCertificate::getIssuer()
{
	return issuer;
}

char * ObjectCertificate::getSHAFingerprint()
{
	return fingerprint;
}

char * ObjectCertificate::getVersion()
{
	return version;
}

char * ObjectCertificate::getSignatureAlgo()
{
	return signatureAlgo;
}

char * ObjectCertificate::getValidityPeriod()
{
	return validity;
}

char * ObjectCertificate::getPem()
{
	return pem;
}

CK_OBJECT_HANDLE ObjectCertificate::getObjectId()
{
	return hObject;
}



char* parsePublicKey(X509 *cert)
{
	char *pubKey;
	int pubkey_algonid = OBJ_obj2nid(cert->cert_info->key->algor->algorithm);


	if (pubkey_algonid == NID_undef) {
		fprintf(stderr, "unable to find specified public key algorithm name.\n");
		return nullptr;
	}

	const char* sslbuf = OBJ_nid2ln(pubkey_algonid);
	char	*buf = (char*)malloc(strlen(sslbuf));
	memcpy(buf, sslbuf, strlen(sslbuf));


	if (pubkey_algonid == NID_rsaEncryption || pubkey_algonid == NID_dsa) {

		EVP_PKEY *pkey = X509_get_pubkey(cert);
		
		assert(pkey != NULL, "unable to extract public key from certificate");

		RSA *rsa_key;
		DSA *dsa_key;
		char *rsa_e_dec, *rsa_n_hex, *dsa_p_hex,
			*dsa_q_hex, *dsa_g_hex, *dsa_y_hex;

		switch (pubkey_algonid) {

			case NID_rsaEncryption:

				rsa_key = pkey->pkey.rsa;
				assert(rsa_key != nullptr, "unable to extract RSA public key");

				rsa_e_dec = BN_bn2dec(rsa_key->e);
				assert(rsa_e_dec != nullptr, "unable to extract rsa exponent");

				rsa_n_hex = BN_bn2hex(rsa_key->n);
				assert(rsa_n_hex != NULL, "unable to extract rsa modulus");

				pubKey = (char*)malloc(30 + strlen(rsa_n_hex) + strlen(rsa_e_dec));
				sprintf(pubKey, "Public Exponent: %s\nModulus: %s", rsa_e_dec, rsa_n_hex);
				return pubKey;
				break;

			case NID_dsa:

				dsa_key = pkey->pkey.dsa;
				assert(dsa_key != NULL, "unable to extract DSA pkey");

				dsa_p_hex = BN_bn2hex(dsa_key->p);
				assert(dsa_p_hex != NULL, "unable to extract DSA p");

				dsa_q_hex = BN_bn2hex(dsa_key->q);
				assert(dsa_q_hex != NULL, "unable to extract DSA q");

				dsa_g_hex = BN_bn2hex(dsa_key->g);
				assert(dsa_g_hex != NULL, "unable to extract DSA g");

				dsa_y_hex = BN_bn2hex(dsa_key->pub_key);
				assert(dsa_y_hex != NULL, "unable to extract DSA y");
				pubKey = (char*)malloc(20 + strlen(dsa_p_hex) + strlen(dsa_q_hex) + strlen(dsa_g_hex) + strlen(dsa_y_hex));
				sprintf(pubKey, "\nDSA:\n\t\tp:%s\n\t\tq:%s\n\t\tg:%s\n\t\ty:%s", dsa_p_hex, dsa_q_hex, dsa_g_hex, dsa_y_hex);
				return pubKey;
				break;

			default:
				break;
		}

		EVP_PKEY_free(pkey);
	}
}

char* parseSubject(X509 *cert)
{
	return X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
}


char* parseIssuer(X509 *cert)
{
	return X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
}

void hex_encode(unsigned char* readbuf, void *writebuf, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		char *l = (char*)(2 * i + ((intptr_t)writebuf));
		sprintf(l, "%02x", readbuf[i]);
	}
}

char * parseSHAFingerprint(X509 *cert)
{
	char *buf;
	buf = (char*)malloc(20);

	const EVP_MD *digest = EVP_sha1();
	unsigned len;

	int rc = X509_digest(cert, digest, (unsigned char*)buf, &len);

	char *strbuf = (char*)malloc(2 * 20 + 1);
	hex_encode((unsigned char*)buf, strbuf, 20);

	return strbuf;
}

char * parseVersion(X509 *cert)
{
	char *buf = (char*)malloc(15);
	int version = ((int)X509_get_version(cert)) + 1;

	sprintf(buf, "%d", version);
	return buf;

}

char * parseSignatureAlgo(X509* cert)
{
	char *buf;


	int pkey_nid = OBJ_obj2nid(cert->cert_info->key->algor->algorithm);

	if (pkey_nid == NID_undef) {
		fprintf(stderr, "unable to find specified signature algorithm name.\n");

	}
	const char* sslbuf = OBJ_nid2ln(pkey_nid);

	buf = _strdup(sslbuf);

	return (char*)sslbuf;
}

int convert_ASN1TIME(ASN1_TIME *t, char* buf, size_t len)
{
	int rc;
	BIO *b = BIO_new(BIO_s_mem());
	rc = ASN1_TIME_print(b, t);

	assert(rc > 0);

	rc = BIO_gets(b, buf, len);
	buf[rc] = '\0';
	assert(rc > 0);
	BIO_free(b);
	return EXIT_SUCCESS;
}


char * parseValidityPeriod(X509 *cert) {

	ASN1_TIME *not_before = X509_get_notBefore(cert);
	ASN1_TIME *not_after = X509_get_notAfter(cert);
	char *validityPeriod;
	char not_after_str[128];
	convert_ASN1TIME(not_after, not_after_str, 128);

	char not_before_str[128];
	convert_ASN1TIME(not_before, not_before_str, 128);
	not_before_str[strlen(not_after_str)] = '\0';
	validityPeriod = (char*)malloc(strlen(not_after_str) + strlen(not_before_str) + 30);
	sprintf(validityPeriod, "%s - %s\0", not_before_str, not_after_str);
	return validityPeriod;

}

char *X509_to_PEM(X509 *cert) {

	BIO *bio = NULL;
	char *pem = NULL;

	if (NULL == cert) {
		return NULL;
	}

	bio = BIO_new(BIO_s_mem());
	if (NULL == bio) {
		return NULL;
	}

	if (0 == PEM_write_bio_X509(bio, cert)) {
		BIO_free(bio);
		return NULL;
	}

	pem = (char *)malloc(bio->num_write + 1);
	if (NULL == pem) {
		BIO_free(bio);
		return NULL;
	}

	memset(pem, 0, bio->num_write + 1);
	BIO_read(bio, pem, bio->num_write);
	BIO_free(bio);
	return pem;
}

ObjectCertificate::ObjectCertificate(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj)
{
	hSession = session;
	hObject = obj;
	pC_GetAttributeValue = (CK_C_GetAttributeValue)PKCS11Library::getFunction("C_GetAttributeValue");





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


	X509 *cert;

	cert = d2i_X509(NULL, (const unsigned char**)&value, value_len);
	assert(cert != NULL);



	
	publicKey = parsePublicKey(cert);
	subject = parseSubject(cert);
	issuer = parseIssuer(cert);
	fingerprint = parseSHAFingerprint(cert);
	version = parseVersion(cert);
	validity = parseValidityPeriod(cert);
	signatureAlgo = parseSignatureAlgo(cert);
	pem = X509_to_PEM(cert);


}

