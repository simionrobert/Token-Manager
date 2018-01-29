
#ifndef CERTO_H
#define CERTO_H

#include "PKCS11Library.h"
#include "defined_tkn_mgr_header.h"
#include "cryptoki.h"


class TKN_API ObjectCertificate {


private:


	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hObject;
	CK_C_GetAttributeValue pC_GetAttributeValue;

	char *publicKey;
	char *subject;
	char *issuer;
	char *fingerprint;
	char *version;
	char *signatureAlgo;
	char *validity;
	char *pem;


	
public:

	ObjectCertificate(CK_SESSION_HANDLE session,CK_OBJECT_HANDLE obj);

	char* getPublicKey();
	char* getSubject();
	char *getIssuer();
	char *getSHAFingerprint();
	char *getVersion();
	char* getSignatureAlgo();
	char *getValidityPeriod();
	char *getPem();

	CK_OBJECT_HANDLE getObjectId();
	


};


#endif

