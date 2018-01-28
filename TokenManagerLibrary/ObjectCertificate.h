
#ifndef CERTO_H
#define CERTO_H

#include "PKCS11Library.h"
#include "defined_tkn_mgr_header.h"
#include "cryptoki.h"


class TKN_API ObjectCertificate {


private:


	char *publicKey;
	char *subject;
	char *issuer;
	char *fingerprint;
	char *version;
	char *signatureAlgo;
	char *validity;


public:
	ObjectCertificate(char *certData, int len);
	char* getPublicKey();
	char* getSubject();
	char *getIssuer();
	char *getSHAFingerprint();
	char *getVersion();
	char* getSignatureAlgo();
	char *getValidityPeriod();

};


#endif

