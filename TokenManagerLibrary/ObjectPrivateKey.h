
#ifndef PKEY_O
#define PKEY_O

#include "cryptoki.h"
#include "defined_tkn_mgr_header.h"
#include "PKCS11Library.h"
#include "ObjectKey.h"


class TKN_API ObjectPrivateKey : ObjectKey {

private:
	int size;
	char *label;
	char *modulus;

public:

	ObjectPrivateKey(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj);



	char *getSize();
	char *getLabel();
	char *getModulus();


};
#endif

