
#ifndef SKEY_O
#define SKEY_O

#include "cryptoki.h"
#include "defined_tkn_mgr_header.h"
#include "PKCS11Library.h"
#include "ObjectKey.h"


class TKN_API ObjectSymmetricKey : ObjectKey {

private:
	size_t size;
	char *key;

public:

	ObjectSymmetricKey(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj);

	char *getSize();
	char *getKey();

};
#endif

