#ifndef  TKN_KEY
#define TKN_KEY

#include "cryptoki.h"
#include "defined_tkn_mgr_header.h"

#include"TokenManagerLibrary.h"

class TKN_API TokenKey {

private:
	PKCS11Library*	library;
	TokenSession *	tokenSession;
public:

	TokenKey(PKCS11Library*	library, TokenSession *	tokenSession);
	int importKeyOnToken(const char * fileName, const char * password);
};

#endif // ! TKN_SLOT
