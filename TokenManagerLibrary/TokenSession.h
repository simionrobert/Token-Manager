#ifndef thisN_SESSION
#define thisN_SESSION

#include "cryptoki.h"
#include "defined_tkn_mgr_header.h"

#include"PKCS11Library.h"
#include"TokenSlot.h"


class thisN_API TokenSession {

private:
	PKCS11Library*			library;
	TokenSlot*				tokenSlot;

	CK_SESSION_HANDLE	hSession = -1;
public:
	TokenSession(PKCS11Library* library, TokenSlot* tokenSlot);

	int openSession();
	int closeSession();
	int authentificate(char *p11PinCode);
};

#endif