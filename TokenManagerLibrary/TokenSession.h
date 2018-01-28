#ifndef TKN_SESSION
#define TKN_SESSION

#include "cryptoki.h"
#include "defined_tkn_mgr_header.h"

#include"PKCS11Library.h"
#include"TokenSlot.h"


class TKN_API TokenSession {

private:
	PKCS11Library*			library;
	TokenSlot*				tokenSlot;
	CK_SESSION_HANDLE		hSession = -1;

public:
	TokenSession(PKCS11Library* library, TokenSlot* tokenSlot);

	int openSession();
	int closeSession();
	int authentificateAsUser(char *p11PinCode);
	int authentificateAsSO(char *p11PinCode);
	
	CK_SESSION_HANDLE getSession();
};

#endif