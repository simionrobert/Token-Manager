#ifndef TKN_MANAGER
#define TKN_MANAGER

#include "cryptoki.h"
#include "defined_tkn_mgr_header.h"
#include "PKCS11Library.h"
#include "TokenSession.h"
#include "TokenObject.h"
#include "RegistryManager.h"
/*
Pentru tudor
*/

class TKN_API TokenManager { 

private:
	// Put here only services which this class uses (maybe not all 3)
	PKCS11Library*	library;
	TokenSlot*		tokenSlot;
	TokenSession*	tokenSession;
	CK_FUNCTION_LIST_PTR pFunctionList;


	/*
	Certs
	*/

    ObjectCertificate **certList ;
    size_t certCount ;

public:
	TokenManager(PKCS11Library* library, TokenSlot* tokenSlot, TokenSession* session);

	int ChangePINAsUser(char *OLDp11PinCode, char *NEWp11PinCode);
	int ChangePINAsSO(char *OLDp11PinCode, char *NEWp11PinCode);
	int formatToken(char* SOPIN, char* label, char* newPIN,int);
	int changePINasUSER(char*userPIN, char*newPIN);
	int changePINasSO(char*soPIN, char*newPIN);
	int unblockPIN(char* soPIN, char*newPIN,int);
	int initializeToken(char *p11PinCodeSO, char* label,int tokenNumber);
	int initializePIN(char *NEWp11PinCode);


	//////////////////////////////////////////////////////////////////////////
	///////////////////////////ded//////////////////////////////////////////

	CK_RV retrieveTokenObjects();
	ObjectCertificate** getCertificates();
	size_t getCertificatesCount();




	
	int numaraObiecteCertificat(CK_SESSION_HANDLE		hSession);
	CK_OBJECT_HANDLE_PTR getObiecteCertificat(CK_SESSION_HANDLE		hSession);
	CK_ATTRIBUTE* getAttribute(CK_OBJECT_HANDLE hObject, CK_SESSION_HANDLE session, CK_ATTRIBUTE* templateAttributeInitial, int len);
	void final();
};


#endif
