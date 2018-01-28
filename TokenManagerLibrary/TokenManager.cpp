#include "stdafx.h"
#define EXPORTING_DLL
#include "TokenManager.h"
#include <assert.h>
#include <Wincrypt.h>
#include <cryptuiapi.h>
#include <tchar.h>
#include <winscard.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "cryptui.lib")

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

TokenManager::TokenManager(PKCS11Library * library, TokenSlot * tokenSlot, TokenSession * session)
{

	certList = NULL;
	certCount = 0;
	assert(library != NULL);
	this->library = library;
	this->tokenSlot = tokenSlot;
	this->tokenSession = session;

	this->pFunctionList = library->getFunctionList();
	assert(this->pFunctionList != NULL);

}

int TokenManager::numaraObiecteCertificat(CK_SESSION_HANDLE		hSession)
{
	CK_LONG value_len = 0;
	CK_BYTE_PTR pValue;
	PCCERT_CONTEXT pCACert = NULL;
	CK_RV	rv;

	CK_OBJECT_HANDLE hObject[100];
	CK_ULONG ulObjectCount;
	CK_BBOOL _true = CK_TRUE;
	int numarObiecte = 0;

	CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	CK_ATTRIBUTE certificateTemplate[] = {
		{ CKA_CLASS, &certClass, sizeof(certClass) },
		{ CKA_TOKEN, &_true, sizeof(_true) }
	};

	CK_FUNCTION_LIST_PTR pFunctionList = this->library->getFunctionList();


	rv = pFunctionList->C_FindObjectsInit(hSession, certificateTemplate, 2);

	if (rv == CKR_OK)
	{
		rv = pFunctionList->C_FindObjects(hSession, hObject, 100, &ulObjectCount);
		if (rv != CKR_OK)
		{
			printf("\nEroare la citirea obiectelor");
		}

		rv = pFunctionList->C_FindObjectsFinal(hSession);
	}
	else
	{
		throw rv;
	}
	printf("Numarul de obiecte de tip Certificat de pe token: %d\n", ulObjectCount);

	return ulObjectCount;
}

CK_OBJECT_HANDLE* TokenManager::getObiecteCertificat(CK_SESSION_HANDLE		hSession)
{
	CK_LONG value_len = 0;
	CK_BYTE_PTR pValue;
	PCCERT_CONTEXT pCACert = NULL;
	CK_RV	rv;

	CK_OBJECT_HANDLE hObject[100];
	CK_ULONG ulObjectCount;
	CK_BBOOL _true = CK_TRUE;
	int numarObiecte = 0;

	CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	CK_ATTRIBUTE certificateTemplate[] = {
		{ CKA_CLASS, &certClass, sizeof(certClass) },
		{ CKA_TOKEN, &_true, sizeof(_true) }
	};


	CK_FUNCTION_LIST_PTR pFunctionList = this->library->getFunctionList();
	rv = pFunctionList->C_FindObjectsInit(hSession, certificateTemplate, 2);

	if (rv == CKR_OK)
	{
		rv = pFunctionList->C_FindObjects(hSession, hObject, 100, &ulObjectCount);
		if (rv != CKR_OK)
		{
			printf("Eroare la citirea obiectelor\n");
			throw rv;
		}

		rv = pFunctionList->C_FindObjectsFinal(hSession);
	}
	else
	{
		throw rv;
	}

	CK_OBJECT_HANDLE *certificate = (CK_OBJECT_HANDLE*)malloc(ulObjectCount * sizeof(CK_OBJECT_HANDLE));
	for (int i = 0; i < ulObjectCount; i++)
	{
		certificate[i] = hObject[i];
	}


	return certificate;
}


CK_ATTRIBUTE* TokenManager::getAttribute(CK_OBJECT_HANDLE hObject, CK_SESSION_HANDLE session, CK_ATTRIBUTE* templateAttributeInitial, int len)
{
	CK_RV rv;
	CK_ATTRIBUTE* templateAttribute = (CK_ATTRIBUTE*)malloc(len * sizeof(CK_ATTRIBUTE));
	for (int i = 0; i < len; i++)
	{
		templateAttribute[i].type = templateAttributeInitial[i].type;
		templateAttribute[i].pValue = NULL;
		templateAttribute[i].ulValueLen = 0;
	}

	CK_LONG* value_len = (CK_LONG*)malloc(sizeof(CK_LONG)*len);
	CK_BYTE_PTR* pValue = (CK_BYTE_PTR*)malloc(sizeof(CK_BYTE_PTR)*len);

	CK_FUNCTION_LIST_PTR pFunctionList = this->library->getFunctionList();
	rv = pFunctionList->C_GetAttributeValue(session, hObject, templateAttribute, len);
	if (rv == CKR_OK)
	{
		for (int i = 0; i < len; i++)
		{
			value_len[i] = (CK_LONG)templateAttribute[i].ulValueLen;
			pValue[i] = new BYTE[value_len[i]];
			templateAttribute[i].pValue = pValue[i];
			templateAttribute[i].ulValueLen = value_len[i];
		}

		rv = pFunctionList->C_GetAttributeValue(session, hObject, templateAttribute, len);
		if (rv == CKR_OK)
		{
			return templateAttribute;

		}
		else
		{
			throw rv;
		}
	}

	else
	{
		throw rv;
	}

	return NULL;
}

void adaugareCertificatInStore(PCCERT_CONTEXT certificat) {
	HCERTSTORE       hCertStore;
	//CERT_SYSTEM_STORE_CURRENT_USER

	hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
	if (!hCertStore)
	{
		printf("Error opening system store.");
	}

	bool ok = CertAddCertificateContextToStore(hCertStore, certificat, CERT_STORE_ADD_REPLACE_EXISTING, NULL);
	if (!ok) {
		printf("Error add system store.");
	}
}

void TokenManager::final() {
	CK_BYTE_PTR pValue;
	CK_LONG value_len = 0;
	CK_RV	rv = 0;
	CK_FLAGS flags = 0;
	CK_SLOT_ID slotID;
	CK_SLOT_INFO slotInfo;
	CK_SESSION_HANDLE session;

	CK_FUNCTION_LIST_PTR pFunctionList = this->library->getFunctionList();

	rv = this->library->getFunctionList()->C_WaitForSlotEvent(NULL, &slotID, NULL_PTR);

	RegistryManager* manager = new RegistryManager();
	TCHAR* valueRead = 0;
	DWORD valueReadLenght = 0;

	manager->readValueFromRegistry(HKEY_LOCAL_MACHINE, "Software\\Wow6432Node\\TokenManager\\SubKeyOne\\SubKeyTwo", "Service", valueRead, valueReadLenght);

	if (valueRead == NULL)
		goto err;

	if (memcmp(valueRead, "1", 2) == 0) {

		if (rv == CKR_OK)
		{
			rv = pFunctionList->C_GetSlotInfo(slotID, &slotInfo);
			if (slotInfo.flags & CKF_TOKEN_PRESENT)
			{
				rv = this->tokenSession->openSession();
				if (rv != 0)
					goto err;

				session = this->tokenSession->getSession();

				int nrCertificate = numaraObiecteCertificat(session);
				CK_OBJECT_HANDLE* certificate = getObiecteCertificat(session);


				CK_ATTRIBUTE templateIDAttribute[] = {
					{ CKA_ID, NULL , 0 },
					{ CKA_SUBJECT, NULL, 0 }
				};
				CK_ATTRIBUTE templateValue[] = {
					{ CKA_VALUE, NULL , 0 }
				};


				for (int i = 0; i < nrCertificate; i++)
				{

					pValue = new BYTE[getAttribute(certificate[i], session, templateValue, 1)->ulValueLen];
					pValue = (CK_BYTE_PTR)getAttribute(certificate[i], session, templateValue, 1)->pValue;
					value_len = getAttribute(certificate[i], session, templateValue, 1)->ulValueLen;
					PCCERT_CONTEXT pCACert = CertCreateCertificateContext(MY_ENCODING_TYPE, pValue, value_len);

					// IAU LABEL-UL SI ID-UL CERTIFICATULUI SI LE COMPAR CU L"" RESPECTIV 0 CA SA VAD DACA ARE CHEIE ASOCIATA
					//IAU LABEL-UL
					CK_ATTRIBUTE templateLabel[] = {
						{ CKA_LABEL, NULL , 0 }
					};
					CK_BYTE_PTR valoare = (CK_BYTE_PTR)getAttribute(certificate[i], session, templateLabel, 1)->pValue;
					DWORD lenvaloare = (DWORD)getAttribute(certificate[i], session, templateLabel, 1)->ulValueLen;

					CHAR* ContainerName = (CHAR*)malloc(lenvaloare * sizeof(CHAR) + 1);
					memcpy(ContainerName, valoare, lenvaloare);
					ContainerName[lenvaloare] = '\0';

					wchar_t* wtext = (wchar_t*)malloc((lenvaloare + 1) * sizeof(wchar_t));
					mbstowcs(wtext, ContainerName, strlen(ContainerName) + 1);//Plus null
					LPWSTR ContainerNameW = wtext;

					// IAU ID-UL
					CK_ATTRIBUTE templateIDAttribute[] = {
						{ CKA_ID, NULL , 0 },
						{ CKA_MODULUS, NULL, 0 }
					};

					CK_BYTE_PTR valoare2 = (CK_BYTE_PTR)getAttribute(certificate[i], session, templateIDAttribute, 1)->pValue;
					DWORD lenvaloare2 = (DWORD)getAttribute(certificate[i], session, templateIDAttribute, 1)->ulValueLen;

					if (lenvaloare != 0 && lenvaloare2 != 0)	//DACA CERTIFICATUL ARE ID SI LABEL INSEAMNA CA ARE CHEIE ASOCIATA
					{
						CRYPT_KEY_PROV_INFO key_prov_info = { 0 };
						key_prov_info.dwProvType = 1;
						key_prov_info.dwKeySpec = 1;
						key_prov_info.pwszContainerName = ContainerNameW;//L"4F5CFA156F94FD55";
						key_prov_info.dwFlags = 0;
						key_prov_info.cProvParam = 0;
						key_prov_info.pwszProvName = L"eToken Base Cryptographic Provider";
						key_prov_info.rgProvParam = 0;

						CertSetCertificateContextProperty(pCACert, CERT_KEY_PROV_INFO_PROP_ID, 0, &key_prov_info);

						adaugareCertificatInStore(pCACert);


					}
				}

				this->tokenSession->closeSession();
			}
			slotID = NULL;
		}
		else
		{
			throw rv;
		}
	}
err:
	printf("\nDone\n");
}


int TokenManager::formatToken(char* SOPIN, char* label, char* newPIN)
{
	//return CKR_OK if ok; else return sth !=CKR_OK
	this->initializeToken(SOPIN, label);
	this->tokenSession->openSession();
	this->tokenSession->authentificateAsSO(SOPIN);
	this->initializePIN(newPIN);
	return 1;
}

int TokenManager::changePINasUSER(char*userPIN,char*newPIN)
{
	//return CKR_OK if ok; else return sth !=CKR_OK
	/*this->tokenSession->openSession();
	this->tokenSession->authentificateAsUser(userPIN);*/
	this->ChangePINAsUser(userPIN, newPIN);
	return 1;
}

int TokenManager::changePINasSO(char*soPIN, char*newPIN)
{
	//return CKR_OK if ok; else return sth !=CKR_OK
	/*this->tokenSession->openSession();
	this->tokenSession->authentificateAsSO(soPIN);*/
	this->ChangePINAsSO(soPIN, newPIN);
	return 1;
}

int TokenManager::unblockPIN(char* soPIN,char*newPIN)
{
	//return CKR_OK if ok; else return sth !=CKR_OK
	this->tokenSession->openSession();
	this->tokenSession->authentificateAsSO(soPIN);
	this->initializePIN(newPIN);
	return 1;
}

int TokenManager::initializeToken(char *p11PinCodeSO,char* label)
{
	CK_SLOT_ID_PTR pSlotList = tokenSlot->getSlotList();
	printf("\nInitializare token.......... ");
	int rv;

	USHORT pinLen = strlen(p11PinCodeSO);
	rv = this->library->getFunctionList()->C_InitToken(pSlotList[0], (CK_CHAR_PTR)p11PinCodeSO, pinLen, (CK_UTF8CHAR_PTR)label);
	if (rv != CKR_OK)
	{
		printf(" EROARE (status = 0x%08X)", rv);
		return 0;
	}
	printf("	OK");
	return 1;
}

int TokenManager::initializePIN(char * NEWp11PinCode)
{
	//sa fiu logat ca so intai
	int rv;
	
	printf("\nInitializare PIN dupa initializarea tokenului..........");
	USHORT pinLen = strlen(NEWp11PinCode);
	rv = this->library->getFunctionList()->C_InitPIN(this->tokenSession->getSession(), (CK_CHAR_PTR)NEWp11PinCode, pinLen);
	if (rv != CKR_OK)
	{
		printf("EROARE  (status = 0x%08X)", rv);
		return 0;
	}
	printf("	OK");
	return 1;
}

int TokenManager::ChangePINAsUser(char * OLDp11PinCode, char * NEWp11PinCode)
{
	int rv;
	printf("\nSchimbare pin.............ca utilizator ");

	USHORT oldPinLen = strlen(OLDp11PinCode);


	USHORT newPinLen = strlen(NEWp11PinCode);

	rv = this->library->getFunctionList()->C_SetPIN(this->tokenSession->getSession(), (CK_CHAR_PTR)OLDp11PinCode, oldPinLen, (CK_CHAR_PTR)NEWp11PinCode, newPinLen);
	if (rv != CKR_OK) {
		printf("EROARE la schibmare pin (0x%08X)", rv);
		return 0;
	}
	printf("OK");
	return 1;

}

int TokenManager::ChangePINAsSO(char * OLDp11PinCode, char * NEWp11PinCode)
{
	int rv;
	printf("\nSchimbare pin.............ca SO ");

	USHORT oldPinLen = strlen(OLDp11PinCode);


	USHORT newPinLen = strlen(NEWp11PinCode);

	rv = this->library->getFunctionList()->C_SetPIN(this->tokenSession->getSession(), (CK_CHAR_PTR)OLDp11PinCode, oldPinLen, (CK_CHAR_PTR)NEWp11PinCode, newPinLen);
	if (rv != CKR_OK) {
		printf("EROARE la schibmare pin (0x%08X)", rv);
		return 0;
	}
	printf("OK");
	return 1;
}



CK_RV TokenManager::retrieveTokenObjects() {

	//Retrieve certs
	//Retrieve keys
	//etc


	CK_RV rv = CKR_OK;

	CK_OBJECT_CLASS		certClass = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_BBOOL			isToken = true;
	CK_BYTE_PTR			subject = NULL_PTR;
	CK_BYTE_PTR			id = NULL_PTR;
	CK_BYTE				certificateValue[2048];

	CK_BYTE_PTR value;
	CK_ULONG value_len;

	CK_OBJECT_HANDLE	hObject[MAX_COUNT]; // Found objects handlers
	CK_ULONG			objectFound = 0;



	//Searching template
	CK_ATTRIBUTE objTemplate[]{

		{
			CKA_CLASS ,&certClass,sizeof(certClass)
		},
		{
			CKA_TOKEN, &isToken, sizeof(isToken)
		}

	};


	printf("\nSearching for objects...");
	rv = this->pFunctionList->C_FindObjectsInit(tokenSession->getSession(),
		objTemplate,
		2);

	if (rv != CKR_OK)
	{
		printf("ERROR Init 0x%08x", rv);
		return rv;
	}

	rv = this->pFunctionList->C_FindObjects(tokenSession->getSession(),
		hObject,
		MAX_COUNT,
		&objectFound);

	if (rv != CKR_OK)
	{
		printf("ERROR Search");
		return rv;
	}
	printf("found %d objects", objectFound);


	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////		Cert search 		////////////////////////////////////////////////////////////

	for (int i = 0; i < objectFound; i++)
	{
		printf("\nRetrieving object %d...", i);


		if (certList == NULL)
		{
			certList = (ObjectCertificate**)malloc(objectFound * sizeof(ObjectCertificate*));
		}

		assert(certList != NULL_PTR);

		certList[i] = (ObjectCertificate *)malloc(sizeof(ObjectCertificate));
		certList[i] = new ObjectCertificate(tokenSession->getSession(), hObject[i]);


	}
	certCount = objectFound;
	printf("\nClosing finding session...");
	rv = this->pFunctionList->C_FindObjectsFinal(tokenSession->getSession());
	if (rv != CKR_OK)
	{
		printf("ERROR Final");
		return rv;

	}
	printf("OK");




}

ObjectCertificate **TokenManager::getCertificates()
{
	return certList;
}

size_t TokenManager::getCertificatesCount()
{
	return certCount;
}
