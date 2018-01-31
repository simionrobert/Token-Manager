#include "stdafx.h"
#define EXPORTING_DLL

#include "TokenManager.h"
#include <assert.h>
#include <Wincrypt.h>
#include <cryptuiapi.h>
#include <tchar.h>
#include <winscard.h>
#include <io.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "cryptui.lib")

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

TokenManager::TokenManager(PKCS11Library * library, TokenSlot * tokenSlot, TokenSession * session)
{
	certList = NULL;
	certCount = 0;
	keyList = NULL;
	keyCount = 0;
	symmetricKeyList = NULL;
	sKeyCount = 0;
	//assert(library != NULL);
	this->library = library;
	this->tokenSlot = tokenSlot;
	this->tokenSession = session;

	this->pFunctionList = library->getFunctionList();
	//assert(this->pFunctionList != NULL);

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

	manager->readValueFromRegistry(HKEY_LOCAL_MACHINE, "Software\\TokenManager", "Service", valueRead, valueReadLenght);

	if (valueRead == NULL) {
		manager->readValueFromRegistry(HKEY_LOCAL_MACHINE, "Software\\WOW6432Node\\TokenManager", "Service", valueRead, valueReadLenght);
	}
	if (valueRead == NULL)
		goto err;

	if (memcmp(valueRead, "1", 2) == 0) {

		if (rv == CKR_OK)
		{
			rv = pFunctionList->C_GetSlotInfo(slotID, &slotInfo);
			if (slotInfo.flags & CKF_TOKEN_PRESENT)
			{
				rv = this->tokenSession->openSession(0);
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


int TokenManager::formatToken(char* SOPIN, char* label, char* newPIN,int slotToken)
{
	//return CKR_OK if ok; else return sth !=CKR_OK
	this->initializeToken(SOPIN, label, slotToken);
	this->tokenSession->openSession(slotToken);
	this->tokenSession->authentificateAsSO(SOPIN, slotToken);
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

int TokenManager::unblockPIN(char* soPIN,char*newPIN,int slotTokenNumber)
{
	//return CKR_OK if ok; else return sth !=CKR_OK
	this->tokenSession->openSession(slotTokenNumber);
	this->tokenSession->authentificateAsSO(soPIN, slotTokenNumber);
	this->initializePIN(newPIN);
	return 1;
}

int TokenManager::initializeToken(char *p11PinCodeSO,char* label,int tokenSlotNumber)
{
	CK_SLOT_ID_PTR pSlotList = tokenSlot->getSlotList();
	printf("\nInitializare token.......... ");
	int rv;

	USHORT pinLen = strlen(p11PinCodeSO);
	rv = this->library->getFunctionList()->C_InitToken(pSlotList[tokenSlotNumber], (CK_CHAR_PTR)p11PinCodeSO, pinLen, (CK_UTF8CHAR_PTR)label);
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





BOOL LoadPrivateKey(LPBYTE pbBlob, DWORD cbSize, PCCERT_CONTEXT pCertContext, CHAR szContainerName[1024])
{
	DWORD dwLen = 0;
	HCRYPTPROV hProv;
	BOOL bRet = CryptAcquireContext(&hProv, NULL, MS_SCARD_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET);
	if (bRet)
	{
		// get the container name
		dwLen = 1024;
		CryptGetProvParam(hProv, PP_CONTAINER, (BYTE*)szContainerName, &dwLen, 0);

		HCRYPTKEY hKey;
		bRet = CryptImportKey(hProv, pbBlob, cbSize, NULL, 0, &hKey);
		if (bRet)
		{
			bRet = CryptSetKeyParam(hKey, KP_CERTIFICATE, pCertContext->pbCertEncoded, 0);
			if (!bRet)
			{
				DWORD dwError = GetLastError();
				_tprintf(_T("Failed to import the certificate into the smart card. Error 0x%.8X\n"), dwError);
			}

			CryptDestroyKey(hKey);
		}
		else
		{
			DWORD dwError = GetLastError();
			_tprintf(_T("Failed to import the private key into the smart card. Error 0x%.8X\n"), dwError);
		}

		CryptReleaseContext(hProv, 0);

		if (!bRet)
		{
			// delete the container because of the error
			CryptAcquireContextA(&hProv, szContainerName, MS_SCARD_PROV_A, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
		}
	}
	else
	{
		DWORD dwError = GetLastError();
		_tprintf(_T("Failed to create a new container on the smart card. Error 0x%.8X\n"), dwError);
	}

	return bRet;
}

void TokenManager::getPFXfromFile(char* filePath,char* parola) {

	PCCERT_CONTEXT   pCertContext = NULL;
	char pszNameString[256];

	void*            pvData;
	DWORD            cbData;
	DWORD            dwPropId = 0;
	LPWSTR szPassword = NULL;
	size_t passLen = 0;

	int lungimeParola = strlen(parola);
	wchar_t* wtext = (wchar_t*)malloc((lungimeParola + 1) * sizeof(wchar_t));
	mbstowcs(wtext, parola, lungimeParola + 1);//Plus null
	szPassword = wtext;

	
	passLen = wcslen(szPassword) + 1;

	// Parse the P12 file
	FILE* pfxFile = _tfopen(filePath, _T("rb"));
	if (!pfxFile)
	{
		_tprintf(_T("Failed to open P12 file for reading\n"));
		return;
	}

	long pfxLength = _filelength(_fileno(pfxFile));
	LPBYTE pbPfxData = (LPBYTE)LocalAlloc(0, pfxLength);
	fread(pbPfxData, 1, pfxLength, pfxFile);
	fclose(pfxFile);

	// Decrypt the content of the PFX file
	CRYPT_DATA_BLOB pfxBlob;
	pfxBlob.cbData = pfxLength;
	pfxBlob.pbData = pbPfxData;

	HCERTSTORE hPfxStore = PFXImportCertStore(&pfxBlob, szPassword, CRYPT_EXPORTABLE);
	if (!hPfxStore)
	{
		if (wcslen(szPassword) == 0)
		{
			// Empty password case. Try with NULL as advised by MSDN
			hPfxStore = PFXImportCertStore(&pfxBlob, NULL, CRYPT_EXPORTABLE);
		}
	}

	if (!hPfxStore)
	{
		_tprintf(_T("Failed to decrypt P12 file content. Please check you typed the correct password"));
		return;
	}

	// Enumerate all certificate on the PFX file
	DWORD dwCertsLoaded = 0;
	DWORD cbSize = 0;
	PCRYPT_KEY_PROV_INFO pKeyInfo = NULL;
	LPTSTR szValue = NULL;

	while ((pCertContext = CertEnumCertificatesInStore(hPfxStore, pCertContext)))
	{
		CertGetNameString(pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, pszNameString, 128);
		printf("Certificate name: %s\n", pszNameString);

		//LUAM COMPONENTELE CHEII (PCRYPTT_KEY_PROV_INFO)

		DWORD dwSize = 0;
		BOOL bIsSuccess = CertGetCertificateContextProperty(pCertContext,
			CERT_KEY_PROV_INFO_PROP_ID,
			NULL,
			&dwSize);
		PCRYPT_KEY_PROV_INFO pKeyProvInfo = (PCRYPT_KEY_PROV_INFO)LocalAlloc(LMEM_ZEROINIT, dwSize);
		bIsSuccess = CertGetCertificateContextProperty(pCertContext,
			CERT_KEY_PROV_INFO_PROP_ID,
			pKeyProvInfo,
			&dwSize);

		HCRYPTPROV hProv = NULL;
		HCRYPTKEY hKey = NULL;
		BOOL bStatus = CryptAcquireContextW(&hProv,
			pKeyProvInfo->pwszContainerName,
			pKeyProvInfo->pwszProvName,
			pKeyProvInfo->dwProvType,
			pKeyProvInfo->dwFlags);
		if (bStatus)
		{
			bStatus = CryptGetUserKey(hProv, pKeyProvInfo->dwKeySpec, &hKey);
			if (bStatus)
			{
				bStatus = CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, NULL, &dwSize);
				if (bStatus)
				{
					LPBYTE pbBlob = (LPBYTE)LocalAlloc(0, dwSize);
					bStatus = CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, pbBlob, &dwSize);
					if (bStatus)
					{
						CHAR szContainerName[1024] = { 0 };
						if (LoadPrivateKey(pbBlob, dwSize, pCertContext, szContainerName))
						{
							//DisplayCertificate(pCertContext, szContainerName, ++dwCertsLoaded);
							printf("Merge ba!\n\n");
						}
						else
						{
							printf("Boom a headshot!\n\n");
						}
					}
					SecureZeroMemory(pbBlob, dwSize);
					LocalFree(pbBlob);
				}

				CryptDestroyKey(hKey);
			}
			CryptReleaseContext(hProv, 0);

			// Delete the key and its container from disk
			// We don't want the key to be persistant
			CryptAcquireContextW(&hProv,
				pKeyProvInfo->pwszContainerName,
				pKeyProvInfo->pwszProvName,
				pKeyProvInfo->dwProvType,
				CRYPT_DELETEKEYSET);
		}
		DWORD err = GetLastError();
		printf("%02x\n", err);
		LocalFree(pKeyProvInfo);

	}

}


//////////////////////////////////////////////////////////////////////////
///////////////////////////////ded/////////////////////////////////////////


CK_RV TokenManager::retrieveCerts() {
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
CK_RV TokenManager::retrievePrivateKeys() {


	CK_RV rv;
	CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
	
	};

	CK_ULONG objectCount;
	CK_OBJECT_HANDLE object[MAX_COUNT];

	rv = pFunctionList->C_FindObjectsInit(this->tokenSession->getSession(), keyTemplate, 1);
	assert(rv == CKR_OK, "Find objects init");


	rv = pFunctionList->C_FindObjects(this->tokenSession->getSession(), object, MAX_COUNT, &objectCount);
	assert(rv == CKR_OK, "Find first object");

	printf("\n\tFound %d keys...", objectCount);
	for (int i = 0; i < objectCount; i++)
	{
		if (keyList == NULL)
		{
			keyList = (ObjectPrivateKey**)malloc(objectCount * sizeof(ObjectPrivateKey*));
		}

		assert(keyList != NULL_PTR);

		keyList[i] = (ObjectPrivateKey *)malloc(sizeof(ObjectPrivateKey));
		keyList[i] = new ObjectPrivateKey(tokenSession->getSession(), object[i]);
	}
	keyCount = objectCount;


	rv = pFunctionList->C_FindObjectsFinal(this->tokenSession->getSession());
	assert(rv == CKR_OK, "Find objects final");

	return rv;

}
CK_RV TokenManager::retrieveSymmetricKeys() {


	CK_KEY_TYPE				keyType = CKK_DES;
	CK_BBOOL				isTrue = CK_TRUE;


	CK_RV rv;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_ATTRIBUTE keyTemplateAES[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &isTrue, sizeof(isTrue) }
	};

	CK_ULONG objectCount;
	CK_OBJECT_HANDLE object[MAX_COUNT];

	rv = pFunctionList->C_FindObjectsInit(this->tokenSession->getSession(), keyTemplateAES, 3);
	assert(rv == CKR_OK, "Find objects init");


	rv = pFunctionList->C_FindObjects(this->tokenSession->getSession(), object, MAX_COUNT, &objectCount);
	assert(rv == CKR_OK, "Find first object");

	printf("\n\tFound %d AES keys...", objectCount);
	for (int i = 0; i < objectCount; i++)
	{
		if (symmetricKeyList == NULL)
		{
			symmetricKeyList = (ObjectSymmetricKey**)malloc(objectCount * sizeof(ObjectSymmetricKey*));
		}

		assert(symmetricKeyList != NULL_PTR);

		symmetricKeyList[sKeyCount] = (ObjectSymmetricKey *)malloc(sizeof(ObjectSymmetricKey));
		symmetricKeyList[sKeyCount] = new ObjectSymmetricKey(tokenSession->getSession(), object[i]);
		sKeyCount++;
	}
	rv = pFunctionList->C_FindObjectsFinal(this->tokenSession->getSession());
	assert(rv == CKR_OK, "Find objects final");

	for (int i = 0; i < objectCount; i++)
		object[i] = NULL;
	objectCount = 0;



	keyType = CKK_DES;

	CK_ATTRIBUTE keyTemplateDES[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &isTrue, sizeof(isTrue) }
	};


	rv = pFunctionList->C_FindObjectsInit(this->tokenSession->getSession(), keyTemplateDES, 3);
	assert(rv == CKR_OK, "Find objects init");

	rv = pFunctionList->C_FindObjects(this->tokenSession->getSession(), object, MAX_COUNT, &objectCount);
	assert(rv == CKR_OK, "Find first object");

	printf("\n\tFound %d DES keys...", objectCount);
	for (int i = 0; i < objectCount; i++)
	{
		if (symmetricKeyList == NULL)
		{
			symmetricKeyList = (ObjectSymmetricKey**)malloc(objectCount * sizeof(ObjectSymmetricKey*));
		}

		assert(symmetricKeyList != NULL_PTR);

		symmetricKeyList[sKeyCount] = (ObjectSymmetricKey *)malloc(sizeof(ObjectSymmetricKey));
		symmetricKeyList[sKeyCount] = new ObjectSymmetricKey(tokenSession->getSession(), object[i]);
		sKeyCount++;
	}
	rv = pFunctionList->C_FindObjectsFinal(this->tokenSession->getSession());
	assert(rv == CKR_OK, "Find objects final");


	return rv;

}


CK_RV TokenManager::retrieveTokenObjects() {


	//Retrieve certs
	retrieveCerts();
	//Retrieve keys
	retrievePrivateKeys();
	//etc
	retrieveSymmetricKeys();
	return CKR_OK;

}

ObjectCertificate **TokenManager::getCertificates()
{
	return certList;
}

size_t TokenManager::getCertificatesCount()
{
	return certCount;
}

ObjectPrivateKey ** TokenManager::getKeys()
{
	return keyList;
}

size_t TokenManager::getKeysCount()
{
	return keyCount;
}

ObjectSymmetricKey ** TokenManager::getSymmetricKeys()
{
	return symmetricKeyList;
}

size_t TokenManager::getSymmetricKeysCount()
{
	return sKeyCount;
}

CK_RV TokenManager::deleteCertificate(unsigned int i)
{

	CK_RV rv = CKR_OK;
	CK_ATTRIBUTE templateIDAttribute[] = {
		{ CKA_ID, NULL , 0 },
	};

	CK_BYTE_PTR valoare2 = (CK_BYTE_PTR)getAttribute(i, this->tokenSession->getSession(), templateIDAttribute, 1)->pValue;
	DWORD lenvaloare2 = (DWORD)getAttribute(i, this->tokenSession->getSession(), templateIDAttribute, 1)->ulValueLen;
	if (lenvaloare2 ==0)	//ESTE CERTIFICAT SIMPLU
	{
		rv = pFunctionList->C_DestroyObject(this->tokenSession->getSession(), i);
		return rv;
	}
	else     //ESTE PFX SI TREBUIE SA STERGEM SI CHEIA
	{
		ObjectPrivateKey**list = this->keyList;
		for (int j = 0; j < this->keyCount; j++)
		{
			int handleobj = list[j]->getObjectId();
			CK_ATTRIBUTE templateIDAttributePK[] = {
				{ CKA_ID, NULL , 0 },
			};

			CK_BYTE_PTR value = (CK_BYTE_PTR)getAttribute(handleobj, this->tokenSession->getSession(), templateIDAttributePK, 1)->pValue;
			DWORD lenvalue = (DWORD)getAttribute(handleobj, this->tokenSession->getSession(), templateIDAttributePK, 1)->ulValueLen;
			if (memcmp(valoare2,value, lenvaloare2)==0)	//ID-UL KEY-ULUI ESTE EGAL CU ID-UL ID-UL CERTIFICATULUI
			{
				rv = pFunctionList->C_DestroyObject(this->tokenSession->getSession(), i);
				rv = deletePrivateKey(handleobj);
				break;
			}
			
		}
	}
	return rv;
}

CK_RV TokenManager::deletePrivateKey(unsigned int i)
{
	CK_RV rv = CKR_OK;
	rv = pFunctionList->C_DestroyObject(this->tokenSession->getSession(), i);
	return rv;
}

CK_RV TokenManager:: deleteSymmetricKey(unsigned int i)
{
	CK_RV rv = CKR_OK;
	rv = pFunctionList->C_DestroyObject(this->tokenSession->getSession(), i);
	return rv;
}

void scrieCertificat(BYTE* pvalue, int val_len, char* nume_fisier) {

	FILE *fp;
	errno_t err;

	if ((err = fopen_s(&fp, nume_fisier, "wb")) != 0)
		printf("File was not opened\n");
	else
	{
		for (int j = 0; j < val_len; j++)
		{
			fprintf(fp, "%c", pvalue[j]);
		}
	}

	fclose(fp);


}



void TokenManager::ExportCertificat(CK_OBJECT_HANDLE handle, CK_SESSION_HANDLE session, char* filePath) {

	CK_ATTRIBUTE templateValue[] = {
		{ CKA_VALUE, NULL , 0 }
	};

	CK_ATTRIBUTE* atribute = getAttribute(handle, session, templateValue, 1);

	scrieCertificat((BYTE*)atribute[0].pValue, atribute[0].ulValueLen, filePath);


}

