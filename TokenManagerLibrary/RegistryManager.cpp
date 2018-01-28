#include "stdafx.h"
#define EXPORTING_DLL
#include "RegistryManager.h"
#include <windows.h>
#include <strsafe.h>
#include <malloc.h>
#include <stdio.h>

HKEY RegistryManager::openRegistryKey(HKEY hKeyRoot,const char* registryName)
{
	HKEY hKey;

	if ((RegOpenKeyEx(hKeyRoot, registryName, 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)) {
		printf("\nError opening the desired subkey (doesn't exist?)\n");
		return NULL;
	}
	else {
		printf("nSucceess!");
	}

	return hKey;
}

//*************************************************************
//
//  deleteRegistryKey()
//
//  Purpose:    Deletes a registry key and all its subkeys / values.
//
//  Parameters: hKeyRoot    -   Root key
//              lpSubKey    -   SubKey to delete
//
//  Return:     TRUE if successful.
//              FALSE if an error occurs.
//
//*************************************************************
int RegistryManager::deleteRegistryKey(HKEY hKeyRoot, LPTSTR lpSubKey)
{
	TCHAR szDelKey[MAX_PATH * 2];

	StringCchCopy(szDelKey, MAX_PATH * 2, lpSubKey);
	
	return RegDelnodeRecurse(hKeyRoot, szDelKey);
}

BOOL RegistryManager::RegDelnodeRecurse(HKEY hKeyRoot, LPTSTR lpSubKey)
{
	LPTSTR lpEnd;
	LONG lResult;
	DWORD dwSize;
	TCHAR szName[MAX_PATH];
	HKEY hKey;
	FILETIME ftWrite;

	// First, see if we can delete the key without having
	// to recurse.

	lResult = RegDeleteKey(hKeyRoot, lpSubKey);

	if (lResult == ERROR_SUCCESS)
		return TRUE;

	lResult = RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);

	if (lResult != ERROR_SUCCESS)
	{
		if (lResult == ERROR_FILE_NOT_FOUND) {
			printf("Key not found.\n");
			return TRUE;
		}
		else {
			printf("Error opening key.\n");
			return FALSE;
		}
	}

	// Check for an ending slash and add one if it is missing.

	lpEnd = lpSubKey + lstrlen(lpSubKey);

	if (*(lpEnd - 1) != TEXT('\\'))
	{
		*lpEnd = TEXT('\\');
		lpEnd++;
		*lpEnd = TEXT('\0');
	}

	// Enumerate the keys

	dwSize = MAX_PATH;
	lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
		NULL, NULL, &ftWrite);

	if (lResult == ERROR_SUCCESS)
	{
		do {
			StringCchCopy(lpEnd, MAX_PATH * 2, szName);

			if (!RegDelnodeRecurse(hKeyRoot, lpSubKey)) {
				break;
			}

			dwSize = MAX_PATH;

			lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
				NULL, NULL, &ftWrite);

		} while (lResult == ERROR_SUCCESS);
	}

	lpEnd--;
	*lpEnd = TEXT('\0');

	RegCloseKey(hKey);

	// Try again to delete the key.

	lResult = RegDeleteKey(hKeyRoot, lpSubKey);

	if (lResult == ERROR_SUCCESS)
		return TRUE;

	return FALSE;
}

int RegistryManager::createRegistryKey(HKEY hKeyRoot,const char * keyName)
{
	DWORD dwDisposition = 0;
	HKEY hKey;

	int errCode = RegCreateKeyEx(hKeyRoot,
		keyName,
		0,
		NULL,
		REG_OPTION_NON_VOLATILE,
		KEY_ALL_ACCESS,
		NULL,
		&hKey,
		&dwDisposition);

	if (errCode == ERROR_SUCCESS) {

		if (dwDisposition != REG_CREATED_NEW_KEY && dwDisposition != REG_OPENED_EXISTING_KEY) {
			goto err;
		}

		printf("\nThe key was successfully created.\n");


		RegCloseKey(hKey);
		return 0;
	}

err:
	printf("\nError creating the desired key (permissions?).\n");
	return 1;
}

int RegistryManager::setRegistryValue(HKEY hKeyRoot,const char * keyName, char* valueName, const unsigned  char* valueData, int valueDataLenght)
{
	HKEY hKey = openRegistryKey(hKeyRoot,keyName);
	if (hKey == NULL) {
		printf("\nKey does not exist\n");
		return 1;
	}


	if (RegSetValueEx(hKey, valueName, NULL, REG_SZ, valueData, sizeof(unsigned char*)*valueDataLenght) == ERROR_SUCCESS) {
		printf("\nThe value of the key was set successfully.\n");
	}
	else {
		printf("\nError setting the value of the key.\n");
		return 1;
	}

	RegCloseKey(hKey);
	return 0;
}

int RegistryManager::readValueFromRegistry(HKEY hKeyRoot,const char* keyName, const char* valueName, TCHAR*& valueData, DWORD& valueLenght)
{
	HKEY hKey = openRegistryKey(hKeyRoot,keyName);
	if (hKey == NULL) {
		printf("\nKey does not exist\n");
		return 1;
	}

	DWORD BufferSize = 128;
	DWORD dwRet;

	valueData = (TCHAR*)malloc(128);

	DWORD valueLenghtTemp = BufferSize;

	dwRet = RegQueryValueEx(hKey,
		valueName,
		NULL,
		NULL,
		(LPBYTE)valueData,
		&valueLenghtTemp);
	
	while (dwRet == ERROR_MORE_DATA)
	{
		// Get a buffer that is big enough.

		BufferSize += 128;
		valueData = (TCHAR*)realloc(valueData, BufferSize);
		valueLenghtTemp = BufferSize;

		printf(".");
		dwRet = RegQueryValueEx(hKey,
			valueName,
			NULL,
			NULL,
			(LPBYTE)valueData,
			&valueLenghtTemp);
	}

	RegCloseKey(hKey);
	if (valueLenght != NULL) {
		valueLenght = valueLenghtTemp;
	}

	if (dwRet == ERROR_SUCCESS) {
		printf("\nValue of %s\\%s is %s\n", keyName, valueName, valueData);
	}
	else {
		printf("\nRegQueryValueEx failed (%d)\n", dwRet);
		return dwRet;
	}
		

	return 0;
}

