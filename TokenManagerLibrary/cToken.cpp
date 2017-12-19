
#include "stdafx.h"
#define EXPORTING_DLL
#include "cToken.h"

cToken::cToken(CK_TOKEN_INFO tokenInfo)
{

	char buff[100];
	int newsize;
	
	this->tokenInfo = {};

	sprintf(buff, "%d.%d", tokenInfo.firmwareVersion.major, tokenInfo.firmwareVersion.minor);
	newsize = strlen(buff);

	
	this->tokenInfo.firmwareVersion = (char*)realloc(this->tokenInfo.firmwareVersion, newsize);
	strcpy((char*)this->tokenInfo.firmwareVersion, buff);


	sprintf(buff, "%d.%d", tokenInfo.hardwareVersion.major, tokenInfo.hardwareVersion.minor);
	newsize = strlen(buff)+1;
	this->tokenInfo.hardwareVersion = (char*)realloc(this->tokenInfo.hardwareVersion, newsize);
	strcpy(this->tokenInfo.hardwareVersion, buff);
	

	tokenInfo.label[31] = '\0';
	sprintf(buff, "%s", tokenInfo.label);
	newsize = strlen(buff) + 1;
	this->tokenInfo.label = (char*)realloc(this->tokenInfo.label, newsize);
	strcpy(this->tokenInfo.label, buff);
	

	tokenInfo.manufacturerID[31] = '\0';
	sprintf(buff, "%s", tokenInfo.manufacturerID);
	newsize = strlen(buff) + 1;
	this->tokenInfo.manufacturerId = (char*)realloc(this->tokenInfo.manufacturerId, newsize);
	strcpy(this->tokenInfo.manufacturerId, buff);


	tokenInfo.model[15] = '\0';
	sprintf(buff, "%s", tokenInfo.model);
	newsize =strlen(buff) + 1;
	this->tokenInfo.model = (char*)realloc(this->tokenInfo.model, newsize);	
	strcpy(this->tokenInfo.model, buff);
	


	tokenInfo.serialNumber[15] = '\0';
	sprintf(buff, "%s", tokenInfo.serialNumber);
	newsize = strlen(buff) + 1;
	this->tokenInfo.serialNumber = (char*)realloc(this->tokenInfo.serialNumber, newsize);
	strcpy(this->tokenInfo.serialNumber, buff);


	tokenInfo.utcTime[15] = '\0';
	sprintf(buff, "%s", tokenInfo.utcTime);
	newsize = strlen(buff) + 1;
	this->tokenInfo.label = (char*)realloc(this->tokenInfo.label, newsize);
	strcpy(this->tokenInfo.label, buff);
	

}

char * cToken::getFirmwareVersion()
{
	return this->tokenInfo.firmwareVersion;
}

char * cToken::getHardwareVersion()
{
	return this->tokenInfo.hardwareVersion;
}

char * cToken::getLabel()
{
	return this->tokenInfo.label;
}

char * cToken::getManufacturerId()
{
	return this->tokenInfo.manufacturerId;
}

char * cToken::getModel()
{
	return this->tokenInfo.model;
}

char * cToken::getSerialNumber()
{
	return this->tokenInfo.serialNumber;
}

char * cToken::getUTCTime()
{
	return this->tokenInfo.utcTime;
}

void cToken::printInfo() {
	printf("\n\tFirmware Version:%s", this->getFirmwareVersion());
	printf("\n\tHardware Version:%s", this->getHardwareVersion());
	printf("\n\tLabel:%s", this->getLabel());
	printf("\n\tManufacturer ID:%s", this->getManufacturerId());
	printf("\n\tModel:%s", this->getModel());
	printf("\n\tSerial No.:%s", this->getSerialNumber());
	printf("\n\tUTC Time:%s", this->getUTCTime());
}