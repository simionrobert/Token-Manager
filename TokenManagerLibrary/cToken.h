

#include "stdafx.h"
#define EXPORTING_DLL
#include "cryptoki.h"

class cToken {

private:

		struct info{	
		char* firmwareVersion;
		char* hardwareVersion;
		char* label;
		char* manufacturerId;
		char *model;
		char *serialNumber;
		char *utcTime;
	};
		info tokenInfo;


public:
	cToken(CK_TOKEN_INFO tokenInfo);

	char *getFirmwareVersion();

	char *getHardwareVersion();

	char *getLabel();

	char *getManufacturerId();

	char *getModel();

	char *getSerialNumber();

	char *getUTCTime();

	void printInfo();


};