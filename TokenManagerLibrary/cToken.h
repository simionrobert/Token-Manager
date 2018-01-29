
#ifndef CTOKEN_H
#define CTOKEN_H


#include "defined_tkn_mgr_header.h"
#include "cryptoki.h"

class TKN_API cToken {

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

#endif