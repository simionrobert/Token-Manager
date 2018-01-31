#ifndef SERVICE_MANAGER
#define SERVICE_MANAGER

#include "defined_tkn_mgr_header.h"
#include"windows.h"

class TKN_API ServiceManager {
public:
	void setServiceActivityStatus(bool status);
};


#endif