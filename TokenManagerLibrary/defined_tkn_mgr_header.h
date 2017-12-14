#ifndef DEFINED_TOKEN_MANAGER_HEADER
#define DEFINED_TOKEN_MANAGER_HEADER

#ifdef EXPORTING_DLL
	#define TKN_API __declspec(dllexport)
#else
	#define TKN_API __declspec(dllimport)
#endif

#endif 
