/*
Aici definim toate functiile API-ului
Acest header il folosim in aplicatia principala sau de test
*/

#ifndef TKN_MNG_DLL
#define TKN_MNG_DLL

#ifdef EXPORTING_DLL
#define TKN_API __declspec(dllexport)
#else
#define TKN_API __declspec(dllimport)
#endif


TKN_API void HelloWorld();
TKN_API void incarcaLibrarie(char* numeLibrarie);
TKN_API void asteaptaToken();

#endif