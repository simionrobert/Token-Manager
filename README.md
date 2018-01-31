# Token-Manager
This is a C++ library for managing cryptografic operations on a token. 

## Getting Started

**Project Currently in Development**

## Description

*TokenManagerLibrary* is the main library. The library can be used by a GUI Interface.

*TokenManagerTest* is used for testing the library. (useful for development)

*TokenService* is a C++ Windows Service which automatically imports certificates from tokens to the Windows Store. However, it can be configured not to import by setting a register value, whose address is HKEY_LOCAL_MACHINE\Software\TokenManager\Service. On 64 bit windows, it is HKEY_LOCAL_MACHINE\Software\WOW6432Node\TokenManager\Service

It uses eTPKCS11.dll, an implementation of PKCS#11 standard.

**Prequesties**:
- eTPKCS11.dll in C:/Windows/system32
- github extension for visual studio

**How to import in Visual Studio**
1. On the git page click **Clone or Download** > **Open in visual studio** button.
2. In visual studio click Clone button. 
3. In Solution Explorer double click TokenManager.sln or you can click on the .sln file direcly in the clone window (same windows as in the 2-nd step).
4. From now on you can sync with the origin/master when you like.

For those who don't have **Open in visual studio** button
1. Copy the link from  **Clone or Download** button
2. In visual Studio click Team > Manage Connections > LocalGit Repositories > Clone > Enter url > Click **clone** button
3. In Solution Explorer double click TokenManager.sln or you can click on the .sln file direcly in the clone window (same windows as in the 2-nd step).
4. From now on you can sync with the origin/master when you like.

## Build
**How to build TokenManagerLibrary**:
1. Right click TokenManagerLibrary > Properties > C/C++ > General > Additional Include Directories and put the directory path of OpenSSL's include folder (ex: pathToProject\TokenManager\TokenManagerLibrary\Libraries\Build-OpenSSL-VC-32-dbg\include)

3. Right click TokenManagerLibrary > Properties > Linker > General > Additional Library Directories and put the directory path of OpenSSL's libs folder (ex: pathToProject\TokenManager\TokenManagerLibrary\Libraries\Build-OpenSSL-VC-32-dbg\lib)

4. Right click TokenManagerLibrary > Properties > Linker > Input >Additional Dependencies and put the name of the OpenSSL's libraries to import them. (ex: libeay32.lib, ssleay32.lib)

5. Right click TokenManagerLibrary > General > Character Set > set to Multy-Byte Character Set

**How to build TokenManagerTest**:
1. Right click Solution > Properties > Common Properties > StarupProject >Single startup project > TokenManagerTest

2. Right click TokenManagerTest > Properties > C/C++ > General > Additional Include Directories and put the directory path of TokenManagerLibrary.h (ex: pathToProject\TokenManager\TokenManagerLibrary)

3. Right click TokenManagerTest > Properties > Linker > General > Additional Library Directories and put the directory path of TokenManagerLibrary.dll (ex: pathToProject\TokenManager\Debug)

4. Right click TokenManagerTest > Properties > Linker > Input >Additional Dependencies and put the name of the library to import 
(ex: TokenManagerLibrary.lib)

5. Right click TokenManagerTest > General > Character Set > set to Multy-Byte Character Set

**How to build TokenService**:
1. Do the same steps described above, but for TokenService.

**How to build for an external project which uses the library**
The same steps described at TokenManagerTest will be done on an external project, including:
- include in your project TokenManagerLibrary.h from pathToProject\TokenManager\TokenManagerLibrary (it's the same, it's not necessary to copy it)

**Build Notes**:
Error SDK Version: Right click TokenManagerLibrary > Retarget projects. 
If this doesn't work, try to  Right click TokenManagerLibrary > Properties > General > Platform Toolset and set what toolset you have.


Error Platform Toolset: Right click TokenManagerLibrary > Properties > General > Platform Toolset > Select what toolset you have (same for test)

**Aditional notes:**
If you have some issues referring parts of code in the master branch add them in the issues section.

## Authors

* **Simion Robert** (https://github.com/simionrobert)
* **Dedita Vlad** (https://github.com/vladdedita)
* **Lica Alexandru** (https://github.com/licaalexandru)
* **Stratulat Adrian** (https://github.com/Adistratulat)

* **Honceriu Tudor** (https://github.com/Tudorikass)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
