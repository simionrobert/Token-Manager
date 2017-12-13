# Token-Manager
Token Manager Project


**Prequesties**:
-eTPKCS11.dll in C:/Windows/system32



**How to build**:
1. Right click Solution > Properties > Common Properties > StarupProject >Single startup project > TokenManagerTest

2. Right click TokenManagerTest > Properties > C/C++ > General > Additional Include Directories and put the directory path of TokenManagerLibrary.h (ex: pathToProject\TokenManager\TokenManagerLibrary)

3. Right click TokenManagerTest > Properties > Linker > General > Additional Library Directories and put the directory path of TokenManagerLibrary.dll (ex: pathToProject\TokenManager\Debug)

4. Right click TokenManagerTest > Properties > Linker > Input >Additional Dependencies and put the name of the library to import 
(ex: TokenManagerLibrary.lib)

The same steps will be done with a GUI and the following:
- include in your project the TokenManagerLibrary.h from pathToProject\TokenManager\TokenManagerLibrary (it's the same, it's not necessary to copy it)



**Aditional notes:**
If you have some issues referring parts of code in the master branch add them in the issues section.
