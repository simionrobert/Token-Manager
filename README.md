# Token-Manager
Token Manager Project




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

**How to build**:
1. Right click Solution > Properties > Common Properties > StarupProject >Single startup project > TokenManagerTest

2. Right click TokenManagerTest > Properties > C/C++ > General > Additional Include Directories and put the directory path of TokenManagerLibrary.h (ex: pathToProject\TokenManager\TokenManagerLibrary)

3. Right click TokenManagerTest > Properties > Linker > General > Additional Library Directories and put the directory path of TokenManagerLibrary.dll (ex: pathToProject\TokenManager\Debug)

4. Right click TokenManagerTest > Properties > Linker > Input >Additional Dependencies and put the name of the library to import 
(ex: TokenManagerLibrary.lib)

5. Right click TokenManagerTest > General > Character Set > set to Multy-Byte Character Set

The same steps will be done with a GUI and the following:
- include in your project the TokenManagerLibrary.h from pathToProject\TokenManager\TokenManagerLibrary (it's the same, it's not necessary to copy it)

**Build Notes**:
Error SDK Version: Right click TokenManagerLibrary > Retarget projects

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
