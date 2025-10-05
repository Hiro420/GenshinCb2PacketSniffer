# GenshinCb2PacketSniffer
An injectable packet sniffer dll for an ancient version of the game

# Usage
- Compile via Visual Studio 2022
- The dll will be generated in an Win64 folder, next to the .sln
- Place [nitrog0d's cimgui.dll](https://github.com/nitrog0d/RLLoader/blob/main/RLLoader.Core/Libraries/cimgui.dll) next to the dll (also give him a star, his code is amazing)
- Inject to the process on startup

If you use mhynot2, you should preferably stop it from allocating the console\
You can do so by commenting out the lines 341-357 in dllmain.cpp

## If it fails to decode packets, restart the process. Probably didn't get lucky with the short window of time it has to perform the hook for the first two packets

## Should work on cbt1, but is untested (will also require you to update protocol definitions)

Copyright© Hiro420