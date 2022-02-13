REM  cryptdll-windows.cmd - written and placed in public domain by Jeffrey Walton
REM                         Copyright assigned to the Crypto++ project.
REM
REM  For details see https://cryptopp.com/wiki/MSBuild_(Command_Line)
REM

REM  Build the Win32/Debug cryptest.exe
msbuild /t:Build /p:Configuration=Debug;Platform=Win32 cryptlib.vcxproj
msbuild /t:Build /p:Configuration=Debug;Platform=Win32 cryptest.vcxproj

REM  Build the Win32/Release cryptopp.dll
msbuild /t:Build /p:Configuration=Release;Platform=Win32 cryptdll.vcxproj

REM  Build the FIPS test driver
msbuild /t:Build /p:Configuration=Release;Platform=Win32 dlltest.vcxproj

REM  Run the FIPS test driver
.\Win32\DLL_Output\Release\dlltest.exe
