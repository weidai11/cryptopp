@echo OFFse
REM set THIS_DIR=%~dp0
set THIS_DIR=.

attrib -R -A -S -H  "%THIS_DIR%\*.aps"
attrib -R -A -S -H  "%THIS_DIR%\*.ncb"
attrib -R -A -S -H  "%THIS_DIR%\*.suo"
attrib -R -A -S -H  "%THIS_DIR%\*.sdf"
attrib -R -A -S -H  "%THIS_DIR%\*.user"

del "%THIS_DIR%\*.aps" /q
del "%THIS_DIR%\*.ncb" /q
del "%THIS_DIR%\*.suo" /q
del "%THIS_DIR%\*.sdf" /q
del "%THIS_DIR%\*.user" /q
del "%THIS_DIR%\*.diff" /q
del "%THIS_DIR%\adhoc.cpp" /q
del "%THIS_DIR%\cryptopp.mac.done" /q
del "%THIS_DIR%\adhoc.cpp.copied" /q

REM Visual Studio build artifacts
rmdir /Q /S "%THIS_DIR%\Debug\"
rmdir /Q /S "%THIS_DIR%\Release\"
rmdir /Q /S "%THIS_DIR%\Win32\"
rmdir /Q /S "%THIS_DIR%\x64\"
rmdir /Q /S "%THIS_DIR%\ipch\"
rmdir /Q /S "%THIS_DIR%\.vs\"

REM Visual Studio VCUpgrade artifacts
del "%THIS_DIR%\*.old" /q
del "%THIS_DIR%\UpgradeLog.htm" /q
del "%THIS_DIR%\UpgradeLog.XML" /q
rmdir /Q /S "%THIS_DIR%\_UpgradeReport_Files\"
rmdir /Q /S "%THIS_DIR%\Backup\"

REM New Visual Studio artifacts after a VCUpgrade 2010
REM attrib -R -A -S -H  "%THIS_DIR%\*.filters"
REM del "%THIS_DIR%\*.filters" /q
REM del "%THIS_DIR%\*.vcxproj" /q