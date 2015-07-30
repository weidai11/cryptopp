@echo OFFse
REM set THIS_DIR=%~dp0
set THIS_DIR=.

attrib -R -A -S -H  "%THIS_DIR%\*.suo"
attrib -R -A -S -H  "%THIS_DIR%\*.sdf"
attrib -R -A -S -H  "%THIS_DIR%\*.vcxproj"
attrib -R -A -S -H  "%THIS_DIR%\*.filters"

del "%THIS_DIR%\*.suo" /q
del "%THIS_DIR%\*.sdf" /q
del "%THIS_DIR%\*.user" /q
del "%THIS_DIR%\*.filters" /q
del "%THIS_DIR%\*.vcxproj" /q
del "%THIS_DIR%\*.diff" /q
del "%THIS_DIR%\adhoc.cpp" /q
del "%THIS_DIR%\adhoc.cpp.copied" /q
del  "%THIS_DIR%\UpgradeLog.htm" /q

REM Visual Studio project conversion
rmdir /Q /S "%THIS_DIR%\Backup\"
rmdir /Q /S "%THIS_DIR%\Debug\"
rmdir /Q /S "%THIS_DIR%\Release\"
rmdir /Q /S "%THIS_DIR%\Win32\"
rmdir /Q /S "%THIS_DIR%\x64\"
rmdir /Q /S "%THIS_DIR%\ipch\"
rmdir /Q /S "%THIS_DIR%\.vs\"