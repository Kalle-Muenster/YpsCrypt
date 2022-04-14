set _link_=%~dp0linkage
set _arch_=%~1
set _conf_=%~2
cd %~dp0
cd..
cd..
set _self_=%CD%\YpsCrypt\bin\%_arch_%\%_conf_%
set _24er_=%CD%\Int24Types\bin\core5\%_arch_%\%_conf_%
set _test_=%CD%\Consola\bin\core5\v142\%_arch_%\Test\%_conf_%\net5.0
cd %CD%\YpsCrypt\YpsTests

del /f /s /q "%_link_%\*.*"
echo copy /y /b "%_24er_%\Int24Types.dll" "%_link_%"
     copy /y /b "%_24er_%\Int24Types.dll" "%_link_%"
echo copy /y /b "%_test_%\Consola.dll" "%_link_%"
	 copy /y /b "%_test_%\Consola.dll" "%_link_%"
echo copy /y /b "%_test_%\Consola.Tests.dll" "%_link_%"
	 copy /y /b "%_test_%\Consola.Tests.dll" "%_link_%"
if "%_conf_%" == "Debug" (
echo copy /y /b "%_24er_%\Int24Types.pdb" "%_link_%"
	 copy /y /b "%_24er_%\Int24Types.pdb" "%_link_%"
echo copy /y /b "%_test_%\Consola.pdb" "%_link_%"
     copy /y /b "%_test_%\Consola.pdb" "%_link_%"
echo copy /y /b "%_test_%\Consola.Tests.pdb" "%_link_%"
     copy /y /b "%_test_%\Consola.Tests.pdb" "%_link_%"
)
echo Toblerone!
