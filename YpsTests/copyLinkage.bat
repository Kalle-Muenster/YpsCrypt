set _link_=%~dp0linkage
set _arch_=%~1
set _conf_=%~2
set _24er_=C:\WORKSPACE\PROJECTS\Int24Types\bin\core5\%_arch_%\%_conf_%
set _self_=C:\WORKSPACE\PROJECTS\YpsCrypt\bin\%_arch_%\%_conf_%
set _line_=C:\WORKSPACE\PROJECTS\ConsolaStreams\bin\core5\v143\%_arch_%\%_conf_%
del /f /s /q "%_link_%\*.*"
:: copy /y /b "%_audi_%\*.dll" "%_link_%"
copy /y /b "%_line_%\StdStreams.dll" "%_link_%"
copy /y /b "%_24er_%\Int24Types.dll" "%_link_%"
copy /y /b "%_self_%\YpsCryps.dll" "%_link_%"
if "%_conf_%" == "Debug" (
::	copy /y /b "%_audi_%\*.pdb" "%_link_%"
	copy /y /b "%_line_%\StdStreams.pdb" "%_link_%"
	copy /y /b "%_24er_%\Int24Types.pdb" "%_link_%"
	copy /y /b "%_self_%\YpsCryps.pdb" "%_link_%"
)
echo Toblerone!

