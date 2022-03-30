set _link_=%~dp0linkage
set _arch_=%~1
set _conf_=%~2
set _24er_=C:\WORKSPACE\PROJECTS\Int24Types\bin\core5\%_arch_%\%_conf_%
:: set _audi_=C:\WORKSPACE\PROJECTS\WaveFileHandling\bin\dotnet\core5\v143\%_conf_%\%_arch_%
:: set _line_=C:\WORKSPACE\PROJECTS\ConsolaStreams\bin\core5\v143\%_arch_%\%_conf_%
del /f /s /q "%_link_%\*.*"
  copy /y /b "%_24er_%\*.*" "%_link_%"
:: copy /y /b "%_audi_%\*.dll" "%_link_%"
:: copy /y /b "%_line_%\StdStreams.dll" "%_link_%"
:: if "%_conf_%" == "Debug" (
::	copy /y /b "%_audi_%\*.pdb" "%_link_%"
::	copy /y /b "%_line_%\StdStreams.pdb" "%_link_%"
:: )


