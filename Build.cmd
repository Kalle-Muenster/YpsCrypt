@if "%ECHO_STATE%"=="" (@echo off ) else (@echo %ECHO_STATE% )

:: Prepare locations
set _name_=YpsCrypt
set _call_=%CD%
cd %~dp0
set _here_=%CD%
set _root_=%CD%

:: Set VersionNumber
set YpsCryptVersionNumber=00000001
set YpsCryptVersionString=0.0.0.1
set DotNetVersionString=core5

:: Set Dependencies
if "%ConsolaBinRoot%"=="" (
set ConsolaBinRoot=C:\WORKSPACE\PROJECTS\GITSPACE\Consola\bin\%DotNetVersionString%
)
if "%Int24TypesBinRoot%"=="" (
set Int24TypesBinRoot=C:\WORKSPACE\PROJECTS\GITSPACE\Int24Types\bin\%DotNetVersionString%
)

:: Set parameters and solution files
call Args "%~1" "%~2" "%~3" "%~4" YpsCryps.sln YpsTests.sln

:: Do the Build
cd %_here_%
call MsBuild %_target_% %_args_%
cd %_call_%

:: Cleanup Environment
call Args ParameterCleanUp

