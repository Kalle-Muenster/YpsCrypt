@if "%ECHO_STATE%"=="" (@echo off ) else (@echo %ECHO_STATE% )

:: Prepare locations
set _name_=YpsCrypt
set _call_=%CD%
cd %~dp0
set _here_=%CD%
set _root_=%CD%

:: Set VersionNumber
set YpsCryptVersionNumber=00000003
set YpsCryptVersionString=0.0.0.3

if "%DotNetVersionString%"=="dot48" set DotNetVersionNumber=48
if "%DotNetVersionString%"=="dot60" set DotNetVersionNumber=60
if "%DotNetVersionString%"=="core5" set DotNetVersionNumber=50

:: Set Dependencies
if "%ConsolaBinRoot%"=="" (
set ConsolaBinRoot=%_root_%\..\Consola\bin\%DotNetVersionString%
)
if "%Int24TypesBinRoot%"=="" (
set Int24TypesBinRoot=%_root_%\..\Int24Types\bin\%DotNetVersionString%
)

:: Set parameters and solution files
call %_root_%\Args "%~1" "%~2" "%~3" "%~4" YpsCrypt%DotNetVersionNumber%.sln YpsTests%DotNetVersionNumber%.sln

:: Do the Build
cd %_here_%
call MsBuild %_target_% %_args_%
cd %_call_%

:: Cleanup Environment
call %_root_%\Args ParameterCleanUp

