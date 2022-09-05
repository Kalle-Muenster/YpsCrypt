@echo off

if "%~1"=="core5" (
set DotnetVersionString=core5
goto END
)

if "%~1"=="dot48" (
set DotnetVersionString=dot48
goto END
)

set ConsolaProject=%~dp0..\Consola\Consola%DotnetVersionString%
set Int24TypesProject=%~dp0..\Int24Types\%DotnetVersionString%


set ARCH=%~1
set CONF=%~2
set CLEAN=%~3

pushd %ConsolaProject%
call Build.cmd "%ARCH%" "%CONF%" %CLEAN%
call Build.cmd "%ARCH%" "%CONF%" Test %CLEAN%
popd

pushd "%Int24TypesProject%"
call Build.cmd "%ARCH%" "%CONF%" %CLEAN%
popd

pushd "%~dp0"
call Build.cmd "%ARCH%" "%CONF%" %CLEAN%
call Build.cmd "%ARCH%" "%CONF%" Test %CLEAN%
popd

set ARCH=
set CONF=
set CLEAN=
:END
