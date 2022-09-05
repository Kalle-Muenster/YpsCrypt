@if not "ECHO_STATE"=="" (@echo %ECHO_STATE%) else (@echo off)
set _here_=%CD%
cd /d %~dp0
cd YpsCrypt50
dotnet restore
cd..
cd YpsTests
dotnet restore YpsTests50.csproj
cd /d %_here_%
set _here_=

