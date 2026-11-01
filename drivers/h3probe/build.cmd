@echo off
rem Build h3probe.sys beside this script, and optionally test-sign it.
rem
rem   build.cmd                  compile and link only
rem   build.cmd <sha1>           ...then sign with that code-signing certificate from CurrentUser\My
rem
rem VSROOT and KV can be set in the environment to override the Build Tools root and the WDK version.
setlocal
pushd "%~dp0"
if not defined VSROOT set "VSROOT=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools"
if not defined KV set "KV=10.0.26100.0"
set "KITS=C:\Program Files (x86)\Windows Kits\10"
for /f "delims=" %%i in ('dir /b /ad "%VSROOT%\VC\Tools\MSVC"') do set MSVCVER=%%i
set "MSVC=%VSROOT%\VC\Tools\MSVC\%MSVCVER%"
set CC="%MSVC%\bin\Hostx64\x64\cl.exe"
set LD="%MSVC%\bin\Hostx64\x64\link.exe"
set SIGNTOOL="%KITS%\bin\%KV%\x64\signtool.exe"
echo MSVC: %MSVCVER%  WDK: %KV%
%CC% /nologo /c /W4 /WX- /GS- /Gy /Z7 /Oi /kernel ^
  /I"%KITS%\Include\%KV%\km" /I"%KITS%\Include\%KV%\shared" ^
  /I"%KITS%\Include\%KV%\ucrt" /I"%MSVC%\include" ^
  /D_AMD64_ /DAMD64 /D_WIN64 /DNDEBUG ^
  h3probe.c /Foh3probe.obj
if errorlevel 1 goto failed
%LD% /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /NODEFAULTLIB /DEBUG ^
  /LIBPATH:"%KITS%\Lib\%KV%\km\x64" /LIBPATH:"%MSVC%\lib\x64" ^
  /OUT:h3probe.sys h3probe.obj ntoskrnl.lib hal.lib BufferOverflowFastFailK.lib aux_klib.lib wdmsec.lib
if errorlevel 1 goto failed
if "%~1"=="" goto built
%SIGNTOOL% sign /sha1 %~1 /fd sha256 h3probe.sys
if errorlevel 1 goto failed
:built
echo BUILD OK %CD%\h3probe.sys
popd
exit /b 0
:failed
popd
exit /b 1
