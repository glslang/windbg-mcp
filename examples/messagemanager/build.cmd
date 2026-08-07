@echo off
rem Build a MessageManager tool with the host MSVC toolchain.
rem Usage: build.cmd <source.c> [out.exe]
setlocal
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat
if not exist "%VCVARS%" (
  echo vcvars64.bat not found at "%VCVARS%"
  exit /b 1
)
call "%VCVARS%" >nul
if "%~2"=="" ( set OUT=%~dpn1.exe ) else ( set OUT=%~2 )
cl /nologo /W3 /O2 /GS- /Fe:"%OUT%" "%~1" /link /SUBSYSTEM:CONSOLE ntdll.lib advapi32.lib
endlocal
