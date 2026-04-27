@echo off

SETLOCAL EnableDelayedExpansion

IF "%1"=="" (
 echo syntax: encrypt_pe.bat ^<src PE^> ^<output encrypted PE^>
 echo need argument: input PE file
 goto lbl_out
)

IF "%2" == "" (
 echo need argument: output PE file
 goto lbl_out
)

set IS_USE_MANIFEST_WONDER_CONTROLS=1

set IS_32_BIT=0
set TARGET_SUBSYSTEM="WINDOWS"
set NOT_HAVE_RELOCS=0
set MANIFEST_FLAG=
set MANIFEST_ARG=/MANIFEST:NO

cd "%~dp0"

if %IS_USE_MANIFEST_WONDER_CONTROLS%==1 set MANIFEST_FLAG=-m
if %IS_USE_MANIFEST_WONDER_CONTROLS%==1 set MANIFEST_ARG=/MANIFEST

for /f "tokens=*" %%i in ('Crypter.exe -s "%~dp0DecryptorPE\Settings.h" -p "%~dp0DecryptorPE\EncryptedPayload.h" -v %MANIFEST_FLAG% "%1"') do ( 
	if "%%i"=="input exe 32 bit" set IS_32_BIT=1
	if "%%i"=="input exe CUI" set TARGET_SUBSYSTEM="CONSOLE"
	if "%%i"=="input .exe file is not have relocations, recompile target .exe with relocs" set NOT_HAVE_RELOCS=1
)

if %NOT_HAVE_RELOCS%==1 (
	echo input exe not have relocs, recompile with relocations
	goto lbl_out
)
echo Input exe is %TARGET_SUBSYSTEM% subsystem



if %IS_32_BIT%==1 (
	echo Input exe file is 32 bit
	rem "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" x86

	cd /D "%~dp0DecryptorPE\VS2015"
	del /Q "Release"
	mkdir "Release"
	cd "Release"

	set INCLUDE=%~dp0Compiler\include2;%~dp0Compiler\include3;%~dp0Compiler\include4;%~dp0Compiler\include;
	set LIB=%~dp0Compiler\lib32;

	"%~dp0Compiler\x86_x86\cl.exe" "%~dp0DecryptorPE\*.c" /GS- /GL /c /analyze- /W0 /Gy /Zc:wchar_t /Gm- /Ox /Zc:inline /fp:precise /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_UNICODE" /D "UNICODE" /D "_CRT_NONSTDC_NO_WARNINGS" /errorReport:prompt /WX- /Zc:forScope /Gd /Oy- /Oi /MT /EHsc /nologo /Os

	rem cl.exe "%~dp0DecryptorPE\*.c" /GS- /GL /analyze- /W0 /Gy /Zc:wchar_t /Zi /Gm- /Ox /sdl- /Zc:inline /fp:precise /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_UNICODE" /D "UNICODE" /D "_CRT_NONSTDC_NO_WARNINGS" /errorReport:prompt /WX- /Zc:forScope /Gd /Oy- /Oi /MT /Fa"Release\" /EHsc /nologo /Fo"Release\" /Os

	"%~dp0Compiler\x86_x86\link.exe" "%~dp0DecryptorPE\VS2015\Release\*.obj" /OUT:"%~dp0DecryptorPE\VS2015\Release\output.exe" %MANIFEST_ARG% /LTCG:incremental /NXCOMPAT /DYNAMICBASE "kernel32.lib" "user32.lib" "gdi32.lib" "winspool.lib" "comdlg32.lib" "advapi32.lib" "shell32.lib" "ole32.lib" "oleaut32.lib" "uuid.lib" "odbc32.lib" "odbccp32.lib" /MACHINE:X86 /OPT:REF /SAFESEH /INCREMENTAL:NO /SUBSYSTEM:%TARGET_SUBSYSTEM% /OPT:ICF /ERRORREPORT:PROMPT /NOLOGO /NODEFAULTLIB /TLBID:1 

) 
if %IS_32_BIT%==0 (

	echo Input exe file is 64 bit
	rem "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" amd64

	cd /D "%~dp0DecryptorPE\VS2015"
	del /Q "Release"
	mkdir "Release"
	cd "Release"

	set INCLUDE=%~dp0Compiler\include2;%~dp0Compiler\include3;%~dp0Compiler\include4;%~dp0Compiler\include;
	set LIB=%~dp0Compiler\lib64;

	"%~dp0Compiler\x86_amd64\cl.exe" "%~dp0DecryptorPE\*.c" /GS- /GL /c /analyze- /W0 /Gy /Zc:wchar_t /Gm- /Ox /Zc:inline /fp:precise /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_UNICODE" /D "UNICODE" /D "_CRT_NONSTDC_NO_WARNINGS" /errorReport:prompt /WX- /Zc:forScope /Gd /Oy- /Oi /MT /EHsc /nologo /Os

	rem cl.exe "%~dp0DecryptorPE\*.c" /GS- /GL /analyze- /W0 /Gy /Zc:wchar_t /Zi /Gm- /Ox /sdl- /Zc:inline /fp:precise /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_UNICODE" /D "UNICODE" /D "_CRT_NONSTDC_NO_WARNINGS" /errorReport:prompt /WX- /Zc:forScope /Gd /Oy- /Oi /MT /Fa"Release\" /EHsc /nologo /Fo"Release\" /Os

	"%~dp0Compiler\x86_amd64\link.exe" "%~dp0DecryptorPE\VS2015\Release\*.obj" /OUT:"%~dp0DecryptorPE\VS2015\Release\output.exe" %MANIFEST_ARG% /LTCG:incremental /NXCOMPAT /DYNAMICBASE /HIGHENTROPYVA "kernel32.lib" "user32.lib" "gdi32.lib" "winspool.lib" "comdlg32.lib" "advapi32.lib" "shell32.lib" "ole32.lib" "oleaut32.lib" "uuid.lib" "odbc32.lib" "odbccp32.lib" /MACHINE:AMD64 /OPT:REF /INCREMENTAL:NO /SUBSYSTEM:%TARGET_SUBSYSTEM% /OPT:ICF /ERRORREPORT:PROMPT /NOLOGO /NODEFAULTLIB /TLBID:1 

)


"%~dp0Crypter.exe" -o "%2" -v "%~dp0DecryptorPE\VS2015\Release\output.exe"


:lbl_out