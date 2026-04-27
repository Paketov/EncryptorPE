/*
 DLL for enject in enother PE file
 By Solodov A. N. aka SANshine aka Paketov aka Antichrist aka CatsEater aka KittyEater aka UniverseFucker

*/

#include <stdint.h>

#include <Windows.h>
#include <Shlwapi.h>
#include <winternl.h>
#include <commctrl.h>
#include <stdio.h>

#include "main.h"

#pragma comment(linker, "/ENTRY:\"DllMain\"")

#define _memset(_Dst, Val, _Size) __stosb((unsigned char*)(_Dst), (unsigned char)(Val), (size_t)(_Size))
#define _memcpy(_Dst, _Src, _Size) __movsb((unsigned char*)(_Dst), (unsigned const char*)(_Src), (size_t)(_Size))


static DWORD ThreadId;
static HANDLE ThreadHandle;
static STARTUPINFOA StartInfo;

typedef struct kkk {
	int Val;
	wchar_t* Text;
} kkk;

kkk val = { 111, L"string" };


static DWORD WINAPI StartThread(LPVOID lpThreadParameter) {

	LoadLibraryA("ws2_32.dll");

	char* Val2 = HeapAlloc(GetProcessHeap(), 0, sizeof(val));

	_memcpy(Val2, &val, sizeof(val));

	StartInfo.cb = sizeof(StartInfo);
	GetStartupInfoA(&StartInfo);


	while (TRUE) {
		MessageBoxW(NULL, L"Some Text To Output", ((kkk*)Val2)->Text, 0);
		Sleep(7000);
	}
	return 0;
}

BOOL WINAPI DllMain(
	HINSTANCE hinstDLL,
	DWORD fdwReason,
	LPVOID lpvReserved
) {

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		ThreadHandle = CreateThread(NULL, 0, StartThread, NULL, 0, &ThreadId);
		break;

	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;

	case DLL_PROCESS_DETACH:
		

		if (lpvReserved != NULL)
		{
			GetProcAddress(hinstDLL, "SomeFunc");
			break;
		}
		break;
	}
	return TRUE;
}
