#pragma once

/*
	DLL for enject in enother PE file
	By Solodov A. N. aka SANshine aka Paketov aka Antichrist aka CatsEater aka KittyEater aka UniverseFucker

*/
#define _CRT_SECURE_NO_WARNINGS


#include <Windows.h>
#include <stdint.h>
#include <stdbool.h>


#define bool int
#define false 0
#define true 1


# define EP_PLATFORM_WINDOWS
# define EP_STDCALL __stdcall
# define EP_CDECL   __cdecl
# define EP_FASTCALL __fastcall
# define EP_FORCEINLINE __forceinline
# define EP_NOINLINE __declspec(noinline)
# define EP_NAKED_FUNCTION __declspec(naked)
# define EP_UNREACHABLE() __assume(0)

#define EP_USE_VIRTUAL_ALLOC_FOR_PE


