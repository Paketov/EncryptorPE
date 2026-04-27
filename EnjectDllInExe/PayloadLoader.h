#pragma once
/*
	DLL enjector for enject DLL in EXE file. When EXE starts, decrypt and running DLL
	By Solodov A. N. aka SANshine aka Paketov aka Antichrist aka CatsEater aka KittyEater aka UniverseFucker
	2026
*/



#include <Windows.h>
#include "main.h"


#ifndef _WIN64
EP_NOINLINE void* ep_get_addr_data(void* Addr);
#else
EP_NOINLINE void* EP_STDCALL ep_get_addr_data(void* Addr);
#endif

EP_NOINLINE void MapAndRunDll();
EP_NOINLINE void EntryPoint();

