#pragma once
/*
	PE Encrypter: decrypt PE from payload and run it
	By Solodov A. N. aka SANshine aka Paketov aka Antichrist aka CatsEater aka KittyEater aka UniverseFucker
	2026
*/
#include <Windows.h>

void MapAndRunDll(const char* input_pe_file, size_t input_pe_file_size);

HMODULE ep_get_module_handle_by_name(char* ModuleName);
void* ep_get_proc_addr_by_name(HMODULE module, char* NameFunction);
HMODULE ep_load_library_by_name(char* ModuleName);

HMODULE ep_get_module_handle_by_hash(uint32_t HashName);
void* ep_get_proc_addr_by_hash(HMODULE module, uint32_t HashFunction);
