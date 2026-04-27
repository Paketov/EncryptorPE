/*
	PE Encrypter: decrypt PE from payload and run it
	By Solodov A. N. aka SANshine aka Paketov aka Antichrist aka CatsEater aka KittyEater aka UniverseFucker
	2026
*/


#include <stdio.h>
#include <Windows.h>
#include <stdint.h>
#include <time.h>
#include "main.h"
#include "XTea.h"


#define OPTIONAL_HEADER_MAGIC_PE32 0x10b
#define OPTIONAL_HEADER_MAGIC_PE64 0x20b

static BOOL isPE(char* image_base, DWORD image_size);
static BOOL isPE32(char* image_base);
static BOOL isGuiApplication(uint16_t subsystem);
static BOOL isHaveReloc(char* image_base);
static BOOL PERemoveDebugDirectory(char* image_base);
static int RVA2Offset(unsigned char * image_base, DWORD rva);
static BOOL RandomizeDosStub(char* image_base);
static BOOL PERandomizeTimeDateStamp(char* image_base);
static BOOL PERandomizeLinkerVersion(char* image_base);
static BOOL SetOsVerToWin95(char* image_base);
static BOOL IsExe(char* image_base);
static BOOL PESetNullCheckSum(char* image_base);

static void print_help() {
	printf(
		"Use: Crypter.exe <options> <input exe>\n"
		" Generate Settings.h and EncryptedPayload.h file for compile PE file\n"
		" List of available options:\n"
		"  -a Use antidebug\n"
		"  -s <output Settings.h> path to output settings.h\n"
		"  -p <output EncryptedPayload.h> path to output EncryptedPayload.h payload file\n"
		"  -m is use manifest for wonder controls\n"
		"  -v set version os to windows 95\n"
		"  -o <output exe> remove debug info from exe and output them\n"
	);
}

BOOL IsAntidebug = FALSE;
BOOL IsUseManifest = FALSE;
BOOL IsSetVersionOsToWin95 = FALSE;
WCHAR* OutputSettings = NULL;
WCHAR* OutputPayload = NULL;
WCHAR* OutputExe = NULL;
WCHAR* InputPE = NULL;

BOOL IsGui = TRUE;
BOOL Is32Bit = TRUE;
BOOL IsFileExe = FALSE;
DWORD SizeOfImage = 0;

int wmain(int argc, WCHAR*argv[]) {
	if (argc <= 1) {
		print_help();
		return 0;
	}

	srand((DWORD)(__rdtsc() & 0x7fffffff));
	for (int i = 1, m = argc; i < m; i++) {
		if (wcscmp(argv[i], L"-a") == 0) {
			IsAntidebug = TRUE;
		} else if (wcscmp(argv[i], L"-m") == 0) {
			IsUseManifest = TRUE;
		} else if (wcscmp(argv[i], L"-v") == 0) {
			IsSetVersionOsToWin95 = TRUE;
		} else if (wcscmp(argv[i], L"-s") == 0) {
			i++;
			if (i >= m) {
				printf("arg to output Settings.h not found (-s option).\n");
				return 1;
			}
			OutputSettings = argv[i];
		} else if (wcscmp(argv[i], L"-p") == 0) {
			i++;
			if (i >= m) {
				printf("arg to output EncryptedPayload.h not found (-p option).\n");
				return 1;
			}
			OutputPayload = argv[i];
		} else if (wcscmp(argv[i], L"-o") == 0) {
			i++;
			if (i >= m) {
				printf("arg to output exe path not found (-o option).\n");
				return 1;
			}
			OutputExe = argv[i];
		}
		else {
			InputPE = argv[i];
		}
	}
	if (OutputSettings == NULL) {
		OutputSettings = L"Settings.h";
	}
	if (OutputPayload == NULL) {
		OutputPayload = L"EncryptedPayload.h";
	}
	if (InputPE == NULL) {
		printf("path to input .exe file was not setted.\n");
		return 1;
	}
	
	FILE* SettingsFile;
	FILE* PayloadFile;
	FILE* PEFile = _wfopen(InputPE, L"rb");
	if (PEFile == NULL) {
		wprintf(L"not open input exe (%s)\n", InputPE);
		return 1;
	}
	if (!OutputExe) {
		SettingsFile = _wfopen(OutputSettings, L"w");
		if (SettingsFile == NULL) {
			wprintf(L"not create Settings.h (%s)\n", OutputSettings);
			return 1;
		}
		PayloadFile = _wfopen(OutputPayload, L"w");
		if (PayloadFile == NULL) {
			wprintf(L"not create EncryptedPayload.h (%s)\n", OutputPayload);
			return 1;
		}
	}

	fseek(PEFile, 0, SEEK_END);
	size_t PEFileLen = ftell(PEFile);
	fseek(PEFile, 0, SEEK_SET);

	uint32_t Pass[10];
	for (size_t i = 0; i < sizeof(Pass); i++) {
		((unsigned char*)Pass)[i] = rand() & 0xff;
	}

	size_t AdditinalPESize = ((rand() * rand() + rand()) % 7000) + (sizeof(Pass) + 1) + XTEA_BLOCK_SIZE;
	size_t PassOffset = PEFileLen + XTEA_BLOCK_SIZE + ((rand() * rand() + rand()) % (AdditinalPESize - ((sizeof(Pass) + 1) + XTEA_BLOCK_SIZE)));

	char* image_base = (char*)malloc(PEFileLen + AdditinalPESize + 2);
	if (fread(image_base, 1, PEFileLen, PEFile) < 1) {
		wprintf(L"fread() failed. PE file not readed\n");
		return 1;
	}
	fclose(PEFile);
	for (int i = PEFileLen, m = i + AdditinalPESize; i < m; i++)
		image_base[i] = rand() & 0xff;

	for (int i = PassOffset, j = 0; j < sizeof(Pass); i++, j++)
		image_base[i] = ((char*)Pass)[j];
	image_base[PassOffset + sizeof(Pass)] = (rand() % 253) + 1; //Must Be Not Null, For Get Info Is Dll Has Been Loaded

	if (!isPE(image_base, PEFileLen)) {
		wprintf(L"input .exe file is not a PE\n");
		return 1;
	}
	if (!OutputExe) {
		if (!isHaveReloc(image_base)) {
			wprintf(L"input .exe file is not have relocations, recompile target .exe with relocs\n");
			return 1;
		}
	}

	/* remove debug info from PE image */
	PERemoveDebugDirectory(image_base);
	RandomizeDosStub(image_base);
	PERandomizeTimeDateStamp(image_base);
	PERandomizeLinkerVersion(image_base);
	PESetNullCheckSum(image_base);
	if (IsSetVersionOsToWin95)
		SetOsVerToWin95(image_base);

	if (OutputExe) {
		FILE* OutputPE = _wfopen(OutputExe, L"wb");
		if (OutputPE == NULL) {
			wprintf(L"not create output exe (%s)\n", OutputExe);
			return 1;
		}
		fwrite(image_base, 1, PEFileLen, OutputPE);
		fflush(OutputPE);
		fclose(OutputPE);
		return 0;
	}
	WORD Characteristics = 0;
	if (Is32Bit = isPE32(image_base)) {
		PIMAGE_NT_HEADERS32 NtHeaders = (PIMAGE_NT_HEADERS32)(image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew);
		IsGui = isGuiApplication(NtHeaders->OptionalHeader.Subsystem);
		SizeOfImage = NtHeaders->OptionalHeader.SizeOfImage;
		Characteristics = NtHeaders->FileHeader.Characteristics;
		printf("input exe 32 bit\n");
	} else {
		PIMAGE_NT_HEADERS64 NtHeaders = (PIMAGE_NT_HEADERS64)(image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew);
		IsGui = isGuiApplication(NtHeaders->OptionalHeader.Subsystem);
		SizeOfImage = NtHeaders->OptionalHeader.SizeOfImage;
		Characteristics = NtHeaders->FileHeader.Characteristics;
		printf("input exe 64 bit\n");
	}
	if(IsGui)
		printf("input exe GUI\n");
	else
		printf("input exe CUI\n");
	fprintf(SettingsFile, "#pragma once\n");
	if(IsAntidebug)
		fprintf(SettingsFile, "#define EP_USE_ANTIDEBUG\n");
	if(IsUseManifest)
		fprintf(SettingsFile, "#define EP_USE_MANIFEST_FOR_WONDER_CONTROLS\n");
	if (!IsGui)
		fprintf(SettingsFile, "#define EP_IS_CONSOLE\n");
	if (!Is32Bit)
		fprintf(SettingsFile, "#define EP_IS_64_BIT_PAYLOAD\n");

	if (Characteristics & IMAGE_FILE_DLL) //Is dll
		fprintf(SettingsFile, "#define EP_PAYLOAD_IS_DLL\n");
	else if (Characteristics & IMAGE_FILE_SYSTEM) //is driver
		fprintf(SettingsFile, "#define EP_PAYLOAD_IS_DRIVER\n");
	else if (Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) //is exe
		fprintf(SettingsFile, "#define EP_PAYLOAD_IS_EXE\n");

	fprintf(SettingsFile, "#define EP_FAKE_LIB_NAME \"lib%u.dll\"\n", rand() * rand() + rand());

	fprintf(SettingsFile, "#define EP_RANDOM1 %u\n", rand() * rand() + rand());
	fprintf(SettingsFile, "#define EP_RANDOM2 %u\n", rand() * rand() + rand());
	fprintf(SettingsFile, "#define EP_RANDOM3 %u\n", rand() * rand() + rand());
	fprintf(SettingsFile, "#define EP_RANDOM4 %u\n", rand() * rand() + rand());
	fprintf(SettingsFile, "#define EP_RANDOM5 %u\n", rand() * rand() + rand());
	fprintf(SettingsFile, "#define EP_RANDOM6 %u\n", rand() * rand() + rand());
	fprintf(SettingsFile, "#define EP_RANDOM7 %u\n", rand() * rand() + rand());
	fprintf(SettingsFile, "#define EP_XOR_HASH_FUNCTION %u\n", rand() * rand() + rand());
	fprintf(SettingsFile, "#define EP_PE_FILE_SIZE %u\n", (unsigned)PEFileLen);
	fprintf(SettingsFile, "#define EP_PE_IMAGE_SIZE %u\n", (unsigned)SizeOfImage);
	fprintf(SettingsFile, "#define EP_OFFSET_PASS_IN_PAYLOAD %u\n", (unsigned)PassOffset);

	fflush(SettingsFile);
	fclose(SettingsFile);

	/* Write PE payload in .h file */

	fprintf(PayloadFile, "#pragma once\n");
	fprintf(PayloadFile, "static unsigned char EncryptedPayload[] = {");

	Xtea3_Data_Encrypt(image_base, PEFileLen, Pass, 1);

	for (size_t i = 0, m = PEFileLen + AdditinalPESize; i < m;) {
		fprintf(PayloadFile, "\n");
		for (size_t j = 0; j < 10 && i < m; i++, j++) {
			fprintf(PayloadFile, "0x%02x%c", ((uint8_t*)image_base)[i], ((i + 1) >= m) ? ' ' : ',');
		}
	}
	
	fprintf(PayloadFile, "};\n");
	fflush(PayloadFile);
	fclose(PayloadFile);

	return 0;
}

static BOOL isPE(char* image_base, DWORD image_size) {
	if (image_size <= sizeof(IMAGE_DOS_HEADER))
		return FALSE;
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)image_base;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;
	if (dos->e_lfanew >= image_size)
		return FALSE;
	PIMAGE_NT_HEADERS64 NtHeaders = (PIMAGE_NT_HEADERS64)(image_base + dos->e_lfanew);
	if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	return TRUE;
}


static BOOL isPE32(char* image_base) {
	PIMAGE_NT_HEADERS32 NtHeaders = image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew;
	return NtHeaders->OptionalHeader.Magic == OPTIONAL_HEADER_MAGIC_PE32;
}


static BOOL isGuiApplication(uint16_t subsystem) {
	switch (subsystem) {
	case IMAGE_SUBSYSTEM_WINDOWS_GUI: //Gui
		return TRUE;
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CUI: //commandline
		return FALSE;
		break;
	default:
		return TRUE;
		break;
	}
}

static BOOL IsExe(char* image_base) {
	if(isPE32(image_base)) {
		PIMAGE_NT_HEADERS32 NtHeaders = (PIMAGE_NT_HEADERS32)(image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew);
		if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) //Is dll
			return FALSE;
		if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_SYSTEM) //is driver
			return FALSE;
		if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) //is exe
			return TRUE;
	} else {
		PIMAGE_NT_HEADERS64 NtHeaders = (PIMAGE_NT_HEADERS64)(image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew);
		if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) //Is dll
			return FALSE;
		if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_SYSTEM) //is driver
			return FALSE;
		if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) //is exe
			return TRUE;
	}
	return FALSE;
}


static BOOL isHaveReloc(char* image_base) {
	if (isPE32(image_base)) {
		PIMAGE_NT_HEADERS32 NtHeaders = (PIMAGE_NT_HEADERS32)(image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew);
		if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
			return FALSE;
		if (!(NtHeaders->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE))
			return FALSE;
		//if (
		//	(NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0) || 
		//	(NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0)
		//) 
		//	return FALSE;
	} else {
		PIMAGE_NT_HEADERS64 NtHeaders = (PIMAGE_NT_HEADERS64)(image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew);
		if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
			return FALSE;
		if (!(NtHeaders->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE))
			return FALSE;
		//DLL_CHARACTER_CAN_MOVE
		//if (
		//	(NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0) ||
		//	(NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0)
		//)
		//	return FALSE;
	}
	return TRUE;
}

static int RVA2Offset(unsigned char * image_base, DWORD rva) {
	PIMAGE_SECTION_HEADER section;
	PIMAGE_SECTION_HEADER max_sec;
	PIMAGE_NT_HEADERS64 header64;
	PIMAGE_NT_HEADERS32 header32;
	if (isPE32(image_base)) {
		header32 = (PIMAGE_NT_HEADERS32)(image_base + ((IMAGE_DOS_HEADER*)image_base)->e_lfanew);
		section = (PIMAGE_SECTION_HEADER)(header32 + 1);
		max_sec = section + header32->FileHeader.NumberOfSections;
	} else {
		header64 = (PIMAGE_NT_HEADERS64)(image_base + ((IMAGE_DOS_HEADER*)image_base)->e_lfanew);
		section = (PIMAGE_SECTION_HEADER)(header64 + 1);
		max_sec = section + header64->FileHeader.NumberOfSections;
	}
	for (; section < max_sec; section++) {
		if ((rva >= section->VirtualAddress) && (rva <= (section->VirtualAddress + section->SizeOfRawData)))
			return section->PointerToRawData + (rva - section->VirtualAddress);
	}
	return 0;
}

static BOOL PERemoveDebugDirectory(char* image_base) {
	if (isPE32(image_base)) {
		PIMAGE_NT_HEADERS32 NtHeaders = (PIMAGE_NT_HEADERS32)(image_base + ((IMAGE_DOS_HEADER*)image_base)->e_lfanew);
		if (NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress == 0)
			return TRUE;
		int OffsetDebugDir = RVA2Offset(image_base, NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
		if (OffsetDebugDir == 0)
			return FALSE;
		PIMAGE_DEBUG_DIRECTORY DebugDir = (PIMAGE_DEBUG_DIRECTORY)(image_base + OffsetDebugDir);
		DWORD DebugDirSize = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;

		for (int i = 0; ((char*)(DebugDir + i)) < (((char*)DebugDir) + DebugDirSize); i++) {
			if (DebugDir[i].AddressOfRawData != 0) {
				int Offset = RVA2Offset(image_base, DebugDir[i].AddressOfRawData);
				if (Offset == 0)
					return FALSE;
				char* DebugInfo = image_base + Offset;
				memset(DebugInfo, 0, DebugDir[i].SizeOfData);
			}
		}
		memset(DebugDir, 0, DebugDirSize);
		NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
		NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
	} else {
		PIMAGE_NT_HEADERS64 NtHeaders = (PIMAGE_NT_HEADERS64)(image_base + ((IMAGE_DOS_HEADER*)image_base)->e_lfanew);
		if (NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress == 0)
			return TRUE;
		int OffsetDebugDir = RVA2Offset(image_base, NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
		if (OffsetDebugDir == 0)
			return FALSE;
		PIMAGE_DEBUG_DIRECTORY DebugDir = (PIMAGE_DEBUG_DIRECTORY)(image_base + OffsetDebugDir);
		DWORD DebugDirSize = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
		for (int i = 0; ((char*)(DebugDir + i)) < (((char*)DebugDir) + DebugDirSize); i++) {
			if (DebugDir[i].AddressOfRawData != 0) {
				int Offset = RVA2Offset(image_base, DebugDir[i].AddressOfRawData);
				if (Offset == 0)
					return FALSE;
				char* DebugInfo = image_base + Offset;
				memset(DebugInfo, 0, DebugDir[i].SizeOfData);
			}
		}
		memset(DebugDir, 0, DebugDirSize);
		NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
		NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
	}
	return TRUE;
}

static BOOL RandomizeDosStub(char* image_base) {
	unsigned char* c = image_base + sizeof(IMAGE_DOS_HEADER);
	unsigned char* mc = image_base + ((IMAGE_DOS_HEADER*)image_base)->e_lfanew;

	for (; c < mc; c++) {
		if (strncmp("!This", c, sizeof("!This") - 1) == 0) {
			for (; (c < mc) && (*c != '\0'); c++);
		}
		else if (strncmp("This", c, sizeof("This") - 1) == 0) {
			for (; (c < mc) && (*c != '\0'); c++);
		}
		else {
			*c = (rand() & 0xffu);
		}
	}
	return TRUE;
}

static BOOL PERandomizeTimeDateStamp(char* image_base) {
	if (isPE32(image_base)) {
		PIMAGE_NT_HEADERS32 NtHeaders = (PIMAGE_NT_HEADERS32)(image_base + ((IMAGE_DOS_HEADER*)image_base)->e_lfanew);
		NtHeaders->FileHeader.TimeDateStamp -= (((DWORD)(__rdtsc() & 0xffffffffu)) % (DWORD)(10 * 365 * 60 * 60 * 24)); //- ~10 year
	} else {
		PIMAGE_NT_HEADERS64 NtHeaders = (PIMAGE_NT_HEADERS64)(image_base + ((IMAGE_DOS_HEADER*)image_base)->e_lfanew);
		NtHeaders->FileHeader.TimeDateStamp -= (((DWORD)(__rdtsc() & 0xffffffffu)) % (DWORD)(10 * 365 * 60 * 60 * 24)); //- ~10 year
	}
	return TRUE;
}

static BOOL PERandomizeLinkerVersion(char* image_base) {
	if (isPE32(image_base)) {
		PIMAGE_NT_HEADERS32 NtHeaders = (PIMAGE_NT_HEADERS32)(image_base + ((IMAGE_DOS_HEADER*)image_base)->e_lfanew);
		NtHeaders->OptionalHeader.MajorLinkerVersion = 0;
		NtHeaders->OptionalHeader.MinorLinkerVersion = 0;
		NtHeaders->OptionalHeader.MajorImageVersion = 0;
		NtHeaders->OptionalHeader.MinorImageVersion = 0;

	} else {
		PIMAGE_NT_HEADERS64 NtHeaders = (PIMAGE_NT_HEADERS64)(image_base + ((IMAGE_DOS_HEADER*)image_base)->e_lfanew);
		NtHeaders->OptionalHeader.MajorLinkerVersion = 0;
		NtHeaders->OptionalHeader.MinorLinkerVersion = 0;
		NtHeaders->OptionalHeader.MajorImageVersion = 0;
		NtHeaders->OptionalHeader.MinorImageVersion = 0;
	}
	return TRUE;
}

/* Set in PE version windows 95 */
static BOOL SetOsVerToWin95(char* image_base) {
	if (isPE32(image_base)) {
		PIMAGE_NT_HEADERS32 NtHeaders = (PIMAGE_NT_HEADERS32)(image_base + ((IMAGE_DOS_HEADER*)image_base)->e_lfanew);
		NtHeaders->OptionalHeader.MajorOperatingSystemVersion = 4;
		NtHeaders->OptionalHeader.MinorOperatingSystemVersion = 0;

		NtHeaders->OptionalHeader.MajorSubsystemVersion = 4;
		NtHeaders->OptionalHeader.MinorSubsystemVersion = 0;

		NtHeaders->OptionalHeader.Win32VersionValue = 0;

		NtHeaders->FileHeader.Characteristics &= ~((WORD)IMAGE_FILE_LARGE_ADDRESS_AWARE);
	}
	else {
		PIMAGE_NT_HEADERS64 NtHeaders = (PIMAGE_NT_HEADERS64)(image_base + ((IMAGE_DOS_HEADER*)image_base)->e_lfanew);
		NtHeaders->OptionalHeader.MajorOperatingSystemVersion = 4;
		NtHeaders->OptionalHeader.MinorOperatingSystemVersion = 0;

		NtHeaders->OptionalHeader.MajorSubsystemVersion = 4;
		NtHeaders->OptionalHeader.MinorSubsystemVersion = 0;

		NtHeaders->OptionalHeader.Win32VersionValue = 0;
	}
	return TRUE;
}

static BOOL PESetNullCheckSum(char* image_base) {
	if (isPE32(image_base)) {
		PIMAGE_NT_HEADERS32 NtHeaders = (PIMAGE_NT_HEADERS32)(image_base + ((IMAGE_DOS_HEADER*)image_base)->e_lfanew);
		NtHeaders->OptionalHeader.CheckSum = 0;
	}else {
		PIMAGE_NT_HEADERS64 NtHeaders = (PIMAGE_NT_HEADERS64)(image_base + ((IMAGE_DOS_HEADER*)image_base)->e_lfanew);
		NtHeaders->OptionalHeader.CheckSum = 0;
	}
	return TRUE;
}

//BOOL CALLBACK EnumResourceNameCallback(HMODULE hModule, LPCTSTR lpType,
//	LPWSTR lpName, LONG_PTR lParam)
//{
//	HRSRC hResInfo = FindResource(hModule, lpName, lpType);
//	DWORD cbResource = SizeofResource(hModule, hResInfo);
//
//	HGLOBAL hResData = LoadResource(hModule, hResInfo);
//	const BYTE *pResource = (const BYTE *)LockResource(hResData);
//
//	TCHAR filename[MAX_PATH];
//	if (IS_INTRESOURCE(lpName))
//		_stprintf_s(filename, _T("#%d.manifest"), lpName);
//	else
//		_stprintf_s(filename, _T("%s.manifest"), lpName);
//
//	FILE *f = _tfopen(filename, _T("wb"));
//	fwrite(pResource, cbResource, 1, f);
//	fclose(f);
//
//	UnlockResource(hResData);
//	FreeResource(hResData);
//
//	return TRUE;   // Keep going
//}

//int _tmain(int argc, _TCHAR* argv[])
//{
//	const TCHAR *pszFileName = argv[0];
//
//	HMODULE hModule = LoadLibraryEx(pszFileName, NULL, LOAD_LIBRARY_AS_DATAFILE);
//	EnumResourceNamesW(hModule, RT_MANIFEST, EnumResourceNameCallback, NULL);
//	FreeLibrary(hModule);
//	return 0;
//}
//
