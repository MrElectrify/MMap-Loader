#include <MMapLoader/PortableExecutable.h>

#include <fstream>
#include <memory>
#include <type_traits>

#include <ntstatus.h>
#include <winternl.h>

typedef struct _RTLP_CURDIR_REF
{
	LONG RefCount;
	HANDLE Handle;
} RTLP_CURDIR_REF, * PRTLP_CURDIR_REF;

typedef struct RTL_RELATIVE_NAME_U {
	UNICODE_STRING RelativeName;
	HANDLE ContainingDirectory;
	PRTLP_CURDIR_REF CurDirRef;
} RTL_RELATIVE_NAME_U, * PRTL_RELATIVE_NAME_U;

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

using MMapLoader::PortableExecutable;

std::optional<std::variant<DWORD, NTSTATUS>> PortableExecutable::Load(const std::string& path) noexcept
{
	// first, resolve ntdll functions
	const auto hNtDll = GetModuleHandle("ntdll");
	if (hNtDll == nullptr)
		return GetLastError();
	using NtCreateSection_t = std::add_pointer_t <NTSTATUS NTAPI(PHANDLE SectionHandle,
		ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
		PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection,
		ULONG AllocationAttributes, HANDLE FileHandle)>;
	using NtMapViewOfSection_t = std::add_pointer_t<NTSTATUS NTAPI(HANDLE SectionHandle,
		HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize,
		PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition,
		ULONG AllocationType, ULONG Protect)>;
	using NtUnmapViewOfSection_t = std::add_pointer_t<NTSTATUS NTAPI(HANDLE ProcessHandle,
		PVOID BaseAddress)>;
	const NtCreateSection_t NtCreateSection_f = reinterpret_cast<NtCreateSection_t>(
		GetProcAddress(hNtDll, "NtCreateSection"));
	const NtMapViewOfSection_t NtMapViewOfSection_f = reinterpret_cast<NtMapViewOfSection_t>(
		GetProcAddress(hNtDll, "NtMapViewOfSection"));
	const NtUnmapViewOfSection_t NtUnmapViewOfSection_f = 
		reinterpret_cast<NtUnmapViewOfSection_t>(
			GetProcAddress(hNtDll, "NtUnmapViewOfSection"));
	if (NtCreateSection_f == nullptr || NtMapViewOfSection_f == nullptr || 
		NtUnmapViewOfSection_f == nullptr)
		return GetLastError();
	// open the file for execution
	OBJECT_ATTRIBUTES localObjectAttributes;
	HANDLE fileHandleRaw = nullptr;
	if (fileHandleRaw = CreateFile(path.c_str(), SYNCHRONIZE | FILE_EXECUTE, 
		NULL, nullptr, OPEN_EXISTING, NULL, nullptr); fileHandleRaw == INVALID_HANDLE_VALUE)
		return GetLastError();
	std::unique_ptr<std::remove_pointer_t<HANDLE>, 
		std::add_pointer_t<decltype(CloseHandle)>>
		fileHandle(fileHandleRaw, CloseHandle);
	// now we can create a section
	HANDLE sectionHandleRaw = nullptr;
	if (NTSTATUS status = NtCreateSection_f(&sectionHandleRaw,
		SECTION_ALL_ACCESS, nullptr, nullptr, PAGE_EXECUTE, SEC_IMAGE,
		fileHandle.get()); status != STATUS_SUCCESS)
		return status;
	std::shared_ptr<std::remove_pointer_t<HANDLE>>
		sectionHandle(sectionHandleRaw, CloseHandle);
	// map the section
	SIZE_T viewSize = 0;
	PVOID imageBase = nullptr;
	if (NTSTATUS status = NtMapViewOfSection_f(sectionHandle.get(),
		GetCurrentProcess(), &imageBase, 0, 0, nullptr, &viewSize,
		SECTION_INHERIT::ViewUnmap, 0, PAGE_READONLY);
		status != STATUS_SUCCESS)
		return status;
	DWORD dwOldProtect = 0;
	// temporary. figure out how to separate sections and give them their own protections
	if (VirtualProtect(imageBase, viewSize, PAGE_EXECUTE_READWRITE, &dwOldProtect) == FALSE)
		return GetLastError();
	// save the view to be unmapped
	m_image = std::shared_ptr<void>(imageBase, 
		[NtUnmapViewOfSection_f, sectionHandle](void* imageBase) 
		{
			// this is a lambda so that the section is closed after
			// the section is unmapped
			NtUnmapViewOfSection_f(GetCurrentProcess(), imageBase);
		});
	// verify that the image is for x86_64
	const auto pDOSHeader = GetRVA<const IMAGE_DOS_HEADER>(0);
	const auto pNTHeader = GetRVA<const IMAGE_NT_HEADERS>(pDOSHeader->e_lfanew);
	if (pNTHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
		pNTHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		// remove the image
		m_image = nullptr;
		return STATUS_INVALID_IMAGE_FORMAT;
	}
	// resolve imports
	if (NTSTATUS status = ResolveImports(); status != STATUS_SUCCESS)
		return status;
	// execute TLS callbacks
	if (NTSTATUS status = ExecuteTLSCallbacks(); status != STATUS_SUCCESS)
		return status;
	return std::nullopt;
}

int PortableExecutable::Run() noexcept
{
	if (m_image == nullptr)
		return -1;
	const auto pDOSHeader = GetRVA<const IMAGE_DOS_HEADER>(0);
	const auto pNTHeaders = GetRVA<const IMAGE_NT_HEADERS>(pDOSHeader->e_lfanew);
	auto EntryPoint_f = GetRVA<int()>(pNTHeaders->OptionalHeader.AddressOfEntryPoint);
	auto hThread = CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(EntryPoint_f),
		nullptr, 0, nullptr);
	if (hThread == nullptr)
		return GetLastError();
	WaitForSingleObject(hThread, INFINITE);
	DWORD exitCode = 0;
	if (GetExitCodeThread(hThread, &exitCode) == FALSE)
		return GetLastError();
	return exitCode;
}

NTSTATUS PortableExecutable::ResolveImports() noexcept
{
	const auto pDOSHeader = GetRVA<const IMAGE_DOS_HEADER>(0);
	const auto pNTHeaders = GetRVA<const IMAGE_NT_HEADERS>(pDOSHeader->e_lfanew);
	const auto& importDir = pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	// import all of the descriptors
	auto pImportDesc = GetRVA<IMAGE_IMPORT_DESCRIPTOR>(importDir.VirtualAddress);
	for (; pImportDesc->Name != 0; ++pImportDesc)
	{
		LPSTR libName = GetRVA<std::remove_pointer_t<LPSTR>>(pImportDesc->Name);
		// load the imported DLL
		HMODULE hLib = LoadLibraryA(libName);
		if (hLib == nullptr)
			return STATUS_OBJECTID_NOT_FOUND;
		// enumerate thunks and fill out import functions
		auto pLookup = pImportDesc->OriginalFirstThunk != 0 ?
			GetRVA<IMAGE_THUNK_DATA>(pImportDesc->OriginalFirstThunk) :
			GetRVA<IMAGE_THUNK_DATA>(pImportDesc->FirstThunk);
		auto pThunk = GetRVA<IMAGE_THUNK_DATA>(pImportDesc->FirstThunk);
		for (;pThunk->u1.AddressOfData != 0; ++pThunk, ++pLookup)
		{
			LPCSTR procName = (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) ?
				reinterpret_cast<LPCSTR>(pThunk->u1.Ordinal & 0xffff) :
				GetRVA<IMAGE_IMPORT_BY_NAME>(pThunk->u1.AddressOfData)->Name;
			LPVOID function = GetProcAddress(hLib, procName);
			// set the First thunk's function
			pThunk->u1.Function = reinterpret_cast<ULONGLONG>(function);
			if (pThunk->u1.Function == 0)
				return STATUS_NOT_FOUND;
		}
	};
	return STATUS_SUCCESS;
}

NTSTATUS PortableExecutable::ExecuteTLSCallbacks() noexcept
{
	const auto pDOSHeader = GetRVA<const IMAGE_DOS_HEADER>(0);
	const auto pNTHeaders = GetRVA<const IMAGE_NT_HEADERS>(pDOSHeader->e_lfanew);
	const auto& tlsDir = pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (tlsDir.VirtualAddress == 0)
		return STATUS_SUCCESS;
	const auto pTLSDir = GetRVA<IMAGE_TLS_DIRECTORY>(tlsDir.VirtualAddress);
	// loop through callbacks
	auto pTLSCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLSDir->AddressOfCallBacks);
	if (pTLSCallback == nullptr)
		return STATUS_SUCCESS;
	for (auto pTLSCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLSDir->AddressOfCallBacks);
		*pTLSCallback != nullptr; ++pTLSCallback)
		(*pTLSCallback)(m_image.get(), DLL_PROCESS_ATTACH, nullptr);
	return STATUS_SUCCESS;
}