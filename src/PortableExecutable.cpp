#include <MMapLoader/PortableExecutable.h>

#include <MMapLoader/Detail/NtFuncs.h>

#include <filesystem>
#include <fstream>
#include <memory>
#include <type_traits>

#include <ntstatus.h>
#include <winternl.h>

using MMapLoader::PortableExecutable;

using namespace MMapLoader::Detail;

std::optional<std::variant<DWORD, NTSTATUS>> PortableExecutable::Load(const std::string& path) noexcept
{
	// initialize NT
	if (Detail::NT::Initialize() == false)
		return STATUS_ACPI_FATAL;
	// map the file
	if (NTSTATUS status = MapFile(path);
		status != STATUS_SUCCESS)
		return status;
	// load and verify headers
	if (NTSTATUS status = LoadHeaders();
		status != STATUS_SUCCESS)
		return status;
	// and process relocations
	if (NTSTATUS status = ProcessRelocations();
		status != STATUS_SUCCESS)
		return status;
	// resolve imports
	if (auto status = ResolveImports();
		status.has_value() == true)
		return status;
	// initializes the loader entry
	if (NTSTATUS status = InitLoaderEntry();
		status != STATUS_SUCCESS)
		return status;
	// initialize static TLS data and execute callbacks
	if (NTSTATUS status = InitTLS();
		status != STATUS_SUCCESS)
		return status;
	// enable exceptions
	if (NTSTATUS status = EnableExceptions();
		status != STATUS_SUCCESS)
		return status;
	// add the entry to the loader hash table
	if (NTSTATUS status = AddEntryToLdrHashTbl();
		status != STATUS_SUCCESS)
		return status;
	// protect sections
	if (DWORD status = ProtectSections();
		status != STATUS_SUCCESS)
		return status;
	return std::nullopt;
}

int PortableExecutable::Run() noexcept
{
	if (m_image.get() == nullptr)
		return -1;
	auto EntryPoint_f = GetRVA<int()>(m_ntHeaders.OptionalHeader.AddressOfEntryPoint);
	return EntryPoint_f();
}

NTSTATUS PortableExecutable::MapFile(const std::string& path) noexcept
{
	// open the file for execution
	HANDLE fileHandleRaw = nullptr;
	if (fileHandleRaw = CreateFile(path.c_str(), SYNCHRONIZE | FILE_EXECUTE,
		NULL, nullptr, OPEN_EXISTING, NULL, nullptr); fileHandleRaw == INVALID_HANDLE_VALUE)
		return GetLastError();
	std::unique_ptr<std::remove_pointer_t<HANDLE>,
		std::add_pointer_t<decltype(CloseHandle)>>
		fileHandle(fileHandleRaw, CloseHandle);
	// now we can create a section
	HANDLE sectionHandleRaw = nullptr;
	if (NTSTATUS status = NT::NtCreateSection_f(&sectionHandleRaw,
		SECTION_ALL_ACCESS, nullptr, nullptr, PAGE_EXECUTE, SEC_IMAGE,
		fileHandle.get()); status != STATUS_SUCCESS)
		return status;
	std::shared_ptr<std::remove_pointer_t<HANDLE>>
		sectionHandle(sectionHandleRaw, CloseHandle);
	// map the section
	SIZE_T viewSize = 0;
	PVOID imageBase = nullptr;
	if (NTSTATUS status = NT::NtMapViewOfSection_f(sectionHandle.get(),
		GetCurrentProcess(), &imageBase, 0, 0, nullptr, &viewSize,
		NT::SECTION_INHERIT::ViewUnmap, 0, PAGE_READWRITE);
		status != STATUS_SUCCESS)
		return status;
	DWORD dwOldProtect = 0;
	// save the view to be unmapped
	m_image = std::shared_ptr<void>(imageBase,
		[sectionHandle](void* imageBase)
		{
			// this is a lambda so that the section is closed after
			// the section is unmapped
			NT::NtUnmapViewOfSection_f(GetCurrentProcess(), imageBase);
		});
	std::filesystem::path fPath(path);
	m_modPath = fPath.wstring();
	m_modName = fPath.stem().wstring() + fPath.extension().wstring();
	return STATUS_SUCCESS;
}

NTSTATUS PortableExecutable::LoadHeaders() noexcept
{
	// first, load the DOS header
	memcpy(&m_dosHeader, m_image.get(), sizeof(m_dosHeader));
	// seek to the nt headers and load it
	memcpy(&m_ntHeaders, GetRVA<IMAGE_NT_HEADERS>(m_dosHeader.e_lfanew), 
		sizeof(IMAGE_NT_HEADERS));
	// verify the architecture
	if (m_ntHeaders.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
		m_ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return STATUS_INVALID_IMAGE_FORMAT;
	// make space for the section headers and load them
	m_sectionHeaders.resize(m_ntHeaders.FileHeader.NumberOfSections);
	// read sections
	auto pSection = GetRVA<IMAGE_SECTION_HEADER>(m_dosHeader.e_lfanew +
		sizeof(IMAGE_NT_HEADERS));
	for (WORD i = 0; 
		i < m_ntHeaders.FileHeader.NumberOfSections; 
		++i, ++pSection)
		memcpy(&m_sectionHeaders[i], pSection, sizeof(IMAGE_SECTION_HEADER));
	return STATUS_SUCCESS;
}

DWORD PortableExecutable::ProtectSections() noexcept
{
	// for each section header, load the section into the image
	for (const auto& sectionHeader : m_sectionHeaders)
	{
		const auto sectionAddr = GetRVA<char>(sectionHeader.VirtualAddress);
		// change protection to the corresponding protection
		DWORD oldProtect = 0;
		if (VirtualProtect(sectionAddr, sectionHeader.Misc.VirtualSize,
			SectionFlagsToProtectionFlags(sectionHeader.Characteristics),
			&oldProtect) == FALSE)
			return GetLastError();
	}
	return ERROR_SUCCESS;
}

NTSTATUS PortableExecutable::ProcessRelocations() noexcept
{
	// first, see if there is even a delta
	const uintptr_t delta = reinterpret_cast<uintptr_t>(m_image.get()) - 
		m_ntHeaders.OptionalHeader.ImageBase;
	if (delta == 0)
		return STATUS_SUCCESS;
	// see if it is relocatable
	if ((m_ntHeaders.OptionalHeader.DllCharacteristics & 
		IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0)
		return STATUS_INVALID_IMAGE_HASH;
	// TODO: relocate it
	return STATUS_ACPI_FATAL;
}

std::optional<std::variant<DWORD, NTSTATUS>> PortableExecutable::ResolveImports() noexcept
{
	const auto& importDir =
		m_ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	// import all of the descriptors
	auto pImportDesc = GetRVA<const IMAGE_IMPORT_DESCRIPTOR>(importDir.VirtualAddress);
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
			// set the proper protection of the thunk
			DWORD dwOldThunkProt = 0;
			if (VirtualProtect(pThunk, sizeof(*pThunk),
				PAGE_READWRITE, &dwOldThunkProt) == FALSE)
				return GetLastError();
			// set the First thunk's function
			pThunk->u1.Function = reinterpret_cast<ULONGLONG>(function);
			// and restore protection
			if (VirtualProtect(pThunk, sizeof(*pThunk),
				dwOldThunkProt, &dwOldThunkProt) == FALSE)
				return GetLastError();
			if (pThunk->u1.Function == 0)
				return STATUS_NOT_FOUND;
		}
	};
	return std::nullopt;
}

NTSTATUS PortableExecutable::InitTLS() noexcept
{
	// first, initialize the static TLS data
	if (NTSTATUS status = AddStaticTLSEntry();
		status != STATUS_SUCCESS)
		return status;
	// now we can call any TLS callbacks
	if (NTSTATUS status = ExecuteTLSCallbacks();
		status != STATUS_SUCCESS)
		return status;
	return STATUS_SUCCESS;
}

NTSTATUS PortableExecutable::InitLoaderEntry() noexcept
{
	m_loaderEntry.DllBase = reinterpret_cast<uint64_t>(m_image.get());
	NT::RtlInitUnicodeString_f(&m_loaderEntry.BaseDllName, m_modName.c_str());
	NT::RtlInitUnicodeString_f(&m_loaderEntry.FullDllName, m_modPath.c_str());
	m_loaderEntry.DdagNode = reinterpret_cast<uint64_t>(&m_ddagNode);
	m_ddagNode.State = NT::_LDR_DDAG_STATE::LdrModulesReadyToRun;
	m_ddagNode.LoadCount = -1;
	// initialize the index
	if (DWORD index = NT::LdrpInsertModuleToIndex_f(&m_loaderEntry,
		GetRVA<IMAGE_NT_HEADERS>(m_dosHeader.e_lfanew));
		index == 0)
		return STATUS_ACPI_FATAL;
	return STATUS_SUCCESS;
}

NTSTATUS PortableExecutable::AddStaticTLSEntry() noexcept
{
	if (NTSTATUS status = NT::LdrpHandleTlsData_f(&m_loaderEntry);
		status != STATUS_SUCCESS)
		return status;
	return STATUS_SUCCESS;
}

NTSTATUS PortableExecutable::ExecuteTLSCallbacks() noexcept
{
	const auto& tlsDir = m_ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
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

NTSTATUS PortableExecutable::AddEntryToLdrHashTbl() noexcept
{
	// todo: remove the entry
	NT::LdrpInsertDataTableEntry_f(&m_loaderEntry);
	return STATUS_SUCCESS;
}

NTSTATUS PortableExecutable::EnableExceptions() noexcept
{
	const auto& excDir = 
		m_ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	const auto pExceptTbl = GetRVA<IMAGE_RUNTIME_FUNCTION_ENTRY>(excDir.VirtualAddress);
	// make sure there is an exception table
	if (pExceptTbl == m_image.get())
		return STATUS_SUCCESS;
	if (RtlAddFunctionTable(pExceptTbl, excDir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), 
		reinterpret_cast<DWORD64>(m_image.get())) == FALSE)
		return STATUS_ACPI_FATAL;
	// add it to the inverted function table too.
	// this lets GetModuleHandleEx find us with a code ptr
	// and will also allow us to add SEH in the future
	NT::RtlInsertInvertedFunctionTable_f(GetRVA<IMAGE_DOS_HEADER>(0), 
		m_ntHeaders.OptionalHeader.SizeOfImage);
	return STATUS_SUCCESS;
}

DWORD PortableExecutable::SectionFlagsToProtectionFlags(DWORD sectionFlags) noexcept
{
	if (sectionFlags & IMAGE_SCN_MEM_EXECUTE)
		return PAGE_EXECUTE_READ;
	else if (sectionFlags & IMAGE_SCN_MEM_WRITE)
		return PAGE_READWRITE;
	else
		return PAGE_READONLY;
}