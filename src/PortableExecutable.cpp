#include <MMapLoader/PortableExecutable.h>
#include <MMapLoader/Util.h>

#include <fstream>
#include <memory>
#include <type_traits>

#include <ntstatus.h>

using MMapLoader::PortableExecutable;

std::optional<std::variant<DWORD, NTSTATUS>> PortableExecutable::Load(const std::string& path) noexcept
{
	// close the file if it's already open
	m_peFile.close();
	// first, try to open the file
	m_peFile.open(path, std::ios_base::binary);
	if (m_peFile.good() == false)
		return ERROR_FILE_NOT_FOUND;
	// import headers
	if (NTSTATUS status = LoadHeaders();
		status != STATUS_SUCCESS)
		return status;
	// allocate the image
	if (DWORD status = AllocImage();
		status != ERROR_SUCCESS)
		return status;
	// now load sections
	if (auto status = LoadSections();
		status.has_value() == true)
		return status;
	// and process relocations
	if (NTSTATUS status = ProcessRelocations();
		status != STATUS_SUCCESS)
		return status;
	// resolve imports
	if (auto status = ResolveImports();
		status.has_value() == true)
		return status;
	// initialize static TLS data and execute callbacks
	if (NTSTATUS status = InitTLS();
		status != STATUS_SUCCESS)
		return status;
	// free discardable sections
	if (DWORD status = FreeDiscardableSections();
		status != ERROR_SUCCESS)
		return status;
	if (NTSTATUS status = EnableExceptions();
		status != STATUS_SUCCESS)
		return status;
	return std::nullopt;
}

DWORD PortableExecutable::AllocImage() noexcept
{
	// first allocate the image as READWRITE
	const LPVOID pMem = VirtualAlloc(
		reinterpret_cast<LPVOID>(m_ntHeaders.OptionalHeader.ImageBase),
		m_ntHeaders.OptionalHeader.SizeOfImage, MEM_RESERVE, PAGE_NOACCESS);
	if (pMem == nullptr)
		return GetLastError();
	m_image = std::shared_ptr<void>(pMem,
		std::bind(VirtualFree, std::placeholders::_1,
			m_ntHeaders.OptionalHeader.SizeOfImage, MEM_DECOMMIT | MEM_RELEASE));
	// commit the headers and read them in
	if (VirtualAlloc(m_image.get(), m_ntHeaders.OptionalHeader.SizeOfHeaders,
		MEM_COMMIT, PAGE_READWRITE) == nullptr)
		return GetLastError();
	if (m_peFile.seekg(0, SEEK_SET).fail() == true ||
		m_peFile.read(reinterpret_cast<char*>(m_image.get()),
			m_ntHeaders.OptionalHeader.SizeOfHeaders).fail() == true)
		return ERROR_FILE_CORRUPT;
	return ERROR_SUCCESS;
}

int PortableExecutable::Run() noexcept
{
	if (m_image.get() == nullptr)
		return -1;
	auto EntryPoint_f = GetRVA<int()>(m_ntHeaders.OptionalHeader.AddressOfEntryPoint);
	return EntryPoint_f();
}

NTSTATUS PortableExecutable::LoadHeaders() noexcept
{
	// first, load the DOS header
	if (m_peFile.read(reinterpret_cast<char*>(&m_dosHeader),
		sizeof(m_dosHeader)).fail() == true)
		return STATUS_END_OF_FILE;
	// check the magic number
	if (m_dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
		return STATUS_INVALID_IMAGE_NOT_MZ;
	// seek to the nt headers and load it
	if (m_peFile.seekg(m_dosHeader.e_lfanew).fail() == true ||
		m_peFile.read(reinterpret_cast<char*>(&m_ntHeaders),
			sizeof(m_ntHeaders)).fail() == true)
		return STATUS_END_OF_FILE;
	// verify the architecture
	if (m_ntHeaders.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
		m_ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return STATUS_INVALID_IMAGE_FORMAT;
	// make space for the section headers and load them
	m_sectionHeaders.resize(m_ntHeaders.FileHeader.NumberOfSections);
	// read sections
	for (WORD i = 0; i < m_ntHeaders.FileHeader.NumberOfSections; ++i)
	{
		if (m_peFile.read(reinterpret_cast<char*>(&m_sectionHeaders[i]),
			sizeof(m_sectionHeaders[i])).fail() == true)
			return STATUS_END_OF_FILE;
	}
	return STATUS_SUCCESS;
}

std::optional<std::variant<DWORD, NTSTATUS>> PortableExecutable::LoadSections() noexcept
{
	// for each section header, load the section into the image
	for (const auto& sectionHeader : m_sectionHeaders)
	{
		// check size to ensure no buffer overrun
		if (sectionHeader.VirtualAddress + sectionHeader.Misc.VirtualSize >=
			m_ntHeaders.OptionalHeader.SizeOfImage)
			return STATUS_SECTION_TOO_BIG;
		const auto sectionAddr = GetRVA<char>(sectionHeader.VirtualAddress);
		// commit the memory
		if (VirtualAlloc(sectionAddr, sectionHeader.Misc.VirtualSize, MEM_COMMIT,
			PAGE_READWRITE) == nullptr)
			return GetLastError();
		// read the data to the section
		if (m_peFile.seekg(sectionHeader.PointerToRawData).fail() == true ||
			m_peFile.read(sectionAddr, sectionHeader.SizeOfRawData).fail() == true)
			return STATUS_END_OF_FILE;
		// change protection to the corresponding protection
		DWORD oldProtect = 0;
		if (VirtualProtect(sectionAddr, sectionHeader.Misc.VirtualSize,
			SectionFlagsToProtectionFlags(sectionHeader.Characteristics),
			&oldProtect) == FALSE)
			return GetLastError();
	}
	return std::nullopt;
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

NTSTATUS PortableExecutable::AddStaticTLSEntry() noexcept
{
	using LdrpHandleTlsData_t = std::add_pointer_t<NTSTATUS NTAPI(
		_LDR_DATA_TABLE_ENTRY_BASE64* pLdrDataTable)>;
	static const LdrpHandleTlsData_t LdrpHandleTlsData_f =
		reinterpret_cast<LdrpHandleTlsData_t>(Util::FindPatternIndirect(
			GetModuleHandle("ntdll"), 
			"\xE8\x00\x00\x00\x00\x8B\xD8\x85\xC0\x78\x0B\xE8\x00\x00\x00\x00", 1));
	if (LdrpHandleTlsData_f == nullptr)
		return STATUS_ACPI_FATAL;
	m_loaderEntry.DllBase = reinterpret_cast<uint64_t>(m_image.get());
	if (NTSTATUS status = LdrpHandleTlsData_f(&m_loaderEntry);
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

DWORD PortableExecutable::FreeDiscardableSections() noexcept
{
	for (const auto& sectionHeader : m_sectionHeaders)
	{
		if (sectionHeader.Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
		{
			// free the section
			if (VirtualFree(GetRVA<void>(sectionHeader.PointerToRawData),
				sectionHeader.SizeOfRawData, MEM_DECOMMIT) == FALSE)
				return GetLastError();
		}
	}
	return ERROR_SUCCESS;
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