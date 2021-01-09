#include <MMapLoader/PortableExecutable.h>

#include <fstream>
#include <iostream>
#include <type_traits>

#include <ntstatus.h>

using MMapLoader::PortableExecutable;

std::optional<std::variant<DWORD, NTSTATUS>> PortableExecutable::Load(const std::string& path) noexcept
{
	// first, try to open the file
	m_peFile.open(path, std::ios_base::binary);
	if (m_peFile.good() == false)
		return STATUS_FILE_NOT_AVAILABLE;
	// import headers
	if (NTSTATUS status = LoadHeaders();
		status != STATUS_SUCCESS)
		return status;
	// attempt to allocate memory for the process
	m_image = std::shared_ptr<void>(VirtualAlloc(
		reinterpret_cast<LPVOID>(m_ntHeaders.OptionalHeader.ImageBase),
		m_ntHeaders.OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE), std::bind(VirtualFree,
			std::placeholders::_1, 0, MEM_DECOMMIT | MEM_RELEASE));
	if (m_image == nullptr)
		return GetLastError();
	// copy the headers
	if (m_peFile.seekg(0).fail() == true ||
		m_peFile.read(reinterpret_cast<char*>(m_image.get()),
			m_ntHeaders.OptionalHeader.SizeOfHeaders).fail() == true)
		return STATUS_END_OF_FILE;
	// now load sections
	if (NTSTATUS status = LoadSections();
		status != STATUS_SUCCESS)
		return status;
	// and process relocations
	if (NTSTATUS status = ProcessRelocations();
		status != STATUS_SUCCESS)
		return status;
	// resolve imports
	if (NTSTATUS status = ResolveImports();
		status != STATUS_SUCCESS)
		return status;
	return std::nullopt;
}

int PortableExecutable::Run() noexcept
{
	if (m_image == nullptr)
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
	if (m_dosHeader.e_magic != 0x5a4d)
		return STATUS_INVALID_IMAGE_NOT_MZ;
	// seek to the nt headers and load it
	if (m_peFile.seekg(m_dosHeader.e_lfanew).fail() == true ||
		m_peFile.read(reinterpret_cast<char*>(&m_ntHeaders), 
			sizeof(m_ntHeaders)).fail() == true)
		return STATUS_END_OF_FILE;
	// verify the architecture
	if (m_ntHeaders.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
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

NTSTATUS PortableExecutable::LoadSections() noexcept
{
	// for each section header, load the section into the image
	for (const auto& sectionHeader : m_sectionHeaders)
	{
		if (m_peFile.seekg(sectionHeader.PointerToRawData).fail() == true ||
			m_peFile.read(reinterpret_cast<char*>(
				reinterpret_cast<uintptr_t>(m_image.get()) +
				sectionHeader.VirtualAddress), sectionHeader.SizeOfRawData).fail() == true)
			return STATUS_END_OF_FILE;
	}
	return STATUS_SUCCESS;
}

NTSTATUS PortableExecutable::ProcessRelocations() noexcept
{
	// first, see if there is even a delta
	uintptr_t delta = reinterpret_cast<uintptr_t>(m_image.get()) -
		m_ntHeaders.OptionalHeader.ImageBase;
	if (delta == 0)
		return STATUS_SUCCESS;
	// see if it is relocatable
	if ((m_ntHeaders.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0)
		return STATUS_INVALID_IMAGE_HASH;
	// TODO: relocate it
	return STATUS_SUCCESS;
}

NTSTATUS PortableExecutable::ResolveImports() noexcept
{
	const auto& importDir =
		m_ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
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
			std::cout << "Resolved " << libName << ':';
			if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				std::cout << reinterpret_cast<uint32_t>(procName);
			else
				std::cout << procName;
			std::cout << " to " << function << '\n';
			// set the First thunk's function
			pThunk->u1.Function = reinterpret_cast<ULONGLONG>(function);
			if (pThunk->u1.Function == 0)
				return STATUS_NOT_FOUND;
		}
	};
	return STATUS_SUCCESS;
}