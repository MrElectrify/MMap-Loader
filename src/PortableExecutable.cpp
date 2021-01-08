#include <MMapLoader/PortableExecutable.h>

#include <fstream>

#include <ntstatus.h>

using MMapLoader::PortableExecutable;

std::optional<std::variant<DWORD, NTSTATUS>> PortableExecutable::Load(const std::string& path) noexcept
{
	// first, try to open the file
	std::ifstream executableFile(path, std::ios_base::binary);
	if (executableFile.good() == false)
		return STATUS_FILE_NOT_AVAILABLE;
	// import headers
	if (NTSTATUS status = LoadHeaders(executableFile);
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
	return std::nullopt;
}

NTSTATUS PortableExecutable::LoadHeaders(std::ifstream& peFile) noexcept
{
	// first, load the DOS header
	if (peFile.read(reinterpret_cast<char*>(&m_dosHeader), 
		sizeof(m_dosHeader)).fail() == true)
		return STATUS_END_OF_FILE;
	// check the magic number
	if (m_dosHeader.e_magic != 0x5a4d)
		return STATUS_INVALID_IMAGE_NOT_MZ;
	// seek to the nt headers and load it
	if (peFile.seekg(m_dosHeader.e_lfanew).fail() == true ||
		peFile.read(reinterpret_cast<char*>(&m_ntHeaders), 
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
		if (peFile.read(reinterpret_cast<char*>(&m_sectionHeaders[i]), 
			sizeof(m_sectionHeaders[i])).fail() == true)
			return STATUS_END_OF_FILE;
	}
	return STATUS_SUCCESS;
}

NTSTATUS PortableExecutable::LoadSections(std::ifstream& peFile) noexcept
{
	return STATUS_SUCCESS;
}