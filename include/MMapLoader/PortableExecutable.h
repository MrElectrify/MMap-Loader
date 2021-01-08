#ifndef MMAPLOADER_PORTABLEEXECUTABLE_H_
#define MMAPLOADER_PORTABLEEXECUTABLE_H_

/// @file
/// PortableExecutable
/// 1/7/21 17:36

// STL includes
#include <fstream>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

// Windows includes
#include <Windows.h>

namespace MMapLoader
{
	/// @brief An abstraction for a PE executable, manually mapped into the local space
	class PortableExecutable
	{
	public:
		PortableExecutable() = default;
		PortableExecutable(const PortableExecutable&) = delete;
		PortableExecutable& operator=(const PortableExecutable&) = delete;
		PortableExecutable(PortableExecutable&&) = default;
		PortableExecutable& operator=(PortableExecutable&&) = default;

		/// @brief Attempts to load an executable from a file
		/// @param path The path of the executable
		/// @return The status code
		std::optional<std::variant<DWORD, NTSTATUS>> Load(const std::string& path) noexcept;
	private:
		/// @brief Loads NT Headers from the pe file
		/// @param peFile The pe file
		/// @return The status code
		NTSTATUS LoadHeaders(std::ifstream& peFile) noexcept;
		/// @brief Loads sections from the pe file
		/// @param peFile The pe file
		/// @return The status code
		NTSTATUS LoadSections(std::ifstream& peFile) noexcept;

		IMAGE_DOS_HEADER m_dosHeader;
		IMAGE_NT_HEADERS m_ntHeaders;
		std::vector<IMAGE_SECTION_HEADER> m_sectionHeaders;

		std::shared_ptr<void> m_image;
	};
}

#endif