#ifndef MMAPLOADER_PORTABLEEXECUTABLE_H_
#define MMAPLOADER_PORTABLEEXECUTABLE_H_

/// @file
/// PortableExecutable
/// 1/7/21 17:36

// MMapLoader includes
#include <MMapLoader/NtStructs.h>

// STL includes
#include <fstream>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

// Windows includes
#define WIN32_LEAN_AND_MEAN 1
#include <Windows.h>
#include <bcrypt.h>

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
		/// @brief Runs the entry point of the executable
		/// @return The return code of the entry point
		int Run() noexcept;
	private:
		/// @brief Allocates memory for the image
		/// @return The status code
		DWORD AllocImage() noexcept;
		/// @brief Loads NT Headers from the pe file
		/// @return The status code
		NTSTATUS LoadHeaders() noexcept;
		/// @brief Loads sections from the pe file
		/// @return The status code
		std::optional<std::variant<DWORD, NTSTATUS>> LoadSections() noexcept;
		/// @brief Process the executable's relocations
		/// @return The status code
		NTSTATUS ProcessRelocations() noexcept;
		/// @brief Resolve the executable's imports
		/// @return The status code
		std::optional<std::variant<DWORD, NTSTATUS>> ResolveImports() noexcept;
		/// @brief Initializes Thread-Local Storage
		/// @return The status code
		NTSTATUS InitTLS() noexcept;
		/// @brief Adds the static TLS entry
		/// @return The status code
		NTSTATUS AddStaticTLSEntry() noexcept;
		/// @brief Executes TLS callbacks
		/// @return The status code
		NTSTATUS ExecuteTLSCallbacks() noexcept;
		/// @brief Frees discardable sections
		/// @return The status code
		DWORD FreeDiscardableSections() noexcept;
		/// @brief Enable exception support. Only enables SEH for now
		/// @return The status code
		NTSTATUS EnableExceptions() noexcept;

		/// @brief Generates protection flags from a section's flags
		/// @param sectionFlags The section's flags
		/// @return The protection flags
		static DWORD SectionFlagsToProtectionFlags(DWORD sectionFlags) noexcept;

		/// @brief Gets a structure at an RVA offset
		/// @tparam T The type to get
		/// @param offset The offset to the structure
		/// @return The structure
		template<typename T>
		T* GetRVA(uintptr_t offset)
		{
			return reinterpret_cast<T*>(
				reinterpret_cast<uintptr_t>(m_image.get()) + offset);
		}

		std::ifstream m_peFile;

		IMAGE_DOS_HEADER m_dosHeader;
		IMAGE_NT_HEADERS m_ntHeaders;
		std::vector<IMAGE_SECTION_HEADER> m_sectionHeaders;
		_LDR_DATA_TABLE_ENTRY_BASE64 m_loaderEntry{};

		std::shared_ptr<void> m_image;
	};
}

#endif