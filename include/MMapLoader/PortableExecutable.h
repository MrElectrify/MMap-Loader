#ifndef MMAPLOADER_PORTABLEEXECUTABLE_H_
#define MMAPLOADER_PORTABLEEXECUTABLE_H_

/// @file
/// PortableExecutable
/// 1/7/21 17:36

// MMapLoader includes
#include <MMapLoader/Detail/NtStructs.h>

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
		BOOL Run() noexcept;
		/// @return The base address of the executable
		void* GetImageBase() const noexcept { return m_image.get(); }
	private:
		/// @brief Maps the PE file into memory
		/// @param path The path to the PE file
		/// @return The status code
		NTSTATUS MapFile(const std::string& path) noexcept;
		/// @brief Loads NT Headers from the pe file
		/// @return The status code
		NTSTATUS LoadHeaders() noexcept;
		/// @brief Protects sections based on their characteristics
		/// @return The status code
		DWORD ProtectSections() noexcept;
		/// @brief Process the executable's relocations
		/// @return The status code
		NTSTATUS ProcessRelocations() noexcept;
		/// @brief Resolve the executable's imports
		/// @return The status code
		std::optional<std::variant<DWORD, NTSTATUS>> ResolveImports() noexcept;
		/// @brief Initializes Thread-Local Storage
		/// @return The status code
		NTSTATUS InitTLS() noexcept;
		/// @brief Initializes the loader entry
		/// @return The status code
		NTSTATUS InitLoaderEntry() noexcept;
		/// @brief Adds the static TLS entry
		/// @return The status code
		NTSTATUS AddStaticTLSEntry() noexcept;
		/// @brief Executes TLS callbacks
		/// @return The status code
		NTSTATUS ExecuteTLSCallbacks() noexcept;
		/// @brief Adds the entry to the loader hash table
		/// @return The status code
		NTSTATUS AddEntryToLdrHashTbl() noexcept;
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

		Detail::NT::_LDR_DATA_TABLE_ENTRY64 m_loaderEntry{};
		Detail::NT::_LDR_DDAG_NODE64 m_ddagNode{};

		std::wstring m_modPath;
		std::wstring m_modName;

		IMAGE_DOS_HEADER m_dosHeader;
		IMAGE_NT_HEADERS m_ntHeaders;
		std::vector<IMAGE_SECTION_HEADER> m_sectionHeaders;

		std::shared_ptr<void> m_image;
	};
}

#endif