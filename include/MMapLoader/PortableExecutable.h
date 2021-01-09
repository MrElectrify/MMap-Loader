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
		/// @brief Resolve the executable's imports
		/// @return The status code
		NTSTATUS ResolveImports() noexcept;
		/// @brief Executes TLS callbacks
		/// @return The status code
		NTSTATUS ExecuteTLSCallbacks() noexcept;

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

		std::shared_ptr<void> m_image;
	};
}

#endif