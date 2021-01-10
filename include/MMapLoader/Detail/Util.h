#ifndef MMAPLOADER_DETAIL_UTIL_H_
#define MMAPLOADER_DETAIL_UTIL_H_

/// @file
/// Util
/// 1/9/21 20:00

// STL includes
#include <cstddef>
#include <string_view>

// Windows includes
#include <Windows.h>

namespace MMapLoader
{
	namespace Detail
	{
		namespace Util
		{
			/// @brief Finds a pattern in a module
			/// @param hModule The module handle
			/// @param signature The signature of the pattern
			/// @param mask The mask of the pattern
			/// @param offset An offset from the beginning of the pattern
			/// @return The address of the pattern, or nullptr if not found
			void* FindPattern(HMODULE hModule, std::string_view signature, size_t offset) noexcept;
			/// @brief Finds a pattern in a module
			/// @tparam N The size of the literal signature
			/// @param hModule The module handle
			/// @param signature The signature of the pattern
			/// @param mask The mask of the pattern
			/// @param offset An offset from the beginning of the pattern
			/// @return The address of the pattern, or nullptr if not found
			template<size_t N>
			void* FindPattern(HMODULE hModule, const char(&signature)[N], size_t offset) noexcept
			{
				return FindPattern(hModule, std::string_view(signature, N), offset);
			}
			/// @brief Finds a pattern in a module
			/// @tparam T The type of pattern to find
			/// @param hModule The module handle
			/// @param signature The signature of the pattern
			/// @param mask The mask of the pattern
			/// @param offset The offset from the beginning of the pattern to the data
			/// @return The address of the pattern, or nullptr if not found
			template<typename T>
			T FindPattern(HMODULE hModule, std::string_view signature, size_t offset) noexcept
			{
				return reinterpret_cast<T>(FindPattern(hModule, signature, offset));
			}
			/// @brief Finds a pattern in a module
			/// @tparam T The type of pattern to find
			/// @tparam N The size of the literal signature
			/// @param signature The signature of the pattern
			/// @param mask The mask of the pattern
			/// @param offset The offset from the beginning of the pattern to the data
			/// @return The address of the pattern, or nullptr if not found
			template<typename T, size_t N>
			T FindPattern(HMODULE hModule, const char(&signature)[N], size_t offset) noexcept
			{
				return FindPattern<T>(hModule, std::string_view(signature, N), offset);
			}

			/// @brief Find an indirect pattern in a module (e.g. indirect call)
			/// @param signature The signature of the pattern
			/// @param mask The mask of the pattern
			/// @param offset The offset from the beginning of the pattern to the indirect offset
			/// @param offsetSize The size of the offset
			/// @return The address of the pattern, or nullptr if not found
			void* FindPatternIndirect(HMODULE hModule, std::string_view signature, size_t offset) noexcept;
			/// @brief Find an indirect pattern in memory (e.g. indirect call)
			/// @tparam N The length of the literal signature
			/// @param signature The signature of the pattern
			/// @param mask The mask of the pattern
			/// @param offset The offset from the beginning of the pattern to the indirect offset
			/// @param offsetSize The size of the offset
			/// @return The address of the pattern, or nullptr if not found
			template<size_t N>
			void* FindPatternIndirect(HMODULE hModule, const char(&signature)[N], size_t offset) noexcept
			{
				return FindPatternIndirect(hModule, std::string_view(signature, N), offset);
			}
			/// @brief Find an indirect pattern in memory (e.g. indirect call)
			/// @tparam T The type of pattern to find
			/// @param signature The signature of the pattern
			/// @param mask The mask of the pattern
			/// @param offset The offset from the beginning of the pattern to the indirect offset
			/// @param offsetSize The size of the offset
			/// @return The address of the pattern, or nullptr if not found
			template<typename T>
			T FindPatternIndirect(HMODULE hModule, std::string_view signature, size_t offset) noexcept
			{
				return reinterpret_cast<T>(FindPatternIndirect(hModule, signature, offset));
			}
			/// @brief Find an indirect pattern in memory (e.g. indirect call)
			/// @tparam T The type of pattern to find
			/// @tparam N The length of the literal signature
			/// @param signature The signature of the pattern
			/// @param mask The mask of the pattern
			/// @param offset The offset from the beginning of the pattern to the indirect offset
			/// @param offsetSize The size of the offset
			/// @return The address of the pattern, or nullptr if not found
			template<typename T, size_t N>
			T FindPatternIndirect(HMODULE hModule, const char(&signature)[N], size_t offset) noexcept
			{
				return FindPatternIndirect<T>(hModule, std::string_view(signature, N), offset);
			}
		}
	}
}

#endif