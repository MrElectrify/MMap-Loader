#ifndef MMAPLOADER_DETAIL_FNPTR_H_
#define MMAPLOADER_DETAIL_FNPTR_H_

/// @file
/// Function Pointer
/// 3/17/21 15:47

// MMapLoader includes
#include <MMapLoader/Detail/Util.h>

// STL includes
#include <cstdint>
#include <string_view>
#include <utility>

namespace MMapLoader
{
	namespace Detail
	{
		template<typename T>
		class FnPtr
		{
		public:
			/// @brief Finds a function pointer with a signature
			/// @param hModule The module that contains the function
			/// @param signature The signature
			/// @param offset The offset from the signature
			/// @param indirect Whether or not the signature is indirect
			FnPtr(HMODULE hModule, std::string_view signature, uint32_t offset = 0, bool indirect = false) noexcept
			{
				m_ptr = indirect ?
					Util::FindPatternIndirect<T>(hModule, signature, offset) :
					Util::FindPattern<T>(hModule, signature, offset);
			}

			/// @brief Finds a function pointer with a signature
			/// @param hModule The module that contains the function
			/// @param signature The signature
			/// @param offset The offset from the signature
			/// @param indirect Whether or not the signature is indirect
			/// @tparam N The signature length
			template<size_t N>
			FnPtr(HMODULE hModule, const char(&signature)[N], uint32_t offset = 0, bool indirect = false) noexcept
				: FnPtr(hModule, std::string_view(signature, N - 1), offset, indirect) {}

			/// @brief Finds a function pointer with a signature if the stored one is not valid
			/// @param hModule The module that contains the function
			/// @param signature The signature
			/// @param offset The offset from the signature
			/// @param indirect Whether or not the signature is indirect
			/// @return The new function pointer
			FnPtr&& OrElse(HMODULE hModule, std::string_view signature, uint32_t offset = 0, bool indirect = false) noexcept
			{
				return IsValid() ? std::move(*this) : FnPtr(hModule, signature, offset, indirect);
			}

			/// @brief Finds a function pointer with a signature if the stored one is not valid
			/// @param hModule The module that contains the function
			/// @param signature The signature
			/// @param offset The offset from the signature
			/// @param indirect Whether or not the signature is indirect
			/// @return The new function pointer
			template<size_t N>
			FnPtr&& OrElse(HMODULE hModule, const char(&signature)[N], uint32_t offset = 0, bool indirect = false) noexcept
			{
				return OrElse(hModule, std::string_view(signature, N), offset, indirect);
			}

			/// @return Whether or not the function pointer is valid
			bool IsValid() const noexcept { return m_ptr != nullptr; }

			/// @return The stored pointer
			T GetPtr() const noexcept { return m_ptr; }
		private:
			T m_ptr;
		};
	}
}

#endif