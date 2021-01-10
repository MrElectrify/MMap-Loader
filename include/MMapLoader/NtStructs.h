#ifndef MMAPLOADER_NTSTRUCTS_H_
#define MMAPLOADER_NTSTRUCTS_H_

/// @file
/// NT Structs
/// 1/9/21 19:54

// STL includes
#include <cstdint>

namespace MMapLoader
{
    template <typename T>
    struct _LIST_ENTRY_T
    {
        T Flink;
        T Blink;
    };

    template <typename T>
    struct _UNICODE_STRING_T
    {
        using type = T;

        uint16_t Length;
        uint16_t MaximumLength;
        T Buffer;
    };

    template<typename T>
    struct _LDR_DATA_TABLE_ENTRY_BASE_T
    {
        _LIST_ENTRY_T<T> InLoadOrderLinks;
        _LIST_ENTRY_T<T> InMemoryOrderLinks;
        _LIST_ENTRY_T<T> InInitializationOrderLinks;
        T DllBase;
        T EntryPoint;
        uint32_t SizeOfImage;
        _UNICODE_STRING_T<T> FullDllName;
        _UNICODE_STRING_T<T> BaseDllName;
        uint32_t Flags;
        uint16_t LoadCount;
        uint16_t TlsIndex;
        _LIST_ENTRY_T<T> HashLinks;
        uint32_t TimeDateStamp;
        T EntryPointActivationContext;
        T PatchInformation;
    };
    using _LDR_DATA_TABLE_ENTRY_BASE64 = _LDR_DATA_TABLE_ENTRY_BASE_T<uint64_t>;
}

#endif