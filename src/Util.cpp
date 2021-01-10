#include <MMapLoader/Util.h>

using namespace MMapLoader;

// Boyer-Moore-Horspool with wildcards implementation
void FillShiftTable(const uint8_t* pPattern, size_t patternSize, uint8_t wildcard, size_t* bad_char_skip)
{
    size_t idx = 0;
    size_t last = patternSize - 1;

    // Get last wildcard position
    for (idx = last; idx > 0 && pPattern[idx] != wildcard; --idx);
    size_t diff = last - idx;
    if (diff == 0)
        diff = 1;

    // Prepare shift table
    for (idx = 0; idx <= UCHAR_MAX; ++idx)
        bad_char_skip[idx] = diff;
    for (idx = last - diff; idx < last; ++idx)
        bad_char_skip[pPattern[idx]] = last - idx;
}

void* Search(uint8_t* pScanPos, size_t scanSize, const uint8_t* pPattern, size_t patternSize, uint8_t wildcard)
{
    size_t bad_char_skip[UCHAR_MAX + 1];
    const uint8_t* scanEnd = pScanPos + scanSize - patternSize;
    intptr_t last = static_cast<intptr_t>(patternSize) - 1;

    FillShiftTable(pPattern, patternSize, wildcard, bad_char_skip);

    // Search
    for (; pScanPos <= scanEnd; pScanPos += bad_char_skip[pScanPos[last]])
    {
        for (intptr_t idx = last; idx >= 0; --idx)
            if (pPattern[idx] != wildcard && pScanPos[idx] != pPattern[idx])
                goto skip;
            else if (idx == 0)
                return pScanPos;
    skip:;
    }

    return nullptr;
}

void* Util::FindPattern(HMODULE hModule, std::string_view signature, size_t offset) noexcept
{
    PIMAGE_NT_HEADERS pNTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uintptr_t>(hModule) + reinterpret_cast<PIMAGE_DOS_HEADER>(hModule)->e_lfanew);
    const LPVOID pCode = reinterpret_cast<LPVOID>(
        reinterpret_cast<uintptr_t>(hModule) + pNTHeaders->OptionalHeader.BaseOfCode);
    MEMORY_BASIC_INFORMATION mi;
    if (VirtualQuery(pCode, &mi, sizeof(mi)) == 0)
        return nullptr;
    uint8_t* res = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(
        Search(reinterpret_cast<BYTE*>(mi.AllocationBase),
            static_cast<size_t>(mi.RegionSize),
            reinterpret_cast<const uint8_t*>(signature.data()), signature.size(), '\0')));
    return (res == nullptr) ? nullptr : res + offset;
}

void* Util::FindPatternIndirect(HMODULE hModule, std::string_view signature, size_t offset) noexcept
{
    int32_t* pOffset = FindPattern<int32_t*>(hModule, signature, offset);
    if (pOffset == nullptr)
        return nullptr;
    // the actual address is an indirect offset from pPattern - offset
    return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(pOffset) + *pOffset + sizeof(int32_t));
}
