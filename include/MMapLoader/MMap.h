#ifndef MMAPLOADER_MMAP_H_
#define MMAPLOADER_MMAP_H_

/// @file
/// MMap Loader
/// 8/9/20 11:27

#include <Windows.h>

extern "C" bool Inject(HANDLE hProc, void* buffer, size_t len);

#endif