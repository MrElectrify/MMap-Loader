#ifndef MMAPLOADER_MMAP_H_
#define MMAPLOADER_MMAP_H_

/// @file
/// MMap Loader
/// 8/9/20 11:27

#include <Windows.h>

enum Stage
{
	Attach,
	MapExe,
	MapDll
};

struct Result
{
	bool success;
	NTSTATUS status;
	const char* statusStr;
	Stage stage;
};

extern "C" void Run(const char* exePath, size_t exePathLen, void* dllBuf, size_t dllBufLen, Result* result);

#endif