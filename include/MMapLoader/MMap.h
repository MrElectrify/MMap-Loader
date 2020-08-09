#ifndef MMAPLOADER_MMAP_H_
#define MMAPLOADER_MMAP_H_

/// @file
/// MMap Loader
/// 8/9/20 11:27

#include <Windows.h>

struct Result
{
	bool success;
	NTSTATUS status;
	const char* statusStr;
};

extern "C" void Inject(HANDLE hProc, void* buffer, size_t len, Result* result);

#endif