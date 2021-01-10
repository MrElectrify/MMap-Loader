#ifndef MMAPLOADER_MMAP_H_
#define MMAPLOADER_MMAP_H_

/// @file
/// MMap Loader
/// 8/9/20 11:27

#include <Windows.h>

struct Result
{
	bool success;
	DWORD status;
	const char* statusStr;
};

/// @brief Runs an executable, and a DLL
/// @param exePath The path of the executable file
/// @param exePathLen The length of the path of the executable file
/// @param dllPaths The paths of the dll files
/// @param dllPathLens The length of the paths of the dll files
/// @param numDlls The number of dlls
/// @param result The result of the operation
extern "C" void Run(const char* exePath, size_t exePathLen, const char** dllPaths, size_t* dllPathLens, size_t numDlls, Result* result);

#endif