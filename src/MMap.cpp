#include <MMapLoader/MMap.h>

#include <array>
#include <fstream>
#include <functional>
#include <memory>
#include <system_error>
#include <type_traits>

#include <ShlObj_core.h>
#include <Windows.h>
#include <winerror.h>

const char* FormatStatus(NTSTATUS status)
{
	static std::array<char, 256> buf;
	const auto str = std::system_category().message(GetLastError());
	strncpy(buf.data(), str.c_str(), str.size());
	return buf.data();
}

bool InjectInternal(HANDLE hProc, const std::string& path) noexcept
{
	// allocate memory for the path length
	std::unique_ptr<void, decltype(std::bind(VirtualFreeEx, hProc,
		std::placeholders::_1, 0, MEM_DECOMMIT | MEM_RELEASE))>
		pFuncName(VirtualAllocEx(hProc, nullptr, path.size() + 1,
			MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE), std::bind(VirtualFreeEx,
				hProc, std::placeholders::_1, 0, MEM_DECOMMIT | MEM_RELEASE));
	if (pFuncName == nullptr)
		return false;
	// write the path
	if (WriteProcessMemory(hProc, pFuncName.get(), path.c_str(),
		path.size(), nullptr) == FALSE)
		return false;
	// loadLibraryA
	DWORD exitCode;
	for (size_t i = 0; i < 3; ++i)
	{
		std::unique_ptr<void, std::add_pointer_t<decltype(CloseHandle)>>
			hThread(CreateRemoteThread(hProc, nullptr, 0,
				reinterpret_cast<LPTHREAD_START_ROUTINE>(&LoadLibraryA),
				pFuncName.get(), NULL, nullptr), CloseHandle);
		if (hThread == nullptr)
			return false;
		if (WaitForSingleObject(hThread.get(), INFINITE) != WAIT_OBJECT_0)
			return false;
		if (GetExitCodeThread(hThread.get(), &exitCode) == FALSE)
			return false;
		if (exitCode != 0)
			break;
	}
	return exitCode != 0;
}

void Inject(HANDLE hProc, void* buffer, size_t len, Result* pResult)
{
	// save the file to %appdata%
	PWSTR str;
	if (SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &str) != S_OK)
	{
		CoTaskMemFree(str);
		pResult->status = GetLastError();
		pResult->statusStr = FormatStatus(pResult->status);
		return;
	}
	std::wstring_view pathView(str);
	std::string path(pathView.begin(), pathView.end());
	CoTaskMemFree(str);
	path += "\\warsawrevamped\\wr.dll";
	path.push_back('\0');
	std::ofstream outFile(path, std::ios_base::binary);
	if (outFile.good() == false)
	{
		pResult->status = 2;
		pResult->statusStr = FormatStatus(pResult->status);
		return;
	}
	outFile.write(reinterpret_cast<const char*>(buffer), len);
	outFile.close();
	if (InjectInternal(hProc, path) == false)
	{
		pResult->status = GetLastError();
		pResult->statusStr = FormatStatus(pResult->status);
		pResult->success = false;
		return;
	}
	pResult->success = true;
}