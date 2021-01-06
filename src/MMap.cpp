#include <MMapLoader/MMap.h>

#include <BlackBone/ManualMap/MMap.h>

#include <array>
#include <fstream>
#include <system_error>

const char* FormatNTStatus(NTSTATUS status)
{
	static std::array<char, 256> buf;
	static const auto ntHandle = LoadLibraryW(L"ntdll.dll");
	if (FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_FROM_HMODULE,
		ntHandle, status, 0, buf.data(), static_cast<DWORD>(buf.size()), nullptr) == 0)
	{
		// yikes, we even failed this.
		const auto str = std::system_category().message(GetLastError());
		strncpy_s(buf.data(), buf.size(), str.c_str(), str.size());
	}
	return buf.data();
}

void Inject(HANDLE hProc, void* buffer, size_t len, Result* pResult)
{
	
	pResult->success = true;
}