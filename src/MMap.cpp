#include <MMapLoader/MMap.h>

#include <BlackBone/ManualMap/MMap.h>
#include <BlackBone/Process/Process.h>

#include <array>
#include <fstream>
#include <system_error>

const char* FormatNTStatus(NTSTATUS status)
{
	static std::array<char, 256> buf;
	static const auto ntHandle = LoadLibraryW(L"ntdll.dll");
	if (FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_FROM_HMODULE,
		ntHandle, status, 0, buf.data(), buf.size(), nullptr) == 0)
	{
		// yikes, we even failed this.
		const auto str = std::system_category().message(GetLastError());
		strncpy(buf.data(), str.c_str(), str.size());
	}
	return buf.data();
}

void Inject(HANDLE hProc, void* buffer, size_t len, Result* pResult)
{
	pResult->success = true;
	constexpr size_t COUNT = 100;
	for (size_t i = 0; i < COUNT; ++i)
	{
		std::ofstream("log.txt") << i;
		blackbone::Process process;
		if (NTSTATUS status = process.Attach(hProc); status != STATUS_SUCCESS)
		{
			pResult->success = false;
			pResult->status = status;
			continue;
		}
		const auto image = process.mmap().MapImage(len, buffer);
		if (image.success() == false)
		{
			pResult->success = false;
			pResult->status = image.status;
			continue;
		}
		break;
	}
	if (pResult->success == false)
	{
		pResult->statusStr = FormatNTStatus(pResult->status);
		return;
	}
}