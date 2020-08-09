#include <MMapLoader/MMap.h>

#include <BlackBone/ManualMap/MMap.h>
#include <BlackBone/Process/Process.h>

#include <array>
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
	blackbone::Process process;
	if (NTSTATUS status = process.Attach(hProc); status != STATUS_SUCCESS)
	{
		pResult->success = false;
		pResult->status = status;
		pResult->statusStr = FormatNTStatus(status);
		return;
	}
	const auto image = process.mmap().MapImage(len, buffer);
	if (image.success() == false)
	{
		pResult->success = false;
		pResult->status = image.status;
		pResult->statusStr = FormatNTStatus(image.status);
		return;
	}
	pResult->success = true;
}