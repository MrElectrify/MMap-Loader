#include <MMapLoader/MMap.h>

#include <MMapLoader/PortableExecutable.h>

#include <array>
#include <system_error>

const char* FormatError(int error)
{
	static std::array<char, 256> buf;
	const auto str = std::system_category().message(error);
	strncpy_s(buf.data(), buf.size(), str.c_str(), str.size());
	return buf.data();
}

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

void Run(const char* exePathStr, size_t exePathLen, void* dllBuf, size_t dllBufLen, Result* result)
{
	MMapLoader::PortableExecutable executable;
	if (auto status = executable.Load(std::string(exePathStr, exePathLen));
		status.has_value() == true)
	{
		result->success = false;
		switch (status->index())
		{
		case 0:
			result->status = std::get<DWORD>(status.value());
			result->statusStr = FormatError(result->status);
			break;
		case 1:
			result->status = std::get<NTSTATUS>(status.value());
			result->statusStr = FormatNTStatus(result->status);
			break;
		}
		return;
	}
	result->success = true;
}