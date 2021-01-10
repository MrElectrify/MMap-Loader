#include <MMapLoader/MMap.h>

#include <MMapLoader/PortableExecutable.h>

#include <array>
#include <filesystem>
#include <system_error>
#include <vector>

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

void Run(const char* exePathStr, size_t exePathLen, const char** dllPaths, 
	size_t* dllBufLens, size_t numDlls, Result* result)
{
	std::filesystem::path exePath(std::string_view(exePathStr, exePathLen));
	// set the current directory to the root of the exe
	const auto oldWorkingDirectory = std::filesystem::current_path();
	std::error_code ec;
	std::filesystem::current_path(exePath.parent_path(), ec);
	if (ec)
	{
		result->status = ec.value();
		static std::array<char, 256> buf;
		const auto str = ec.message();
		strncpy_s(buf.data(), buf.size(), str.c_str(), str.size());
		result->statusStr = buf.data();
		result->success = false;
		return;
	}
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
	std::vector<MMapLoader::PortableExecutable> dlls;
	// load all DLLs
	for (size_t i = 0; i < numDlls; ++i)
	{
		MMapLoader::PortableExecutable dll;
		if (auto status = dll.Load(std::string(dllPaths[i], dllBufLens[i]));
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
		// call DllMain
		if (dll.Run() == TRUE)
			dlls.push_back(std::move(dll));
	}
	executable.Run();
	result->success = true;
}