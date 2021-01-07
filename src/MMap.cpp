#include <MMapLoader/MMap.h>

#include <BlackBone/ManualMap/MMap.h>
#include <BlackBone/Process/Process.h>

#include <array>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <system_error>
#include <vector>

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
	blackbone::Process thisProc;
	// attach to the current process
	if (auto status = thisProc.Attach(GetCurrentProcess());
		status != STATUS_SUCCESS)
	{
		// failed to attach to the current process?
		result->status = status;
		result->statusStr = FormatNTStatus(status);
		result->success = false;
		result->stage = Stage::Attach;
		return;
	}
	std::error_code ec;
	std::string_view exePathStrV(exePathStr, exePathLen);
	if (std::filesystem::exists(exePathStrV) == false ||
		std::filesystem::is_regular_file(exePathStrV) == false)
	{
		result->status = STATUS_FILE_NOT_AVAILABLE;
		result->statusStr = FormatNTStatus(result->status);
		result->success = false;
		result->stage = Stage::MapExe;
		return;
	}
	std::filesystem::path exePath(exePathStrV);
	// set the current directory to the root of the exe
	const auto oldWorkingDirectory = std::filesystem::current_path();
	std::filesystem::current_path(exePath.parent_path(), ec);
	if (ec)
	{
		result->status = ec.value();
		result->statusStr = ec.message().c_str();
		result->success = false;
		result->stage = Stage::MapExe;
		return;
	}
	std::ifstream inFile(exePath, std::ios_base::binary);
	inFile.seekg(0, SEEK_END);
	size_t size = inFile.tellg();
	inFile.seekg(0, SEEK_SET);
	std::vector<char> fileBuf(size);
	inFile.read(fileBuf.data(), fileBuf.size());
	// set the data directory
	SetEnvironmentVariableA("GAME_DATA_DIR",
		exePath.parent_path().string().c_str());
	// attempt to map the exe into the current process
	if (auto status = thisProc.mmap().MapImage(fileBuf.size(), fileBuf.data(), false,
		blackbone::eLoadFlags::NoDelayLoad);
		status.success() == false)
	{
		// failed to map image
		result->status = status.status;
		result->statusStr = FormatNTStatus(status.status);
		result->success = false;
		result->stage = Stage::MapExe;
		return;
	}
	std::filesystem::current_path(oldWorkingDirectory, ec);
	result->success = true;
}