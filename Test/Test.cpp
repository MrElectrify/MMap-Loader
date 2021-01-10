#include <filesystem>
#include <iostream>
#include <string_view>
#include <system_error>
#include <vector>

#include <MMapLoader/MMap.h>

int main(int argc, char* argv[])
{
	if (argc != 3)
	{
		std::cout << "Usage: " << argv[0] << " <exePath:path> <dllPath:path>\n";
		return 1;
	}
	const std::string_view gamePath = argv[1];
	const std::string_view dllPath = argv[2];
	const char* dllPaths[] = { dllPath.data() };
	size_t dllSizes[] = { dllPath.size() };
	const std::filesystem::path exePath(gamePath);
	// set the GAME_DATA_DIR variable
	if (SetEnvironmentVariableA("GAME_DATA_DIR",
		exePath.parent_path().string().c_str()) == FALSE)
	{
		std::cerr << "Failed to set environment variable: " <<
			std::system_category().message(GetLastError()) << " (" <<
			std::hex << GetLastError() << ")\n";
		return 1;
	}
	Result res;
	Run(gamePath.data(), gamePath.size(), dllPaths, dllSizes, 1, &res);
	if (res.success == false)
	{
		std::cerr << "Failed to start: " << res.statusStr << " (" << 
			std::hex << res.status << ")\n" << std::dec;
		return 1;
	}
	std::cout << "Success\n";
	return 0;
}