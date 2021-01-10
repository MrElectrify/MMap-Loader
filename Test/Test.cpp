#include <filesystem>
#include <iostream>
#include <string_view>
#include <system_error>

#include <MMapLoader/MMap.h>

int main()
{
	constexpr const std::string_view gameStr = "C:\\Program Files (x86)\\Origin Games\\Battlefield 4\\bf4_dev.exe";
	const std::filesystem::path exePath(gameStr);
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
	Run(gameStr.data(), gameStr.size(), nullptr, 0, &res);
	if (res.success == false)
	{
		std::cerr << "Failed to start: " << res.statusStr << " (" << 
			std::hex << res.status << ")\n" << std::dec;
		return 1;
	}
	std::cout << "Success\n";
	return 0;
}