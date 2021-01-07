#include <iostream>
#include <string_view>

#include <MMapLoader/MMap.h>

int main()
{
	constexpr const std::string_view gameStr = "C:\\Program Files (x86)\\Origin Games\\Battlefield 4\\game.bin";
	Result res;
	Run(gameStr.data(), gameStr.size(), nullptr, 0, &res);
	if (res.success == false)
	{
		std::cerr << "Failed to start: " << res.statusStr << " (" << res.status << ")\n";
		return 1;
	}
	std::cout << "Success\n";
	return 0;
}