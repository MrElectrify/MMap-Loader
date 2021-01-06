#include <iostream>

#include <MMapLoader/MMap.h>

int main()
{
	Result res;
	Run(nullptr, 0, &res);
	if (res.success == false)
	{
		std::cerr << "Failed to start: " << res.statusStr << " (" << res.status << ")\n";
		return 1;
	}
	std::cout << "Success\n";
	return 0;
}