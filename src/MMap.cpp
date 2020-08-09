#include <MMapLoader/MMap.h>

#include <BlackBone/ManualMap/MMap.h>
#include <BlackBone/Process/Process.h>

#include <vector>

bool Inject(HANDLE hProc, void* buffer, size_t len)
{
	blackbone::Process process;
	if (process.Attach(hProc) != STATUS_SUCCESS)
		return false;
	const auto image = process.mmap().MapImage(len, buffer);
	return image.success();
}