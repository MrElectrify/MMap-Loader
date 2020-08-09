#include <MMapLoader/MMap.h>

#include <BlackBone/ManualMap/MMap.h>
#include <BlackBone/Process/Process.h>

bool Inject(HANDLE hProc, void* buffer, size_t len)
{
	blackbone::Process process;
	if (process.Attach(hProc) != STATUS_SUCCESS)
		return false;
	return process.mmap().MapImage(len, buffer).success();
}