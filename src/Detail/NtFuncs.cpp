#include <MMapLoader/Detail/NtFuncs.h>

#include <MMapLoader/Detail/FnPtr.h>
#include <MMapLoader/Detail/Util.h>

#include <CompileTimeEncryption/XorStr.h>

#include <atomic>

#include <Windows.h>

using namespace MMapLoader::Detail;

NT::LdrpHandleTlsData_t NT::LdrpHandleTlsData_f;
NT::LdrpInsertDataTableEntry_t NT::LdrpInsertDataTableEntry_f;
NT::LdrpInsertModuleToIndex_t NT::LdrpInsertModuleToIndex_f;
NT::NtCreateSection_t NT::NtCreateSection_f;
NT::NtMapViewOfSection_t NT::NtMapViewOfSection_f;
NT::NtUnmapViewOfSection_t NT::NtUnmapViewOfSection_f;
NT::RtlInitUnicodeString_t NT::RtlInitUnicodeString_f;
NT::RtlInsertInvertedFunctionTable_t NT::RtlInsertInvertedFunctionTable_f;

bool NT::Initialize() noexcept
{
	static std::atomic_bool hasInit = false;
	static std::atomic_bool res = false;
	if (hasInit == true)
		return res;
	hasInit = true;
	const auto hNTDll = GetModuleHandle(XorStr("ntdll"));
	if (hNTDll == nullptr)
		return false;
	if (LdrpHandleTlsData_f = FnPtr<LdrpHandleTlsData_t>(hNTDll,
			"\xE8\x00\x00\x00\x00\x8B\xD8\x85\xC0\x78\x0B"
			"\xE8\x00\x00\x00\x00", 1, true).GetPtr();
		LdrpHandleTlsData_f == nullptr)
		return false;
	if (LdrpInsertDataTableEntry_f = FnPtr<LdrpInsertDataTableEntry_t>(
		hNTDll, "\xE8\x00\x00\x00\x00\x48\x8B\xD5\x48\x8B\xCF", 1, 
		true).GetPtr();
		LdrpInsertDataTableEntry_f == nullptr)
		return false;
	if (LdrpInsertModuleToIndex_f = FnPtr<LdrpInsertModuleToIndex_t>(
			hNTDll, "\xE8\x00\x00\x00\x00\x45\x33\xC9\x33\xD2", 1, true).OrElse(
			hNTDll, "\xE8\x00\x00\x00\x00\x33\xD2\x44\x8D\x42\x01", 1, true).GetPtr();
		LdrpInsertModuleToIndex_f == nullptr)
		return false;
	if (NtCreateSection_f = reinterpret_cast<NtCreateSection_t>(
			GetProcAddress(hNTDll, XorStr("NtCreateSection")));
		NtCreateSection_f == nullptr)
		return false;
	if (NtMapViewOfSection_f = reinterpret_cast<NtMapViewOfSection_t>(
			GetProcAddress(hNTDll, XorStr("NtMapViewOfSection")));
		NtCreateSection_f == nullptr)
		return false;
	if (NtUnmapViewOfSection_f = reinterpret_cast<NtUnmapViewOfSection_t>(
			GetProcAddress(hNTDll, XorStr("NtUnmapViewOfSection")));
		NtCreateSection_f == nullptr)
		return false;
	if (RtlInitUnicodeString_f = reinterpret_cast<RtlInitUnicodeString_t>(
			GetProcAddress(hNTDll, XorStr("RtlInitUnicodeString")));
		RtlInitUnicodeString_f == nullptr)
		return false;
	if (RtlInsertInvertedFunctionTable_f = FnPtr<RtlInsertInvertedFunctionTable_t>(
			hNTDll, "\xE8\x00\x00\x00\x00\x41\x09\x5E\x68", 1, true).GetPtr();
		RtlInsertInvertedFunctionTable_f == nullptr)
		return false;
	return res = true;
}