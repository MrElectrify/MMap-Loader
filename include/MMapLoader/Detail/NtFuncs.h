#ifndef MMAPLOADER_DETAIL_NTFUNCS_H_
#define MMAPLOADER_DETAIL_NTFUNCS_H_

/// @file
/// NT Functions
/// 1/10/21 13:26

// MMapLoader includes
#include <MMapLoader/Detail/NtStructs.h>

// STL includes
#include <type_traits>

// Windows includes
#include <ntstatus.h>

namespace MMapLoader
{
	namespace Detail
	{
		namespace NT
		{
			bool Initialize() noexcept;

			using LdrpHandleTlsData_t = std::add_pointer_t<NTSTATUS NTAPI(
				_LDR_DATA_TABLE_ENTRY64* pLdrDataTable)>;
			using LdrpInsertDataTableEntry_t =
				std::add_pointer_t<void __fastcall(_LDR_DATA_TABLE_ENTRY64* pEntry)>;
			using LdrpInsertModuleToIndex_t = std::add_pointer_t<DWORD NTAPI(
				_LDR_DATA_TABLE_ENTRY64* pTblEntry, IMAGE_NT_HEADERS* pNTHeaders)>;
			using NtCreateSection_t = std::add_pointer_t<NTSTATUS NTAPI(PHANDLE SectionHandle,
				ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
				PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection,
				ULONG AllocationAttributes, HANDLE FileHandle)>;
			using NtMapViewOfSection_t = std::add_pointer_t<NTSTATUS NTAPI(HANDLE SectionHandle,
				HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize,
				PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition,
				ULONG AllocationType, ULONG Protect)>;
			using NtUnmapViewOfSection_t = std::add_pointer_t<NTSTATUS NTAPI(HANDLE ProcessHandle,
				PVOID BaseAddress)>;
			using RtlInitUnicodeString_t = std::add_pointer_t<decltype(RtlInitUnicodeString)>;
			using RtlInsertInvertedFunctionTable_t = std::add_pointer_t<void NTAPI(
				IMAGE_DOS_HEADER* pImage, DWORD ImageSize)>;

			extern LdrpHandleTlsData_t LdrpHandleTlsData_f;
			extern LdrpInsertDataTableEntry_t LdrpInsertDataTableEntry_f;
			extern LdrpInsertModuleToIndex_t LdrpInsertModuleToIndex_f;
			extern NtCreateSection_t NtCreateSection_f;
			extern NtMapViewOfSection_t NtMapViewOfSection_f;
			extern NtUnmapViewOfSection_t NtUnmapViewOfSection_f;
			extern RtlInitUnicodeString_t RtlInitUnicodeString_f;
			extern RtlInsertInvertedFunctionTable_t RtlInsertInvertedFunctionTable_f;
		}
	}
}

#endif