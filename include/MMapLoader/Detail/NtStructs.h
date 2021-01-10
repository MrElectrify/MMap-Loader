#ifndef MMAPLOADER_DETAIL_NTSTRUCTS_H_
#define MMAPLOADER_DETAIL_NTSTRUCTS_H_

/// @file
/// NT Structs
/// 1/9/21 19:54

// STL includes
#include <cstdint>
#include <Windows.h>
#include <Winternl.h>

namespace MMapLoader
{
    namespace Detail
    {
        namespace NT
        {
            typedef struct _RTLP_CURDIR_REF
            {
                LONG RefCount;
                HANDLE Handle;
            } RTLP_CURDIR_REF, * PRTLP_CURDIR_REF;

            typedef struct RTL_RELATIVE_NAME_U {
                UNICODE_STRING RelativeName;
                HANDLE ContainingDirectory;
                PRTLP_CURDIR_REF CurDirRef;
            } RTL_RELATIVE_NAME_U, * PRTL_RELATIVE_NAME_U;

            typedef enum _SECTION_INHERIT {
                ViewShare = 1,
                ViewUnmap = 2
            } SECTION_INHERIT, * PSECTION_INHERIT;

            template <typename T>
            struct _LIST_ENTRY_T
            {
                T Flink;
                T Blink;
            };

            template<typename T>
            struct _RTL_BALANCED_NODE
            {
                union
                {
                    T Children[2];
                    struct
                    {
                        T Left;
                        T Right;
                    };
                };
                union
                {
                    struct
                    {
                        __int8 Red : 1;
                    };
                    struct
                    {
                        __int8 Balance : 2;
                    };
                    uint64_t ParentValue;
                };
            };

            template<typename T>
            struct _LDR_DATA_TABLE_ENTRY_BASE_T
            {
                _LIST_ENTRY_T<T> InLoadOrderLinks;              // 0x0
                _LIST_ENTRY_T<T> InMemoryOrderLinks;            // 0x10
                _LIST_ENTRY_T<T> InInitializationOrderLinks;    // 0x20
                T DllBase;                                      // 0x30
                T EntryPoint;                                   // 0x38
                uint32_t SizeOfImage;                           // 0x40
                UNICODE_STRING FullDllName;                     // 0x48
                UNICODE_STRING BaseDllName;                     // 0x58
                union
                {
                    char FlagGroup[4];
                    unsigned int Flags;
                    struct
                    {
                        unsigned __int32 PackagedBinary : 1;
                        unsigned __int32 MarkedForRemoval : 1;
                        unsigned __int32 ImageDll : 1;
                        unsigned __int32 LoadNotificationsSent : 1;
                        unsigned __int32 TelemetryEntryProcessed : 1;
                        unsigned __int32 ProcessStaticImport : 1;
                        unsigned __int32 InLegacyLists : 1;
                        unsigned __int32 InIndexes : 1;
                        unsigned __int32 ShimDll : 1;
                        unsigned __int32 InExceptionTable : 1;
                        unsigned __int32 ReservedFlags1 : 2;
                        unsigned __int32 LoadInProgress : 1;
                        unsigned __int32 LoadConfigProcessed : 1;
                        unsigned __int32 EntryProcessed : 1;
                        unsigned __int32 ProtectDelayLoad : 1;
                        unsigned __int32 ReservedFlags3 : 2;
                        unsigned __int32 DontCallForThreads : 1;
                        unsigned __int32 ProcessAttachCalled : 1;
                        unsigned __int32 ProcessAttachFailed : 1;
                        unsigned __int32 CorDeferredValidate : 1;
                        unsigned __int32 CorImage : 1;
                        unsigned __int32 DontRelocate : 1;
                        unsigned __int32 CorILOnly : 1;
                        unsigned __int32 ChpeImage : 1;
                        unsigned __int32 ReservedFlags5 : 2;
                        unsigned __int32 Redirected : 1;
                        unsigned __int32 ReservedFlags6 : 2;
                        unsigned __int32 CompatDatabaseProcessed : 1;
                    };
                };                                 // 0x68
                uint16_t ObseleteLoadCount;                     // 0x6C
                uint16_t TlsIndex;                              // 0x6E
                _LIST_ENTRY_T<T> HashLinks;                     // 0x70
                uint32_t TimeDateStamp;                         // 0x80
                T EntryPointActivationContext;                  // 0x88
            };

            enum _LDR_DLL_LOAD_REASON
            {
                LoadReasonStaticDependency = 0x0,
                LoadReasonStaticForwarderDependency = 0x1,
                LoadReasonDynamicForwarderDependency = 0x2,
                LoadReasonDelayloadDependency = 0x3,
                LoadReasonDynamicLoad = 0x4,
                LoadReasonAsImageLoad = 0x5,
                LoadReasonAsDataLoad = 0x6,
                LoadReasonEnclavePrimary = 0x7,
                LoadReasonEnclaveDependency = 0x8,
                LoadReasonUnknown = 0xFFFFFFFF,
            };

            template<typename T>
            struct _LDRP_CSLIST_T
            {
                T Tail;
            };

            enum _LDR_DDAG_STATE
            {
                LdrModulesMerged = 0xFFFFFFFB,
                LdrModulesInitError = 0xFFFFFFFC,
                LdrModulesSnapError = 0xFFFFFFFD,
                LdrModulesUnloaded = 0xFFFFFFFE,
                LdrModulesUnloading = 0xFFFFFFFF,
                LdrModulesPlaceHolder = 0x0,
                LdrModulesMapping = 0x1,
                LdrModulesMapped = 0x2,
                LdrModulesWaitingForDependencies = 0x3,
                LdrModulesSnapping = 0x4,
                LdrModulesSnapped = 0x5,
                LdrModulesCondensed = 0x6,
                LdrModulesReadyToInit = 0x7,
                LdrModulesInitializing = 0x8,
                LdrModulesReadyToRun = 0x9,
            };

            template<typename T>
            struct _LDR_DDAG_NODE_T
            {
                _LIST_ENTRY Modules;
                T* ServiceTagList;
                unsigned int LoadCount;
                unsigned int LoadWhileUnloadingCount;
                unsigned int LowestLink;
                _LDRP_CSLIST_T<T> Dependencies;
                _LDRP_CSLIST_T<T> IncomingDependencies;
                _LDR_DDAG_STATE State;
                _SINGLE_LIST_ENTRY CondenseLink;
                unsigned int PreorderNumber;
            };

            template<typename T>
            struct _LDR_DATA_TABLE_ENTRY_T :
                _LDR_DATA_TABLE_ENTRY_BASE_T<T>
            {
                T Lock;                                     // 0x90
                T DdagNode;                                 // 0x98
                _LIST_ENTRY_T<T> NodeModuleLink;            // 0xA0
                T LoadContext;                              // 0xB0
                T ParentDllBase;                            // 0xB8
                T SwitchBackContext;                        // 0xC0
                _RTL_BALANCED_NODE<T> BaseAddressIndexNode; // 0xC8
                _RTL_BALANCED_NODE<T> MappingInfoIndexNode; // 0xE0
                uint64_t OriginalBase;                      // 0xF8
                _LARGE_INTEGER LoadTime;                    // 0x100
                uint32_t BaseNameHashValue;                 // 0x108
                _LDR_DLL_LOAD_REASON LoadReason;            // 0x10C
                uint32_t ImplicitPathOptions;               // 0x110
                uint32_t ReferenceCount;                    // 0x114
                uint32_t DependentLoadFlags;                // 0x118
                char SigningLevel;                          // 0x11C
            };

            using _LDR_DDAG_NODE64 = _LDR_DDAG_NODE_T<uint64_t>;
            using _LDR_DATA_TABLE_ENTRY_BASE64 = _LDR_DATA_TABLE_ENTRY_BASE_T<uint64_t>;
            using _LDR_DATA_TABLE_ENTRY64 = _LDR_DATA_TABLE_ENTRY_T<uint64_t>;
        }
    }
}

#endif