#pragma once
#include <intrin.h>
#include <windef.h>
#include <tdi.h>
#include <qos.h>

#ifdef __cplusplus
extern "C" {
#endif

    // winnt.h
#define PROCESS_TERMINATE					(0x0001)
#define PROCESS_CREATE_THREAD				(0x0002)
#define PROCESS_SET_SESSIONID				(0x0004)
#define PROCESS_VM_OPERATION				(0x0008)
#define PROCESS_VM_READ						(0x0010)
#define PROCESS_VM_WRITE					(0x0020)
#define PROCESS_DUP_HANDLE					(0x0040)
#define PROCESS_CREATE_PROCESS				(0x0080)
#define PROCESS_SET_QUOTA					(0x0100)
#define PROCESS_SET_INFORMATION				(0x0200)
#define PROCESS_QUERY_INFORMATION			(0x0400)
#define PROCESS_SUSPEND_RESUME				(0x0800)
#define PROCESS_SET_PORT					PROCESS_SUSPEND_RESUME
#define PROCESS_QUERY_LIMITED_INFORMATION	(0x1000)
#define PROCESS_SET_LIMITED_INFORMATION		(0x2000)
#if (NTDDI_VERSION >= NTDDI_VISTA)
#define PROCESS_ALL_ACCESS					(STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
											0xFFFF)
#else
#define PROCESS_ALL_ACCESS					(STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
											0xFFF)
#endif

    typedef struct _PROCESS_MITIGATION_POLICY_INFORMATION
    {
        PROCESS_MITIGATION_POLICY Policy;
        union
        {
            PROCESS_MITIGATION_ASLR_POLICY ASLRPolicy;
            PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY StrictHandleCheckPolicy;
            PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY SystemCallDisablePolicy;
            PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ExtensionPointDisablePolicy;
            PROCESS_MITIGATION_DYNAMIC_CODE_POLICY DynamicCodePolicy;
            PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY ControlFlowGuardPolicy;
            PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY SignaturePolicy;
            PROCESS_MITIGATION_FONT_DISABLE_POLICY FontDisablePolicy;
            PROCESS_MITIGATION_IMAGE_LOAD_POLICY ImageLoadPolicy;
            PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY SystemCallFilterPolicy;
            PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY PayloadRestrictionPolicy;
            PROCESS_MITIGATION_CHILD_PROCESS_POLICY ChildProcessPolicy;
        } u;
    } PROCESS_MITIGATION_POLICY_INFORMATION, * PPROCESS_MITIGATION_POLICY_INFORMATION;

    typedef enum _PS_PROTECTED_TYPE : UCHAR
    {
        PsProtectedTypeNone,
        PsProtectedTypeProtectedLight,
        PsProtectedTypeProtected,
        PsProtectedTypeMax
    } PS_PROTECTED_TYPE;

    typedef enum _PS_PROTECTED_SIGNER : UCHAR
    {
        PsProtectedSignerNone,
        PsProtectedSignerAuthenticode,
        PsProtectedSignerCodeGen,
        PsProtectedSignerAntimalware,
        PsProtectedSignerLsa,
        PsProtectedSignerWindows,
        PsProtectedSignerWinTcb,
        PsProtectedSignerWinSystem,
        PsProtectedSignerApp,
        PsProtectedSignerMax
    } PS_PROTECTED_SIGNER;

    typedef struct _PS_PROTECTION
    {
        union
        {
            struct
            {
                PS_PROTECTED_TYPE Type : 3;
                BOOLEAN Audit : 1;
                PS_PROTECTED_SIGNER Signer : 4;
            } s;
            UCHAR Level;
        };
    } PS_PROTECTION, * PPS_PROTECTION;

    // Source: https://github.com/processhacker2/processhacker2/blob/master/phnt/include/ntexapi.h
    typedef enum _SYSTEM_INFORMATION_CLASS
    {
        SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
        SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
        SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
        SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
        SystemPathInformation, // not implemented
        SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
        SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
        SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
        SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
        SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
        SystemCallTimeInformation, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
        SystemModuleInformation, // q: RTL_PROCESS_MODULES
        SystemLocksInformation, // q: RTL_PROCESS_LOCKS
        SystemStackTraceInformation, // q: RTL_PROCESS_BACKTRACES
        SystemPagedPoolInformation, // not implemented
        SystemNonPagedPoolInformation, // not implemented
        SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
        SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
        SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
        SystemVdmInstemulInformation, // q
        SystemVdmBopInformation, // not implemented // 20
        SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
        SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
        SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION
        SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
        SystemFullMemoryInformation, // not implemented
        SystemLoadGdiDriverInformation, // s (kernel-mode only)
        SystemUnloadGdiDriverInformation, // s (kernel-mode only)
        SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
        SystemSummaryMemoryInformation, // not implemented
        SystemMirrorMemoryInformation, // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
        SystemPerformanceTraceInformation, // q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
        SystemObsolete0, // not implemented
        SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
        SystemCrashDumpStateInformation, // s (requires SeDebugPrivilege)
        SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
        SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
        SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
        SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
        SystemPrioritySeperation, // s (requires SeTcbPrivilege)
        SystemVerifierAddDriverInformation, // s (requires SeDebugPrivilege) // 40
        SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
        SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION
        SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
        SystemCurrentTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION
        SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
        SystemTimeSlipNotification, // s (requires SeSystemtimePrivilege)
        SystemSessionCreate, // not implemented
        SystemSessionDetach, // not implemented
        SystemSessionInformation, // not implemented (SYSTEM_SESSION_INFORMATION)
        SystemRangeStartInformation, // q: SYSTEM_RANGE_START_INFORMATION // 50
        SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
        SystemVerifierThunkExtend, // s (kernel-mode only)
        SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
        SystemLoadGdiDriverInSystemSpace, // s (kernel-mode only) (same as SystemLoadGdiDriverInformation)
        SystemNumaProcessorMap, // q
        SystemPrefetcherInformation, // q: PREFETCHER_INFORMATION; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
        SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
        SystemRecommendedSharedDataAlignment, // q
        SystemComPlusPackage, // q; s
        SystemNumaAvailableMemory, // 60
        SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION
        SystemEmulationBasicInformation, // q
        SystemEmulationProcessorInformation,
        SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
        SystemLostDelayedWriteInformation, // q: ULONG
        SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
        SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
        SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
        SystemHotpatchInformation, // q; s: SYSTEM_HOTPATCH_CODE_INFORMATION
        SystemObjectSecurityMode, // q: ULONG // 70
        SystemWatchdogTimerHandler, // s (kernel-mode only)
        SystemWatchdogTimerInformation, // q (kernel-mode only); s (kernel-mode only)
        SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION
        SystemWow64SharedInformationObsolete, // not implemented
        SystemRegisterFirmwareTableInformationHandler, // s (kernel-mode only)
        SystemFirmwareTableInformation, // SYSTEM_FIRMWARE_TABLE_INFORMATION
        SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
        SystemVerifierTriageInformation, // not implemented
        SystemSuperfetchInformation, // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
        SystemMemoryListInformation, // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
        SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
        SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
        SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[]
        SystemVerifierCancellationInformation, // not implemented // name:wow64:whNT32QuerySystemVerifierCancellationInformation
        SystemProcessorPowerInformationEx, // not implemented
        SystemRefTraceInformation, // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
        SystemSpecialPoolInformation, // q; s (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
        SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
        SystemErrorPortInformation, // s (requires SeTcbPrivilege)
        SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
        SystemHypervisorInformation, // q; s (kernel-mode only)
        SystemVerifierInformationEx, // q; s: SYSTEM_VERIFIER_INFORMATION_EX
        SystemTimeZoneInformation, // s (requires SeTimeZonePrivilege)
        SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
        SystemCoverageInformation, // q; s // name:wow64:whNT32QuerySystemCoverageInformation; ExpCovQueryInformation
        SystemPrefetchPatchInformation, // not implemented
        SystemVerifierFaultsInformation, // s (requires SeDebugPrivilege)
        SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
        SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
        SystemProcessorPerformanceDistribution, // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION // 100
        SystemNumaProximityNodeInformation, // q
        SystemDynamicTimeZoneInformation, // q; s (requires SeTimeZonePrivilege)
        SystemCodeIntegrityInformation, // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
        SystemProcessorMicrocodeUpdateInformation, // s
        SystemProcessorBrandString, // q // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
        SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
        SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // since WIN7 // KeQueryLogicalProcessorRelationship
        SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[]
        SystemStoreInformation, // q; s // SmQueryStoreInformation
        SystemRegistryAppendString, // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
        SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
        SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
        SystemCpuQuotaInformation, // q; s // PsQueryCpuQuotaInformation
        SystemNativeBasicInformation, // not implemented
        SystemSpare1, // not implemented
        SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
        SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
        SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
        SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
        SystemSystemPtesInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
        SystemNodeDistanceInformation, // q
        SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
        SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
        SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
        SystemSessionBigPoolInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
        SystemBootGraphicsInformation, // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
        SystemScrubPhysicalMemoryInformation, // q; s: MEMORY_SCRUB_INFORMATION
        SystemBadPageInformation,
        SystemProcessorProfileControlArea, // q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
        SystemCombinePhysicalMemoryInformation, // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
        SystemEntropyInterruptTimingCallback,
        SystemConsoleInformation, // q: SYSTEM_CONSOLE_INFORMATION
        SystemPlatformBinaryInformation, // q: SYSTEM_PLATFORM_BINARY_INFORMATION
        SystemThrottleNotificationInformation,
        SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
        SystemDeviceDataInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
        SystemDeviceDataEnumerationInformation,
        SystemMemoryTopologyInformation, // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
        SystemMemoryChannelInformation, // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
        SystemBootLogoInformation, // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
        SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // since WINBLUE
        SystemSpare0,
        SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
        SystemPageFileInformationEx, // q: SYSTEM_PAGEFILE_INFORMATION_EX
        SystemSecureBootInformation, // q: SYSTEM_SECUREBOOT_INFORMATION
        SystemEntropyInterruptTimingRawInformation,
        SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
        SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
        SystemKernelDebuggerInformationEx, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
        SystemBootMetadataInformation, // 150
        SystemSoftRebootInformation,
        SystemElamCertificateInformation, // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
        SystemOfflineDumpConfigInformation,
        SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
        SystemRegistryReconciliationInformation,
        SystemEdidInformation,
        SystemManufacturingInformation, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
        SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
        SystemHypervisorDetailInformation, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
        SystemProcessorCycleStatsInformation, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION // 160
        SystemVmGenerationCountInformation,
        SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
        SystemKernelDebuggerFlags,
        SystemCodeIntegrityPolicyInformation, // q: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
        SystemIsolatedUserModeInformation, // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
        SystemHardwareSecurityTestInterfaceResultsInformation,
        SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
        SystemAllowedCpuSetsInformation,
        SystemDmaProtectionInformation, // q: SYSTEM_DMA_PROTECTION_INFORMATION
        SystemInterruptCpuSetsInformation, // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
        SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
        SystemCodeIntegrityPolicyFullInformation,
        SystemAffinitizedInterruptProcessorInformation,
        SystemRootSiloInformation, // q: SYSTEM_ROOT_SILO_INFORMATION
        SystemCpuSetInformation, // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
        SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
        SystemWin32WerStartCallout,
        SystemSecureKernelProfileInformation, // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
        SystemCodeIntegrityPlatformManifestInformation, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
        SystemInterruptSteeringInformation, // 180
        SystemSupportedProcessorArchitectures,
        SystemMemoryUsageInformation, // q: SYSTEM_MEMORY_USAGE_INFORMATION
        SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
        SystemPhysicalMemoryInformation, // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
        SystemControlFlowTransition,
        SystemKernelDebuggingAllowed,
        SystemActivityModerationExeState, // SYSTEM_ACTIVITY_MODERATION_EXE_STATE
        SystemActivityModerationUserSettings, // SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
        SystemCodeIntegrityPoliciesFullInformation,
        SystemCodeIntegrityUnlockInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
        SystemIntegrityQuotaInformation,
        SystemFlushInformation, // q: SYSTEM_FLUSH_INFORMATION
        SystemProcessorIdleMaskInformation, // since REDSTONE3
        SystemSecureDumpEncryptionInformation,
        SystemWriteConstraintInformation, // SYSTEM_WRITE_CONSTRAINT_INFORMATION
        SystemKernelVaShadowInformation, // SYSTEM_KERNEL_VA_SHADOW_INFORMATION
        SystemSpeculationControlInformation = 201, // SYSTEM_SPECULATION_CONTROL_INFORMATION
        MaxSystemInfoClass
    } SYSTEM_INFORMATION_CLASS;

    typedef struct _SYSTEM_THREAD_INFORMATION
    {
        LARGE_INTEGER KernelTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER CreateTime;
        ULONG WaitTime;
        PVOID StartAddress;
        CLIENT_ID ClientId;
        KPRIORITY Priority;
        LONG BasePriority;
        ULONG ContextSwitches;
        ULONG ThreadState;
        ULONG WaitReason;
    } SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

    typedef struct _SYSTEM_PROCESS_INFORMATION
    {
        ULONG NextEntryOffset;
        ULONG NumberOfThreads;
        LARGE_INTEGER SpareLi1;
        LARGE_INTEGER SpareLi2;
        LARGE_INTEGER SpareLi3;
        LARGE_INTEGER CreateTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER KernelTime;
        UNICODE_STRING ImageName;
        KPRIORITY BasePriority;
        HANDLE UniqueProcessId;
        HANDLE InheritedFromUniqueProcessId;
        ULONG HandleCount;
        ULONG SessionId;
        ULONG_PTR PageDirectoryBase;
        SIZE_T PeakVirtualSize;
        SIZE_T VirtualSize;
        ULONG PageFaultCount;
        SIZE_T PeakWorkingSetSize;
        SIZE_T WorkingSetSize;
        SIZE_T QuotaPeakPagedPoolUsage;
        SIZE_T QuotaPagedPoolUsage;
        SIZE_T QuotaPeakNonPagedPoolUsage;
        SIZE_T QuotaNonPagedPoolUsage;
        SIZE_T PagefileUsage;
        SIZE_T PeakPagefileUsage;
        SIZE_T PrivatePageCount;
        LARGE_INTEGER ReadOperationCount;
        LARGE_INTEGER WriteOperationCount;
        LARGE_INTEGER OtherOperationCount;
        LARGE_INTEGER ReadTransferCount;
        LARGE_INTEGER WriteTransferCount;
        LARGE_INTEGER OtherTransferCount;
        SYSTEM_THREAD_INFORMATION Threads[1];
    } SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


    typedef struct _EXHANDLE
    {
        union
        {
            struct
            {
                ULONG TagBits : 2;
                ULONG Index : 30;
            };
            VOID* GenericHandleOverlay;
            ULONGLONG Value;
        };
    } EXHANDLE, * PEXHANDLE;

    typedef struct _HANDLE_TABLE_ENTRY
    {
        union
        {
            LONG_PTR VolatileLowValue;
            LONG_PTR LowValue;
            PVOID InfoTable;
            LONG_PTR RefCountField;
            struct
            {
                ULONG_PTR Unlocked : 1;
                ULONG_PTR RefCnt : 16;
                ULONG_PTR Attributes : 3;
                ULONG_PTR ObjectPointerBits : 44;
            };
        };
        union
        {
            LONG_PTR HighValue;
            struct _HANDLE_TABLE_ENTRY* NextFreeHandleEntry;
            EXHANDLE LeafHandleValue;
            struct
            {
                ULONG32 GrantedAccessBits : 25;
                ULONG32 NoRightsUpgrade : 1;
                ULONG32 Spare1 : 6;
            };
            ULONG32 Spare2;
        };
    } HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;

    typedef struct _HANDLE_TABLE_FREE_LIST
    {
        ULONG_PTR FreeListLock;
        PHANDLE_TABLE_ENTRY FirstFreeHandleEntry;
        PHANDLE_TABLE_ENTRY lastFreeHandleEntry;
        LONG32 HandleCount;
        ULONG32 HighWaterMark;
        ULONG32 Reserved[8];
    } HANDLE_TABLE_FREE_LIST, * PHANDLE_TABLE_FREE_LIST;

    typedef struct _HANDLE_TABLE
    {
        ULONG32 NextHandleNeedingPool;
        LONG32 ExtraInfoPages;
        ULONG_PTR TableCode;
        PEPROCESS QuotaProcess;
        LIST_ENTRY HandleTableList;
        ULONG32 UniqueProcessId;
        union
        {
            ULONG32 Flags;
            struct
            {
                BOOLEAN StrictFIFO : 1;
                BOOLEAN EnableHandleExceptions : 1;
                BOOLEAN Rundown : 1;
                BOOLEAN Duplicated : 1;
                BOOLEAN RaiseUMExceptionOnInvalidHandleClose : 1;
            };
        };
        ULONG_PTR HandleContentionEvent;
        ULONG_PTR HandleTableLock;
        union
        {
            HANDLE_TABLE_FREE_LIST FreeLists[1];
            BOOLEAN ActualEntry[32];
        };
        PVOID DebugInfo;
    } HANDLE_TABLE, * PHANDLE_TABLE;

    typedef struct _OBJECT_TYPE_INITIALIZER
    {
        USHORT Length;					  // Uint2B
        UCHAR ObjectTypeFlags;			  // UChar
        ULONG ObjectTypeCode;			  // Uint4B
        ULONG InvalidAttributes;		  // Uint4B
        GENERIC_MAPPING GenericMapping;	  // _GENERIC_MAPPING
        ULONG ValidAccessMask;			 // Uint4B
        ULONG RetainAccess;				  // Uint4B
        POOL_TYPE PoolType;				 // _POOL_TYPE
        ULONG DefaultPagedPoolCharge;	 // Uint4B
        ULONG DefaultNonPagedPoolCharge; // Uint4B
        PVOID DumpProcedure;			 // Ptr64     void
        PVOID OpenProcedure;			// Ptr64     long
        PVOID CloseProcedure;			// Ptr64     void
        PVOID DeleteProcedure;				// Ptr64     void
        PVOID ParseProcedure;			// Ptr64     long
        PVOID SecurityProcedure;			// Ptr64     long
        PVOID QueryNameProcedure;			// Ptr64     long
        PVOID OkayToCloseProcedure;			// Ptr64     unsigned char
#if (NTDDI_VERSION >= NTDDI_WINBLUE)    // Win8.1
        ULONG WaitObjectFlagMask;			// Uint4B
        USHORT WaitObjectFlagOffset;		// Uint2B
        USHORT WaitObjectPointerOffset;		// Uint2B
#endif
    }OBJECT_TYPE_INITIALIZER, * POBJECT_TYPE_INITIALIZER;

    typedef struct _OBJECT_TYPE
    {
        LIST_ENTRY TypeList;			     // _LIST_ENTRY
        UNICODE_STRING Name;				 // _UNICODE_STRING
        PVOID DefaultObject;				 // Ptr64 Void
        UCHAR Index;						 // UChar
        ULONG TotalNumberOfObjects;			 // Uint4B
        ULONG TotalNumberOfHandles;			 // Uint4B
        ULONG HighWaterNumberOfObjects;		 // Uint4B
        ULONG HighWaterNumberOfHandles;		 // Uint4B
        OBJECT_TYPE_INITIALIZER TypeInfo;	 // _OBJECT_TYPE_INITIALIZER
        EX_PUSH_LOCK TypeLock;				 // _EX_PUSH_LOCK
        ULONG Key;						     // Uint4B
        LIST_ENTRY CallbackList;			 // _LIST_ENTRY
    }OBJECT_TYPE, * POBJECT_TYPE;



    typedef struct OB_CALLBACK_t OB_CALLBACK;
    /*
    * Internal / undocumented version of OB_OPERATION_REGISTRATION
    */
    typedef struct OB_CALLBACK_ENTRY_t {
        LIST_ENTRY CallbackList; // linked element tied to _OBJECT_TYPE.CallbackList
        OB_OPERATION Operations; // bitfield : 1 for Creations, 2 for Duplications
        BOOL Enabled;            // self-explanatory
        OB_CALLBACK* Entry;      // points to the structure in which it is included
        POBJECT_TYPE ObjectType; // points to the object type affected by the callback
        POB_PRE_OPERATION_CALLBACK PreOperation;      // callback function called before each handle operation
        POB_POST_OPERATION_CALLBACK PostOperation;     // callback function called after each handle operation
        KSPIN_LOCK Lock;         // lock object used for synchronization
    } OB_CALLBACK_ENTRY, * POB_CALLBACK_ENTRY;


    /*
    * A callback entry is made of some fields followed by concatenation of callback entry items, and the buffer of the associated Altitude string
    * Internal / undocumented (and compact) version of OB_CALLBACK_REGISTRATION
    */
    typedef struct OB_CALLBACK_t {
        USHORT Version;                           // usually 0x100
        USHORT OperationRegistrationCount;        // number of registered callbacks
        PVOID RegistrationContext;                // arbitrary data passed at registration time
        UNICODE_STRING AltitudeString;            // used to determine callbacks order
        struct OB_CALLBACK_ENTRY_t EntryItems[1]; // array of OperationRegistrationCount items
        WCHAR AltitudeBuffer[1];                  // is AltitudeString.MaximumLength bytes long, and pointed by AltitudeString.Buffer
    } OB_CALLBACK, * POB_CALLBACK;



#if NTDDI_VERSION >= NTDDI_VISTA
    NTKERNELAPI
        BOOLEAN
        PsIsProtectedProcess(
            _In_ PEPROCESS Process
        );
#endif

#if NTDDI_VERSION >= NTDDI_WINBLUE
    NTKERNELAPI
        BOOLEAN
        PsIsProtectedProcessLight(
            _In_ PEPROCESS Process
        );
#endif

    NTKERNELAPI
        BOOLEAN
        PsIsSystemProcess(
            _In_ PEPROCESS Process
        );

    NTKERNELAPI
        NTSTATUS
        PsLookupProcessByProcessId(
            _In_ HANDLE ProcessId,
            _Outptr_ PEPROCESS* Process
        );

#if NTDDI_VERSION >= NTDDI_WIN10
    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        ZwGetNextProcess(
            _In_opt_ HANDLE ProcessHandle,
            _In_ ACCESS_MASK DesiredAccess,
            _In_ ULONG HandleAttributes,
            _In_ ULONG Flags,
            _Out_ PHANDLE NewProcessHandle
        );
#endif

#if NTDDI_VERSION >= NTDDI_WIN10_RS3
    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        ZwGetNextThread(
            _In_ HANDLE ProcessHandle,
            _In_ HANDLE ThreadHandle,
            _In_ ACCESS_MASK DesiredAccess,
            _In_ ULONG HandleAttributes,
            _In_ ULONG Flags,
            _Out_ PHANDLE NewThreadHandle
        );
#endif

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        ZwQueryInformationProcess(
            _In_ HANDLE ProcessHandle,
            _In_ PROCESSINFOCLASS ProcessInformationClass,
            _Out_ PVOID ProcessInformation,
            _In_ ULONG ProcessInformationLength,
            _Out_opt_ PULONG ReturnLength
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        ZwQuerySystemInformation(
            _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
            _Out_opt_ PVOID SystemInformation,
            _In_ ULONG SystemInformationLength,
            _Out_opt_ PULONG ReturnLength
        );

    NTKERNELAPI
        UCHAR* 
        PsGetProcessImageFileName(
            _In_ PEPROCESS Process);
    //win7 �� win10��ͬ
    typedef BOOLEAN(*EX_ENUMERATE_HANDLE_ROUTINE)(
#if !defined(_WIN7_)
        IN PHANDLE_TABLE HandleTable,
#endif
        IN PHANDLE_TABLE_ENTRY HandleTableEntry,
        IN HANDLE Handle,
        IN PVOID EnumParameter
        );

    NTKERNELAPI
        BOOLEAN
        ExEnumHandleTable(
            IN PHANDLE_TABLE HandleTable,
            IN EX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure,
            IN PVOID EnumParameter,
            OUT PHANDLE Handle
        );

    NTKERNELAPI
        VOID
        FASTCALL
        ExfUnblockPushLock(
            IN OUT PEX_PUSH_LOCK PushLock,
            IN OUT PVOID WaitBlock
        );

#ifdef __cplusplus
}
#endif

