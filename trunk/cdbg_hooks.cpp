#include "cdbg.h"

//
// KiUserExceptionDispatcher
//

VOID
CdbgKiUserExceptionDispatcherHandler(
	EXCEPTION_RECORD *rec,
	CONTEXT *ctx
	)
{
	ULONG _this;
	__asm {
		call _1
_1:		pop [_this]
	}
	_this &= 0xFFFFF000;

	HANDLE hPort = *(HANDLE*)(_this + 0x10);
	NTSTATUS Status;

	NTSTATUS (WINAPI *_ZwRequestPort)(HANDLE,PVOID);
	NTSTATUS (WINAPI *_ZwReplyWaitReceivePort)(HANDLE,PVOID,PVOID,PVOID);

	*(ULONG*)&_ZwRequestPort = *(ULONG*)(_this + 0x14);
	*(ULONG*)&_ZwReplyWaitReceivePort = *(ULONG*)(_this + 0x18);

	char msgbuf[0x148] = {0};
	LPC_MESSAGE* lpc = (LPC_MESSAGE*)msgbuf;
	CDBG_LPC_MESSAGE *cdbg = (CDBG_LPC_MESSAGE*) &lpc->Data;

	cdbg->Type = LMT_EXCEPTION;

	__asm xchg esp,esp;
	__asm nop;

	cdbg->ExceptionRecord = **(&rec-1);
	cdbg->pCtx = (ULONG) *(&ctx-1);

	lpc->DataSize = sizeof(*cdbg);
	lpc->MessageSize = lpc->DataSize + sizeof(*lpc) - 1;

	Status = _ZwRequestPort (hPort, lpc);

	Status = _ZwReplyWaitReceivePort (hPort, 0, 0, lpc);

	__asm
	{
		// ecx = &ZwContinue
		mov ecx, [_this]
		mov ecx, [ecx + 0x1c]

		// eax = ctx
		lea eax, [ctx-4]
		mov eax, [eax]
		
		leave

		push 0       // push 0
		push eax     // push ctx
		call ecx	 // call ZwContinue
	}
}
__declspec(naked) void CdbgKiUserExceptionDispatcherHandler_end(){__asm nop;
}


//
// ZwTerminateProcess
//

VOID
CdbgZwTerminateProcessHandler(
	IN HANDLE               ProcessHandle OPTIONAL,
	IN NTSTATUS             ExitStatus
	)
{
	ULONG _this;
	__asm {
		call _1
_1:		pop [_this]
	}
	_this &= 0xFFFFF000;

	HANDLE hPort = *(HANDLE*)(_this + 0x10);
	NTSTATUS Status;

	NTSTATUS (WINAPI *_ZwRequestPort)(HANDLE,PVOID);
	NTSTATUS (WINAPI *_ZwReplyWaitReceivePort)(HANDLE,PVOID,PVOID,PVOID);

	*(ULONG*)&_ZwRequestPort = *(ULONG*)(_this + 0x14);
	*(ULONG*)&_ZwReplyWaitReceivePort = *(ULONG*)(_this + 0x18);

	char msgbuf[0x148] = {0};
	LPC_MESSAGE* lpc = (LPC_MESSAGE*)msgbuf;
	CDBG_LPC_MESSAGE *cdbg = (CDBG_LPC_MESSAGE*) &lpc->Data;

	cdbg->Type = LMT_EXITPROCESS;

	__asm xchg esp,esp;
	__asm nop;

	cdbg->ExitStatus = ExitStatus;


	lpc->DataSize = sizeof(*cdbg);
	lpc->MessageSize = lpc->DataSize + sizeof(*lpc) - 1;

	Status = _ZwRequestPort (hPort, lpc);

	__asm
	{
		mov eax, [_this]
		add eax, 0x300

		//
		// Remove hook
		//

		mov byte ptr [eax+0x10], 0xE9
		mov ecx, 0x300
		sub ecx, 0x310
		sub ecx, 5
		mov dword ptr [eax+0x11], ecx

		leave
		jmp eax
	}
}
__declspec(naked) void CdbgZwTerminateProcessHandler_end(){__asm nop;
}

//
// ZwTerminateThread
//

VOID
CdbgZwTerminateThreadHandler(
	IN HANDLE               ThreadHandle,
	IN NTSTATUS             ExitStatus
	)
{
	ULONG _this;
	__asm {
		call _1
_1:		pop [_this]
	}
	_this &= 0xFFFFF000;

	HANDLE hPort = *(HANDLE*)(_this + 0x10);
	NTSTATUS Status;

	NTSTATUS (WINAPI *_ZwRequestPort)(HANDLE,PVOID);
	NTSTATUS (WINAPI *_ZwReplyWaitReceivePort)(HANDLE,PVOID,PVOID,PVOID);

	*(ULONG*)&_ZwRequestPort = *(ULONG*)(_this + 0x14);
	*(ULONG*)&_ZwReplyWaitReceivePort = *(ULONG*)(_this + 0x18);

	char msgbuf[0x148] = {0};
	LPC_MESSAGE* lpc = (LPC_MESSAGE*)msgbuf;
	CDBG_LPC_MESSAGE *cdbg = (CDBG_LPC_MESSAGE*) &lpc->Data;

	cdbg->Type = LMT_EXITTHREAD;

	__asm xchg esp,esp;
	__asm nop;

	cdbg->ExitStatus = ExitStatus;


	lpc->DataSize = sizeof(*cdbg);
	lpc->MessageSize = lpc->DataSize + sizeof(*lpc) - 1;

	Status = _ZwRequestPort (hPort, lpc);

	__asm
	{
		mov eax, [_this]
		add eax, 0x400

		leave
		jmp eax
	}
	
}
__declspec(naked) void CdbgZwTerminateThreadHandler_end(){__asm nop;
}



BOOL
CdbgUserExceptionDispatcherHook(
	PDEBUGGEE dbg
	)
/*++
	Set KiUserExceptionDispatcher hook
--*/
{
	LPVOID hooks = VirtualAllocEx (dbg->hProcess, 0, PAGE_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!hooks)
	{
		lstrcpy (cdbg_last_err, "Cannot alloc memory: ");
		FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err+strlen(cdbg_last_err), 1023, 0);
		return FALSE;
	}

	//
	// Store useful addresses
	//

	dbg->hooks = hooks;
	dbg->KiUserExceptionDispatcher = (PVOID) GetProcAddress(GetModuleHandle("ntdll.dll"), "KiUserExceptionDispatcher");
	dbg->ZwTerminateProcess = (PVOID) GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwTerminateProcess");
	dbg->ZwTerminateThread = (PVOID) GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwTerminateThread");

	ULONG t;

	//
	// HOOKS map:
	//
	//  000X0000     JMP xxxxx       KiUserExceptionDispatcherHook
	//  000X0005     JMP xxxxx       TopLevelExceptionFilter
	//  000X000A     ULONG			 PreviousFilter
	//  000X0010     HANDLE			 LPC port handle
	//  000X0014    ZwRequestPort
	//  000X0018    ZwReplyWaitReceivePort
	//  000X001C    ZwContinue
	// ...
	//  000X0100     splice buffer for KiUserExceptionDispatcher
	// ...
	//  000X0110     KiUserExceptionDispatcher LPC code
	//
	//  000X0300     ZwTerminateProcess splice buffer
	//  000X0310     ZwTerminateProcess handler
	// ...
	//  000X0400     ZwTerminateThread splice
	//  000X0410     ZwTerminateThread handler

	//
	// Read old bytes/write KiUserExceptionDispatcher  handler & hook
	//

	if(!ReadProcessMemory (dbg->hProcess, dbg->KiUserExceptionDispatcher, dbg->KiUserExcDisp_Old, 5, &t))
	{
		printf("WriteProcessMemory failed for reading KiUserExceptionDispatcher\n", __LINE__);
		return FALSE;
	}

	if(!WriteProcessMemory (dbg->hProcess, hooks, "\xE9\x0B\x01\x00\x00", 5, &t))
	{
		printf("WriteProcessMemory failed for writing KiUserExceptionDispatcher jmp code [err %d]\n", __LINE__);
		return FALSE;
	}

	if (!WriteProcessMemory (dbg->hProcess, (PUCHAR)hooks+5, "\xEB\xFE", 2, &t))
	{
		printf("WriteProcessMemory failed for writing TopLevelFilter jmp code [err %d]\n", __LINE__);
		return FALSE;
	}
	

	if(!WriteProcessMemory (dbg->hProcess, (PUCHAR)hooks+0x110, CdbgKiUserExceptionDispatcherHandler, 
		(ULONG)CdbgKiUserExceptionDispatcherHandler_end-(ULONG)CdbgKiUserExceptionDispatcherHandler, &t))
	{
		wsprintf(cdbg_last_err, "WriteProcessMemory failed for writing KiUserExceptionDispatcher handler body [err %d]\n", __LINE__);
		FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err+strlen(cdbg_last_err), 1023, 0);
		return FALSE;
	}

	CdbgSpliceFunctionEx (dbg->hProcess, dbg->KiUserExceptionDispatcher, hooks, (PUCHAR)hooks + 0x100, 16, &t);

	//
	// Set ZwTerminateProcess splicing
	//

	if(!ReadProcessMemory (dbg->hProcess, dbg->ZwTerminateProcess, dbg->ZwTerminateProcess_Old, 5, &t))
	{
		printf("WriteProcessMemory failed for reading ZwTerminateProcess\n", __LINE__);
		return FALSE;
	}

	if(!WriteProcessMemory (dbg->hProcess, (PUCHAR)hooks+0x310, CdbgZwTerminateProcessHandler, 
		(ULONG)CdbgZwTerminateProcessHandler_end-(ULONG)CdbgZwTerminateProcessHandler, &t))
	{
		wsprintf(cdbg_last_err, "WriteProcessMemory failed for writing CdbgZwTerminateProcessHandler handler body [err %d]\n", __LINE__);
		FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err+strlen(cdbg_last_err), 1023, 0);
		return FALSE;
	}

	CdbgSpliceFunctionEx (dbg->hProcess, dbg->ZwTerminateProcess, (PUCHAR)hooks+0x310, (PUCHAR)hooks + 0x300, 16, &t);

	//
	// Create remote thread SetUnhandledExceptionFilter
	//

	HANDLE hth = CreateRemoteThread (dbg->hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)SetUnhandledExceptionFilter, (PUCHAR)hooks+5, 0, 0);
	WaitForSingleObject (hth, INFINITE);
	ULONG PreviousFilter = 0;
	GetExitCodeThread (hth, &PreviousFilter);

	//
	// Write previous filter
	//

	if(!WriteProcessMemory (dbg->hProcess, (PUCHAR)hooks+0xA, &PreviousFilter, 4, &t))
	{
		printf("WriteProcessMemory failed for writing PreviousFilter ULONG [err %d at line %d]\n", GetLastError(), __LINE__);
		return FALSE;
	}

	//
	// Set ZwTerminateThread splicing
	//

	if(!ReadProcessMemory (dbg->hProcess, dbg->ZwTerminateThread, dbg->ZwTerminateThread_Old, 5, &t))
	{
		printf("WriteProcessMemory failed for reading ZwTerminateThread\n", __LINE__);
		return FALSE;
	}

	if(!WriteProcessMemory (dbg->hProcess, (PUCHAR)hooks+0x410, CdbgZwTerminateThreadHandler, 
		(ULONG)CdbgZwTerminateThreadHandler_end-(ULONG)CdbgZwTerminateThreadHandler, &t))
	{
		wsprintf(cdbg_last_err, "WriteProcessMemory failed for writing ZwTerminateThread handler body [err %d]\n", __LINE__);
		FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err+strlen(cdbg_last_err), 1023, 0);
		return FALSE;
	}

	CdbgSpliceFunctionEx (dbg->hProcess, dbg->ZwTerminateThread, (PUCHAR)hooks+0x410, (PUCHAR)hooks + 0x400, 16, &t);


	//
	// Set our IAT
	//

	PVOID tmp = GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwRequestPort");
	if (!WriteProcessMemory (dbg->hProcess, (PUCHAR)hooks+0x14, &tmp, 4, &t))
	{
		printf("WriteProcessMemory failed for writing Zw* function table [err %d]\n", __LINE__);
		return FALSE;
	}
	tmp = GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwReplyWaitReceivePort");
	if (!WriteProcessMemory (dbg->hProcess, (PUCHAR)hooks+0x18, &tmp, 4, &t))
	{
		printf("WriteProcessMemory failed for writing Zw* function table [err %d]\n", __LINE__);
		return FALSE;
	}
	tmp = GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwContinue");
	if (!WriteProcessMemory (dbg->hProcess, (PUCHAR)hooks+0x1C, &tmp, 4, &t))
	{
		printf("WriteProcessMemory failed for writing Zw* function table [err %d]\n", __LINE__);
		return FALSE;
	}
	


	return TRUE;
}

VOID
CdbgUserExceptionDispatcherUnhook(
	PDEBUGGEE dbg
	)
/*++
	Clear KiUserExceptionDispatcherHook
--*/
{
	ULONG w=0;
	WriteProcessMemory (dbg->hProcess, dbg->KiUserExceptionDispatcher, dbg->KiUserExcDisp_Old, 5, &w);
	WriteProcessMemory (dbg->hProcess, dbg->ZwTerminateProcess, dbg->ZwTerminateProcess_Old, 5, &w);
	WriteProcessMemory (dbg->hProcess, dbg->ZwTerminateThread, dbg->ZwTerminateThread_Old, 5, &w);
	
	// Restore previous exception handler
	HANDLE hth = CreateRemoteThread (dbg->hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)SetUnhandledExceptionFilter, 
		(PUCHAR)dbg->hooks+0xA, 0, 0);
	WaitForSingleObject (hth, INFINITE);


	VirtualFreeEx (dbg->hProcess, dbg->hooks, PAGE_SIZE, MEM_RELEASE);
}

