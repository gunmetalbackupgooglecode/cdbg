#include "cdbg.h"
#include "ldasm.h"

HANDLE OpenThread (ULONG desiredAccess, BOOL inheritHandle, ULONG threadID)
{
	HANDLE (WINAPI *func)(ULONG,BOOL,ULONG);
	*(FARPROC*)&func = GetProcAddress (GetModuleHandle("kernel32.dll"), "OpenThread");
	return func (desiredAccess, inheritHandle, threadID);
}

HWND GetConsoleWindow(void)
{
	HWND (WINAPI *func)();
	*(FARPROC*)&func = GetProcAddress (GetModuleHandle("kernel32.dll"), "GetConsoleWindow");
	return func();
}

HANDLE heap;

PVOID GetSystemInformation (SYSTEM_INFORMATION_CLASS InfoClass)
{
	NTSTATUS Status;
	PVOID Buffer;
	ULONG Size = PAGE_SIZE;

	do
	{
		Buffer = halloc (Size);

		Status = ZwQuerySystemInformation ( InfoClass,
											Buffer,
											Size,
											&Size );

		if (Status == STATUS_INFO_LENGTH_MISMATCH)
			hfree (Buffer);
	}
	while (Status == STATUS_INFO_LENGTH_MISMATCH);

	if (!NT_SUCCESS(Status))
	{
		hfree (Buffer);
		return NULL;
	}

	return Buffer;
}


//
// APIs
//


char cdbg_last_err[1024] = "Success";


BOOL
CdbgLookupProcessName(
	PSYSTEM_PROCESSES_INFORMATION Buffer OPTIONAL,
	ULONG dwProcessId,
	char *ProcessNameBuffer,
	ULONG MaxLength
	)
/*++
	Lookup process name by process ID
--*/
{
	if (dwProcessId == 0)
	{
		strncpy (ProcessNameBuffer, "System Idle Process", MaxLength);
		return TRUE;
	}

	PSYSTEM_PROCESSES_INFORMATION locBuffer = Buffer;

	if (locBuffer == NULL)
	{
		locBuffer = (PSYSTEM_PROCESSES_INFORMATION) GetSystemInformation (SystemProcessesAndThreadsInformation);
	}

	__try
	{
		for (PSYSTEM_PROCESSES_INFORMATION Proc=locBuffer; ; *(ULONG*)&Proc += Proc->NextEntryDelta)
		{
			if (Proc->ProcessId == dwProcessId)
			{
				WideCharToMultiByte (CP_ACP, 0, Proc->ProcessName.Buffer, Proc->ProcessName.Length, ProcessNameBuffer,
					MaxLength, 0, 0);

				return TRUE;
			}

			if (!Proc->NextEntryDelta) break;
		}

		lstrcpy (cdbg_last_err, "Process not found");
	}
	__finally
	{
		if (!Buffer)
			hfree (locBuffer);
	}

	return FALSE;
}

PDEBUGGEE
CdbgAttach(
	ULONG dwProcessId
	)
/*++
	Attach debugger to the specified process.
--*/
{
	PDEBUGGEE dbg = (PDEBUGGEE) halloc(sizeof(DEBUGGEE));

	dbg->dwProcessId = dwProcessId;
	dbg->hProcess = OpenProcess (PROCESS_ALL_ACCESS, 0, dwProcessId);

	if (dbg->hProcess == NULL)
	{
		lstrcpy (cdbg_last_err, "Opening process failed, OS reported error: ");
		FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err+strlen(cdbg_last_err), sizeof(cdbg_last_err)-1, 0);
		hfree (dbg);
		return NULL;
	}

	PSYSTEM_PROCESSES_INFORMATION Buffer = (PSYSTEM_PROCESSES_INFORMATION) 
		GetSystemInformation (SystemProcessesAndThreadsInformation);

	ULONG processes = 0;
	for (PSYSTEM_PROCESSES_INFORMATION Proc=Buffer; ; *(ULONG*)&Proc += Proc->NextEntryDelta)
	{
		processes++;
	
		if (Proc->ProcessId == dwProcessId)
		{
			dbg->nThreads = Proc->ThreadCount;

			WideCharToMultiByte (CP_ACP, 0, Proc->ProcessName.Buffer, Proc->ProcessName.Length, dbg->name, 255, 0,0);

			dbg->hThreads = (HANDLE*) halloc (sizeof(HANDLE)*dbg->nThreads);
			if (dbg->hThreads == NULL)
			{
				ZwClose (dbg->hProcess);
				hfree (Buffer);
				hfree (dbg);
				return NULL;
			}

			dbg->dwThreadIds = (ULONG*) halloc (sizeof(ULONG)*dbg->nThreads);
			if (dbg->dwThreadIds == NULL)
			{
				ZwClose (dbg->hProcess);
				hfree (dbg->hThreads);
				hfree (Buffer);
				hfree (dbg);
				return NULL;
			}

			for (ULONG i=0; i<Proc->ThreadCount; i++)
			{
				dbg->dwThreadIds[i] = (ULONG) Proc->Threads[i].ClientId.UniqueThread;
				dbg->hThreads[i] = OpenThread (THREAD_ALL_ACCESS, 0, dbg->dwThreadIds[i]);
			}

			if (!CdbgUserExceptionDispatcherHook (dbg))
			{
				for (ULONG i=0; i<Proc->ThreadCount; i++)
					ZwClose (dbg->hThreads);
				ZwClose (dbg->hProcess);
				hfree (dbg->hThreads);
				hfree (Buffer);
				hfree (dbg);
				return NULL;
			}

			dbg->BreakPointBuffers = VirtualAllocEx (dbg->hProcess, 0, MAX_BPS*SIZEOF_BP_BUFFER, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

			printf("Bp buffers = %08x\n", dbg->BreakPointBuffers);


			//
			// Get module base
			//

			HANDLE hModThread = CreateRemoteThread (dbg->hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetModuleHandle, NULL, 0, 0);

			WaitForSingleObject (hModThread, INFINITE);
			GetExitCodeThread (hModThread, &dbg->ModuleBase);
			CloseHandle (hModThread);

			//
			// Create lpc server
			//

			OBJECT_ATTRIBUTES oa;
			InitializeObjectAttributes (&oa, 0, 0, 0, 0);

			NTSTATUS Status;

			Status = ZwCreatePort (&dbg->hMessagePort, &oa, 0, LPC_BUFFER_SIZE, 0);
			if (!NT_SUCCESS(Status))
			{
				printf("LPC: ZwCreatePort failed with status %08x\n", Status);

				CdbgUserExceptionDispatcherUnhook (dbg);
				for (ULONG i=0; i<Proc->ThreadCount; i++)
					ZwClose (dbg->hThreads);
				ZwClose (dbg->hProcess);
				hfree (dbg->hThreads);
				hfree (Buffer);
				hfree (dbg);
				return NULL;
			}

			HANDLE hTargetPort;
			DuplicateHandle (GetCurrentProcess(), dbg->hMessagePort, dbg->hProcess, &hTargetPort, 0, 0, DUPLICATE_SAME_ACCESS);

			ULONG t;
			if(!WriteProcessMemory (dbg->hProcess, (PUCHAR)dbg->hooks + 0x10, &hTargetPort, 4, &t))
			{
				printf("WriteProcessMemory failed for writing LPC port handle [err %d]\n", __LINE__);
				return FALSE;
			}


			printf("LPC port created [handle=%08x]\n", dbg->hMessagePort);

			dbg->hLpcServer = CreateThread (NULL, NULL, CdbgLpcServer, dbg, 0, 0);

			hfree (Buffer);

			if(!SymInitialize (dbg->hProcess, 0, TRUE))
			{
				CdbgDetach (dbg);
				dbg = NULL;
				printf("SymInitialize failed for the process\n");
			}

			return dbg;
		}

		if (!Proc->NextEntryDelta) break;
	}

	printf("processes = %d\n", processes);
	Sleep(-1);

	hfree (Buffer);
	hfree (dbg);
	return NULL;
}

BOOL g_KillOnDetach = TRUE;

VOID
CdbgDetach(
	PDEBUGGEE dbg
	)
/*++
	Detach debugger
--*/
{
	CdbgUserExceptionDispatcherUnhook (dbg);

	ULONG i;
	for (i=0; i<MAX_BPS; i++)
	{
		if (dbg->bps[i].Present)
		{
			CdbgRemoveSoftwareBreakpoint (dbg, 0, i);
		}
	}

	HANDLE hProcess;
	
	if (g_KillOnDetach)
		hProcess = OpenProcess (PROCESS_TERMINATE, 0, dbg->dwProcessId);

	CdbgFastDetach (dbg);

	if (g_KillOnDetach)
	{
		TerminateProcess (hProcess, 0);
		CloseHandle (hProcess);
	}
}

VOID
CdbgFastDetach(
	PDEBUGGEE dbg
	)
/*++
	Perform fast detaching when the process is being terminated.
--*/
{
	TerminateThread (dbg->hLpcServer, 0);

	VirtualFreeEx (dbg->hProcess, dbg->BreakPointBuffers, SIZEOF_BP_BUFFER * MAX_BPS, MEM_RELEASE);

	for (ULONG i=0; i<dbg->nThreads; i++)
		ZwClose (dbg->hThreads);

	ZwClose (dbg->hProcess);

	hfree (dbg->hThreads);
	hfree (dbg);
}

INT
CdbgSetSoftwareBreakpoint(
	PDEBUGGEE dbg,
	ULONG Address,
	BOOLEAN OneShot
	)
/*++
	Set software breakpoint
--*/
{
	ULONG t;
	UCHAR OldByte = 0;

	if (!(ReadProcessMemory (dbg->hProcess, (LPCVOID)Address, &OldByte, 1, &t) &&
		  WriteProcessMemory (dbg->hProcess, (LPVOID)Address, "\xCC", 1, &t)))
	{
		FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, sizeof(cdbg_last_err)-1, 0);
		return -1;
	}

	for (int i=0; i<MAX_BPS; i++)
	{
		if (dbg->bps[i].Present == 0)
		{
			dbg->bps[i].Present = 1;
			dbg->bps[i].Hardware = 0;
			dbg->bps[i].AddressLow = Address;
			dbg->bps[i].OldByte = OldByte;
			dbg->bps[i].OneShot = OneShot;

			if (!OneShot)
			{
				UCHAR buffer[SIZEOF_BP_BUFFER];

				if ( !ReadProcessMemory (dbg->hProcess, (LPCVOID)Address, buffer, SIZEOF_BP_BUFFER, &t))
				{
					FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, sizeof(cdbg_last_err)-1, 0);
					return -1;
				}

				buffer[0] = OldByte;

				ULONG len = size_of_code (buffer);
				PUCHAR bpbase = (PUCHAR) dbg->BreakPointBuffers;

				buffer[len] = 0xE9;
				*(ULONG*)&buffer[len+1] = (Address + len) - ((ULONG)bpbase + SIZEOF_BP_BUFFER*i + len) - 5;
				
				if ( !WriteProcessMemory (dbg->hProcess, bpbase + SIZEOF_BP_BUFFER*i, buffer, SIZEOF_BP_BUFFER, &t))
				{
					FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, sizeof(cdbg_last_err)-1, 0);
					return -1;
				}

				dbg->bps[i].AddressOfBuffer = (ULONG)bpbase + SIZEOF_BP_BUFFER*i;
			}

			return i;
		}
	}

	lstrcpy (cdbg_last_err, "Not enough slots");
	return -1;
}


BOOL
CdbgRemoveSoftwareBreakpoint(
	PDEBUGGEE dbg,
	ULONG Address,
	INT Number
	)
/*++
	Remove software breakpoint
--*/
{
	if (Address)
	{
		Number = -1;
		for (int i=0; i<MAX_BPS; i++)
		{
			if (dbg->bps[i].Present == 1 && dbg->bps[i].AddressLow == Address)
			{
				Number = i; break;
			}
		}
	}

	if (Number != -1)
	{
		dbg->bps[Number].Present = 0;
		
		ULONG t;
		if(!WriteProcessMemory (dbg->hProcess, (LPVOID)dbg->bps[Number].AddressLow, &dbg->bps[Number].OldByte, 1, &t))
		{
			FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, sizeof(cdbg_last_err)-1, 0);
			return FALSE;
		}

		return TRUE;
	}

	lstrcpy (cdbg_last_err, "Not found");
	return FALSE;
}


INT
CdbgSetHardwareBreakpoint(
	PDEBUGGEE dbg,
	ULONG Address,
	BOOLEAN OneShot,
	UCHAR Type,
	UCHAR Length
	)
/*++
	Set hardware breakpoint
--*/
{
	for (int i=0; i<4; i++)
	{
		if (dbg->hws[i] == 0)
		{
			ULONG r;

			for (r=0; r<MAX_BPS; r++)
			{
				if (dbg->bps[r].Present == 0)
				{
					dbg->hws[i] = &dbg->bps[r];
					break;
				}
			}

			dbg->hws[i]->Present = 1;
			dbg->hws[i]->Hardware = 1;
			dbg->hws[i]->AddressLow = Address;
			dbg->hws[i]->Type = Type;
			dbg->hws[i]->OneShot = OneShot;
			dbg->hws[i]->BpNum = i;


			for (ULONG j=0; j<dbg->nThreads; j++)
			{
				CONTEXT ctx = {CONTEXT_DEBUG_REGISTERS};

				BOOL a = GetThreadContext (dbg->hThreads[j], &ctx);

				REG_DR7 dr7;
				dr7.Raw = ctx.Dr7;

				switch (i)
				{
				case 0:
					dr7.Len0 = Length - 1;
					dr7.Local0 = 1;
					dr7.ReadWrite0 = Type;
					ctx.Dr0 = Address;
					break;
				case 1:
					dr7.Len1 = Length - 1;
					dr7.Local1 = 1;
					dr7.ReadWrite1 = Type;
					ctx.Dr1 = Address;
					break;
				case 2:
					dr7.Len2 = Length - 1;
					dr7.Local2 = 1;
					dr7.ReadWrite2 = Type;
					ctx.Dr2 = Address;
					break;
				case 3:
					dr7.Len3 = Length - 1;
					dr7.Local3 = 1;
					dr7.ReadWrite3 = Type;
					ctx.Dr3 = Address;
					break;
				}

				ctx.Dr7 = dr7.Raw;

				a = SetThreadContext (dbg->hThreads[j], &ctx);

				if (!OneShot)
				{
					UCHAR buffer[SIZEOF_BP_BUFFER];
					ULONG t;

					if ( !ReadProcessMemory (dbg->hProcess, (LPCVOID)Address, buffer, SIZEOF_BP_BUFFER, &t))
					{
						FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, sizeof(cdbg_last_err)-1, 0);
						return -1;
					}

					ULONG len = size_of_code (buffer);
					PUCHAR bpbase = (PUCHAR) dbg->BreakPointBuffers;

					buffer[len] = 0xE9;
					*(ULONG*)&buffer[len+1] = (Address + len) - ((ULONG)bpbase + SIZEOF_BP_BUFFER*r + len) - 5;
					
					if ( !WriteProcessMemory (dbg->hProcess, bpbase + SIZEOF_BP_BUFFER*r, buffer, SIZEOF_BP_BUFFER, &t))
					{
						FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, sizeof(cdbg_last_err)-1, 0);
						return -1;
					}

					dbg->bps[r].AddressOfBuffer = (ULONG)bpbase + SIZEOF_BP_BUFFER*r;

				} // if !OneShot

			} // for j=nThreads

			return r;

		} // if hws==0

	} // for
	return 0;
}


BOOL
CdbgRemoveHardwareBreakpoint(
	PDEBUGGEE dbg,
	ULONG Address,
	INT Number
	)
/*++
	Remove software breakpoint
--*/
{
	if (Address)
	{
		Number = -1;
		for (int i=0; i<MAX_BPS; i++)
		{
			if (dbg->bps[i].Present == 1 && dbg->bps[i].AddressLow == Address)
			{
				Number = i; break;
			}
		}
	}

	if (Number != -1)
	{
		ULONG i = dbg->bps[Number].BpNum;

		dbg->bps[Number].Present = 0;
		dbg->hws[i] = NULL;

		for (ULONG j=0; j<dbg->nThreads; j++)
		{
			CONTEXT ctx = {CONTEXT_DEBUG_REGISTERS};

			BOOL a = GetThreadContext (dbg->hThreads[j], &ctx);

			REG_DR7 dr7;
			dr7.Raw = ctx.Dr7;

			switch (i)
			{
			case 0:
				dr7.Local0 = 0;
				ctx.Dr0 = 0;
				break;
			case 1:
				dr7.Local1 = 0;
				ctx.Dr1 = 0;
				break;
			case 2:
				dr7.Local2 = 0;
				ctx.Dr2 = 0;
				break;
			case 3:
				dr7.Local3 = 0;
				ctx.Dr3 = 0;
				break;
			}

			ctx.Dr7 = dr7.Raw;

			a = SetThreadContext (dbg->hThreads[j], &ctx);
		}
		

		return TRUE;
	}

	lstrcpy (cdbg_last_err, "Not found");
	return FALSE;
}


BOOL
CdbgDisableSoftwareBreakpoint(
	PDEBUGGEE dbg,
	ULONG Address,
	INT Number
	)
/*++
	Remove software breakpoint
--*/
{
	if (Address)
	{
		Number = -1;
		for (int i=0; i<MAX_BPS; i++)
		{
			if (dbg->bps[i].Present == 1 && dbg->bps[i].AddressLow == Address)
			{
				Number = i; break;
			}
		}

	}

	if (Number != -1)
	{
		dbg->bps[Number].Disabled = 1;
		
		ULONG t;
		if(!WriteProcessMemory (dbg->hProcess, (LPVOID)dbg->bps[Number].AddressLow, &dbg->bps[Number].OldByte, 1, &t))
		{
			FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, sizeof(cdbg_last_err)-1, 0);
			return FALSE;
		}

		return TRUE;
	}

	lstrcpy (cdbg_last_err, "Not found");
	return FALSE;
}

BOOL
CdbgEnableSoftwareBreakpoint(
	PDEBUGGEE dbg,
	ULONG Address,
	INT Number
	)
/*++
	Remove software breakpoint
--*/
{
	if (Address)
	{
		Number = -1;
		for (int i=0; i<MAX_BPS; i++)
		{
			if (dbg->bps[i].Present == 1 && dbg->bps[i].AddressLow == Address)
			{
				Number = i; break;
			}
		}
	}

	if (Number != -1)
	{
		dbg->bps[Number].Disabled = 0;
		
		ULONG t;
		if(!WriteProcessMemory (dbg->hProcess, (LPVOID)dbg->bps[Number].AddressLow, "\xCC", 1, &t))
		{
			FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, sizeof(cdbg_last_err)-1, 0);
			return FALSE;
		}

		return TRUE;
	}

	lstrcpy (cdbg_last_err, "Not found");
	return FALSE;
}

HANDLE
CdbgLookupThread(
	PDEBUGGEE dbg,
	ULONG UniqueThread
	)
/*++
	Look-up thread handle in DEBUGGEE structure for the specified thread id
--*/
{
	for (ULONG i=0; i<dbg->nThreads; i++)
	{
		if (dbg->dwThreadIds[i] == UniqueThread)
			return dbg->hThreads[i];
	}
	return NULL;
}

VOID
CdbgResumeProcess(
	PDEBUGGEE dbg
	)
/*++
	Resumes all threads suspended by CdbgSuspendProcess()
--*/
{
	for (ULONG i=0; i<dbg->nThreads; i++)
	{
		if (dbg->dwThreadIds[i] & 0x80000000)
		{
			dbg->dwThreadIds[i] &= ~0x80000000;
			ResumeThread (dbg->hThreads[i]);
		}
	}
}

VOID
CdbgSuspendProcess(
	PDEBUGGEE dbg
	)
/*++
	Suspend all running threads in the process.
--*/
{
	PSYSTEM_PROCESSES_INFORMATION Buffer = (PSYSTEM_PROCESSES_INFORMATION) GetSystemInformation (SystemProcessesAndThreadsInformation);
	if (Buffer == NULL)
	{
		lstrcpy (cdbg_last_err, "GetSystemInformation failed");
		return;
	}

	for (PSYSTEM_PROCESSES_INFORMATION Proc=Buffer; ; *(ULONG*)&Proc += Proc->NextEntryDelta)
	{
		if (Proc->ProcessId == dbg->dwProcessId)
		{
			for (ULONG iThread=0; iThread < Proc->ThreadCount; iThread++)
			{
				if (Proc->Threads[iThread].State == THREAD_STATE_READY)
				{
					for (ULONG i=0; i<dbg->nThreads; i++)
					{
						if (dbg->dwThreadIds[i] == Proc->Threads[iThread].ClientId.UniqueThread)
						{
							SuspendThread (dbg->hThreads[i]);
							dbg->dwThreadIds[i] |= 0x80000000;
						}
					}
				}
			}

			break;
		}
		if (!Proc->NextEntryDelta) break;
	}
}

#define DPRINT(X) //printf X
#pragma warning(disable:4311 4312)

#define EmitJumpCommand( Proc, From, To )		\
		{										\
			BYTE _splice[5] = {0xE9};			\
			ULONG _t;							\
			*(ULONG*)&_splice[1] = (ULONG)(To) - (ULONG)(From) - 5; \
			WriteProcessMemory (Proc, (PVOID)From, _splice, 5, &_t);		\
		}


BOOLEAN
CdbgSpliceFunctionEx(
	IN  HANDLE	hProcess,
	IN	PVOID	OriginalAddress,
    IN	PVOID	HookFunction,
	OUT	PVOID	SplicingBuffer,
	IN	ULONG	MaxLength,
	OUT	PULONG	BytesWritten
	)
{
	ULONG Len;
	ULONG Ptr, NextAddress;
	BOOLEAN Status = FALSE;

	DPRINT(("Entering CdbgSpliceFunctionEx( 0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x )\n",
		(ULONG)OriginalAddress,
		(ULONG)HookFunction,
		(ULONG)SplicingBuffer,
		sizeof(MaxLength),
		(ULONG)BytesWritten));

	//
    // Copy integer number of instructions to the buffer
	//

	DPRINT(("Copying instructions\n"));
	*BytesWritten = 0;
	ULONG t;

	for( Ptr = (ULONG)OriginalAddress; Ptr < ((ULONG)OriginalAddress+5); Ptr+=Len )
	{
		UCHAR temp_code[20];
		ReadProcessMemory (hProcess, (PVOID)Ptr, temp_code, 20, &t);

		Len = size_of_code( temp_code );

		DPRINT(("Command decoded at address 0x%08x, length 0x%08x\n", Ptr, Len));

		if (Len > 20)
		{
			DPRINT(("ASSERTION FAILURE: Len <= 20"));
			goto _exit;
		}

		if( Ptr < ((ULONG)OriginalAddress+5) )
		{
			if( (Ptr-(ULONG)OriginalAddress+5) >= MaxLength )
			{
				DPRINT(("Error: buffer is too small\n"));
				goto _exit;
			}

		//	memcpy( (PVOID)((ULONG)SplicingBuffer+(Ptr-(ULONG)OriginalAddress)), temp_code, Len );
			WriteProcessMemory( hProcess, (PVOID)((ULONG)SplicingBuffer+(Ptr-(ULONG)OriginalAddress)), temp_code, Len, &t);

			*BytesWritten += Len;
		}
	}


	NextAddress = Ptr;
	Ptr += (ULONG)SplicingBuffer -(ULONG)OriginalAddress;

	DPRINT(("*BytesWritten = 0x%08x, Ptr = 0x%08x, NextAddress = 0x%08x\n", *BytesWritten, Ptr, NextAddress));

	DPRINT(("Generating splicing buffer\n"));

	//
	// Emit splicing jump to the buffer
	//

	DWORD Old;
	VirtualProtectEx( hProcess, OriginalAddress, 5, PAGE_READWRITE, &Old );

	EmitJumpCommand( hProcess, OriginalAddress, HookFunction );

	VirtualProtectEx( hProcess, OriginalAddress, 5, Old, &Old );

	DPRINT(("Original address bytes: %02x %02x %02x %02x %02x\n",
		((PBYTE)OriginalAddress)[0],
		((PBYTE)OriginalAddress)[1],
		((PBYTE)OriginalAddress)[2],
		((PBYTE)OriginalAddress)[3],
		((PBYTE)OriginalAddress)[4]
		));

	EmitJumpCommand( hProcess, Ptr, NextAddress );

	Status = 1;

_exit:
    
	return Status;
}


void PrintMessage(LPC_MESSAGE* lpc)
{
	char *MessageTypes[] = {
		"LPC_NEW_MESSAGE",
		"LPC_REQUEST",
		"LPC_REPLY",
		"LPC_DATAGRAM",
		"LPC_LOST_REPLY",
		"LPC_PORT_CLOSED",
		"LPC_CLIENT_DIED",
		"LPC_EXCEPTION",
		"LPC_DEBUG_EVENT",
		"LPC_ERROR_EVENT",
		"LPC_CONNECTION_REQUEST"
	};

	printf("LPC_MESSAGE %08x:\n", lpc);
	printf(" DataSize = %08x\n", lpc->DataSize);
	printf(" MessageSize = %08x\n", lpc->MessageSize);
	printf(" MessageType = %s [%08x]\n", lpc->MessageType > 10 ? "LPC_UNKNOWN" : MessageTypes[lpc->MessageType], lpc->MessageType);
	printf(" VirtualRangesOffset = %08x\n", lpc->VirtualRangesOffset);
	printf(" ClientId.UniqueThread = %08x\n", lpc->ClientId.UniqueThread);
	printf(" ClientId.UniqueProcess = %08x\n", lpc->ClientId.UniqueProcess);
	printf(" MessageId = %08x\n", lpc->MessageId);
	printf(" SectionSize = %08x\n", lpc->SectionSize);

	for( int i=0; i<lpc->DataSize; i++ ) {
		printf(" %02x", lpc->Data[i]);
	}

	printf("\n\n");
}

char *LmtTypes[] = {
	"LMT_UNKNOWN",
	"LMT_NEWTHREAD",		// 1 arg -  ThreadId
	"LMT_EXITTHREAD",		// 2 args -  ThreadId, ExitStatus
	"LMT_EXITPROCESS",	// 1 arg -  ExitStatus
	"LMT_EXCEPTION",
	"LMT_UNHANDLEDEXCEPTION"
};

ULONG LastEip = 0;

#undef OP_NONE
#undef OP_DATA_I8
#undef OP_DATA_I16
#undef OP_DATA_I32
#undef OP_MODRM
#undef OP_DATA_PRE66_67
#undef OP_PREFIX
#undef OP_REL32
#undef OP_REL8

extern "C" {
#include "Disasm.h"
}

VOID
CdbgCorrectPatchedMemory(
	PDEBUGGEE dbg,
	ULONG VirtualAddressStart,
	ULONG Size,
	PVOID Buffer
	)
/*++
	Correct the memory patches (0xCCs) with the right value
--*/
{
	for (int i=0; i<MAX_BPS; i++)
	{
		if (dbg->bps[i].AddressLow >= VirtualAddressStart &&
			dbg->bps[i].AddressLow < (VirtualAddressStart + Size) &&
			dbg->bps[i].Hardware == 0)
		{
			if (dbg->bps[i].OneShot)
				((UCHAR*)Buffer)[ dbg->bps[i].AddressLow - VirtualAddressStart ] = dbg->bps[i].OldByte;
			else
			{
				ULONG t;

				ReadProcessMemory (dbg->hProcess, (LPCVOID)dbg->bps[i].AddressOfBuffer, 
					&((UCHAR*)Buffer)[ dbg->bps[i].AddressLow - VirtualAddressStart ],
					1, &t);
			}
		}
	}
}


ULONG
WINAPI
CdbgLpcServer(
	LPVOID pdbg
	)
/*++
	LPC server thread for the debuggee.
--*/
{
	PDEBUGGEE dbg = (PDEBUGGEE) pdbg;

	char MsgBuf[0x148];
	LPC_MESSAGE *msg = (LPC_MESSAGE*) MsgBuf;

	NTSTATUS Status;
	ULONG Failures = 0;

	while (TRUE)
	{
		Status = ZwReplyWaitReceivePort ( dbg->hMessagePort,
										  NULL,
										  NULL,
										  msg );

		if (!NT_SUCCESS(Status))
		{
			printf("LPC: ZwRequestWaitReplyPort failed with status %08x\n", Status);
			Failures ++;

			if (Failures < 5)
				continue;

			printf("5 failures reached\nDetaching\n");

			CdbgDetach (dbg);

			// never reach here - CdbgDetach kills us.
			return 0;
		}

		Failures = 0;

		//PrintMessage (msg);

		if (msg->MessageType == LPC_DATAGRAM)
		{
			CDBG_LPC_MESSAGE *msgdata = (CDBG_LPC_MESSAGE*) &msg->Data;

			/*
			if (msgdata->Type == LMT_EXCEPTION &&
				msgdata->ExceptionRecord.ExceptionCode == STATUS_BREAKPOINT &&
				dbg->StoppedSystem == 1)
			{
				CdbgRemoveSoftwareBreakpoint (dbg, 0, 0);
				dbg->StoppedSystem = 0;
				dbg->bps[0].Present = 1;
				CdbgpLpcContinue (dbg);
				continue;
			}
			*/

			printf("\r");

			int BpStopped = -1;

			if (msgdata->Type == LMT_EXCEPTION)
				LastEip = (ULONG)msgdata->ExceptionRecord.ExceptionAddress;

			if (msgdata->Type == LMT_EXCEPTION &&
				(msgdata->ExceptionRecord.ExceptionCode == STATUS_BREAKPOINT ||
				 msgdata->ExceptionRecord.ExceptionCode == STATUS_SINGLE_STEP))
			{
				for (int i=0; i<MAX_BPS; i++)
				{
					//printf("Testing %d (%d) : %08x==%08x\n", i, dbg->bps[i].Present, dbg->bps[i].AddressLow, msgdata->ExceptionRecord.ExceptionAddress);
					if (dbg->bps[i].Present &&
						(LPVOID)dbg->bps[i].AddressLow == msgdata->ExceptionRecord.ExceptionAddress)
					{
						printf("DBG: Breakpoint %d hit: %08x\n", i, dbg->bps[i].AddressLow);

						Sleep(100);

						if (dbg->bps[i].OneShot)
						{
							if (!dbg->bps[i].Hardware)
							{
								if(!CdbgRemoveSoftwareBreakpoint (dbg, 0, i))
									printf("Cannot remove one-shot breakpoint: %s\n", cdbg_last_err);
								else
									printf("DBG: One-Shot breakpoint disabled.\n");
							}
							else
							{
								if(!CdbgRemoveHardwareBreakpoint (dbg, 0, i))
									printf("Cannot remove one-shot hw breakpoint: %s\n", cdbg_last_err);
								else
									printf("DBG: One-Shot hw breakpoint disabled.\n");
							}

							if ((ULONG)msgdata->ExceptionRecord.ExceptionAddress == dbg->EntryPoint)
							{
								printf("DBG: Debugged process stopped on its entry point\n");
								dbg->StoppedSystem = 1;
							}
						}
						else
						{
							CONTEXT ctx;
							ULONG t;

							//
							// Change EIP to the buffer
							//
							
							ReadProcessMemory (dbg->hProcess, (LPCVOID)msgdata->pCtx, &ctx, sizeof(CONTEXT), &t);
							ctx.Eip = dbg->bps[i].AddressOfBuffer;
							WriteProcessMemory (dbg->hProcess, (LPVOID)msgdata->pCtx, &ctx, sizeof(CONTEXT), &t);
						}

						break;
					}
				}

				BpStopped = i;
				if (i == MAX_BPS)
				{
//					if (dbg->StoppedSystem = 1)
//					{
//						printf("Temp breakpoint hit\ncdbg >");
//						dbg->StoppedSystem = 0;
//						Sleep(100);
//						CdbgpLpcContinue (dbg);
//						continue;
//					}

					if (msgdata->ExceptionRecord.ExceptionCode == STATUS_SINGLE_STEP)
					{
						if (dbg->SingleStepNext)
							printf("DBG: Single step\n");
						else
							printf("DBG: Embedded INT1 command\n");
					}
					else
					{
						printf("DBG: Embedded INT3 command\n");
					}
				}

				dbg->StoppedContext = msgdata->pCtx;
			}

			switch (msgdata->Type)
			{
			case LMT_EXCEPTION:

				if (!(msgdata->ExceptionRecord.ExceptionCode == STATUS_SINGLE_STEP &&
					dbg->SingleStepNext))
				{
					printf("DBG: Exception %08x at address %08x in process %s [flags=%08x, args=(%d) %08x %08x %08x %08x]\n",
						msgdata->ExceptionRecord.ExceptionCode,
						msgdata->ExceptionRecord.ExceptionAddress,
						dbg->name,
						msgdata->ExceptionRecord.ExceptionFlags,
						msgdata->ExceptionRecord.NumberParameters,
						msgdata->ExceptionRecord.ExceptionInformation[0],
						msgdata->ExceptionRecord.ExceptionInformation[1],
						msgdata->ExceptionRecord.ExceptionInformation[2],
						msgdata->ExceptionRecord.ExceptionInformation[3]
						);
				}
				else
				{
					Sleep(100);
					dbg->SingleStepNext = 0;

					CONTEXT ctx;
					ULONG t;
					
					ReadProcessMemory (dbg->hProcess, (LPCVOID)msgdata->pCtx, &ctx, sizeof(CONTEXT), &t);
					ctx.EFlags &= ~EFLAGS_TF;
					WriteProcessMemory (dbg->hProcess, (LPVOID)msgdata->pCtx, &ctx, sizeof(CONTEXT), &t);
				}

				CdbgSuspendProcess (dbg);
				dbg->Stopped = 1;
				dbg->StoppedEip = (ULONG)msgdata->ExceptionRecord.ExceptionAddress;

				{
					UCHAR xBytes[20];
					LPVOID addr;
					ULONG t;

					if (BpStopped < MAX_BPS && dbg->bps[BpStopped].Hardware==0 && dbg->bps[BpStopped].OneShot==0)
					{
						addr = (LPVOID) dbg->bps[BpStopped].AddressOfBuffer;
					}
					else
					{
						addr = (LPVOID) LastEip;
					}

					printf("\r");

					if (!ReadProcessMemory (dbg->hProcess, addr, xBytes, sizeof(xBytes), &t))
					{
						printf("%08x: ???\n", msgdata->ExceptionRecord.ExceptionAddress);
					}
					else
					{
						if (BpStopped < MAX_BPS && dbg->bps[BpStopped].Hardware==0 && dbg->bps[BpStopped].OneShot==1)
						{
							xBytes[0] = dbg->bps[BpStopped].OldByte;
						}

						TInstruction Inst;
						TDisCommand Cmd;
						TMnemonicOptions Opts;

						PUCHAR cPtr = xBytes;
						ULONG Len = 0;

						memset (&Inst, 0, sizeof(Inst));
						memset (&Cmd, 0, sizeof(Cmd));
						memset (&Opts, 0, sizeof(Opts));

						Len = InstrDecode (cPtr, &Inst, FALSE);
						InstrDasm (&Inst, &Cmd, FALSE);

						Opts.AddHexDump = 1;
						Opts.AlternativeAddres = LastEip;
						Opts.AddAddresPart = 1;
						Opts.MnemonicAlign = 30;
						Opts.RealtiveOffsets = 0;
						Opts.LookupSymbols = 1;
						Opts.hProcess = dbg->hProcess;
						Opts.ShowDisplacement = g_ShowDisplacement;

						char Mnemonic[256] = {0};

						MakeMnemonic (Mnemonic, &Cmd, &Opts);
						printf("%s\n", Mnemonic);
					}
				}

				break;

			case LMT_EXITPROCESS:

				printf("DBG: Process %d [%s] exited with status %08x\n", 
					msg->ClientId.UniqueProcess,
					dbg->name,
					msgdata->ExitStatus
					);

				CdbgFastDetach (dbg);
				::dbg = NULL;

				break;

			case LMT_EXITTHREAD:

				printf("DBG: Thread %d in process %d [%s] exited with status %08x\n", 
					msg->ClientId.UniqueThread,
					msg->ClientId.UniqueProcess,
					dbg->name,
					msgdata->ExitStatus
					);
				break;
			}

			printf("cdbg> ");

			FlashWindow (hWnd, TRUE);

			/*printf("MessageType: %s (%d)\n", LmtTypes[msgdata->Type], msgdata->Type);
			printf("ThreadId: %x\n", msgdata->ThreadId);
			printf("ExitStatus: %x\n", msgdata->ExitStatus);
			printf("ExcCode: %x\n", msgdata->ExceptionRecord.ExceptionCode);
			*/
		}

	}

	return 0;
}

BOOL
CdbgpLpcContinue(
	PDEBUGGEE dbg
	)
{
	NTSTATUS Status;
	LPC_MESSAGE lpc = {0};

	lpc.MessageSize = lpc.DataSize + sizeof(lpc) - 1;

	Status = ZwRequestPort (dbg->hMessagePort, &lpc);

	if (!NT_SUCCESS(Status))
	{
		wsprintf (cdbg_last_err, "ZwRequestPort failed with status %08x\n", Status);
		return FALSE;
	}

	return TRUE;
}

BOOL
CdbgContinue(
	PDEBUGGEE dbg
	)
/*++
	Continue execution
--*/
{
	if (!dbg->Stopped)
	{
		lstrcpy (cdbg_last_err, "Debuggee is already running");
		return FALSE;
	}

	CdbgResumeProcess (dbg);
	dbg->Stopped = 0;

	return CdbgpLpcContinue (dbg);
}
