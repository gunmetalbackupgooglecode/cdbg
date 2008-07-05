#include "cdbg.h"

//
// Command table
//

CMD_HANDLER_ENTRY CommandTable[] = {
	CMD_ENTRY (attach, 1, "attaches to a process with the specified PID/name"),
	CMD_ENTRY (detach, 0, "detaches from the process previously attached by attach command"),
	CMD_ENTRY (ver, 0, "displays version information"),
	CMD_ENTRY (tasklist, 0, "displays list of the processes in the system"),
	CMD_ENTRY (window, 1, "searches the window by its name or handle"),
	CMD_ENTRY (process, 1, "searches the process by its name or PID"),
	CMD_ENTRY (thread, 1, "seacrhes the thread by its name or TID"),
	CMD_ENTRY (taskkill, 1, "kills the process by its PID"),
	CMD_ENTRY (bp, 1, "inserts the breakpoint. debugger should be attached to a process"),
	CMD_ENTRY (c, 0, "runs stopped program. debugger should be attached to a process"),
	CMD_ENTRY (hw, 1, "inserts the hw breakpoint"),
	CMD_ENTRY (help, 0, "displays this help"),
	CMD_ENTRY (run, 1, "runs the specified program"),
	CMD_ENTRY (kill, 0, "kills current program"),
	CMD_ENTRY (u, 0, "disassembles the program"),
	CMD_ENTRY (showdisp, 0, "control the show-displacement disassembler flag"),
	CMD_ENTRY (t, 0, "trace over one command"),
	CMD_ENTRY (s, 0, "step into one command"),
	CMD_ENTRY (r, 0, "display registers information or change register"),
	CMD_ENTRY (dm, 0, "display memory contents"),
	{do_e, 0, "?", "evaluates an expression"},
	CMD_END
};

//
// Common
//

PDEBUGGEE dbg = NULL;

bool AssertAttached()
{
	if (!dbg)
	{
		printf("Debugger should be attached to a process to perform this operation\n");
		return 1;
	}
	return 0;
}
#define ASSERT_ATTACHED() {if(AssertAttached()) return;}



//
// Command handlers
//

CMDHANDLER (exit)
{
	if (dbg)
	{
		CdbgDetach (dbg);
	}
}

CMDHANDLER (ver)
{
	printf("CDBG console debugger [Great] version " CDBG_VER "\n");
}

CMDHANDLER (attach)
{
	ARG *proc = GetArg(1);
	char name[32] = "";

	if (dbg)
	{
		printf("Already attached to %d [%s]\n", dbg->dwProcessId, dbg->name);
		return;
	}

	switch (proc->type)
	{
	case AT_DWORD:

		//
		// A process id supplied.
		//

		if (!CdbgLookupProcessName (NULL, proc->dw, name, sizeof(name)-1))
		{
			printf("Looking up process ID %d failed: %s\n", proc->dw, cdbg_last_err);
			break;
		}

		printf("Attaching to process ID %d [%s]... ", proc->dw, name);

		dbg = CdbgAttach (proc->dw);

		if (dbg==NULL)
		{
			printf("[FAILED]\n%s\n", cdbg_last_err);
		}
		else printf("[ OK ]\n");

		break;
	
	case AT_STRING:
		
		printf("Searching for process %s ...\n", proc->str);

		WCHAR procname[256];
		MultiByteToWideChar (CP_ACP, 0, proc->str, strlen(proc->str), procname, 255);

		PSYSTEM_PROCESSES_INFORMATION Buffer = (PSYSTEM_PROCESSES_INFORMATION) 
			GetSystemInformation (SystemProcessesAndThreadsInformation);

		for (PSYSTEM_PROCESSES_INFORMATION Proc=Buffer; ; *(ULONG*)&Proc += Proc->NextEntryDelta)
		{
			if (Proc->ProcessName.Buffer && wcsstr(Proc->ProcessName.Buffer,procname))
			{
				printf("Attaching to process ID %d [%s]... ", Proc->ProcessId, proc->str);

				dbg = CdbgAttach (Proc->ProcessId);

				if (dbg==NULL)
				{
					printf("[FAILED]\n%s\n", cdbg_last_err);
				}
				else printf("[ OK ]\n");

				hfree (Buffer);
				return;
			}

			if (Proc->NextEntryDelta == 0)
				break;
		}

		printf("Process not found\n");

		hfree (Buffer);
		break;
	}

	FreeArg (proc);
}

CMDHANDLER (detach)
{
	ASSERT_ATTACHED();

	printf("~ Detaching from process id %d\n", dbg->dwProcessId);
	CdbgDetach (dbg);

	dbg = NULL;

	printf("+ Session ended\n");
}

struct WND
{
	HWND hWnd;
	ULONG threadID;
	ULONG processID;
	char processName[256];
	char title[256];
	ULONG swShow;
};

ULONG nWindows;
ULONG iWindow;
ULONG fullWindows;

BOOL WINAPI WndEnumProc (HWND hWnd, LPARAM lParam)
{
	WND **pWnds = (WND**)lParam;

	if (*pWnds == 0)
	{
		iWindow = 0;
		fullWindows = 0;
		nWindows = 200;
		*pWnds = (WND*) halloc (sizeof(WND)*nWindows);
	}

	if (iWindow == nWindows)
	{
		nWindows += 40;
		*pWnds = (WND*) hrealloc (*pWnds, sizeof(WND)*nWindows);
	}

	fullWindows++;

	WINDOWPLACEMENT wp = {0};
	wp.length = sizeof(wp);

	GetWindowPlacement (hWnd, &wp);

	if ( (GetWindowLong(hWnd, GWL_STYLE) & WS_SYSMENU) &&
		 wp.showCmd != SW_HIDE )
	{
		(*pWnds)[iWindow].swShow = wp.showCmd;
		(*pWnds)[iWindow].hWnd = hWnd;
		(*pWnds)[iWindow].threadID = GetWindowThreadProcessId (hWnd, &(*pWnds)[iWindow].processID);
		GetWindowText (hWnd, (*pWnds)[iWindow].title, sizeof((*pWnds)[iWindow].title));

		if ( strlen((*pWnds)[iWindow].title)>0 )
		{
			iWindow ++;
		}
	}

	return TRUE;
}

void UiDumpProcessShort (WND* wnds, PSYSTEM_PROCESSES_INFORMATION Proc)
{
	char *wnd = "";

	for (ULONG i=0; i<iWindow; i++)
	{
		if (wnds[i].processID == Proc->ProcessId)
		{
			wnd = wnds[i].title;
			break;
		}
	}

	char wnd2[256];
	CharToOem (wnd, wnd2);
	wnd2[44] = '.';
	wnd2[45] = '.';
	wnd2[46] = '.';
	wnd2[47] = 0;
	printf("%5d %5d %14S %s\n", Proc->ProcessId, Proc->InheritedFromProcessId, Proc->ProcessName.Buffer, wnd2);
}

char *ThStates[] = {
	"Initialized",
	"Ready",
	"Running",
	"Standby",
	"Terminated",
	"Wait",
	"Transition",
	"Unknown"
};

char* swCommands[] = {
	"SW_HIDE",
	"SW_NORMAL",
	"SW_SHOWMINIMIZED",
	"SW_MAXIMIZE",
	"SW_SHOWNOACTIVATE",
	"SW_SHOW",
	"SW_MINIMIZE",
	"SW_SHOWMINNOACTIVE",
	"SW_SHOWNA",
	"SW_RESTORE",
	"SW_SHOWDEFAULT",
	"SW_FORCEMINIMIZE"
};

char* WaitReasons[] = {
    "Executive",
    "FreePage",
    "PageIn",
    "PoolAllocation",
    "DelayExecution",
    "Suspended",
    "UserRequest",
    "WrExecutive",
    "WrFreePage",
    "WrPageIn",
    "WrPoolAllocation",
    "WrDelayExecution",
    "WrSuspended",
    "WrUserRequest",
    "WrEventPair",
    "WrQueue",
    "WrLpcReceive",
    "WrLpcReply",
    "WrVirtualMemory",
    "WrPageOut",
    "WrRendezvous",
    "Spare2",
    "Spare3",
    "Spare4",
    "Spare5",
    "Spare6",
    "WrKernel"
};


void UiDumpThreadShort (WND* wnds, PSYSTEM_THREADS_INFORMATION Thread)
{
	char *wnd = "";

	for (ULONG i=0; i<iWindow; i++)
	{
		if (wnds[i].threadID == (ULONG)Thread->ClientId.UniqueThread)
		{
			wnd = wnds[i].title;
			break;
		}
	}

	char wnd2[256];
	CharToOem (wnd, wnd2);
	wnd2[44] = '.';
	wnd2[45] = '.';
	wnd2[46] = '.';
	wnd2[47] = 0;
	printf("%5d %5d %10s %15s %14x  %s\n",
		Thread->ClientId.UniqueThread, Thread->ClientId.UniqueProcess, 
		ThStates[Thread->State], 
		WaitReasons[Thread->WaitReason],
		Thread->StartAddress,
		wnd2);
}

void UiDumpThreadFull (WND* wnds, PSYSTEM_THREADS_INFORMATION Thread)
{
	char *wnd = "";

	printf("Thread  TID=%d, PID=%d\n", Thread->ClientId.UniqueThread, Thread->ClientId.UniqueProcess);
	printf("Thread state: %s\n", ThStates[Thread->State]);
	printf("Wait reason:  %s\n", WaitReasons[Thread->WaitReason]);
	printf("Start address: %08x\n", Thread->StartAddress);
	printf("Context switches: %d\n", Thread->ContextSwitchCount);
	printf("Base priority: %d\n", Thread->BasePriority);
	
	printf("Windows owned by thread:\n");

	for (ULONG i=0; i<iWindow; i++)
	{
		if (wnds[i].threadID == (ULONG)Thread->ClientId.UniqueThread)
		{
			printf("HWND=%06x, ShowCmd=%s TID=%d Title='%s' \n", 
				wnds[i].hWnd,
				swCommands[wnds[i].swShow], 
				wnds[i].threadID, 
				wnds[i].title);
		}
	}
}

void UiDumpProcessFull (WND* wnds, PSYSTEM_PROCESSES_INFORMATION Proc)
{
	char *wnd = "";

	printf("Process  [%S]  PID=%d, PPID=%d\n", Proc->ProcessName.Buffer, Proc->ProcessId, Proc->InheritedFromProcessId);
	printf("Windows owned by process:\n");

	for (ULONG i=0; i<iWindow; i++)
	{
		if (wnds[i].processID == Proc->ProcessId)
		{
			printf("HWND=%06x, ShowCmd=%s TID=%d Title='%s' \n", 
				wnds[i].hWnd,
				swCommands[wnds[i].swShow], 
				wnds[i].threadID, 
				wnds[i].title);
		}
	}

	printf("Threads:\n");
	printf("  TID   PID      State      WaitReason   StartAddress  Window\n"
		   " ==============================================================\n");

	for (i=0; i<Proc->ThreadCount; i++)
	{
		UiDumpThreadShort (wnds, &Proc->Threads[i]);
	}
}

CMDHANDLER (tasklist)
{
	printf("[1/3] Loading processes information...\r");

	PSYSTEM_PROCESSES_INFORMATION Buffer = (PSYSTEM_PROCESSES_INFORMATION) 
		GetSystemInformation (SystemProcessesAndThreadsInformation);

	printf("[2/3] Loading windows information...  \r");

	WND *wnds = NULL;
	EnumWindows (WndEnumProc, (LPARAM)&wnds);

	printf("[3/3] Synchronizing...                \r");

	printf("  PID  PPID          Image  Window\n"
		   " ==================================\n");

	int processes = 0;
	for (PSYSTEM_PROCESSES_INFORMATION Proc=Buffer; ; *(ULONG*)&Proc += Proc->NextEntryDelta)
	{
		UiDumpProcessShort (wnds, Proc);
		processes++;

		if (!Proc->NextEntryDelta) break;
	}

	printf("Total %d processes, %d windows in the system [%d active]\n", processes, fullWindows, iWindow);

	hfree (wnds);
	hfree (Buffer);
}

CMDHANDLER (window)
{
	ARG* arg = GetArg(1);

	HWND hWnd = 0;

	if (arg->type == AT_DWORD)
	{
		hWnd = (HWND)arg->dw;

		WND wnd;
		WINDOWPLACEMENT wp = {0};
		wp.length = sizeof(wp);

		if (!GetWindowPlacement (hWnd, &wp))
		{
			printf("Cannot get window HWND=%x properties\n", hWnd);
			return;
		}

		wnd.swShow = wp.showCmd;
		wnd.hWnd = hWnd;
		wnd.threadID = GetWindowThreadProcessId (hWnd, &wnd.processID);
		GetWindowText (hWnd, wnd.title, sizeof(wnd.title));

		printf("HWND=%06x, ShowCmd=%s PID=%d TID=%d Title='%s' ", 
			wnd.hWnd,
			swCommands[wnd.swShow], 
			wnd.processID, wnd.threadID, 
			wnd.title);
		
		CdbgLookupProcessName (NULL, wnd.processID, wnd.processName, sizeof(wnd.processName)-1);

		printf("Image='%s'\n", wnd.processName);
	}
	else
	{
		printf("[1/3] Loading processes information...\r");

		PSYSTEM_PROCESSES_INFORMATION Buffer = (PSYSTEM_PROCESSES_INFORMATION) 
			GetSystemInformation (SystemProcessesAndThreadsInformation);

		printf("[2/3] Loading windows information...  \r");

		WND *wnds = NULL;
		EnumWindows (WndEnumProc, (LPARAM)&wnds);

		printf("[3/3] Synchronizing...                \r");


		for (ULONG i=0; i<iWindow; i++)
		{
			if (strstr(wnds[i].title, arg->str))
			{
				printf("HWND=%06x, ShowCmd=%s PID=%d TID=%d Title='%s' ", 
					wnds[i].hWnd,
					swCommands[wnds[i].swShow], 
					wnds[i].processID, wnds[i].threadID, 
					wnds[i].title);
				
				CdbgLookupProcessName (Buffer, wnds[i].processID, wnds[i].processName, sizeof(wnds[i].processName)-1);

				printf("Image='%s'\n", wnds[i].processName);
			}
		}

		hfree (wnds);
		hfree (Buffer);
	}

	FreeArg (arg);
}

CMDHANDLER (process)
{
	ARG *arg = GetArg(1);

	ULONG dwProcessId = -1;

	if (arg->type == AT_DWORD)
	{
		dwProcessId = arg->dw;
	}

	printf("[1/3] Loading processes information...\r");

	PSYSTEM_PROCESSES_INFORMATION Buffer = (PSYSTEM_PROCESSES_INFORMATION) 
		GetSystemInformation (SystemProcessesAndThreadsInformation);

	printf("[2/3] Loading windows information...  \r");

	WND *wnds = NULL;
	EnumWindows (WndEnumProc, (LPARAM)&wnds);

	printf("[3/3] Synchronizing...                \r");

	if (arg->type != AT_DWORD)
	{
		printf("Processes matching criteria '%s':\n\n", arg->str);

		printf("PID  PPID  Image          Window\n");
	}

	for (PSYSTEM_PROCESSES_INFORMATION Proc=Buffer; ; *(ULONG*)&Proc += Proc->NextEntryDelta)
	{
		if (arg->type == AT_STRING)
		{
			char processName[256];
			WideCharToMultiByte (CP_ACP, 0, Proc->ProcessName.Buffer, Proc->ProcessName.Length, processName, 255, 0, 0);

			if (strstr(processName, arg->str))
			{
				UiDumpProcessShort (wnds, Proc);
			}
		}
		else
		{
			if (Proc->ProcessId == dwProcessId)
			{
				UiDumpProcessFull (wnds, Proc);
			}
		}

		if (!Proc->NextEntryDelta) break;
	}

	hfree (wnds);
	hfree (Buffer);
	FreeArg (arg);
}


CMDHANDLER (thread)
{
	ARG *arg = GetArg(1);

	if (arg->type == AT_STRING)
	{
		printf("Strings are not allowed in the first argument\n");
		FreeArg (arg);
		return;
	}

	printf("[1/3] Loading processes information...\r");

	PSYSTEM_PROCESSES_INFORMATION Buffer = (PSYSTEM_PROCESSES_INFORMATION) 
		GetSystemInformation (SystemProcessesAndThreadsInformation);

	printf("[2/3] Loading windows information...  \r");

	WND *wnds = NULL;
	EnumWindows (WndEnumProc, (LPARAM)&wnds);

	printf("[3/3] Synchronizing...                \r");

	for (PSYSTEM_PROCESSES_INFORMATION Proc=Buffer; ; *(ULONG*)&Proc += Proc->NextEntryDelta)
	{
		for (ULONG i=0; i<Proc->ThreadCount; i++)
		{
			if (Proc->Threads[i].ClientId.UniqueThread == arg->dw)
			{
				UiDumpThreadFull (wnds, &Proc->Threads[i]);
			}
		}

		if (!Proc->NextEntryDelta) break;
	}


	hfree (wnds);
	hfree (Buffer);
	FreeArg (arg);
}

CMDHANDLER (taskkill)
{
	ARG *arg = GetArg(1);

	if (arg->type == AT_STRING)
	{
		printf("Strings are not allowed in the first argument\n");
		FreeArg (arg);
		return;
	}

	char procname[256];
	if(!CdbgLookupProcessName (NULL, arg->dw, procname, sizeof(procname)-1))
	{
		printf("Error while looking up process: %s\n", cdbg_last_err);
		FreeArg (arg);
		return;
	}

	printf("Terminating process %d [%s] ...\n", arg->dw, procname);

	HANDLE hProcess = OpenProcess (PROCESS_TERMINATE, 0, arg->dw);
	if (hProcess ==  NULL)
	{
		FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, 1023, 0);
		printf("OS error while opening process: %s\n", cdbg_last_err);
		FreeArg (arg);
		return;
	}

	TerminateProcess (hProcess, 0xFFFFFFFF);

	ZwClose (hProcess);

	if (dbg && dbg->dwProcessId == arg->dw)
	{
		CdbgDetach (dbg);
		dbg = NULL;
	}

	printf("Process terminated\n");
	FreeArg (arg);
}

BOOLEAN CdbgLookupRegister (ARG *arg, CONTEXT *ctx, ULONG *Value, ULONG *Size)
{
	if (!stricmp(arg->str, "eax"))		{ *Value =  ctx->Eax; *Size=4; }
	else if (!stricmp(arg->str, "ecx")) { *Value =  ctx->Ecx; *Size=4; }
	else if (!stricmp(arg->str, "edx")) { *Value =  (ctx->Edx); *Size=4; }
	else if (!stricmp(arg->str, "ebx")) { *Value =  (ctx->Ebx); *Size=4; }
	else if (!stricmp(arg->str, "esi")) { *Value =  (ctx->Esi); *Size=4; }
	else if (!stricmp(arg->str, "edi")) { *Value =  (ctx->Edi); *Size=4; }
	else if (!stricmp(arg->str, "esp")) { *Value =  (ctx->Esp); *Size=4; }
	else if (!stricmp(arg->str, "ebp")) { *Value =  (ctx->Ebp); *Size=4; }
	else if (!stricmp(arg->str, "eip")) { *Value =  (ctx->Eip); *Size=4; }
	else if (!stricmp(arg->str, "es"))  { *Value =  (ctx->SegEs); *Size=2; }
	else if (!stricmp(arg->str, "ds"))  { *Value =  (ctx->SegDs); *Size=2; }
	else if (!stricmp(arg->str, "ss"))  { *Value =  (ctx->SegSs); *Size=2; }
	else if (!stricmp(arg->str, "cs"))  { *Value =  (ctx->SegCs); *Size=2; }
	else if (!stricmp(arg->str, "fs"))  { *Value =  (ctx->SegFs); *Size=2; }
	else if (!stricmp(arg->str, "gs"))  { *Value =  (ctx->SegGs); *Size=2; }
	else if (!stricmp(arg->str, "efl")) { *Value =  (ctx->EFlags); *Size=4; }

	else if (!stricmp(arg->str, "ax"))  { *Value =  (ctx->Eax & 0xFFFF); *Size=2; }
	else if (!stricmp(arg->str, "cx"))  { *Value =  (ctx->Ecx & 0xFFFF); *Size=2; }
	else if (!stricmp(arg->str, "dx"))  { *Value =  (ctx->Edx & 0xFFFF); *Size=2; }
	else if (!stricmp(arg->str, "bx"))  { *Value =  (ctx->Ebx & 0xFFFF); *Size=2; }
	else if (!stricmp(arg->str, "si"))  { *Value =  (ctx->Esi & 0xFFFF); *Size=2; }
	else if (!stricmp(arg->str, "di"))  { *Value =  (ctx->Edi & 0xFFFF); *Size=2; }
	else if (!stricmp(arg->str, "sp"))  { *Value =  (ctx->Esp & 0xFFFF); *Size=2; }
	else if (!stricmp(arg->str, "bp"))  { *Value =  (ctx->Ebp & 0xFFFF); *Size=2; }
	else if (!stricmp(arg->str, "ip"))  { *Value =  (ctx->Eip & 0xFFFF); *Size=2; }
	else if (!stricmp(arg->str, "fl"))  { *Value =  (ctx->EFlags & 0xFFFF); *Size=2; }

	else if (!stricmp(arg->str, "al"))  { *Value =  (ctx->Eax & 0xFF); *Size=1; }
	else if (!stricmp(arg->str, "ah"))  { *Value =  (ctx->Eax & 0xFF00) >> 8; *Size=1; }
	else if (!stricmp(arg->str, "cl"))  { *Value =  (ctx->Ecx & 0xFF); *Size=1; }
	else if (!stricmp(arg->str, "ch"))  { *Value =  (ctx->Ecx & 0xFF00) >> 8; *Size=1; }
	else if (!stricmp(arg->str, "dl"))  { *Value =  (ctx->Edx & 0xFF); *Size=1; }
	else if (!stricmp(arg->str, "dh"))  { *Value =  (ctx->Edx & 0xFF00) >> 8; *Size=1; }
	else if (!stricmp(arg->str, "bl"))  { *Value =  (ctx->Ebx & 0xFF); *Size=1; }
	else if (!stricmp(arg->str, "bh"))  { *Value =  (ctx->Ebx & 0xFF00) >> 8; *Size=1; }

	else return false;

	return true;
}

ULONG CdbgLookupSymbolArgument (ARG *arg)
{
	ULONG Address;

	switch (arg->type)
	{
	case AT_DWORD:

		Address = arg->dw;
		break;

	case AT_STRING:
		
		{
			IMAGEHLP_SYMBOL Symbol = {0};
			Symbol.SizeOfStruct = sizeof(Symbol);

			SymGetSymFromName(dbg->hProcess, arg->str, &Symbol);

			if (!(Address = Symbol.Address))
			{
				CONTEXT ctx;
				ULONG t;
				ULONG size;

				ReadProcessMemory (dbg->hProcess, (void*)dbg->StoppedContext, &ctx, sizeof(ctx), &t);

				strlwr(arg->str);

				if (CdbgLookupRegister (arg, &ctx, &t, &size))
					return t;

				printf("Symbol %s not found\n", arg->str);
				return NULL;
			}
		}

		break;
	}

	return Address;
}

CMDHANDLER (bp)
{
	ARG *arg = GetArg(1);

	ASSERT_ATTACHED();

	ULONG Address = CdbgLookupSymbolArgument (arg);
	if (!Address)
	{
		FreeArg (arg);
		return;
	}

	if (Address & 0x80000000)
	{
		printf("Address (%08x) should be smaller than 80000000\n", Address);
		FreeArg (arg);
		return;
	}

	BOOLEAN OneShot = FALSE;
	if (argc == 2)
	{
		arg = GetArg(2);
		if (arg->type == AT_DWORD)
		{
			printf("Second argument (if supplied) should be a boolean\n");
		}
		OneShot = !!arg->dw;
	}

	INT i = CdbgSetSoftwareBreakpoint (dbg, Address, OneShot);

	if (i == -1)
	{
		printf("Breakpoint set failed: %s\n", cdbg_last_err);
		FreeArg (arg);
		return;
	}

	printf("Breakpoint %d defined at %08x. Type: %s\n", i, Address, OneShot ? "One-Shot" : "Permanent");
}

CMDHANDLER(c)
{
	ASSERT_ATTACHED();

/*	if (dbg->StoppedSystem)
	{
		ResumeThread (dbg->hThreads[0]);
		dbg->StoppedSystem = 0;
		printf("Continued.\n");
	}
	else
*/

	{
		if(!CdbgContinue (dbg))
			printf("Continue failed: %s\n", cdbg_last_err);
		else
			printf("Continued.\n");
	}
}



CMDHANDLER (help)
{
	do_ver (0,0);

	printf(
		"General principles\n"
		" There are two types of arguments of the commands:\n"
		"  ULONG   This type of argument is a integer double-word. It can be specified in decimal or hexadecimal notations,"
		" for example: the value of 119 can be specified as 119 (decimal) or 0x77 (hexadecimal)\n"
		"  STRING  This type of argument is a string. For example, 'calc.exe'.\n"
		"\n"
		"Available commands:\n"
		"\n"
		);

	for (int i=0; CommandTable[i].handler; i++)
	{
		printf("%10s  %d  %s\n", CommandTable[i].name, CommandTable[i].args, CommandTable[i].help);
	}

	printf("\nThe number after the command is the minimal number of arguments of this command.\n");
}


CMDHANDLER(hw)
{
	ARG *arg = GetArg(1);

	ASSERT_ATTACHED();

	ULONG Address = CdbgLookupSymbolArgument (arg);
	FreeArg (arg);

	if (Address == 0)
	{
		return;
	}

	if (Address & 0x80000000)
	{
		printf("Address (%08x) should be smaller than 80000000\n", Address);
		return;
	}

	BOOLEAN OneShot = FALSE;
	if (argc == 2)
	{
		arg = GetArg(2);
		if (arg->type == AT_DWORD)
		{
			printf("Second argument (if supplied) should be a boolean\n");
		}
		OneShot = !!arg->dw;
		FreeArg (arg);
	}

	OneShot = 1;

	CdbgSetHardwareBreakpoint(
		dbg,
		Address,
		OneShot,
		0, //UCHAR Type,
		1 //UCHAR Length
		);


	printf("HW Breakpoint defined at %08x. Type: %s\n", Address, OneShot ? "One-Shot" : "Permanent");
}

CMDHANDLER (run)
{
	if (dbg != NULL)
	{
		printf("Please detach from the process being debugged now.\n");
		return;
	}
	if (argc == 1)
	{
		printf("Please specify file name to run\n");
		return;
	}

	//DEBUG
	cmdargs = "D:\\fasm\\crackme_vm.exe";
	//

	printf("Running %s ...\n", cmdargs);

	PROCESS_INFORMATION pi = {0};
	STARTUPINFO si = {sizeof(si)};

	if(!CreateProcess (0, cmdargs, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, 1023, 0);
		printf("Cannot create process: %s\n", cdbg_last_err);
		return;
	}

	dbg = CdbgAttach (pi.dwProcessId);

	CloseHandle (pi.hProcess);

	ULONG t, entry;
	WORD lfanew;
	ReadProcessMemory (dbg->hProcess, (LPCVOID)(dbg->ModuleBase + FIELD_OFFSET(IMAGE_DOS_HEADER,e_lfanew)), &lfanew, 2, &t);
	ReadProcessMemory (dbg->hProcess, (LPCVOID)(dbg->ModuleBase + lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS,OptionalHeader.AddressOfEntryPoint)), &entry, 4, &t);

	entry += dbg->ModuleBase;
	dbg->EntryPoint = entry;

	CdbgSetSoftwareBreakpoint (dbg, entry, TRUE);

	printf("Program will break on entry point of main module after you resume it.\n");
	
	ResumeThread (pi.hThread);
	CloseHandle (pi.hThread);
}

CMDHANDLER (kill)
{
	ASSERT_ATTACHED();

	HANDLE hProcess = OpenProcess (PROCESS_TERMINATE, 0, dbg->dwProcessId);

	CdbgDetach (dbg);
	dbg = NULL;

	TerminateProcess (hProcess, 0);
	CloseHandle (hProcess);

	printf("Program terminated, debugger detached\n");
}

extern "C" {
#include "Disasm.h"
}

BOOL g_ShowDisplacement = FALSE;

CMDHANDLER(u)
{
	ASSERT_ATTACHED ();

	if (argc > 0)
	{
		ARG *arg = GetArg(1);

		ULONG _sym = CdbgLookupSymbolArgument (arg);
		if (_sym == NULL)
		{
			FreeArg (arg);
			return;
		}

		LastEip = _sym;
		FreeArg (arg);
	}

	const UCHAR nBytes = 50;
	UCHAR xBytes[nBytes];
	ULONG t;

	if(!ReadProcessMemory (dbg->hProcess, (LPVOID)LastEip, xBytes,
		nBytes, &t))
	{
		FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, 1023, 0);
		printf("Can't read process memory at %08x: %s\n",
			LastEip, cdbg_last_err);
		return;
	}

	CdbgCorrectPatchedMemory (dbg, LastEip, nBytes, xBytes);

	TInstruction Inst;
	TDisCommand Cmd;
	TMnemonicOptions Opts;

	PUCHAR cPtr = xBytes;
	ULONG Len = 0;

	while (1)
	{
		memset (&Inst, 0, sizeof(Inst));
		memset (&Cmd, 0, sizeof(Cmd));
		memset (&Opts, 0, sizeof(Opts));

		Len = InstrDecode (cPtr, &Inst, FALSE);
		InstrDasm (&Inst, &Cmd, FALSE);


		if (cPtr+Len > &xBytes[nBytes])
			break;

		Opts.AddHexDump = 1;
		Opts.AlternativeAddres = LastEip + (ULONG)cPtr - (ULONG)xBytes;
		Opts.AddAddresPart = 1;
		Opts.MnemonicAlign = 32;
		Opts.RealtiveOffsets = 0;
		Opts.LookupSymbols = 1;
		Opts.hProcess = dbg->hProcess;
		Opts.ShowDisplacement = g_ShowDisplacement;

		if (Opts.AlternativeAddres == 0x0040261A)
		{
			__try
			{
				__asm int 3;
			}
			__except(1)
			{
			}
		}
		char Mnemonic[512] = {0};

		MakeMnemonic (Mnemonic, &Cmd, &Opts);

		char buffer[256] = {0};
		ULONG Disp = 1;

		IMAGEHLP_SYMBOL *Symbol = (IMAGEHLP_SYMBOL*)buffer;
		Symbol->SizeOfStruct = sizeof(buffer);
		Symbol->MaxNameLength = sizeof(buffer) - sizeof(IMAGEHLP_SYMBOL);
		if(SymGetSymFromAddr (dbg->hProcess, Opts.AlternativeAddres, &Disp, Symbol))
		{
			if (Disp == 0)
				printf("\n%s:\n", Symbol->Name);
			else if (cPtr == xBytes)
				printf("\n%s + 0x%x:\n", Symbol->Name, Disp);
		}

		printf("%s\n", Mnemonic);

		if (strstr(Mnemonic, "REG_NONE"))
		{
			__try
			{
				printf("DISASM ERROR: Command decoding failed [REG_NONE found in decode]\n");
				break;
			}
			__except(1)
			{
			}
		}

		cPtr += Len;
	}
	
	LastEip += (ULONG)cPtr - (ULONG)xBytes;
}

CMDHANDLER(showdisp)
{
	if (argc == 0)
	{
		printf("g_ShowDisplacement = %d\n", g_ShowDisplacement);
		return;
	}

	ARG* arg = GetArg(1);
	if (arg->type == AT_STRING)
	{
		printf("String cannot be a first argument to showdisp\n");
		FreeArg (arg);
		return;
	}

	g_ShowDisplacement = !!(arg->dw);
	printf("g_ShowDisplacement set to %d\n", g_ShowDisplacement);
}

CMDHANDLER(s)
{
	ASSERT_ATTACHED();

	if (dbg->Stopped == 0)
	{
		printf("Debuggee is running.\n");
		return;
	}

	ULONG t;
	CONTEXT ctx;
	if(!ReadProcessMemory (dbg->hProcess, (PVOID)dbg->StoppedContext, &ctx, sizeof(CONTEXT), &t))
	{
		FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, 1023, 0);
		printf("Can't read process memory at %08x: %s\n",
			dbg->StoppedContext, cdbg_last_err);
		return;
	}
	ctx.EFlags |= EFLAGS_TF;
	if(!WriteProcessMemory (dbg->hProcess, (PVOID)dbg->StoppedContext, &ctx, sizeof(CONTEXT), &t))
	{
		FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, 1023, 0);
		printf("Can't write process memory at %08x: %s\n",
			dbg->StoppedContext, cdbg_last_err);
		return;
	}

	dbg->SingleStepNext = 1;

	DO_COMMAND_NOARG (c);
}

CMDHANDLER(t)
{
	ASSERT_ATTACHED();

	if (dbg->Stopped == 0)
	{
		printf("Debuggee is running.\n");
		return;
	}

	ULONG t;
	UCHAR bytes[10];

	if(!ReadProcessMemory (dbg->hProcess, (PVOID)dbg->StoppedEip, bytes, sizeof(bytes), &t))
	{
		FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, 1023, 0);
		printf("Can't read process memory at %08x: %s\n",
			dbg->StoppedContext, cdbg_last_err);
		return;
	}

	TInstruction inst = {0};
	TDisCommand cmd = {0};
	InstrDecode (bytes, &inst, FALSE);
	InstrDasm (&inst, &cmd, FALSE);

	if (cmd.CmdOrdinal == 0x9A) // CALL
	{
		CdbgSetSoftwareBreakpoint (dbg, dbg->StoppedEip + inst.InstrLen, TRUE);
		DO_COMMAND_NOARG (c);
	}
	else
	{
		DO_COMMAND_NOARG (s);
	}
}

CMDHANDLER(r)
{
	ASSERT_ATTACHED();
	if (dbg->Stopped == 0)
	{
		printf("Debuggee is running.\n");
		return;
	}

	CONTEXT ctx;
	ULONG t;

	if(!ReadProcessMemory (dbg->hProcess,(void*) dbg->StoppedContext, &ctx, sizeof(CONTEXT), &t))
	{
		FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, 1023, 0);
		printf("Cannot read process memory: %s\n", cdbg_last_err);
		return;
	}

	if (argc > 0)
	{
		for (int i=1; i<=argc; i++)
		{
			ARG *arg = GetArg(i);
			if (arg->type != AT_STRING)
			{
				printf("Register name required in the %d argument\n", i);
				FreeArg(arg);
				return;
			}

			strlwr(arg->str);

			ULONG size;
			if (CdbgLookupRegister (arg, &ctx, &t, &size))
			{
				strupr(arg->str);
				if (size == 1)
				{
					printf("%s  = %02x         ", arg->str, t);
				}
				else if (size == 2)
				{
					printf("%s  = %04x       ", arg->str, t);
				}
				else
				{
					printf("%s = %08x   ", arg->str, t);
				}
			}
			else
			{
				printf("Unknown register %s\n", arg->str);
			}

			if ((i % 4) == 0)
				printf("\n");

			FreeArg(arg);
		}
	}
	else
	{
		printf("EAX = %08x   ECX = %08x   EDX = %08x   EBX = %08x\n"
			   "ESI = %08x   EDI = %08x   EBP = %08x   ESP = %08x\n"
			   "EIP = %08x   ES  = %04x       DS  = %04x       SS  = %04x\n"
			   "FS  = %04x       GS  = %04x       CS = %04x        EFL = %08x\n"
			  ,
			ctx.Eax, ctx.Ecx, ctx.Edx, ctx.Ebx,
			ctx.Esi, ctx.Edi, ctx.Ebp, ctx.Esp, 
			ctx.Eip, ctx.SegEs, ctx.SegDs, ctx.SegSs,
			ctx.SegFs, ctx.SegGs, ctx.SegCs, ctx.EFlags
			);
	}
}

//#define DM_NUMBER_ELEMENTS 64
#define DM_SIZE 64

CMDHANDLER(dm)
{
	ASSERT_ATTACHED();

	if (argc < 1)
	{
		printf("dm requires 1 or 2 arguments: elem size(1,2 or 4) and (optionally) [start address]\n");
		return;
	}

	ARG* argsize = GetArg(1);
	if (argsize->type == AT_STRING)
	{
		printf("DWORD required in the first argument\n");
		FreeArg (argsize);
		return;
	}
	ULONG size = argsize->dw;
	FreeArg (argsize);

	if (size != 1 && size!=2 && size!=4)
	{
		printf("First argument should be 1, 2 or 4\n");
		return;
	}
	
	ULONG Address;

	if (argc > 1)
	{
		ARG* argaddr = GetArg(2);
		Address = CdbgLookupSymbolArgument (argaddr);
		FreeArg (argaddr);
	}
	else
	{
		Address = LastEip;
	}

	Address &= (0 - size);


	UCHAR buffer[DM_SIZE] = {0};
	ULONG t = 0;
	
	ULONG sz = DM_SIZE;
	do
	{
		ReadProcessMemory(dbg->hProcess, (void*)Address, buffer, sz, &t);

		sz --;

	}
	while (t == 0 && sz>0);
		
	if (sz == 0)
	{
		FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, 1023, 0);
		printf("Can't read process memory at %08x: %s [Read=%d]\n", Address, cdbg_last_err, t);
		return;
	}

	ULONG AndArgs[5] = { 0, 0xFF, 0xFFFF, 0xFFFFFF, 0xFFFFFFFF };

	char formatstring[6];
	sprintf (formatstring, "%%%ds ", size*2);

	for (ULONG ptr=Address&0xFFFFFFF0; ptr<Address; ptr += size)
	{
		if (!(ptr % 16))
		{
			printf("\n%08x: ", ptr);
		}

		printf(formatstring, "");
	}

	if ((Address & 0xF) >= 8)
		printf (" ");
	
	sprintf (formatstring, "%%0%dx ", size*2);

	char *unk[5] = { 0, "??", "????", 0, "????????" };

	for (ptr=Address; ptr<=(Address + DM_SIZE); ptr += size)
	{
		
		if (!(ptr % 16))
		{
			if (size == 1 && ptr!=Address)
			{
				ULONG tptr = ptr-16;

				printf(" ");

				for (; tptr<Address; tptr++)
					printf(" ");

				for (; tptr<ptr; tptr++)
				{
					if (tptr-Address >= t)
						printf("?");
					else
						printf("%c", isprint(buffer[tptr-Address]) ? buffer[tptr-Address] : '.');

					if ((tptr & 0xF) == 7)
						printf(" ");
				}
			}

			if (ptr != (Address + DM_SIZE))
			{
				printf("\n%08x: ", ptr);
			}
		}

		if (ptr!=(Address + DM_SIZE))
		{
			if (ptr-Address >= t)
			{
				printf("%s ", unk[size]);
			}
			else
			{
				printf(formatstring, (*(ULONG*)&buffer[ptr-Address]) & AndArgs[size]);
			}
		}

		if ((ptr & 0xF) == 7)
			printf(" ");
	}
	ptr--;
	if (ptr % 16)
	{
		if (size == 1)
		{
			ULONG tptr = ptr & 0xFFFFFFF0;

			sprintf (formatstring, "%%%ds ", size*2);
			for (ULONG i=0; i < 16-(ptr & 0xF); i++)
			{
				printf(formatstring, "");
			}

			printf(" ");

			for (; tptr<ptr; tptr++)
			{
				printf("%c", isprint(buffer[tptr-Address]) ? buffer[tptr-Address] : '.');
			}
		}
	}

	LastEip = ptr;

	printf("\n");
}

CMDHANDLER(e)
{
	ASSERT_ATTACHED();

	if (argc < 1)
	{
		printf("Not enough arguments (need 1 argument)\n");
		return;
	}

	ARG *arg = GetArg(1);

	ULONG Address;

	if (arg->type == AT_STRING)
	{
		Address = CdbgLookupSymbolArgument (arg);

		printf("%s = 0x%08x = %d\n", arg->str, Address, Address);
	}
	else
	{
		Address = arg->dw;
	}

	char buffer[256] = {0};
	ULONG Disp = 1;

	IMAGEHLP_SYMBOL *Symbol = (IMAGEHLP_SYMBOL*)buffer;
	Symbol->SizeOfStruct = sizeof(buffer);
	Symbol->MaxNameLength = sizeof(buffer) - sizeof(IMAGEHLP_SYMBOL);

	printf("%d = 0x%08x", Address, Address);
	if(SymGetSymFromAddr (dbg->hProcess, Address, &Disp, Symbol))
	{
		printf(" = %s",  Symbol->Name);
		if (Disp != 0)
			printf(" + 0x%x", Disp);
	}
	printf("\n");

	FreeArg(arg);
}
