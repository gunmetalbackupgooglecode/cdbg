#pragma once

#include <ntdll.h>
#include <stdio.h>
#include <imagehlp.h>

//
// Common macro
//

#define EXC_HANDLING 0

#define STATIC_ASSERT(x)  extern char __dummy[(x)?1:-1];

#define CDBG_VER "0.1-devel"

#define EFLAGS_TF  (1<<8)

#define MAX_BPS 128

#define BTS_0 0x00
#define BTS_1 0x01
#define BTS_2 0x03
#define BTS_3 0x07
#define BTS_4 0x0F
#define BTS_5 0x1F
#define BTS_6 0x3F
#define BTS_7 0x7F
#define BIS_8 0xFF

#define EXTRACT_BITS(VALUE,STBIT,NBITS) (((VALUE)>>STBIT) & (BTS_##NBITS))


//
// Breakpoints
//

typedef struct BREAKPOINT
{
	union
	{
		ULONG Address;
		struct
		{
			ULONG AddressLow : 31;
			ULONG Present : 1;
		};
	};
	BOOLEAN Hardware;
	BOOLEAN OneShot;
	BOOLEAN Disabled;
	union
	{
		UCHAR OldByte;	// if Hardware == 0 && OneShot == 1
		struct
		{
			UCHAR Type;		// if Hardware == 1
			UCHAR BpNum;
		};
		ULONG AddressOfBuffer; // if Hardware == 0 && OneShot == 0
	};
} *PBREAKPOINT;

typedef union REG_DR7
{
	struct
	{
		ULONG Local0 : 1;
		ULONG Global0 : 1;
		ULONG Local1 : 1;
		ULONG Global1 : 1;
		ULONG Local2 : 1;
		ULONG Global2 : 1;
		ULONG Local3 : 1;
		ULONG Global3 : 1;
		ULONG LocalE : 1;
		ULONG GlobalE : 1;
		
		ULONG Reserved : 6;

		ULONG ReadWrite0 : 2;
		ULONG Len0 : 2;
		ULONG ReadWrite1 : 2;
		ULONG Len1: 2;
		ULONG ReadWrite2 : 2;
		ULONG Len2 : 2;
		ULONG ReadWrite3 : 2;
		ULONG Len3 : 2;
	};
	ULONG Raw;
} *PREG_DR7;

STATIC_ASSERT (sizeof(REG_DR7) == sizeof(ULONG));

typedef union REG_DR6
{
	struct
	{
		ULONG Break0 : 1;
		ULONG Break1 : 1;
		ULONG Break2 : 1;
		ULONG Break3 : 1;
		ULONG Reserved : 9;
		ULONG BD : 1;
		ULONG BS : 1;
		ULONG BT : 1;
		ULONG Reserved2 : 12;
	};
	ULONG Raw;
} *PREG_DR6;

//
// Thread states
//

#define THREAD_STATE_INITIALIZED        0
#define THREAD_STATE_READY              1
#define THREAD_STATE_RUNNING            2
#define THREAD_STATE_STANDBY            3
#define THREAD_STATE_TERMINATED         4
#define THREAD_STATE_WAIT               5
#define THREAD_STATE_TRANSITION         6
#define THREAD_STATE_UNKNOWN            7

//
// Debuggee instance
//

typedef struct DEBUGGEE
{
	BOOLEAN Stopped;
	BOOLEAN StoppedSystem;
	ULONG StoppedContext;
	BOOLEAN SingleStepNext;
	ULONG StoppedEip;

	HANDLE hProcess;
	ULONG nThreads;
	HANDLE *hThreads;
	ULONG dwProcessId;
	ULONG *dwThreadIds;
	char name[256];
	ULONG ModuleBase;
	ULONG EntryPoint;

	HANDLE hLpcServer;
	HANDLE hMessagePort;

	PVOID KiUserExceptionDispatcher;
	UCHAR KiUserExcDisp_Old[5];

	PVOID ZwTerminateProcess;
	UCHAR ZwTerminateProcess_Old[5];

	PVOID ZwTerminateThread;
	UCHAR ZwTerminateThread_Old[5];

	PVOID hooks;
	PVOID BreakPointBuffers;

	BREAKPOINT bps[MAX_BPS];

	PBREAKPOINT hws[4];

} *PDEBUGGEE;

#define SIZEOF_BP_BUFFER 32

#define LPC_BUFFER_SIZE 0x130

//
// CDBG API
//

extern ULONG LastEip;
extern char *cmdargs;
extern BOOL g_KillOnDetach;
extern BOOL g_ShowDisplacement;


VOID
CdbgCorrectPatchedMemory(
	PDEBUGGEE dbg,
	ULONG VirtualAddressStart,
	ULONG Size,
	PVOID Buffer
	);

PDEBUGGEE
CdbgAttach(
	ULONG dwProcessId
	);

VOID
CdbgDetach(
	PDEBUGGEE dbg
	);

BOOL
CdbgpLpcContinue(
	PDEBUGGEE dbg
	);

VOID
CdbgFastDetach(
	PDEBUGGEE dbg
	);

BOOL
CdbgLookupProcessName(
	PSYSTEM_PROCESSES_INFORMATION Buffer OPTIONAL,
	ULONG dwProcessId,
	char *ProcessNameBuffer,
	ULONG MaxLength
	);

BOOL
CdbgUserExceptionDispatcherHook(
	PDEBUGGEE dbg
	);

VOID
CdbgUserExceptionDispatcherUnhook(
	PDEBUGGEE dbg
	);

ULONG
WINAPI
CdbgLpcServer(
	LPVOID pdbg
	);

INT
CdbgSetSoftwareBreakpoint(
	PDEBUGGEE dbg,
	ULONG Address,
	BOOLEAN OneShot
	);

INT
CdbgSetHardwareBreakpoint(
	PDEBUGGEE dbg,
	ULONG Address,
	BOOLEAN OneShot,
	UCHAR Type,
	UCHAR Length
	);

BOOL
CdbgRemoveSoftwareBreakpoint(
	PDEBUGGEE dbg,
	ULONG Address,
	INT Number
	);

BOOL
CdbgDisableSoftwareBreakpoint(
	PDEBUGGEE dbg,
	ULONG Address,
	INT Number
	);

BOOL
CdbgEnableSoftwareBreakpoint(
	PDEBUGGEE dbg,
	ULONG Address,
	INT Number
	);

HANDLE
CdbgLookupThread(
	PDEBUGGEE dbg,
	ULONG UniqueThread
	);

BOOL
CdbgContinue(
	PDEBUGGEE dbg
	);

VOID
CdbgSuspendProcess(
	PDEBUGGEE dbg
	);

VOID
CdbgResumeProcess(
	PDEBUGGEE dbg
	);

enum LPCMSG_TYPE
{
	// Message types
	LMT_UNKNOWN,
	LMT_NEWTHREAD,		// 1 arg -  ThreadId
	LMT_EXITTHREAD,		// 2 args -  ThreadId, ExitStatus
	LMT_EXITPROCESS,	// 1 arg -  ExitStatus
	LMT_EXCEPTION,
	LMT_UNHANDLEDEXCEPTION
};

struct CDBG_LPC_MESSAGE
{
	LPCMSG_TYPE Type;
	union
	{
		struct
		{
			ULONG ThreadId;
			ULONG ExitStatus;
		};

		struct
		{
			EXCEPTION_RECORD ExceptionRecord;
			ULONG pCtx;
		};
	};
};


STATIC_ASSERT (sizeof(CDBG_LPC_MESSAGE) < 0x130);
			


extern HANDLE heap;
extern HWND hWnd;

#define hinit() heap = GetProcessHeap();
#define halloc(x) HeapAlloc(heap, HEAP_ZERO_MEMORY, x)
#define hrealloc(p,x) HeapReAlloc(heap, HEAP_ZERO_MEMORY, p, x)
#define hfree(x) HeapFree(heap,0,x)


PVOID GetSystemInformation (SYSTEM_INFORMATION_CLASS InfoClass);
HANDLE OpenThread (ULONG desiredAccess, BOOL inheritHandle, ULONG threadID);
HWND GetConsoleWindow(void);

#define CMDHANDLER(CMD) void do_##CMD(int argc, char** argv)

#define DO_COMMAND(CMD) do_##CMD(argc,argv);
#define DO_COMMAND_NOARG(CMD) do_##CMD(0,NULL);

struct CMD_THREAD_ARGS
{
	int argc;
	char **argv;
};

struct CMD_HANDLER_ENTRY
{
	void (*handler)(int,char**);
	int args;
	char *name;
	char *help;
};

extern CMD_HANDLER_ENTRY CommandTable[1024];

#define CMD_ENTRY(NAME,ARGC,HELP) { do_##NAME, ARGC, #NAME, HELP }
#define CMD_END {0,0,0}

#include "commands.h"

extern PDEBUGGEE dbg;

enum ARG_TYPE
{
	AT_DWORD,
	AT_STRING
};

struct ARG
{
	ARG_TYPE type;
	union
	{
		ULONG dw;
		char str[256];
	};
};

ARG* __getarg (int argc, char** argv, int n);

#define GetArg(x) __getarg(argc,argv,x)
#define FreeArg(p) hfree(p)

extern char cdbg_last_err[];

BOOLEAN
CdbgSpliceFunctionEx(
	IN  HANDLE	hProcess,
	IN	PVOID	OriginalAddress,
    IN	PVOID	HookFunction,
	OUT	PVOID	SplicingBuffer,
	IN	ULONG	MaxLength,
	OUT	PULONG	BytesWritten
	);
