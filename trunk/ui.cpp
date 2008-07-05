#include "cdbg.h"

//
// Get command argument from argv[] array, recognize its type and fill ARG structure
//

ARG* __getarg (int argc, char** argv, int n)
{
	if (n > argc)
	{
		printf("* Not enough arguments for command [expected arg %d, found %d args total]\n", n, argc);
		ExitThread(0);
		return NULL;
	}

	//
	// Recognize type
	//

	ARG *arg = (ARG*) halloc (sizeof(ARG));
	
	if (isdigit(argv[n][0]))
	{
		// dword

		arg->type = AT_DWORD;

		if (argv[n][0] == '0' && argv[n][1] == 'x')
		{
			sscanf (&argv[n][2], "%x", &arg->dw);
		}
		else if(argv[n][strlen(argv[n])-1] == 'h')
		{
			argv[n][strlen(argv[n])-1] = 0;
			sscanf (argv[n], "%x", &arg->dw);
		}
		else
		{
			arg->dw = atoi (argv[n]);
		}

		return arg;
	}

	// string

	arg->type = AT_STRING;

	char *pstr = argv[n];

	if (*pstr == '"')
	{
		pstr++;
		if (pstr[strlen(pstr)-1] == '"')
		{
			pstr[strlen(pstr)-1] = 0;
		}
		else
		{
			printf("* Argument not valid for string: arg=%d, [%s]\n", n,argv[0]);
			printf("* The error was: \" quote mismatch\n");
			hfree (arg);
			ExitThread(0);
			return NULL;
		}
	}
	else
	{
		if (pstr[strlen(pstr)-1] == '"')
		{
			printf("* Argument not valid for string: arg=%d, [%s]\n", n,argv[0]);
			printf("* The error was: \" quote mismatch\n");
			hfree (arg);
			ExitThread(0);
			return NULL;
		}
	}

	if (*pstr == '\'')
	{
		pstr++;
		if (pstr[strlen(pstr)-1] == '\'')
		{
			pstr[strlen(pstr)-1] = 0;
		}
		else
		{
			printf("* Argument not valid for string: arg=%d, [%s]\n", n,argv[0]);
			printf("* The error was: ' quote mismatch\n");
			hfree (arg);
			ExitThread(0);
			return NULL;
		}
	}
	else
	{
		if (pstr[strlen(pstr)-1] == '\'')
		{
			printf("* Argument not valid for string: arg=%d, [%s]\n", n,argv[0]);
			printf("* The error was: ' quote mismatch\n");
			hfree (arg);
			ExitThread(0);
			return NULL;
		}
	}


	strncpy (arg->str, pstr, sizeof(arg->str)-1);
	return arg;
}


//
// UI
//

HANDLE hCmdThread = NULL;

CMD_THREAD_ARGS tharg;

BOOL WINAPI ConsoleHandler (ULONG Event)
{
	switch (Event)
	{
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
		if (hCmdThread)
		{
			TerminateThread (hCmdThread, 0);

			char *cmd = "<unk>";

			if (tharg.argv && tharg.argv[0])
				cmd = tharg.argv[0];

			printf("! Ctrl-C: Forced command '%s' termination\n", cmd);
		}
		return TRUE;	// don't execute next handler

	case CTRL_CLOSE_EVENT:
		DO_COMMAND_NOARG (exit);
		break;
	}

	return FALSE;
}

extern "C" BOOL WINAPI IsDebuggerPresent();

ULONG WINAPI CommandThread (LPVOID cmd)
{
	CMD_THREAD_ARGS *p = (CMD_THREAD_ARGS*) cmd;

	//
	// Found & call appropriate command handler
	//

	for (int i=0; CommandTable[i].handler; i++)
	{
		if (!stricmp(p->argv[0], CommandTable[i].name))
		{
#if EXC_HANDLING
			PEXCEPTION_POINTERS ep;

			__try
			{
#endif
				CommandTable[i].handler (p->argc, p->argv);
#if EXC_HANDLING
			}
			__except ( (ep=GetExceptionInformation()), EXCEPTION_EXECUTE_HANDLER )
			{
				printf("*** STOP: Exception %08x occurred in the debugger internal routine at address %08x\n",
					ep->ExceptionRecord->ExceptionCode,
					ep->ExceptionRecord->ExceptionAddress);

				DO_COMMAND_NOARG (exit);
				
				if (IsDebuggerPresent())
					__asm int 3;

				ExitProcess(0);
			}
#endif
			return 0;
		}
	}

	printf("Command not found: '%s'. Please check spelling\n", p->argv[0]);

	return 0 ;
}

char *cmdptr;
char *cmdargs;

HWND hWnd;

int main()
{
	printf("//==============================     \n");
	printf("// CDBG console debugger " CDBG_VER" \n");
	printf("//   [c] Great, 2008                 \n");
	printf("//==============================     \n");
	printf("\n");
	printf("~ Initializing\n");

	hinit();
	SetConsoleCtrlHandler (ConsoleHandler,TRUE);
	SetConsoleTitle ("CDBG");
	hWnd = GetConsoleWindow();

	printf("+ Ready\n");
	
	char command[1024] = "";
	char prevcmd[1024] = "";

	char *args[200] = {0};

	for(;;)
	{
		lstrcpy (cdbg_last_err, "Success");

		printf("\ncdbg> ");

		fgets (command, sizeof(command)-1, stdin);

		//
		// Delete first spaces.
		//

		for (cmdptr = command; isspace(*cmdptr); cmdptr++);

		//
		// Delete last spaces.
		//

		ULONG l = strlen(cmdptr);
		while (isspace(cmdptr[l-1]))
		{
			cmdptr[l-1] = 0;
			l--;
		}

		if (strlen(cmdptr)==0)
		{
			strcpy(command, prevcmd);
			cmdptr = command;
		}
		else
		{
			strcpy (prevcmd, cmdptr);
		}

		//
		// Parse command
		//

		int arg=0;
		char *prev = cmdptr;

		cmdargs = 0;

		for (char *sp=cmdptr; ; sp++)
		{
			if (*sp == 0)
			{
				args[arg++] = prev;
				break;
			}

			if (isspace(*sp))
			{
				*(sp++) = 0;
				args[arg++] = prev;
				
				while (isspace(*sp))
					sp++;

				if (cmdargs == NULL)
					cmdargs = sp;

				prev = sp;
			}
		}

		if (!stricmp(args[0], "exit"))
			break;

		tharg.argc = arg-1;
		tharg.argv = args;

		hCmdThread = CreateThread (NULL, NULL, CommandThread, &tharg, 0, 0);
		WaitForSingleObject (hCmdThread, INFINITE);
		hCmdThread = 0;
	}
	
	DO_COMMAND_NOARG (exit);
	printf("~ Bye, bye\n");

	return 0;
}
