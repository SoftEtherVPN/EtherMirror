#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <locale.h>
#include <time.h>
#include <errno.h>

#include <seclib.h>
#include "project.h"

static EM *em = NULL;

// Process starting function
void StartProcess()
{
	// Start the server
	Debug("StartProcess() Begin.\n");

	InitEth();

	em = NewEm();

	Debug("StartProcess() End.\n");
}

// Process termination function
void StopProcess()
{
	// Stop the server
	Debug("StopProcess() Begin.\n");

	if (em != NULL)
	{
		FreeEm(em);
		em = NULL;
	}

	FreeEth();

	Debug("StopProcess() End.\n");
}

// Service test
void service_test(UINT num, char **arg)
{
	Print("Starting...\n");
	StartProcess();

	Print("Service started.\n");
	Print("Press Enter key to stop the service.\n");

	GetLine(NULL, 0);

	Print("Stopping...\n");
	StopProcess();
	Print("Service stopped.\n");
}

// Test function definition list
void test(UINT num, char **arg)
{
	if (true)
	{
		Print("Test! %u\n", IsX64());

		Temp_TestFunction("Nekosan");
		return;
	}
}

typedef void (TEST_PROC)(UINT num, char **arg);

typedef struct TEST_LIST
{
	char *command_str;
	TEST_PROC *proc;
} TEST_LIST;

TEST_LIST test_list[] =
{
	{ "test", test },
	{ "ss", service_test },
};

// Test function
void TestMain(char *cmd)
{
	char tmp[MAX_SIZE];
	bool first = true;
	bool exit_now = false;

	Print("Test Program\n");

#ifdef	OS_WIN32
	MsSetEnableMinidump(false);
#endif	// OS_WIN32
	while (true)
	{
		Print("TEST>");
		if (first && StrLen(cmd) != 0 && g_memcheck == false)
		{
			first = false;
			StrCpy(tmp, sizeof(tmp), cmd);
			exit_now = true;
			Print("%s\n", cmd);
		}
		else
		{
			GetLine(tmp, sizeof(tmp));
		}
		Trim(tmp);
		if (StrLen(tmp) != 0)
		{
			UINT i, num;
			bool b = false;
			TOKEN_LIST *token = ParseCmdLine(tmp);
			char *cmd = token->Token[0];
			if (!StrCmpi(cmd, "exit") || !StrCmpi(cmd, "quit") || !StrCmpi(cmd, "q"))
			{
				FreeToken(token);
				break;
			}
			else
			{
				num = sizeof(test_list) / sizeof(TEST_LIST);
				for (i = 0;i < num;i++)
				{
					if (!StrCmpi(test_list[i].command_str, cmd))
					{
						char **arg = Malloc(sizeof(char *) * (token->NumTokens - 1));
						UINT j;
						for (j = 0;j < token->NumTokens - 1;j++)
						{
							arg[j] = CopyStr(token->Token[j + 1]);
						}
						test_list[i].proc(token->NumTokens - 1, arg);
						for (j = 0;j < token->NumTokens - 1;j++)
						{
							Free(arg[j]);
						}
						Free(arg);
						b = true;
						Print("\n");
						break;
					}
				}
				if (b == false)
				{
					Print("Invalid Command: %s\n\n", cmd);
				}
			}
			FreeToken(token);

			if (exit_now)
			{
				break;
			}
		}
	}
	Print("Exiting...\n\n");
}

// Entry point
int main(int argc, char *argv[])
{
	bool memchk = false;
	UINT i;
	char cmd[MAX_SIZE];
	char *s;
	bool is_service_mode = false;

	cmd[0] = 0;
	if (argc >= 2)
	{
		char *second_arg = argv[1];

		if (StrCmpi(second_arg, "start") == 0 || StrCmpi(second_arg, "stop") == 0 || StrCmpi(second_arg, "execsvc") == 0 || StrCmpi(second_arg, "help") == 0 ||
			(second_arg[0] == '/' && StrCmpi(second_arg, "/memcheck") != 0))
		{
			// service mode
			is_service_mode = true;
		}

		if (is_service_mode == false)
		{
			for (i = 1;i < (UINT)argc;i++)
			{
				s = argv[i];
				if (s[0] == '/')
				{
					if (!StrCmpi(s, "/memcheck"))
					{
						memchk = true;
					}
				}
				else
				{
					StrCpy(cmd, sizeof(cmd), &s[0]);
				}
			}
		}
	}

	if (is_service_mode == false)
	{
		// Test mode

		//MayaquaMinimalMode();

		SetHamMode();

		InitMayaqua(memchk, true, argc, argv);
		EnableProbe(false);
		InitCedar();
		SetHamMode();

		//TestMain(cmdline);
		service_test(0, NULL);

		FreeCedar();
		FreeMayaqua();
	}
	else
	{
		// Service mode
#ifdef OS_WIN32
		return MsService("ETHERMIRROR", StartProcess, StopProcess, 0, argv[1]);
#else // OS_WIN32
		return UnixService(argc, argv, "ethermirror", StartProcess, StopProcess);
#endif // OS_WIN32

	}

	return 0;
}

