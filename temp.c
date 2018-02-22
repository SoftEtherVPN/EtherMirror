// Temporary source file
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

void Temp_TestFunction(char *tmp)
{
	Print("Test: %s\n", tmp);
}

// Read the ini file with the specified filename
LIST *ReadIniFileW(wchar_t *filename)
{
	BUF *b = ReadDumpW(filename);
	LIST *ret = ReadIni(b);

	FreeBuf(b);
	return ret;
}
LIST *ReadIniFile(char *filename)
{
	wchar_t tmp[MAX_PATH];

	if (filename == NULL)
	{
		return NULL;
	}

	StrToUni(tmp, sizeof(tmp), filename);

	return ReadIniFileW(tmp);
}

// Get the string from the read ini file
bool IniGetStr(LIST *o, char *key, char *str, UINT str_size)
{
	char *s;
	bool ret = false;
	if (o == NULL || key == NULL || str == NULL)
	{
		return false;
	}
	str[0] = 0;

	s = IniStrValue(o, key);

	if (IsEmptyStr(s) == false)
	{
		StrCpy(str, str_size, s);

		ret = true;
	}

	return ret;
}



