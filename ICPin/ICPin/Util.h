#pragma once
#include"common.h"

using namespace std;

namespace Util 
{

	// Vars
	extern FILE* log;
	extern time_t tStart;
	extern string imageName;
	extern ADDRINT base, start, end, entry;
	// Funcs
	UINT64 READ_SIZE(ADDRINT, size_t);
	VOID loginit(string);
	VOID logend();
	VOID Log(BOOL, const char* fmt...);
	VOID startTimer();
	double queryElapsedTime(BOOL);
	string StrtoLower(string);
	VOID printContext(const CONTEXT*, UINT32);
}