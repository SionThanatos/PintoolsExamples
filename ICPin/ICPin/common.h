#pragma once

// Standard C
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
// C++
#include <unordered_map>
#include <map>
#include <unordered_set>
#include <set>
#include <time.h>
#include <locale>
#include <algorithm>
#include<vector>
#include<string>
// Pin
#include "pin.H"



using namespace std;

// Memory access types
#define READ 0
#define WRITE 1
#define OTHER 2

typedef unsigned long DWORD;

namespace WIN 
{


#pragma once
#define _WINDOWS_H_PATH_ C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/um

#include <windows.h>


}

#define PAGE_ANYEXE (PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY)

#ifdef _WIN64
	#define REG_PC REG_RIP
	#define REG_SP REG_RSP
#else:
	#define REG_PC REG_EIP
	#define REG_SP REG_ESP
#endif


