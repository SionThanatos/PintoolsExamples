//查看函数参数值 RTN_InsertCall

#include "pin.H"
#include <iostream>
#include <fstream>
using std::cerr;
using std::endl;
using std::hex;
using std::ios;
using std::string;

/* ===================================================================== */
/* Names of malloc and free */
/* ===================================================================== */
#if defined(TARGET_MAC)
#define MALLOC "_malloc"
#define FREE "_free"
#else
#define MALLOC "malloc"
#define FREE "free"
#endif

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

std::ofstream TraceFile;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "malloctrace.out", "specify trace file name");

/* ===================================================================== */

/// <summary>
/// 返回参数
/// </summary>
/// <param name="name"></param>
/// <param name="size"></param>
VOID Arg1Before(CHAR* name, ADDRINT size) 
{ 
    TraceFile << name << "(" << size << ")" << endl; 
}

/// <summary>
/// 返回 返回值
/// </summary>
/// <param name="ret"></param>
VOID MallocAfter(ADDRINT ret) 
{ 
    TraceFile << "  returns " << ret << endl; 
}

/* ===================================================================== */
/* Instrumentation routines                                              */
/* ===================================================================== */

/// <summary>
/// 对malloc和free进行插桩
/// 打印其参数以及malloc返回值
/// </summary>
/// <param name="img"></param>
/// <param name="v"></param>
VOID Image(IMG img, VOID* v)
{
    // Instrument the malloc() and free() functions.  
    // Print the input argument of each malloc() or free(), and the return value of malloc().

    //  Find the malloc() function. 查找malloc函数
    RTN mallocRtn = RTN_FindByName(img, MALLOC);
    if (RTN_Valid(mallocRtn))
    {
        RTN_Open(mallocRtn);

        // Instrument malloc() to print the input argument value and the return value.
        //对查找到的malloc函数进行插桩并打印参数
        RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before, IARG_ADDRINT, MALLOC, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,IARG_END);
        
        //打印返回值
        RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)MallocAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

        RTN_Close(mallocRtn);
    }

    // Find the free() function.
    //查找free函数
    RTN freeRtn = RTN_FindByName(img, FREE);
    if (RTN_Valid(freeRtn))
    {
        RTN_Open(freeRtn);
        // Instrument free() to print the input argument value.
        //插桩打印参数
        RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before, IARG_ADDRINT, FREE, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,IARG_END);
        RTN_Close(freeRtn);
    }
}



VOID Fini(INT32 code, VOID* v) 
{ 
    TraceFile.close(); 
}

/// <summary>
/// Print Help Message
/// </summary>
/// <returns></returns>
INT32 Usage()
{
    cerr << "This tool produces a trace of calls to malloc." << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/// <summary>
/// 主函数
/// </summary>
/// <param name="argc"></param>
/// <param name="argv"></param>
/// <returns></returns>
int main(int argc, char* argv[])
{
    // Initialize pin & symbol manager
    PIN_InitSymbols();
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    // Write to a file since cout and cerr maybe closed by the application
    TraceFile.open(KnobOutputFile.Value().c_str());
    TraceFile << hex;
    TraceFile.setf(ios::showbase);

    // Register Image to be called to instrument functions.
    //注册image函数
    IMG_AddInstrumentFunction(Image, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}


