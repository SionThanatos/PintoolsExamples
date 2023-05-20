//计算一个procedure 过程 被调用的次数，以及每个过程中执行的命令总数 routine插桩
// This tool counts the number of times a routine is executed and the number of instructions executed in a routine


/*
 routine instrumentation
通过“caching”插桩请求实现，会有额外的内存空间要求，属于一种“提前插桩”。
routine instrumentation 模式下，Pintool 在 image 首次加载时就对整个 routine 进行检查和插桩，
对 routine 中的每条指令都可以插桩，但是没有充分的信息可以将指令划分为 BBL。
插入位置可以是执行例程或指令的前后。
这种模式其实更大程度上属于 image instrumentation 的替代方法，使用的 API 为 RTN_AddInstrumentFunction。
需要注意的是，在 image 和 routine instrumentation 模式下，
插桩时并不确定 routine 是否会被执行，但是通过识别 routine 的开始指令，可以遍历出执行过的 routine 的指令。
*/

#include <fstream>
#include <iomanip>
#include <iostream>
#include <string.h>
#include "pin.H"
using std::cerr;
using std::dec;
using std::endl;
using std::hex;
using std::ofstream;
using std::setw;
using std::string;

ofstream outFile;

// Holds instruction count for a single procedure
//保存procedure的指令数
typedef struct RtnCount
{
    string _name;
    string _image;
    ADDRINT _address;
    RTN _rtn;
    UINT64 _rtnCount;
    UINT64 _icount;
    struct RtnCount* _next;
} RTN_COUNT;

// Linked list of instruction counts for each routine
//每个例程的指令链表
RTN_COUNT* RtnList = 0;

// This function is called before every instruction is executed
VOID docount(UINT64* counter) 
{ 
    (*counter)++; 
}

const char* StripPath(const char* path)
{
    const char* file = strrchr(path, '/');
    if (file)
        return file + 1;
    else
        return path;
}

// Pin calls this function every time a new rtn is executed
//新的例程时调用
VOID Routine(RTN rtn, VOID* v)
{
    // Allocate a counter for this routine
    //对该例程设置计数器
    RTN_COUNT* rc = new RTN_COUNT;

    // The RTN goes away when the image is unloaded, so save it now because we need it in the fini
    //image卸载时 RTN结构数据消失，所以在此处保存，后续fini时还要使用
    rc->_name     = RTN_Name(rtn);
    rc->_image    = StripPath(IMG_Name(SEC_Img(RTN_Sec(rtn))).c_str());
    rc->_address  = RTN_Address(rtn);
    rc->_icount   = 0;
    rc->_rtnCount = 0;

    // Add to list of routines
    //添加到例程链表
    rc->_next = RtnList;
    RtnList   = rc;

    RTN_Open(rtn);

    // Insert a call at the entry point of a routine to increment the call count
    //在例程入口插入一个call，增加call计数
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(rc->_rtnCount), IARG_END);

    // For each instruction of the routine
    //对于例程中的每条指令
    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
    {
        // Insert a call to docount to increment the instruction counter for this rtn
        //插入指令计数，增加例程中的指令数
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(rc->_icount), IARG_END);
    }

    RTN_Close(rtn);
}


/// <summary>
///退出时， 打印每个procedure的名字和计数
/// This function is called when the application exits
/// It prints the name and count for each procedure
/// </summary>
/// <param name="code"></param>
/// <param name="v"></param>
VOID Fini(INT32 code, VOID* v)
{
    outFile << setw(23) << "Procedure"
            << " " << setw(15) << "Image"
            << " " << setw(18) << "Address"
            << " " << setw(12) << "Calls"
            << " " << setw(12) << "Instructions" << endl;

    for (RTN_COUNT* rc = RtnList; rc; rc = rc->_next)
    {
        if (rc->_icount > 0)
            outFile << setw(23) << rc->_name << " " << setw(15) << rc->_image << " " << setw(18) << hex << rc->_address << dec
                    << " " << setw(12) << rc->_rtnCount << " " << setw(12) << rc->_icount << endl;
    }
}

/// <summary>
/// Print Help Message  
/// </summary>
/// <returns></returns>
INT32 Usage()
{
    cerr << "This Pintool counts the number of times a routine is executed" << endl;
    cerr << "and the number of instructions executed in a routine" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}


int main(int argc, char* argv[])
{
    // Initialize symbol table code, needed for rtn instrumentation
    //初始化符号
    PIN_InitSymbols();

    outFile.open("proccount.out");

    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    // Register Routine to be called to instrument rtn
    RTN_AddInstrumentFunction(Routine, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
