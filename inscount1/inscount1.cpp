//计算BBL（单入口出口数量） trace插桩
//在每个BBL进行插桩代替每个指令插桩，计数以BBL为单位

/*
在一个代码序列第一次执行前进行插桩，这种粒度的插桩称为“trace instrumentation”。
在这种模式下，Pintool 一次“trace”执行一次检查和插桩，“
trace”是指从一个 branch 开始，以一个无条件跳转 branch 结束，包含 call 和 return。
Pin 会保证每个 trace 只有一个顶部入口，但是可能包含多个出口。
如果一个分支连接到了一个 trace 的中间位置，Pin 会生成一个以该分支作为开始的新的 trace 。
Pin 将 trace 切分成了基本块，每个基本块称为“BBL”，每个 BBL 是一个单一入口、单一出口的指令序列。
如果有分支连接到了 BBL 的中间位置，会定义一个新的 BBL 。
通常以 BBL 为单位插入分析调用，而不是对每个指令都插入，这样可以降低分析调用的性能消耗。
trace instrumentation 通过 TRACE_AddInstrumentFunction API 调用。
因为 Pin 是在程序执行时动态发现程序的执行流，所以 BBL 的概念与传统的基本块的概念有所不同

*/
#include <iostream>
#include <fstream>
#include "pin.H"
using std::cerr;
using std::endl;
using std::ios;
using std::ofstream;
using std::string;

ofstream OutFile;

// The running count of instructions is kept here make it static to help the compiler optimize docount
//设置静态变量帮助优化docount
static UINT64 icount = 0;


/// <summary>
/// 每一个block前调用
/// This function is called before every block
/// </summary>
/// <param name="c"></param>
VOID docount(UINT32 c) 
{ 
    icount += c; 
}


/// <summary>
/// Pin calls this function every time a new basic block is encountered
/// It inserts a call to docount
/// pin在遇到一个新的block的时候进行调用
/// </summary>
/// <param name="trace"></param>
/// <param name="v"></param>
VOID Trace(TRACE trace, VOID* v)
{
    // Visit every basic block  in the trace
    //访问trace中的每个bbl
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        // Insert a call to docount before every bbl, passing the number of instructions
        //在每个bbl前插入，传入指令数量
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)docount, IARG_UINT32, BBL_NumIns(bbl), IARG_END);
    }
}

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "inscount.out", "specify output file name");

/// <summary>
/// 结束
/// </summary>
/// <param name="code"></param>
/// <param name="v"></param>
VOID Fini(INT32 code, VOID* v)
{
    // Write to a file since cout and cerr maybe closed by the application
    OutFile.setf(ios::showbase);
    OutFile << "Count " << icount << endl;
    OutFile.close();
}

/// <summary>
/// Print Help Message  
/// </summary>
/// <returns></returns>
INT32 Usage()
{
    cerr << "This tool counts the number of dynamic instructions executed" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}


int main(int argc, char* argv[])
{
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    OutFile.open(KnobOutputFile.Value().c_str());

    // Register Instruction to be called to instrument instructions
    //注册trace插桩函数
    TRACE_AddInstrumentFunction(Trace, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
