

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
static UINT64 icount = 0;

// This function is called before every instruction is executed
//这里就是要插桩的代码
VOID docount() 
{ 
    icount++; 
}

// Pin calls this function every time a new instruction is encountered
//遇到一条新指令调用一次该函数
VOID Instruction(INS ins, VOID* v)
{
    // Insert a call to docount before every instruction, no arguments are passed
    //指定调用桩代码函数，执行插入操作，没有对桩代码函数进行传参
    //每调用一次指令则指令计数+1
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_END);
}

//处理输出文件，默认文件名未 insconut.out
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "inscount.out", "specify output file name");

// This function is called when the application exits
//程序退出时调用
VOID Fini(INT32 code, VOID* v)
{
    // Write to a file since cout and cerr maybe closed by the application
    //将输出保存到文件
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


/// <summary>
/// 
/// </summary>
/// <param name="argc"></param>
/// <param name="argv">argv are the entire command line: pin -t <toolname> -- ...</param>
/// <returns></returns>
int main(int argc, char* argv[])
{
    // Initialize pin
    //pin初始化
    if (PIN_Init(argc, argv)) return Usage();

    OutFile.open(KnobOutputFile.Value().c_str());

    //注册插桩函数
    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

    //注册程序退出的处理函数
    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    //启动函数
    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
