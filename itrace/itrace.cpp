//打印指令地址

#include <stdio.h>
#include "pin.H"

FILE* trace;

/// <summary>
/// // This function is called before every instruction is executed and prints the IP
/// 每条指令执行前打印ip地址
/// </summary>
/// <param name="ip"></param>
VOID PrintRegisterIP(VOID* ip) 
{ 
    fprintf(trace, "%p\n", ip); 
}

/// <summary>
/// Pin calls this function every time a new instruction is encountered
/// 遇到一个新指令就调用一次
/// </summary>
/// <param name="ins"></param>
/// <param name="v"></param>
VOID Instruction(INS ins, VOID* v)
{
    // Insert a call to PrintRegisterIP before every instruction, and pass it the IP
    //插入call 调用打印ip的函数，并且传递参数
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)PrintRegisterIP, IARG_INST_PTR, IARG_END);
}

/// <summary>
/// This function is called when the application exits
/// 程序退出后调用
/// </summary>
/// <param name="code"></param>
/// <param name="v"></param>
VOID Fini(INT32 code, VOID* v)
{
    fprintf(trace, "#eof\n");
    fclose(trace);
}

/// <summary>
/// Print Help Message   
/// </summary>
/// <returns></returns>
INT32 Usage()
{
    PIN_ERROR("This Pintool prints the IPs of every instruction executed\n" + KNOB_BASE::StringKnobSummary() + "\n");
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
    //打开输出文件
    trace = fopen("itrace.out", "w");

    // Initialize pin
    //初始化
    if (PIN_Init(argc, argv)) return Usage();

    // Register Instruction to be called to instrument instructions
    //注册桩
    INS_AddInstrumentFunction(Instruction, 0);

    // Register Fini to be called when the application exits
    //注册退出
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    //开始
    PIN_StartProgram();

    return 0;
}
