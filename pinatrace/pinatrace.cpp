//对内存读写指令插桩

/*
 *  This file contains an ISA-portable PIN tool for tracing memory accesses.
 */

#include <stdio.h>
#include "pin.H"

FILE* trace;

/// <summary>
/// Print a memory read record
/// 打印地址读的指令
/// </summary>
/// <param name="ip"></param>
/// <param name="addr"></param>
VOID RecordMemRead(VOID* ip, VOID* addr) 
{ 
    fprintf(trace, "%p: R %p\n", ip, addr); 
}

/// <summary>
/// Print a memory write record
/// 打印地址写的指令
/// </summary>
/// <param name="ip"></param>
/// <param name="addr"></param>
VOID RecordMemWrite(VOID* ip, VOID* addr) 
{ 
    fprintf(trace, "%p: W %p\n", ip, addr); 
}

/// <summary>
/// Is called for every instruction and instruments reads and writes
/// 指令调用时调用
/// </summary>
/// <param name="ins"></param>
/// <param name="v"></param>
VOID Instruction(INS ins, VOID* v)
{
    // Instruments memory accesses using a predicated call, i.e.
    // the instrumentation is called iff the instruction will actually be executed.
    //
    // On the IA-32 and Intel(R) 64 architectures conditional moves and REP
    // prefixed instructions appear as predicated instructions in Pin.

    //获取指令中的内存操作数计数
    UINT32 memOperands = INS_MemoryOperandCount(ins);

    // Iterate over each memory operand of the instruction.
    //遍历指令，寻找内存操作数
    for (UINT32 memOp = 0; memOp < memOperands; memOp++)
    {

        //如果是读
        if (INS_MemoryOperandIsRead(ins, memOp))
        {
            //插入读函数计数桩
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead, IARG_INST_PTR, IARG_MEMORYOP_EA, memOp,IARG_END);
        }
        // Note that in some architectures a single memory operand can be both read and written (for instance incl (%eax) on IA-32)
        // In that case we instrument it once for read and once for write.
        //某些架构下，内存操作数可以同时用作读和写，这种情况只记录一次

        //如果是写
        if (INS_MemoryOperandIsWritten(ins, memOp))
        {
            //插入写函数计数桩
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite, IARG_INST_PTR, IARG_MEMORYOP_EA, memOp,IARG_END);
        }
    }
}

/// <summary>
/// 结束程序时调用
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
    PIN_ERROR("This Pintool prints a trace of memory addresses\n" + KNOB_BASE::StringKnobSummary() + "\n");
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
    if (PIN_Init(argc, argv)) return Usage();

    trace = fopen("pinatrace.out", "w");

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}
