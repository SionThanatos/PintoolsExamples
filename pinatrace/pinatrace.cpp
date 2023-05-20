//���ڴ��дָ���׮

/*
 *  This file contains an ISA-portable PIN tool for tracing memory accesses.
 */

#include <stdio.h>
#include "pin.H"

FILE* trace;

/// <summary>
/// Print a memory read record
/// ��ӡ��ַ����ָ��
/// </summary>
/// <param name="ip"></param>
/// <param name="addr"></param>
VOID RecordMemRead(VOID* ip, VOID* addr) 
{ 
    fprintf(trace, "%p: R %p\n", ip, addr); 
}

/// <summary>
/// Print a memory write record
/// ��ӡ��ַд��ָ��
/// </summary>
/// <param name="ip"></param>
/// <param name="addr"></param>
VOID RecordMemWrite(VOID* ip, VOID* addr) 
{ 
    fprintf(trace, "%p: W %p\n", ip, addr); 
}

/// <summary>
/// Is called for every instruction and instruments reads and writes
/// ָ�����ʱ����
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

    //��ȡָ���е��ڴ����������
    UINT32 memOperands = INS_MemoryOperandCount(ins);

    // Iterate over each memory operand of the instruction.
    //����ָ�Ѱ���ڴ������
    for (UINT32 memOp = 0; memOp < memOperands; memOp++)
    {

        //����Ƕ�
        if (INS_MemoryOperandIsRead(ins, memOp))
        {
            //�������������׮
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead, IARG_INST_PTR, IARG_MEMORYOP_EA, memOp,IARG_END);
        }
        // Note that in some architectures a single memory operand can be both read and written (for instance incl (%eax) on IA-32)
        // In that case we instrument it once for read and once for write.
        //ĳЩ�ܹ��£��ڴ����������ͬʱ��������д���������ֻ��¼һ��

        //�����д
        if (INS_MemoryOperandIsWritten(ins, memOp))
        {
            //����д��������׮
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite, IARG_INST_PTR, IARG_MEMORYOP_EA, memOp,IARG_END);
        }
    }
}

/// <summary>
/// ��������ʱ����
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
/// ������
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
