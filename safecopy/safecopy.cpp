//PIN_SafeCopy
//��ԭ�ڴ�������ָ��������Ŀ���ڴ�������ʹ���ɷ��ʣ�Ҳ�ܰ�ȫ���ظ�������
//��api�����Զ�д������ڴ�����


#include <stdio.h>
#include "pin.H"
#include <iostream>
#include <fstream>
using std::cerr;
using std::endl;

std::ofstream* out = 0;

//=======================================================
//  Analysis routines
//=======================================================

/// <summary>
/// Move from memory to register
/// ���ڴ�ת�Ƶ��Ĵ�����
/// </summary>
/// <param name="reg"></param>
/// <param name="addr"></param>
/// <returns></returns>
ADDRINT DoLoad(REG reg, ADDRINT* addr)
{
    *out << "Emulate loading from addr " << addr << " to " << REG_StringShort(reg) << endl;
    ADDRINT value;
    PIN_SafeCopy(&value, addr, sizeof(ADDRINT));
    return value;
}

//=======================================================
// Instrumentation routines
//=======================================================

VOID EmulateLoad(INS ins, VOID* v)
{
    // Find the instructions that move a value from memory to a register
    //�ҵ���ֵmove���Ĵ�����ָ��
    if (INS_Opcode(ins) == XED_ICLASS_MOV && INS_IsMemoryRead(ins) && INS_OperandIsReg(ins, 0) && INS_OperandIsMemory(ins, 1))
    {
        // op0 <- *op1
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(DoLoad), IARG_UINT32, REG(INS_OperandReg(ins, 0)), IARG_MEMORYREAD_EA,
                       IARG_RETURN_REGS, INS_OperandReg(ins, 0), IARG_END);

        // Delete the instruction
        //ɾ��ָ��
        INS_Delete(ins);
    }
}

/// <summary>
/// Print Help Message     
/// </summary>
/// <returns></returns>
INT32 Usage()
{
    cerr << "This tool demonstrates the use of SafeCopy" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
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
    // Write to a file since cout and cerr maybe closed by the application
    //���
    out = new std::ofstream("safecopy.out");

    // Initialize pin & symbol manager
    //��ʼ��pin�����
    if (PIN_Init(argc, argv)) return Usage();
    PIN_InitSymbols();

    // Register EmulateLoad to be called to instrument instructions
    //ע��EmulateLoad�������в�׮
    INS_AddInstrumentFunction(EmulateLoad, 0);

    // Never returns
    PIN_StartProgram();
    return 0;
}
