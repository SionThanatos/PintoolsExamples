//PIN_SafeCopy
//从原内存区域复制指定数量到目标内存区，即使不可访问，也能安全返回给调用者
//该api还可以读写程序的内存数据


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
/// 从内存转移到寄存器中
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
    //找到从值move到寄存器的指令
    if (INS_Opcode(ins) == XED_ICLASS_MOV && INS_IsMemoryRead(ins) && INS_OperandIsReg(ins, 0) && INS_OperandIsMemory(ins, 1))
    {
        // op0 <- *op1
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(DoLoad), IARG_UINT32, REG(INS_OperandReg(ins, 0)), IARG_MEMORYREAD_EA,
                       IARG_RETURN_REGS, INS_OperandReg(ins, 0), IARG_END);

        // Delete the instruction
        //删除指令
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
/// 主函数
/// </summary>
/// <param name="argc"></param>
/// <param name="argv"></param>
/// <returns></returns>
int main(int argc, char* argv[])
{
    // Write to a file since cout and cerr maybe closed by the application
    //输出
    out = new std::ofstream("safecopy.out");

    // Initialize pin & symbol manager
    //初始化pin与符号
    if (PIN_Init(argc, argv)) return Usage();
    PIN_InitSymbols();

    // Register EmulateLoad to be called to instrument instructions
    //注册EmulateLoad函数进行插桩
    INS_AddInstrumentFunction(EmulateLoad, 0);

    // Never returns
    PIN_StartProgram();
    return 0;
}
