//��ӡָ���ַ

#include <stdio.h>
#include "pin.H"

FILE* trace;

/// <summary>
/// // This function is called before every instruction is executed and prints the IP
/// ÿ��ָ��ִ��ǰ��ӡip��ַ
/// </summary>
/// <param name="ip"></param>
VOID PrintRegisterIP(VOID* ip) 
{ 
    fprintf(trace, "%p\n", ip); 
}

/// <summary>
/// Pin calls this function every time a new instruction is encountered
/// ����һ����ָ��͵���һ��
/// </summary>
/// <param name="ins"></param>
/// <param name="v"></param>
VOID Instruction(INS ins, VOID* v)
{
    // Insert a call to PrintRegisterIP before every instruction, and pass it the IP
    //����call ���ô�ӡip�ĺ��������Ҵ��ݲ���
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)PrintRegisterIP, IARG_INST_PTR, IARG_END);
}

/// <summary>
/// This function is called when the application exits
/// �����˳������
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
/// ������
/// </summary>
/// <param name="argc"></param>
/// <param name="argv"></param>
/// <returns></returns>
int main(int argc, char* argv[])
{
    //������ļ�
    trace = fopen("itrace.out", "w");

    // Initialize pin
    //��ʼ��
    if (PIN_Init(argc, argv)) return Usage();

    // Register Instruction to be called to instrument instructions
    //ע��׮
    INS_AddInstrumentFunction(Instruction, 0);

    // Register Fini to be called when the application exits
    //ע���˳�
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    //��ʼ
    PIN_StartProgram();

    return 0;
}
