

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
//�������Ҫ��׮�Ĵ���
VOID docount() 
{ 
    icount++; 
}

// Pin calls this function every time a new instruction is encountered
//����һ����ָ�����һ�θú���
VOID Instruction(INS ins, VOID* v)
{
    // Insert a call to docount before every instruction, no arguments are passed
    //ָ������׮���뺯����ִ�в��������û�ж�׮���뺯�����д���
    //ÿ����һ��ָ����ָ�����+1
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_END);
}

//��������ļ���Ĭ���ļ���δ insconut.out
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "inscount.out", "specify output file name");

// This function is called when the application exits
//�����˳�ʱ����
VOID Fini(INT32 code, VOID* v)
{
    // Write to a file since cout and cerr maybe closed by the application
    //��������浽�ļ�
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
    //pin��ʼ��
    if (PIN_Init(argc, argv)) return Usage();

    OutFile.open(KnobOutputFile.Value().c_str());

    //ע���׮����
    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

    //ע������˳��Ĵ�����
    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    //��������
    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
