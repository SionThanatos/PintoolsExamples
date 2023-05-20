//����BBL������ڳ��������� trace��׮
//��ÿ��BBL���в�׮����ÿ��ָ���׮��������BBLΪ��λ

/*
��һ���������е�һ��ִ��ǰ���в�׮���������ȵĲ�׮��Ϊ��trace instrumentation����
������ģʽ�£�Pintool һ�Ρ�trace��ִ��һ�μ��Ͳ�׮����
trace����ָ��һ�� branch ��ʼ����һ����������ת branch ���������� call �� return��
Pin �ᱣ֤ÿ�� trace ֻ��һ��������ڣ����ǿ��ܰ���������ڡ�
���һ����֧���ӵ���һ�� trace ���м�λ�ã�Pin ������һ���Ը÷�֧��Ϊ��ʼ���µ� trace ��
Pin �� trace �зֳ��˻����飬ÿ���������Ϊ��BBL����ÿ�� BBL ��һ����һ��ڡ���һ���ڵ�ָ�����С�
����з�֧���ӵ��� BBL ���м�λ�ã��ᶨ��һ���µ� BBL ��
ͨ���� BBL Ϊ��λ����������ã������Ƕ�ÿ��ָ����룬�������Խ��ͷ������õ��������ġ�
trace instrumentation ͨ�� TRACE_AddInstrumentFunction API ���á�
��Ϊ Pin ���ڳ���ִ��ʱ��̬���ֳ����ִ���������� BBL �ĸ����봫ͳ�Ļ�����ĸ���������ͬ

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
//���þ�̬���������Ż�docount
static UINT64 icount = 0;


/// <summary>
/// ÿһ��blockǰ����
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
/// pin������һ���µ�block��ʱ����е���
/// </summary>
/// <param name="trace"></param>
/// <param name="v"></param>
VOID Trace(TRACE trace, VOID* v)
{
    // Visit every basic block  in the trace
    //����trace�е�ÿ��bbl
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        // Insert a call to docount before every bbl, passing the number of instructions
        //��ÿ��bblǰ���룬����ָ������
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)docount, IARG_UINT32, BBL_NumIns(bbl), IARG_END);
    }
}

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "inscount.out", "specify output file name");

/// <summary>
/// ����
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
    //ע��trace��׮����
    TRACE_AddInstrumentFunction(Trace, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
