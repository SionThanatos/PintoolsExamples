//����һ��procedure ���� �����õĴ������Լ�ÿ��������ִ�е��������� routine��׮
// This tool counts the number of times a routine is executed and the number of instructions executed in a routine


/*
 routine instrumentation
ͨ����caching����׮����ʵ�֣����ж�����ڴ�ռ�Ҫ������һ�֡���ǰ��׮����
routine instrumentation ģʽ�£�Pintool �� image �״μ���ʱ�Ͷ����� routine ���м��Ͳ�׮��
�� routine �е�ÿ��ָ����Բ�׮������û�г�ֵ���Ϣ���Խ�ָ���Ϊ BBL��
����λ�ÿ�����ִ�����̻�ָ���ǰ��
����ģʽ��ʵ����̶������� image instrumentation �����������ʹ�õ� API Ϊ RTN_AddInstrumentFunction��
��Ҫע����ǣ��� image �� routine instrumentation ģʽ�£�
��׮ʱ����ȷ�� routine �Ƿ�ᱻִ�У�����ͨ��ʶ�� routine �Ŀ�ʼָ����Ա�����ִ�й��� routine ��ָ�
*/

#include <fstream>
#include <iomanip>
#include <iostream>
#include <string.h>
#include "pin.H"
using std::cerr;
using std::dec;
using std::endl;
using std::hex;
using std::ofstream;
using std::setw;
using std::string;

ofstream outFile;

// Holds instruction count for a single procedure
//����procedure��ָ����
typedef struct RtnCount
{
    string _name;
    string _image;
    ADDRINT _address;
    RTN _rtn;
    UINT64 _rtnCount;
    UINT64 _icount;
    struct RtnCount* _next;
} RTN_COUNT;

// Linked list of instruction counts for each routine
//ÿ�����̵�ָ������
RTN_COUNT* RtnList = 0;

// This function is called before every instruction is executed
VOID docount(UINT64* counter) 
{ 
    (*counter)++; 
}

const char* StripPath(const char* path)
{
    const char* file = strrchr(path, '/');
    if (file)
        return file + 1;
    else
        return path;
}

// Pin calls this function every time a new rtn is executed
//�µ�����ʱ����
VOID Routine(RTN rtn, VOID* v)
{
    // Allocate a counter for this routine
    //�Ը��������ü�����
    RTN_COUNT* rc = new RTN_COUNT;

    // The RTN goes away when the image is unloaded, so save it now because we need it in the fini
    //imageж��ʱ RTN�ṹ������ʧ�������ڴ˴����棬����finiʱ��Ҫʹ��
    rc->_name     = RTN_Name(rtn);
    rc->_image    = StripPath(IMG_Name(SEC_Img(RTN_Sec(rtn))).c_str());
    rc->_address  = RTN_Address(rtn);
    rc->_icount   = 0;
    rc->_rtnCount = 0;

    // Add to list of routines
    //��ӵ���������
    rc->_next = RtnList;
    RtnList   = rc;

    RTN_Open(rtn);

    // Insert a call at the entry point of a routine to increment the call count
    //��������ڲ���һ��call������call����
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(rc->_rtnCount), IARG_END);

    // For each instruction of the routine
    //���������е�ÿ��ָ��
    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
    {
        // Insert a call to docount to increment the instruction counter for this rtn
        //����ָ����������������е�ָ����
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(rc->_icount), IARG_END);
    }

    RTN_Close(rtn);
}


/// <summary>
///�˳�ʱ�� ��ӡÿ��procedure�����ֺͼ���
/// This function is called when the application exits
/// It prints the name and count for each procedure
/// </summary>
/// <param name="code"></param>
/// <param name="v"></param>
VOID Fini(INT32 code, VOID* v)
{
    outFile << setw(23) << "Procedure"
            << " " << setw(15) << "Image"
            << " " << setw(18) << "Address"
            << " " << setw(12) << "Calls"
            << " " << setw(12) << "Instructions" << endl;

    for (RTN_COUNT* rc = RtnList; rc; rc = rc->_next)
    {
        if (rc->_icount > 0)
            outFile << setw(23) << rc->_name << " " << setw(15) << rc->_image << " " << setw(18) << hex << rc->_address << dec
                    << " " << setw(12) << rc->_rtnCount << " " << setw(12) << rc->_icount << endl;
    }
}

/// <summary>
/// Print Help Message  
/// </summary>
/// <returns></returns>
INT32 Usage()
{
    cerr << "This Pintool counts the number of times a routine is executed" << endl;
    cerr << "and the number of instructions executed in a routine" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}


int main(int argc, char* argv[])
{
    // Initialize symbol table code, needed for rtn instrumentation
    //��ʼ������
    PIN_InitSymbols();

    outFile.open("proccount.out");

    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    // Register Routine to be called to instrument rtn
    RTN_AddInstrumentFunction(Routine, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
