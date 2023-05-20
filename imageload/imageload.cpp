
//��ӳ�����ж����Ϣ��ӡ
// This tool prints a trace of image load and unload events

/*
 image instrumentation
ͨ����caching����׮����ʵ�֣����ж�����ڴ�ռ�Ҫ������һ�֡���ǰ��׮����
image instrumentation ģʽ�£�Pintool �� IMG:Image Object��һ�μ���ʱ�������� imgaes ���м��Ͳ�׮�� 
Pintool ���Ա��� image �� sections��SEC:Section Object�� 
������ section �е� routine��RTN:Routine��
��������һ�� routine �е� instructions��INS��
����λ�ÿ��������̻�ָ���ǰ�����棬������ʵ�֣�ʹ�õ� API Ϊ IMG_AddInstrumentFunction ��
image instrumentation ��Ҫ�е�����Ϣ��ȷ�� routine �ı߽磬
�����ڵ��� PIN_Init ֮ǰ����Ҫ�ȳ�ʼ��������Ϣ PIN_InitSysmbols��
*/

#include "pin.H"
#include <iostream>
#include <fstream>
#include <stdlib.h>
using std::endl;
using std::ofstream;
using std::string;

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "imageload.out", "specify file name");

ofstream TraceFile;


/// <summary>
/// pin��image����ʱ���ã��ڸð���û�в�׮
/// Pin calls this function every time a new img is loaded
/// It can instrument the image, but this example does not
/// Note that imgs (including shared libraries) are loaded lazily
/// </summary>
/// <param name="img"></param>
/// <param name="v"></param>
VOID ImageLoad(IMG img, VOID* v) 
{ 
    TraceFile << "Loading " << IMG_Name(img) << ", Image id = " << IMG_Id(img) << endl; 
}


/// <summary>
/// ��ӳ��ж��ʱ���ã����ڽ�Ҫж�ص�image�޷���׮
/// Pin calls this function every time a new img is unloaded
/// You can't instrument an image that is about to be unloaded
/// </summary>
/// <param name="img"></param>
/// <param name="v"></param>
VOID ImageUnload(IMG img, VOID* v) 
{ 
    TraceFile << "Unloading " << IMG_Name(img) << endl; 
}


/// <summary>
/// ����������ã��ر�����ļ�
/// This function is called when the application exits
/// It closes the output file.
/// </summary>
/// <param name="code"></param>
/// <param name="v"></param>
VOID Fini(INT32 code, VOID* v)
{
    if (TraceFile.is_open())
    {
        TraceFile.close();
    }
}

/// <summary>
/// Print Help Message    
/// </summary>
/// <returns></returns>
INT32 Usage()
{
    PIN_ERROR("This tool prints a log of image load and unload events\n" + KNOB_BASE::StringKnobSummary() + "\n");
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
    // Initialize symbol processing
    //���ų�ʼ��
    PIN_InitSymbols();

    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    TraceFile.open(KnobOutputFile.Value().c_str());

    // Register ImageLoad to be called when an image is loaded
    IMG_AddInstrumentFunction(ImageLoad, 0);

    // Register ImageUnload to be called when an image is unloaded
    IMG_AddUnloadFunction(ImageUnload, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
