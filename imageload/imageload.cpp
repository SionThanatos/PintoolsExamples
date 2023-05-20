
//将映像加载卸载信息打印
// This tool prints a trace of image load and unload events

/*
 image instrumentation
通过“caching”插桩请求实现，会有额外的内存空间要求，属于一种“提前插桩”。
image instrumentation 模式下，Pintool 在 IMG:Image Object第一次加载时，对整个 imgaes 进行检查和插桩， 
Pintool 可以遍历 image 的 sections：SEC:Section Object， 
可以是 section 中的 routine：RTN:Routine，
还可以是一个 routine 中的 instructions：INS。
插入位置可以是例程或指令的前面或后面，都可以实现，使用的 API 为 IMG_AddInstrumentFunction 。
image instrumentation 需要有调试信息来确定 routine 的边界，
所以在调用 PIN_Init 之前，需要先初始化符号信息 PIN_InitSysmbols。
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
/// pin在image加载时调用，在该案例没有插桩
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
/// 在映像卸载时调用，对于将要卸载的image无法插桩
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
/// 程序结束调用，关闭输出文件
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
/// 主函数
/// </summary>
/// <param name="argc"></param>
/// <param name="argv"></param>
/// <returns></returns>
int main(int argc, char* argv[])
{
    // Initialize symbol processing
    //符号初始化
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
