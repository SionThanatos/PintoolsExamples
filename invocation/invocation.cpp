//插桩顺序

#include "pin.H"
#include <iostream>
#include <fstream>
using std::cerr;
using std::dec;
using std::endl;
using std::hex;
using std::ios;
using std::ofstream;
using std::string;

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "invocation.out", "specify output file name");

ofstream OutFile;

/*
 * Analysis routines
 */
VOID Taken(const CONTEXT* ctxt)
{
    ADDRINT TakenIP = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    OutFile << "Taken: IP = " << hex << TakenIP << dec << endl;
}

VOID Before(CONTEXT* ctxt)
{
    ADDRINT BeforeIP = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    OutFile << "Before: IP = " << hex << BeforeIP << dec << endl;
}

VOID After(CONTEXT* ctxt)
{
    ADDRINT AfterIP = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    OutFile << "After: IP = " << hex << AfterIP << dec << endl;
}

/*
 * Instrumentation routines
 */
VOID ImageLoad(IMG img, VOID* v)
{
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        // RTN_InsertCall() and INS_InsertCall() are executed in order of appearance.  
        // In the code sequence below, the IPOINT_AFTER is executed before the IPOINT_BEFORE.
        //RTN_InsertCall() and INS_InsertCall()谁先出现谁先执行
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            // Open the RTN.
            //打开RTN
            RTN_Open(rtn);

            // IPOINT_AFTER is implemented by instrumenting each return instruction in a routine.  
            // Pin tries to find all return instructions, but success is not guaranteed.
            //IPOINT_AFTER通过在一个routine中对每个return指令插桩实现
            //pin会查找所有return指令
            RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)After, IARG_CONTEXT, IARG_END);

            // Examine each instruction in the routine.
            //查找routine中每个指令
            for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
            {
                if (INS_IsRet(ins))
                {
                    // instrument each return instruction. 插桩每条指令
                    // IPOINT_TAKEN_BRANCH always occurs last. IPOINT_TAKEN_BRANCH总是最后使用
                    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)Before, IARG_CONTEXT, IARG_END);
                    INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)Taken, IARG_CONTEXT, IARG_END);
                }
            }
            // Close the RTN.
            RTN_Close(rtn);
        }
    }
}

VOID Fini(INT32 code, VOID* v) 
{ 
    OutFile.close(); 
}

/// <summary>
/// Print Help Message  
/// </summary>
/// <returns></returns>
INT32 Usage()
{
    cerr << "This is the invocation pintool" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    // Initialize pin & symbol manager
    if (PIN_Init(argc, argv)) return Usage();
    PIN_InitSymbols();

    // Register ImageLoad to be called to instrument instructions
    IMG_AddInstrumentFunction(ImageLoad, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Write to a file since cout and cerr maybe closed by the application
    OutFile.open(KnobOutputFile.Value().c_str());
    OutFile.setf(ios::showbase);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
/* ===================================================================== */
