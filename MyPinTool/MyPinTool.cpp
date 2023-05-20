#include "pin.H"
#include <iostream>
#include <fstream>
using std::cerr;
using std::endl;
using std::string;

/* ================================================================== */
// Global variables
/* ================================================================== */

UINT64 insCount    = 0; //number of dynamically executed instructions
UINT64 bblCount    = 0; //number of dynamically executed basic blocks
UINT64 threadCount = 0; //total number of threads, including main thread

std::ostream* out = &cerr;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */

//处理输出文件
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "specify file name for MyPinTool output");

KNOB< BOOL > KnobCount(KNOB_MODE_WRITEONCE, "pintool", "count", "1",
                       "count instructions, basic blocks and threads in the application");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/// <summary>
/// Print out help message.
/// </summary>
/// <returns></returns>
INT32 Usage()
{
    cerr << "This tool prints out the number of dynamically executed " << endl
         << "instructions, basic blocks and threads in the application." << endl
         << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

/// <summary>
/// Increase counter of the executed basic blocks and instructions.
/// This function is called for every basic block when it is about to be executed.
/// note use atomic operations for multi-threaded applications
/// </summary>
/// <param name="numInstInBbl">number of instructions in the basic block</param>
VOID CountBbl(UINT32 numInstInBbl)
{
    bblCount++;
    insCount += numInstInBbl;
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */


/// <summary>
/// Insert call to the CountBbl() analysis routine before every basic block  of the trace.
/// This function is called every time a new trace is encountered.
/// </summary>
/// <param name="trace">trace to be instrumented</param>
/// <param name="v">value specified by the tool in the TRACE_AddInstrumentFunction function call</param>
VOID Trace(TRACE trace, VOID* v)
{
    // Visit every basic block in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        // Insert a call to CountBbl() before every basic bloc, passing the number of instructions
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)CountBbl, IARG_UINT32, BBL_NumIns(bbl), IARG_END);
    }
}


/// <summary>
/// Increase counter of threads in the application.
/// This function is called for every thread created by the application when it is about to start running (including the root thread).
/// </summary>
/// <param name="threadIndex">ID assigned by PIN to the new thread</param>
/// <param name="ctxt">initial register state for the new thread</param>
/// <param name="flags">thread creation flags (OS specific)</param>
/// <param name="v">value specified by the tool in the PIN_AddThreadStartFunction function call</param>
VOID ThreadStart(THREADID threadIndex, CONTEXT* ctxt, INT32 flags, VOID* v) 
{ 
    threadCount++; 
}


/// <summary>
/// Print out analysis results.
/// This function is called when the application exits.
/// </summary>
/// <param name="code">exit code of the application</param>
/// <param name="v">value specified by the tool in the PIN_AddFiniFunction function call</param>
VOID Fini(INT32 code, VOID* v)
{
    *out << "===============================================" << endl;
    *out << "MyPinTool analysis results: " << endl;
    *out << "Number of instructions: " << insCount << endl;
    *out << "Number of basic blocks: " << bblCount << endl;
    *out << "Number of threads: " << threadCount << endl;
    *out << "===============================================" << endl;
}



/// <summary>
/// The main procedure of the tool.
/// This function is called when the application image is loaded but not yet started.
/// </summary>
/// <param name="argc">total number of elements in the argv array</param>
/// <param name="argv">array of command line arguments, including pin -t <toolname> -- ...</param>
/// <returns></returns>
int main(int argc, char* argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    string fileName = KnobOutputFile.Value();

    if (!fileName.empty())
    {
        out = new std::ofstream(fileName.c_str());
    }

    if (KnobCount)
    {
        // Register function to be called to instrument traces
        TRACE_AddInstrumentFunction(Trace, 0);

        // Register function to be called for every thread before it starts running
        PIN_AddThreadStartFunction(ThreadStart, 0);

        // Register function to be called when the application exits
        PIN_AddFiniFunction(Fini, 0);
    }

    cerr << "===============================================" << endl;
    cerr << "This application is instrumented by MyPinTool" << endl;
    if (!KnobOutputFile.Value().empty())
    {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }
    cerr << "===============================================" << endl;

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
