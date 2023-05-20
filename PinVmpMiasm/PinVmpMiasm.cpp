
#include "pin.H"
#include <iostream>
#include <fstream>
#include <set>
#include <map>

using namespace std;

//define in pin3.21 types_vmapi.PH
static const UINT32 MAX_BYTES_PER_PIN_REG = 64;
static const UINT32 MAX_WORDS_PER_PIN_REG = (MAX_BYTES_PER_PIN_REG / 2);
static const UINT32 MAX_DWORDS_PER_PIN_REG = (MAX_WORDS_PER_PIN_REG / 2);
static const UINT32 MAX_QWORDS_PER_PIN_REG = (MAX_DWORDS_PER_PIN_REG / 2);
static const UINT32 MAX_FLOATS_PER_PIN_REG = (MAX_BYTES_PER_PIN_REG / sizeof(float));
static const UINT32 MAX_DOUBLES_PER_PIN_REG = (MAX_BYTES_PER_PIN_REG / sizeof(double));


/*! @ingroup CONTEXT
 *  A container large enough to hold registers up to the size of the largest vector register (ZMM - 64 bytes)).
 *  Implemented as a union to allow viewing the value as different types (signed/unsigned integer or floating point)
 *  and allow access in blocks of various sizes.
 */
union PIN_REGISTER
{
	UINT8 byte[MAX_BYTES_PER_PIN_REG];
	UINT16 word[MAX_WORDS_PER_PIN_REG];
	UINT32 dword[MAX_DWORDS_PER_PIN_REG];
	UINT64 qword[MAX_QWORDS_PER_PIN_REG];

	INT8 s_byte[MAX_BYTES_PER_PIN_REG];
	INT16 s_word[MAX_WORDS_PER_PIN_REG];
	INT32 s_dword[MAX_DWORDS_PER_PIN_REG];
	INT64 s_qword[MAX_QWORDS_PER_PIN_REG];

	FLT32 flt[MAX_FLOATS_PER_PIN_REG];
	FLT64 dbl[MAX_DOUBLES_PER_PIN_REG];
};




/* ===================================================================== */
// Utilities
/* ===================================================================== */

/// <summary>
/// 帮助
/// </summary>
/// <returns></returns>
INT32 Usage()
{
    cerr << "Trace tool that logs instruction disassembly and run trace." << endl << endl;
    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
// Global files
/* ===================================================================== */

FILE * tracefile;
FILE * insfile;
FILE * blockfile;

static REG writeea_scratch_reg;


/// <summary>
/// 打开文件
/// </summary>
void InitFiles()
{
	tracefile = fopen("bin.trace", "wb");
	insfile = fopen("bin.ins", "wb");
	blockfile = fopen("bin.block", "wb");
	ASSERT(tracefile && insfile && blockfile, "open file failed");
}

/// <summary>
/// 将指令写入trace文件
/// </summary>
/// <param name="insAddr"></param>
void LogTrace(ADDRINT insAddr)
{
	fwrite(&insAddr, sizeof(ADDRINT), 1, tracefile);
}


#if defined(TARGET_IA32)
#define INS_LOG_FORMAT "%#x\t%s\t"
#else
#define INS_LOG_FORMAT "%#lx\t%s\t"
#endif

void LogIns(ADDRINT insAddr, const char *disasm, USIZE insSize, UINT8 *insBytes) 
{
	fprintf(insfile, INS_LOG_FORMAT, insAddr, disasm);
	for (USIZE i = 0; i < insSize; i++) 
	{
		fprintf(insfile, "%02X", insBytes[i]);
	}
	fprintf(insfile, "\n");
}

void CloseFiles()
{
	fclose(tracefile);
	fclose(insfile);
	fclose(blockfile);
}


/* ===================================================================== */
// Analysis routines
/* ===================================================================== */


int insCount;
/// <summary>
/// 跟踪指令执行并记录其地址
/// </summary>
/// <param name="insAddr"></param>
/// <returns></returns>
VOID InsTrace(ADDRINT insAddr)
{
	insCount++; //记录累计执行的指令数量
	LogTrace(insAddr);
}


ADDRINT filter_ip_low, filter_ip_high; //IMG_LowAddress 和 IMG_HighAddress 函数分别用于获取指定映像的最低和最高有效地址
/// <summary>
/// 在程序启动时加载可执行文件
/// </summary>
/// <param name="img"></param>
/// <param name="v"></param>
/// <returns></returns>
VOID ImageLoad(IMG img, VOID *v) 
{
	cerr << "[+] Images loads. " << IMG_Name(img) << endl;
	if (IMG_IsMainExecutable(img)) 
	{
		filter_ip_low = IMG_LowAddress(img);
		filter_ip_high = IMG_HighAddress(img);
		cerr << "[-] Log range:" << StringFromAddrint(filter_ip_low) << "-" << StringFromAddrint(filter_ip_high) << endl;
	}
}

/// <summary>
/// 获取指令地址并进行跟踪和分析操作
/// </summary>
/// <param name="ins"></param>
/// <param name="v"></param>
/// <returns></returns>
VOID Instruction_addr(INS ins, VOID *v)
{
	//获取当前指令的地址
	ADDRINT ip =  INS_Address(ins);

	//当前指令是否在之前定义的地址范围内，如果在，则执行
	if (ip >= filter_ip_low && ip <= filter_ip_high)
	{
		//创建一个大小为 0x20 的指令缓冲区，并通过 PIN_SafeCopy 函数将指令内容从内存中复制到该缓冲区中
		UINT8 ins_buf[0x20];  // instructions won't be too long.
		USIZE ins_size = INS_Size(ins);
		ASSERT(ins_size < sizeof(ins_buf), "so long ins");
		PIN_SafeCopy(ins_buf, (VOID *)ip, ins_size);

		//调用 LogIns 函数，将指令地址、反汇编结果以及指令大小和具体内容记录下来，用于后续的跟踪和分析
		LogIns(ip, INS_Disassemble(ins).c_str(), INS_Size(ins), ins_buf);

		//在指令执行时，向指令地址插入一个回调函数 InsTrace，用于记录指令执行地址
		INS_InsertCall(ins, IPOINT_BEFORE,
			(AFUNPTR)InsTrace, //回调
			IARG_INST_PTR,
			IARG_END);
	}
}


/// <summary>
/// 将寄存器名字转换为对应的枚举值
/// </summary>
/// <param name="r">REG 类型的参数 r</param>
/// <returns>返回一个 UINT32 类型的值</returns>
UINT32 RegToEnum(REG r) 
{
#if defined(TARGET_IA32E)
	switch (REG_FullRegName(r)) 
	{
	case REG_GAX: return 0;
	case REG_GCX: return 8;
	case REG_GDX: return 16;
	case REG_GBX: return 24;
	case REG_STACK_PTR: return 32;
	case REG_GBP: return 40;
	case REG_GSI: return 48;
	case REG_GDI: return 56;
	case REG_R8:  return 8 * 8;
	case REG_R9:  return 9 * 8;
	case REG_R10: return 10 * 8;
	case REG_R11: return 11 * 8;
	case REG_R12: return 12 * 8;
	case REG_R13: return 13 * 8;
	case REG_R14: return 14 * 8;
	case REG_R15: return 15 * 8;
	case REG_INST_PTR: return 16 * 8;
	default: return 1024;
	}
#else
	switch (REG_FullRegName(r)) 
	{
	case REG_EAX: return 0;
	case REG_ECX: return 4;
	case REG_EDX: return 8;
	case REG_EBX: return 12;
	case REG_ESP: return 16;
	case REG_EBP: return 20;
	case REG_ESI: return 24;
	case REG_EDI: return 28;
	case REG_EIP: return 32;
	default: return 1024;
	}
#endif
}

// flags
#define IS_VALID    0x80000000
#define IS_WRITE    0x40000000
#define IS_MEM      0x20000000
#define IS_START    0x10000000


struct change 
{
	uint32_t number;
	uint32_t flags;	
	uint64_t address;
	uint64_t data;
};

/// <summary>
/// 将变化信息写入分析结果文件
/// </summary>
/// <param name="tid"></param>
/// <param name="addr"></param>
/// <param name="data"></param>
/// <param name="flags"></param>
static inline void add_change(THREADID tid, uint64_t addr, uint64_t data, uint32_t flags) 
{
	struct change c;
	c.number = insCount;
	c.flags = flags;
	c.address = addr;
	c.data = data;
	fwrite(&c, sizeof(change), 1, tracefile);
}


/// <summary>
/// 将大块数据变化写入到分析结果文件中
/// </summary>
/// <param name="tid"></param>
/// <param name="addr"></param>
/// <param name="data"></param>
/// <param name="flags"></param>
/// <param name="size"></param>
static void add_big_change(THREADID tid, uint64_t addr, const void *data, uint32_t flags, size_t size) 
{
	const UINT64 *v = (const UINT64 *)data;
	while (size >= 8) 
	{
		add_change(tid, addr, *v, flags | 64);
		addr += 8; size -= 8; v++;
	}
	if (size) 
	{
		UINT64 x = *v & ~(~(UINT64)0 << size * 8);
		add_change(tid, addr, x, flags | (size * 8));
	}
}

/// <summary>
/// 记录开始
/// </summary>
/// <param name="tid"></param>
/// <param name="ip"></param>
/// <param name="size"></param>
/// <returns></returns>
VOID RecordStart(THREADID tid, ADDRINT ip, UINT32 size)
{
	insCount++;
	add_change(tid, ip, size, IS_START);
}

/// <summary>
/// 记录寄存器读
/// </summary>
/// <param name="tid"></param>
/// <param name="regaddr"></param>
/// <param name="value"></param>
/// <param name="size"></param>
/// <returns></returns>
VOID RecordRegRead(THREADID tid, UINT32 regaddr, PIN_REGISTER *value, UINT32 size) 
{
	add_big_change(tid, regaddr, value->byte, 0, size);
}

/// <summary>
/// 记录寄存器写
/// </summary>
/// <param name="tid"></param>
/// <param name="regaddr"></param>
/// <param name="value"></param>
/// <param name="size"></param>
/// <returns></returns>
VOID RecordRegWrite(THREADID tid, UINT32 regaddr, PIN_REGISTER *value, UINT32 size) 
{
	add_big_change(tid, regaddr, value->byte, IS_WRITE, size);
}

/// <summary>
/// 读取内存时记录操作
/// </summary>
/// <param name="tid"></param>
/// <param name="addr"></param>
/// <param name="size"></param>
/// <returns></returns>
VOID RecordMemRead(THREADID tid, ADDRINT addr, UINT32 size) 
{
	UINT64 value[16];
	PIN_SafeCopy(value, (const VOID *)addr, size); // Can assume it worked.
	add_big_change(tid, addr, value, IS_MEM, size);
}


static const ADDRINT WRITEEA_SENTINEL = (sizeof(ADDRINT) > 4) ? (ADDRINT)0xDEADDEADDEADDEADull : (ADDRINT)0xDEADDEADul;


/// <summary>
/// 记录内存写操作的地址信息
/// </summary>
/// <param name="tid"></param>
/// <param name="addr"></param>
/// <param name="oldval"></param>
/// <returns></returns>
ADDRINT RecordMemWrite1(THREADID tid, ADDRINT addr, ADDRINT oldval) 
{
	return addr;
}

/// <summary>
/// 记录内存写操作的相关信息
/// </summary>
/// <param name="tid"></param>
/// <param name="addr"></param>
/// <param name="size"></param>
/// <returns></returns>
ADDRINT RecordMemWrite2(THREADID tid, ADDRINT addr, UINT32 size) 
{
	UINT64 value[16];
	PIN_SafeCopy(value, (const VOID *)addr, size); // Can assume it worked.
	add_big_change(tid, addr, value, IS_MEM | IS_WRITE, size);
	return WRITEEA_SENTINEL;
}

/// <summary>
/// 指令插桩回调
/// </summary>
/// <param name="ins"></param>
/// <param name="v"></param>
/// <returns></returns>
VOID Instruction(INS ins, VOID *v) 
{
	//将当前指令地址赋值给变量 address
	ADDRINT address = INS_Address(ins);

	//判断当前指令地址是否在过滤范围内，如果是则直接返回
	const bool filtered = address < filter_ip_low || filter_ip_high <= address;
	if (filtered) return;

	//定义一个长度为 0x20 的字节型数组 ins_buf 用于保存指令内容，并获取当前指令长度（字节数），存储在变量 ins_size 中
	UINT8 ins_buf[0x20];  // instructions won't be too long.
	USIZE ins_size = INS_Size(ins);
	ASSERT(ins_size < sizeof(ins_buf), "so long ins");
	PIN_SafeCopy(ins_buf, (VOID *)address, ins_size);

	//调用 LogIns 函数，将当前指令地址、指令的反汇编字符串、指令长度以及指令内容作为参数，将这些信息一起写入到分析结果文件中
	LogIns(address, INS_Disassemble(ins).c_str(), INS_Size(ins), ins_buf);

	//调用 INS_InsertCall 函数，在指令执行前插入一条记录开始的函数调用 RecordStart，并将线程 ID、指令地址、指令长度等信息作为参数传递给记录函数。
	//这里使用了 CALL_ORDER_FIRST 参数保证所有记录函数都在 RecordStart 函数之后执行
	INS_InsertCall(
		ins, IPOINT_BEFORE, (AFUNPTR)RecordStart, IARG_THREAD_ID,
		IARG_INST_PTR,
		IARG_UINT32, (UINT32)INS_Size(ins),
		IARG_CALL_ORDER, CALL_ORDER_FIRST,
		IARG_END
	);

	UINT32 rRegs = INS_MaxNumRRegs(ins);//读寄存器
	UINT32 wRegs = INS_MaxNumWRegs(ins);//写寄存器
	UINT32 memOps = INS_MemoryOperandCount(ins);//获取当前指令中涉及到内存操作数（Memory Operand）的总数

	// INS_InsertPredicatedCall to skip inactive CMOVs and REPs.
	//遍历当前指令的读寄存器列表
	for (UINT32 i = 0; i < rRegs; i++) 
	{
		//INS_RegR(ins, i)函数返回当前指令中第i个源操作数或目标操作数所涉及到的寄存器，其中ins表示当前的指令对象
		REG r = INS_RegR(ins, i);
		
		//REG_is_gr(REG_FullRegName(r))函数用于判断指定的寄存器是否是通用寄存器（General-purpose Register）
		if (!REG_is_gr(REG_FullRegName(r))) continue;
		
		//对于每一个是通用寄存器的读寄存器，调用 INS_InsertPredicatedCall 函数，
		//在指令执行前插入一条记录寄存器读取的函数调用 RecordRegRead，
		//并将线程 ID、寄存器枚举值、寄存器对象、寄存器大小等信息作为参数传递给记录函数
		INS_InsertPredicatedCall(
			ins, IPOINT_BEFORE, (AFUNPTR)RecordRegRead, IARG_THREAD_ID,
			IARG_UINT32, RegToEnum(r),
			IARG_REG_CONST_REFERENCE, r,
			IARG_UINT32, REG_Size(r),
			IARG_END
		);
	}

	//遍历当前指令的写寄存器列表
	for (UINT32 i = 0; i < wRegs; i++) 
	{
		REG r = INS_RegW(ins, i);
		if (!REG_is_gr(REG_FullRegName(r))) continue;
		if (INS_HasFallThrough(ins)) 
		{
			INS_InsertPredicatedCall(
				ins, IPOINT_AFTER, (AFUNPTR)RecordRegWrite, IARG_THREAD_ID,
				IARG_UINT32, RegToEnum(r),
				IARG_REG_CONST_REFERENCE, r,
				IARG_UINT32, REG_Size(r),
				IARG_END
			);
		}

		//果当前指令是分支或调用指令，则在分支或调用成功时插入一条记录寄存器写入的函数调用
		if (INS_IsBranchOrCall(ins)) 
		{
			INS_InsertPredicatedCall(
				ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)RecordRegWrite, IARG_THREAD_ID,
				IARG_UINT32, RegToEnum(r),
				IARG_REG_CONST_REFERENCE, r,
				IARG_UINT32, REG_Size(r),
				IARG_END
			);
		}
	}

	//如果当前指令是 XSAVE 指令，则直接返回，因为该指令还未被支持
	if (INS_Mnemonic(ins) == "XSAVE") 
	{
		// Still not supported. 
		return;
	}

	//遍历当前指令的内存操作数列表
	for (UINT32 i = 0; i < memOps; i++) 
	{
		//如果操作数是读操作数，调用 INS_InsertPredicatedCall 函数，在指令执行前插入一条记录内存读取的函数调用 RecordMemRead
		if (INS_MemoryOperandIsRead(ins, i)) 
		{
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead, IARG_THREAD_ID,
				IARG_MEMORYOP_EA, i,
				IARG_MEMORYREAD_SIZE,
				IARG_END
			);
		}

		//如果操作数是写操作数，则先在指令执行前插入一条记录内存写入的函数调用 RecordMemWrite1
		if (INS_MemoryOperandIsWritten(ins, i)) 
		{
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite1, IARG_THREAD_ID,
				IARG_MEMORYOP_EA, i,
				IARG_REG_VALUE, writeea_scratch_reg,
				IARG_RETURN_REGS, writeea_scratch_reg,
				IARG_END
			);

			//检查当前指令是否具有“落空”效应（即执行后控制流无条件地转移到下一条指令），如果有，则在该指令之后插入一个回调函数RecordMemWrite2来记录内存写入操作
			if (INS_HasFallThrough(ins)) 
			{
				INS_InsertPredicatedCall(
					ins, IPOINT_AFTER, (AFUNPTR)RecordMemWrite2, IARG_THREAD_ID,
					IARG_REG_VALUE, writeea_scratch_reg,
					IARG_MEMORYWRITE_SIZE,
					IARG_RETURN_REGS, writeea_scratch_reg,
					IARG_END
				);
			}
			if (INS_IsBranchOrCall(ins)) 
			{
				INS_InsertPredicatedCall(
					ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)RecordMemWrite2, IARG_THREAD_ID,
					IARG_REG_VALUE, writeea_scratch_reg,
					IARG_MEMORYWRITE_SIZE,
					IARG_RETURN_REGS, writeea_scratch_reg,
					IARG_END
				);
			}
		}
	}


}


VOID BblTrace(ADDRINT addr)
{
	fwrite(&addr, sizeof(ADDRINT), 1, blockfile);
}

/// <summary>
/// 跟踪回调
/// </summary>
/// <param name="trace"></param>
/// <param name="v"></param>
/// <returns></returns>
VOID Trace(TRACE trace, VOID *v)
{
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		ADDRINT addr = BBL_Address(bbl);
		if (addr >= filter_ip_low && addr <= filter_ip_high) 
		{
			BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)BblTrace,
				IARG_UINT32, addr,
				IARG_END);
		}
	}
}

/// <summary>
/// 线程启动回调监听
/// </summary>
/// <param name="threadIndex"></param>
/// <param name="ctxt"></param>
/// <param name="flags"></param>
/// <param name="v"></param>
/// <returns></returns>
VOID ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
	cerr << "[+] Thread " << threadIndex << " starts" << endl;
}


/// <summary>
/// 初始化，加载文件
/// </summary>
void Init()
{
	InitFiles();
}


/// <summary>
/// 结束
/// </summary>
/// <param name="code"></param>
/// <param name="v"></param>
/// <returns></returns>
VOID Fini(INT32 code, VOID *v)
{
	CloseFiles();
	cerr << "\n[+] "<< insCount <<" instructions logged." << endl;
	cerr << "=============================================" << endl;
	cerr << "<< END >>" << endl;
}


/// <summary>
/// 主函数
/// </summary>
/// <param name="argc"></param>
/// <param name="argv"></param>
/// <returns></returns>
int main(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }

	//初始化，加载文件
	Init();
	
	//获取一个工具寄存器，用于存储临时数据
	writeea_scratch_reg = PIN_ClaimToolRegister();
	if (!REG_valid(writeea_scratch_reg)) {
		fprintf(stderr, "[!] Failed to claim a scratch register.\n");
		return 1;
	}

	//调用 IMG_AddInstrumentFunction 函数，将 ImageLoad 函数注册为映像加载时的回调函数
	IMG_AddInstrumentFunction(ImageLoad, 0);

	//调用 INS_AddInstrumentFunction 函数，将 Instruction 函数注册为指令执行时的回调函数
	INS_AddInstrumentFunction(Instruction, 0);

	//调用 TRACE_AddInstrumentFunction 函数，将 Trace 函数注册为跟踪时的回调函数
	TRACE_AddInstrumentFunction(Trace, 0);

	//调用 PIN_AddThreadStartFunction 函数，将 ThreadStart 函数注册为线程开始时的回调函数
    PIN_AddThreadStartFunction(ThreadStart, 0);

	//调用 PIN_AddFiniFunction 函数，将 Fini 函数注册为程序结束时的回调函数
    PIN_AddFiniFunction(Fini, 0);

    //开始执行被分析的二进制程序，并进入监听状态，直到程序运行结束
    PIN_StartProgram();    
    return 0;
}

