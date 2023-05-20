
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
/// ����
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
/// ���ļ�
/// </summary>
void InitFiles()
{
	tracefile = fopen("bin.trace", "wb");
	insfile = fopen("bin.ins", "wb");
	blockfile = fopen("bin.block", "wb");
	ASSERT(tracefile && insfile && blockfile, "open file failed");
}

/// <summary>
/// ��ָ��д��trace�ļ�
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
/// ����ָ��ִ�в���¼���ַ
/// </summary>
/// <param name="insAddr"></param>
/// <returns></returns>
VOID InsTrace(ADDRINT insAddr)
{
	insCount++; //��¼�ۼ�ִ�е�ָ������
	LogTrace(insAddr);
}


ADDRINT filter_ip_low, filter_ip_high; //IMG_LowAddress �� IMG_HighAddress �����ֱ����ڻ�ȡָ��ӳ�����ͺ������Ч��ַ
/// <summary>
/// �ڳ�������ʱ���ؿ�ִ���ļ�
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
/// ��ȡָ���ַ�����и��ٺͷ�������
/// </summary>
/// <param name="ins"></param>
/// <param name="v"></param>
/// <returns></returns>
VOID Instruction_addr(INS ins, VOID *v)
{
	//��ȡ��ǰָ��ĵ�ַ
	ADDRINT ip =  INS_Address(ins);

	//��ǰָ���Ƿ���֮ǰ����ĵ�ַ��Χ�ڣ�����ڣ���ִ��
	if (ip >= filter_ip_low && ip <= filter_ip_high)
	{
		//����һ����СΪ 0x20 ��ָ���������ͨ�� PIN_SafeCopy ������ָ�����ݴ��ڴ��и��Ƶ��û�������
		UINT8 ins_buf[0x20];  // instructions won't be too long.
		USIZE ins_size = INS_Size(ins);
		ASSERT(ins_size < sizeof(ins_buf), "so long ins");
		PIN_SafeCopy(ins_buf, (VOID *)ip, ins_size);

		//���� LogIns ��������ָ���ַ����������Լ�ָ���С�;������ݼ�¼���������ں����ĸ��ٺͷ���
		LogIns(ip, INS_Disassemble(ins).c_str(), INS_Size(ins), ins_buf);

		//��ָ��ִ��ʱ����ָ���ַ����һ���ص����� InsTrace�����ڼ�¼ָ��ִ�е�ַ
		INS_InsertCall(ins, IPOINT_BEFORE,
			(AFUNPTR)InsTrace, //�ص�
			IARG_INST_PTR,
			IARG_END);
	}
}


/// <summary>
/// ���Ĵ�������ת��Ϊ��Ӧ��ö��ֵ
/// </summary>
/// <param name="r">REG ���͵Ĳ��� r</param>
/// <returns>����һ�� UINT32 ���͵�ֵ</returns>
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
/// ���仯��Ϣд���������ļ�
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
/// ��������ݱ仯д�뵽��������ļ���
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
/// ��¼��ʼ
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
/// ��¼�Ĵ�����
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
/// ��¼�Ĵ���д
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
/// ��ȡ�ڴ�ʱ��¼����
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
/// ��¼�ڴ�д�����ĵ�ַ��Ϣ
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
/// ��¼�ڴ�д�����������Ϣ
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
/// ָ���׮�ص�
/// </summary>
/// <param name="ins"></param>
/// <param name="v"></param>
/// <returns></returns>
VOID Instruction(INS ins, VOID *v) 
{
	//����ǰָ���ַ��ֵ������ address
	ADDRINT address = INS_Address(ins);

	//�жϵ�ǰָ���ַ�Ƿ��ڹ��˷�Χ�ڣ��������ֱ�ӷ���
	const bool filtered = address < filter_ip_low || filter_ip_high <= address;
	if (filtered) return;

	//����һ������Ϊ 0x20 ���ֽ������� ins_buf ���ڱ���ָ�����ݣ�����ȡ��ǰָ��ȣ��ֽ��������洢�ڱ��� ins_size ��
	UINT8 ins_buf[0x20];  // instructions won't be too long.
	USIZE ins_size = INS_Size(ins);
	ASSERT(ins_size < sizeof(ins_buf), "so long ins");
	PIN_SafeCopy(ins_buf, (VOID *)address, ins_size);

	//���� LogIns ����������ǰָ���ַ��ָ��ķ�����ַ�����ָ����Լ�ָ��������Ϊ����������Щ��Ϣһ��д�뵽��������ļ���
	LogIns(address, INS_Disassemble(ins).c_str(), INS_Size(ins), ins_buf);

	//���� INS_InsertCall ��������ָ��ִ��ǰ����һ����¼��ʼ�ĺ������� RecordStart�������߳� ID��ָ���ַ��ָ��ȵ���Ϣ��Ϊ�������ݸ���¼������
	//����ʹ���� CALL_ORDER_FIRST ������֤���м�¼�������� RecordStart ����֮��ִ��
	INS_InsertCall(
		ins, IPOINT_BEFORE, (AFUNPTR)RecordStart, IARG_THREAD_ID,
		IARG_INST_PTR,
		IARG_UINT32, (UINT32)INS_Size(ins),
		IARG_CALL_ORDER, CALL_ORDER_FIRST,
		IARG_END
	);

	UINT32 rRegs = INS_MaxNumRRegs(ins);//���Ĵ���
	UINT32 wRegs = INS_MaxNumWRegs(ins);//д�Ĵ���
	UINT32 memOps = INS_MemoryOperandCount(ins);//��ȡ��ǰָ�����漰���ڴ��������Memory Operand��������

	// INS_InsertPredicatedCall to skip inactive CMOVs and REPs.
	//������ǰָ��Ķ��Ĵ����б�
	for (UINT32 i = 0; i < rRegs; i++) 
	{
		//INS_RegR(ins, i)�������ص�ǰָ���е�i��Դ��������Ŀ����������漰���ļĴ���������ins��ʾ��ǰ��ָ�����
		REG r = INS_RegR(ins, i);
		
		//REG_is_gr(REG_FullRegName(r))���������ж�ָ���ļĴ����Ƿ���ͨ�üĴ�����General-purpose Register��
		if (!REG_is_gr(REG_FullRegName(r))) continue;
		
		//����ÿһ����ͨ�üĴ����Ķ��Ĵ��������� INS_InsertPredicatedCall ������
		//��ָ��ִ��ǰ����һ����¼�Ĵ�����ȡ�ĺ������� RecordRegRead��
		//�����߳� ID���Ĵ���ö��ֵ���Ĵ������󡢼Ĵ�����С����Ϣ��Ϊ�������ݸ���¼����
		INS_InsertPredicatedCall(
			ins, IPOINT_BEFORE, (AFUNPTR)RecordRegRead, IARG_THREAD_ID,
			IARG_UINT32, RegToEnum(r),
			IARG_REG_CONST_REFERENCE, r,
			IARG_UINT32, REG_Size(r),
			IARG_END
		);
	}

	//������ǰָ���д�Ĵ����б�
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

		//����ǰָ���Ƿ�֧�����ָ����ڷ�֧����óɹ�ʱ����һ����¼�Ĵ���д��ĺ�������
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

	//�����ǰָ���� XSAVE ָ���ֱ�ӷ��أ���Ϊ��ָ�δ��֧��
	if (INS_Mnemonic(ins) == "XSAVE") 
	{
		// Still not supported. 
		return;
	}

	//������ǰָ����ڴ�������б�
	for (UINT32 i = 0; i < memOps; i++) 
	{
		//����������Ƕ������������� INS_InsertPredicatedCall ��������ָ��ִ��ǰ����һ����¼�ڴ��ȡ�ĺ������� RecordMemRead
		if (INS_MemoryOperandIsRead(ins, i)) 
		{
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead, IARG_THREAD_ID,
				IARG_MEMORYOP_EA, i,
				IARG_MEMORYREAD_SIZE,
				IARG_END
			);
		}

		//�����������д��������������ָ��ִ��ǰ����һ����¼�ڴ�д��ĺ������� RecordMemWrite1
		if (INS_MemoryOperandIsWritten(ins, i)) 
		{
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite1, IARG_THREAD_ID,
				IARG_MEMORYOP_EA, i,
				IARG_REG_VALUE, writeea_scratch_reg,
				IARG_RETURN_REGS, writeea_scratch_reg,
				IARG_END
			);

			//��鵱ǰָ���Ƿ���С���ա�ЧӦ����ִ�к��������������ת�Ƶ���һ��ָ�������У����ڸ�ָ��֮�����һ���ص�����RecordMemWrite2����¼�ڴ�д�����
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
/// ���ٻص�
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
/// �߳������ص�����
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
/// ��ʼ���������ļ�
/// </summary>
void Init()
{
	InitFiles();
}


/// <summary>
/// ����
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
/// ������
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

	//��ʼ���������ļ�
	Init();
	
	//��ȡһ�����߼Ĵ��������ڴ洢��ʱ����
	writeea_scratch_reg = PIN_ClaimToolRegister();
	if (!REG_valid(writeea_scratch_reg)) {
		fprintf(stderr, "[!] Failed to claim a scratch register.\n");
		return 1;
	}

	//���� IMG_AddInstrumentFunction �������� ImageLoad ����ע��Ϊӳ�����ʱ�Ļص�����
	IMG_AddInstrumentFunction(ImageLoad, 0);

	//���� INS_AddInstrumentFunction �������� Instruction ����ע��Ϊָ��ִ��ʱ�Ļص�����
	INS_AddInstrumentFunction(Instruction, 0);

	//���� TRACE_AddInstrumentFunction �������� Trace ����ע��Ϊ����ʱ�Ļص�����
	TRACE_AddInstrumentFunction(Trace, 0);

	//���� PIN_AddThreadStartFunction �������� ThreadStart ����ע��Ϊ�߳̿�ʼʱ�Ļص�����
    PIN_AddThreadStartFunction(ThreadStart, 0);

	//���� PIN_AddFiniFunction �������� Fini ����ע��Ϊ�������ʱ�Ļص�����
    PIN_AddFiniFunction(Fini, 0);

    //��ʼִ�б������Ķ����Ƴ��򣬲��������״̬��ֱ���������н���
    PIN_StartProgram();    
    return 0;
}

