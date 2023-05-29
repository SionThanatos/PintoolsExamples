#配置文件

EXE_PATH = r"C:\Users\ZAI\Desktop\Research\pin\PintoolsExamples\PinVmpMiasm\testvmp2\test.vmp_2.13.8_pro.exe"
# EXE_PATH = "C:\\Users\\Moon\\Desktop\\vmp1.81\\test.vmp_2.13.8_pro.exe"
# EXE_PATH = "C:\\Users\\Moon\\Desktop\\vmp1.81\\test.vmp_1.81_demo.exe"
# EXE_PATH = "D:\\papers\\test_asm\\test_pin\\base64_vmp\\base64.vmp_2.13.8.exe"
# EXE_PATH = "D:\\papers\\pin\\pin-3.2-81205-msvc-windows\source\\tools\\MyPinTool\\py\\work\\bin_op.vmp_2.exe"
START_ADDR = 0x401000
END_ADDR = 0x040101A #0x0401169 #0x40127C
VM = 'vmp'  # vmp/cv/vmp3

# File Path
PIN_PATH = 'D:\\reverse\\pin-windows\\pin\\ia32\\bin\\pin.exe'
PIN_TOOL_PATH = 'C:\\Users\\ZAI\\Desktop\\Research\\pin\\PintoolsExamples\\PinVmpMiasm\\Debug\\PinVmpMiasm.dll'

PIN_CMD = '%s  -t %s -- %s' % (PIN_PATH, PIN_TOOL_PATH, EXE_PATH)

BASE_PATH = 'C:\\Users\\ZAI\\Desktop\\Research\\pin\\PintoolsExamples\\PinVmpMiasm\\PythonVmpReport\\PythonVmpReport\\'
WORK_PATH = BASE_PATH + 'work\\'

INS_PATH = WORK_PATH + 'bin.ins'
TRACE_PATH = WORK_PATH + 'bin.trace'

REPORT_PATH = BASE_PATH + "report\\index.html"
BROWSER_PATH = '"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"'
IMAGE_FOLDER = BASE_PATH + 'report\\image\\'

# Report
MAX_ROW = 300

