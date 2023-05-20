#符号执行

from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container

from miasm.ir.symbexec import SymbolicExecutionEngine


from miasm.arch.x86 import regs
from miasm.arch.x86.regs import *

from miasm.expression.expression import *
from miasm.expression.simplifications import expr_simp

from miasm.core import asmblock
from miasm.ir.translators import Translator


import config




# patch shift

def patch_shift_rotate():
    import miasm.expression.expression as m2_expr
    from miasm.expression.simplifications import expr_simp
    from miasm.arch.x86.arch import mn_x86, repeat_mn, replace_regs
    from miasm.expression.expression_helper import expr_cmps, expr_cmpu
    import miasm.arch.x86.regs as regs
    from miasm.ir.ir import IntermediateRepresentation, IRBlock, AssignBlock

    import  miasm.arch.x86.sem
    get_shift = miasm.arch.x86.sem.get_shift
    update_flag_znp = miasm.arch.x86.sem.update_flag_znp

    def patch_shift_tpl(op, ir, instr, a, b, c=None, op_inv=None, left=False,
               custom_of=None):
        # assert c is not None
        if c is not None:
            shifter = get_shift(a, c)
        else:
            shifter = get_shift(a, b)

        res = m2_expr.ExprOp(op, a, shifter)
        cf_from_dst = m2_expr.ExprOp(op, a,
                                     (shifter - m2_expr.ExprInt(1, a.size)))
        cf_from_dst = cf_from_dst.msb() if left else cf_from_dst[:1]

        new_cf = cf_from_dst
        i1 = m2_expr.ExprInt(1, size=a.size)
        if c is not None:
            # There is a source for new bits
            isize = m2_expr.ExprInt(a.size, size=a.size)
            mask = m2_expr.ExprOp(op_inv, i1, (isize - shifter)) - i1

            # An overflow can occured, emulate the 'undefined behavior'
            # Overflow behavior if (shift / size % 2)
            base_cond_overflow = c if left else (
                c - m2_expr.ExprInt(1, size=c.size))
            cond_overflow = base_cond_overflow & m2_expr.ExprInt(a.size, c.size)
            if left:
                # Overflow occurs one round before right
                mask = m2_expr.ExprCond(cond_overflow, mask, ~mask)
            else:
                mask = m2_expr.ExprCond(cond_overflow, ~mask, mask)

            # Build res with dst and src
            res = ((m2_expr.ExprOp(op, a, shifter) & mask) |
                   (m2_expr.ExprOp(op_inv, b, (isize - shifter)) & ~mask))

            # Overflow case: cf come from src (bit number shifter % size)
            cf_from_src = m2_expr.ExprOp(op, b,
                                         (c.zeroExtend(b.size) &
                                          m2_expr.ExprInt(a.size - 1, b.size)) - i1)
            cf_from_src = cf_from_src.msb() if left else cf_from_src[:1]
            new_cf = m2_expr.ExprCond(cond_overflow, cf_from_src, cf_from_dst)

        # Overflow flag, only occured when shifter is equal to 1
        if custom_of is None:
            value_of = a.msb() ^ a[-2:-1] if left else b[:1] ^ a.msb()
        else:
            value_of = custom_of

        # Build basic blocks
        e_do = [
            m2_expr.ExprAssign(regs.cf, new_cf),
            m2_expr.ExprAssign(regs.of, m2_expr.ExprCond(shifter - i1,
                                                 m2_expr.ExprInt(0, regs.of.size),
                                                 value_of)),
            m2_expr.ExprAssign(a, res),
        ]
        e_do += update_flag_znp(res)

        return (e_do, [])

    miasm.arch.x86.sem._shift_tpl = patch_shift_tpl



    def patch_rotate_tpl(ir, instr, dst, src, op, left=False):
        '''Template to generate a rotater with operation @op
        A temporary basic block is generated to handle 0-rotate
        @op: operation to execute
        @left (optional): indicates a left rotate if set, default is False
        '''
        # Compute results
        shifter = get_shift(dst, src)
        res = m2_expr.ExprOp(op, dst, shifter)

        # CF is computed with 1-less round than `res`
        new_cf = m2_expr.ExprOp(
            op, dst, shifter - m2_expr.ExprInt(1, size=shifter.size))
        new_cf = new_cf.msb() if left else new_cf[:1]

        # OF is defined only for @b == 1
        new_of = m2_expr.ExprCond(src - m2_expr.ExprInt(1, size=src.size),
                                  m2_expr.ExprInt(0, size=of.size),
                                  res.msb() ^ new_cf if left else (dst ^ res).msb())

        # Build basic blocks
        e_do = [m2_expr.ExprAssign(cf, new_cf),
                m2_expr.ExprAssign(of, new_of),
                m2_expr.ExprAssign(dst, res)
                ]
        # Don't generate conditional shifter on constant
        return (e_do, [])

        # if isinstance(shifter, m2_expr.ExprInt):
        #     if int(shifter) != 0:
        #         return (e_do, [])
        #     else:
        #         return ([], [])
        # e = []
        # lbl_do = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
        # lbl_skip = m2_expr.ExprId(ir.get_next_label(instr), ir.IRDst.size)
        # e_do.append(m2_expr.ExprAssign(ir.IRDst, lbl_skip))
        # e.append(m2_expr.ExprAssign(
        #     ir.IRDst, m2_expr.ExprCond(shifter, lbl_do, lbl_skip)))
        # return (e, [IRBlock(lbl_do.name, [AssignBlock(e_do, instr)])])

    miasm.arch.x86.sem._rotate_tpl = patch_rotate_tpl

    def patch_rotate_with_carry_tpl(ir, instr, op, dst, src):
        # Compute results
        shifter = get_shift(dst, src).zeroExtend(dst.size + 1)
        result = m2_expr.ExprOp(op, m2_expr.ExprCompose(dst, cf), shifter)

        new_cf = result[dst.size:dst.size +1]
        new_dst = result[:dst.size]

        result_trunc = result[:dst.size]
        if op == '<<<':
            of_value = result_trunc.msb() ^ new_cf
        else:
            of_value = (dst ^ result_trunc).msb()
        # OF is defined only for @b == 1
        new_of = m2_expr.ExprCond(src - m2_expr.ExprInt(1, size=src.size),
                                  m2_expr.ExprInt(0, size=of.size),
                                  of_value)


        # Build basic blocks
        e_do = [m2_expr.ExprAssign(cf, new_cf),
                m2_expr.ExprAssign(of, new_of),
                m2_expr.ExprAssign(dst, new_dst)
                ]

        return (e_do, [])
        # Don't generate conditional shifter on constant
        # if isinstance(shifter, m2_expr.ExprInt):
        #     if int(shifter) != 0:
        #         return (e_do, [])
        #     else:
        #         return ([], [])
        # e = []
        # lbl_do = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
        # lbl_skip = m2_expr.ExprId(ir.get_next_label(instr), ir.IRDst.size)
        # e_do.append(m2_expr.ExprAssign(ir.IRDst, lbl_skip))
        # e.append(m2_expr.ExprAssign(
        #     ir.IRDst, m2_expr.ExprCond(shifter, lbl_do, lbl_skip)))
        # return (e, [IRBlock(lbl_do.name, [AssignBlock(e_do, instr)])])

    miasm.arch.x86.sem.rotate_with_carry_tpl = patch_rotate_with_carry_tpl


    def patch_bsr_bsf(ir, instr, dst, src, op_name):
        """
        IF SRC == 0
            ZF = 1
            DEST is left unchanged
        ELSE
            ZF = 0
            DEST = @op_name(SRC)
        """
        # lbl_src_null = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
        # lbl_src_not_null = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
        # lbl_next = m2_expr.ExprId(ir.get_next_label(instr), ir.IRDst.size)

        # aff_dst = m2_expr.ExprAssign(ir.IRDst, lbl_next)
        # e = [m2_expr.ExprAssign(ir.IRDst, m2_expr.ExprCond(src,
        #                                                 lbl_src_not_null,
        #                                                 lbl_src_null))]
        # e_src_null = []
        # e_src_null.append(m2_expr.ExprAssign(zf, m2_expr.ExprInt(1, zf.size)))
        # # XXX destination is undefined
        # e_src_null.append(aff_dst)

        # e_src_not_null = []
        # e_src_not_null.append(m2_expr.ExprAssign(zf, m2_expr.ExprInt(0, zf.size)))
        # e_src_not_null.append(m2_expr.ExprAssign(dst, m2_expr.ExprOp(op_name, src)))
        # e_src_not_null.append(aff_dst)

        return [], []
        # return e, [IRBlock(lbl_src_null.name, [AssignBlock(e_src_null, instr)]),
                   # IRBlock(lbl_src_not_null.name, [AssignBlock(e_src_not_null, instr)])]

    # miasm.arch.x86.sem.bsr_bsf = patch_bsr_bsf

    def patch_div(ir, instr, src1):
        """
        将除法指令调整为使用指定的符号对象 (src1) 来执行除法运算
        ir 是一个 IR 对象，表示当前的中间代码；
        instr 是一个指令对象，表示要修补的除法指令；
        src1 是一个符号对象，包含被除数
        """

        # print( '[*] Calling patched div.'

        #先根据 src1 的大小确定要使用的寄存器和寄存器组合
        e = []
        size = src1.size
        if size == 8:
            src2 = mRAX[instr.mode][:16]
        elif size in [16, 32, 64]:
            s1, s2 = mRDX[size], mRAX[size]
            src2 = m2_expr.ExprCompose(s2, s1)
        else:
            raise ValueError('div arg not impl', src1)

        c_d = m2_expr.ExprOp('udiv', src2, src1.zeroExtend(src2.size))
        c_r = m2_expr.ExprOp('umod', src2, src1.zeroExtend(src2.size))

        # if 8 bit div, only ax is affected
        if size == 8:
            e.append(m2_expr.ExprAssign(src2, m2_expr.ExprCompose(c_d[:8], c_r[:8])))
        else:
            e.append(m2_expr.ExprAssign(s1, c_r[:size]))
            e.append(m2_expr.ExprAssign(s2, c_d[:size]))

        return e, []

        # lbl_div = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
        # lbl_except = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
        # lbl_next = m2_expr.ExprId(ir.get_next_label(instr), ir.IRDst.size)

        # do_div = []
        # do_div += e
        # do_div.append(m2_expr.ExprAssign(ir.IRDst, lbl_next))
        # blk_div = IRBlock(lbl_div.name, [AssignBlock(do_div, instr)])

        # do_except = []
        # do_except.append(m2_expr.ExprAssign(exception_flags, m2_expr.ExprInt(
        #     EXCEPT_DIV_BY_ZERO, exception_flags.size)))
        # do_except.append(m2_expr.ExprAssign(ir.IRDst, lbl_next))
        # blk_except = IRBlock(lbl_except.name, [AssignBlock(do_except, instr)])

        # e = []
        # e.append(m2_expr.ExprAssign(ir.IRDst,
        #                          m2_expr.ExprCond(src1, lbl_div, lbl_except)))

        # return e, [blk_div, blk_except]

    miasm.arch.x86.sem.div = patch_div
    miasm.arch.x86.sem.mnemo_func['div'] = patch_div


    def patch_idiv(ir, instr, src1):
        e = []
        size = src1.size

        if size == 8:
            src2 = mRAX[instr.mode][:16]
        elif size in [16, 32, 64]:
            s1, s2 = mRDX[size], mRAX[size]
            src2 = m2_expr.ExprCompose(s2, s1)
        else:
            raise ValueError('div arg not impl', src1)

        c_d = m2_expr.ExprOp('idiv', src2, src1.signExtend(src2.size))
        c_r = m2_expr.ExprOp('imod', src2, src1.signExtend(src2.size))

        # if 8 bit div, only ax is affected
        if size == 8:
            e.append(m2_expr.ExprAssign(src2, m2_expr.ExprCompose(c_d[:8], c_r[:8])))
        else:
            e.append(m2_expr.ExprAssign(s1, c_r[:size]))
            e.append(m2_expr.ExprAssign(s2, c_d[:size]))

        return e, []

        # lbl_div = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
        # lbl_except = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
        # lbl_next = m2_expr.ExprId(ir.get_next_label(instr), ir.IRDst.size)

        # do_div = []
        # do_div += e
        # do_div.append(m2_expr.ExprAssign(ir.IRDst, lbl_next))
        # blk_div = IRBlock(lbl_div.name, [AssignBlock(do_div, instr)])

        # do_except = []
        # do_except.append(m2_expr.ExprAssign(exception_flags, m2_expr.ExprInt(
        #     EXCEPT_DIV_BY_ZERO, exception_flags.size)))
        # do_except.append(m2_expr.ExprAssign(ir.IRDst, lbl_next))
        # blk_except = IRBlock(lbl_except.name, [AssignBlock(do_except, instr)])

        # e = []
        # e.append(m2_expr.ExprAssign(ir.IRDst,
        #                          m2_expr.ExprCond(src1, lbl_div, lbl_except)))

        # return e, [blk_div, blk_except]

    miasm.arch.x86.sem.idiv = patch_idiv    
    miasm.arch.x86.sem.mnemo_func['idiv'] = patch_idiv

    # print( '[*] Miasm patched.'

patch_shift_rotate()


#####################################


class TranslatorC2(Translator):

    __LANG__ = "C2"

    def from_ExprId(self, expr):
        if isinstance(expr.name, asmblock.AsmRaw):
            return "0x%x" % expr.name.offset
        return str(expr)

    def from_ExprInt(self, expr):
        #Use int(expr) on ExprInt instead of expr.arg.arg
        #return "%#x" % expr.arg.arg
        return "%#x" % int(expr)

    def from_ExprAssign(self, expr):
        return "%s = %s" % tuple(map(self.from_expr, (expr.dst, expr.src)))

    def from_ExprCond(self, expr):
        return "(%s)?(%s):(%s)" % tuple(map(self.from_expr,
                                        (expr.cond, expr.src1, expr.src2)))

    def from_ExprMem(self, expr):
        if expr.size not in [8, 16, 32, 64]:
            raise NotImplementedError('Unsupported mem size: %d' % expr.size)

        #return "*(uint%d_t *)(%s)" % (expr.size, self.from_expr(expr.arg))
        return "*(uint%d_t *)(%s)" % (expr.size, self.from_expr(expr.ptr))

    def from_ExprOp(self, expr):

        if len(expr.args) == 1:
            if expr.op in ['!', '-']:
                # return "(~ %s)&0x%x" % (self.from_expr(expr.args[0]),
                                        # size2mask(expr.args[0].size))
                return "%s(%s)" % (expr.op,  self.from_expr(expr.args[0]))
            elif expr.op == 'parity':
                # ignored
                return '0'

            else:
                raise NotImplementedError('Unknown op: %r' % expr.op)

        elif len(expr.args) == 2:
            if expr.op in ['==', '+', '-', '*', '/', '^', '&', '|', '>>', '<<' ]:
                # return '(((%s&0x%x) %s (%s&0x%x))&0x%x)' % (
                #     self.from_expr(expr.args[0]), size2mask(expr.args[0].size),
                #     str(expr.op),
                #     self.from_expr(expr.args[1]), size2mask(expr.args[1].size),
                #     size2mask(expr.args[0].size))
                return  "(%s) %s (%s)" %(self.from_expr(expr.args[0]),str(expr.op),self.from_expr(expr.args[1]))

            elif expr.op == '<<<': # TODO: <<< is << ?
                return  "(%s) %s (%s)" %(self.from_expr(expr.args[0]),'<<',self.from_expr(expr.args[1]))

            elif expr.op == '>>>': 
                return  "(%s) %s (%s)" %(self.from_expr(expr.args[0]),'>>',self.from_expr(expr.args[1]))

            elif expr.op == 'a>>':
                return  "(%s) %s (%s)" %(self.from_expr(expr.args[0]),'>>',self.from_expr(expr.args[1]))

            elif expr.op == 'umod' or expr.op == 'imod':
                return  "(%s) %s (%s)" %(self.from_expr(expr.args[0]),'%',self.from_expr(expr.args[1]))

            elif expr.op == 'udiv' or expr.op == 'idiv':
                return  "(%s) %s (%s)" %(self.from_expr(expr.args[0]),'/',self.from_expr(expr.args[1]))

            elif expr.op == "segm":
                # ignore seg register
                return str(self.from_expr(expr.args[1]))

            else:
                raise NotImplementedError('Unknown op: %r' % expr.op)

        elif len(expr.args) >= 3 and expr.is_associative():  # ?????
            oper = ['(%s)' % (self.from_expr(arg))
                    for arg in expr.args]
            oper = str(expr.op).join(oper)
            return oper

        else:
            raise NotImplementedError('Unknown op: %s' % expr.op)


    def from_ExprSlice(self, expr):
        """
        从 Miasm ExprSlice 对象中提取的表达式转换为符号执行引擎可处理的 C 表达式
        """
        # XXX check mask for 64 bit & 32 bit compat
        #转换过程中使用 Miasm 表达式的参数（arg）、起始位置（start）和结束位置（stop）
        #它将从 arg 中选择一系列位，类似于 Python 中的切片。
        #其返回值是 C 语言中代表所选位的逐位异或（bitwise XOR）运算结果的字符串
        #该方法按照 arg 的类型和大小从输入中计算出要截取的长度。 
        #然后，使用 C 语言的移位运算符将 arg 向右移动 start 次以确保开始位置可以正确对齐。 
        #最后，使用相应位掩码与运算符使得输出仅包含所需的位，并以字符串格式返回
        return "((%s>>%d) & 0x%X)" % (self.from_expr(expr.arg),
                                      expr.start,
                                      (1 << (expr.stop - expr.start)) - 1)

    
    def from_ExprCompose(self, expr):
        """
        从 Miasm ExprComopse 对象中提取的表达式转换为符号执行引擎可处理的 C 表达式
        """

        #检查提供的表达式的大小是否为 8、16、32 或 64 位 如果不是，则抛出“不支持的大小”异常
        if expr.size not in [8, 16, 32, 64]:
            raise NotImplementedError('Unsupported size: %d' % expr.size)

        out = []
        # XXX check mask for 64 bit & 32 bit compat
        dst_cast = "uint%d_t" % expr.size
        for index, arg in expr.iter_args():
            out.append("(((%s)(%s & 0x%X)) << %d)" % (dst_cast,
                                                      self.from_expr(arg),
                                                      (1 << arg.size) - 1,
                                                      index))
        #使用“ |”操作将数组中的所有元素连接起来，生成完整的 C 表达式并返回
        out = ' | '.join(out)
        return '(' + out + ')'



def filter_common(expr_value):
    """
    过滤出现频率较高的表达式和常量
    """

    #定义了一个空列表 out 来存储符合条件的元组
    out = []

    #对传入的元组按照 (expr, value) 排序
    for expr, value in sorted(expr_value):
        if (expr, value) in symbols_init.items():
            continue
        if (expr, value) in addition_infos.items():
            continue
        if expr in [regs.zf, regs.cf, regs.nf, regs.of, regs.pf, regs.af,
                    ExprId('IRDst', 32), regs.EIP]:
            continue

        expr = expr_simp(expr.replace_expr(addition_infos))
        value = expr_simp(value.replace_expr(addition_infos))
        
        if expr == value:
            continue

        out.append((expr, value))

    return out

def filter_vmp(expr_value):
    """
        Only care EBP, ESI, memory(base by EBP, EDI).
    """
    out = []
    for expr, value in expr_value:

        if expr in [regs.EBP, regs.ESI]:
            out.append((expr, value))

        elif isinstance(expr, ExprMem):            
            if regs.ESP in expr or regs.ESP_init in expr: 
                continue  # skip ss:[esp] junk
            out.append((expr, value))

        else:
            #out.append((expr, value))
            pass

    return out

def filter_cv(expr_value):

    return expr_value


def state_to_expr(sb, vm='vmp', trans = False):
    """
    主要功能是将 sb 对象中的符号表转换为 C 语言表达式
    sb 是一个状态对象，包含了当前的寄存器状态和内存状态
    vm 是一个字符串，表示当前的虚拟机类型，默认为 'vmp'
    trans 是一个布尔值，如果为 True，则在输出中使用 C 语言风格的表达式
    """

    #删除所有地址高于堆栈指针 (ESP) 的内存
    sb.del_mem_above_stack(regs.ESP)

    #过滤掉一些通用的符号表项
    out = filter_common(sb.symbols.items())

    #根据虚拟机类型 (vm) 进一步筛选此列表
    if vm == 'vmp':
        sb.del_mem_above_stack(regs.EBP)
        out = filter_vmp(out)
    elif vm == 'cv':
        out = filter_cv(out)
    else:
        # raise NotImplementedError('Unknown VM: %s' % vm)
        pass

    buf = ''
    for expr, value in out:
        #在生成 C 代码时，如果 trans 参数设置为 True，
        #则会创建一个 TranslatorC2() 对象并执行 from_expr() 方法将符号表项和值转换为 C 语言风格的表达式，否则直接使用原始表达式
        c2 = TranslatorC2()
        if trans:
            expr_c = c2.from_expr(expr)
            value_c = c2.from_expr(value)
        else:
            expr_c = expr
            value_c = value

        buf +=  '\t%s = %s;\n' % (expr_c, value_c)

    return buf


addition_infos = {}
symbols_init = regs.regs_init.copy()
for expr in symbols_init:
    if expr.size == 1:  # set all flags 0
        symbols_init[expr] = ExprInt(0, 1)


def symexec(handler):
    """
    实现了符号执行的逻辑。
    该函数使用 Miasm 框架在 x86_32 架构上进行模拟器操作
    """
    from miasm.arch.x86.arch import mn_x86
    from miasm.core.locationdb import LocationDB

    #从 handler 中获取字节码指令序列 inst_bytes
    inst_bytes = handler.bytes_without_jmp
    #inst_disa = mn_x86.dis(inst_bytes, 32)

    #使用 Miasm 工具集进行反汇编操作，并创建出机器对象和地址定位数据库（loc_db）
    machine = Machine("x86_32")
    location_db = LocationDB()
    #将字节码传入容器（Container）中，进行解析操作，获得二进制流（bin_stream）
    cont = Container.from_string(inst_bytes,location_db)
    bs = cont.bin_stream
    #使用机器对象中的 dis_engine 方法对二进制流进行解包，返回反汇编指令块 asm_block
    mdis = machine.dis_engine(bs, loc_db=cont.loc_db)

    #在执行期间，我们不会对最后一条指令进行解析，因为它可能不完整
    #我们使用 dont_dis 列表来排除掉这条指令的地址
    end_offset = len(inst_bytes)
    mdis.dont_dis = [end_offset]

    asm_block = mdis.dis_block(0)

    #ira = machine.ira(mdis.loc_db)
    #use ".lifter_model_call" instead of ".ira"'
    #我们使用 lifter_model_call 方法创建 IRA 对象并调用 new_ircfg 方法以得到 IRCFG 对象
    ira = machine.lifter_model_call(location_db)
    #ira.add_block(asm_block)   #删除
    
    #ira_instance = ira()  # 创建ira类的实例
    ircfg = ira.new_ircfg()  # 调用new_ircfg()方法 
    ira.add_asmblock_to_ircfg(asm_block, ircfg)

    #使用 SymbloicExecutionEngine (symb) 进行内存模拟和符号执行
    symb = SymbolicExecutionEngine(ira, symbols_init)

    #cur_addr = symb.run_block_at(ircfg, addr, step=False)(0)
    cur_addr = symb.run_block_at(ircfg,0,step=False)
    count = 0

    #使用 while 循环执行 IRCFG 中的每个基本块，直到到达最后一个基本块
    while cur_addr != ExprInt(end_offset, 32): # execute to end
        #在每个基本块之间切换时，将当前状态 cur_addr 传递给 symb.run_block_at 方法以进行符号执行操作
        cur_addr = symb.run_block_at(ircfg,cur_addr,step=False)
        #cur_addr = symb.run_block_at(ircfg, addr, step=False)(cur_addr)

        #如果计数器 count 的值大于 1000，则认为程序已经陷入死循环，需要退出
        count += 1
        if count > 1000: 
            print( '[!] to many loop at %s' % handler.name)
            break    

    return symb




class SymExecObject(object):
    
    @property    
    def bytes_without_jmp(self):
        """
        Clear all jump instructions.

        jmp -> nop
        jxx -> nop
        call xxx -> push ret_addr
        """

        buf =''

        from miasm.arch.x86.arch import mn_x86
        from miasm.arch.x86.arch import conditional_branch
        from miasm.arch.x86.arch import unconditional_branch
        from miasm.expression.expression import ExprInt

        #jmp等跳转指令
        branch_name =  conditional_branch + unconditional_branch
        call_name = ['CALL']

        #遍历当前指令列表
        for ins in self.instructions:
            ins_x86 =  mn_x86.dis(ins.bytes, 32)

            COLOR_DISASM = "\033[1;32m"  # 绿色粗体
            COLOR_INS_X86 = "\033[1;35m"  # 紫色粗体
            COLOR_bytes = "\033[1;31m"
            COLOR_RESET = "\033[0m"  # 清除样式

            # 定义文本内容
            disasm_text = "disasm: "
            space_text = "    "  # 些空格

            #import textwrap
            #str_ins_x86 = str(ins_x86)
            #wrapped_ins_x86 = textwrap.fill(str_ins_x86, width=80)

            # 使用颜色代码拼接文本
            colored_disasm = f"{COLOR_DISASM}{disasm_text}{COLOR_RESET}"
            colored_ins_x86 = f"{COLOR_INS_X86}{ins_x86}{COLOR_RESET}"
            colored_bytes = f"{COLOR_bytes}{ins.bytes}{COLOR_RESET}"

            # 打印带颜色的文本
            print(colored_disasm + colored_ins_x86 + space_text+ colored_bytes)
            #print("disasm:",ins_x86,ins.bytes)


            #如果是跳转指令则打上nop
            if ins_x86.name in branch_name:
                buf += '\x90'  #  NOP
                #print("buf",buf)
            elif ins_x86.name in call_name:
                ret_addr = ExprInt(ins.addr + ins.size, 32)
                ins_x86.args = [ret_addr]
                ins_x86.name = 'PUSH'
                buf += (str(mn_x86.asm(ins_x86)[0])[2:-1])
                #print("buf",buf)
            else:
                buf += (str(ins.bytes)[2:-1])
                #print("buf",buf)
                #buf += ins.bytes
        byte_buf = b'' + str(buf)[2:-1].encode()
        return byte_buf


    @property
    def ins_str_with_trace(self):
        buf = ''
        for ins in self.instructions: 
            trace = ins.traces[0]
            buf += str(ins) + '\t; ' + trace.change_str
            buf += '\n'

        return buf

    @property
    def ins_str_without_jmp(self):
        from miasm.arch.x86.disasm import dis_x86_32
        from miasm.core.locationdb import LocationDB
        loc_db = LocationDB()
        buf = self.bytes_without_jmp
        #d = dis_x86_32(buf,loc_db=loc_db)
        machine = Machine("x86_32")
        d = machine.dis_engine(buf, loc_db=loc_db)
        d.dont_dis = [len(buf)]
        return str(d.dis_block(0))


    def to_sym_state(self):
        import symexec
        sb = symexec.symexec(self)
        return sb


    def to_expr(self):
        try:
            sb = self.to_sym_state()
            import symexec
            return symexec.state_to_expr(sb, config.VM, False)
        except Exception as e:
            return 'Error %s' % e

    def to_c(self):
        try:
            sb = self.to_sym_state()
            import symexec
            c_str = symexec.state_to_expr(sb, config.VM, True)
            return c_str
        except Exception as e:
            return 'Error %s' % e

if __name__ == '__main__':
    # main() 测试用

    vAdd = '8b45000145049c8f4500e9ea140000'.decode('hex')
    vNor = '8b45008b5504f7d0f7d221d08945049c8f4500e97b140000'.decode('hex')
    vShl = '8b45008a4d0483ed02d3e08945049c8f4500e929ffffff'.decode('hex')

    symb = symexec(vAdd)
    print(state_to_c(symb))

    # c2 = TranslatorC2()
    # for expr in symb.modified_mems():
    #     print( expr
    #     print( c2.from_expr(expr_simp(expr))
    # symexec(vNor)
    # symexec(vShl)