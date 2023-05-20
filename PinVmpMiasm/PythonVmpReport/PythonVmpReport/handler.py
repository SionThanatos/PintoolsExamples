
import config

from symexec import SymExecObject

class Handler(SymExecObject):
    """
    Handler，该类继承自 SymExecObject。
    它代表了一组连续的基本块（basic block），以及它们在程序中的执行顺序。
    每个 Handler 对象都有一个 head 和一个 tail 基本块，分别表示此处理器对象的第一和最后一个基本块
    Handler 类还定义了许多方法和属性用于获取、修改和检查相关的属性
    """

    DEFAULT_NAME = 'Handler'

    def __init__(self):
        self.blocks = []
        self.head = None
        self.tail = None

        self.copy = [] # same handler

        self._name = None

    @property
    def name(self):
        """
        name 属性返回当前处理器对象的名称（如果没有指定，则默认为其地址值）
        """
        if self._name:
            return self._name
        else:
            return 'Handler_%x' % self.addr

    def __repr__(self):
        return '<%s>' % self.name

    def add_block(self, block):
        """
        add_block() 方法用于将一个新的基本块添加到当前处理器对象的末尾，并且根据现有的基本块结构来检查其是否处于正确的位置
        """
        if not self.head:
            self.head = block

        if self.tail:
            if block.addr not in self.tail.nexts:
                return False

        self.blocks.append(block)
        self.tail = block

        return True

    def add_copy(self, handler):
        """
        add_copy 用于将一个 Handler 对象添加到当前处理对象的副本列表
        """
        self.copy.append(handler)


    @property
    def is_valid(self):
        return self.head is not None

    @property
    def addr(self):
        return self.head.addr


    @property
    def bytes(self):
        return ''.join(b.bytes for b in self.blocks)

    @property
    def instructions(self):
        ins = []
        for b in self.blocks:
            ins += b.instructions
        return ins

    @property
    def ins_str(self):
        """
        ins_str 返回一个包含当前处理器对象所有指令字符串拼接而成的字符串
        """
        return '\n'.join(b.ins_str for b in self.blocks)    


    def __str__(self):
        buf = self.name
        buf += '(%#x) %d blocks' % (self.addr, len(self.blocks))
        for b in self.blocks:
            buf += '\n\t' + repr(b)
        
        if len(self.copy) > 0:
            buf += '\n[COPY] '+ '\n'.join(str(i) for i in self.copy)

        return buf
    



