

class Instruction(object):


    def __init__(self, addr, disasm, bytes):
        self.addr = addr
        self.disasm = disasm
        self.bytes = bytes
        self.traces = []

    def __str__(self):
        # return '%#x\t%s\t%s' % (self.addr, 
        #     self.bytes.encode('hex').upper(),
        #     self.disasm)
        return '%#x\t%s' % (self.addr, self.disasm)

    def __repr__(self):
        return '<INS %#x %s>' % (self.addr, self.disasm)

    @property
    def size(self):
        return len(self.bytes)

    def add_trace(self, trace):
        self.traces.append(trace)

    def print_trace(self, i=0):
        if len(self.traces) == 0:
            print( '[!] No Trace at %s' % self)
        if i >= len(self.traces):
            print( self.traces[-1])
        else:
            print( self.traces[i])


'''
def parse_file(filepath):
    for line in open(filepath, 'rb').read().splitlines():
        #addr, diasm, hexbytes = line.split('\t')
        addr, diasm, hexbytes = line.split('\t')
        yield Instruction(int(addr, 16), diasm, hexbytes.decode('hex'))
        #yield Instruction(int(addr, 16), diasm, codecs.decode(hexbytes, 'hex'))
'''

def parse_file(filepath):

    with open(filepath, 'rb') as f:
        for line in f:
            decoded_line = line.decode('utf-8')
            parts = decoded_line.strip().split('\t')
            addr = int(parts[0], 16)
            diasm = parts[1]
            hexbytes = bytes.fromhex(parts[2])
            #该函数生成一个 Instruction 对象，包括地址、反汇编指令和十六进制字节
            yield Instruction(addr, diasm, hexbytes)


if __name__ == '__main__':
    for ins in parse_file('../bin.ins'):
        print(ins)