# coding:utf-8

import struct
#import cPickle
import pickle as cPickle
import time
import os
import sys

from functools import wraps


import instruction
import trace
import handler
import config
import report

from block import BasicBlock, BlockLoop


# so @profile won't throw error when running without line_profiler.
if 'profile' not in  dir(__builtins__):
    profile = lambda func: func

def time_profile(orig_func):
    @wraps(orig_func) # wraps make wrap_func.__name__ = func
    def wrap_func(*args, **kwargs):
        time_start = time.time()
        result = orig_func(*args, **kwargs)
        time_end = time.time()
        print('[*] Running %s(): %0.4f seconds' % (orig_func.__name__, time_end - time_start))
        return result
    return wrap_func

#基本块管理类
class BBLManager(object):

    def __init__(self):
        """
        初始化类实例
        """
        #instructions 是一个字典，用来存储地址和指令
        self.instructions = {} # (addr, ins)

        #blocks 是一个字典，用来存储地址和基本块
        self.blocks = {}  # (addr, block)

        #loops 是一个集合，用来存储循环地址
        self.loops = set()

        #head_block 是一个基本块，用来存储解析短语的第一个基本块
        self.head_block = None  # first block in parse phrase

        #traces 是一个列表，用来存储所有的trace
        self.traces = []

        #handler_traces 是一个列表，用来存储所有的handler trace
        self.handler_traces = []

        #分发器
        self.dispatcher = None  # We only support single dispatcher. TODO: multi-dispatchers.

        #handlers 是一个字典，用来存储地址和处理器
        self.handlers = {}    # {addr, Handler}


    def add_trace(self, trace):
        self.traces.append(trace)

    @property #@property 装饰器被用来将这个函数转化为只读属性，可以像访问普通属性一样访问这个函数。当你在使用这个属性时，就会自动地调用 head_addr() 函数并返回该函数的返回值
    def head_addr(self):
        return self.head_block.addr


    def add_handler(self, handler):
        """
        向 self.handlers 字典中添加一个处理程序（handler）
        """
        if handler.addr in self.handlers: #如果 handler 的地址已经存在于字典中，则将其作为副本添加到相应的键中
            self.handlers[handler.addr].add_copy(handler)
        else: #如果地址在字典中不存在，则将其作为新键值对加入到字典中
            self.handlers[handler.addr] = handler


    def _add_loop(self, loop):
        """
        将传入的 loop 添加到对象或实例的 loops 属性中
        """
        # return True if a new loop is appended.
        if loop in self.loops:
            return False
        else:
            self.loops.add(loop) # this will call loop.__hash__()
            return True

    def add_ins(self, ins):
        """
        将传入的 loop 添加到对象或实例的 loops 属性中
        """
        self.instructions[ins.addr] = ins

    def get_ins(self, addr):
        return self.instructions[addr]

    @time_profile
    def load_ins_info(self, filename):
        """
        load instructions address, disassembly and binary bytes.
        加载指令（instructions）的地址、反汇编和二进制字节码
        """
        print('[*] Loading instructions from %s' % filename)

        #解析给定文件中的每个指令，并将其添加到对象的指令列表中
        for ins in instruction.parse_file(filename):
            self.add_ins(ins)

            # Init block.
            #对于每个指令，该函数还会创建一个基本块（basic block），并将该指令添加到基本块中
            block = BasicBlock()
            block.add_ins(ins)
            #该基本块会被添加到对象的基本块字典中
            self.blocks[block.addr] = block

        print('[+] %d instructions loaded.' % len(self.instructions))

        # blocks = open(filename, 'rb').read().split('####BBL\n')[1:] # skip first ''
        # for buf in blocks:
        #     lines = buf.splitlines()
        #     try:
        #         start_addr, end_addr, size, ins_count = lines[0].split('\t')
        #     except ValueError,e:
        #         print e, 'at line:', lines
        #         continue

        #     start_addr = int(start_addr,16)
        #     end_addr = int(end_addr, 16)
        #     size = int(size,10)
        #     ins_count =  int(ins_count,10)  # not used.

        #     b = BasicBlock(start_addr, end_addr, size)

            # if not self.head_block:
            #     self.head_block = block

        #     # parse ins
        #     for line in lines[1:]:
        #         addr, dis = line.split('\t')
        #         addr = int(addr,16)
        #         b.ins.append((addr, dis))


        #     if start_addr not in self.blocks:
        #         self.blocks[start_addr] = b
        #     else:
        #         # TODO: handle block at same address.
        #         # of course this will never happen when we use INS trace.
        #         if self.blocks[start_addr].size != b.size:
        #             print '='*40 + 'Block collision!'
        #             print self.blocks[start_addr]
        #             print '='*40
        #             print b
        #             print '='*40

    # ==============================================================================


    @profile
    def _buffer_process_addr(self, filename, start_addr=None, end_addr=None, x64=False):
        """
        buffered io. faster.
        使用缓冲I/O来读取一个文件中存储的地址序列，并返回这些地址
        filename: 表示要读取的文件的路径及文件名
        start_addr: 可选参数，表示从哪个地址开始读取。如果指定了这个参数，则只有在遍历文件中的地址时找到这个地址后才会开始返回结果
        end_addr: 可选参数，表示从哪个地址结束读取。如果指定了这个参数，则会在遍历到这个地址之前停止返回结果
        x64: 可选参数，如果设为True则表示文件中存储的地址是64位（8字节）长，否则是32位（4字节）长，默认值为False
        """
        # get file size.
        #先打开文件并获取文件大小
        f = open(filename, 'rb')
        f.seek(0, 2) # to end
        filesize = f.tell()
        f.seek(0)

        # compatible x86 & x64.
        #按照一定的缓冲区大小（10MB*2）读取文件内容，每次读取的内容都是以指定长度（x64参数可选）为单位的地址序列
        BUFSIZE = 1024*1024*10*2
        if x64:
            ADDR_SIZE = 8
            ADDR_FMT = 'Q'
        else:  # x86
            ADDR_SIZE = 4
            ADDR_FMT = 'I'

        read_size = 0
        started = False
        ended = False

        # read block addr sequence.
        #根据参数start_addr和end_addr指定的起始和结束地址来决定是否需要返回当前缓冲区内的地址，从而实现对指定地址范围内的地址序列的读取
        #如果start_addr和end_addr两个参数都没有被指定，则会返回整个文件中的所有地址数据
        while True:
            addrs = f.read(BUFSIZE) # read larger buffer goes faster.
            read_size += len(addrs)
            if len(addrs) == 0: break
            assert len(addrs) % ADDR_SIZE == 0

            addrs = struct.unpack(ADDR_FMT*(len(addrs)/ADDR_SIZE), addrs)

            # start at start_addr.
            #如果指定了start_addr参数，则只有在遍历到第一个start_addr之后才开始返回结果，即先跳过从文件头至第一个start_addr之间的地址数据
            if start_addr and not started:
                if start_addr not in addrs:
                    continue
                else:
                    addrs = addrs[addrs.index(start_addr): ]
                    started = True

            # end at end_addr
            if end_addr:
                if end_addr in addrs:
                    addrs = addrs[ : addrs.index(end_addr)]
                    ended = True

            # this works faster than "for addr in addrs: yield addr"
            yield addrs

            if read_size % (BUFSIZE) == 0:
                print('\r%0.2f %% processed\t%s' % (read_size*100.0/filesize, time.asctime()))

            if ended:
                break

        f.close()


    def _process_trace(self, filename, start_addr, end_addr, x64=False):
        """
        解析指定的跟踪文件，并遍历其中的所有指令,并将这些指令添加到self.insns字典中
        """
        started = False

        #parse_file()函数会逐行读取跟踪文件中的每一行内容
        for t in trace.parse_file(filename):

            # print t
            #如果地址t.addr等于start_addr，则设置started为True
            if t.addr == start_addr:
                started = True

            #如果地址t.addr等于end_addr，则直接退出循环
            if t.addr == end_addr:
                break

            #如果started已经被设置为True，则说明之前已经遍历到了start_addr处
            if started:
                #因此调用get_ins()函数将该地址对应的指令对象ins创建或获取出来。
                ins = self.get_ins(t.addr)
                #并将该跟踪记录t添加到ins的跟踪记录列表中（即调用ins.add_trace(t)）
                ins.add_trace(t)

                self.add_trace(t)

                yield t.addr



    @time_profile
    @profile
    def load_trace(self, filename, start_addr=None, end_addr=None, x64=False):
        """
        Construct BBL graph. head_block is set here.
        从跟踪文件中构建BBL图，并找到其中的循环

        filename: trace file.
        start_addr: start processing at this address. (start_addr will be processed)
        end_addr: stop processing at this address. (end_addr will *not* be processed)
        x64: True for x64 , False for x86
        """

        print('[*] Loading traces from %s' % filename)

        prev_block = None #prev_block用于记录上一个block（基本块）

        addr_seq = []     #addr_seq用于记录所有的地址序列
        addr_set = set()  #addr_set用于记录所有的地址集合

        loops = []        #loops用于保存已找到的循环信息

        count = 0        #count用于统计遍历的指令数目

        # for addrs in self._buffer_process_addr(filename, start_addr, end_addr, x64):
        #     for addr in addrs:

        #调用_process_trace()函数来解析给定的跟踪文件，并将其中的指令遍历后返回对应的地址
        for addr in self._process_trace(filename, start_addr, end_addr, x64):
            count += 1

            #获取该地址对应的basic block
            cur_block = self.blocks[addr]

            #如果当前还没有设置过头结点，则将该basic block设置为头结点
            if not self.head_block:
                self.head_block = cur_block

            #给该basic block的执行次数加1
            cur_block.exec_count += 1
            
            #如果存在上一个basic block，则构建前驱后继
            if prev_block:
                cur_block.add_prev(prev_block.start_addr) #将上一个basic block的end地址添加到该basic block的前驱节点列表中
                prev_block.add_next(cur_block.start_addr) #将该basic block的start地址添加到上一个basic block的后继节点列表中
            prev_block = cur_block

            # Finding loops.
            #找循环：如果该地址在addr_set中出现过，则说明找到了循环
            if addr in addr_set: # set(using hash to search) is much faaaaaster than list.
                # loop found.
                loop_start = addr_seq.index(addr)

                #根据循环起始地址和结束地址创建一个BlockLoop对象
                loop = BlockLoop(addr_seq[loop_start: ])

                #loop = tuple(addr_seq[loop_start: ])
                #将其中的地址序列从addr_seq中提取出来，同时从addr_set中删除这些地址
                addr_seq = addr_seq[ :loop_start]
                for i in loop.addr_seq:
                    addr_set.remove(i)

                #将该循环添加到loops列表中
                if self._add_loop(loop):
                    #for node in loop.list_nodes(self):
                    #    node.add_loop(loop)
                    self.blocks[addr].add_loop(loop) # head node.

            addr_seq.append(addr)
            addr_set.add(addr)

        '''
        # clear dead block whose exec_count is 0.
        for addr in self.blocks.keys():
            if self.blocks[addr].exec_count == 0:
                self.blocks.pop(addr)
        '''
        #通过检查所有basic block的exec_count属性
        #将那些没有任何执行记录的basic block从self.blocks字典中删除
        #因为只有具有执行记录的basic block才能连接成控制流程图中的节点
        keys_to_delete = []
        for addr in self.blocks.keys():
            # Your code here
            if self.blocks[addr].exec_count == 0:
                keys_to_delete.append(addr)
        for addr in keys_to_delete:
            del self.blocks[addr]
        

        print('[+] %s traces processed.' % count)


    # ==============================================================================
    # Use DFS algrithm to search graph to find circles staticly,
    # but we got a lot more senseless results.

    def _dfs_find_circle(self, addr, path=[]):
        """
        DFS to find circle.
        递归函数，在基本块的前后继关系中寻找循环
        addr，表示当前正在查找的基本块
        path=[]，记录在查找过程中经过的所有基本块的地址
        """

        #判断当前的基本块地址addr是否已经在path中出现过（即形成了循环） 如果是，则说明找到了循环
        if addr in path:
            # circle found.
            # yield path[path.index(addr):]
            #将其保存到self.loops属性中
            circle = path[path.index(addr):]
            self.loops.append(circle)

            #并把其中每个basic block都加入到对应的循环中
            for addr in circle:
                self.blocks[addr].add_loop(circle)
            return

        #如果当前的基本块地址addr没有在path中出现过，则说明还没形成循环，需要继续向下查找
        else:
            #将该地址添加到path列表中，然后遍历下一个基本块的地址next_addr
            path.append(addr)
            for next_addr in self.blocks[addr].nexts:
                # only for py3
                # yield from self._dfs_find_circle(self, next_addr, path)

                #调用自身进行递归查找
                self._dfs_find_circle(next_addr, path)
            path.pop()
            return

    # result make no sense !!!! 
    # use loops generated from trace.

    def find_all_circle(self):
        self.loops = []
        self._dfs_find_circle(self.head_addr)

    # ==============================================================================

    def _hot_blocks(self, loop_count_min):
        return filter(self.blocks.values(), lambda node: node.loop_count > loop_count_min )


    # ==============================================================================

    def _can_merge_to_prev(self, cur):
        """
        判断当前的基本块是否可以和前驱基本块合并
        """

        #判断当前基本块的前驱节点数量是否为1（因为只有一个前驱节点才能进行合并）
        if cur.prev_count != 1 : return False
       
       #在Python 3中，dict_keys对象是一个视图而不是一个列表，因此不能直接进行索引操作
        prev = self.blocks[list(cur.prevs.keys())[0]] #记录当前基本块的前驱节点地址

        #判断该前驱节点的后继节点数量是否为1（因为只有一个后继节点才能进行合并）
        if prev.next_count != 1: return False

        #说明当前基本块能够和前驱节点合并，返回True
        return True


    def _merge_to_prev(self, cur):
        prev = self.blocks[list(cur.prevs.keys())[0]]

        # this shoud be same
        assert prev.exec_count == cur.exec_count
        prev.merge_block(cur)
        self.blocks.pop(cur.start_addr)

        # # start not change
        # prev.end_addr = cur.end_addr

        # prev.size += cur.size
        # prev.ins_count += cur.ins_count
        # prev.ins += cur.ins

        # # prev.prevs not change
        # prev.nexts = cur.nexts

        # fix cur->next->prev.
        for addr in prev.nexts:
            next_block = self.blocks[addr]
            next_block.prevs.pop(cur.addr) # remove reference to current block
            next_block.prevs[prev.addr] = cur.prevs[prev.addr] # add reference to prev block



    def _repair_loop(self):
        """
        修复每个循环中的地址序列
        """
        for loop in self.loops:
            i = 0
            block = None
            new_addr_seq = []
            last_idx = 0

            for i, addr in enumerate(loop.addr_seq):
                if addr in self.blocks:
                    new_addr_seq.append(addr)
 
                    if block:
                        assert tuple(block.ins_addrs) == loop.addr_seq[last_idx:i]
                        last_idx = i                
                    block = self.blocks[addr]
            assert tuple(block.ins_addrs) == loop.addr_seq[last_idx:i+1]

            loop.addr_seq = tuple(new_addr_seq)


    @time_profile
    def consolidate_blocks(self):
        """
        if current node has unique predecessor and the predecessor has unique successor, 
        consolidate current node with the predecessor. 

        合并基本块
        判断当前基本块是否有唯一的前继节点，并且该前继节点是否有唯一的后继节点。
        如果成立，就将当前基本块与其前继节点合并为一个基本块
        这个操作相当于将两个连续的基本块做了优化，避免了中间存在无意义的跳转指令或者其他不必要的指令浪费时间
        """
        print('[*] Constructing execution graph ...')
        print('[+] Before consolidation: %d'%len(self.blocks))
        
        #遍历当前二进制文件中所有的基本块
        for addr in list(self.blocks.keys()):
            node =  self.blocks[addr]
            #判断当前节点是否有唯一的前继节点以及其前继节点是否有唯一的后继节点
            if self._can_merge_to_prev(node):
                self._merge_to_prev(node) #如果成立，则将当前节点与其前继节点合并为一个节点

        print('[+] After consolidation: %d'% len(set(self.blocks.values())))

        # Consolidate blocks of loops
        #合并完成之后，修复所有循环内部的基本块
        self._repair_loop()

        print('[*] Execution graph constructed.')


    # ==============================================================================


    def gen_bbl_graph(self, level=1, g_format='jpg', out_name='bbl', display=False):
        """
        draw basic block graph with pydot.
        将基本块的相关信息以图形化的方式展示出来
        
        level：控制节点标签信息显示的级别
            level 0: blank
            level 1: address
            level 2: instructions
            level 3: all
        g_format：生成文件的格式
            format: dot, jpg, svg, pdf
        out_name：生成文件的名称
        display：是否在浏览器中打开生成的图形文件
        """
        import pydot
        #调用pydot库创建有向图g
        g = pydot.Dot(g_type='dig') # directed graph

        #遍历所有的基本块（node为BasicBlock实例）
        for node in self.blocks.values():
            if node.exec_count == 0: continue #如果该基本块没有执行过（即exec_count为0），则跳过

            if level == 0: #根据level设置节点标签信息，如果level为0，则不设置任何标签；
                label = ''
            elif level == 1: #如果level为1，则设置地址信息
                label = '%#x' % node.start_addr
            elif level == 2:
                label = '%#x(%d) exec(%d)'%(node.start_addr, node.ins_count, node.exec_count)
                label += '\n' + node.ins_str + '\n'
                label = label.replace('\n', '\l')  # make text left-aligned.
            else: #如果level为3，则设置所有信息
                label = str(node).replace('\n','\l')

            #将节点添加到图g中，使用start_addr作为节点ID，label作为节点的标签信息
            g.add_node(pydot.Node(node.start_addr, label = label))

            #为每个节点添加其后继节点，即连接由start_addr到nexts中的地址
            for next_addr in node.nexts:
                g.add_edge(pydot.Edge(node.start_addr, next_addr , label = ''))#str(node.nexts[next_addr])))
        
        try:
            import os
            #根据g_format将图g生成相应的文件，并根据display决定是否在浏览器中打开
            path = config.IMAGE_FOLDER + out_name + '.' + g_format
            
            if g_format == 'jpg':
                g.write_jpg(path)
                if display: os.system(path)

            elif g_format == 'pdf':
                g.write_pdf(path)
                if display: os.system(path)

            elif g_format == 'svg':
                g.write_svg(path)
                if display: os.system('%s %s' %(config.BROWSER_PATH, path))
            else: 
                g.write_dot(path + '.dot')
                os.system('dot -T%s %s.dot -o %s') % (g_format, path, path)
        except Exception as e:
            print('[!] error in dot.exe: %s' % e)



    def display_bbl_graph(self, level=1, g_format='jpg', out_name='bbl'):
        self.gen_bbl_graph(level, g_format, out_name, True)


    def display_bbl_graph_ida(self, level=1):
        """
        draw basic block graph with IDA pro. much faster!!!
        使用IDA Pro显示基本块之间的前后继关系
        """
        try:
            from idaapi import GraphViewer
        except:
            print('Must run in IDA pro !!')
            return 

        class MyGraph(GraphViewer):

            def __init__(self, bm, level=1):
                GraphViewer.__init__(self, 'BBL graph')
                self.bm = bm
                self.level = level

            def OnRefresh(self):
                print('OnRefresh')
                #清空图中所有元素，将当前二进制文件中所有基本块作为节点放入到图g中
                self.Clear()
                self._nodes = self.bm.blocks.values()

                #遍历每个节点，添加其与后继节点的边
                for node in self._nodes:
                    for next_addr in node.nexts:
                        self.AddEdge(self._nodes.index(node), self._nodes.index(self.bm.blocks[next_addr])) 

                return True

            #在不同的level下设置节点标签信息，返回对应信息
            def OnGetText(self, node_id):
                node = self[node_id]
                
                
                if self.level == 0:
                    return ''
                elif self.level == 1:
                    return '%#x' % node.addr
                elif self.level == 2:
                    return '%#x(%d) %d'%(node.start_addr, node.ins_count, node.exec_count)
                else:
                    return '%#x(%d) %d\n%s'%(node.start_addr, node.ins_count, node.exec_count, node.ins_str())
          
        #创建MyGraph实例g，并调用其Show()方法在IDA Pro中显示
        g = MyGraph(self)
        g.Show()

    # ==============================================================================


    def sorted_blocks(self, sorted_by):
        """
        对当前对象中的所有块进行排序，并按照指定的属性对其进行排序，最后返回排好序的块列表
        """

        '''
        cmp_map = {
            "prev_count": lambda x,y: x.prev_count - y.prev_count,
            "next_count": lambda x,y: x.next_count - y.next_count,
            "ins_count": lambda x,y: x.ins_count - y.ins_count,
            "exec_count": lambda x,y: x.exec_count - y.exec_count,
            "prev_mul_next_count": lambda x,y: x.prev_count*x.next_count - y.prev_count*y.next_count,
            "loop_count":  lambda x,y: x.loop_count - y.loop_count,
        }
        '''
        
        #定义了一个名为 cmp_map 的字典，其中包含了多个键值对，每个键表示一种排序方式，对应的值是一个 lambda 函数，用来获取块的指定属性值
        cmp_map = {
        "prev_count": lambda x: x.prev_count,
        "next_count": lambda x: x.next_count,
        "ins_count": lambda x: x.ins_count,
        "exec_count": lambda x: x.exec_count,
        "prev_mul_next_count": lambda x: x.prev_count*x.next_count,
        "loop_count":  lambda x: x.loop_count,
        }

        #检查传入的 sorted_by 参数是否属于 cmp_map 中定义的键，如果不是的话就会打印错误信息并返回 None；
        #否则，函数通过调用 Python 内置函数 sorted() 来对块进行排序
        if sorted_by not in cmp_map:
            print("sorted by: " + ','.join(cmp_map))
            return

        # descending sort.
        #在Python 3中已经移除了 cmp 函数
        #return sorted(self.blocks.values(), cmp_map[sorted_by], reverse=True)
        return sorted(self.blocks.values(), key=cmp_map[sorted_by], reverse=True)


    # Searching address which is not start address of block can be slow. 
    def addr_to_block(self, addr):
        """
        根据给定的地址 addr，返回包含该地址的块对象
        """

        #首先判断地址 addr 是否在当前对象维护的块字典中，如果是的话就直接返回相应的块对象
        if addr in self.blocks:
            return self.blocks[addr]
        else: #否则，函数遍历所有的块对象，检查地址 addr 是否在当前块对象的 ins_addrs（指令地址）列表中，如果存在的话就返回该块对象
            for block in self.blocks.values():
                if addr in block.ins_addrs:
                    return block


    # ==============================================================================



    def draw_block_loop_ida(self, block, loop_length=5):
        """
        draw basic block graph with IDA pro. much faster!!!
        """
        try:
            from idaapi import GraphViewer
        except:
            print('Must run in IDA pro !!')
            return 

        class MyGraph(GraphViewer):
            def __init__(self, bm):
                GraphViewer.__init__(self, 'BBL graph')
                self.bm=bm

            def OnRefresh(self):
                # print 'OnRefresh'
                self.Clear()
                block_set = [] 

                # set.union(*[set(lp.addr_seq[:loop_length]) for lp in block.loops])
                # this graph looks better.
                for lp in bm.loops:
                    for addr in lp.addr_seq[:loop_length]:
                        if addr not in block_set:
                            block_set.append(addr)

                self._nodes = [bm.blocks[addr] for addr in block_set]

                for node in self._nodes:
                    for next_addr in node.nexts:
                        if next_addr in block_set:
                            self.AddEdge(self._nodes.index(node), self._nodes.index(bm.blocks[next_addr])) 

                return True

            def OnGetText(self, node_id):
                node = self._nodes[node_id]
                if self.Count() < 100:
                    return '%#x(%d) %d\n%s'%(node.start_addr, node.ins_count, node.exec_count, node.ins_str())
                else:
                    return '%#x(%d) %d'%(node.start_addr, node.ins_count, node.exec_count)
                return str(self._nodes[node_id])

        g = MyGraph(self)
        g.Show()


    def detect_handlers(self):
        """
        识别Vmp Handler
        """

        #根据不同类型的虚拟机（vmp、vmp3和cv），找到dispatcher的基本块
        if config.VM == 'vmp' or config.VM == 'cv':
            
            dispatcher = self.sorted_blocks('loop_count')[0] # find the hottest block. 

            print('[+] Dispatcher found at %#x.' % dispatcher.addr)

            #遍历每个loop块并进行处理，将处理后的结果加入self.handlers中
            for loop in dispatcher.loops:
                #使用list_nodes方法获取所有的基本块
                loop_blocks = list(loop.list_nodes(self))
                #如果第一个基本块不是dispatcher，就抛出异常
                assert loop_blocks[0] == dispatcher

                #handler 检测
                h = handler.Handler()
                for b in loop_blocks[1:]:
                    if not h.add_block(b):
                        break  # if add failed, we stop. 如果添加其他基本块时失败了，则break退出当前操作

                #判断h.is_valid是否为真，如果是则将处理后的结果加入self.handlers中
                if h.is_valid:
                    self.add_handler(h)

            self.dispatcher = dispatcher            

        #如果是vmp3虚拟机，则通过判断block是否以”jmp edi”的模式结尾来检查handlers
        elif config.VM == 'vmp3':
            
            jmp_edi_blocks = []
            
            for addr in self.blocks:
                b = self.blocks[addr]
                if b.ends_with_jmp_edi and b.ins_count < 10: # short block
                    jmp_edi_blocks.append(addr)

            for addr in self.blocks:
                if addr in jmp_edi_blocks:
                    continue

                b = self.blocks[addr]

                if b.ends_with_jmp_edi:  # block ends with "jmp edi" patten
                    h = handler.Handler()
                    h.add_block(b)
                    self.add_handler(h)
                else:                    # block jump to `jmp_edi_block`
                    if len(b.nexts) != 1:
                        continue
                    next_addr = b.nexts.keys()[0]
                    if next_addr in jmp_edi_blocks:
                        next_b = self.blocks[next_addr]
                        h = handler.Handler()
                        h.add_block(b)
                        h.add_block(next_b)
                        self.add_handler(h)                       

        else:
            raise NotImplementedError('unsupported VM type %s' % config.VM)

        print ('[+] %s %s-handlers found.' % (len(self.handlers), config.VM))



    def dump_handlers(self):

        for addr in self.handlers:
            print (self.handlers[addr])
            # block = self.blocks[dispatcher_addr]
            # print 'Dispatcher:'
            # print block.ins_str

            # handler_addrs = self.handlers[dispatcher_addr]
            # print '[+] %d Handler(s):' % len(handler_addrs)
            # for addr in handler_addrs:                
            #     handler = self.blocks[addr]
            #     print '#'*80
            #     print 'Handler:'
            #     # print bm.blocks[addr].bytes.encode('hex')
            #     print handler.ins_str 
            #     print 'C repr:'
            #     print handler.to_c()      

        print ('='*20)


    def extract_handler_trace(self, force=False):

        if not force and len(self.handler_traces) > 0:
            return self.handler_traces

        # Collect all trace.
        traces = []
        for handler in self.handlers.values():
            block = handler.head
            ins = block.instructions[0]
            traces += ins.traces

        # sorted by trace id.

        #traces.sort(lambda x,y: x.id - y.id)
        traces.sort(key=lambda x: x.id)


        self.handler_traces = traces;
        return traces




def dump_bm(infofile, tracefile, dumpfile, x64=False):
    global bm
    bm = BBLManager()
    bm.load_ins_info(infofile)
    bm.load_trace(tracefile,x64=x64)
    bm.consolidate_blocks()
    cPickle.dump(bm, open(dumpfile,'wb'))   


def load_bm(dumpfile):
    global bm
    bm = cPickle.load(open(dumpfile,'rb'))
    


def run_pin_and_dump(exe_path):

    cmd = r'..\..\..\pin.exe  -t obj-ia32\MyPinTool.dll -logins -- %s' % exe_path
    os.system(cmd)

    infofile = r'D:\papers\pin\pin-3.2-81205-msvc-windows\source\tools\MyPinTool\INS.info'
    tracefile = r'D:\papers\pin\pin-3.2-81205-msvc-windows\source\tools\MyPinTool\INS.trace'

    abspath = os.path.abspath(exe_path)
    exe_name = os.path.splitext(os.path.basename(abspath))[0]
    dumpfile = r'D:\papers\pin\pin-3.2-81205-msvc-windows\source\tools\MyPinTool\%s.dump' % exe_name
    dump_bm(infofile, tracefile, dumpfile)

    print(bm.sorted_blocks('loop_count')[:10])

def load_from_exepath(exe_path):
    abspath = os.path.abspath(exe_path)
    exe_name = os.path.splitext(os.path.basename(abspath))[0]
    dumpfile = r'D:\papers\pin\pin-3.2-81205-msvc-windows\source\tools\MyPinTool\%s.dump' % exe_name
    load_bm(dumpfile)

def main(path):
    run_pin_and_dump(path)
    #load_from_exepath(path)


if __name__ == '__main__':
    # main(sys.argv[1])
    # load_bm(r'D:\paper\papers\pin\pin-3.2-81205-msvc-windows\source\tools\MyPinTool\base64.vmp_1.81_demo.dump')
    # for dispatcher in bm.detect_vm_loop():
    #     bm.draw_block_loop_ida(dispatcher)
    global bm
    bm = BBLManager()
    bm.load_ins_info(r'D:\papers\pin\pin-3.2-81205-msvc-windows\source\tools\MyPinTool\bin.ins')
    bm.load_trace(r'D:\papers\pin\pin-3.2-81205-msvc-windows\source\tools\MyPinTool\bin.trace',
        # start_addr=0x401000, end_addr=0x40127C) # allop
        start_addr=0x401000, end_addr=0x00401169) # base64
    # bm.load_trace('../bin.block')      
    bm.consolidate_blocks()
    # cPickle.dump(bm, open('test.dump','wb')) 
    # bm.display_bbl_graph()
    # bm.display_bbl_graph_ida()

    bm.detect_handlers() 
    bm.dump_handlers()


    report.gen_report(bm)
    report.open_report()


    # for h in bm.handlers.values():
    #     print '*'*20
    #     print h
    #     print h.ins_str
    #     print h.to_expr('cv')


    # h = bm.handlers[0x405853]

    # s = h.to_sym_state()

    # s.emul_ir_block(0, True)