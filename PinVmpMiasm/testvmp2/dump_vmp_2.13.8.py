import od2_trace_parser

handler_map = {
    0x405640 : 'vPopNULL4',
    0x405881 : 'vJmp',
    0x405853 : 'vWriteMem4',
    0x404b2b : 'vPushImm4',
    0x404227 : 'vPushVESP',
    0x4058ab : 'vPushReg4',
    0x404b6c : 'vPushImmSx2',
    0x40468d : 'vAdd4',
    0x40584e : 'vPopReg4',
    0x404558 : 'vReadMem4',
    0x4046f2 : 'vPushImmSx4',
    0x404123 : 'vReadMemSs4',
    0x405b14 : 'vShr4',
    0x4045d3 : 'vNor4',
    0x404443 : 'vRet',
    0x40493f : 'vPushImm1'
}

def find_handler_address(handlers):
    s = set()
    for t in handlers:
        s.add(t.registers['EDX'])
    
    print(len(s))
    for i in s:
        print('%#x : \'Handler_%x\',' % (i,i))

if __name__ == '__main__':

    traces = od2_trace_parser.parse_od2_trace('trace_2.13.8.txt')

    handlers = od2_trace_parser.search_trace(traces, a=0x0404213)

    # find_handler_address(handlers)


    for t in traces:
        if t.address in handler_map:
            pcode =  handler_map[t.address]
            if pcode == 'vPopReg4':
                print('%s\tR%d\t= %#x' % (pcode, 
                    (t.next_to(0x4056af).registers['EAX'] & 0x3C)/4, 
                    t.next_to(0x4056af).registers['EDX']))
            elif pcode == 'vPushReg4':
                print ('%s\tR%d\t= %#x' % (pcode, 
                    (t.next_to(0x404254).registers['EAX'] & 0x3C)/4,
                     t.next_to(0x404257).registers['EDX']))                    
            elif pcode == 'vPushImmSx2':
                print ('%s\t%#x' % (pcode, t.next_to(0x40531f).registers['EAX']))
            elif pcode == 'vPushImm4':
                print ('%s\t%#x' % (pcode, t.next_to(0x404ce9).registers['EAX']))
            elif pcode == 'vPushImmSx4':
                print ('%s\t%#x' % (pcode, t.next_to(0x404a85).registers['EAX']))
            elif pcode == 'vPushImm1':
                print ('%s\t%#x' % (pcode, t.next_to(0x405be0).registers['EAX'] & 0xff))
            else:
                print(pcode)