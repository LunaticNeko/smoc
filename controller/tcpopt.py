# TCP Option reader
# (A very quick one)
#
# Quick interface guide (code too badly written to read for now):
#
# split_opts
#   Inputs: byte array
#   Output: List of <TCPOption>* <TCPGarbledOption>?
#
# check_kind
#   Inputs: What you get from split_opts, int (IANA TCP Option Kind No.)
#   Output: Bool (True means option list contains the type you want)
#
# (* means zero or more, ? means one or more, REGEX style)


# Conforming with IANA rules.
ONLYBYTE = 0
N = -1

from binascii import hexlify, unhexlify

# This is partially implemented for now.
TCPOPT_KIND_EOL = 0
TCPOPT_KIND_NOP = 1
TCPOPT_KIND_MSS = 2
TCPOPT_KIND_WS = 3
TCPOPT_KIND_TS = 8
TCPOPT_KIND_MPTCP = 30

TCP_OPTION_KINDS = {
            0: (ONLYBYTE, 'End of Option List'),
            1: (ONLYBYTE, 'No-Operation'),
            2: (4, 'Maximum Segment Size'),
            3: (3, 'Window Scale'),
            8: (10, 'Timestamps'),
            30: (N, 'Multipath TCP')
        }

MPTCP_OPTION_SUBTYPES = {
            0x0: 'MP_CAPABLE',
            0x1: 'MP_JOIN',
            0x2: 'DSS',
            0x3: 'ADD_ADDR',
            0x4: 'REMOVE_ADDR',
            0x5: 'MP_PRIO',
            0x6: 'MP_FAIL',
            0x7: 'MP_FASTCLOSE',
            0xf: 'private use'
        }

class TCPOption:
    def __init__(self, kind, length=None, data=None):
        self.opt_kind = kind
        self.opt_kind_name = TCP_OPTION_KINDS[kind]
        self.opt_length = length
        self.opt_data = data

class TCPGarbledOption:
    def __init__(self, data):
        self.opt_kind = None
        self.opt_data = data

#TODO: Actually check and enforce length of each type
#      (if specified in IANA docs)
def split_opts(option_string):
    options = []
    i=0
    while i < len(option_string):
        octet = ord(option_string[i])
        if octet in TCP_OPTION_KINDS:
            if TCP_OPTION_KINDS[octet][0] == ONLYBYTE:
                options.append(TCPOption(octet))
                i+=1
                continue
            else:
                option_length = ord(option_string[i+1])
                options.append(TCPOption(octet, option_length, option_string[i+2:i+option_length]))
                i+=option_length
        else:
            options.append(TCPGarbledOption(option_string[i:]))
            break
    return options


def check_kind(option_list, kind):
    for option in option_list:
        if option.opt_kind == kind:
            return True
    return False

if __name__ == '__main__':
    A = split_opts(unhexlify('0101080a79941a9e799185911e082001c3f3aaa799'))
    print check_kind(A, 0x01) #True
    print check_kind(A, 0x30) #True
    print check_kind(A, 0x99) #False (garbage has None kind)
