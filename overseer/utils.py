from itertools import tee, izip
from pox.lib.addresses import IPAddr
from hashlib import sha1
import struct
from pprint import pprint
from binascii import hexlify, unhexlify

class MPTCPPacketInfo:
    kind = 0x1e
    length = None
    srcip = None
    dstip = None
    srcport = None
    dstport = None
    tcpflags = None

class MPTCPCapablePacketInfo(MPTCPPacketInfo):
    subtype = 0
    version = None
    mpflags = None
    #flag_chksum = flag_a = None
    #flag_extensibility = flag_b = None
    #flag_hmac = flag_h = None
    mpflag_sendkey = None
    mpflag_recvkey = None

class MPTCPJoinPacketInfo(MPTCPPacketInfo):
    subtype = 1
    backup = None
    addrid = None
    recvtok = None
    nonce = None

class MPTCPInvalidLengthException(Exception):
    pass

class MPTCPInvalidPacketException(Exception):
    pass

def inspect_mptcp_packet(packet):
    '''
    Inspects a packet for MPTCP.
    Fields that can be returned:
     - subtype
     - sendkey
     - recvkey
     - recvtok
     - dstip
     - srcip
     - dstport
     - srcport

    BIT/BYTE ORDER  of MPTCP option FIELDS

      PacketType   TCPFlag  Subtype  Length
      CAPABLE 1    SYN      0        12
      CAPABLE 2    SYNACK   0        20
      JOIN 1       SYN      1        12
      JOIN 2       SYNACK   1        16
      JOIN 3       ACK      1        24    (not used by our controller)
    '''

    TCP_SYN = 0x02
    TCP_SYNACK = 0x12
    TCP_OPTION_KIND_MPTCP = 0x1e
    MPTCP_MP_CAPABLE_ONEKEY_LENGTH = 12
    MPTCP_MP_CAPABLE_TWOKEY_LENGTH = 20
    MPTCP_MP_JOIN_LENGTH = 12
    MPTCP_MP_JOIN2_LENGTH = 16
    MPTCP_MP_JOIN3_LENGTH = 24


    return_packet = MPTCPPacketInfo()

    #print packet
    tcp_packet = packet.find("tcp")
    ip_packet = packet.find("ipv4")

    if tcp_packet is None:
        raise MPTCPInvalidPacketException("Can't find TCP header.")

    #print dir(tcp_packet)
    #print dir(ip_packet)

    for option in tcp_packet.options:
        if option.type == TCP_OPTION_KIND_MPTCP:
            mptcp_subtype = struct.unpack('B', option.val[0])[0] >> 4
            length = len(option.val)+2 #two bytes were "cut" by POX parser
            print "Subtype: %d" % (mptcp_subtype)
            print "Length: %d" % (len(option.val))
            print "TCPopt: %s" % (hexlify(option.val))
            if mptcp_subtype == 0:
                subtypeversion = None
                return_packet = MPTCPCapablePacketInfo()
                return_packet.length = length
                #if one key (length 12)
                if length == MPTCP_MP_CAPABLE_ONEKEY_LENGTH:
                    subtypeversion, return_packet.mpflags, return_packet.sendkey = struct.unpack('!BB8s',option.val)
                #if two keys (length 20)
                elif length == MPTCP_MP_CAPABLE_TWOKEY_LENGTH:
                    subtypeversion, return_packet.mpflags, return_packet.sendkey, return_packet.recvkey = struct.unpack('!BB8s8s',option.val)
                else:
                    raise MPTCPInvalidLengthException("Expected Length 12 or 20, got %d" % (length))
                return_packet.version = subtypeversion & 0b1111
                break
            elif mptcp_subtype == 1:
                return_packet = MPTCPJoinPacketInfo()
                return_packet.length = length
                if length == MPTCP_MP_JOIN_LENGTH:
                    subtypebackup, return_packet.addrid, return_packet.recvtok, return_packet.nonce = struct.unpack('!BB4s4s',option.val)
                    return_packet.backup = not not subtypebackup & 0b00000001
                elif length == MPTCP_MP_JOIN2_LENGTH:
                    pass
                elif length == MPTCP_MP_JOIN3_LENGTH:
                    pass
                else:
                    raise MPTCPInvalidLengthException("Expected Length 12/16/20, got %d" % (length))
                break
    try:
        return_packet.srcport = tcp_packet.srcport
        return_packet.dstport = tcp_packet.dstport
        return_packet.srcip = ip_packet.srcip
        return_packet.dstip = ip_packet.dstip
    except:
        pass
    pprint(return_packet)
    return return_packet


    # if MPTCP
    #   if MP_CAPABLE:
    #       get keys (key is sender-side) & hash & tcp port number
    #       create new dict entry <(hash,portNo): pathSet>
    #       find path
    #   if MP_JOIN:
    #       get hash
    #       if hash exists:
    #
    #


def pairwise(iterable):
    """
    Taken from: http://stackoverflow.com/questions/5764782/iterate-through-pairs-of-items-in-python-list

    s -> (s0,s1), (s1,s2), (s2, s3), ...

    for v, w in pairwise(a):
    ...
    """
    a, b = tee(iterable)
    next(b, None)
    return izip(a, b)


def create_path_identifier(from_ip, from_port, to_ip, to_port):
    """
    Create path identifier to use with flow-preference table

    The identifier is just a tuple containing various information
    """
    return (from_ip, from_port, to_ip, to_port)
