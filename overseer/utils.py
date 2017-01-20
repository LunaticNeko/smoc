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
    hmac = None

class MPTCPInvalidLengthException(Exception):
    pass

class MPTCPInvalidPacketException(Exception):
    pass

def inspect_mptcp_packet(packet):
    '''
    DEPRECEATED: not used as of POX 0.5.0

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
    MPTCP_SUBTYPE_MP_CAPABLE = 0
    MPTCP_SUBTYPE_MP_JOIN = 1
    MPTCP_MP_CAPABLE_ONEKEY_LENGTH = 12
    MPTCP_MP_CAPABLE_TWOKEY_LENGTH = 20
    MPTCP_MP_JOIN_LENGTH = 12
    MPTCP_MP_JOIN2_LENGTH = 16
    MPTCP_MP_JOIN3_LENGTH = 24
    MPTCP_SUBTYPE_STR = ['CAPABLE', 'JOIN', 'DSS', 'ADD_ADDR', 'REMOVE_ADDR', 'PRIO', 'FAIL', 'FASTCLOSE']

    return_packet = MPTCPPacketInfo()

    tcp_packet = packet.find("tcp")
    ip_packet = packet.find("ipv4")

    if tcp_packet is None:
        raise MPTCPInvalidPacketException("Can't find TCP header.")

    for option in tcp_packet.options:
        if option.type == TCP_OPTION_KIND_MPTCP:
            mptcp_subtype = option.subtype
            if mptcp_subtype == MPTCP_SUBTYPE_MP_CAPABLE:
                subtypeversion = None
                return_packet = MPTCPCapablePacketInfo()
                return_packet.sendkey = option.skey
                return_packet.recvkey = option.rkey
                return_packet.version = option.version
                return_packet.mptflags = option.flags
                break
            elif mptcp_subtype == MPTCP_SUBTYPE_MP_JOIN:
                return_packet = MPTCPJoinPacketInfo()
                return_packet.addrid = option.address_id
                return_packet.recvtok = option.rtoken
                return_packet.nonce = option.srand
                return_packet.mptflags = option.flags
            else: #MPTCP but not MP_CAPABLE or MP_JOIN
                pass
            return_packet.subtype = option.subtype
    try:
        return_packet.srcport = tcp_packet.srcport
        return_packet.dstport = tcp_packet.dstport
        return_packet.srcip = ip_packet.srcip
        return_packet.dstip = ip_packet.dstip
        return_packet.tcpflags = tcp_packet.flags
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
