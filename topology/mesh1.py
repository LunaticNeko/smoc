"""

Mesh1: Simple mesh topology with 4 sites.

All topology files are to be run using mininet.

Each host has two interfaces connected to same site-switch.

 H1 === S1 --------------- S3 === H3
        | \                 |
        |  \-------------\  |
        |                 \ |
 H2 === S2 --------------- S4 === H4


"""

from mininet.topo import Topo

class Mesh1(Topo):
    def __init__(self):
        Topo.__init__(self)

        h = []
        s = [None]
        h.append(self.addHost('h0'))
        for i in range(1,5):
            h.append(self.addHost('h%s' % i))
            s.append(self.addSwitch('s%s' % i))
            "Two links each"
            self.addLink(h[i], s[i], port1=0, port2=0)
            'self.addLink(h[i],s[i])'

        self.addLink(h[0],s[1])

        switchlinks = [(1,2), (1,3), (1,4), (2,4), (3,4)]
        for x,y in switchlinks:
            self.addLink(s[x], s[y], port1=10+y, port2=10+x)


        """self.addLink(s[1],s[2])
        self.addLink(s[1],s[3])
        self.addLink(s[1],s[4])
        self.addLink(s[2],s[4])
        self.addLink(s[3],s[4])"""

topos = {'mesh1': (lambda: Mesh1())}
