"""

simple

All topology files are to be run using mininet.

 H1 --- S1 --- H2

"""

from mininet.topo import Topo

class Simple(Topo):
    def __init__(self):
        Topo.__init__(self)

        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        s1 = self.addSwitch('s1')

        self.addLink(h1,s1)
        self.addLink(s1,h2)


topos = {'simple': (lambda: Simple())}
