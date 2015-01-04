# MULTIGRAPH ROUTING
#
# For RYU
#

import networkx as nx

def order_tuple_list(L):
    return [(a,b) if a<=b else (b,a) for (a,b) in L]

class MPRoute(nx.Graph):
    def __init__(self, V = None, E = None, *args, **kwargs):
        nx.Graph.__init__(self)
        print 'Initializing MPRoute. Listing all nodes and edges ...'
        print 'V{%d} = %s' % (len(V),V)
        print 'E{%d} = %s' % (len(E),E)
        print 'Removing duplicates and inserting'
        E = set(order_tuple_list(E))
        print 'E\'{%d} = %s' % (len(E),E)
        self.add_nodes_from(V)
        self.add_edges_from(E)
        print 'Generating spanning tree.'
        self.mst_edges = nx.minimum_spanning_tree(self).edges()
        self.mst_edges = order_tuple_list(self.mst_edges)
        print 'E\'\'{%d} = %s' % (len(self.mst_edges), self.mst_edges)
        self.removed_edges = set(E) - set(self.mst_edges)
        print 'E\'-E\'\'{%d} = %s' % (len(self.removed_edges), self.removed_edges)

if __name__=="__main__":
    m = MPRoute([1,2,3,4],[(1,2),(2,3),(3,4),(1,4),(1,3),(2,4)])
    print m.nodes()[0]
