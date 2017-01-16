"""
Fires up overseer and related components
"""


def launch():
  import samples.pretty_log
  samples.pretty_log.launch()
  # import pox.openflow
  # pox.openflow.launch()
  import pox.openflow.discovery
  pox.openflow.discovery.launch()
  import pox.misc.gephi_topo
  pox.misc.gephi_topo.launch()
  import pox.host_tracker
  pox.host_tracker.launch(arpAware=15, arpSilent=45, arpReply=1, entryMove=10)
  import pox.topology
  pox.topology.launch()
  import smoc.topology
  smoc.topology.launch()
  import pox.openflow.spanning_tree
  pox.openflow.spanning_tree.launch(no_flood=True, hold_down=True)
  import smoc.overseer
  smoc.overseer.launch()
  import pox.web.webcore
  pox.web.webcore.launch()
  #import overseer.api
  #overseer.api.launch()
  #import mupoxstats
  #mupoxstats.launch(interval=1, threshold=1000)
