[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FLunaticNeko%2Fsmoc.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2FLunaticNeko%2Fsmoc?ref=badge_shield)

smoc
====
simple multipath openflow controller

Requirements
------------

For OpenFlow Controller Machine
* NetworkX

For Host Machines
* MPTCP (required because this controller was made specifically to route this protocol)

How simple is it?
-----------------
As of writing this, the "get\_path" method is less than 50 lines, comments included.

It is simple because it leverages networkx and works on a purely hop-based basis.
It should be marginally better than cramming all flows into the least-hop path.

We plan to include more features in the future, such as bandwidth or capacity-based
path calculation.

Basis of work
-------------
This work is based on overseer.

Usage
-----

Clone this repository into POX's ext directory and launch included sample launcher with the following command

    $ ./pox.py smoc.samples.launch


## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FLunaticNeko%2Fsmoc.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2FLunaticNeko%2Fsmoc?ref=badge_large)