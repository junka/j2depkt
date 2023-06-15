
Implement a parser so we can understand a packet with cmdline below easily

```
pattern:
ETHER()/IP()/UDP()/VXLAN()/ETHER()/IP()
action:
RSS()/METER()/PORT()
```

All possible pattern sytax could be :
```
ANY
ETHER()
IP()
ARP()
IP6()
TCP()
UDP()
IPIP()
MPLS()
VLAN()
GRE()
ARP()
...
```

All possible action sytax could be:
```
RSS()
QUEUE()
SAMPLE()
DROP()
METER()
PORT()
```

generate a parser for ovs to accept rules to rte_flow code.

or

generate bpf code for packet capture
