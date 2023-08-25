
Yes, [tcpdump](https://github.com/the-tcpdump-group/tcpdump) is good start point to know the basis of a packet in the network.

It is easy to learn how to use the basic tcpdump expression like `ip` `host` `src` ,etc. However the whole tcpdump expression grammar is not that easy to remember. At least for me, I may have to check the manpage each time I want to combine some advanced filters. And for some protocol filters like VXLAN inner src ip which is not supported by the tcpdump expression, we may have to calculate the offset from the outer udp and then use the expression like `udp[42:4]=` to filter it out.

How to calculate the offset? udp 8 + vxlan 8 + inner ether 14 + inner ip 12 offset to source address = 42. and `:4` means we need load 4 bytes from the position 42 offset of the outer udp start point. Emmm, it works anyway. 

I like the idea about [Scapy](https://github.com/secdev/scapy) that builds stacked layers for any type of packets you may want to sniff or send. It is designed as a DSL for packet crafting. When you use it in different scenario to captrue or test classic or self-designed protocols, it is really easy to write a packet with layers concated together. The packet generator [Trex](https://github.com/cisco-system-traffic-generator/trex-core) is using it as packet builder engine. But even scapy sniff is a wrap of libpcap too, it does not use the DSL it owns.

---

So my goal is using [peg](https://www.piumarta.com/software/peg/) to implement a parser for this DSL that follows the Scapy style.

The packet pattern should be recognized by scapy. However it has limitations and is only a subset of what scapy supported. I did not test all of it in scapy.

```
ETHER()/IP()/UDP()/VXLAN()/ETHER()/IP():RSS()/METER()/PORT()
```
It consists of patterns and actions with colon as a delimeter
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
... to be added.

```

All possible action sytax could be:
```
RSS()
QUEUE()
SAMPLE()
DROP()
METER()
PORT()
... to be added
```

As for the actions, the ultimated goal is using it as a codegen to generate rules wrtten for rte_flow code, so we can easily use it as a new bifurcation / offloading rule builder engine for DPDK application like ovs.

But as a start for me to learn the peg parser. I would like to implement an action with SAMPLE to generate cbpf code and inject it to tcpdump's libpcap filter. So the scapy style can work as a replacement for the tcpdump expression.

To filter out a VXLAN packet with inner src ip. We can just
```
tcpdump -i eth0 -nev ETHER()/IP()/UDP()/VXLAN()/ETHER()/IP(src=192.168.0.1):SAMPLE
```
Like scapy does, some default values can be ignored by the rule.
