Root <- Skip Comment? Rule EOF

Rule <- Pattern COLON Skip Packet (SEPT Packet)* Action COLON Skip ActionField

bin     <- [01]
bin_    <- '_'? bin
oct     <- [0-7]
oct_    <- '_'? oct
hex     <- [0-9a-fA-F]
hex_    <- '_'? hex
dec     <- [0-9]
dec_    <- '_'? dec

bin_int <- bin bin_*
oct_int <- oct oct_*
dec_int <- dec dec_*
hex_int <- hex hex_*

INTEGER <- "0b" bin_int Skip / "0o" oct_int Skip
            / "0x" hex_int Skip / dec_int   Skip

EQUAL           <- '=' Skip
COLON           <- ':' Skip
COMMA           <- ',' Skip
SLASH           <- '/' Skip
DOT             <- '.' Skip
OR              <- '|' Skip
Open            <- '(' Skip
Close           <- ')' Skip
Skip            <- ( Space / Comment )*
Comment         <- '#' ( !EOL . )* EOL
Space           <- ' ' / '\t' / EOL
EOL             <- '\r\n' / '\n' / '\r'
EOF             <- !.

ActionField     <- 'RSS' / 'DROP' / 'QUEUE' / 'PORT' / 'METER'
                    / 'SAMPLE'

Action          <- 'action'
Pattern         <- 'pattern'

SEPT            <- SLASH / OR

Packet          <- ETHER_P / IP_P / UDP_P / TCP_P / VXLAN_P / GRE_P / VLAN_P / MPLS_P / IP6_P / ANY_P / SCTP_P / ICMP_P / ARP_P

ETHER_FIELD     <- 'src' / 'dst'
IP_FIELD        <- 'tos' / 'csum' / 'frag' / 'ttl' / 'id' / 'proto'
UDP_FIELD       <- 'src' / 'dst' / 'csum' / 'len'
TCP_FIELD       <- 'src' / 'dst' / 'csum' / 'len' / 'opt' / 'flags'
VXLAN_FIELD     <- 'vni' / 'flags'
IP6_FIELD       <- 'class' / 'frag' / 'ttl' / 'id' / 'proto'
GRE_FIELD       <- 'proto' / 'csum' / 'key' / 'recur'
VLAN_FIELD      <- 'tag'
MPLS_FIELD      <- 'label' / 'ttl'
SCTP_FIELD      <- 'src' / 'dst' / 'type' / 'flags' / 'len' / 'csum' / 'tag'
ICMP_FIELD      <- 'type' / 'code' / 'csum' / 'id' / 'seq'
ARP_FIELD       <- 'sha' / 'spa' / 'tha' / 'tpa'

tcp_flags       <- 'syn' / 'fin' / 'rst' / 'ack' / 'push' / 'ece' / 'cwr' / 'urg'

ETHER_P         <- 'ETHER' (Open ((ETHER_FIELD EQUAL macaddr (SLASH macaddr)? COMMA?) / ('type' EQUAL INTEGER (SLASH INTEGER)? COMMA?))* Close)?
IP_P            <- 'IP' (Open ((('src' / 'dst') EQUAL ipaddr (SLASH ipaddr / ipprefix)? COMMA?) / (IP_FIELD EQUAL INTEGER (SLASH INTEGER)? COMMA?))* Close)?
VXLAN_P         <- 'VXLAN' (Open (VXLAN_FIELD EQUAL INTEGER (SLASH INTEGER)? COMMA?)* Close)?
UDP_P           <- 'UDP' (Open (UDP_FIELD EQUAL INTEGER (SLASH INTEGER)? COMMA?)* Close)?
TCP_P           <- 'TCP' (Open ((TCP_FIELD EQUAL INTEGER (SLASH INTEGER)? COMMA?) / ('flags' EQUAL tcp_flags (SEPT tcp_flags)*))* Close)?
VLAN_P          <- 'VLAN' (Open (VLAN_FIELD EQUAL INTEGER (SLASH INTEGER)? COMMA?)* Close)?
MPLS_P          <- 'MPLS' (Open (MPLS_FIELD EQUAL INTEGER (SLASH INTEGER)? COMMA?)* Close)?
GRE_P           <- 'GRE' (Open (GRE_FIELD EQUAL INTEGER (SLASH INTEGER)? COMMA?)* Close)?
IP6_P           <- "IP6" (Open ((('src' / 'dst') EQUAL ip6addr (SLASH ipprefix)? COMMA?) / (IP6_FIELD EQUAL INTEGER COMMA?))* Close)?
SCTP_P          <- "SCTP" (Open (SCTP_FIELD EQUAL INTEGER (SLASH INTEGER)? COMMA?)* Close)?
ICMP_P          <- "ICMP" (Open (ICMP_FIELD EQUAL INTEGER (SLASH INTEGER)? COMMA?)* Close)?
ARP_P           <- "ARP" (Open ((ARP_FIELD EQUAL macaddr (SLASH macaddr)? COMMA?) / ("opcode" EQUAL INTEGER (SLASH INTEGER)? COMMA?))* Close)?
ANY_P           <- "ANY"

macaddr         <- hex hex COLON hex hex COLON hex hex COLON hex hex COLON  hex hex COLON hex hex Skip
ipaddr          <- dec_int DOT dec_int DOT dec_int DOT dec_int Skip
ipprefix        <- dec_int
group           <- hex (hex (hex hex?)?)?
ip6addr         <- (group COLON group)* COLON group COLON group COLON group COLON group COLON group
