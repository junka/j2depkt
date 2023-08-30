#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rte_errno.h>
#include <rte_ethdev.h>

#include "dpdkrflow.h"
#include "utils.h"

#define YY_CTX_LOCAL

#define YY_INPUT(ctx, buf, result, max)                                        \
  {                                                                            \
    int c = fgetc(ctx->stream);                                                \
    result = (EOF == c) ? 0 : (*(buf) = c, 1);                                 \
  }

struct rflow {
  int nitem;
  struct rte_flow_item *items;
  int naction;
  struct rte_flow_action actions[8];
};
#define MAX_LAYER_NUM (32)
#define YY_CTX_MEMBERS                                                         \
  struct rflow flows;                                                          \
  unsigned long offset;                                                        \
  void *spec[MAX_LAYER_NUM];                                                   \
  void *mask[MAX_LAYER_NUM];                                                   \
  int layerid;                                                                 \
  FILE *stream;

static uint32_t rflow_len = 1 << 4;
static void rflow_append(struct rflow *flows, enum rte_flow_item_type type,
                         void* spec, void * mask) {
  struct rte_flow_item item = {
      .type = type,
      .spec = spec,
      .last = NULL,
      .mask = mask,
  };
  flows->nitem++;
  if (flows->nitem > rflow_len) {
    rflow_len <<= 1;
    flows->items =
        realloc(flows->items, rflow_len * sizeof(struct rte_flow_item));
  }
  flows->items[flows->nitem - 1] = item;
}
#define YY_PATTERN(yy, type, spec, mask)  \
 { rflow_append(&yy->flows, type, spec, mask); }

void alloc_specmask(void **specs, void **masks, int idx, size_t size)
{
  specs[idx] = calloc(1, size);
  masks[idx] = calloc(1, size);
}
#define YY_ETHER_START(yy)                                                     \
  {                                                                            \
    alloc_specmask(yy->spec, yy->mask, yy->layerid,                            \
                   sizeof(struct rte_flow_item_eth));                          \
  }
#define YY_ETHER_MAC(yy, yytext, ifsrc)                                        \
  {                                                                            \
    unsigned char addr[ETH_ALEN];                                              \
    unsigned char mask[ETH_ALEN];                                              \
    macstr2addr(yytext, addr, mask);                                           \
    struct rte_flow_item_eth *eth_spec = yy->spec[yy->layerid];                \
    struct rte_flow_item_eth *eth_mask = yy->mask[yy->layerid];                \
    if (ifsrc) {                                                               \
      memcpy(&eth_spec->src, addr, ETH_ALEN);                                  \
      memcpy(&eth_mask->src, mask, ETH_ALEN);                                  \
    } else {                                                                   \
      memcpy(&eth_spec->dst, addr, ETH_ALEN);                                  \
      memcpy(&eth_mask->dst, mask, ETH_ALEN);                                  \
    }                                                                          \
  }
#define YY_ETHER_TYPE(yy, yytext)                                              \
  {                                                                            \
    struct rte_flow_item_eth *eth_spec = yy->spec[yy->layerid];                \
    struct rte_flow_item_eth *eth_mask = yy->mask[yy->layerid];                \
    eth_spec->type = RTE_BE16(integervalue(yytext));                           \
    eth_mask->type = 0xFFFF;                                                   \
  }

#define YY_ETHER_END(yy)                                                       \
  {                                                                            \
    struct rte_flow_item_eth *eth_spec = yy->spec[yy->layerid];                \
    struct rte_flow_item_eth *eth_mask = yy->mask[yy->layerid];                \
    YY_PATTERN(yy, RTE_FLOW_ITEM_TYPE_ETH, eth_spec, eth_mask);                \
    yy->layerid++;                                                             \
  }
#define YY_VLAN_START(yy)                                                      \
  {                                                                            \
    alloc_specmask(yy->spec, yy->mask, yy->layerid,                            \
                   sizeof(struct rte_flow_item_vlan));                         \
  }
#define YY_VLAN_TPID(yy, yytext)
#define YY_VLAN_TAG(yy, yytext)
#define YY_VLAN_END(yy)                                                        \
  {                                                                            \
    struct rte_flow_item_vlan *vlan_spec = yy->spec[yy->layerid];              \
    struct rte_flow_item_vlan *vlan_mask = yy->mask[yy->layerid];              \
    YY_PATTERN(yy, RTE_FLOW_ITEM_TYPE_VLAN, vlan_spec, vlan_mask);             \
    yy->layerid++;                                                             \
  }
#define YY_IP_START(yy)                                                        \
  {                                                                            \
    alloc_specmask(yy->spec, yy->mask, yy->layerid,                            \
                   sizeof(struct rte_flow_item_ipv4));                         \
  }

#define YY_IP_ADDR(yy, yytext, src)                                            \
  {                                                                            \
    uint32_t addr, mask;                                                       \
    ipstr2addr(yytext, &addr, &mask);                                          \
    struct rte_flow_item_ipv4 *ip4_spec = yy->spec[yy->layerid];               \
    struct rte_flow_item_ipv4 *ip4_mask = yy->mask[yy->layerid];               \
    if (src) {                                                                 \
      ip4_spec->hdr.src_addr = addr;                                           \
      ip4_mask->hdr.src_addr = mask;                                           \
    } else {                                                                   \
      ip4_spec->hdr.dst_addr = addr;                                           \
      ip4_mask->hdr.dst_addr = mask;                                           \
    }                                                                          \
  }

#define YY_IP_FIELD1(yy, yytext, off)                                          \
  {                                                                            \
    struct rte_flow_item_ipv4 *ip4_spec = yy->spec[yy->layerid];               \
    struct rte_flow_item_ipv4 *ip4_mask = yy->mask[yy->layerid];               \
    if (off == 1) {                                                            \
      ip4_spec->hdr.type_of_service = integervalue(yytext);                    \
      ip4_mask->hdr.type_of_service = 0xFF;                                    \
    } else if (off == 8) {                                                     \
      ip4_spec->hdr.time_to_live = integervalue(yytext);                       \
      ip4_mask->hdr.time_to_live = 0xFF;                                       \
    } else if (off == 9) {                                                     \
      ip4_spec->hdr.next_proto_id = integervalue(yytext);                      \
      ip4_mask->hdr.next_proto_id = 0xFF;                                      \
    }                                                                          \
  }
#define YY_IP_FIELD2(yy, yytext, off)                                          \
  {                                                                            \
    struct rte_flow_item_ipv4 *ip4_spec = yy->spec[yy->layerid];               \
    struct rte_flow_item_ipv4 *ip4_mask = yy->mask[yy->layerid];               \
    if (off == 2) {                                                            \
      ip4_spec->hdr.total_length = RTE_BE16(integervalue(yytext));             \
      ip4_mask->hdr.total_length = 0xFFFF;                                     \
    } else if (off == 4) {                                                     \
      ip4_spec->hdr.packet_id = RTE_BE16(integervalue(yytext));                \
      ip4_mask->hdr.packet_id = 0xFFFF;                                        \
    } else if (off == 6) {                                                     \
      ip4_spec->hdr.fragment_offset = RTE_BE16(integervalue(yytext));          \
      ip4_mask->hdr.fragment_offset = 0xFFFF;                                  \
    } else if (off == 10) {                                                    \
      ip4_spec->hdr.hdr_checksum = RTE_BE16(integervalue(yytext));             \
      ip4_mask->hdr.hdr_checksum = 0xFFFF;                                     \
    }                                                                          \
  }

#define YY_IP_END(yy)                                                          \
  {                                                                            \
    struct rte_flow_item_ipv4 *ip4_spec = yy->spec[yy->layerid];               \
    struct rte_flow_item_ipv4 *ip4_mask = yy->mask[yy->layerid];               \
    YY_PATTERN(yy, RTE_FLOW_ITEM_TYPE_IPV4, ip4_spec, ip4_mask);               \
    yy->layerid++;                                                             \
  }

#define YY_IP6_START(yy)                                                       \
  {                                                                            \
    alloc_specmask(yy->spec, yy->mask, yy->layerid,                            \
                   sizeof(struct rte_flow_item_ipv6));                         \
  }
#define YY_IP6_ADDR(yy, yytext, src)
#define YY_IP6_FIELD(yy, yytext, name)                                         \
  {                                                                            \
    struct rte_flow_item_ipv6 *ip6_spec = yy->spec[yy->layerid];               \
    struct rte_flow_item_ipv6 *ip6_mask = yy->mask[yy->layerid];               \
    if (!strcmp(name, "version")) {                                            \
      ip6_spec->hdr.vtc_flow |= RTE_BE32(integervalue(yytext) << 28);          \
      ip6_mask->hdr.vtc_flow |= RTE_BE32(0xF0000000);                          \
    } else if (!strcmp(name, "traffic_class")) {                               \
      ip6_spec->hdr.vtc_flow |= RTE_BE32(integervalue(yytext) << 20);          \
      ip6_mask->hdr.vtc_flow |= RTE_BE32(0x0FF00000);                          \
    } else if (!strcmp(name, "flowlabel")) {                                   \
      ip6_spec->hdr.vtc_flow |= RTE_BE32(integervalue(yytext));                \
      ip6_mask->hdr.vtc_flow |= RTE_BE32(0xFFFFF);                             \
    } else if (!strcmp(name, "plen")) {                                        \
      ip6_spec->hdr.payload_len = RTE_BE16(integervalue(yytext));              \
      ip6_mask->hdr.payload_len = RTE_BE16(0xFFFF);                            \
    } else if (!strcmp(name, "nexthdr")) {                                     \
      ip6_spec->hdr.proto = integervalue(yytext);                              \
      ip6_mask->hdr.proto = 0xFF;                                              \
    } else if (!strcmp(name, "hotlimit")) {                                    \
      ip6_spec->hdr.hop_limits = integervalue(yytext);                         \
      ip6_mask->hdr.hop_limits = 0xFF;                                         \
    }                                                                          \
  }
#define YY_IP6_END(yy)                                                         \
  {                                                                            \
    struct rte_flow_item_ipv6 *ip6_spec = yy->spec[yy->layerid];               \
    struct rte_flow_item_ipv6 *ip6_mask = yy->mask[yy->layerid];               \
    YY_PATTERN(yy, RTE_FLOW_ITEM_TYPE_IPV6, ip6_spec, ip6_mask);               \
    yy->layerid++;                                                             \
  }

#define YY_UDP_START(yy)                                                       \
  {                                                                            \
    alloc_specmask(yy->spec, yy->mask, yy->layerid,                            \
                   sizeof(struct rte_flow_item_udp));                          \
  }
#define YY_UDP_FIELD(yy, yytext, off)                                          \
  {                                                                            \
    struct rte_flow_item_udp *udp_spec = yy->spec[yy->layerid];                \
    struct rte_flow_item_udp *udp_mask = yy->mask[yy->layerid];                \
    if (off == 0) {                                                            \
      udp_spec->hdr.src_port = RTE_BE16(integervalue(yytext));                 \
      udp_mask->hdr.src_port = 0xFFFF;                                         \
    } else if (off == 2) {                                                     \
      udp_spec->hdr.dst_port = RTE_BE16(integervalue(yytext));                 \
      udp_mask->hdr.dst_port = 0xFFFF;                                         \
    } else if (off == 4) {                                                     \
      udp_spec->hdr.dgram_len = RTE_BE16(integervalue(yytext));                \
      udp_mask->hdr.dgram_len = 0xFFFF;                                        \
    } else if (off == 6) {                                                     \
      udp_spec->hdr.dgram_cksum = RTE_BE16(integervalue(yytext));              \
      udp_mask->hdr.dgram_cksum = 0xFFFF;                                      \
    }                                                                          \
  }
#define YY_UDP_END(yy)                                                         \
  {                                                                            \
    struct rte_flow_item_udp *udp_spec = yy->spec[yy->layerid];                \
    struct rte_flow_item_udp *udp_mask = yy->mask[yy->layerid];                \
    YY_PATTERN(yy, RTE_FLOW_ITEM_TYPE_UDP, udp_spec, udp_mask);                \
    yy->layerid++;                                                             \
  }

#define YY_TCP_START(yy)                                                       \
  {                                                                            \
    alloc_specmask(yy->spec, yy->mask, yy->layerid,                            \
                   sizeof(struct rte_flow_item_tcp));                          \
  }
#define YY_TCP_FIELD1(yy, yytext, off)                                         \
  {                                                                            \
    struct rte_flow_item_tcp *tcp_spec = yy->spec[yy->layerid];                \
    struct rte_flow_item_tcp *tcp_mask = yy->mask[yy->layerid];                \
    tcp_spec->hdr.data_off = integervalue(yytext);                             \
    tcp_mask->hdr.data_off = integervalue(yytext);                             \
  }
#define YY_TCP_FIELD2(yy, yytext, off)                                         \
  {                                                                            \
    struct rte_flow_item_tcp *tcp_spec = yy->spec[yy->layerid];                \
    struct rte_flow_item_tcp *tcp_mask = yy->mask[yy->layerid];                \
    if (off == 0) {                                                            \
      tcp_spec->hdr.src_port = RTE_BE16(integervalue(yytext));                 \
      tcp_mask->hdr.src_port = 0xFFFF;                                         \
    } else if (off == 2) {                                                     \
      tcp_spec->hdr.dst_port = RTE_BE16(integervalue(yytext));                 \
      tcp_mask->hdr.dst_port = 0xFFFF;                                         \
    } else if (off == 14) {                                                    \
      tcp_spec->hdr.rx_win = RTE_BE16(integervalue(yytext));                   \
      tcp_mask->hdr.rx_win = 0xFFFF;                                           \
    } else if (off == 16) {                                                    \
      tcp_spec->hdr.cksum = RTE_BE16(integervalue(yytext));                    \
      tcp_mask->hdr.cksum = 0xFFFF;                                            \
    } else if (off == 18) {                                                    \
      tcp_spec->hdr.tcp_urp = RTE_BE16(integervalue(yytext));                  \
      tcp_mask->hdr.tcp_urp = 0xFFFF;                                          \
    }                                                                          \
  }
#define YY_TCP_FIELD4(yy, yytext, off)                                         \
  {                                                                            \
    struct rte_flow_item_tcp *tcp_spec = yy->spec[yy->layerid];                \
    struct rte_flow_item_tcp *tcp_mask = yy->mask[yy->layerid];                \
    if (off == 4) {                                                            \
      tcp_spec->hdr.sent_seq = RTE_BE32(integervalue(yytext));                 \
      tcp_mask->hdr.sent_seq = 0xFFFFFFFF;                                     \
    } else if (off == 8) {                                                     \
      tcp_spec->hdr.recv_ack = RTE_BE16(integervalue(yytext));                 \
      tcp_mask->hdr.recv_ack = 0xFFFFFFFF;                                     \
    }                                                                          \
  }

static const char *tcpflags[] = {
    "fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr",
};

#define YY_TCP_FLAGS(yy, yytext)                                               \
  {                                                                            \
    uint8_t flag = 0;                                                          \
    for (int i = 0; i < sizeof(tcpflags) / sizeof(char *); i++) {              \
      if (strstr(yytext, tcpflags[i])) {                                       \
        flag |= (1 << i);                                                      \
      }                                                                        \
    }                                                                          \
    struct rte_flow_item_tcp *tcp_spec = yy->spec[yy->layerid];                \
    struct rte_flow_item_tcp *tcp_mask = yy->mask[yy->layerid];                \
    tcp_spec->hdr.tcp_flags = flag;                                            \
    tcp_mask->hdr.tcp_flags = flag;                                            \
  }

#define YY_TCP_END(yy)                                                         \
  {                                                                            \
    struct rte_flow_item_tcp *tcp_spec = yy->spec[yy->layerid];                \
    struct rte_flow_item_tcp *tcp_mask = yy->mask[yy->layerid];                \
    YY_PATTERN(yy, RTE_FLOW_ITEM_TYPE_TCP, tcp_spec, tcp_mask);                \
    yy->layerid++;                                                             \
  }

#define YY_ICMP_START(yy)                                                      \
  {                                                                            \
    alloc_specmask(yy->spec, yy->mask, yy->layerid,                            \
                   sizeof(struct rte_flow_item_icmp));                         \
  }

#define YY_ICMP_FIELD1(yy, yytext, off)                                        \
  {                                                                            \
    struct rte_flow_item_icmp *icmp_spec = yy->spec[yy->layerid];              \
    struct rte_flow_item_icmp *icmp_mask = yy->mask[yy->layerid];              \
    if (off == 0) {                                                            \
      icmp_spec->hdr.icmp_type = integervalue(yytext);                         \
      icmp_mask->hdr.icmp_type = 0xFF;                                         \
    } else if (off == 1) {                                                     \
      icmp_spec->hdr.icmp_code = integervalue(yytext);                         \
      icmp_mask->hdr.icmp_code = 0xFF;                                         \
    }                                                                          \
  }
#define YY_ICMP_FIELD2(yy, yytext, off)                                        \
  {                                                                            \
    struct rte_flow_item_icmp *icmp_spec = yy->spec[yy->layerid];              \
    struct rte_flow_item_icmp *icmp_mask = yy->mask[yy->layerid];              \
    if (off == 2) {                                                            \
      icmp_spec->hdr.icmp_cksum = RTE_BE16(integervalue(yytext));              \
      icmp_mask->hdr.icmp_cksum = 0xFFFF;                                      \
    } else if (off == 4) {                                                     \
      icmp_spec->hdr.icmp_ident = RTE_BE16(integervalue(yytext));              \
      icmp_mask->hdr.icmp_ident = 0xFFFF;                                      \
    } else if (off == 6) {                                                     \
      icmp_spec->hdr.icmp_seq_nb = RTE_BE16(integervalue(yytext));             \
      icmp_mask->hdr.icmp_seq_nb = 0xFFFF;                                     \
    }                                                                          \
  }
#define YY_ICMP_END(yy)                                                        \
  {                                                                            \
    struct rte_flow_item_icmp *icmp_spec = yy->spec[yy->layerid];              \
    struct rte_flow_item_icmp *icmp_mask = yy->mask[yy->layerid];              \
    YY_PATTERN(yy, RTE_FLOW_ITEM_TYPE_ICMP, icmp_spec, icmp_mask);             \
    yy->layerid++;                                                             \
  }

#define YY_ARP_START(yy)                                                       \
  {                                                                            \
    alloc_specmask(yy->spec, yy->mask, yy->layerid,                            \
                   sizeof(struct rte_flow_item_arp_eth_ipv4));                 \
  }
#define YY_ARP_ADDR(yy, yytext, off)                                           \
  {                                                                            \
    uint32_t addr, mask;                                                       \
    ipstr2addr(yytext, &addr, &mask);                                          \
    struct rte_flow_item_arp_eth_ipv4 *arp_spec = yy->spec[yy->layerid];       \
    struct rte_flow_item_arp_eth_ipv4 *arp_mask = yy->mask[yy->layerid];       \
    if (off == 14) {                                                           \
      arp_spec->spa = addr;                                                    \
      arp_mask->spa = mask;                                                    \
    } else if (off == 24) {                                                    \
      arp_spec->tpa = addr;                                                    \
      arp_mask->tpa = mask;                                                    \
    }                                                                          \
  }
#define YY_ARP_MAC(yy, yytext, off)                                            \
  {                                                                            \
    unsigned char addr[ETH_ALEN];                                              \
    unsigned char mask[ETH_ALEN];                                              \
    macstr2addr(yytext, addr, mask);                                           \
    struct rte_flow_item_arp_eth_ipv4 *arp_spec = yy->spec[yy->layerid];       \
    struct rte_flow_item_arp_eth_ipv4 *arp_mask = yy->mask[yy->layerid];       \
    if (off == 8) {                                                            \
      memcpy(&arp_spec->sha, addr, ETH_ALEN);                                   \
      memcpy(&arp_mask->sha, mask, ETH_ALEN);                                   \
    } else if (off == 18) {                                                    \
      memcpy(&arp_spec->tha, addr, ETH_ALEN);                                   \
      memcpy(&arp_mask->tha, mask, ETH_ALEN);                                   \
    }                                                                          \
  }
#define YY_ARP_FIELD1(yy, yytext, off)                                         \
  {                                                                            \
    struct rte_flow_item_arp_eth_ipv4 *arp_spec = yy->spec[yy->layerid];       \
    struct rte_flow_item_arp_eth_ipv4 *arp_mask = yy->mask[yy->layerid];       \
    if (off == 4) {                                                            \
      arp_spec->hln = integervalue(yytext);                                    \
      arp_mask->hln = 0xFF;                                                    \
    } else if (off == 5) {                                                     \
      arp_spec->pln = integervalue(yytext);                                    \
      arp_mask->pln = 0xFF;                                                    \
    }                                                                          \
  }
#define YY_ARP_FIELD2(yy, yytext, off)                                         \
  {                                                                            \
    struct rte_flow_item_arp_eth_ipv4 *arp_spec = yy->spec[yy->layerid];       \
    struct rte_flow_item_arp_eth_ipv4 *arp_mask = yy->mask[yy->layerid];       \
    if (off == 0) {                                                            \
      arp_spec->hrd = RTE_BE16(integervalue(yytext));                          \
      arp_mask->hrd = 0xFFFF;                                                  \
    } else if (off == 2) {                                                     \
      arp_spec->pro = RTE_BE16(integervalue(yytext));                          \
      arp_mask->pro = 0xFFFF;                                                  \
    } else if (off == 6) {                                                     \
      arp_spec->op = RTE_BE16(integervalue(yytext));                           \
      arp_mask->op = 0xFFFF;                                                   \
    }                                                                          \
  }
#define YY_ARP_END(yy)                                                         \
  {                                                                            \
    struct rte_flow_item_arp_eth_ipv4 *arp_spec = yy->spec[yy->layerid];       \
    struct rte_flow_item_arp_eth_ipv4 *arp_mask = yy->mask[yy->layerid];       \
    YY_PATTERN(yy, RTE_FLOW_ITEM_TYPE_ARP_ETH_IPV4, arp_spec, arp_mask);       \
    yy->layerid++;                                                             \
  }

#define YY_VXLAN_START(yy)                                                     \
  {                                                                            \
    alloc_specmask(yy->spec, yy->mask, yy->layerid,                            \
                   sizeof(struct rte_flow_item_vxlan));                        \
  }
#define YY_VXLAN_FLAG(yy, yytext)                                              \
  {                                                                            \
    struct rte_flow_item_vxlan *vxlan_spec = yy->spec[yy->layerid];            \
    struct rte_flow_item_vxlan *vxlan_mask = yy->mask[yy->layerid];            \
    vxlan_spec->hdr.vx_flags = RTE_BE32(integervalue(yytext) << 24);           \
    vxlan_mask->hdr.vx_flags = RTE_BE32(0xFF000000);                           \
  }
#define YY_VXLAN_VNI(yy, yytext)                                               \
  {                                                                            \
    struct rte_flow_item_vxlan *vxlan_spec = yy->spec[yy->layerid];            \
    struct rte_flow_item_vxlan *vxlan_mask = yy->mask[yy->layerid];            \
    vxlan_spec->hdr.vx_vni = RTE_BE32(integervalue(yytext) << 8);              \
    vxlan_mask->hdr.vx_vni = RTE_BE32(0xFFFFFF00);                             \
  }

#define YY_VXLAN_END(yy)                                                       \
  {                                                                            \
    struct rte_flow_item_vxlan *vxlan_spec = yy->spec[yy->layerid];            \
    struct rte_flow_item_vxlan *vxlan_mask = yy->mask[yy->layerid];            \
    YY_PATTERN(yy, RTE_FLOW_ITEM_TYPE_VXLAN, vxlan_spec, vxlan_mask);          \
    yy->layerid++;                                                             \
  }

#define YY_GENEVE_START(yy)                                                    \
  {                                                                            \
    alloc_specmask(yy->spec, yy->mask, yy->layerid,                            \
                   sizeof(struct rte_flow_item_geneve));                       \
  }
#define YY_GENEVE_VER(yy, yytext)                                              \
  {                                                                            \
    struct rte_flow_item_geneve *geneve_spec = yy->spec[yy->layerid];          \
    struct rte_flow_item_geneve *geneve_mask = yy->mask[yy->layerid];          \
    geneve_spec->ver_opt_len_o_c_rsvd0 |=                                      \
        RTE_BE16(integervalue(yytext) << 14);                                  \
    geneve_mask->ver_opt_len_o_c_rsvd0 |= RTE_BE16(0xC000);                    \
  }
#define YY_GENEVE_OPTLEN(yy, yytext)                                           \
  {                                                                            \
    struct rte_flow_item_geneve *geneve_spec = yy->spec[yy->layerid];          \
    struct rte_flow_item_geneve *geneve_mask = yy->mask[yy->layerid];          \
    geneve_spec->ver_opt_len_o_c_rsvd0 |= RTE_BE16(integervalue(yytext) << 8); \
    geneve_mask->ver_opt_len_o_c_rsvd0 |= RTE_BE16(0x3FFF);                    \
  }
#define YY_GENEVE_PROTO(yy, yytext)                                            \
  {                                                                            \
    struct rte_flow_item_geneve *geneve_spec = yy->spec[yy->layerid];          \
    struct rte_flow_item_geneve *geneve_mask = yy->mask[yy->layerid];          \
    geneve_spec->protocol = RTE_BE16(integervalue(yytext));                    \
    geneve_mask->protocol = 0xFFFF;                                            \
  }
#define YY_GENEVE_VNI(yy, yytext)                                              \
  {                                                                            \
    struct rte_flow_item_geneve *geneve_spec = yy->spec[yy->layerid];          \
    struct rte_flow_item_geneve *geneve_mask = yy->mask[yy->layerid];          \
    geneve_spec->vni[0] = (integervalue(yytext) >> 16) & 0xFF;                 \
    geneve_mask->vni[0] = 0xFF;                                                \
    geneve_spec->vni[1] = (integervalue(yytext) >> 8) & 0xFF;                  \
    geneve_mask->vni[1] = 0xFF;                                                \
    geneve_spec->vni[2] = integervalue(yytext) & 0xFF;                         \
    geneve_mask->vni[2] = 0xFF;                                                \
  }
#define YY_GENEVE_END(yy)                                                      \
  {                                                                            \
    struct rte_flow_item_geneve *geneve_spec = yy->spec[yy->layerid];          \
    struct rte_flow_item_geneve *geneve_mask = yy->mask[yy->layerid];          \
    YY_PATTERN(yy, RTE_FLOW_ITEM_TYPE_GENEVE, geneve_spec, geneve_mask);       \
    yy->layerid++;                                                             \
  }

#define YY_ICMP6_START(yy)                                                     \
  {                                                                            \
    alloc_specmask(yy->spec, yy->mask, yy->layerid,                            \
                   sizeof(struct rte_flow_item_icmp6));                        \
  }
#define YY_ICMP6_FIELD1(yy, yytext, off)                                       \
  {                                                                            \
    struct rte_flow_item_icmp6 *icmp6_spec = yy->spec[yy->layerid];            \
    struct rte_flow_item_icmp6 *icmp6_mask = yy->mask[yy->layerid];            \
    if (off == 0) {                                                            \
      icmp6_spec->type = integervalue(yytext);                                 \
      icmp6_mask->type = 0xFF;                                                 \
    } else if (off == 1) {                                                     \
      icmp6_spec->code = integervalue(yytext);                                 \
      icmp6_mask->code = 0xFF;                                                 \
    }                                                                          \
  }
#define YY_ICMP6_FIELD2(yy, yytext, off)                                       \
  {                                                                            \
    struct rte_flow_item_icmp6 *icmp6_spec = yy->spec[yy->layerid];            \
    struct rte_flow_item_icmp6 *icmp6_mask = yy->mask[yy->layerid];            \
    if (off == 2) {                                                            \
      icmp6_spec->checksum = RTE_BE16(integervalue(yytext));                   \
      icmp6_mask->checksum = 0xFFFF;                                           \
    }                                                                          \
  }

#define YY_ICMP6_END(yy)                                                       \
  {                                                                            \
    struct rte_flow_item_icmp6 *icmp6_spec = yy->spec[yy->layerid];            \
    struct rte_flow_item_icmp6 *icmp6_mask = yy->mask[yy->layerid];            \
    YY_PATTERN(yy, RTE_FLOW_ITEM_TYPE_ICMP6, icmp6_spec, icmp6_mask);          \
    yy->layerid++;                                                             \
  }

#define YY_MPLS_START(yy)                                                      \
  {                                                                            \
    alloc_specmask(yy->spec, yy->mask, yy->layerid,                            \
                   sizeof(struct rte_flow_item_mpls));                         \
  }
#define YY_MPLS_LABEL(yy, yytext)                                              \
  {                                                                            \
    struct rte_flow_item_mpls *mpls_spec = yy->spec[yy->layerid];              \
    struct rte_flow_item_mpls *mpls_mask = yy->mask[yy->layerid];              \
    mpls_spec->label_tc_s[0] = integervalue(yytext) & 0xFF;                    \
    mpls_mask->label_tc_s[0] = 0xFF;                                           \
    mpls_spec->label_tc_s[1] = integervalue(yytext) & 0xFF00 >> 8;             \
    mpls_mask->label_tc_s[1] = 0xFF;                                           \
    mpls_spec->label_tc_s[2] |= integervalue(yytext) & 0xF0000 >> 16;          \
    mpls_mask->label_tc_s[2] |= 0xF0;                                          \
  }
#define YY_MPLS_EXP(yy, yytext)                                                \
  {                                                                            \
    struct rte_flow_item_mpls *mpls_spec = yy->spec[yy->layerid];              \
    struct rte_flow_item_mpls *mpls_mask = yy->mask[yy->layerid];              \
    mpls_spec->label_tc_s[2] |= (integervalue(yytext) < 1);                    \
    mpls_mask->label_tc_s[2] |= 0x0E;                                          \
  }
#define YY_MPLS_S(yy, yytext)                                                  \
  {                                                                            \
    struct rte_flow_item_mpls *mpls_spec = yy->spec[yy->layerid];              \
    struct rte_flow_item_mpls *mpls_mask = yy->mask[yy->layerid];              \
    mpls_spec->label_tc_s[2] |= integervalue(yytext);                          \
    mpls_mask->label_tc_s[2] |= 0x01;                                          \
  }
#define YY_MPLS_TTL(yy, yytext)                                                \
  {                                                                            \
    struct rte_flow_item_mpls *mpls_spec = yy->spec[yy->layerid];              \
    struct rte_flow_item_mpls *mpls_mask = yy->mask[yy->layerid];              \
    mpls_spec->ttl = integervalue(yytext);                                     \
    mpls_mask->ttl = 0xFF;                                                     \
  }
#define YY_MPLS_END(yy)                                                        \
  {                                                                            \
    struct rte_flow_item_mpls *mpls_spec = yy->spec[yy->layerid];              \
    struct rte_flow_item_mpls *mpls_mask = yy->mask[yy->layerid];              \
    YY_PATTERN(yy, RTE_FLOW_ITEM_TYPE_MPLS, mpls_spec, mpls_mask);             \
    yy->layerid++;                                                             \
  }

#define YY_SCTP_START(yy)
#define YY_SCTP_FIELD2(yy, yytext, off)
#define YY_SCTP_FIELD4(yy, yytext, off)
#define YY_SCTP_END(yy)

#define YY_GRE_START(yy)
#define YY_GRE_C(yy, yytext)
#define YY_GRE_VER(yy, yytext)
#define YY_GRE_PROTO(yy, yytext)
#define YY_GRE_CSUM(yy, yytext)
#define YY_GRE_END(yy)

#define YY_OSPF_START(yy)
#define YY_OSPF_FIELD1(yy, yytext, off)
#define YY_OSPF_FIELD2(yy, yytext, off)
#define YY_OSPF_FIELD4(yy, yytext, off)
#define YY_OSPF_AUTH(yy, yytext)
#define YY_OSPF_END(yy)

#define YY_RSS(yy, yytext)                                                     \
  {                                                                            \
    struct rte_flow_action *act = &yy->flows.actions[yy->flows.naction];       \
    uint16_t queues[32];                                                       \
    for (int i = 0; i < 32; i++) {                                             \
      queues[i] = i;                                                           \
    }                                                                          \
    act->type = RTE_FLOW_ACTION_TYPE_RSS;                                      \
    struct rte_flow_action_rss *rss =                                          \
        malloc(sizeof(struct rte_flow_action_rss));                            \
    act->conf = rss;                                                           \
    rss->level = 2;                                                      \
    rss->types = ETH_RSS_IPV4 | ETH_RSS_UDP | ETH_RSS_TCP;               \
    rss->queue_num = integervalue(yytext);                               \
    rss->queue = queues;                                                 \
    yy->flows.naction++;                                                       \
  }
#define YY_QUEUE(yy, yytext) \
  { \
  }
#define YY_DROP(yy)
#define YY_PORT(yy)
#define YY_SAMPLE(yy)

#include "parser.c"

void yyerror(yycontext *ctx, char *message) {
  fprintf(stderr, " %s", message);

  if (ctx->__pos < ctx->__limit) {
    // Find the offending line.
    int pos = ctx->__limit;
    while (ctx->__pos < pos) {
      if (ctx->__buf[pos] == '\n') {
        ++pos;
        break;
      }
      --pos;
    }

    ctx->__buf[ctx->__limit] = '\0';
    fprintf(stderr, "%s", ctx->__buf + pos);
  }

  fprintf(stderr, "\n");
}

struct rte_flow *dpdkflow_compile(uint16_t port_id,
                                  struct rte_flow_attr *attr,
                                  char *capstr)
{
  printf("%s\n", capstr);
  yycontext ctx;
  memset(&ctx, 0, sizeof(yycontext));
  FILE *stream = fmemopen(capstr, strlen(capstr), "r");
  ctx.stream = stream;
  ctx.flows.items = malloc(rflow_len * sizeof(struct rte_flow_item));
  if (yyparse(&ctx) == 0) {
    yyerror(&ctx, "syntax error\n");
    fclose(stream);
    free(ctx.flows.items);
    return NULL;
  }
  fclose(stream);
  
  rflow_append(&ctx.flows, RTE_FLOW_ITEM_TYPE_END, NULL, NULL);

  struct rte_flow_action *act = &ctx.flows.actions[ctx.flows.naction];
  act->type = RTE_FLOW_ACTION_TYPE_END;
  act->conf = NULL;

  struct rte_flow_error error;
  memset(&error, 0, sizeof(error));
  int ret = rte_flow_validate(port_id, attr, ctx.flows.items, ctx.flows.actions, &error);
  if (ret < 0) {
    printf("error in the flow %s\n", rte_strerror(rte_errno));
    return NULL;
  }
  memset(&error, 0, sizeof(error));
  struct rte_flow *f = rte_flow_create(port_id, attr, ctx.flows.items, ctx.flows.actions, &error);
  if (f == NULL) {
    printf("fail to create flow %s\n", rte_strerror(rte_errno));
    return NULL;
  }
  free(ctx.flows.items);
  YYRELEASE(&ctx);

  return f;
}