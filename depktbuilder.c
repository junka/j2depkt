#include <stdbool.h>
#include <stdlib.h>

#include <stdint.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_arp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/mpls.h>
#include <linux/ipv6.h>
#include <endian.h>

#include "depktbuilder.h"
#include "utils.h"

#define FRAME_SIZE 1518

struct vlan {
  uint16_t tci;
  uint16_t proto;
};

static int plen = FRAME_SIZE;

static void* pkt_layer_push(void *pkt, int *pkt_len, int size) {
  if (size + *pkt_len > plen) {
    plen <<= 1;
    pkt = realloc(pkt, plen);
  }
  void * d = pkt + *pkt_len;
  *pkt_len += size;
  return d;
}

#define YY_CTX_LOCAL

#define YY_INPUT(ctx, buf, result, max)                                        \
  {                                                                            \
    int c = fgetc(ctx->stream);                                                \
    result = (EOF == c) ? 0 : (*(buf) = c, 1);                                 \
  }

#define YY_CTX_MEMBERS \
  FILE *stream; \
  void *pkt; \
  int pkt_len; \
  void *cur;

#define YY_VLAN_START(yy)                                                      \
  { yy->cur = pkt_layer_push(yy->pkt, &yy->pkt_len, sizeof(struct vlan)); }
#define YY_VLAN_PROTO(yy, yytext)                                              \
  {                                                                            \
    struct vlan *v = yy->cur;                                                  \
    v->proto = integervalue(yytext);                                           \
  }
#define YY_VLAN_TAG(yy, yytext)                                                \
  {                                                                            \
    struct vlan *v = yy->cur;                                                  \
    v->tci = integervalue(yytext);                                             \
  }
#define YY_VLAN_END(yy)

#define YY_ETHER_START(yy)                                                     \
  {                                                                            \
    yy->cur = pkt_layer_push(yy->pkt, &yy->pkt_len, sizeof(struct ethhdr));    \
  }
#define YY_ETHER_MAC(yy, yytext, src)                                          \
  {                                                                            \
    struct ethhdr *eth = yy->cur;                                              \
    unsigned char addr[ETH_ALEN];                                              \
    unsigned char mask[ETH_ALEN];                                              \
    macstr2addr(yytext, addr, mask);                                           \
    if (src) {                                                                 \
      memcpy(eth->h_source, addr, ETH_ALEN);                                   \
    } else {                                                                   \
      memcpy(eth->h_dest, addr, ETH_ALEN);                                     \
    }                                                                          \
  }
#define YY_ETHER_TYPE(yy, yytext)                                              \
  {                                                                            \
    struct ethhdr *eth = yy->cur;                                              \
    eth->h_proto = integervalue(yytext);                                       \
  }
#define YY_ETHER_END(yy)

#define YY_IP_START(yy)                                                        \
  {                                                                            \
    yy->cur = pkt_layer_push(yy->pkt, &yy->pkt_len, sizeof(struct iphdr));     \
    struct iphdr *ip = yy->cur;                                                \
    ip->version = 4;                                                           \
    ip->ihl = 5;                                                               \
    ip->tos = 0;                                                               \
    ip->ttl = 64;                                                              \
    ip->check = 0;                                                             \
    ip->id = 0;                                                                \
    ip->frag_off = 0;                                                          \
    ip->protocol = 17;                                                         \
  }
#define YY_IP_ADDR(yy, yytext, src)                                            \
  {                                                                            \
    struct iphdr *ip = yy->cur;                                                \
    uint32_t addr, mask;                                                       \
    ipstr2addr(yytext, &addr, &mask);                                          \
    if (src) {                                                                 \
      ip->saddr = addr;                                                        \
    } else {                                                                   \
      ip->daddr = addr;                                                        \
    }                                                                          \
  }
#define YY_IP_FIELD2(yy, yytext, off)                                          \
  {                                                                            \
    struct iphdr *ip = yy->cur;                                                \
    if (off == 2) {                                                            \
      ip->tot_len = integervalue(yytext);                                      \
    } else if (off == 4) {                                                     \
      ip->id = integervalue(yytext);                                           \
    } else if (off == 6) {                                                     \
      ip->frag_off = integervalue(yytext);                                     \
    } else if (off == 10) {                                                    \
      ip->check = integervalue(yytext);                                        \
    }                                                                          \
  }
#define YY_IP_FIELD1(yy, yytext, off)                                          \
  {                                                                            \
    struct iphdr *ip = yy->cur;                                                \
    if (off == 1) {                                                            \
      ip->tos = integervalue(yytext);                                          \
    } else if (off == 8) {                                                     \
      ip->ttl = integervalue(yytext);                                          \
    } else if (off == 9) {                                                     \
      ip->protocol = integervalue(yytext);                                     \
    }                                                                          \
  }
#define YY_IP_END(yy)

#define YY_UDP_START(yy)                                                       \
  {                                                                            \
    yy->cur = pkt_layer_push(yy->pkt, &yy->pkt_len, sizeof(struct iphdr));     \
    struct udphdr *udp = yy->cur;                                              \
    udp->source = 0;                                                           \
    udp->dest = 0;                                                             \
  }
#define YY_UDP_FIELD(yy, yytext, off)                                          \
  {                                                                            \
    struct udphdr *udp = yy->cur;                                              \
    if (off == 0) {                                                            \
      udp->source = integervalue(yytext);                                      \
    } else if (off == 2) {                                                     \
      udp->dest = integervalue(yytext);                                        \
    } else if (off == 4) {                                                     \
      udp->len = integervalue(yytext);                                         \
    } else if (off == 6) {                                                     \
      udp->check = integervalue(yytext);                                       \
    }                                                                          \
  }
#define YY_UDP_END(yy)

#define YY_TCP_START(yy)                                                       \
  {                                                                            \
    yy->cur = pkt_layer_push(yy->pkt, &yy->pkt_len, sizeof(struct iphdr));     \
    struct tcphdr *tcp = yy->cur;                                              \
    tcp->source = 0;                                                           \
    tcp->dest = 0;                                                             \
  }
#define YY_TCP_FIELD2(yy, yytext, off)                                         \
  {                                                                            \
    struct tcphdr *tcp = yy->cur;                                              \
    if (off == 0) {                                                            \
      tcp->source = integervalue(yytext);                                      \
    } else if (off == 2) {                                                     \
      tcp->ack_seq = integervalue(yytext);                                     \
    } else if (off == 14) {                                                    \
      tcp->window = integervalue(yytext);                                      \
    } else if (off == 16) {                                                    \
      tcp->check = integervalue(yytext);                                       \
    } else if (off == 18) {                                                    \
      tcp->urg_ptr = integervalue(yytext);                                     \
    }                                                                          \
  }
#define YY_TCP_FIELD1(yy, yytext, off)                                         \
  {                                                                            \
    struct tcphdr *tcp = yy->cur;                                              \
    if (off == 12) {                                                           \
      tcp->doff = integervalue(yytext);                                        \
    }                                                                          \
  }
#define YY_TCP_FIELD4(yy, yytext, off)                                         \
  {                                                                            \
    struct tcphdr *tcp = yy->cur;                                              \
    if (off == 4) {                                                            \
      tcp->seq = 0;                                                            \
    } else if (off == 8) {                                                     \
      tcp->ack_seq = 0;                                                        \
    }                                                                          \
  }
#define YY_TCP_FLAGS(yy, yytext)
#define YY_TCP_END(yy)

#define YY_ARP_START(yy)                                                       \
  {                                                                            \
    yy->cur = pkt_layer_push(yy->pkt, &yy->pkt_len, sizeof(struct arphdr)+20); \
    struct arphdr *arp = yy->cur;                                              \
    arp->ar_hrd = 0;                                                           \
    arp->ar_pro = 0;                                                           \
  }
#define YY_ARP_ADDR(yy, yytext, off)                                           \
  {                                                                            \
    struct arphdr *arp = yy->cur;                                              \
    uint32_t addr, mask;                                                       \
    ipstr2addr(yytext, &addr, &mask);                                          \
  }
#define YY_ARP_MAC(yy, yytext, off)
#define YY_ARP_FIELD1(yy, yytext, off)                                         \
  {                                                                            \
    struct arphdr *arp = yy->cur;                                              \
    if (off == 4) {                                                            \
      arp->ar_hln = integervalue(yytext);                                      \
    } else if (off == 5) {                                                     \
      arp->ar_pln = integervalue(yytext);                                      \
    }                                                                          \
  }
#define YY_ARP_FIELD2(yy, yytext, off)                                         \
  {                                                                            \
    struct arphdr *arp = yy->cur;                                              \
    if (off == 0) {                                                            \
      arp->ar_hrd = integervalue(yytext);                                      \
    } else if (off == 2) {                                                     \
      arp->ar_pro = integervalue(yytext);                                      \
    } else if (off == 6) {                                                     \
      arp->ar_op = integervalue(yytext);                                       \
    }                                                                          \
  }
#define YY_ARP_END(yy)
struct vxlan_hdr {
  uint32_t vx_flags; /**< flag (8) + Reserved (24). */
  uint32_t vx_vni;   /**< VNI (24) + Reserved (8). */
};
#define VXLAN_DEFAULT_FLAGS 0x08000000
#define YY_VXLAN_START(yy)                                                     \
  {                                                                            \
    yy->cur = pkt_layer_push(yy->pkt, &yy->pkt_len, sizeof(struct vxlan_hdr)); \
    struct vxlan_hdr *vxlan = yy->cur;                                         \
    vxlan->vx_flags = VXLAN_DEFAULT_FLAGS;                                     \
    vxlan->vx_vni = 0;                                                         \
  }
#define YY_VXLAN_FLAG(yy, yytext)                                              \
  {                                                                            \
    struct vxlan_hdr *vxlan = yy->cur;                                         \
    vxlan->vx_flags = integervalue(yytext);                                    \
  }
#define YY_VXLAN_VNI(yy, yytext)                                               \
  {                                                                            \
    struct vxlan_hdr *vxlan = yy->cur;                                         \
    vxlan->vx_vni = integervalue(yytext);                                      \
  }
#define YY_VXLAN_END(yy)

struct geneve_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
  uint8_t ver : 2;       /**< Version. */
  uint8_t opt_len : 6;   /**< Options length. */
  uint8_t oam : 1;       /**< Control packet. */
  uint8_t critical : 1;  /**< Critical packet. */
  uint8_t reserved1 : 6; /**< Reserved. */
#else
  uint8_t opt_len : 6;   /**< Options length. */
  uint8_t ver : 2;       /**< Version. */
  uint8_t reserved1 : 6; /**< Reserved. */
  uint8_t critical : 1;  /**< Critical packet. */
  uint8_t oam : 1;       /**< Control packet. */
#endif
  uint16_t proto;  /**< Protocol type. */
  uint8_t vni[3];    /**< Virtual network identifier. */
  uint8_t reserved2; /**< Reserved. */
  uint32_t opts[];   /**< Variable length options. */
};

#define YY_GENEVE_START(yy)                                                    \
  {                                                                            \
    yy->cur =                                                                  \
        pkt_layer_push(yy->pkt, &yy->pkt_len, sizeof(struct geneve_hdr));      \
    struct geneve_hdr *geneve = yy->cur;                                       \
    geneve->proto = 0;                                                         \
    geneve->opt_len = 0;                                                       \
  }
#define YY_GENEVE_VER(yy, yytext)                                              \
  {                                                                            \
    struct geneve_hdr *geneve = yy->cur;                                       \
    geneve->vni[0] = 0xFF & (integervalue(yytext) >> 16);                      \
    geneve->vni[1] = 0xFF & (integervalue(yytext) >> 8);                       \
    geneve->vni[2] = 0xFF & (integervalue(yytext));                            \
  }
#define YY_GENEVE_VNI(yy, yytext)                                              \
  {                                                                            \
    struct geneve_hdr *geneve = yy->cur;                                       \
    geneve->ver = integervalue(yytext);                                        \
  }
#define YY_GENEVE_OPTLEN(yy, yytext)                                           \
  {                                                                            \
    struct geneve_hdr *geneve = yy->cur;                                       \
    geneve->opt_len = integervalue(yytext);                                        \
  }
#define YY_GENEVE_PROTO(yy, yytext)                                            \
  {                                                                            \
    struct geneve_hdr *geneve = yy->cur;                                       \
    geneve->proto = integervalue(yytext);                                        \
  }
#define YY_GENEVE_END(yy)

#define YY_ANY_FIELD(yy, yytext, off, size)

#define YY_ICMP_START(yy)                                                      \
  {                                                                            \
    yy->cur = pkt_layer_push(yy->pkt, &yy->pkt_len, sizeof(struct icmphdr));   \
    struct icmphdr *icmp = yy->cur;                                            \
    icmp->type = 0;                                                            \
  }
#define YY_ICMP_FIELD1(yy, yytext, off)                                        \
  {                                                                            \
    struct icmphdr *icmp = yy->cur;                                            \
    if (off == 0) {                                                            \
      icmp->type = integervalue(yytext);                                       \
    } else if (off == 1) {                                                     \
      icmp->code = integervalue(yytext);                                       \
    }                                                                          \
  }

#define YY_ICMP_FIELD2(yy, yytext, off)                                        \
  {                                                                            \
    struct icmphdr *icmp = yy->cur;                                            \
    if (off == 2) {                                                            \
      icmp->checksum = integervalue(yytext);                                   \
    } else if (off == 4) {                                                     \
      icmp->un.echo.id = integervalue(yytext);                                 \
    } else if (off == 6) {                                                     \
      icmp->un.echo.sequence = integervalue(yytext);                           \
    }                                                                          \
  }
#define YY_ICMP_END(yy)

#define YY_ICMP6_START(yy)                                                     \
  {                                                                            \
    yy->cur = pkt_layer_push(yy->pkt, &yy->pkt_len, sizeof(struct icmp6hdr));  \
    struct icmp6hdr *icmp6 = yy->cur;                                          \
    icmp6->icmp6_type = 0;                                                     \
  }
#define YY_ICMP6_FIELD1(yy, yytext, off)                                       \
  {                                                                            \
    struct icmp6hdr *icmp6 = yy->cur;                                          \
    if (off == 0) {                                                            \
      icmp6->icmp6_type = integervalue(yytext);                                \
    } else if (off == 1) {                                                     \
      icmp6->icmp6_code = integervalue(yytext);                                \
    }                                                                          \
  }
#define YY_ICMP6_FIELD2(yy, yytext, off)                                       \
  {                                                                            \
    struct icmp6hdr *icmp6 = yy->cur;                                          \
    if (off == 2) {                                                            \
      icmp6->icmp6_cksum = integervalue(yytext);                               \
    } else if (off == 4) {                                                     \
      icmp6->icmp6_dataun.u_echo.identifier = integervalue(yytext);            \
    } else if (off == 6) {                                                     \
      icmp6->icmp6_dataun.u_echo.sequence = integervalue(yytext);              \
    }                                                                          \
  }
#define YY_ICMP6_END(yy)

#define YY_SCTP_START(yy)
#define YY_SCTP_FIELD2(yy, yytext, off)
#define YY_SCTP_FIELD4(yy, yytext, off)
#define YY_SCTP_END(yy)

#define YY_MPLS_START(yy)                                                      \
  {                                                                            \
    yy->cur =                                                                  \
        pkt_layer_push(yy->pkt, &yy->pkt_len, sizeof(struct mpls_label));      \
    struct mpls_label *mpls = yy->cur;                                         \
    mpls->entry = 0;                                                           \
  }
#define YY_MPLS_LABEL(yy, yytext)                                              \
  {                                                                            \
    struct mpls_label *mpls = yy->cur;                                         \
    mpls->entry |= integervalue(yytext)<< 12;                                  \
  }
#define YY_MPLS_EXP(yy, yytext)                                                \
  {                                                                            \
    struct mpls_label *mpls = yy->cur;                                         \
    mpls->entry |= integervalue(yytext) << 9;                                  \
  }
#define YY_MPLS_S(yy, yytext)                                                  \
  {                                                                            \
    struct mpls_label *mpls = yy->cur;                                         \
    mpls->entry |= integervalue(yytext) << 8;                                  \
  }
#define YY_MPLS_TTL(yy, yytext)                                                \
  {                                                                            \
    struct mpls_label *mpls = yy->cur;                                         \
    mpls->entry |= integervalue(yytext);                                       \
  }
#define YY_MPLS_END(yy)

#define YY_GRE_START(yy)
#define YY_GRE_C(yy, yytext)
#define YY_GRE_VER(yy, yytext)
#define YY_GRE_PROTO(yy, yytext)
#define YY_GRE_CSUM(yy, yytext)
#define YY_GRE_END(yy)

#define YY_IP6_START(yy)                                                       \
  {                                                                            \
    yy->cur = pkt_layer_push(yy->pkt, &yy->pkt_len, sizeof(struct ipv6hdr));   \
    struct ipv6hdr *ip6 = yy->cur;                                             \
    ip6->version = 6;                                                          \
  }
#define YY_IP6_ADDR(yy, yytext, src)                                           \
  {                                                                            \
    struct ipv6hdr *ip6 = yy->cur;                                             \
    uint32_t addr[4], mask[4];                                                 \
    ip6str2addr(yytext, addr, mask);                                           \
    if (src) {                                                                 \
      memcpy(&ip6->saddr, addr, 16);                                           \
    } else {                                                                   \
      memcpy(&ip6->daddr, addr, 16);                                           \
    }                                                                          \
  }
#define YY_IP6_FIELD(yy, yytext, name)                                         \
  {                                                                            \
    struct ipv6hdr *ip6 = yy->cur;                                             \
    if (!strcmp(name, "version")) {                                            \
      ip6->version = integervalue(yytext);                                     \
    } else if (!strcmp(name, "traffic_class")) {                               \
      ip6->priority = integervalue(yytext);                                    \
    } else if (!strcmp(name, "flowlabel")) {                                   \
      ip6->flow_lbl[0] = integervalue(yytext) >> 16;                           \
      ip6->flow_lbl[1] = integervalue(yytext) >> 8;                            \
      ip6->flow_lbl[2] = integervalue(yytext);                                 \
    } else if (!strcmp(name, "plen")) {                                        \
      ip6->payload_len = integervalue(yytext);                                 \
    } else if (!strcmp(yytext, "nexthdr")) {                                   \
      ip6->nexthdr = integervalue(yytext);                                     \
    } else if (!strcmp(name, "hoplimit")) {                                    \
      ip6->hop_limit = integervalue(yytext);                                   \
    }                                                                          \
  }
#define YY_IP6_END(yy)

#define YY_OSPF_START(yy)
#define YY_OSPF_FIELD1(yy, yytext, off)
#define YY_OSPF_FIELD2(yy, yytext, off)
#define YY_OSPF_FIELD4(yy, yytext, off)
#define YY_OSPF_AUTH(yy, yytext)
#define YY_OSPF_END(yy)

static const char *rawmsg = "12345678790abcdefghijklmnopqrstuvwxyz";

#define YY_RAW_START(yy)                                                       \
  {                                                                            \
    yy->cur = pkt_layer_push(yy->pkt, &yy->pkt_len, 100);                      \
  }
#define YY_RAW_PATTERN(yy, yytext)                                             \
  {                                                                            \
    void *msg = yy->cur;                                                       \
    memcpy(msg, yytext, strlen(yytext));                                       \
    if (strlen(yytext) > 100) {                                                \
      pkt_layer_push(yy->pkt, &yy->pkt_len, strlen(msg) - 100);                \
    }                                                                          \
  }
#define YY_RAW_OFF(yy, yytext)
#define YY_RAW_LEN(yy, yytext)
#define YY_RAW_END(yy)

#define YY_RSS(yy, yytext)
#define YY_QUEUE(yy, yytext)
#define YY_DROP(yy)
#define YY_PORT(yy)
#define YY_SAMPLE(yy)
#define YY_COUNT(yy, yytext)
#define YY_MARK(yy, yytext)

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
void *
depkt_build(char *capstr) {
    void * ret = NULL;
    yycontext ctx;
    memset(&ctx, 0, sizeof(yycontext));
    FILE *stream = fmemopen(capstr, strlen(capstr), "r");
    if (!stream) {
      return NULL;
    }
    ctx.stream = stream;
    ctx.pkt = calloc(1, plen);
    if (yyparse(&ctx) == 0) {
      yyerror(&ctx, "syntax error\n");
      fclose(stream);
      return NULL;
    }
    ret = ctx.pkt;
    fclose(stream);
    YYRELEASE(&ctx);
    return ret;
}