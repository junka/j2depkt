

#include <gtest/gtest.h>
#include <stdint.h>
#include <cstdio>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define YY_CTX_LOCAL

#define YY_INPUT(ctx, buf, result, max)                                        \
  {                                                                            \
    int c = fgetc(ctx->stream);                                                \
    result = (EOF == c) ? 0 : (*(buf) = c, 1);                                 \
  }
#define YY_CTX_MEMBERS                                                         \
  FILE *stream;

#define YY_VLAN_START(yy)
#define YY_VLAN_PROTO(yy, yytext)
#define YY_VLAN_TAG(yy, yytext)
#define YY_VLAN_END(yy)

#define YY_ETHER_START(yy)
#define YY_ETHER_MAC(yy, yytext, src)
#define YY_ETHER_TYPE(yy, yytext)
#define YY_ETHER_END(yy)

#define YY_IP_START(yy)
#define YY_IP_ADDR(yy, yytext, src)
#define YY_IP_FIELD2(yy, yytext, off)
#define YY_IP_FIELD1(yy, yytext, off)
#define YY_IP_END(yy)

#define YY_UDP_START(yy)
#define YY_UDP_FIELD(yy, yytext, off)
#define YY_UDP_END(yy)

#define YY_TCP_START(yy)
#define YY_TCP_FIELD1(yy, yytext, off)
#define YY_TCP_FIELD2(yy, yytext, off)
#define YY_TCP_FIELD4(yy, yytext, off)
#define YY_TCP_FLAGS(yy, yytext)
#define YY_TCP_END(yy)

#define YY_ARP_START(yy)
#define YY_ARP_ADDR(yy, yytext, off)
#define YY_ARP_MAC(yy, yytext, off)
#define YY_ARP_FIELD1(yy, yytext, off)
#define YY_ARP_FIELD2(yy, yytext, off)
#define YY_ARP_END(yy)


#define YY_VXLAN_START(yy)
#define YY_VXLAN_FLAG(yy, yytext)
#define YY_VXLAN_VNI(yy, yytext)
#define YY_VXLAN_END(yy)

#define YY_GENEVE_START(yy)
#define YY_GENEVE_VER(yy, yytext)
#define YY_GENEVE_VNI(yy, yytext)
#define YY_GENEVE_OPTLEN(yy, yytext)
#define YY_GENEVE_PROTO(yy, yytext)
#define YY_GENEVE_END(yy)

#define YY_ANY_FIELD(yy, yytext, off, size)

#define YY_ICMP_START(yy)
#define YY_ICMP_FIELD1(yy, yytext, off)
#define YY_ICMP_FIELD2(yy, yytext, off)
#define YY_ICMP_END(yy)

#define YY_ICMP6_START(yy)
#define YY_ICMP6_FIELD1(yy, yytext, off)
#define YY_ICMP6_FIELD2(yy, yytext, off)
#define YY_ICMP6_END(yy)


#define YY_SCTP_START(yy)
#define YY_SCTP_FIELD2(yy, yytext, off)
#define YY_SCTP_FIELD4(yy, yytext, off)
#define YY_SCTP_END(yy)

#define YY_MPLS_START(yy)
#define YY_MPLS_LABEL(yy, yytext)
#define YY_MPLS_EXP(yy, yytext)
#define YY_MPLS_S(yy, yytext)
#define YY_MPLS_TTL(yy, yytext)
#define YY_MPLS_END(yy)

#define YY_GRE_START(yy)
#define YY_GRE_C(yy, yytext)
#define YY_GRE_VER(yy, yytext)
#define YY_GRE_PROTO(yy, yytext)
#define YY_GRE_CSUM(yy, yytext)
#define YY_GRE_END(yy)

#define YY_IP6_START(yy)
#define YY_IP6_ADDR(yy, yytext, src)
#define YY_IP6_FIELD(yy, yytext, name)
#define YY_IP6_END(yy)

#define YY_OSPF_START(yy)
#define YY_OSPF_FIELD1(yy, yytext, off)
#define YY_OSPF_FIELD2(yy, yytext, off)
#define YY_OSPF_FIELD4(yy, yytext, off)
#define YY_OSPF_AUTH(yy, yytext)
#define YY_OSPF_END(yy)

#define YY_RAW_START(yy)
#define YY_RAW_PATTERN(yy, yytext)
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

#include "../parser.c"

#ifdef __cplusplus
}
#endif

using namespace std;

int parse_string(string capstr) {
    yycontext ctx;
    memset(&ctx, 0, sizeof(yycontext));
    FILE *stream = fmemopen((void *)capstr.c_str(), capstr.length(), "r");
    ctx.stream = stream;
    if (yyparse(&ctx) == 0) {
        fclose(stream);
        YYRELEASE(&ctx);
        return 1;
    }
    fclose(stream);
    YYRELEASE(&ctx);
    return 0;
}

// Demonstrate some basic assertions.
TEST(parser, ProtoName) {
    // valid input string.
    EXPECT_EQ(parse_string("ETHER()/IP()/UDP():SAMPLE"),  0);
    EXPECT_EQ(parse_string("ETHER/IP/TCP:DROP"), 0);
    // invalid input string, protocol or action unknown
    EXPECT_EQ(parse_string("ETHER()/IP()/UDP():REP"), 1);
    EXPECT_EQ(parse_string("ETHER()/IPS()/UDP():DROP"), 1);
    EXPECT_EQ(parse_string("ETHER()/IP6()/UDP6:SAMPLE"), 1);
    EXPECT_EQ(parse_string("ETHER/IP4()/ICMP:SAMPLE"), 1);
    EXPECT_EQ(parse_string("ETH/IP/UDP:SAMPLE"), 1);
}

TEST(parser, EtherType) {
    // ether range overflow string
    EXPECT_EQ(parse_string("ETHER(type=0x800)/IP()/UDP():SAMPLE"), 0);
    EXPECT_EQ(parse_string("ETHER(type=2048)/IP()/UDP():DROP"), 0);
    EXPECT_EQ(parse_string("ETHER(type=65536)/IP()/UDP:SAMPLE"), 1);
    EXPECT_EQ(parse_string("ETHER(type=-1)/IP()/UDP:SAMPLE"), 1);
    EXPECT_EQ(parse_string("ETHER(type=0x1FFFF)/IP()/UDP:SAMPLE"), 1);
}

TEST(parser, EtherMac) {
    EXPECT_EQ(parse_string("ETHER(src=3a:0c:52:fe:47:40)/IP:SAMPLE"),0);
    EXPECT_EQ(parse_string("ETHER(dst=3a:0c:52:fe:47:40)/IP()/UDP():DROP"), 0);
    EXPECT_EQ(parse_string("ETHER(src=65536)/IP()/UDP:SAMPLE"), 1);
    EXPECT_EQ(parse_string("ETHER(src=-1)/IP()/UDP:SAMPLE"), 1);
    EXPECT_EQ(parse_string("ETHER(src=0x1FFFF)/IP()/UDP:SAMPLE"), 1);
    EXPECT_EQ(parse_string("ETHER(src=1:2:2:3:2:1)/IP()/UDP:SAMPLE"), 1);
    EXPECT_EQ(parse_string("ETHER(src=3a:0c:52:fe:47:1)/IP()/UDP:SAMPLE"), 1);
    EXPECT_EQ(parse_string("ETHER(src=00:00:52:fe:47:01/FF:FF:FF:aa:aa:aa)/IP()/UDP:SAMPLE"), 0);
}

TEST(parser, IPaddr) {
    EXPECT_EQ(parse_string("ETHER(src=3a:0c:52:fe:47:40)/IP(src=192.168.0.1):SAMPLE"), 0);
    EXPECT_EQ(parse_string("ETHER(type=800)/IP(src=192.168.0.1/32):SAMPLE"), 0);
    EXPECT_EQ(parse_string("ETHER()/IP(src=192.168.0.1/255.255.0.0, tos=1):SAMPLE"), 0);
    EXPECT_EQ(parse_string("ETHER()/IP(dst=192.168.0.1/256.255.0.0):SAMPLE"), 1);
    EXPECT_EQ(parse_string("ETHER()/IP(dst=192.168.0.1/33):SAMPLE"), 1);
    EXPECT_EQ(parse_string("ETHER()/IP(src=192.168.0.1/-1):SAMPLE"), 1);
    EXPECT_EQ(parse_string("ETHER()/IP(src=-2):SAMPLE"), 1);
    EXPECT_EQ(parse_string("ETHER()/IP(src=6288230):SAMPLE"), 1);
    EXPECT_EQ(parse_string("ETHER()/IP(src=192.168.0.1000):SAMPLE"), 1);
    EXPECT_EQ(parse_string("ETHER()/IP(dst=182.1.1):SAMPLE"), 1);
}

TEST(parser, IPField) {
    EXPECT_EQ(parse_string("ETHER/IP(src=192.168.0.1, ttl=32):SAMPLE"), 0);
    EXPECT_EQ(parse_string("ETHER(type=800)/IP(src=192.168.0.1/32):SAMPLE"), 0);
    EXPECT_EQ(parse_string("ETHER()/IP(tos=1, ttl=257):SAMPLE"), 1);
    EXPECT_EQ(parse_string("ETHER()/IP(frag=1):SAMPLE"), 0);
    EXPECT_EQ(parse_string("ETHER()/IP(frag=0x189):SAMPLE"), 0);
    EXPECT_EQ(parse_string("ETHER()/IP(frag=0o1891):SAMPLE"), 1);
    EXPECT_EQ(parse_string("ETHER()/IP(frag=65536):SAMPLE"), 1);
    EXPECT_EQ(parse_string("ETHER()/IP(proto=17):SAMPLE"), 0);
    EXPECT_EQ(parse_string("ETHER()/IP(proto=317):SAMPLE"), 1);
    EXPECT_EQ(parse_string("ETHER()/IP(src=192.168.0.1, id=312):SAMPLE"), 0);
    EXPECT_EQ(parse_string("ETHER()/IP(id=112390):SAMPLE"), 1);
    EXPECT_EQ(parse_string("ETHER()/IP(len=0xffff):SAMPLE"), 0);
    EXPECT_EQ(parse_string("ETHER()/IP(csum=-1):SAMPLE"), 1);
    EXPECT_EQ(parse_string("ETHER()/IP(csum=0x8902):SAMPLE"), 0);
}


TEST(parser, actions) {
    EXPECT_EQ(parse_string("ETHER(type=0x800)/IP(proto=6)/UDP(dst=4789):RSS(queue=4)"), 0);
    EXPECT_EQ(parse_string("ETHER(type=0x800)/IP(proto=6):RSS(queue=-1)"), 1);
    EXPECT_EQ(parse_string("ETHER(type=0x800)/IP(proto=6):RSS"), 0);
    EXPECT_EQ(parse_string("ETHER(type=0x800)/IP(proto=6):SAMPLE"), 0);
    EXPECT_EQ(parse_string("ETHER(type=0x800)/IP(proto=6):QUEUE(id=0)"), 0);
    EXPECT_EQ(parse_string("ETHER(type=0x800)/IP(proto=6):QUEUE(id=-1)"), 1);
}
