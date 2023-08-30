#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#include "depktcap.h"
#include "utils.h"

#define YY_CTX_LOCAL

#define YY_INPUT(ctx, buf, result, max)                                        \
  {                                                                            \
    int c = fgetc(ctx->stream);                                                \
    result = (EOF == c) ? 0 : (*(buf) = c, 1);                                 \
  }

#define YY_CTX_MEMBERS                                                         \
  struct bpf_program prog;                                                     \
  unsigned long offset;                                                        \
  unsigned short prev_layer;                                                   \
  FILE *stream;

static uint32_t bpf_len = 1 << 4;
static void bpf_append(struct bpf_program *bp, u_short code, u_char jt,
                       u_char jf, uint32_t k) {
  struct bpf_insn ins = {
      .code = code,
      .jt = jt,
      .jf = jf,
      .k = k,
  };
  bp->bf_len++;
  if (bp->bf_len > bpf_len) {
    bpf_len <<= 1;
    bp->bf_insns = realloc(bp->bf_insns, bpf_len * sizeof(struct bpf_insn));
  }
  bp->bf_insns[bp->bf_len - 1] = ins;
}

void bpf_jmp_update(struct bpf_program *bp, uint8_t delt) {
  for (int i = 0; i < bp->bf_len; i++) {
    if (bp->bf_insns[i].jf) {
      bp->bf_insns[i].jf += delt;
    }
    if (bp->bf_insns[i].jt) {
      bp->bf_insns[i].jt += delt;
    }
  }
}

#define YY_BPF(yy, code, jt, jf, k)                                            \
  { bpf_append(&yy->prog, code, jt, jf, k); }

#define YY_BITS32_VALUE(yy, yytext, offset)                                    \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 2);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_W | BPF_LD), 0, 0, offset);                      \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, integervalue(yytext));       \
  }

#define YY_BITS16_VALUE(yy, yytext, offset)                                    \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 2);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_H | BPF_LD), 0, 0, offset);                      \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, integervalue(yytext));       \
  }

#define YY_BITS8_VALUE(yy, yytext, offset)                                     \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 2);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_B | BPF_LD), 0, 0, offset);                      \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, integervalue(yytext));       \
  }

#define YY_VLAN_START(yy)
#define YY_VLAN_TPID(yy, yytext) YY_BITS16_VALUE(yy, yytext, yy->offset)
#define YY_VLAN_TAG(yy, yytext)                                                \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 3);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_H | BPF_LD), 0, 0, yy->offset + 2);              \
    YY_BPF(yy, (BPF_AND | BPF_K | BPF_ALU), 0, 0, 0x0FFF);                     \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, integervalue(yytext));       \
  }
#define YY_VLAN_END(yy) yy->offset += 4;

#define YY_ETHER_START(yy)
#define YY_ETHER_MAC(yy, yytext, src)                                          \
  {                                                                            \
    unsigned char addr[ETH_ALEN];                                              \
    unsigned char mask[ETH_ALEN];                                              \
    macstr2addr(yytext, addr, mask);                                           \
    bpf_jmp_update(&yy->prog, 4);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_W | BPF_LD), 0, 0,                               \
           yy->offset + 2 + (src ? 6 : 0));                                    \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 3,                              \
           (addr[0] | addr[1] << 8 | addr[2] << 16 | addr[3] << 24));          \
    YY_BPF(yy, (BPF_ABS | BPF_H | BPF_LD), 0, 0,                               \
           yy->offset + 0 + (src ? 6 : 0));                                    \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, (addr[4] | addr[5] << 8));   \
  }

#define YY_ETHER_TYPE(yy, yytext) YY_BITS16_VALUE(yy, yytext, yy->offset+12)
#define YY_ETHER_END(yy) yy->offset += 14;

#define YY_IP_START(yy)

#define YY_IP_ADDR(yy, yytext, src)                                            \
  {                                                                            \
    uint32_t addr, mask;                                                       \
    ipstr2addr(yytext, &addr, &mask);                                          \
    if (mask == 0xFFFFFFFF) {                                                  \
      bpf_jmp_update(&yy->prog, 2);                                            \
      YY_BPF(yy, (BPF_ABS | BPF_W | BPF_LD), 0, 0,                             \
             yy->offset + 12 + (src ? 0 : 4));                                 \
      YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, addr);                     \
    } else {                                                                   \
      bpf_jmp_update(&yy->prog, 3);                                            \
      YY_BPF(yy, (BPF_ABS | BPF_W | BPF_LD), 0, 0,                             \
             yy->offset + 12 + (src ? 0 : 4));                                 \
      YY_BPF(yy, (BPF_AND | BPF_K | BPF_ALU), 0, 0, mask);                     \
      YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, addr &mask);               \
    }                                                                          \
  }

#define YY_IP_FIELD2(yy, yytext, off)                                          \
  YY_BITS16_VALUE(yy, yytext, yy->offset + off)
#define YY_IP_FIELD1(yy, yytext, off)                                          \
  YY_BITS8_VALUE(yy, yytext, yy->offset + off)

#define YY_IP_END(yy) yy->offset += 20

#define YY_UDP_START(yy)
#define YY_UDP_FIELD(yy, yytext, off)                                          \
  YY_BITS16_VALUE(yy, yytext, yy->offset + off)
#define YY_UDP_END(yy) yy->offset += 8;

#define YY_TCP_START(yy)
#define YY_TCP_FIELD1(yy, yytext, off)                                         \
  YY_BITS8_VALUE(yy, yytext, yy->offset + off)
#define YY_TCP_FIELD2(yy, yytext, off)                                         \
  YY_BITS16_VALUE(yy, yytext, yy->offset + off)
#define YY_TCP_FIELD4(yy, yytext, off)                                         \
  YY_BITS32_VALUE(yy, yytext, yy->offset + off)
#define YY_TCP_END(yy) yy->offset += 20

#define YY_ARP_START(yy)
#define YY_ARP_ADDR(yy, yytext, off)                                           \
  {                                                                            \
    uint32_t addr, mask;                                                       \
    ipstr2addr(yytext, &addr, &mask);                                          \
    if (mask == 0xFFFFFFFF) {                                                  \
      bpf_jmp_update(&yy->prog, 2);                                            \
      YY_BPF(yy, (BPF_ABS | BPF_W | BPF_LD), 0, 0, yy->offset + off);          \
      YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, addr);                     \
    } else {                                                                   \
      bpf_jmp_update(&yy->prog, 3);                                            \
      YY_BPF(yy, (BPF_ABS | BPF_W | BPF_LD), 0, 0, yy->offset + off);          \
      YY_BPF(yy, (BPF_AND | BPF_K | BPF_ALU), 0, 0, mask);                     \
      YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, addr &mask);               \
    }                                                                          \
  }
#define YY_ARP_MAC(yy, yytext, off)                                            \
  {                                                                            \
    unsigned char addr[ETH_ALEN];                                              \
    unsigned char mask[ETH_ALEN];                                              \
    macstr2addr(yytext, addr, mask);                                           \
    bpf_jmp_update(&yy->prog, 4);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_W | BPF_LD), 0, 0, yy->offset + 2 + off);        \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 3,                              \
           (addr[0] | addr[1] << 8 | addr[2] << 16 | addr[3] << 24));          \
    YY_BPF(yy, (BPF_ABS | BPF_H | BPF_LD), 0, 0, yy->offset + off);            \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, (addr[4] | addr[5] << 8));   \
  }
#define YY_ARP_FIELD1(yy, yytext, off)                                         \
  YY_BITS8_VALUE(yy, yytext, yy->offset + off)
#define YY_ARP_FIELD2(yy, yytext, off)                                         \
  YY_BITS16_VALUE(yy, yytext, yy->offset + off)
#define YY_ARP_END(yy) yy->offset += 28

#define YY_VXLAN_START(yy)
#define YY_VXLAN_FLAG(yy, yytext)                                              \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 2);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_B | BPF_LD), 0, 0, yy->offset);                  \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, integervalue(yytext));       \
  }

#define YY_VXLAN_VNI(yy, yytext)                                               \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 4);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_W | BPF_LD), 0, 0, yy->offset + 4);              \
    YY_BPF(yy, (BPF_AND | BPF_K | BPF_ALU), 0, 0, 0xFFFFFF00);                 \
    YY_BPF(yy, (BPF_RSH | BPF_K | BPF_ALU), 0, 0, 8);                          \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, integervalue(yytext));       \
  }
#define YY_VXLAN_END(yy) yy->offset += 8

#define YY_GENEVE_START(yy)
#define YY_GENEVE_VER(yy, yytext)                                              \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 4);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_B | BPF_LD), 0, 0, yy->offset);                  \
    YY_BPF(yy, (BPF_AND | BPF_K | BPF_ALU), 0, 0, 0xC0);                       \
    YY_BPF(yy, (BPF_RSH | BPF_K | BPF_ALU), 0, 0, 6);                          \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, integervalue(yytext));       \
  }
#define YY_GENEVE_OPTLEN(yy, yytext)                                           \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 3);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_B | BPF_LD), 0, 0, yy->offset);                  \
    YY_BPF(yy, (BPF_AND | BPF_K | BPF_ALU), 0, 0, 0x3F);                       \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, integervalue(yytext));       \
    __ = integervalue(yytext);                                                 \
  }
#define YY_GENEVE_PROTO(yy, yytext) YY_BITS16_VALUE(yy, yytext, yy->offset + 2)
#define YY_GENEVE_VNI(yy, yytext) YY_VXLAN_VNI(yy, yytext)
#define YY_GENEVE_END(yy)                                                      \
  {                                                                            \
    yy->offset += (8 + __);                                                    \
    __ = 0;                                                                    \
  }

#define YY_ANY_FIELD(yy, yytext, off, size)                                    \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 2);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_W | BPF_LD), 0, 0, yy->offset + off);            \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, integervalue(yytext));       \
  }

#define YY_ICMP_START(yy)
#define YY_ICMP_FIELD1(yy, yytext, off)                                        \
  YY_BITS8_VALUE(yy, yytext, yy->offset + off)

#define YY_ICMP_FIELD2(yy, yytext, off)                                        \
  YY_BITS16_VALUE(yy, yytext, yy->offset + off)
#define YY_ICMP_END(yy) yy->offset += 8

#define YY_ICMP6_START(yy)
#define YY_ICMP6_FIELD1(yy, yytext, off) YY_ICMP_FIELD1(yy, yytext, off)
#define YY_ICMP6_FIELD2(yy, yytext, off) YY_ICMP_FIELD2(yy, yytext, off)
#define YY_ICMP6_END(yy) yy->offset += 8

#define YY_SCTP_START(yy)
#define YY_SCTP_FIELD2(yy, yytext, off)                                        \
  YY_BITS16_VALUE(yy, yytext, yy->offset + off)

#define YY_SCTP_FIELD4(yy, yytext, off)                                        \
  YY_BITS32_VALUE(yy, yytext, yy->offset + off)
#define YY_SCTP_END(yy)                                                        \
  yy->offset += (12 + __);                                                     \
  __ = 0;

#define YY_MPLS_START(yy)
#define YY_MPLS_LABEL(yy, yytext)                                              \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 4);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_W | BPF_LD), 0, 0, yy->offset);                  \
    YY_BPF(yy, (BPF_AND | BPF_K | BPF_ALU), 0, 0, 0xFFFFF000);                 \
    YY_BPF(yy, (BPF_RSH | BPF_K | BPF_ALU), 0, 0, 12);                         \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, integervalue(yytext));       \
  }

#define YY_MPLS_EXP(yy, yytext)                                                \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 4);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_B | BPF_LD), 0, 0, yy->offset + 2);              \
    YY_BPF(yy, (BPF_AND | BPF_K | BPF_ALU), 0, 0, 0x0E);                       \
    YY_BPF(yy, (BPF_RSH | BPF_K | BPF_ALU), 0, 0, 1);                          \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, integervalue(yytext));       \
  }

#define YY_MPLS_S(yy, yytext)                                                  \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 3);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_B | BPF_LD), 0, 0, yy->offset + 2);              \
    YY_BPF(yy, (BPF_AND | BPF_K | BPF_ALU), 0, 0, 0x01);                       \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, integervalue(yytext));       \
  }
#define YY_MPLS_TTL(yy, yytext)                                                \
  YY_BITS8_VALUE(yy, yytext, yy->offset + 3)
#define YY_MPLS_END(yy) yy->offset += 4;

#define YY_GRE_START(yy)
#define YY_GRE_C(yy, yytext)                                                   \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 4);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_B | BPF_LD), 0, 0, yy->offset);                  \
    YY_BPF(yy, (BPF_AND | BPF_K | BPF_ALU), 0, 0, 0x80);                       \
    YY_BPF(yy, (BPF_RSH | BPF_K | BPF_ALU), 0, 0, 7);                          \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, integervalue(yytext));       \
  }

#define YY_GRE_VER(yy, yytext)                                                 \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 3);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_B | BPF_LD), 0, 0, yy->offset + 1);              \
    YY_BPF(yy, (BPF_AND | BPF_K | BPF_ALU), 0, 0, 0x7);                        \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, integervalue(yytext));       \
  }

#define YY_GRE_PROTO(yy, yytext) YY_BITS16_VALUE(yy, yytext, yy->offset + 2)

#define YY_GRE_CSUM(yy, yytext)                                                \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 5);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_B | BPF_LD), 0, 0, yy->offset);                  \
    YY_BPF(yy, (BPF_AND | BPF_K | BPF_ALU), 0, 0, 0x80);                       \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 3, 0x80);                       \
    YY_BPF(yy, (BPF_ABS | BPF_H | BPF_LD), 0, 0, yy->offset + 4);              \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, integervalue(yytext));       \
    __ = 4;                                                                   \
  }
#define YY_GRE_END(yy)                                                         \
  yy->offset += (4 + __);                                                      \
  __ = 0;

#define YY_IP6_START(yy)
#define YY_IP6_ADDR(yy, yytext, src)                                           \
  {                                                                            \
    uint32_t addr[4], mask[4];                                                 \
    ip6str2addr(yytext, addr, mask);                                           \
    int prefix = __builtin_popcount(mask[0]) + __builtin_popcount(mask[1]) +   \
                 __builtin_popcount(mask[2]) + __builtin_popcount(mask[3]);    \
    bpf_jmp_update(&yy->prog, 2 * ((prefix ? prefix - 1 : 0) / 32) + 2);       \
    YY_BPF(yy, (BPF_ABS | BPF_W | BPF_LD), 0, 0,                               \
           yy->offset + 8 + (src ? 0 : 16));                                   \
    YY_BPF(yy,                                                                 \
           (prefix >= 32) ? (BPF_JEQ | BPF_K | BPF_JMP)                        \
                          : (BPF_JSET | BPF_K | BPF_JMP),                      \
           prefix >= 32 ? 0 : ((prefix - 1) / 32) * 2 + 1,                     \
           prefix >= 32 ? ((prefix - 1) / 32) * 2 + 1 : 0, addr[0] & mask[0]); \
    if (prefix > 32) {                                                         \
      YY_BPF(yy, (BPF_ABS | BPF_W | BPF_LD), 0, 0,                             \
             yy->offset + 8 + (src ? 4 : 20));                                 \
      YY_BPF(yy,                                                               \
             (prefix >= 64) ? (BPF_JEQ | BPF_K | BPF_JMP)                      \
                            : (BPF_JSET | BPF_K | BPF_JMP),                    \
             prefix >= 64 ? 0 : ((prefix - 1) / 32 - 1) * 2 + 1,               \
             prefix >= 64 ? ((prefix - 1) / 32 - 1) * 2 + 1 : 0,               \
             addr[1] & mask[1]);                                               \
    }                                                                          \
    if (prefix > 64) {                                                         \
      YY_BPF(yy, (BPF_ABS | BPF_W | BPF_LD), 0, 0,                             \
             yy->offset + 8 + (src ? 8 : 24));                                 \
      YY_BPF(yy,                                                               \
             (prefix >= 96) ? (BPF_JEQ | BPF_K | BPF_JMP)                      \
                            : (BPF_JSET | BPF_K | BPF_JMP),                    \
             prefix >= 96 ? 0 : ((prefix - 1) / 32 - 2) * 2 + 1,               \
             prefix >= 96 ? ((prefix - 1) / 32 - 2) * 2 + 1 : 0,               \
             addr[2] & mask[2]);                                               \
    }                                                                          \
    if (prefix > 96) {                                                         \
      YY_BPF(yy, (BPF_ABS | BPF_W | BPF_LD), 0, 0,                             \
             yy->offset + 8 + (src ? 12 : 28));                                \
      YY_BPF(yy,                                                               \
             (prefix == 128) ? (BPF_JEQ | BPF_K | BPF_JMP)                     \
                             : (BPF_JSET | BPF_K | BPF_JMP),                   \
             (prefix == 128) ? 0 : 1, (prefix == 128) ? 1 : 0,                 \
             addr[3] & mask[3]);                                               \
    }                                                                          \
  }

#define YY_IP6_FIELD(yy, yytext, name)                                         \
  {                                                                            \
    if (!strcmp(name, "version")) {                                            \
      bpf_jmp_update(&yy->prog, 4);                                            \
      YY_BPF(yy, (BPF_ABS | BPF_B | BPF_LD), 0, 0, yy->offset);                \
      YY_BPF(yy, (BPF_AND | BPF_K | BPF_ALU), 0, 0, 0xF0);                     \
      YY_BPF(yy, (BPF_RSH | BPF_K | BPF_ALU), 0, 0, 4);                        \
      YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, integervalue(yytext));     \
    } else if (!strcmp(name, "traffic_class")) {                               \
      bpf_jmp_update(&yy->prog, 4);                                            \
      YY_BPF(yy, (BPF_ABS | BPF_H | BPF_LD), 0, 0, yy->offset);                \
      YY_BPF(yy, (BPF_AND | BPF_K | BPF_ALU), 0, 0, 0x0FF0);                   \
      YY_BPF(yy, (BPF_RSH | BPF_K | BPF_ALU), 0, 0, 4);                        \
      YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, integervalue(yytext));     \
    } else if (!strcmp(name, "flowlabel")) {                                   \
      bpf_jmp_update(&yy->prog, 3);                                            \
      YY_BPF(yy, (BPF_ABS | BPF_W | BPF_LD), 0, 0, yy->offset);                \
      YY_BPF(yy, (BPF_AND | BPF_K | BPF_ALU), 0, 0, 0xFFFFF);                  \
      YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, integervalue(yytext));     \
    } else if (!strcmp(name, "plen")) {                                        \
      bpf_jmp_update(&yy->prog, 2);                                            \
      YY_BPF(yy, (BPF_ABS | BPF_H | BPF_LD), 0, 0, yy->offset + 4);            \
      YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, integervalue(yytext));     \
    } else if (!strcmp(yytext, "nexthdr")) {                                   \
      YY_BPF(yy, (BPF_ABS | BPF_B | BPF_LD), 0, 0, yy->offset + 6);            \
      YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, integervalue(yytext));     \
    } else if (!strcmp(name, "hoplimit")) {                                    \
      bpf_jmp_update(&yy->prog, 2);                                            \
      YY_BPF(yy, (BPF_ABS | BPF_B | BPF_LD), 0, 0, yy->offset + 7);            \
      YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, integervalue(yytext));     \
    }                                                                          \
  }
#define YY_IP6_END(yy) yy->offset += 40

#define YY_OSPF_START(yy)
#define YY_OSPF_FIELD1(yy, yytext, off)                                        \
  YY_BITS8_VALUE(yy, yytext, yy->offset + off)
#define YY_OSPF_FIELD2(yy, yytext, off)                                        \
  YY_BITS16_VALUE(yy, yytext, yy->offset + off)
#define YY_OSPF_FIELD4(yy, yytext, off)                                        \
  YY_BITS32_VALUE(yy, yytext, yy->offset + off)

#define YY_OSPF_AUTH(yy, yytext)                                               \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 4);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_W | BPF_LD), 0, 0, yy->offset + 16);             \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 3, integervalue(yytext));       \
    YY_BPF(yy, (BPF_ABS | BPF_W | BPF_LD), 0, 0, yy->offset + 20);             \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, integervalue(yytext));       \
  }
#define YY_OSPF_END(yy) yy->offset += 24;

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
    bpf_jmp_update(&yy->prog, 5);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_H | BPF_LD), 0, 0, yy->offset - 20 + 6);         \
    YY_BPF(yy, (BPF_JSET | BPF_K | BPF_JMP), 4, 0, 0x1FFF);                    \
    YY_BPF(yy, (BPF_MSH | BPF_B | BPF_LDX), 0, 0, yy->offset - 20);            \
    YY_BPF(yy, (BPF_IND | BPF_B | BPF_LD), 0, 0, yy->offset - 20 + 13);        \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, flag);                       \
  }

#define YY_RSS(yy, yytext)
#define YY_QUEUE(yy, yytext)
#define YY_DROP(yy)
#define YY_PORT(yy)
#define YY_SAMPLE(yy)                                                          \
  {                                                                            \
    YY_BPF(yy, (BPF_K | BPF_RET), 0, 0, 0x40000);                              \
    YY_BPF(yy, BPF_K | BPF_RET, 0, 0, 0);                                      \
  }


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

int depkt_compile(char *capstr, struct bpf_program *prog)
{
  printf("%s\n", capstr);
  yycontext ctx;
  memset(&ctx, 0, sizeof(yycontext));
  FILE *stream = fmemopen(capstr, strlen(capstr), "r");
  ctx.stream = stream;
  ctx.prog.bf_insns = malloc(bpf_len * sizeof(struct bpf_insn));
  if (yyparse(&ctx) == 0) {
    yyerror(&ctx, "syntax error\n");
    return -1;
  }
  fclose(stream);

  prog->bf_len = ctx.prog.bf_len;
  prog->bf_insns = ctx.prog.bf_insns;
  YYRELEASE(&ctx);

  return 0;
}