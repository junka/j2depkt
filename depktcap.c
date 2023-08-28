#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <sys/socket.h>

#include "depktcap.h"

#define YY_CTX_LOCAL

#define YY_INPUT(ctx, buf, result, max)                                        \
  {                                                                            \
    int c = fgetc(ctx->stream);                                                \
    result = (EOF == c) ? 0 : (*(buf) = c, 1);                                 \
  }

#define YY_CTX_MEMBERS                                                         \
  struct bpf_program prog;                                                     \
  unsigned long offset;                                                        \
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

static int macstr2addr(char *macstr, uint8_t addr[ETH_ALEN],
                       uint8_t mask[ETH_ALEN]) {
  char *token = NULL;
  char *rest = NULL;
  char *macCopy = strdup(macstr);
  char *maskstr = NULL;
  token = strtok_r(macCopy, "/", &rest);

  if (rest && strlen(rest) > 0) {
    for (int i = ETH_ALEN - 1; i >= 0; i--) {
      maskstr = strtok_r(rest, ":", &rest);
      sscanf(maskstr, "%hhx", &mask[i]);
    }
  }

  rest = token;
  for (int i = ETH_ALEN - 1; i >= 0; i--) {
    token = strtok_r(rest, ":", &rest);
    sscanf(token, "%hhx", &addr[i]);
  }

  free(macCopy);
  return 0;
}

static int ipstr2addr(char *ipstr, uint32_t *ip, uint32_t *mask) {
  char *rest = NULL;
  char *ipCopy = strdup(ipstr);
  char *token = strtok_r(ipCopy, "/", &rest);

  inet_pton(AF_INET, token, ip);
  *ip = htonl(*ip);
  *mask = 0xFFFFFFFF;
  if (rest && strlen(rest)) {
    if (strstr(rest, ".")) {
      inet_pton(AF_INET, rest, mask);
      *mask = htonl(*mask);
    } else {
      *mask = strtoul(rest, NULL, 10);
      if (*mask < 32) {
        *mask = ~(0xFFFFFFFF >> *mask);
      } else {
        *mask = 0xFFFFFFFF;
      }
    }
  }

  free(ipCopy);
  return 0;
}

static int ip6str2addr(char *ipstr, uint32_t ip[4], uint32_t mask[4]) {
  char *rest = NULL;
  char *ipCopy = strdup(ipstr);
  char *token = strtok_r(ipCopy, "/", &rest);

  inet_pton(AF_INET6, token, ip);
  ip[0] = htonl(ip[0]);
  ip[1] = htonl(ip[1]);
  ip[2] = htonl(ip[2]);
  ip[3] = htonl(ip[3]);
  memset(mask, 0xFF, 4 * sizeof(uint32_t));
  if (rest && strlen(rest)) {
    if (strstr(rest, ":")) {
      inet_pton(AF_INET6, rest, mask);
      mask[0] = htonl(mask[0]);
      mask[1] = htonl(mask[1]);
      mask[2] = htonl(mask[2]);
      mask[3] = htonl(mask[3]);
    } else {
      mask[3] = strtoul(rest, NULL, 10);
      if (mask[3] < 32) {
        mask[0] = ~(0xFFFFFFFF >> mask[3]);
        mask[1] = 0;
        mask[2] = 0;
        mask[3] = 0;
      } else if (mask[3] < 64) {
        mask[1] = ~(0xFFFFFFFF >> (mask[3] - 32));
        mask[2] = 0;
        mask[3] = 0;
      } else if (mask[3] < 96) {
        mask[2] = ~(0xFFFFFFFF >> (mask[3] - 64));
        mask[3] = 0;
      } else if (mask[3] < 128) {
        mask[3] = ~(0xFFFFFFFF >> (mask[3] - 96));
      } else if (mask[3] == 128) {
        mask[3] = 0xFFFFFFFF;
      }
    }
  }

  free(ipCopy);
  return 0;
}

#define YY_VLAN_TPID(yy, yytext)                                               \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 2);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_H | BPF_LD), 0, 0, yy->offset);                  \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, strtol(yytext, 0, 16));      \
  }

#define YY_VLAN_TAG(yy, yytext)                                                \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 3);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_H | BPF_LD), 0, 0, yy->offset + 2);              \
    YY_BPF(yy, (BPF_AND | BPF_K | BPF_ALU), 0, 0, 0x0FFF);                     \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, strtol(yytext, 0, 10));      \
  }

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

#define YY_ETHER_TYPE(yy, yytext)                                              \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 2);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_H | BPF_LD), 0, 0, yy->offset + 12);             \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, strtol(yytext, 0, 16));      \
  }

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

#define YY_IP_FIELD(yy, yytext, off, size)                                     \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 2);                                              \
    if (size == 2) {                                                           \
      YY_BPF(yy, (BPF_ABS | BPF_H | BPF_LD), 0, 0, yy->offset + off);          \
    } else if (size == 1) {                                                    \
      YY_BPF(yy, (BPF_ABS | BPF_B | BPF_LD), 0, 0, yy->offset + off);          \
    }                                                                          \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, strtol(yytext, 0, 10));      \
  }

#define YY_UDP_FIELD(yy, yytext, off)                                          \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 2);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_H | BPF_LD), 0, 0, yy->offset + off);            \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, strtol(yytext, 0, 10));      \
  }

#define YY_TCP_FIELD(yy, yytext, off, size)                                    \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 2);                                              \
    if (size == 4) {                                                           \
      YY_BPF(yy, (BPF_ABS | BPF_W | BPF_LD), 0, 0, yy->offset + off);          \
    } else if (size == 2) {                                                    \
      YY_BPF(yy, (BPF_ABS | BPF_H | BPF_LD), 0, 0, yy->offset + off);          \
    }                                                                          \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, strtol(yytext, 0, 10));      \
  }

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

#define YY_ARP_FIELD(yy, yytext, off, size)                                    \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 2);                                              \
    if (size == 1) {                                                           \
      YY_BPF(yy, (BPF_ABS | BPF_B | BPF_LD), 0, 0, yy->offset + off);          \
    } else if (size == 2) {                                                    \
      YY_BPF(yy, (BPF_ABS | BPF_H | BPF_LD), 0, 0, yy->offset + off);          \
    }                                                                          \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, strtol(yytext, 0, 10));      \
  }

#define YY_VXLAN_FLAG(yy, yytext)                                              \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 2);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_B | BPF_LD), 0, 0, yy->offset);                  \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, strtol(yytext, 0, 16));      \
  }

#define YY_VXLAN_VNI(yy, yytext)                                               \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 4);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_W | BPF_LD), 0, 0, yy->offset + 4);              \
    YY_BPF(yy, (BPF_AND | BPF_K | BPF_ALU), 0, 0, 0xFFF0);                     \
    YY_BPF(yy, (BPF_RSH | BPF_K | BPF_ALU), 0, 0, 8);                          \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, strtol(yytext, 0, 16));      \
  }

#define YY_ANY_FIELD(yy, yytext, off, size)                                    \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 2);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_W | BPF_LD), 0, 0, yy->offset + off);            \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, strtol(yytext, 0, 16));      \
  }

#define YY_ICMP_FIELD(yy, yytext, off, size)                                   \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 2);                                              \
    if (size == 1) {                                                           \
      YY_BPF(yy, (BPF_ABS | BPF_B | BPF_LD), 0, 0, yy->offset + off);          \
      YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, strtol(yytext, 0, 10));    \
    } else if (size == 2) {                                                    \
      YY_BPF(yy, (BPF_ABS | BPF_H | BPF_LD), 0, 0, yy->offset + off);          \
      YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, strtol(yytext, 0, 10));    \
    }                                                                          \
  }

#define YY_SCTP_FIELD(yy, yytext, off, size)                                   \
  {                                                                            \
    bpf_jmp_update(&yy->prog, 2);                                              \
    if (size == 4) {                                                           \
      YY_BPF(yy, (BPF_ABS | BPF_W | BPF_LD), 0, 0, yy->offset + off);          \
      YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, strtol(yytext, 0, 10));    \
    } else if (size == 2) {                                                    \
      YY_BPF(yy, (BPF_ABS | BPF_H | BPF_LD), 0, 0, yy->offset + off);          \
      YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, strtol(yytext, 0, 10));    \
    }                                                                          \
  }

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
    bpf_jmp_update(&yy->prog, 2);                                              \
    if (!strcmp(name, "version")) {                                            \
      YY_BPF(yy, (BPF_ABS | BPF_B | BPF_LD), 0, 0, yy->offset);                \
      YY_BPF(yy, (BPF_AND | BPF_K | BPF_ALU), 0, 0, 0xF);                      \
      YY_BPF(yy, (BPF_RSH | BPF_K | BPF_ALU), 0, 0, 4);                        \
      YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, strtol(yytext, 0, 10));    \
    } else if (!strcmp(name, "traffic_class")) {                               \
      YY_BPF(yy, (BPF_ABS | BPF_H | BPF_LD), 0, 0, yy->offset);                \
      YY_BPF(yy, (BPF_AND | BPF_K | BPF_ALU), 0, 0, 0xFF0);                    \
      YY_BPF(yy, (BPF_RSH | BPF_K | BPF_ALU), 0, 0, 4);                        \
      YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, strtol(yytext, 0, 10));    \
    } else if (!strcmp(name, "flowlabel")) {                                   \
      YY_BPF(yy, (BPF_ABS | BPF_W | BPF_LD), 0, 0, yy->offset);                \
      YY_BPF(yy, (BPF_AND | BPF_K | BPF_ALU), 0, 0, 0xFFFFF);                  \
      YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, strtol(yytext, 0, 10));    \
    } else if (!strcmp(name, "plen")) {                                        \
      YY_BPF(yy, (BPF_ABS | BPF_H | BPF_LD), 0, 0, yy->offset + 4);            \
      YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, strtol(yytext, 0, 10));    \
    } else if (!strcmp(yytext, "nexthdr")) {                                   \
      YY_BPF(yy, (BPF_ABS | BPF_B | BPF_LD), 0, 0, yy->offset + 6);            \
      YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, strtol(yytext, 0, 10));    \
    } else if (!strcmp(name, "hoplimit")) {                                    \
      YY_BPF(yy, (BPF_ABS | BPF_B | BPF_LD), 0, 0, yy->offset + 7);            \
      YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, strtol(yytext, 0, 10));    \
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
    bpf_jmp_update(&yy->prog, 5);                                              \
    YY_BPF(yy, (BPF_ABS | BPF_H | BPF_LD), 0, 0, yy->offset - 20 + 6);         \
    YY_BPF(yy, (BPF_JSET | BPF_K | BPF_JMP), 4, 0, 0x1FFF);                    \
    YY_BPF(yy, (BPF_MSH | BPF_B | BPF_LDX), 0, 0, yy->offset - 20);            \
    YY_BPF(yy, (BPF_IND | BPF_B | BPF_LD), 0, 0, yy->offset - 20 + 13);        \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, flag);                       \
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