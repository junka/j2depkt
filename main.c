
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#include <sys/socket.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#include <pcap/bpf.h>
#include <pcap/pcap.h>


#define YY_CTX_LOCAL

#define YY_CTX_MEMBERS \
    struct bpf_program prog; \
    unsigned long offset;

static uint32_t bpf_len = 1 << 4;
static void
bpf_append(struct bpf_program *bp, u_short code, u_char jt,
                       u_char jf, uint32_t k)
{
  struct bpf_insn ins = {
      .code = code,
      .jt = jt,
      .jf = jf,
      .k = k,
  };
  bp->bf_len ++;
  if (bp->bf_len > bpf_len) {
    bpf_len <<= 1;
    bp->bf_insns = realloc(bp->bf_insns, bpf_len * sizeof(struct bpf_insn));
  }
  bp->bf_insns[bp->bf_len - 1] = ins;
}

void bpf_jmp_update(struct bpf_program *bp, uint8_t delt)
{
  for (int i = 0; i < bp->bf_len; i ++) {
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

static int ipstr2addr(char *ipstr, uint32_t *ip, uint32_t *mask)
{
  char *rest;
  char *ipCopy = strdup(ipstr);
  char *token = strtok_r(ipCopy, "/", &rest);

  inet_pton(AF_INET, token, ip);
  *ip = htonl(*ip);
  *mask = 0xFFFFFFFF;
  if (rest) {
    if (strstr(rest, ".")) {
      printf("%s\n", rest);
      inet_pton(AF_INET, rest, mask);
      *mask = htonl(*mask);
      printf("%x\n", *mask);
    } else {
      *mask = strtoul(rest, NULL, 10);
      *mask = ~(0xFFFFFFFF >> *mask);
      printf("%x\n", *mask);
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
    YY_BPF(yy, (BPF_ABS | BPF_AND | BPF_ALU), 0, 0, 0x0FFF);                   \
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
      YY_BPF(yy, (BPF_AND | BPF_W | BPF_ALU), 0, 0, mask);                     \
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
      YY_BPF(yy, (BPF_ABS | BPF_H | BPF_LD), 0, 0, yy->offset + off);          \
    } else if (size == 2) {                                                    \
      YY_BPF(yy, (BPF_ABS | BPF_B | BPF_LD), 0, 0, yy->offset + off);          \
    }                                                                          \
    YY_BPF(yy, (BPF_JEQ | BPF_K | BPF_JMP), 0, 1, strtol(yytext, 0, 10));      \
  }

static const char *tcpflags[] = {
  "fin",
  "syn",
  "rst",
  "psh",
  "ack",
  "urg",
  "ece",
  "cwr",
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

#include "build/parser.c"

void yyerror(yycontext *ctx, char *message) {
  fprintf(stderr, " %s", message);

  if (ctx->__pos < ctx->__limit ) {
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

int main(int argc, char **argv)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *hdl = NULL;

  FILE *stream = fmemopen((void *)argv[1], strlen(argv[1]), "r");
  setbuf(stream, NULL);
  FILE *oristdin = stdin;
  stdin = stream;

  yycontext ctx;
  memset(&ctx, 0, sizeof(yycontext));
  ctx.prog.bf_insns = malloc(bpf_len * sizeof(struct bpf_insn));
  if (yyparse(&ctx) == 0) {
    yyerror(&ctx, "syntax error\n");
    return 1;
  }
  // recover the stream
  stdin = oristdin;
  fclose(stream);

  if (argc > 2) {
    hdl = pcap_open_live(argv[2], 100, 0, 1000, errbuf);
    if (hdl == NULL) {
      fprintf(stderr, "Couldn't open device %s: %s\n", argv[2], errbuf);
      return -1;
    }
  }
  bpf_dump(&ctx.prog, 2);
  // we did not need pcap_compile, bpf_prog will be translated from our self defined DSL
  if (pcap_setfilter(hdl, &ctx.prog) == -1) {
    fprintf(stderr, "Couldn't install filter %s\n",
            pcap_geterr(hdl));
    pcap_close(hdl);
    return 2;
  }

  struct pcap_pkthdr hdr;
  const u_char *packet = pcap_next(hdl, &hdr);
  // printf("Capture a packet length %d, type 0x%x\n", hdr.len, packet[12] << 8 | packet[13]);

  pcap_close(hdl);
  pcap_freecode(&ctx.prog);
  YYRELEASE(&ctx);

  return 0;
}