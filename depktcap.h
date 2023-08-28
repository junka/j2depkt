#ifndef __DEPKTPCAP_H__
#define __DEPKTPCAP_H__

#include <stdint.h>

#ifndef lib_pcap_bpf_h

/* instruction classes */
#define BPF_CLASS(code) ((code)&0x07)
#define BPF_LD 0x00
#define BPF_LDX 0x01
#define BPF_ST 0x02
#define BPF_STX 0x03
#define BPF_ALU 0x04
#define BPF_JMP 0x05
#define BPF_RET 0x06
#define BPF_MISC 0x07

/* ld/ldx fields */
#define BPF_SIZE(code) ((code)&0x18)
#define BPF_W 0x00
#define BPF_H 0x08
#define BPF_B 0x10
/*				0x18	reserved; used by BSD/OS */
#define BPF_MODE(code) ((code)&0xe0)
#define BPF_IMM 0x00
#define BPF_ABS 0x20
#define BPF_IND 0x40
#define BPF_MEM 0x60
#define BPF_LEN 0x80
#define BPF_MSH 0xa0
/*				0xc0	reserved; used by BSD/OS */
/*				0xe0	reserved; used by BSD/OS */

/* alu/jmp fields */
#define BPF_OP(code) ((code)&0xf0)
#define BPF_ADD 0x00
#define BPF_SUB 0x10
#define BPF_MUL 0x20
#define BPF_DIV 0x30
#define BPF_OR 0x40
#define BPF_AND 0x50
#define BPF_LSH 0x60
#define BPF_RSH 0x70
#define BPF_NEG 0x80
#define BPF_MOD 0x90
#define BPF_XOR 0xa0
/*				0xb0	reserved */
/*				0xc0	reserved */
/*				0xd0	reserved */
/*				0xe0	reserved */
/*				0xf0	reserved */

#define BPF_JA 0x00
#define BPF_JEQ 0x10
#define BPF_JGT 0x20
#define BPF_JGE 0x30
#define BPF_JSET 0x40
/*				0x50	reserved; used on BSD/OS */
/*				0x60	reserved */
/*				0x70	reserved */
/*				0x80	reserved */
/*				0x90	reserved */
/*				0xa0	reserved */
/*				0xb0	reserved */
/*				0xc0	reserved */
/*				0xd0	reserved */
/*				0xe0	reserved */
/*				0xf0	reserved */
#define BPF_SRC(code) ((code)&0x08)
#define BPF_K 0x00
#define BPF_X 0x08

/* ret - BPF_K and BPF_X also apply */
#define BPF_RVAL(code) ((code)&0x18)
#define BPF_A 0x10
/*				0x18	reserved */

/* misc */
#define BPF_MISCOP(code) ((code)&0xf8)
#define BPF_TAX 0x00
/*				0x08	reserved */
/*				0x10	reserved */
/*				0x18	reserved */
/* #define	BPF_COP		0x20	NetBSD "coprocessor" extensions */
/*				0x28	reserved */
/*				0x30	reserved */
/*				0x38	reserved */
/* #define	BPF_COPX	0x40	NetBSD "coprocessor" extensions */
/*					also used on BSD/OS */
/*				0x48	reserved */
/*				0x50	reserved */
/*				0x58	reserved */
/*				0x60	reserved */
/*				0x68	reserved */
/*				0x70	reserved */
/*				0x78	reserved */
#define BPF_TXA 0x80
/*				0x88	reserved */
/*				0x90	reserved */
/*				0x98	reserved */
/*				0xa0	reserved */
/*				0xa8	reserved */
/*				0xb0	reserved */
/*				0xb8	reserved */
/*				0xc0	reserved; used on BSD/OS */
/*				0xc8	reserved */
/*				0xd0	reserved */
/*				0xd8	reserved */
/*				0xe0	reserved */
/*				0xe8	reserved */
/*				0xf0	reserved */
/*				0xf8	reserved */

struct bpf_insn {
  uint16_t code;
  uint8_t jt;
  uint8_t jf;
  uint32_t k;
};

struct bpf_program {
  uint32_t bf_len;
  struct bpf_insn *bf_insns;
};
#endif


#ifdef __cplusplus
extern "C" {
#endif

int depkt_compile(char *capstr, struct bpf_program *prog);

#ifdef __cplusplus
}
#endif

#endif /*__DEPKTPCAP_H__*/