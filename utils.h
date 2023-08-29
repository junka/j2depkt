#ifndef __DEPKT_UTILS_H__
#define __DEPKT_UTILS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <linux/if_ether.h>

uint32_t integervalue(const char *intstr);

int macstr2addr(char *macstr, uint8_t addr[ETH_ALEN],
                       uint8_t mask[ETH_ALEN]);
int ipstr2addr(char *ipstr, uint32_t *ip, uint32_t *mask);
int ip6str2addr(char *ipstr, uint32_t ip[4], uint32_t mask[4]);


#ifdef __cplusplus
}
#endif

#endif