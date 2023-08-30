#ifndef __DPDK_RFLOW_H__
#define __DPDK_RFLOW_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_flow.h>

struct rte_flow *dpdkflow_compile(uint16_t port_id, struct rte_flow_attr *attr,
                                  char *capstr);

#ifdef __cplusplus
}
#endif

#endif