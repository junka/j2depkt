#include <stdint.h>
#include <signal.h>

#include <rte_ethdev.h>
#include <rte_eal.h>
#include <rte_cycles.h>

#include "dpdkrflow.h"

static volatile bool force_quit;
static struct rte_eth_conf port_conf = {
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
    },
    .rxmode = {
        .mq_mode =RTE_ETH_MQ_RX_RSS,
    },
};
static void signal_handler(int signum) {
  if (signum == SIGINT || signum == SIGTERM) {
    printf("\n\nSignal %d received, preparing to exit...\n", signum);
    force_quit = true;
  }
}
static int pkt_main_loop(__rte_unused void *arg) {
  struct rte_mbuf *pkts_burst[32];
  struct rte_mbuf *m;
  unsigned i, j, nb_rx;
  printf("Main loop....\n");
  while (!force_quit) {
    /* Read packet from RX queues. 8< */
    for (i = 0; i < 4; i++) {

      nb_rx = rte_eth_rx_burst(0, i, pkts_burst, 32);

      if (unlikely(nb_rx == 0))
        continue;

      printf("rx %d pkts from queue %u\n", nb_rx, i);
      for (j = 0; j < nb_rx; j++) {
        m = pkts_burst[j];
        rte_prefetch0(rte_pktmbuf_mtod(m, void *));
        //drop all packet
        rte_pktmbuf_free(m);
      }
    }
    /* >8 End of read packet from RX queues. */
  }
  return 0;
}

int main(int argc, char *argv[]) {
  uint16_t nb_rxd = 1024;
  uint16_t nb_txd = 1024;
  int ret = rte_eal_init(argc, argv);
  if (ret < 0) {
    rte_exit(EXIT_FAILURE, "invalid EAL arguments\n");
  }
  force_quit = false;
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  int nb_ports = rte_eth_dev_count_avail();
  if (nb_ports != 1) {
    rte_exit(EXIT_FAILURE, "No Ethernet ports or more than one\n");
  }
  struct rte_mempool *pktmbuf_pool = rte_pktmbuf_pool_create(
      "mbuf_pool", 10000, 256, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  struct rte_eth_dev_info devinfo;
  ret = rte_eth_dev_info_get(0, &devinfo);
  if (ret != 0) {
    rte_exit(EXIT_FAILURE, "Error getting info for port\n");
  }
  struct rte_eth_rxconf rxq_conf = devinfo.default_rxconf;
  struct rte_eth_txconf txq_conf = devinfo.default_txconf;
  if (devinfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_RSS_HASH) {
    port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_RSS_HASH;
  }
  ret = rte_eth_dev_configure(0, 4, 4, &port_conf);
  if (ret < 0) {
    rte_exit(EXIT_FAILURE, "can not configure device\n");
  }

  ret = rte_eth_dev_adjust_nb_rx_tx_desc(0, &nb_rxd, &nb_txd);
  if (ret < 0) {
    rte_exit(EXIT_FAILURE, "can not adjust number of descriptor\n");
  }
  for (int i = 0; i < 4; i++) {
    ret = rte_eth_rx_queue_setup(0, i, nb_rxd, rte_eth_dev_socket_id(0),
                                 &rxq_conf, pktmbuf_pool);
    if (ret < 0) {
      rte_exit(EXIT_FAILURE, "fail to setup rx queue\n");
    }
    ret = rte_eth_tx_queue_setup(0, i, nb_txd, rte_eth_dev_socket_id(0),
                                 &txq_conf);
    if (ret < 0) {
      rte_exit(EXIT_FAILURE, "fail to setup tx queue\n");
    }
  }
  struct rte_flow_error error;
  ret = rte_flow_isolate(0, 1, &error);
  if (ret < 0) {
    rte_exit(EXIT_FAILURE, "can not isolate a port\n");
  }
  ret = rte_eth_dev_start(0);
  if (ret < 0) {
    rte_exit(EXIT_FAILURE, "can not start the device\n");
  }

  struct rte_flow_attr attr = {
      .ingress = 1,
      .transfer = 0,
      .priority = 2,
  };
  struct rte_flow *rflow = dpdkflow_compile(
      0, &attr, "ETHER(type=0x800)/IP(proto=17)/UDP(dst=4789):RSS(queue=4)");
  if (rflow == NULL) {
    rte_exit(EXIT_FAILURE, "fail to create flow\n");
  }

  rte_eal_mp_remote_launch(pkt_main_loop, NULL, CALL_MAIN);

  ret = rte_flow_flush(0, &error);
  if (ret < 0) {
    rte_exit(EXIT_FAILURE, "fail to flush flow rules\n");
  }
  ret = rte_eth_dev_stop(0);
  if (ret < 0) {
    rte_exit(EXIT_FAILURE, "fail to stop device\n");
  }
  rte_eal_cleanup();
  return 0;
}
