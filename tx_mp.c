#include "tx_mp.h"
#include <stdio.h>
#include <string.h>
#include <odp.h>
#include <stdlib.h>

inline odp_packet_t generate_mbuf(struct packet_model pm, odp_pool_t mp, uint32_t pkt_length, char smac[], char dmac[])
{
    odp_packet_t m;
    m = odp_packet_alloc(mp, pkt_length);
    if(m == ODP_PACKET_INVALID)
    {
        fprintf(stderr, "alloc pkt failed!\n");
        exit(-1);
    }
    char *data = odp_packet_data(m);
    if(pm.is_udp)
    {
        memcpy(pm.udp.eth.src.addr, smac, 6);
        memcpy(pm.udp.eth.dst.addr, dmac, 6);
        memcpy(data, &pm.udp, sizeof(pm.udp));
    }
    else
    {
        memcpy(pm.tcp.eth.src.addr, smac, 6);
        memcpy(pm.tcp.eth.dst.addr, dmac, 6);
        memcpy(data, &pm.tcp, sizeof(pm.tcp));
    }
    packet_set_len(m, pkt_length);
    return m;
}

/*
struct rte_mempool* tx_mempool_create(int n, int lcore_id)
{
    char name[64];
    struct rte_mempool *mp;
    struct rte_mbuf *m;
    int poolsz, i, pmi;
    snprintf(name, 64, "tx_mempool_lcore(%d)", lcore_id);
    mp = rte_pktmbuf_pool_create(name, n, MAX_TX_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_DATAROOM, rte_lcore_to_socket_id(lcore_id));
    if(mp == NULL)
    {
        rte_exit(EINVAL, "create mempool for lcore %d failed\n", lcore_id);
    }
    rte_mempool_dump(stdout, mp);
    return mp;
}*/
/*
int tx_mempool_alloc_bulk(struct rte_mempool *mp, struct rte_mbuf *mbuf[], int n)
{
    int ret, i;
    ret = rte_mempool_get_bulk(mp, (void**)mbuf, n);
    if(ret >= 0)
    {
        for(i = 0; i < n; i++)
        {
            tx_mbuf_init_noreset(mbuf[i]);
        }
    }
    return ret;
}

void tx_mempool_free_bulk(struct rte_mbuf *mbuf[], int n)
{
    int i;
    for(i = 0; i < n; i++)
    {
        rte_pktmbuf_free(mbuf[i]);
    }
}*/
