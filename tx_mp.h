#ifndef TX_MP
#define TX_MP

#include <odp.h>
#include "pm.h"

/*int tx_mempool_alloc_bulk(struct rte_mempool *mp, struct rte_mbuf *mbuf[], int n);*/

//void tx_mempool_free_bulk(struct rte_mbuf *mbuf[], int n);

/*static inline void tx_mbuf_init_noreset(struct rte_mbuf *m)
{
    m->next = NULL;
    m->nb_segs = 1;
    m->port = 0xff;
    m->data_off = (RTE_PKTMBUF_HEADROOM <= m->buf_len) ? RTE_PKTMBUF_HEADROOM : m->buf_len;
    RTE_MBUF_ASSERT(rte_mbuf_refcnt_read(m) == 0);
    rte_mbuf_refcnt_set(m, 1);
}*/

odp_packet_t generate_mbuf(struct packet_model pm, odp_pool_t mp, uint32_t pkt_length, char smac[], char dmac[]);

#endif
