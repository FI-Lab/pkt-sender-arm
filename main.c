#include <stdio.h>
#include <netinet/in.h>
#include <stddef.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

#include <odp.h>
#include <odp/helper/linux.h>
#include <odp/helper/udp.h>
#include <odp/helper/ip.h>
#include <odp/helper/tcp.h>
#include "odp_packet_io_internal.h"

#include "pm.h"
#include "tload.h"
#include "tx_mp.h"

//#define GEN_VXLAN

#define NB_MBUF 4096
#define NB_BURST 16
#define BUF_SIZE 2048

#define NB_MAX_PM 1000001

#define PRINT_GAP 2

/* global data */
struct 
{
    uint32_t total_trace;
    char trace_file[256];

    char names[ODP_CONFIG_PKTIO_ENTRIES][64];
    char dmacs[ODP_CONFIG_PKTIO_ENTRIES][6];
    int nic_num;
    odp_cpumask_t cpu_mask;

}ginfo;

/* generate mbuf */
struct packet_model pms[NB_MAX_PM];

/* pkt length*/
extern uint32_t pkt_length;

static void usage()
{
    printf("Usage: pkt-sender -i <ifaces> -t <trace_file> -L <pkt_length> -d <dmacs>\n");
    exit(-1);
}

static void parse_ifs(char *str)
{
    char *s, *sp, *tok[ODP_CONFIG_PKTIO_ENTRIES];
    int i;
    for(i = 0, s = str;;)
    {
        tok[i] = strtok_r(s, ",", &sp);
        s = NULL;
        if(tok[i] == NULL)
        {
            break;
        }
        memcpy(ginfo.names[i], tok[i], strlen(tok[i]) + 1);
        i++;
    }
    if(ginfo.nic_num != 0 && ginfo.nic_num != i)
    {
        fprintf(stderr, "number of dmacs != number of port!\n");
        exit(-1);
    }
    ginfo.nic_num = i;
}

static void parse_dmac_helper(int idx, char *str)
{
    char *s, *sp, *tok[6];
    int i;
    for(i = 0, s = str;;)
    {
        tok[i] = strtok_r(s, ":", &sp);
        s = NULL;
        if(tok[i] == NULL)
        {
            break;
        }
        ginfo.dmacs[idx][i] = strtoul(tok[i], NULL, 16);
        i++;
    }
}

static void parse_dmacs(char *str)
{
    char *s, *sp, *tok[ODP_CONFIG_PKTIO_ENTRIES];
    int i;
    for(i = 0, s = str;;)
    {
        tok[i] = strtok_r(s, ",", &sp);
        s = NULL;
        if(tok[i] == NULL)
        {
            break;
        }
        parse_dmac_helper(i, tok[i]);
        i++;
    }
    if(ginfo.nic_num != 0 && ginfo.nic_num != i)
    {
        fprintf(stderr, "number of dmacs != number of port!\n");
        exit(-1);
    }
    ginfo.nic_num = i;
}

static void parse_params(int argc, char **argv)
{
    char opt;
    int have_ifs = 0, have_traces = 0, have_dmacs = 0;
    while((opt = getopt(argc, argv, "i:t:d:L:")) != 255)
    {
        switch(opt)
        {
            case 'i': parse_ifs(optarg); have_ifs = 1; break;
            case 't': memcpy(ginfo.trace_file, optarg, strlen(optarg)+1); have_traces = 1; break;
            case 'L': 
                      pkt_length = atoi(optarg);
                      if(pkt_length < 64)
                      {
                          fprintf(stderr, "pkt_length >= 64!\n");
                          exit(-1);
                      }
                      break;
            case 'd': parse_dmacs(optarg); have_dmacs = 1; break;
            default: usage();
        }
    }
    if(!have_ifs || !have_traces || !have_dmacs)
    {
        usage();
    }

}
/**************************************************************/

/* lcore main */

struct
{
    uint64_t tx_total;
    uint64_t last_tx_total;
    uint64_t tx_pps;
    uint64_t tx_mbps;
    uint64_t rx_total;
    uint64_t last_rx_total;
    uint64_t rx_pps;
    uint64_t rx_mbps;
}port_stats[ODP_CONFIG_PKTIO_ENTRIES];

#define D02_MAX_ETH 2
struct
{
    uint64_t tx_pps;
    uint64_t tx_mbps;
    uint64_t tx_total;
    uint64_t rx_pps;
    uint64_t rx_mbps;
    uint64_t rx_total;
}eth_stats[D02_MAX_ETH];

struct lcore_args
{
    odp_pktio_t port_hdl;
    char mac[6];
    uint32_t trace_idx;
}lc_args[ODP_CONFIG_PKTIO_ENTRIES];

static odp_pool_t create_pkt_pool(char *name, uint32_t obj_sz, uint32_t elt_num)
{
    odp_pool_param_t param;
    odp_pool_t pool;
    memset(&param, 0, sizeof(param));
    param.type = ODP_POOL_PACKET;
    param.pkt.num = elt_num;
    param.pkt.len = obj_sz;
    param.pkt.seg_len = PACKET_SEG_LEN;
    param.pkt.lock = 0;
    pool = odp_pool_create(name, &param);
    return pool;
}

int init_all_if()
{
    odp_pktio_t hdl;
    odp_pool_t pool;
    int i;
    uint32_t mtu;

    for(i = 0; i < ginfo.nic_num; i++)
    {
        pool = create_pkt_pool(ginfo.names[i], BUF_SIZE, NB_MBUF);
        if(pool == ODP_POOL_INVALID)
        {
            return -1;
        }
        hdl = odp_pktio_open(ginfo.names[i], pool);
        if(hdl == ODP_PKTIO_INVALID)
        {
            return -1;
        }
        if(odp_pktio_mac_addr(hdl, lc_args[i].mac, 6) < 0)
        {
            return -1;
        }
        if((mtu = odp_pktio_mtu(hdl)) < 0)
        {
            return -1;
        }
        /*
        if(odp_pktio_promisc_mode_set(hdl, 1) < 0)
        {
            return -1;
        }*/
        //if(odp_pktio_start(hdl) < 0)
        //{
        //    return -1;
        //}
        lc_args[i].port_hdl = hdl;
        printf("NIC: %s (MAC:%2x-%2x-%2x-%2x-%2x-%2x, MTU:%u)\n",
                ginfo.names[i],
                lc_args[i].mac[0], lc_args[i].mac[1], lc_args[i].mac[2],
                lc_args[i].mac[3], lc_args[i].mac[4], lc_args[i].mac[5],
                mtu);
        struct odp_pktio_eth_link link;
        odp_pktio_link_get(hdl, &link);
        printf("iface %s %s\n", ginfo.names[i], link.link_status == 1 ? "up" : "down");
    }
    return 0;
}

static void dump_buf(char *buf, int len)
{
    int i;
    for(i = 0; i < len; i++)
    {
        if(i % 16 == 0)
        {
            printf("\n");
        }
        printf("%02x ", buf[i]);
    }
    printf("\n");
}

static void* sender_lcore_main(void *args)
{
    struct lcore_args *largs;
    int ret;
    odp_packet_t pkt_tbl[NB_BURST];
    int cpu_id = odp_cpu_id();
    largs = &lc_args[cpu_id];

    int rv_nb, sd_nb;

    odp_pktio_t hdl = largs->port_hdl;
    odp_pool_t mp = get_pktio_entry(hdl)->s.pkt_odp.pool;
    char *smac = largs->mac;
    char *dmac = ginfo.dmacs[cpu_id];

    printf("sender thread start on cpu(%d)\n"
            "smac: %02x:%02x:%02x:%02x:%02x:%02x\n"
            "dmac: %02x:%02x:%02x:%02x:%02x:%02x\n", cpu_id,
            smac[0], smac[1], smac[2], smac[3], smac[4], smac[5],
            dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5]);

    port_stats[cpu_id].tx_total = port_stats[cpu_id].last_tx_total = 0;
    port_stats[cpu_id].rx_total = port_stats[cpu_id].last_rx_total = 0;

    //static int c1 = 0, c2 = 0;
    //static int c3 = 0, c4 = 0;
    for(;;) 
    {
        rv_nb = odp_pktio_recv(hdl, pkt_tbl, NB_BURST);
        port_stats[cpu_id].rx_total += rv_nb;
        //printf("recv %d\n", rv_nb);
        while(rv_nb--)
        {
            odp_packet_free(pkt_tbl[rv_nb]);
        }
        for(sd_nb = 0; sd_nb < NB_BURST; sd_nb++)
        {
            if(largs->trace_idx == ginfo.total_trace)
            {
                largs->trace_idx = 0;
            }
            pkt_tbl[sd_nb] = generate_mbuf(pms[largs->trace_idx++], mp, pkt_length, smac, dmac);
        }
        sd_nb = odp_pktio_send(hdl, pkt_tbl, sd_nb);
        //printf("send %d\n", sd_nb);
        port_stats[cpu_id].tx_total += sd_nb;
        while(sd_nb < NB_BURST)
        {
            odp_packet_free(pkt_tbl[sd_nb++]);
        }
    }
    return NULL;
}

static void* print_stats(void* args)
{
    int nb_ports = *((int*)args);
    int i, j;
    uint64_t tx_total;
    uint64_t tx_last_total;
    uint64_t rx_total;
    uint64_t rx_last_total;
    uint64_t last_cyc, cur_cyc;
    uint64_t frame_len;
#ifdef GEN_VXLAN
    frame_len = pkt_length + 20 + 14 + 20 + 8 + 8;
#else
    frame_len = pkt_length + 20;
#endif
    double time_diff;
    last_cyc = odp_time_cycles();
    for(;;)
    {
        sleep(PRINT_GAP);
        i = system("clear");
        memset(eth_stats, 0, sizeof(eth_stats[0]) * D02_MAX_ETH);
        for(i = 0; i < nb_ports; i++)
        {
            tx_total = port_stats[i].tx_total;
            tx_last_total = port_stats[i].last_tx_total;
            rx_total = port_stats[i].rx_total;
            rx_last_total = port_stats[i].last_rx_total;

            cur_cyc = odp_time_cycles();
            time_diff = (cur_cyc - last_cyc) / (double)odp_sys_cpu_hz();
            port_stats[i].last_tx_total = tx_total;
            port_stats[i].tx_pps = (uint64_t)((tx_total - tx_last_total) / time_diff);
            port_stats[i].tx_mbps = port_stats[i].tx_pps * (frame_len) * 8 / (1000000);
            port_stats[i].last_rx_total = rx_total;
            port_stats[i].rx_pps = (uint64_t)((rx_total - rx_last_total) / time_diff);
            port_stats[i].rx_mbps = port_stats[i].rx_pps * (frame_len) * 8 / (1000000);
            j = (i * 2) / nb_ports;
            eth_stats[j].tx_pps += port_stats[i].tx_pps;
            eth_stats[j].tx_mbps += port_stats[i].tx_mbps;
            eth_stats[j].tx_total += tx_total;
            eth_stats[j].rx_pps += port_stats[i].rx_pps;
            eth_stats[j].rx_mbps += port_stats[i].rx_mbps;
            eth_stats[j].rx_total += rx_total;
        }
        last_cyc = odp_time_cycles();

        for(i = 0; i < D02_MAX_ETH; i++)
        {
            printf("Eth-port %d Statistics:\n", i);
            printf(">>>>>>>>>>>tx rate: %llupps\n", (unsigned long long)eth_stats[i].tx_pps);
            printf(">>>>>>>>>>>tx rate: %lluMbps\n", (unsigned long long)eth_stats[i].tx_mbps);
            printf(">>>>>>>>>>tx total: %llu\n", (unsigned long long)eth_stats[i].tx_total);
            printf("\n");
            printf(">>>>>>>>>>>rx rate: %llupps\n", (unsigned long long)eth_stats[i].rx_pps);
            printf(">>>>>>>>>>>rx rate: %lluMbps\n", (unsigned long long)eth_stats[i].rx_mbps);
            printf(">>>>>>>>>>rx total: %llu\n", (unsigned long long)eth_stats[i].rx_total);
            printf("============================\n");
        }
        /*for(i = 0; i < nb_ports; i++)
        {
            printf("Port %d Statistics:\n", i);
            printf(">>>>>>>>>>>tx rate: %llupps\n", (unsigned long long)port_stats[i].tx_pps);
            printf(">>>>>>>>>>>tx rate: %lluMbps\n", (unsigned long long)port_stats[i].tx_mbps);
            printf(">>>>>>>>>>tx total: %llu\n", (unsigned long long)port_stats[i].tx_total);
            printf("\n");
            printf(">>>>>>>>>>>rx rate: %llupps\n", (unsigned long long)port_stats[i].rx_pps);
            printf(">>>>>>>>>>>rx rate: %lluMbps\n", (unsigned long long)port_stats[i].rx_mbps);
            printf(">>>>>>>>>>rx total: %llu\n", (unsigned long long)port_stats[i].rx_total);
            printf("============================\n");
        }*/
    }
}

int main(int argc, char **argv)
{
    int ret;
    ret = odp_init_global(NULL, NULL);
    if(ret < 0)
    {
        fprintf(stderr, "odp_init_global failed!\n");
        exit(-1);
    }
    ret = odp_init_local(ODP_THREAD_CONTROL);
    if(ret < 0)
    {
        fprintf(stderr, "odp_init_local failed!\n");
        exit(-1);
    }

    parse_params(argc, argv);

    ret = init_all_if();
    if(ret < 0)
    {
        fprintf(stderr, "init all ifs!\n");
        exit(EXIT_FAILURE);
    }

    ret = load_trace(ginfo.trace_file, pms);   

    ginfo.total_trace = ret;
    if(ret < 0)
    {
        fprintf(stderr, "load traces failed!\n");
        exit(EXIT_FAILURE);
    }

    int i;
    odp_cpumask_zero(&ginfo.cpu_mask);
    for(i = 0; i < ginfo.nic_num; i++)
    {
        lc_args[i].trace_idx = 0;
        odp_cpumask_set(&ginfo.cpu_mask, i);
    }

    odph_linux_pthread_t thr_tbl[ODP_CONFIG_PKTIO_ENTRIES];
    int thr_num;
    thr_num = odph_linux_pthread_create(thr_tbl, &ginfo.cpu_mask, sender_lcore_main, NULL);
    if(thr_num != ginfo.nic_num)
    {
        fprintf(stderr, "thread start failed!\n");
        exit(-1);
    }

    odph_linux_pthread_t thr_stat_hdl;
    odp_cpumask_t thr_stat_mask;

    odp_cpumask_zero(&thr_stat_mask);
    odp_cpumask_set(&thr_stat_mask, ginfo.nic_num);
    if(odph_linux_pthread_create(&thr_stat_hdl, &thr_stat_mask, print_stats, &ginfo.nic_num) != 1)
    {
        fprintf(stderr, "stat thread start failure!\n");
        exit(EXIT_FAILURE);
    }

    odph_linux_pthread_join(thr_tbl, thr_num);
    odph_linux_pthread_join(&thr_stat_hdl, 1);

    odp_term_local();
    odp_term_global();
    return 0;
}
