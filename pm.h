#ifndef PM_H
#define PM_H

#include <odp/helper/eth.h>
#include <odp/helper/ip.h>
#include <odp/helper/tcp.h>
#include <odp/helper/udp.h>

struct packet_model
{
    struct
    {
        odph_ethhdr_t eth;
        odph_ipv4hdr_t ip;
        odph_tcphdr_t tcp;
    }__attribute__((__packed__)) tcp;
    struct
    {
        odph_ethhdr_t eth;
        odph_ipv4hdr_t ip;
        odph_udphdr_t udp;
    }__attribute__((__packed__)) udp;
    int is_udp;
};

#endif
