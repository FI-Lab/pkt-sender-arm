#include "tload.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>
#include "pm.h"

#include <odp/helper/ip.h>
#include <odp/helper/tcp.h>

uint32_t pkt_length = 64;

#if 0
static void debug_pm(struct packet_model pm)
{
    printf("0x0000: %04X %04X %04X %04X %04X %04X %04X %04X\n",
            ((uint16_t)pm.eth.dst.addr[0] << 8) | pm.eth.dst.addr[1],
            ((uint16_t)pm.eth.dst.addr[2] << 8) | pm.eth.dst.addr[3],
            ((uint16_t)pm.eth.dst.addr[4] << 8) | pm.eth.dst.addr[5],
            ((uint16_t)pm.eth.src.addr[0] << 8) | pm.eth.src.addr[1],
            ((uint16_t)pm.eth.src.addr[2] << 8) | pm.eth.src.addr[3],
            ((uint16_t)pm.eth.src.addr[4] << 8) | pm.eth.src.addr[5],
            ((uint16_t)ntohs(pm.eth.type)),
            ((uint16_t)pm.ip.ver_ihl << 8) | pm.ip.tos);
    printf("0x0010: %04X %04X %04X %04X %04X %04X %04X %04X\n",
            ntohs(pm.ip.tot_len),
            ntohs(pm.ip.id),
            ntohs(pm.ip.frag_offset),
            ((uint16_t)pm.ip.ttl << 8) | pm.ip.proto,
            ntohs(pm.ip.chksum),
            (uint16_t)(ntohl(pm.ip.src_addr) >> 16),
            (uint16_t)(ntohl(pm.ip.src_addr) & 0xffff),
            (uint16_t)(ntohl(pm.ip.dst_addr) >> 16));
    printf("0x0020: %04X ", (uint16_t)(ntohl(pm.ip.dst_addr) & 0xffff));
    if(pm.ip.proto == 6)
    {
        printf("%04X %04X %04X %04X %04X %04X %04X\n",
                ntohs(pm.l4.tcp.hdr.src_port),
                ntohs(pm.l4.tcp.hdr.dst_port),
                ntohl(pm.l4.tcp.hdr.seq_no) >> 16,
                ntohl(pm.l4.tcp.hdr.seq_no) & 0xffff,
                ntohl(pm.l4.tcp.hdr.ack_no) >> 16,
                ntohl(pm.l4.tcp.hdr.ack_no) & 0xffff,
                ((uint16_t)pm.l4.tcp.hdr.rsvd1 << 8) | pm.l4.tcp.hdr.flags);
        
        printf("0x0030: %04X %04X %04X\n",
                ntohs(pm.l4.tcp.hdr.window),
                ntohs(pm.l4.tcp.hdr.cksum),
                ntohs(pm.l4.tcp.hdr.urgptr));
    }
    else
    {
        printf("%04X %04X %04X %04X\n",
                ntohs(pm.l4.udp.hdr.src_port),
                ntohs(pm.l4.udp.hdr.dst_port),
                ntohs(pm.l4.udp.hdr.length),
                ntohs(pm.l4.udp.hdr.chksum));
    }
}
#endif

int load_trace_line(FILE *fp, struct packet_model *pm)
{
    int i;
    char buff[256];
    char *tok[7], *s, *sp;
    if(fgets(buff, 256, fp) == NULL)
    {
        return END_LINE;
    }
    for(i = 0, s = buff; i < NB_FIELD; i++, s = NULL)
    {
        tok[i] = strtok_r(s, " \t\n", &sp);
    }

    uint8_t proto;
    proto = (uint8_t)strtoul(tok[4], NULL, 0);
    if(proto != 6 && proto != 17)
    {
        return INVALID_LINE;
    }
    
    if(proto == 6)
    {
        //ether header
        memset(&(pm->tcp.eth.dst), 0, sizeof(pm->tcp.eth.dst));
        memset(&(pm->tcp.eth.src), 0, sizeof(pm->tcp.eth.src));
        pm->tcp.eth.dst.addr[5] = (uint8_t)0x02;
        pm->tcp.eth.src.addr[5] = (uint8_t)0x01;
        pm->tcp.eth.type = htons((uint16_t)0x0800);

        //ipv4 header
        pm->tcp.ip.proto = proto;
        pm->tcp.ip.ver_ihl = (uint8_t)0x45;
        pm->tcp.ip.tos = (uint8_t)0;
        pm->tcp.ip.tot_len = htons((uint16_t)(pkt_length - 18));
        pm->tcp.ip.id = 0;
        pm->tcp.ip.frag_offset = 0x0040;//DF
        pm->tcp.ip.ttl = 0xff;
        pm->tcp.ip.chksum = 0;
        pm->tcp.ip.src_addr = htonl(strtoul(tok[0], NULL, 0));
        pm->tcp.ip.dst_addr = htonl(strtoul(tok[1], NULL, 0));
        pm->tcp.ip.chksum = odp_chksum(&(pm->tcp.ip), 20);

        //l4 header
        pm->tcp.tcp.src_port = htons((uint16_t)strtoul(tok[2], NULL, 0));
        pm->tcp.tcp.dst_port = htons((uint16_t)strtoul(tok[3], NULL, 0));
        pm->tcp.tcp.seq_no = htonl(1);
        pm->tcp.tcp.ack_no = htonl(2);
        pm->tcp.tcp.rsvd1 = (uint8_t)(sizeof(odph_tcphdr_t)>>2)<<4;
        pm->tcp.tcp.flags = (uint8_t)0x10;
        pm->tcp.tcp.window = htons(0xffff);
        pm->tcp.tcp.cksm= 0;
        pm->tcp.tcp.urgptr = 0;
        //don't calculate cksm, so l4 cksm is invalid
        //pm->tcp.tcp.cksm = rte_ipv4_udptcp_cksum(&(pm->tcp.ip), (void*)&(pm->tcp.tcp));
        pm->is_udp = 0;
    }
    else
    {
        //ether header
        memset(&(pm->udp.eth.dst), 0, sizeof(pm->udp.eth.dst));
        memset(&(pm->udp.eth.src), 0, sizeof(pm->udp.eth.src));
        pm->udp.eth.dst.addr[5] = (uint8_t)0x02;
        pm->udp.eth.src.addr[5] = (uint8_t)0x01;
        pm->udp.eth.type = htons((uint16_t)0x0800);

        //ipv4 header
        pm->udp.ip.proto = proto;
        pm->udp.ip.ver_ihl = (uint8_t)0x45;
        pm->udp.ip.tos = (uint8_t)0;
        pm->udp.ip.tot_len = htons((uint16_t)(pkt_length - 18));
        pm->udp.ip.id = 0;
        pm->udp.ip.frag_offset = 0x0040;//DF
        pm->udp.ip.ttl = 0xff;
        pm->udp.ip.chksum = 0;
        pm->udp.ip.src_addr = htonl(strtoul(tok[0], NULL, 0));
        pm->udp.ip.dst_addr = htonl(strtoul(tok[1], NULL, 0));
        pm->udp.ip.chksum = odp_chksum(&(pm->udp.ip), 20);


        pm->udp.udp.src_port = htons((uint16_t)strtoul(tok[2], NULL, 0));
        pm->udp.udp.dst_port = htons((uint16_t)strtoul(tok[3], NULL, 0));
        pm->udp.udp.length = htons((uint16_t)(pkt_length - 18 - sizeof(odph_ipv4hdr_t)));
        pm->udp.udp.chksum = 0;
        //don't calculate l4 cksm, so it's invalid
        //pm->udp.udp.chksum = rte_ipv4_udptcp_cksum(&(pm->udp.ip), (void*)&(pm->udp.udp));
        pm->is_udp = 1;
    }
    return VALID_LINE;
}

int load_trace(const char *file, struct packet_model pms[])
{
    FILE *fp = fopen(file, "rb");
    int ret = 0;
    int count = 0;
    if(fp == NULL)
    {
        fprintf(stderr, "trace file not exist!\n");
        exit(-1);
    }
    while((ret = load_trace_line(fp, &pms[count])) != END_LINE)
    {
        if(ret == VALID_LINE)
        {
            count++;
        }
    }
    printf("total trace %d\n", count);
    return count;
}

