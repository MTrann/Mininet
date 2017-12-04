/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
/*void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );*/
void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

void sr_handlepacket(struct sr_instance* sr,uint8_t * packet/* lent */,unsigned int len, char* interface/* lent */);
void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,unsigned int len, uint32_t next_hop_ip, struct sr_if *out_iface);
void sr_handlepacket_ip(struct sr_instance* sr,uint8_t *packet,unsigned int len,char* interface);
void sr_forward_handler(struct sr_instance* sr,uint8_t *packet,unsigned int len,struct sr_if *interface);
void sr_forward_packet(struct sr_instance* sr,uint8_t *packet,unsigned int len,uint8_t macAddress,struct  sr_if *outgoingInterface);
void sr_handle_ip_packet_reception(struct sr_instance* sr,uint8_t *packet,unsigned int len,sr_if *interface);
uint8_t is_ip_packet_ok(sr_ip_hdr_t *ip_header,unsigned int len);
uint8_t is_icmp_packet_ok(sr_icmp_hdr_t *icmp_header,unsigned int len);
uint8_t is_icmp_chksum_ok(sr_icmp_hdr_t *icmp_header);
uint8_t is_ip_chksum_ok(sr_ip_hdr_t *ip_header);
int send_icmp(struct sr_instance* sr, uint8_t icmp_type, uint8_t icmp_code,uint8_t *originalPacket, struct sr_if *interface);
sr_ethernet_hdr_t *get_ethernet_header(uint8_t *packet);
sr_ip_hdr_t *get_ip_header(uint8_t *packet);
sr_icmp_hdr_t *get_icmp_header(uint8_t *packet);
sr_icmp_t3_hdr_t *get_icmp_t3_header(uint8_t *packet);



#endif /* SR_ROUTER_H */
