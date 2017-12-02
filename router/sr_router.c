/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
 *             unsigned int orig_len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces 
 *---------------------------------------------------------------------*/
void sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
    unsigned int orig_len, struct sr_if *src_iface)
{
  /* Allocate space for packet */
  unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *reply_pkt = (uint8_t *)malloc(reply_len);
  if (NULL == reply_pkt)
  {
    fprintf(stderr,"Failed to allocate space for ARP reply");
    return;
  }

  sr_ethernet_hdr_t *orig_ethhdr = (sr_ethernet_hdr_t *)orig_pkt;
  sr_arp_hdr_t *orig_arphdr = 
      (sr_arp_hdr_t *)(orig_pkt + sizeof(sr_ethernet_hdr_t));

  sr_ethernet_hdr_t *reply_ethhdr = (sr_ethernet_hdr_t *)reply_pkt;
  sr_arp_hdr_t *reply_arphdr = 
      (sr_arp_hdr_t *)(reply_pkt + sizeof(sr_ethernet_hdr_t));

  /* Populate Ethernet header */
  memcpy(reply_ethhdr->ether_dhost, orig_ethhdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(reply_ethhdr->ether_shost, src_iface->addr, ETHER_ADDR_LEN);
  reply_ethhdr->ether_type = orig_ethhdr->ether_type;

  /* Populate ARP header */
  memcpy(reply_arphdr, orig_arphdr, sizeof(sr_arp_hdr_t));
  reply_arphdr->ar_hrd = orig_arphdr->ar_hrd;
  reply_arphdr->ar_pro = orig_arphdr->ar_pro;
  reply_arphdr->ar_hln = orig_arphdr->ar_hln;
  reply_arphdr->ar_pln = orig_arphdr->ar_pln;
  reply_arphdr->ar_op = htons(arp_op_reply); 
  memcpy(reply_arphdr->ar_tha, orig_arphdr->ar_sha, ETHER_ADDR_LEN);
  reply_arphdr->ar_tip = orig_arphdr->ar_sip;
  memcpy(reply_arphdr->ar_sha, src_iface->addr, ETHER_ADDR_LEN);
  reply_arphdr->ar_sip = src_iface->ip;

  /* Send ARP reply */
  printf("Send ARP reply\n");
  print_hdrs(reply_pkt, reply_len);
  sr_send_packet(sr, reply_pkt, reply_len, src_iface->name);
  free(reply_pkt);
} /* -- sr_send_arpreply -- */

/*---------------------------------------------------------------------
 * Method: sr_send_arprequest(struct sr_instance *sr, 
 *             struct sr_arpreq *req,i struct sr_if *out_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces 
 *---------------------------------------------------------------------*/
void sr_send_arprequest(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface)
{
  /* Allocate space for ARP request packet */
  unsigned int reqst_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *reqst_pkt = (uint8_t *)malloc(reqst_len);
  if (NULL == reqst_pkt)
  {
    fprintf(stderr,"Failed to allocate space for ARP reply");
    return;
  }

  sr_ethernet_hdr_t *reqst_ethhdr = (sr_ethernet_hdr_t *)reqst_pkt;
  sr_arp_hdr_t *reqst_arphdr = 
      (sr_arp_hdr_t *)(reqst_pkt + sizeof(sr_ethernet_hdr_t));

  /* Populate Ethernet header */
  memset(reqst_ethhdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
  memcpy(reqst_ethhdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
  reqst_ethhdr->ether_type = htons(ethertype_arp);

  /* Populate ARP header */
  reqst_arphdr->ar_hrd = htons(arp_hrd_ethernet);
  reqst_arphdr->ar_pro = htons(ethertype_ip);
  reqst_arphdr->ar_hln = ETHER_ADDR_LEN;
  reqst_arphdr->ar_pln = sizeof(uint32_t);
  reqst_arphdr->ar_op = htons(arp_op_request); 
  memcpy(reqst_arphdr->ar_sha, out_iface->addr, ETHER_ADDR_LEN);
  reqst_arphdr->ar_sip = out_iface->ip;
  memset(reqst_arphdr->ar_tha, 0x00, ETHER_ADDR_LEN);
  reqst_arphdr->ar_tip = req->ip;

  /* Send ARP request */
  printf("Send ARP request\n");
  print_hdrs(reqst_pkt, reqst_len);
  sr_send_packet(sr, reqst_pkt, reqst_len, out_iface->name);
  free(reqst_pkt);
} /* -- sr_send_arprequest -- */

/*---------------------------------------------------------------------
 * Method: sr_handle_arpreq(struct sr_instance *sr, 
 *             struct sr_arpreq *req, struct sr_if *out_iface)
 * Scope:  Global
 *
 * Perform processing for a pending ARP request: do nothing, timeout, or  
 * or generate an ARP request packet 
 *---------------------------------------------------------------------*/
void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface)
{
  time_t now = time(NULL);
  if (difftime(now, req->sent) >= 1.0)
  {
    if (req->times_sent >= 5)
    {
      /*********************************************************************/
      /* TODO: send ICMP host uncreachable to the source address of all    */
      /* packets waiting on this request                                   */


      sr_packet packet;
      packet = req->packets;
      char*  interface;

      while(packet != NULL)
      {
        interface = packet.iface;

        sr_send_packet(sr, packet, packet->len, interface);
        packet = packet.next;
      }



      /*********************************************************************/
     struct sr_packet *curr_packet = reg->packet;
     while(curr_packet != NULL){
         send_icmp_packe(sr,curr_packet, 3,0);
         curr_packet = curr_packet -> next;
     }
        
      
      sr_arpreq_destroy(&(sr->cache), req);
    }
    else
    { 
      /* Send ARP request packet */
      sr_send_arprequest(sr, req, out_iface);
       
      /* Update ARP request entry to indicate ARP request packet was sent */ 
      req->sent = now;
      req->times_sent++;
    }
  }
} /* -- sr_handle_arpreq -- */

/*---------------------------------------------------------------------
 * Method: void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, uint32_t next_hop_ip, 
 *             struct sr_if *out_iface)
 * Scope:  Local
 *
 * Queue a packet to wait for an entry to be added to the ARP cache
 *---------------------------------------------------------------------*/
void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
    unsigned int len, uint32_t next_hop_ip, struct sr_if *out_iface)
{
    struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, 
            pkt, len, out_iface->name);
    sr_handle_arpreq(sr, req, out_iface);
} /* -- sr_waitforarp -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Handle an ARP packet that was received by the router
 *---------------------------------------------------------------------*/
void sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
    unsigned int len, struct sr_if *src_iface)
{
  /* Drop packet if it is less than the size of Ethernet and ARP headers */
  if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)))
  {
    printf("Packet is too short => drop packet\n");
    return;
  }

  sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

  switch (ntohs(arphdr->ar_op))
  {
  case arp_op_request:
  {
    /* Check if request is for one of my interfaces */
    if (arphdr->ar_tip == src_iface->ip)
    { sr_send_arpreply(sr, pkt, len, src_iface); }
    break;
  }
  case arp_op_reply:
  {
    /* Check if reply is for one of my interfaces */
    if (arphdr->ar_tip != src_iface->ip)
    { break; }

    /* Update ARP cache with contents of ARP reply */
    struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arphdr->ar_sha, 
        arphdr->ar_sip);

    /* Process pending ARP request entry, if there is one */
    if (req != NULL)
    {
      /*********************************************************************/
      /* TODO: send all packets on the req->packets linked list            */



      /*********************************************************************/

      /* Release ARP request entry */
      sr_arpreq_destroy(&(sr->cache), req);
    }
    break;
  }    
  default:
    printf("Unknown ARP opcode => drop packet\n");
    return;
  }
} /* -- sr_handlepacket_arp -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/






/*
TODO:
overview:
  icmp messages
  packet forwarding

More indepth:

  unfinished:
    sr_handlepacket_ip
    sr_handle_ip_packet_reception
    send_icmp_echo_reply

  Need:
   send_icmp_error
    sr_forward_packet

/////////////////////////////////////////////////////////////////////////
//NOTE: THE NEEDED LIST IS INCOMPLETE. WE MAY NEED MORE THAN JUST THAT.// 
//THE UNFINISHED LIST IS ALSO INCOMPLETE, ONE THE NEEDED LIST IS BEGUN //
//THE UNFINISHED LIST WILL EXPAND.                                     //
/////////////////////////////////////////////////////////////////////////
//PLEASE UPDATE THE LISTS AS YOU WORK ON THE PROJECT                   //
/////////////////////////////////////////////////////////////////////////

Dependencies:

  sr_handlepacket_ip
    sr_handle_ip_packet_reception
    sr_forward_packet

  sr_handleip_packet_reception
    send_icmp_echo_reply
    send_icmp_error

  sr_forward_packet
    send_icmp_error
*/
void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);
  printf("*** -> Received packet of length %d \n",len);
  struct sr_if simpleRouterInterface* = sr_get_interface(sr,interface);
  uint16_t ethtype = ethertype(packet);
  switch(ethtype){
    case(ethertype_ip):
      sr_handlepacket_ip(sr,packet,len,simpleRouterInterface);
      break;
    case(ethertype_arp):
      sr_handlepacket_arp(sr,packet,len,simpleRouterInterface);
      break
    default:
      fprintf(stderr, "Packet type Unknown, dropping.", );
  }
}

void sr_handlepacket_ip(struct sr_instance* sr,
        uint8_t *packet,
        unsigned int len,
        char* interface){
  //gets header
  sr_ip_hdr_t ip_header* = get_ip_header(packet);
  //check if packet is ok
  if(!is_ip_packet_ok(ip_header,len)){
    return;
  }
  //walk through our routers interfaces and see if the ip matches with the packet headers ip destination
  struct sr_if *interfaces = sr->if_list;
  while(interfaces){
    if(interfaces->ip==ip_header->ip_dst){
      //it matches!
      sr_handle_ip_packet_reception(sr,packet,len,interfaces);
      return;
    }
    interfaces = interfaces->next;
    //Packet is not ours
      //check ttl
      //if ttl is less than or equal to 1
        //send an ICMP time exceeded (type 11 code 0)
      //else
        //forward the packet
          //look up next hop address by doing a LPM on the routing table using the packet's destination address
          //if it does not exist
            //send an icmp port unreachable (type3, code 3)
          //if it does exist
            //determine outgoing interface and next-hop MAC address
              //it might be necessary to send ARP request to determine MAC address
            //encapsulate IP datagram in ethernet packet
            //forward packet to outgoing interface
  }
}
void sr_handle_ip_packet_reception(struct sr_instance* sr,
        uint8_t *packet,
        unsigned int len,
        sr_if *interface){
  /*
    Will probably need seperate methods for the two... I have an incomplete one for the echo reply... my head hurts... I'm going to bed...
  */
  sr_ip_hdr_t ip_header = get_ip_header(packet);
  uint8_t packets_ip_protocol = ip_header->ip_p;
  if(packets_ip_protocol==ip_protocol_icmp)
  {

    sr_icmp_hdr_t *icmpHeader = get_icmp_header(packet);
    //NEED TO CHECK THE HEADER OF ICMP HERE
    //NEED TO CHECK THE HEADER OF ICMP HERE
    //NEED TO CHECK THE HEADER OF ICMP HERE
    //NEED TO CHECK THE HEADER OF ICMP HERE
    uint8_t icmpType = icmpHeader->icmp_type;

    if(icmpType==0x008){
      //reply with echo reply. (type 0x0, code 0x0)

    }
    else{
      return;
    }
  }
  else{
    //generate icmp port unreachable
  }
  
}


uint8_t is_ip_packet_ok(sr_ip_hdr_t *ip_header,unsigned int len){
  //sanity check for ip packets
  //check checksum
  uint8_t isPacketOkay = (is_ip_chksum_ok());
  //check length
  if(len < (sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)))
    isPacketOkay=0;
  return isPacketOkay;
}

uint8_t is_ip_chksum_ok(sr_ip_hdr_t *ip_header){
  uint16_t hdrSum = ip_header->ip_sum;
  ip_header->ip_sum=0;
  uint8_t isChkSumOk =(cksum(ip_header,sizeof(sr_ip_hdr_t))==hdrSum);
  ip_header->ip_sum = hdrSum;
  return isChkSumOk;
}
//returns the lcoation of the IP header within the packet
sr_ethernet_hdr_t *get_ethernet_header(uint8_t packet*){
  return (sr_ethernet_hdr_t *)packet;
}
sr_ip_hdr_t *get_ip_header(uint8_t packet*){
  return (sr_ip_hdr_t *)packet+sizeof(sr_ethernet_hdr_t);
}
sr_icmp_hdr_t *get_icmp_header(uint8_t packet*){
  return (sr_icmp_hdr_t *)packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t);
}



//INCOMPLETE//
int send_icmp_echo_reply(struct sr_instance* sr, uint8_t icmp_type, uint8_t icmp_code,uint8_t *originalPacket, struct sr_if *interface ){

  /*
  //length of packet headers
  unsigned int length = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_ip_hdr_t);
  //allocated enough space for all the headers, no payload really...
  uint8_t *packet = (uint8_t*)malloc(len);
  //default as 0's 
  bzero(packet,len);
  //get ethernet header
  sr_ethernet_hdr_t *originalEthernetHeader = get_ethernet_header (originalPacket);
  sr_ip_hdr_t       *originalIPHeader       = get_ip_header       (originalPacket);
  sr_icmp_hdr_t     *originalIcmpHeader     = get_icmp_header     (originalPacket);
  sr_ethernet_hdr_t *ethernetHeader         = get_ethernet_header (packet);
  sr_ip_hdr_t *packetIPHeader               = get_ip_header       (packet);
  sr_icmp_hdr_t *icmpHeader                 = get_icmp_header     (packet);
  memcpy(ethernetHeader->ether_dhost,ethernetHeader->ether_shost,ETHER_ADDR_LEN);
  memcpy(ethernetHeader->ether_shost,interface->ip,ETHER_ADDR_LEN);
  uint32_t sourceIP = originalIPHeader->ip;
  packetIPHeader->ip_src = interface->ip;
  packetIPHeader->ip_dst = sourceIP;
  icmpHeader->icmp_type=icmp_type;
  icmpHeader->icmp_code=icmp_code;
  icmpHeader->icmp_sum=0;
  icmpHeader->icmp_sum=cksum(icmp_hdr,sizeof(sr_icmp_hdr_t));
  return sr_send_packet(sr,packet,len,)
  */

}

