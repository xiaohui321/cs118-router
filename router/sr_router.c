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
/* debug mode */

#define _DB_
#ifdef  _DB_
#define DB(X); X;
#else
#define DB(X); 
#endif

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sr_router.h"
#include "sr_arpcache.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"
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
    
} /* -- sr_init -- */

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

void sr_handlepacket(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
  
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  DB(print_hdr_eth(packet)); 

  uint16_t type = ethertype(packet);

  if (type == ethertype_ip)
    sr_handle_ip_packet(sr, packet, len, interface); 
  else if (type == ethertype_arp) 
    sr_handle_arp_packet(sr, packet, len, interface); 
  else
    fprintf(stderr, "ERROR: The type of packet is unknown. [ABORT]\n");
} /* end sr_handlepacket */


void sr_handle_arp_packet(struct sr_instance* sr, uint8_t *packet, unsigned int len, char* iface) {
  DB(printf("DEBUG: Handling ARP packet.\n"));

  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
    fprintf(stderr, "ERROR: This ARP packet does not have a enough length. [ABORT]\n");
    return;
  }
  
  sr_arp_hdr_t * arp_frame = (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
  DB(print_hdr_arp((uint8_t *) arp_frame));
  
  struct sr_if* interface = sr_get_interface_by_ip(sr, arp_frame->ar_tip);
  
  if(interface == NULL){
    fprintf(stderr, "ERROR: Can not find a matching interface. [ABORT]\n");
    return;
  }
  
  DB(sr_print_if(interface));

  if(strcmp(iface, interface->name)){
    fprintf(stderr, "ERROR: The interface found does not match with the given interface. [ABORT].\n");
    return;
  }

  if(arp_op_reply == ntohs(arp_frame->ar_op)){
    DB(printf("DEBUG: Processing ARP reply packet.\n"));
    struct sr_arpreq * arp_req = sr_arpcache_insert(&(sr->cache), arp_frame->ar_sha, arp_frame->ar_sip);
    if(arp_req == NULL) return;
    struct sr_packet * pkt = arp_req->packets;
    for (; pkt != NULL; pkt = pkt->next){
      sr_ethernet_hdr_t* eth_frame = (sr_ethernet_hdr_t *)(pkt->buf);
      struct sr_if* interface = sr_get_interface(sr, pkt->iface);
      memcpy(eth_frame->ether_dhost, arp_frame->ar_sha, ETHER_ADDR_LEN);
      memcpy(eth_frame->ether_shost, interface->addr, ETHER_ADDR_LEN);
      DB(print_hdrs(pkt->buf, pkt->len));
      sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
    }
  }else if(arp_op_request == ntohs(arp_frame->ar_op)){
    DB(printf("DEBUG: Processing ARP request packet.\n"));
    arp_frame->ar_tip = arp_frame->ar_sip;
    arp_frame->ar_sip = interface->ip;
    arp_frame->ar_op  = htons(arp_op_reply);
    memcpy(arp_frame->ar_tha, arp_frame->ar_sha, ETHER_ADDR_LEN);
    memcpy(arp_frame->ar_sha, interface->addr, ETHER_ADDR_LEN);
    sr_ethernet_hdr_t* eth_frame = (sr_ethernet_hdr_t*)(packet);
    memcpy(eth_frame->ether_dhost, arp_frame->ar_tha, ETHER_ADDR_LEN);
    memcpy(eth_frame->ether_shost, arp_frame->ar_sha, ETHER_ADDR_LEN);
    sr_send_packet(sr, packet, len, iface);
  }else{
    fprintf(stderr, "ERROR: The type of this ARP packet is unknown. [ABORT].\n");
  }
}

void sr_send_packet_by_ip(struct sr_instance* sr, uint8_t* packet, unsigned int len, uint32_t ip, char* iface){
  DB(printf("DEBUG: Send packet by ip address.\n"));
  struct sr_arpentry * arp_entry = sr_arpcache_lookup(&(sr->cache), ip);
  if(arp_entry){
    DB(printf("DEBUG: ARP cache found.\n"));
      sr_ethernet_hdr_t* eth_frame = (sr_ethernet_hdr_t *)(packet);
      struct sr_if* interface = sr_get_interface(sr, iface);
      memcpy(eth_frame->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
      memcpy(eth_frame->ether_shost, interface->addr, ETHER_ADDR_LEN);
      DB(print_hdrs(packet, len));
      sr_send_packet(sr, packet, len, iface);
  }else{
    DB(printf("DEBUG: ARP cache not found.\n"));
    struct sr_arpreq * arp_req = sr_arpcache_queuereq(&(sr->cache), ip, packet, len, iface);
    arp_req->interface_name = iface;
    sr_handle_all_arp_requests(sr,arp_req);
  }
}

void sr_handle_all_arp_requests(struct sr_instance* sr, struct sr_arpreq* arp_req) {
  DB(printf("DEBUG: Processing all the arp requests in the queue.\n"));
  time_t time_now = time(NULL);

  if (difftime(time_now, arp_req->sent) < 1.0)
    return;

  if (arp_req->times_sent < 5){
    /* Send request again */
    DB(printf("DEBUG: Resend ARP Request.\n"));
    DB(print_addr_ip_int(ntohl(arp_req->ip)));

    uint8_t* whole_frame = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    struct sr_if* interface = sr_get_interface(sr, arp_req->interface_name);

    /* ethernet frame */
    sr_ethernet_hdr_t* eth_frame = (struct sr_ethernet_hdr*) whole_frame;
    eth_frame->ether_type = htons(ethertype_arp);

    /* arp frame */
    sr_arp_hdr_t* arp_frame = (sr_arp_hdr_t*) (whole_frame + sizeof(sr_ethernet_hdr_t));
    arp_frame->ar_hrd = htons(arp_hrd_ethernet);
    arp_frame->ar_pro = htons(ethertype_ip);
    arp_frame->ar_hln = ETHER_ADDR_LEN;
    arp_frame->ar_pln = 4;
    arp_frame->ar_op  = htons(arp_op_request);
    arp_frame->ar_sip = interface->ip;
    arp_frame->ar_tip = arp_req->ip;
    memcpy(arp_frame->ar_sha, interface->addr, ETHER_ADDR_LEN);
    memcpy(eth_frame->ether_shost, interface->addr, ETHER_ADDR_LEN);

    int i;
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
      arp_frame->ar_tha[i] = 0xFF;
      eth_frame->ether_dhost[i] = 0xFF;
    }
    arp_req->sent = time_now;
    arp_req->times_sent++;
    sr_send_packet(sr, whole_frame, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface->name);
    free(whole_frame);
  } else {
    DB(printf("DEBUG: Have sent 5 Times. Host is Unreachable.\n"));
    struct sr_packet * pkt = arp_req->packets;
    for (; pkt != NULL; pkt = pkt->next) {
      sr_ip_hdr_t * ip_frame = (sr_ip_hdr_t *)(pkt->buf + sizeof(sr_ethernet_hdr_t));
      sr_handle_icmp_packet(sr, 3, 1, ip_frame->ip_src, (uint8_t *)ip_frame, pkt->iface);
    }
    sr_arpreq_destroy(&(sr->cache), arp_req);
  }
}

void sr_handle_icmp_packet(struct sr_instance* sr, uint8_t type, uint8_t code, uint32_t ip, uint8_t* data, char* iface) {

  DB(printf("DEBUG: Handling ICMP packet.\n"));
  uint8_t* whole_frame = (uint8_t *) malloc ( sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

  /* ethernet frame */
  sr_ethernet_hdr_t* eth_frame = (sr_ethernet_hdr_t *)(whole_frame);
  eth_frame->ether_type = htons(ethertype_ip);

  /* ip frame*/
  sr_ip_hdr_t * ip_frame = (sr_ip_hdr_t *)(whole_frame + sizeof(sr_ethernet_hdr_t));
  struct sr_if* interface = sr_get_interface(sr, iface);
  ip_frame->ip_v   = 4;
  ip_frame->ip_hl  = 5;
  ip_frame->ip_tos = 0;
  ip_frame->ip_len = htons( sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  ip_frame->ip_id  = htons(0);
  ip_frame->ip_off = htons(IP_DF);
  ip_frame->ip_ttl = 100;
  ip_frame->ip_p   = ip_protocol_icmp;
  ip_frame->ip_sum = 0;
  ip_frame->ip_sum = cksum(whole_frame + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
  ip_frame->ip_dst = ip;
  ip_frame->ip_src = interface->ip;

  /* icmp frame */
  sr_icmp_t3_hdr_t * icmp_frame = (sr_icmp_t3_hdr_t *)(whole_frame + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  memcpy(icmp_frame->data, data, ICMP_DATA_SIZE);
  icmp_frame->icmp_type = type;
  icmp_frame->icmp_code = code;
  icmp_frame->unused    = 0;
  icmp_frame->next_mtu  = 0;
  icmp_frame->icmp_sum  = 0;
  icmp_frame->icmp_sum  = cksum(whole_frame + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), sizeof(sr_icmp_t3_hdr_t));

  /* send */
  struct sr_rt* rt = sr_find_rt_by_ip(sr, ip);
  if (rt == NULL) {
    fprintf(stderr, "ERROR: Can not find a route to the destination. [ABORT]\n");
    return;
  }
  sr_send_packet_by_ip(sr, whole_frame, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), ip, rt->interface);
  free(whole_frame);
}

void sr_handle_ip_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* iface) {
  DB(printf("DEBUG: Handling IP packet.\n"));

  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    fprintf(stderr, "ERROR: This IP packet does not have a enough length. [ABORT]\n");
    return;
  }

  DB(print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t))); 

  /* ip request frame */
  sr_ip_hdr_t * ip_request_frame = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  uint16_t old_checksum = ip_request_frame->ip_sum;
  ip_request_frame->ip_sum = 0;
  
  if (old_checksum != cksum(packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t))) {
    fprintf(stderr, "ERROR: IP checksum is incorrect. [ABORT]\n");
    return;
  }
  
  /* Check if in router's interfaces */
  struct sr_if* interface = sr_get_interface_by_ip(sr, ip_request_frame->ip_dst);

  
  if(!interface){
    DB(printf("DEBUG: Forwarding IP packet.\n"));
    struct sr_rt * forward_rt = sr_find_rt_by_ip(sr, ip_request_frame->ip_dst);
    
    if (forward_rt == NULL) {
      DB(printf("DEBUG: Cannot find a route to the destination. [ABORT]\n"));
      sr_handle_icmp_packet(sr, 3, 0, ip_request_frame->ip_src, (uint8_t *)ip_request_frame, iface);
      return;
    }
    
    ip_request_frame->ip_ttl--;
    if (ip_request_frame->ip_ttl == 0) {
      DB(printf("DEBUG: IP packet expired.\n"));
      sr_handle_icmp_packet(sr, 11, 0, ip_request_frame->ip_src, (uint8_t *)ip_request_frame, iface);
      return;
    }
    
    ip_request_frame->ip_sum = 0;
    ip_request_frame->ip_sum = cksum((uint8_t*) ip_request_frame, sizeof(sr_ip_hdr_t));
    sr_send_packet_by_ip(sr, packet, len, forward_rt->gw.s_addr,forward_rt->interface);
    
    return;
  }
  
  /* interface found */
  if (ip_request_frame->ip_p ==  ip_protocol_icmp) { 
    DB(printf("DEBUG: Handling ICMP packet.\n"));
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)) {
      fprintf(stderr, "ERROR: This ICMP packet does not have a enough length. [ABORT]\n");
      return;
    }
    
    /* ICMP frame */
    sr_icmp_hdr_t * icmp_request_frame = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    old_checksum = icmp_request_frame->icmp_sum;
    icmp_request_frame->icmp_sum = 0;
    if (old_checksum != cksum((uint8_t *) icmp_request_frame, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t))) {
      fprintf(stderr, "ERROR: ICMP checksum is incorrect. [ABORT]\n");
      return;
    }
    
    if (icmp_request_frame->icmp_type != 8 || icmp_request_frame->icmp_code != 0) {
      printf("ERROR: This ICMP packet has an incorrect type and/or code. [ABORT]\n");
      return;
    }
    
    /* response */
    uint8_t* whole_frame = (uint8_t *) malloc (len);
    memcpy(whole_frame + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t),
	   len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
    
    /* ethernet frame */
    sr_ethernet_hdr_t* eth_frame = (sr_ethernet_hdr_t *) whole_frame;
    eth_frame->ether_type = htons(ethertype_ip);
    
    /* IP frame */
    sr_ip_hdr_t* ip_frame = (sr_ip_hdr_t *) (whole_frame + sizeof(sr_ethernet_hdr_t));
    ip_frame->ip_v   = 4;
    ip_frame->ip_hl  = 5;
    ip_frame->ip_tos = 0;
    ip_frame->ip_len = htons(len - sizeof(sr_ethernet_hdr_t));
    ip_frame->ip_id  = htons(0);
    ip_frame->ip_off = htons(IP_DF);
    ip_frame->ip_ttl = 100;
    ip_frame->ip_p   = ip_protocol_icmp;
    ip_frame->ip_sum = 0;
    ip_frame->ip_sum = cksum(whole_frame + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
    ip_frame->ip_dst = ip_request_frame->ip_src;
    ip_frame->ip_src = ip_request_frame->ip_dst;
    
    /* ICMP frame */
    sr_icmp_hdr_t* icmp_frame = (sr_icmp_hdr_t *)(whole_frame + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_frame->icmp_type = 0;
    icmp_frame->icmp_code = 0;
    icmp_frame->icmp_sum  = 0; 
    icmp_frame->icmp_sum  = cksum(whole_frame + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), 
				  len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
    
    /* send response */
    sr_send_packet_by_ip(sr, whole_frame, len, ip_frame->ip_dst, iface);
    
    free(whole_frame);
    
  } else if (ip_request_frame->ip_p == 6 || ip_request_frame->ip_p == 17) {
    DB(printf("DEBUG: Handling UDP/TCP packet.\n"));
    sr_handle_icmp_packet(sr, 3, 3, ip_request_frame->ip_src, (uint8_t *)ip_request_frame, iface);
  
  } else 
    fprintf(stderr, "ERROR: Cannot find the corresponding protocol. [ABORT]\n");
}