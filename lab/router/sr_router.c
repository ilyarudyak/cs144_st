/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * *************THIS IS MY FILE*************
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
#include <unistd.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h" /* headers */
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Definitions
 *---------------------------------------------------------------------*/
#define MIN_IP_HDR_LEN 20 
#define MAX_IP_HDR_LEN 60
#define DEFAULT_TTL 64
#define ICMP_IP_HDR_LEN 5
#define ICMP_IP_HDR_LEN_BYTES ICMP_IP_HDR_LEN * 4
#define ICMP_COPIED_DATAGRAM_DATA_LEN 8
#define ICMP_ECHO_REQUEST_CODE 8 
#define ICMP_ECHO_REPLY_CODE 0
#define ICMP_UNREACHABLE_TYPE 3
#define ICMP_HOST_CODE 1
#define ICMP_NET_CODE 0
#define ICMP_PORT_CODE 3
#define ICMP_TIME_EXCEEDED_TYPE 11

/*---------------------------------------------------------------------
 * Internal Function Prototypes
 *---------------------------------------------------------------------*/
/* arp */

/* 1) add entry to arp table 2) call process_arp_request */
/*void process_arp(struct sr_instance* sr, uint8_t *packet,
        		 unsigned int len, char* interface);*/

/* send arp reply*/
void process_arp_request(struct sr_instance* sr,
       			     	 struct sr_arp_hdr *arp_hdr,
       			    	 struct sr_if*);

/*int valid_arp(uint8_t *packet, unsigned int len);*/




/* ip */
/*void process_ip(struct sr_instance* sr, uint8_t *packet,
        		unsigned int len, char* interface);
int valid_ip(uint8_t *packet, unsigned int len);
void forward_ip_pkt(struct sr_instance* sr, struct sr_ip_hdr *ip_hdr);*/


/* icmp */
/*void process_icmp(struct sr_instance* sr, struct sr_ip_hdr *ip_hdr);
int valid_icmp(struct sr_ip_hdr *ip_hdr);*/

/*other*/
/*int ping_address_match(uint32_t dip);*/

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

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  /* if type of ethernet frame == 0x0806, it's arp packet - process it*/
  if (ethertype(packet) == ethertype_arp)
      printf("%d", valid_arp(packet, len));
      

}/* end sr_ForwardPacket */

/*---------------------------------------------------------------------
 * Method: sr_encap_and_send_pkt(struct sr_instance* sr, 
 *						  							uint8_t *packet, 
 *						 		  					unsigned int len, 
 *						  	  					uint32_t dip,
 *						  							int send_icmp,
 *						  							sr_ethertype type)
 * Scope:  Global
 *
 * Sends a packet of length len and destination ip address dip, by 
 * looking up the shortest prefix match of the dip (net byte order). 
 * If the destination is not found, it sends an ICMP host unreachable. 
 * If it finds a match, it then checks the arp cache to find the 
 * associated hardware address. If the hardware address is found it 
 * sends it, otherwise it queues the packet and sends an ARP request. 
 *
 *---------------------------------------------------------------------*/
void sr_encap_and_send_pkt(struct sr_instance* sr,
						   uint8_t *packet, 
						   unsigned int len, 
						   uint32_t dip,
						   int send_icmp,
						   enum sr_ethertype type)
{
	struct sr_arpentry *arp_entry;
	struct sr_arpreq *arp_req;
	struct sr_ethernet_hdr eth_hdr;
	uint8_t *eth_pkt;
	struct sr_if *interface;
	struct sr_rt *rt;
	unsigned int eth_pkt_len;
	
	/* 1) Look up shortest prefix match in your routing table. */
	rt = sr_longest_prefix_match(sr, ip_in_addr(dip));
	
	/* If the entry doesn't exist, send ICMP host unreachable and return if necessary. */
	/*if (rt == 0) {
		if (send_icmp)
			sr_send_icmp(sr, packet, len, ICMP_UNREACHABLE_TYPE, ICMP_NET_CODE);
		return;
	}*/
	
	/* 2) Fetch the appropriate outgoing interface from routing table. */
	interface = sr_get_interface(sr, rt->interface);
	
	/* If there is already an arp entry in the cache, send now. */
	arp_entry = sr_arpcache_lookup(&sr->cache, rt->gw.s_addr);
	if (arp_entry || type == ethertype_arp) 
    {
		
		/* Create the ethernet packet. */
		eth_pkt_len = len + sizeof(eth_hdr);
		eth_hdr.ether_type = htons(type);
		
		/* Destination is broadcast if it is an arp request. */
		if (type == ethertype_arp && ((struct sr_arp_hdr *)packet)->ar_op == htons(arp_op_request))
			memset(eth_hdr.ether_dhost, 255, ETHER_ADDR_LEN);
		
		/* Destination is the arp entry mac if it is an ip packet or and are reply. */
		else
			memcpy(eth_hdr.ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);

		memcpy(eth_hdr.ether_shost, interface->addr, ETHER_ADDR_LEN);
		eth_pkt = malloc(eth_pkt_len);
		memcpy(eth_pkt, &eth_hdr, sizeof(eth_hdr));
		memcpy(eth_pkt + sizeof(eth_hdr), packet, len);
		sr_send_packet(sr, eth_pkt, eth_pkt_len, rt->interface);
		free(eth_pkt);
		if (arp_entry)
			free(arp_entry);
	
	/* Otherwise add it to the arp request queue. */
	} 
    /*else 
    {
		eth_pkt = malloc(len);
		memcpy(eth_pkt, packet, len);
		arp_req = sr_arpcache_queuereq(&sr->cache, rt->gw.s_addr, eth_pkt, len, rt->interface);
		sr_arpreq_handle(sr, arp_req);
		free(eth_pkt);
	}*/
}

/*---------------------------------------------------------------------
 * Method: process_arp_request(struct sr_instance* sr,
 *		      			   	  			 uint8_t * packet,
 *      			  	     				 char* interface)
 * Scope:  Internal
 *
 * This function processes an arp packet request.
 *
 *---------------------------------------------------------------------*/
void process_arp_request(struct sr_instance* sr,
       			   	  	 struct sr_arp_hdr *arp_hdr,
       			     	 struct sr_if* interface)
{
	struct sr_arp_hdr reply_arp_hdr;
	
	/* Create an ARP header with the appropriate reply information */
    /* fixed fields of arp header*/
	reply_arp_hdr.ar_hrd = htons(arp_hrd_ethernet); /* old enum = 1 ethernet*/
	reply_arp_hdr.ar_pro = htons(arp_pro_ip); /* NEW enum = 0x0800 ipv4*/
	reply_arp_hdr.ar_hln = ETHER_ADDR_LEN; /* ethernet length = 6*/
	reply_arp_hdr.ar_pln = sizeof(uint32_t); /* = 4 it's ipv4 */

    /*from enum arp_op_reply = 0x0002 - this is a REPLY message*/
	reply_arp_hdr.ar_op = htons(arp_op_reply);

    /* address fields*/
    /* source addresses - from interface!!!*/
	reply_arp_hdr.ar_sip = interface->ip;
    memcpy(reply_arp_hdr.ar_sha, interface->addr, ETHER_ADDR_LEN);

    /*target addresses - from incoming arp request*/
	reply_arp_hdr.ar_tip = arp_hdr->ar_sip;	
    memcpy(reply_arp_hdr.ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
		
	/* Encapsulate and attempt to send it. */
	sr_encap_and_send_pkt(sr, 
					      (uint8_t *)&reply_arp_hdr, 
			     		  sizeof(struct sr_arp_hdr), 
					      arp_hdr->ar_sip,
					      1,
					      ethertype_arp);
}










