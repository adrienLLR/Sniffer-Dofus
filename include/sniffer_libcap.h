#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset
#include <sys/types.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <net/if.h>
#include <pthread.h>

#define TIMEOUT 1000
#define SIZEOF_IPV6 40

 /*
  * Important : The buffer contains the DATA PAYLOAD, not the whole packet
  */
#ifndef STRUCTPACKET
struct packet {
    int size;
    unsigned char *buffer;
    int source_port;
    int dest_port;
};
#endif

//------------- Logfile file descriptor and error buffer variables -----------
extern FILE* logfile;
extern char errbuf[100];
//----------------------------------------------------------------------------

//------------- Synchronize variables --------------
extern struct packet packet_collected;
extern pthread_mutex_t packet_mutex;
extern pthread_cond_t packet_cond;
extern int synchro;
//--------------------------------------------------

uint8_t get_bit(uint8_t number, int index);
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
/*
 * Return the ethernet type. Useful to know if it is IPv6 or IPv4.
 */
static u_int16_t ether_packet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *p);
/*
 * Function to use to have a complete display of the packets
 */
void display_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *buffer);
void debug_display(struct packet packet_collected, int size, int header_size);
void ipv4_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);
void ipv4_print_ethernet_header(const u_char *Buffer, int Size);
void ipv4_print_ip_header(const u_char * Buffer, int Size);
void ipv4_print_ip_packet(const u_char * , int);
void ipv4_print_tcp_packet(const u_char *  , int );
void ipv4_print_udp_packet(const u_char * , int);
void ipv4_print_icmp_packet(const u_char * , int );
void ipv6_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);
void ipv6_print_ip_header(const u_char * buffer, int Size);
void ipv6_print_tcp_packet(const u_char * Buffer, int Size);
void PrintData (const u_char * , int);
char* chose_livedevice_to_sniff_on(void);
pcap_t* get_device_handle(char* devname);
void apply_filter(pcap_t *handle, char *packet_filter, bpf_u_int32 netp);