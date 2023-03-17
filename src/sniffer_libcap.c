#include "sniffer_libcap.h"
#include <assert.h>
#include "ip6.h"

//----- Global variables ------
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,total=0,i,j;	
int tcp6=0,udp6=0,icmp6=0,others6=0,total6=0;	
//-----------------------------

uint16_t bate(unsigned char *buffer) {
    int o1 = (int) buffer[0];
    int o2 = (int) buffer[1];
    return (uint16_t) 256 * o1 + o2; 
}

int bote(unsigned char *buffer) {
	if ( buffer[0] == 0) return 0;
    return (bate(buffer) >> 2);
}

pcap_t* get_device_handle(char* devname) {
	pcap_t* handle;
    //Open the device for sniffing
	printf("Opening device %s for sniffing ... " , devname);
	handle = pcap_open_live(devname , 65536 , 1 , TIMEOUT , errbuf);
    if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
		exit(1);
	}
	printf("Done\n");
	return handle;
}

void apply_filter(pcap_t *handle, char *packet_filter, bpf_u_int32 netp) {
    struct bpf_program fcode;      /* hold compiled program     */
    // Lets try and compile the program.. non-optimized ( because of the 0 )
    if (pcap_compile(handle, &fcode, packet_filter, 0, netp) == -1) {
        fprintf(stderr, "Error calling pcap_compile\n"); 
        exit(1); 
    }
    // Set the compiled program as the filter
    if (pcap_setfilter(handle, &fcode) == -1) { 
        fprintf(stderr,"Error setting filter\n"); 
        exit(1); 
    }
}

char* chose_livedevice_to_sniff_on() {
    pcap_if_t *alldevsp , *device;

	char *devname , devs[100][100];
	int count = 1 , n;
	
	//First get the list of available devices
	printf("Finding available devices ... ");
	if( pcap_findalldevs( &alldevsp , errbuf) )
	{
		printf("Error finding devices : %s" , errbuf);
		exit(1);
	}
	printf("Done");
	
	//Print the available devices
	printf("\nAvailable Devices are :\n");
	for(device = alldevsp ; device != NULL ; device = device->next)
	{
		printf("%d. %s - %s\n" , count , device->name , device->description);
		if(device->name != NULL)
		{
			strcpy(devs[count] , device->name);
		}
		count++;
	}
	
	//Ask user which device to sniff
	printf("Enter the number of the device you want to sniff : ");
	scanf("%d" , &n);
    devname = malloc(sizeof(devs[n]));
    strcpy(devname, devs[n]);
    pcap_freealldevs(alldevsp);
    return devname;
    
}

static u_int16_t ether_packet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *p) {
  struct ether_header *eptr = (struct ether_header*)p;
  assert(pkthdr->caplen <= pkthdr->len);
  assert(pkthdr->caplen >= sizeof(struct ether_header));
  return eptr->ether_type;
}

// WARNING : The memory pointed to by pkt_data is not guaranteed to remain allocated after the callback routine returns !!
void process_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *buffer) {
	const u_int16_t type = ether_packet(user, header, buffer);
	int size = header->len;
	struct tcphdr *tcph;
	int header_size;

	pthread_mutex_lock(&packet_mutex);
	while (synchro == 0) {
		pthread_cond_wait(&packet_cond, &packet_mutex);
	}
	synchro--;

	switch (ntohs(type)) {
		case ETHERTYPE_IP:
		{
			struct ip *iph = (struct ip *)( buffer  + sizeof(ether_header_t));
			int iphdrlen = iph->ip_hl*4;
			tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(ether_header_t));
			header_size =  sizeof(ether_header_t) + iphdrlen + tcph->th_off*4;
			break;
		}
		case ETHERTYPE_IPV6:
		{
			tcph=(struct tcphdr*)(buffer + SIZEOF_IPV6 + sizeof(ether_header_t));
			header_size =  sizeof(ether_header_t) + SIZEOF_IPV6 + tcph->th_off*4;
			break;
		}
	}
	int source_port = ntohs(tcph->th_sport);
	int dest_port = ntohs(tcph->th_dport);
	packet_collected.source_port = source_port;
	packet_collected.dest_port = dest_port;
	packet_collected.size = size-header_size;
	packet_collected.buffer = malloc(sizeof(unsigned char)*(size-header_size));
	memset(packet_collected.buffer, 0, sizeof(unsigned char)*(size-header_size));
	// if you whish to copy the whole packet, just remove the "+ header_size"
	memcpy(packet_collected.buffer, buffer + header_size, (size_t)(size-header_size));

	// Comment this if no need to print the packet in a logfile
	debug_display(packet_collected, size, header_size);
	//

	pthread_cond_signal(&packet_cond);
	pthread_mutex_unlock(&packet_mutex);
	return;
}

// ------------------------------------- Displaying part -------------------------------------------

void debug_display(struct packet packet_collected, int size, int header_size) {
	PrintData(packet_collected.buffer, size-header_size);
	fprintf(logfile, "    Message id : %i\n", bote(packet_collected.buffer));
	if (packet_collected.source_port == 5555) fprintf(logfile, "    Packet server");
	else fprintf(logfile, "    Packet client");
	fprintf(logfile, "\n");
	fflush( logfile );
}


void display_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *buffer) {
	const u_int16_t type = ether_packet(user, header, buffer);
	int size = header->len;
	++total;
	switch (ntohs(type)) {
		case ETHERTYPE_IP:
			ipv4_handler(user, header, buffer);
			break;
		case ETHERTYPE_IPV6:
			ipv6_handler(user, header, buffer);
			break;
	}
}

void ipv4_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer) {
	int size = header->len;
	//Get the IP Header part of this packet , excluding the ethernet header
	struct ip *iph = (struct ip*)(buffer + sizeof(ether_header_t));
	switch (iph->ip_p) //Check the Protocol and do accordingly...
	{
		case 1:  //ICMP Protocol
			++icmp;
			ipv4_print_icmp_packet( buffer , size);
			break;

		case 6:  //TCP Protocol
			++tcp;
			ipv4_print_tcp_packet(buffer , size);
			break;
		
		case 17: //UDP Protocol
			++udp;
			ipv4_print_udp_packet(buffer , size);
			break;
		
		default: //Some Other Protocol like ARP etc.
			++others;
			break;
	}
	printf("IPv4 || TCP : %d   UDP : %d   ICMP : %d  Others : %d   Total : %d\n", tcp , udp , icmp , others , total);
}

void ipv4_print_ethernet_header(const u_char *Buffer, int Size) {
	ether_header_t *eth = (ether_header_t *)Buffer;
	
	fprintf(logfile , "\n");
	fprintf(logfile , "Ethernet Header\n");
	fprintf(logfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->ether_dhost[0] , eth->ether_dhost[1] , eth->ether_dhost[2] , eth->ether_dhost[3] , eth->ether_dhost[4] , eth->ether_dhost[5] );
	fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->ether_shost[0] , eth->ether_shost[1] , eth->ether_shost[2] , eth->ether_shost[3] , eth->ether_shost[4] , eth->ether_shost[5] );
	fprintf(logfile , "   |-Protocol            : %u \n",(unsigned short)eth->ether_type);
}

void ipv4_print_ip_header(const u_char * Buffer, int Size) {
	ipv4_print_ethernet_header(Buffer , Size);
	struct ip *iph = (struct ip *)(Buffer  + sizeof(ether_header_t) );
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->ip_src.s_addr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->ip_dst.s_addr;
	
	fprintf(logfile , "\n");
	fprintf(logfile , "IP Header\n");
	fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph->ip_v);
	fprintf(logfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ip_hl,((unsigned int)(iph->ip_hl))*4);
	fprintf(logfile , "   |-Type Of Service   : %d\n",(unsigned int)iph->ip_tos);
	fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->ip_len));
	fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph->ip_id));
	//fprintf(logfile , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
	//fprintf(logfile , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
	//fprintf(logfile , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
	fprintf(logfile , "   |-TTL      : %d\n",(unsigned int)iph->ip_ttl);
	fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph->ip_p);
	fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->ip_sum));

	fprintf(logfile , "   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
	fprintf(logfile , "   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
}

void ipv4_print_tcp_packet(const u_char * Buffer, int Size) {
	unsigned short iphdrlen;
	
	struct ip *iph = (struct ip *)( Buffer  + sizeof(ether_header_t) );
	iphdrlen = iph->ip_hl*4;
	
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(ether_header_t));
			
	int header_size =  sizeof(ether_header_t) + iphdrlen + tcph->th_off*4;
	
	fprintf(logfile , "\n\n***********************TCP Packet*************************\n");	
		
	ipv4_print_ip_header(Buffer,Size);
		
	fprintf(logfile , "\n");
	fprintf(logfile , "TCP Header\n");
	fprintf(logfile , "   |-Source Port      : %u\n",ntohs(tcph->th_sport));
	fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph->th_dport));
	fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->th_seq));
	fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->th_ack));
	fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->th_off,(unsigned int)tcph->th_off*4);
	//fprintf(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
	//fprintf(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
	fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int) get_bit(tcph->th_flags, 5));
	fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int) get_bit(tcph->th_flags, 4));
	fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int) get_bit(tcph->th_flags, 3));
	fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int) get_bit(tcph->th_flags, 2));
	fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int) get_bit(tcph->th_flags, 1));
	fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int) get_bit(tcph->th_flags, 0));
	fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->th_win));
	fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->th_sum));
	fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->th_urp);
	fprintf(logfile , "\n");
	fprintf(logfile , "                        DATA Dump                         ");
	fprintf(logfile , "\n");
		
	fprintf(logfile , "IP Header\n");
	PrintData(Buffer,iphdrlen);
		
	fprintf(logfile , "TCP Header\n");
	PrintData(Buffer+iphdrlen,tcph->th_off*4);
		
	fprintf(logfile , "Data Payload\n");	
	PrintData(Buffer + header_size , Size - header_size );
						
	fprintf(logfile , "\n###########################################################");
}

void ipv4_print_udp_packet(const u_char *Buffer , int Size) {
	unsigned short iphdrlen;
	
	struct ip *iph = (struct ip *)(Buffer +  sizeof(ether_header_t));
	iphdrlen = iph->ip_hl*4;
	
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(ether_header_t));
	
	int header_size =  sizeof(ether_header_t) + iphdrlen + sizeof udph;
	
	fprintf(logfile , "\n\n***********************UDP Packet*************************\n");
	
	ipv4_print_ip_header(Buffer,Size);			
	
	fprintf(logfile , "\nUDP Header\n");
	fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->uh_sport));
	fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->uh_dport));
	fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->uh_ulen));
	fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->uh_sum));
	
	fprintf(logfile , "\n");
	fprintf(logfile , "IP Header\n");
	PrintData(Buffer , iphdrlen);
		
	fprintf(logfile , "UDP Header\n");
	PrintData(Buffer+iphdrlen , sizeof udph);
		
	fprintf(logfile , "Data Payload\n");	
	
	//Move the pointer ahead and reduce the size of string
	PrintData(Buffer + header_size , Size - header_size);
	
	fprintf(logfile , "\n###########################################################");
}

void ipv4_print_icmp_packet(const u_char * Buffer , int Size) {
	unsigned short iphdrlen;
	
	struct ip *iph = (struct ip *)(Buffer  + sizeof(ether_header_t));
	iphdrlen = iph->ip_hl * 4;
	
	struct icmp *icmph = (struct icmp *)(Buffer + iphdrlen  + sizeof(ether_header_t));
	
	fprintf(logfile , "\n\n***********************ICMP Packet*************************\n");	
	
	ipv4_print_ip_header(Buffer , Size);
			
	fprintf(logfile , "\n");
		
	fprintf(logfile , "ICMP Header\n");
	fprintf(logfile , "   |-Type : %d",(unsigned int)(icmph->icmp_type));
			
	if((unsigned int)(icmph->icmp_type) == 11)
	{
		fprintf(logfile , "  (TTL Expired)\n");
	}
	else if((unsigned int)(icmph->icmp_type) == ICMP_ECHOREPLY)
	{
		fprintf(logfile , "  (ICMP Echo Reply)\n");
	}
	
	fprintf(logfile , "   |-Code : %d\n",(unsigned int)(icmph->icmp_code));
	fprintf(logfile , "   |-Checksum : %d\n",ntohs(icmph->icmp_cksum));
	//fprintf(logfile , "   |-ID       : %d\n",ntohs(icmph->id));
	//fprintf(logfile , "   |-Sequence : %d\n",ntohs(icmph->sequence));
	fprintf(logfile , "\n");

	fprintf(logfile , "Ethernet Header\n");
	PrintData(Buffer, sizeof(ether_header_t));
	
	fprintf(logfile , "IP Header\n");
	PrintData(Buffer + sizeof(ether_header_t), iphdrlen);
		
	fprintf(logfile , "ICMP Data Payload\n");	
	PrintData(Buffer + sizeof(ether_header_t) + iphdrlen , Size - (sizeof(ether_header_t) + iphdrlen) );
	
	fprintf(logfile , "\n###########################################################");
}

void ipv6_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer) {
	int size = header->len;
	struct ip6_hdr *iph = (struct ip6_hdr *)(buffer  + sizeof(ether_header_t));
	switch (iph->ip6_ctlun.ip6_un1.ip6_un1_nxt) // No need to ntohs, this a 8 bits number
	{
		case 58:  //ICMP6 Protocol
			++icmp6;
			// ipv6_print_icmp_packet( buffer , size); TODO
			// ipv6_print_ip_header(buffer, header->len);
			break;

		case 6:  //TCP Protocol
			++tcp6;
			ipv6_print_tcp_packet(buffer, header->len);
			break;
		
		case 17: //UDP Protocol
			++udp6;
			// ipv6_print_udp_packet(buffer , size); TODO
			// ipv6_print_ip_header(buffer, header->len);
			break;
		
		default:
			++others6;
			break;
	}
	printf("IPv6 || TCP : %d   UDP : %d   ICMP : %d  Others : %d   Total : %d\n", tcp6 , udp6 , icmp6 , others6 , total6);
	fflush( logfile ); // Force the logfile to synchronize with the buffer
}

void ipv6_print_ip_header(const u_char * buffer, int Size) {
	ipv4_print_ethernet_header(buffer , Size);
	struct ip6_hdr *iph = (struct ip6_hdr *)(buffer  + sizeof(ether_header_t));
	
	fprintf(logfile , "\n");
	fprintf(logfile , "IP Header\n");
	fprintf(logfile , "   |-IP Version        : 6\n");
	fprintf(logfile , "   |-IP Header Length  : 40\n");
	fprintf(logfile , "   |-Next Header (Protocol) : %d\n", (unsigned int)iph->ip6_ctlun.ip6_un1.ip6_un1_nxt);
	fprintf(logfile , "   |-Payload length   : %d\n",(unsigned int)iph->ip6_ctlun.ip6_un1.ip6_un1_plen);

	char* src_str = malloc(INET6_ADDRSTRLEN*sizeof(char));
	char* dst_str = malloc(INET6_ADDRSTRLEN*sizeof(char));

	fprintf(logfile , "   |-Source IP        : %s\n" , inet_ntop(AF_INET6, iph->ip6_src.__u6_addr.__u6_addr16, src_str, INET6_ADDRSTRLEN*sizeof(char)));
	fprintf(logfile , "   |-Destination IP   : %s\n" , inet_ntop(AF_INET6, iph->ip6_dst.__u6_addr.__u6_addr16, dst_str, INET6_ADDRSTRLEN*sizeof(char)));
	free(src_str);
	free(dst_str);	
	fprintf(logfile ,  "\n" );
}

void ipv6_print_tcp_packet(const u_char * Buffer, int Size) {
	unsigned short iphdrlen;
	struct ip6_hdr *iph = (struct ip6_hdr *)(Buffer  + sizeof(ether_header_t));
	iphdrlen = 40;
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(ether_header_t));
	int header_size =  sizeof(ether_header_t) + iphdrlen + tcph->th_off*4;
	
	fprintf(logfile , "\n\n*********************** TCP Packet 6 *************************\n");	
		
	ipv6_print_ip_header(Buffer,Size);
		
	fprintf(logfile , "\n");
	fprintf(logfile , "TCP Header\n");
	fprintf(logfile , "   |-Source Port      : %u\n",ntohs(tcph->th_sport));
	fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph->th_dport));
	fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->th_seq));
	fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->th_ack));
	fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->th_off,(unsigned int)tcph->th_off*4);
	//fprintf(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
	//fprintf(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
	fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int) get_bit(tcph->th_flags, 5));
	fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int) get_bit(tcph->th_flags, 4));
	fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int) get_bit(tcph->th_flags, 3));
	fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int) get_bit(tcph->th_flags, 2));
	fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int) get_bit(tcph->th_flags, 1));
	fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int) get_bit(tcph->th_flags, 0));
	fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->th_win));
	fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->th_sum));
	fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->th_urp);
	fprintf(logfile , "\n");
	fprintf(logfile , "                        DATA Dump                         ");
	fprintf(logfile , "\n");
		
	fprintf(logfile , "IP Header\n");
	PrintData(Buffer,iphdrlen);
		
	fprintf(logfile , "TCP Header\n");
	PrintData(Buffer+iphdrlen,tcph->th_off*4);
		
	fprintf(logfile , "Data Payload\n");	
	PrintData(Buffer + header_size , Size - header_size );
						
	fprintf(logfile , "\n###########################################################");

}

void PrintData (const u_char * data , int Size) {
	fprintf(logfile ,  "\n" );
	fprintf(logfile ,  "######### DATA ##########\n" );
	int i , j;
	for(i=0 ; i < Size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			fprintf(logfile , "         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet
				
				else fprintf(logfile , "."); //otherwise print a dot
			}
			fprintf(logfile , "\n");
		} 
		
		if(i%16==0) fprintf(logfile , "   ");

		fprintf(logfile , " %02X",(unsigned int)data[i]);
				
		if( i==Size-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) 
			{
			  fprintf(logfile , "   "); //extra spaces
			}
			
			fprintf(logfile , "         ");
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) 
				{
				  fprintf(logfile , "%c",(unsigned char)data[j]);
				}
				else 
				{
				  fprintf(logfile , ".");
				}
			}
			
			fprintf(logfile ,  "\n" );
		}
	}
}

uint8_t get_bit(uint8_t number, int index) {
    return ( (number >> index) & 1 );
}