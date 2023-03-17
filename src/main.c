#include "main.h"

/* 

 /!\ INFO /!\  De base, le buffer de libpcap fait 65535 bytes.
 Cela veut dire que je peux choper 540 paquets sans les traiter. 
 Apres experimentation, ca met 1 min pour choper les 540 paquets
 donc je devrais avoir le temps de faire de la synchronisation
 Au pire : aggrandir le buffer si besoin

 Some examples for the filter : 
 "icmp6 || icmp"
 "ip6 host 2a01:cb16:65:b07d:19ab:f40e:f96a:636 and tcp and len >= 50"
 "ip host google.com and icmp"
 "tcp port 5555 && len <= 120" 
 
 */

int main(int argc, char **argv) {   
    pthread_cond_init(&packet_cond, NULL);
    pthread_mutex_init(&packet_mutex, NULL);
    pthread_t sniffer_thread;
    pthread_t callback_thread;
    char devname[4] = "en0";

    if (pthread_create(&sniffer_thread, NULL, sniffer, (void*) devname) == -1) {
        printf("Error while creating the sniffer thread\n");
        exit(0);
    }
    if (pthread_create(&callback_thread, NULL, callback, NULL) == -1) {
        printf("Error while creating the data parser thread\n");
        exit(0);
    }
    // Use to let the thread run independently :
    // pthread_detach(sniffer_thread);
    // Otherwise, use this :
    pthread_join(sniffer_thread, NULL);
    pthread_join(callback_thread, NULL);
    pthread_mutex_destroy(&packet_mutex);
}

void *sniffer(void *arg) {
    bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip of the host machine    */
    pcap_t *handle;             // Handle of the device chosen
    char *packet_filter = "tcp port 5555";
    char *devname = (char*) arg;

	// ask pcap for the network address and mask of the device
    pcap_lookupnet(devname, &netp, &maskp, errbuf);
	handle = get_device_handle(devname);
    apply_filter(handle, packet_filter, netp);
	logfile=fopen("bin/log.txt","w"); if (logfile==NULL) {fprintf(stderr, "Unable to create file."); exit(1);}
    //Put the device in sniff loop
	pcap_loop(handle , NB_TO_SNIFF , process_packet , NULL);	
    return NULL;
}


void* callback(void *arg) {
    register_inventoryweight_class();
    for (int i = 0; i < NB_TO_SNIFF; i++) {
        synchronizer(get_messages);
    }
    return NULL;
}

void synchronizer(void (*function)(void)) {
    pthread_mutex_lock(&packet_mutex);
    while (synchro == 1) {
        pthread_cond_wait(&packet_cond, &packet_mutex);
    }
    synchro++;
    function();
    pthread_cond_signal(&packet_cond);
    pthread_mutex_unlock(&packet_mutex);
}

void get_messages() {
    unsigned char **buffer = get_buffer();
    dofus_message *first_msg = malloc(sizeof(dofus_message));
    get_dofus_message(buffer, packet_collected.source_port, first_msg);
    display_msg(first_msg, 1);
}

void printf_packet_info() {
    unsigned char **ptr_packet = get_buffer();
    int size = packet_collected.size, instance_id, message_id, type_len;
    uint16_t header = get_header(ptr_packet);
    message_id = get_message_id(header);
    type_len = get_typelen(header);

    if (packet_collected.source_port != DOFUS_SOURCE_PORT) instance_id = get_instance_id(ptr_packet);
    int message_length = get_message_length(ptr_packet, type_len);
    if (message_length > 0 ) {
        if (packet_collected.source_port == DOFUS_SOURCE_PORT) printf("---- Server packet ---- \n\n");
        else printf("---- Client packet ---- \n\n");
        if (packet_collected.source_port != DOFUS_SOURCE_PORT) printf("Instance ID : %i\n", instance_id);
        printf("Message id : %i\nType len : %i\nMessage length : %i\n", message_id, type_len, message_length);
        printf("\n");
    }
    free(packet_collected.buffer);
    free(ptr_packet);
}

unsigned char** get_buffer() {
    unsigned char *packet = packet_collected.buffer;
    unsigned char **ptr_packet = malloc(sizeof(unsigned char*));
    *ptr_packet = packet;
    return ptr_packet;
}