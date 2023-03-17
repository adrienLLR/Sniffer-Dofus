#include "sniffer_libcap.h"
#include "data_parser.h"
#include "message.h"
#include <pthread.h>

#define HEADER 2
#define INSTANCE_ID 4
#define NB_TO_SNIFF 200

FILE *logfile;
char errbuf[100];
unsigned char tampon[1800];
struct packet packet_collected;
pthread_mutex_t packet_mutex;
pthread_cond_t packet_cond;
int synchro = 1;


int main(int argc, char **argv);

void* sniffer(void *arg);
void* callback(void *arg);
void synchronizer(void (*function)(void));

void printf_packet_info();
void get_messages();
unsigned char** get_buffer();