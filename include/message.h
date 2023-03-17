#include "data_parser.h"

#define DOFUS_SOURCE_PORT 5555

typedef struct dofus_message {
    int message_id;
    int type_len;
    int source_port;
    int message_length;
    void* content;
    struct dofus_message* next;
} dofus_message;

typedef struct dofus_class {
    char *name;
    int message_id;
    void* (*alloc_func)(void);
    void (*release_func)(void*);
    void (*deserialize)(unsigned char**, void*);
    void (*to_string)(void*);
} dofus_class;


typedef struct inventory_weight_message {
    int inventory_weight;
    int shop_weight;
    int weight_max;
} inventory_weight_message;



/*
 * Recursive function. Take in entry a malloced dofus_message struct and construct the linked list
 * of dofus messages. If the message is not present in the ones implemented, the content is NULL.
 */
void get_dofus_message(unsigned char **buffer, int source_port, dofus_message* msg);

void register_dofus_class(void* (*alloc_func)(void), void (*release_func)(void*), 
                          void (*deserialize)(unsigned char**, void*), char *name, 
                          void (*to_string)(void*), int message_id);

dofus_class* get_dofus_class(int message_id);

void fill_msg_info(unsigned char **buffer, int source_port, uint16_t header, dofus_message* msg);

/*
 * Return -1 if the class of the message is not implemented, 0 if not
 */
int fill_msg_content(unsigned char **buffer, dofus_message *msg);

void display_msg(dofus_message *msg, int msg_number);

// ----------------- Class functions ------------------------

void register_inventoryweight_class();
