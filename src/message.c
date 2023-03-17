#include "message.h"

dofus_class *dofus_class_table[10];
int indx = 0;

void get_dofus_message(unsigned char **buffer, int source_port, dofus_message* msg) {
    // printf("1\n");
    int16_t header = get_header(buffer);
    if (header == -1) { // no more messages to read, message_id becomes -1 to signify the end.
        msg->message_id = -1;
        return;
    }
    // printf("2\n");
    fill_msg_info(buffer, source_port, header, msg);
    // printf("3\n");
    if (fill_msg_content(buffer, msg) == -1) *buffer = *buffer + msg->message_length;
    // printf("4\n");
    msg->next = malloc(sizeof(dofus_message));
    // printf("5\n");
    get_dofus_message(buffer, source_port, msg->next);
}

void register_dofus_class(void* (*alloc_func)(void), void (*release_func)(void*), 
                          void (*deserialize)(unsigned char**, void*), char *name, 
                          void (*to_string)(void*), int message_id) {
    dofus_class *c = malloc(sizeof(dofus_class));
    c->name = name;
    c->message_id = message_id;
    c->alloc_func = alloc_func;
    c->release_func = release_func;
    c->deserialize = deserialize;    
    c->to_string = to_string;      
    dofus_class_table[indx] = c;
    indx++; if (indx < 10) return; printf("Too much dofus class registered"); exit(0);
}

dofus_class* get_dofus_class(int message_id) {
    for (int i = 0; i < indx; i++) {
        dofus_class *c = dofus_class_table[i];
        if (c->message_id == message_id) return c;
    }
    return NULL;
}

void fill_msg_info(unsigned char **buffer, int source_port, uint16_t header, dofus_message* msg) {
    msg->source_port = source_port;
    msg->message_id = get_message_id(header);
    msg->type_len = get_typelen(header);
    if (source_port != DOFUS_SOURCE_PORT) get_instance_id(buffer);
    msg->message_length = get_message_length(buffer, msg->type_len);
}

int fill_msg_content(unsigned char **buffer, dofus_message *msg) {
    dofus_class *c = get_dofus_class(msg->message_id);
    if (c == NULL) return -1;
    void *object_instance = c->alloc_func();
    c->deserialize(buffer, object_instance);
    msg->content = object_instance;
    return 0;
}

void display_msg(dofus_message *msg, int msg_number) {
    if (msg->message_id == -1) return;
    printf("----- Message number %i in the packet -----\nMessage id : %i\nMessage length : %i\nSource port : %i\n", msg_number, msg->message_id, msg->message_length, msg->source_port);
    dofus_class* c = get_dofus_class(msg->message_id);
    if (c != NULL) c->to_string(msg->content); else printf("The message is no present in the database\n");
    printf("------ End of message -------\n\n");
    if (msg->next->message_id != -1) display_msg(msg->next, msg_number + 1);
}

// ------------- InventoryWeightMessage || Message ID : 5080 -------------
void* alloc_inventoryweightmessage() {
    inventory_weight_message *msg = malloc(sizeof(inventory_weight_message));
    return (void*) msg;
}
void release_inventoryweightmessage(void *msg) {
    inventory_weight_message* cast_msg = (inventory_weight_message*) msg;
    free(cast_msg);
}
void deserialize_inventoryweightmessage(unsigned char **buffer, void *msg) {
    ((inventory_weight_message*) msg)->inventory_weight = read_unsigned_int(buffer);
    ((inventory_weight_message*) msg)->shop_weight = read_unsigned_int(buffer);
    ((inventory_weight_message*) msg)->weight_max = read_unsigned_int(buffer);
}

void to_string_inventoryweightmessage(void* content) {
    inventory_weight_message* cast_content = (inventory_weight_message*) content;
    printf("Inventory Weight Message :\nInventory Weight = %i | Shop Weight = %i | Weight Max = %i\n", cast_content->inventory_weight, cast_content->shop_weight, cast_content->weight_max);
}

void register_inventoryweight_class() {
    register_dofus_class(alloc_inventoryweightmessage, release_inventoryweightmessage, deserialize_inventoryweightmessage, "inventoryweight", to_string_inventoryweightmessage, 5080);
}
// -----------------------------------------------------------------------
