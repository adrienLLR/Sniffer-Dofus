#include "data_parser.h"

// Les ID utiles : ObjectQuantityMessage 5311 après fauchage


// Note : Le buffer est en big-endian c'est-à-dire que l'octet le plus fort est à gauche
// ou à l'adresse mémoire la plus petite

int test_if_buffer_empty(unsigned char **buffer, int index) {
    unsigned char *buffer_p = *buffer;
    for (int i = 0; i < index; i++) {
        if (buffer_p[i] == BACKSLASH_0_ASCII_VALUE) return -1;
    }
    return 0;
}

int16_t get_header(unsigned char **buffer) {
    if (test_if_buffer_empty(buffer, 2) == -1) return -1;
    return read_unsigned_short(buffer);
}

int get_message_id(int16_t header) {
    if (header == -1) return -1;
    return (int) (((uint16_t) header) >> 2);
}

int get_typelen(int16_t header) {
    if (header == -1) return -1;
    return (int) (((uint16_t) header) & 3);
}

int get_instance_id(unsigned char **buffer) {
    return read_unsigned_int(buffer);
}

int get_message_length(unsigned char **buffer, int type_len) {
    int message_length = 0;
    switch(type_len) {
        case 0:
            break;
        case 1:
            message_length = read_unsigned_byte(buffer);
            break;
        case 2:
            message_length = read_unsigned_short(buffer);
            break;
        case 3:
            ;
            int x1 = (int) ((read_byte(buffer) & 0xFF) << 16);
            int x2 = (int) ((read_byte(buffer + 1) & 0xFF) << 8);
            int x3 = (int) (read_byte(buffer + 2) & 0xFF);
            message_length = x1 + x2 + x3;
            break;

    }
    return message_length;
}

// ID : 5311, paquet reçu après fauchage de blé
int* get_ObjectQuantityMessage(unsigned char **buffer) {
    if (test_if_buffer_empty(buffer, 4*3) == -1) return 0;
    int objectUID = read_unsigned_int(buffer);
    int quantity = read_unsigned_int(buffer + 4);
    int origin = (int) read_byte(buffer + 8);
    int  *objectquantitymessage_ptr = malloc(3 * sizeof(int));
    objectquantitymessage_ptr[0] = objectUID; objectquantitymessage_ptr[1] = quantity; objectquantitymessage_ptr[2] = origin;
    return objectquantitymessage_ptr;
}




