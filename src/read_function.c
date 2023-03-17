#include "read_function.h"

uint32_t read_unsigned_int(unsigned char **buffer) {
    unsigned char *buffer_p = *buffer;
    *buffer = (*buffer + 4);
    return 16777216 * (uint32_t) buffer_p[0] + 65536 * (uint32_t) buffer_p[1] + 256 * (uint32_t) buffer_p[2] + (uint32_t) buffer_p[3];
}

uint16_t read_unsigned_short(unsigned char **buffer) {
    unsigned char *buffer_p = *buffer;
    *buffer = (*buffer + 2);
    int o1 = (int) buffer_p[0];
    int o2 = (int) buffer_p[1];
    return (uint16_t) 256 * o1 + o2; 
}

uint8_t read_unsigned_byte(unsigned char **buffer) {
    unsigned char *buffer_p = *buffer;
    *buffer = (*buffer + 1);
    return (uint8_t) buffer_p[0];
}

int8_t read_byte(unsigned char **buffer) {
    unsigned char *buffer_p = *buffer;
    *buffer = (*buffer + 1);
    return (int8_t) buffer_p[0];
}