#include<stdio.h>
#include<stdlib.h>
#include<string.h> 
#include "read_function.h"

#define BACKSLASH_0_ASCII_VALUE 0

/*
 * Test if the read is possible from the start to the index.
 * Prevent Segmentation fault
 */
int test_if_buffer_empty(unsigned char **buffer, int index);

int16_t get_header(unsigned char **buffer);
int get_message_id(int16_t header);
int get_message_length(unsigned char **buffer, int type_len);
int get_typelen(int16_t header);
int get_instance_id(unsigned char **buffer);
