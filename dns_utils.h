#ifndef DNS_UTILS_H
#define DNS_UTILS_H

#include "general_utils.h"
#include "params.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>
#include <stdint.h>

int get_domain_name(const u_char *data, const u_char *original_dns_pointer, int number_of_recursions, int data_printed_size, FILE *fp, char *domain_name, int current_length);
int print_domain_name_setup(const u_char *data, const u_char *original_dns_pointer, bool possible_translation);

void print_ipv6_address(const uint8_t *data);
void print_ipv4_address(const uint8_t *data);
void print_MX(const uint8_t *data, const uint8_t *original_dns_pointer);
void print_SRV(const uint8_t *data, const uint8_t *original_dns_pointer);
void print_SOA(const uint8_t *data, const uint8_t *original_dns_pointer);
void print_q_type(const uint8_t *data, uint16_t qtype, const uint8_t *original_dns_pointer);
void print_CLASS_and_TYPE(uint16_t qclass, uint16_t qtype);

#endif