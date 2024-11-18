#include "dns_utils.h"

int get_domain_name(const u_char *data, const u_char *original_dns_pointer, int number_of_recursions, int data_printed_size, FILE *fp, char *domain_name, int current_length){
    if ((*data & 0xC0) == 0xC0){
        uint16_t pointer_offset = 0;
        pointer_offset = ((*data & 0x3F) << 8) | *(data + 1);
        number_of_recursions++;
        return get_domain_name(original_dns_pointer+pointer_offset, original_dns_pointer, number_of_recursions, data_printed_size, fp, domain_name, current_length);
    }
    else{
        uint8_t name_length = *data;
        if (name_length != 0){
            data ++;
            if (number_of_recursions == 0){
                data_printed_size++;
            }

            for (size_t i = 0; i < name_length; i++) {
                if (current_length < 254) {  // 254 because the last byte is for '\0'
                    domain_name[current_length++] = *data;
                    domain_name[current_length] = '\0';
                }
                data ++;
                
                if (number_of_recursions == 0){
                    data_printed_size++;
                }
            }
            if (current_length < 254) {
                domain_name[current_length++] = '.';
                domain_name[current_length] = '\0';
            }

            return get_domain_name(data, original_dns_pointer, number_of_recursions, data_printed_size, fp, domain_name, current_length);
        }
        if (number_of_recursions == 0){
            data_printed_size++;
        }
    }
    return data_printed_size + 2*number_of_recursions;
}

int print_domain_name_setup(const u_char *data, const u_char *original_dns_pointer, bool possible_translation){
    FILE *fp = NULL;
    if (params.domainsfile != NULL){
        fp = fopen(params.domainsfile, "a+");
        if (fp == NULL){
            fprintf(stderr, "Error oppening file\n");
            return -1;
        }
    }
    
    char *domain_name = malloc(255 * sizeof(char));
    if (domain_name == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }
    domain_name[0] = '\0';

    int return_value =  get_domain_name(data, original_dns_pointer, 0, 0, fp, domain_name, 0);

    if (params.verbose){
        printf("%s", domain_name);
    }
    
    if (fp != NULL){
        int length = strlen(domain_name);
        domain_name[length-1] = '\0';       // remove last dot
        fprintf(fp, "%s\n", domain_name);
        fflush(fp);                         // Ensure all written data is saved before checking duplicates
        remove_duplicate_last_line(fp);
        fclose(fp);
    }
    
    if(params.translationsfile != NULL && possible_translation){
        FILE *fp_translations_file = fopen(params.translationsfile, "a+");
        if (fp_translations_file == NULL){
            fprintf(stderr, "Error oppening file\n");
            return -1;
        }

        fprintf(fp_translations_file, "%s ", domain_name);
        fclose(fp_translations_file);
    }

    free(domain_name);
    return return_value;
}

void print_ipv6_address(const u_char *data) {
    size_t ipv6_address_size = 40;
    char *ipv6_address = (char *)malloc(ipv6_address_size);
    
    if (ipv6_address == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }

    snprintf(ipv6_address, ipv6_address_size, 
            "%x:%x:%x:%x:%x:%x:%x:%x",
            ntohs(*((uint16_t *)(data + 0))),
            ntohs(*((uint16_t *)(data + 2))),
            ntohs(*((uint16_t *)(data + 4))),
            ntohs(*((uint16_t *)(data + 6))),
            ntohs(*((uint16_t *)(data + 8))),
            ntohs(*((uint16_t *)(data + 10))),
            ntohs(*((uint16_t *)(data + 12))),
            ntohs(*((uint16_t *)(data + 14))));
    
    if (params.verbose) {
        printf("%s", ipv6_address);
    }

    if(params.translationsfile != NULL){
        FILE *fp_translations_file = fopen(params.translationsfile, "a+");
        if (fp_translations_file == NULL){
            fprintf(stderr, "Error oppening file\n");
            return;
        }

        fprintf(fp_translations_file, "%s\n", ipv6_address);
        fflush(fp_translations_file);                         // Ensure all written data is saved before checking duplicates
        remove_duplicate_last_line(fp_translations_file);
        fclose(fp_translations_file);
    }

    free(ipv6_address);
}

void print_ipv4_address(const u_char *data){
    size_t ipv4_address_size = 16;
    char *ipv4_address = (char *)malloc(ipv4_address_size);
    if (ipv4_address == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }
    
    snprintf(ipv4_address, ipv4_address_size, "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);

    if(params.verbose){
        printf("%s", ipv4_address);
    }

    if(params.translationsfile != NULL){
        FILE *fp_translations_file = fopen(params.translationsfile, "a+");
        if (fp_translations_file == NULL){
            fprintf(stderr, "Error oppening file\n");
            free(ipv4_address);
            return;
        }

        fprintf(fp_translations_file, "%s\n", ipv4_address);
        fflush(fp_translations_file);                         // Ensure all written data is saved before checking duplicates
        remove_duplicate_last_line(fp_translations_file);
        fclose(fp_translations_file);
    }

    free(ipv4_address);
}

void print_MX(const u_char *data, const u_char *original_dns_pointer){
    uint16_t preference = ntohs(*((uint16_t*)data));
    data += 2;
    printf(" %u ", preference);
    print_domain_name_setup(data, original_dns_pointer, false);        // email
}

void print_SRV(const u_char *data, const u_char *original_dns_pointer){
    uint16_t priority = ntohs(*((uint16_t*)data));
    uint16_t weight = ntohs(*((uint16_t*)(data + 2)));
    uint16_t port = ntohs(*((uint16_t*)(data + 4)));
    data += 6;

    printf(" %u %u %u ", priority, weight, port);
    print_domain_name_setup(data, original_dns_pointer, false);        // email
}

void print_SOA(const u_char *data, const u_char *original_dns_pointer){
    data += print_domain_name_setup(data, original_dns_pointer, false);        // nameserver
    if (params.verbose){
        printf(" ");
    }
    data += print_domain_name_setup(data, original_dns_pointer, false);        // email

    uint32_t serial = ntohl(*((uint32_t*)data));
    uint32_t refresh_interval = ntohl(*((uint32_t*)(data+4)));
    uint32_t retry_interval = ntohl(*((uint32_t*)(data+8)));
    uint32_t expire_limit = ntohl(*((uint32_t*)(data+12)));
    uint32_t minimum_ttl = ntohl(*((uint32_t*)(data+16)));

    if (params.verbose){
        printf(" %u %u %u %u %u", serial, refresh_interval, retry_interval, expire_limit, minimum_ttl);
    }
}

void print_q_type(const u_char *data, uint16_t qtype, const u_char *original_dns_pointer){
    bool remove_domain_name_from_file = true;
    switch (qtype){
        case 1:                                         //A
            print_ipv4_address(data);
            remove_domain_name_from_file = false;
            break;
        case 2:                                         // NS
            print_domain_name_setup(data, original_dns_pointer, false);
            break;
        case 5:                                         // CNAME
            print_domain_name_setup(data, original_dns_pointer, false);
            break;
        case 15:
            print_MX(data, original_dns_pointer);       // MX
            break;
        case 6:                                         // SOA
            print_SOA(data, original_dns_pointer);
            break;
        case 28:                                        // AAAA
            print_ipv6_address(data);
            remove_domain_name_from_file = false;
            break;
        case 33:
            print_SRV(data, original_dns_pointer);      // SRV
            break;
        default:
            printf("unknown");
    }
    
    // removes last line from file, as it is domain name but without trnaslation following
    if(params.translationsfile != NULL && remove_domain_name_from_file){
        FILE *fp_translations_file = fopen(params.translationsfile, "a+");
        if (fp_translations_file == NULL){
            fprintf(stderr, "Error oppening file\n");
            return;
        }
        remove_last_line(fp_translations_file);
        fclose(fp_translations_file);
    }
    if(params.verbose){
        printf("\n");
    }
}

void print_CLASS_and_TYPE(uint16_t qclass, uint16_t qtype){
    switch (qclass){
    case 1:
        printf(" IN ");
        break;    
    default:
        printf(" IN ");
        break;
    }

    switch (qtype){
    case 1:
        printf("A");
        break;
    case 2:
        printf("NS");
        break;
    case 5:
        printf("CNAME");
        break;
    case 15:
        printf("MX");
        break;
    case 6:
        printf("SOA");
        break;
    case 28:
        printf("AAAA");
        break;
    case 33:
        printf("SRV");
        break;
    default:
        printf("unknown");
    }
}
