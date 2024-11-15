#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#define __USE_MISC 1
#include <pcap.h>

#include <netinet/in.h>
#include <netinet/ether.h>   // for struct ether_header
#include <netinet/ip.h>      // for struct ip
#include <netinet/ip6.h>
#include <netinet/tcp.h>     // for struct tcphdr
#include <netinet/udp.h>     // for struct udphdr

// super hack to check if optional arg is present, reference: https://cfengine.com/blog/2021/optional-arguments-with-getopt-long/
#define OPTIONAL_ARGUMENT_IS_PRESENT \
    ((optarg == NULL && optind < argc && argv[optind][0] != '-') \
     ? (bool) (optarg = argv[optind++]) \
     : (optarg != NULL))

struct dns_header
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};


bool verbose = false;
char *pcapfile = NULL;
char *domainsfile = NULL;
char *translationsfile = NULL;

void print_interfaces() {
    pcap_if_t *interfaces;  // Pointer to the list of network interfaces
    char errbuf[PCAP_ERRBUF_SIZE];  // Error buffer

    // Find all available network interfaces
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return;
    }

    // Print table header
    printf("%-25s %-50s %-10s\n", "interface", "description", "flags");

    // Iterate through the list of interfaces and print them
    pcap_if_t *iface;
    for (iface = interfaces; iface != NULL; iface = iface->next) {
        printf("%-25s %-50s %-10d\n", iface->name, (iface->description ? iface->description : "N/A"), iface->flags);
    }

    pcap_freealldevs(interfaces);
}


void process_args(int argc, char *argv[], char **interface, char **pcapfile, char **domainsfile, char** translationsfile, bool *verbose) {
    int opt;
    while ((opt = getopt(argc, argv, "vi::p:d:t:")) != -1) {
        switch (opt) {
        case 'v':
            *verbose = true;
            break;
        case 'i':
            if (OPTIONAL_ARGUMENT_IS_PRESENT){
                *interface = optarg;
                break;
            }
            fprintf(stderr, "Interface not specified.\n");
            print_interfaces();
            exit(1);
            
        case 'p':
            if (OPTIONAL_ARGUMENT_IS_PRESENT){
                *pcapfile = optarg;
                break;
            }
            fprintf(stderr, "Pcapfile not specified.\n");
            exit(1);

        case 'd':
            if (OPTIONAL_ARGUMENT_IS_PRESENT){
                *domainsfile = optarg;
                break;
            }
            fprintf(stderr, "Domainsfile not specified.\n");
            exit(1);

            break;
        case 't':
            if (OPTIONAL_ARGUMENT_IS_PRESENT){
                *translationsfile = optarg;
                break;
            }
            fprintf(stderr, "Translationsfile not specified.\n");
            exit(1);

        default:
            fprintf(stderr, "Unexpected option %c\n", opt);
            exit (1);
        }
    }

    if (*interface == NULL && *pcapfile == NULL){
        fprintf(stderr, "Interface or pcapfile must be specified\n");
        exit(1);
    }

    if (*interface != NULL && *pcapfile != NULL){
        fprintf(stderr, "Can not use Interface AND pcapfile together\n");
        exit(1);
    }
    
}

/*
    function that prints timestamp
*/
void print_timestamp(){
    time_t now;
    time(&now);
    
    // Convert to local time format
    struct tm *local = localtime(&now);
    
    // Create a buffer to hold the formatted time
    char timestamp[20];
    
    // Format the time as YYYY-MM-DD HH:MM:SS
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", local);

    if (verbose){
        printf("Timestamp: %s\n", timestamp);
    }
    else{
        printf("%s ", timestamp);
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

void remove_duplicate_last_line(FILE *fp) {
    char last_line[1024] = {0};
    char current_line[1024] = {0};
    long last_line_position = 0;
    long position_before_read = 0;

    // Move to the beginning of the file for reading
    fseek(fp, 0, SEEK_SET);

    // Find the position and content of the last line
    while (fgets(current_line, sizeof(current_line), fp) != NULL) {
        position_before_read = last_line_position;  // Position before reading new line
        last_line_position = ftell(fp);  // Position after reading
        strncpy(last_line, current_line, sizeof(last_line) - 1);
        last_line[sizeof(last_line) - 1] = '\0'; // Ensure null termination
    }

    // Check for duplicates by rewinding and comparing lines
    rewind(fp);
    bool is_duplicate = false;
    while (ftell(fp) < position_before_read && fgets(current_line, sizeof(current_line), fp) != NULL) {
        if (strcmp(current_line, last_line) == 0) {
            is_duplicate = 1;
            break;
        }
    }

    if (is_duplicate) {
        if (ftruncate(fileno(fp), position_before_read) != 0) {
            fprintf(stderr, "Error removing duplicate line from file\n");
        }
    }
}

int print_domain_name(const u_char *data, const u_char *original_dns_pointer, int number_of_recursions, int data_printed_size, FILE *fp){
    if ((*data & 0xC0) == 0xC0){
        uint16_t pointer_offset = 0;
        pointer_offset = ((*data & 0x3F) << 8) | *(data + 1);
        number_of_recursions++;
        return print_domain_name(original_dns_pointer+pointer_offset, original_dns_pointer, number_of_recursions, data_printed_size, fp);
    }
    else{
        uint8_t name_length = *data;
        if (name_length != 0){
            data ++;
            if (number_of_recursions == 0){
                data_printed_size++;
            }

            for (size_t i = 0; i < name_length; i++) {
                if(verbose){
                    printf("%c", *data);
                }
                if (fp != NULL){
                    fprintf(fp, "%c", *data);
                }
                
                data ++;
                if (number_of_recursions == 0){
                    data_printed_size++;
                }
            }
            if (verbose){
                printf(".");
            }
            if (fp != NULL){
                fprintf(fp, ".");
            }
            return print_domain_name(data, original_dns_pointer, number_of_recursions, data_printed_size, fp);
        }
        if (number_of_recursions == 0){
            data_printed_size++;
        }
    }

    if (fp != NULL){
        fprintf(fp, "\n");
    }
    return data_printed_size + 2*number_of_recursions;
}

int print_domain_name_setup(const u_char *data, const u_char *original_dns_pointer){
    FILE *fp = NULL;
    if (domainsfile != NULL){
        fp = fopen(domainsfile, "a+");
        if (fp == NULL){
            fprintf(stderr, "Error oppening file\n");
            return -1;
        }
    }
    
    int return_value =  print_domain_name(data, original_dns_pointer, 0, 0, fp);

    if (fp != NULL){
        fflush(fp); // Ensure all written data is saved before checking duplicates
        remove_duplicate_last_line(fp);
        fclose(fp);
    }
    return return_value;
}

void print_ipv6_address(const u_char *data){
    for (int i = 0; i < 8; i++) {
        // Read 2 bytes, treat them as a 16-bit integer in network byte order
        uint16_t segment = ntohs(*((uint16_t *)(data + i * 2)));

        // Print the segment in hexadecimal
        printf("%x", segment);

        // Print a colon after each segment except the last one
        if (i < 7) {
            printf(":");
        }
    }
}

const u_char * print_SOA(const u_char *data, const u_char *original_dns_pointer){
    data += print_domain_name_setup(data, original_dns_pointer);        // nameserver
    printf(" ");
    data += print_domain_name_setup(data, original_dns_pointer);        // enail

    uint32_t serial = ntohl(*((uint32_t*)data));
    data += 4;
    uint32_t refresh_interval = ntohl(*((uint32_t*)data));
    data += 4;
    uint32_t retry_interval = ntohl(*((uint32_t*)data));
    data += 4;
    uint32_t expire_limit = ntohl(*((uint32_t*)data));
    data += 4;
    uint32_t minimum_ttl = ntohl(*((uint32_t*)data));
    data += 4;

    printf(" %u %u %u %u %u", serial, refresh_interval, retry_interval, expire_limit, minimum_ttl);
    return data;
}

const u_char * print_DNS_question(const u_char *data,  const u_char *original_dns_pointer){
    
    data += print_domain_name_setup(data, original_dns_pointer);

    if(verbose){
        uint16_t qtype = ntohs(*((uint16_t*)data));
        uint16_t qclass = ntohs(*((uint16_t*)(data + 2)));
        print_CLASS_and_TYPE(qclass, qtype);
        printf("\n\n");
    }
    data+=4;
    return data;
}

const u_char * print_DNS_answer(const u_char *data, const u_char *original_dns_pointer, int count){
    for (int i = 0; i < count; i++) {
        
        data += print_domain_name_setup(data, original_dns_pointer);

        uint16_t qtype = ntohs(*((uint16_t*)(data + 0)));
        uint16_t qclass = ntohs(*((uint16_t*)(data + 2)));
        uint32_t ttl = ntohs(*((uint16_t*)(data + 4)));
        uint16_t rd_length = ntohs(*((uint16_t*)(data + 8)));
        data+=10;
        
        if (verbose){
            printf(" %d", ttl);
            print_CLASS_and_TYPE(qclass, qtype);
            printf(" ");
            switch (qtype){
                case 1:                            //A
                    printf("%d.%d.%d.%d", data[0], data[1], data[2], data[3]);
                    break;
                case 2:                             // NS
                    print_domain_name_setup(data, original_dns_pointer);
                    break;
                case 5:                             // CNAME
                    print_domain_name_setup(data, original_dns_pointer);
                    break;
                case 15:
                    printf("MX");
                    break;
                case 6:
                    print_SOA(data, original_dns_pointer);
                    break;
                case 28:                            //AAAA
                    print_ipv6_address(data);
                    break;
                case 33:
                    printf("SRV");
                    break;
                default:
                    printf("unknown");
            }
            printf("\n");
        }
        data += rd_length;

        // printf("\nnext data:");
        // const u_char *data2 = data;
        // for (size_t i = 0; i < 5; i++){
        //     printf("  0x%02X", *data2);
        //     data2++;
        // }
    }
    if (verbose){
        printf("\n");
    }
    return data;
}

void print_DNS_data(const u_char *data, int len) {
    (void) len;
    // int line_length = 16;
    // int current_char = 0;
    // while (current_char < len) {
    //     if (len - current_char < 16) {
    //         line_length = len - current_char;
    //     }
    //     print_line(data, line_length, current_char);
    //     current_char += 16;
    // }
    // printf("end of old print \n");

    const u_char *original_dns_pointer = data;

    struct dns_header header;

    header.id = ntohs(*((uint16_t*)(data + 0)));
    header.flags = ntohs(*((uint16_t*)(data+2)));
    header.qdcount = ntohs(*((uint16_t*)(data + 4)));
    header.ancount = ntohs(*((uint16_t*)(data + 6)));
    header.nscount = ntohs(*((uint16_t*)(data + 8)));
    header.arcount = ntohs(*((uint16_t*)(data + 10)));

    bool flag_QR = header.flags & 0x8000;
    uint16_t flag_OPCODE = header.flags & 0x7800;
    bool flag_AA = header.flags & 0x0400;
    bool flag_TC = header.flags & 0x0200;
    bool flag_RD = header.flags & 0x0100;
    
    bool flag_RA = header.flags & 0x0800;
    // bool flag_Z = header.flags & 0x0040;
    bool flag_AD = header.flags & 0x0020;
    bool flag_CD = header.flags & 0x0010;
    uint16_t flag_RCODE = header.flags & 0x000F;

    data+=12;

    if (verbose){
        printf("Identifier: 0x%04X\n", header.id);
        printf("Flags: QR=%d, OPCODE=%d, AA=%d, TC=%d, RD=%d, RA=%d, AD=%d, CD=%d, RCODE=%d\n\n", flag_QR, flag_OPCODE, flag_AA, flag_TC, flag_RD, flag_RA, flag_AD, flag_CD, flag_RCODE);        
    }
    else{
        printf("(%s %d/%d/%d/%d)\n", flag_QR ? "R" : "Q", header.qdcount, header.ancount, header.nscount, header.arcount);
    }
    
    if (header.qdcount != 0){
        if (verbose){
            printf("[Question Section]\n");
        }
        data = print_DNS_question(data, original_dns_pointer);
    }        
    if (header.ancount != 0){
        if (verbose){
            printf("[Answer Section]\n");
        }
        data = print_DNS_answer(data, original_dns_pointer, header.ancount);
    }
    if (header.nscount != 0){
        if (verbose){
            printf("[Authority Section]\n");
        }
        data = print_DNS_answer(data, original_dns_pointer, header.nscount);
    }
    if (header.arcount != 0){
        if (verbose){
            printf("[Additional  Section]\n");
        }        
        data = print_DNS_answer(data, original_dns_pointer, header.arcount);
    }
}

/*
    function creates a packet capture handle using the specified network device and filter expression.
*/
pcap_t* create_pcap_handle(char* device, char* filter){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    struct bpf_program bpf;
    bpf_u_int32 netmask;
    bpf_u_int32 srcip;


    // Get network device source IP address and netmask.
    if (pcap_lookupnet(device, &srcip, &netmask, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
        return NULL;
    }

    // Open the device for live capture.
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        return NULL;
    }

    // Convert the packet filter epxression into a packet filter binary.
    if (pcap_compile(handle, &bpf, filter, 0, netmask) == PCAP_ERROR) {
        fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
        return NULL;
    }

    // Bind the packet filter to the libpcap handle.
    if (pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(handle));
        return NULL;
    }

    return handle;
}

/*
    callback function that is used for printing ipv4 / ipv6 metadata..
*/
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packetptr) {
    (void)args;

    struct ether_header *eth_header = (struct ether_header *) packetptr;

    print_timestamp();
    
    int offset = sizeof(struct ether_header);

    // IPv4 packet
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip*)(packetptr + offset);
        offset += ip_header->ip_hl * 4;

        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);


        if (verbose) {
            printf("SrcIP: %s\n", src_ip);
            printf("DstIP: %s\n", dst_ip);
        }
        else {
            printf("%s -> %s ", src_ip, dst_ip);
        }

        // Check if the transport protocol is TCP or UDP
        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr*)(packetptr + offset);
            if (verbose) {
                printf("SrcPort: TCP/%d\n", ntohs(tcp_header->th_sport));
                printf("DstPort: TCP/%d\n", ntohs(tcp_header->th_dport));
            }
            offset += tcp_header->th_off * 4;
        }
        else if (ip_header->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr*)(packetptr + offset);
            if (verbose) {
                printf("SrcPort: UDP/%d\n", ntohs(udp_header->uh_sport));
                printf("DstPort: UDP/%d\n", ntohs(udp_header->uh_dport));
            }
            offset += sizeof(struct udphdr);
        }
        else {
            fprintf(stderr, "Unsupported protocol in IPv4\n");
            return;
        }
    }

    // IPv6 packet
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
        struct ip6_hdr *ip6_header = (struct ip6_hdr*)(packetptr + sizeof(struct ether_header));
        offset += sizeof(struct ip6_hdr);

        char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip, INET6_ADDRSTRLEN);

        if (verbose) {
            printf("Src IP: %s\n", src_ip);
            printf("Dst IP: %s\n", dst_ip);
        } else {
            printf("%s -> %s ", src_ip, dst_ip);
        }

        // Check if the transport protocol is TCP or UDP
        if (ip6_header->ip6_nxt == IPPROTO_TCP) {
            struct tcphdr *tcp6_header = (struct tcphdr*)(packetptr + offset);
            if (verbose) {
                printf("Src port: TCP/%d\n", ntohs(tcp6_header->th_sport));
                printf("Dst port: TCP/%d\n", ntohs(tcp6_header->th_dport));
            }
            offset += tcp6_header->th_off * 4;
        }
        else if (ip6_header->ip6_nxt == IPPROTO_UDP) {
            struct udphdr *udp6_header = (struct udphdr*)(packetptr + offset);
            if (verbose) {
                printf("Src port: UDP/%d\n", ntohs(udp6_header->uh_sport));
                printf("Dst port: UDP/%d\n", ntohs(udp6_header->uh_dport));
            }
            offset += sizeof(struct udphdr);
        }
        else {
            fprintf(stderr, "Unsupported protocol in IPv6\n");
            return;
        }
    }
    else {
        fprintf(stderr, "Unsupported Ethernet type\n");
        return;
    }
    
    print_DNS_data(packetptr + offset, header->len - offset);
}

int main(int argc, char *argv[]){

    char *interface = NULL;


    char *filter = "udp port 53";

    process_args(argc, argv, &interface, &pcapfile, &domainsfile, &translationsfile, &verbose);

    // printf("interface: %s\n", interface);
    // printf("pcapfile: %s\n", pcapfile);
    // printf("domainsfile: %s\n", domainsfile);
    // printf("transaltionsfile: %s\n", translationsfile);
    // printf("bool verbose: %d\n", verbose);

    pcap_t* handle;
    handle = create_pcap_handle(interface, filter);
    if (handle == NULL) {
        return -1;
    }

    // main loop will start here
    int count = 0;
    if (pcap_loop(handle, count, packet_handler, (u_char*)NULL) < 0) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }
    pcap_close(handle);

    return 0;
}