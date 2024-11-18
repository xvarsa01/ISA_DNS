/*
 * Author: Varsányi Adam
 * Login: xvarsa01
 * Date: 18.11.2024
 * Description: Main project structure with main function and all pcap functions.
 */

#include "dns_monitor.h"

global_params params = {false, NULL, NULL, NULL};

/*
    Function processes and prints the DNS Question section of the message. The function returns the updated pointer to the data after 
    DNS question section.
*/
const u_char * print_DNS_question(const u_char *data,  const u_char *original_dns_pointer){
    data += print_domain_name_setup(data, original_dns_pointer, false);

    if(params.verbose){
        uint16_t qtype = ntohs(*((uint16_t*)data));
        uint16_t qclass = ntohs(*((uint16_t*)(data + 2)));
        print_CLASS_and_TYPE(qclass, qtype);
        printf("\n\n");
    }
    data+=4;
    return data;
}

/*
    Function processes and prints the DNS Answer / Authority / Additional section of the message. The function returns the updated
    pointer to the data after this section.
*/
const u_char * print_DNS_answer(const u_char *data, const u_char *original_dns_pointer, int count){
    for (int i = 0; i < count; i++) {
        
        data += print_domain_name_setup(data, original_dns_pointer, true);

        uint16_t qtype = ntohs(*((uint16_t*)(data + 0)));
        uint16_t qclass = ntohs(*((uint16_t*)(data + 2)));
        uint32_t ttl = ntohl(*((uint32_t*)(data + 4)));
        uint16_t rd_length = ntohs(*((uint16_t*)(data + 8)));
        data+=10;
        
        if (params.verbose){
            printf(" %d", ttl);
            print_CLASS_and_TYPE(qclass, qtype);
            printf(" ");
        }
        print_q_type(data, qtype, original_dns_pointer);
        data += rd_length;
    }
    if (params.verbose){
        printf("\n");
    }
    return data;
}

/*
    Function processes and prints the entire DNS message, including the header and all sections: 
    Question, Answer, Authority, and Additional.
*/
void print_DNS_data(const u_char *data, int len) {
    (void) len;

    const u_char *original_dns_pointer = data;

    struct dns_header
    {
        uint16_t id;
        uint16_t flags;
        uint16_t qdcount;
        uint16_t ancount;
        uint16_t nscount;
        uint16_t arcount;
    } header;
    
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

    if (params.verbose){
        printf("Identifier: 0x%04X\n", header.id);
        printf("Flags: QR=%d, OPCODE=%d, AA=%d, TC=%d, RD=%d, RA=%d, AD=%d, CD=%d, RCODE=%d\n\n", flag_QR, flag_OPCODE, flag_AA, flag_TC, flag_RD, flag_RA, flag_AD, flag_CD, flag_RCODE);        
    }
    else{
        printf("(%s %d/%d/%d/%d)\n", flag_QR ? "R" : "Q", header.qdcount, header.ancount, header.nscount, header.arcount);
    }
    
    if (header.qdcount != 0){
        if (params.verbose){
            printf("[Question Section]\n");
        }
        data = print_DNS_question(data, original_dns_pointer);
    }        
    if (header.ancount != 0){
        if (params.verbose){
            printf("[Answer Section]\n");
        }
        data = print_DNS_answer(data, original_dns_pointer, header.ancount);
    }
    if (header.nscount != 0){
        if (params.verbose){
            printf("[Authority Section]\n");
        }
        data = print_DNS_answer(data, original_dns_pointer, header.nscount);
    }
    if (header.arcount != 0){
        if (params.verbose){
            printf("[Additional  Section]\n");
        }        
        data = print_DNS_answer(data, original_dns_pointer, header.arcount);
    }
}

/*
    Function creates a packet capture handle using the specified network device and filter expression.
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
    Callback function that is used for printing ipv4 / ipv6 metadata..
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


        if (params.verbose) {
            printf("SrcIP: %s\n", src_ip);
            printf("DstIP: %s\n", dst_ip);
        }
        else {
            printf("%s -> %s ", src_ip, dst_ip);
        }

        // Check if the transport protocol is TCP or UDP
        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr*)(packetptr + offset);
            if (params.verbose) {
                printf("SrcPort: TCP/%d\n", ntohs(tcp_header->th_sport));
                printf("DstPort: TCP/%d\n", ntohs(tcp_header->th_dport));
            }
            offset += tcp_header->th_off * 4;
        }
        else if (ip_header->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr*)(packetptr + offset);
            if (params.verbose) {
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

        if (params.verbose) {
            printf("Src IP: %s\n", src_ip);
            printf("Dst IP: %s\n", dst_ip);
        } else {
            printf("%s -> %s ", src_ip, dst_ip);
        }

        // Check if the transport protocol is TCP or UDP
        if (ip6_header->ip6_nxt == IPPROTO_TCP) {
            struct tcphdr *tcp6_header = (struct tcphdr*)(packetptr + offset);
            if (params.verbose) {
                printf("Src port: TCP/%d\n", ntohs(tcp6_header->th_sport));
                printf("Dst port: TCP/%d\n", ntohs(tcp6_header->th_dport));
            }
            offset += tcp6_header->th_off * 4;
        }
        else if (ip6_header->ip6_nxt == IPPROTO_UDP) {
            struct udphdr *udp6_header = (struct udphdr*)(packetptr + offset);
            if (params.verbose) {
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

    process_args(argc, argv, &interface, &params.pcapfile, &params.domainsfile, &params.translationsfile, &params.verbose);

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