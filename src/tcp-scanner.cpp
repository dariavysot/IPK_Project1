#include "ipk-l4-scan.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h> 
#include <arpa/inet.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/if_ether.h>  // ether_header та ETHERTYPE_IP
#include <netinet/in.h>

//#include <cstdlib>

struct pseudo_header {
    u_int32_t src;
    u_int32_t dst;
    u_int8_t reserved;
    u_int8_t protocol;
    u_int16_t length;
};

unsigned short checksum(void *b, int len) {
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    for (sum = 0; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void sendSynPacket(int sock, const ScanConfig &config, int port) {
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, config.target.c_str(), &target.sin_addr);

    char packet[sizeof(struct ip) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    struct ip *iph = (struct ip *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ip));

    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_ttl = 64;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_src.s_addr = inet_addr(config.target.c_str());
    iph->ip_dst = target.sin_addr;
    iph->ip_sum = 0;
    iph->ip_sum = checksum((unsigned short *)iph, sizeof(struct ip));

    //srand(time(NULL)); 
    //int source_port = 1024 + (rand() % 64511); 

    //tcph->th_sport = htons(source_port);
    tcph->th_dport = htons(port);
    tcph->th_flags = TH_SYN;
    tcph->th_off = 5;
    tcph->th_sum = 0;

    struct pseudo_header psh;
    psh.src = iph->ip_src.s_addr;
    psh.dst = iph->ip_dst.s_addr;
    psh.reserved = 0;
    psh.protocol = IPPROTO_TCP;
    psh.length = htons(sizeof(struct tcphdr));

    char pseudo_packet[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
    memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
    memcpy(pseudo_packet + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

    tcph->th_sum = checksum((unsigned short *)pseudo_packet, sizeof(pseudo_packet));

    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&target, sizeof(target)) < 0) {
        perror("Error sending SYN packet");
    } else {
        std::cout << "Sent SYN to port " << port << " from " << config.target << std::endl;
                 // << " with source port " << source_port 
    }
}

std::string receiveResponse(const ScanConfig &config, int /*target_port*/) { 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(config.interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        std::cerr << "Error opening pcap device: " << errbuf << std::endl;
        return "error";
    }

    struct pcap_pkthdr header;
    const u_char *packet;

    while ((packet = pcap_next(handle, &header)) != NULL) {
        struct ether_header *eth_header = (struct ether_header *)packet;
        if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
            struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
            if (ip_header->ip_p == IPPROTO_TCP) {
                struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4));

                // Make sure it's not just an ACK
                if ((tcp_header->th_flags & TH_ACK) && !(tcp_header->th_flags & TH_SYN) && !(tcp_header->th_flags & TH_RST)) {
                    continue;  // Skip clean ACKs
                }

                // If SYN-ACK → port is open
                if ((tcp_header->th_flags & TH_SYN)) {
                    return "open";
                }

                // If RST → port is closed
                if (tcp_header->th_flags & TH_RST) {
                    return "closed";
                }

                if (ip_header->ip_p == IPPROTO_ICMP) {
                    struct icmp *icmp_header = (struct icmp *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4));
                    
                    if (icmp_header->icmp_type == 3 && icmp_header->icmp_code == 3) {
                        return "filtered"; // ICMP Destination Unreachable (Port Unreachable) 3
                    }
                }
            }
        }
    }

    pcap_close(handle);
    return "filtered";  // If there is no response
}

void scanTcpPorts(const ScanConfig &config) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Error creating raw socket");
        return;
    }

    std::cout << "PORT STATE\n";

    for (int port : config.tcp_ports) {
        sendSynPacket(sock, config, port);
        std::string result = receiveResponse(config, port);
        std::cout << port << "/tcp " << result << std::endl;
        usleep(config.timeout * 1000);
    }

    close(sock);
}