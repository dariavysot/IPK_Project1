#include "ipk-l4-scan.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <chrono>

void sendUdpPacket(int sock, const ScanConfig &config, const std::string &resolvedIP, bool use_ipv6, int port) {
    if (use_ipv6) {
        struct sockaddr_in6 target6{};
        target6.sin6_family = AF_INET6;
        target6.sin6_port = htons(port);
        inet_pton(AF_INET6, resolvedIP.c_str(), &target6.sin6_addr);

        char buffer[10] = "test"; 
        if (sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&target6, sizeof(target6)) < 0) {
            perror("Error sending UDP packet (IPv6)");
        } else {
            std::cout << "Sent UDP to port " << port << " on target " << resolvedIP << " (IPv6)" << std::endl;
        }
    } else {
        struct sockaddr_in target{};
        target.sin_family = AF_INET;
        target.sin_port = htons(port);
        inet_pton(AF_INET, resolvedIP.c_str(), &target.sin_addr);

        char buffer[10] = "test";
        if (sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&target, sizeof(target)) < 0) {
            perror("Error sending UDP packet (IPv4)");
        } else {
            std::cout << "Sent UDP to port " << port << " on target " << resolvedIP << " (IPv4)" << std::endl;
        }
    }
}

// Отримання відповіді через pcap
std::string receiveUdpResponse(const ScanConfig &config, int port, pcap_t *handle) {
    struct pcap_pkthdr header;
    const u_char *packet;

    std::string filter_exp = "icmp";
    struct bpf_program filter;
    if (pcap_compile(handle, &filter, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
        return "error";
    } 
    if (pcap_setfilter(handle, &filter) == -1) {
        std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
        return "error";
    }

    while ((packet = pcap_next(handle, &header)) != NULL) {
        struct ether_header *eth_header = (struct ether_header *)packet;
        if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
            struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
            if (ip_header->ip_p == IPPROTO_ICMP) {
                struct icmp *icmp_header = (struct icmp *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4));

                if (icmp_header->icmp_type == 3 && icmp_header->icmp_code == 3) {
                    std::cout << "ICMP Destination Unreachable received -> Port " << port << " is closed\n";
                    return "closed";
                }
            }
        }
    }

    return "open"; 
}

void scanUdpPorts(const ScanConfig &config, const std::string &resolvedIP, bool use_ipv6) {
    int sock = socket(use_ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("Error creating socket");
        return;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(config.interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        std::cerr << "Error opening pcap device: " << errbuf << std::endl;
        return;
    }

    std::cout << "PORT STATE\n";
    for (int port : config.udp_ports) {
        sendUdpPacket(sock, config, resolvedIP, use_ipv6, port);
        std::string result = receiveUdpResponse(config, port, handle);
        std::cout << port << "/udp " << result << std::endl;
    }

    pcap_close(handle);
    close(sock);
}
