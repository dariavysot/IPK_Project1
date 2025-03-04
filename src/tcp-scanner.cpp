#include "ipk-l4-scan.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h> 
#include <arpa/inet.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/if_ether.h>  // ether_header та ETHERTYPE_IP
#include <netinet/in.h>
#include <chrono>
#include <sys/time.h>
#include <sys/select.h>

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

void sendSynPacket(int sock, const ScanConfig &config, const std::string &resolvedIP, bool use_ipv6, int port) {
    if (use_ipv6) {
        struct sockaddr_in6 target6{};
        target6.sin6_family = AF_INET6;
        target6.sin6_port = htons(port);
        inet_pton(AF_INET6, resolvedIP.c_str(), &target6.sin6_addr);

        char packet[sizeof(struct ip6_hdr) + sizeof(struct tcphdr)];
        memset(packet, 0, sizeof(packet));

        struct ip6_hdr *ip6h = (struct ip6_hdr *)packet;
        struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ip6_hdr));

        ip6h->ip6_flow = 0;
        ip6h->ip6_vfc = 6 << 4;
        ip6h->ip6_plen = htons(sizeof(struct tcphdr));
        ip6h->ip6_nxt = IPPROTO_TCP;
        ip6h->ip6_hlim = 64;
        inet_pton(AF_INET6, "::1", &ip6h->ip6_src); // Використовуємо loopback для тесту
        inet_pton(AF_INET6, resolvedIP.c_str(), &ip6h->ip6_dst);

        tcph->th_dport = htons(port);
        tcph->th_flags = TH_SYN;
        tcph->th_off = 5;
        tcph->th_sum = 0;

        if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&target6, sizeof(target6)) < 0) {
            perror("Error sending SYN packet (IPv6)");
        } else {
            std::cout << "Sent SYN to port " << port << " on target " << resolvedIP << " (IPv6)" << std::endl;
        }
    } else {
        struct sockaddr_in target{};
        target.sin_family = AF_INET;
        target.sin_port = htons(port);
        inet_pton(AF_INET, resolvedIP.c_str(), &target.sin_addr);

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
        iph->ip_sum = checksum((unsigned short *)iph, sizeof(struct ip));

        tcph->th_dport = htons(port);
        tcph->th_flags = TH_SYN;
        tcph->th_off = 5;
        tcph->th_sum = 0;

        if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&target, sizeof(target)) < 0) {
            perror("Error sending SYN packet (IPv4)");
        } else {
            std::cout << "Sent SYN to port " << port << " on target " << resolvedIP << " (IPv4)" << std::endl;
        }
    }
}

std::string receiveResponse(const ScanConfig &config, int /*target_port*/) { 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(config.interface.c_str(), BUFSIZ, 1, config.timeout, errbuf);
    if (handle == NULL) {
        std::cerr << "Error opening pcap device: " << errbuf << std::endl;
        return "error";
    }

    struct pcap_pkthdr *header;
    const u_char *packet;
    int res;

    //auto start_time = std::chrono::high_resolution_clock::now();

    int pcap_fd = pcap_get_selectable_fd(handle);
    fd_set fds;
    struct timeval timeout;
    timeout.tv_sec = config.timeout / 1000;
    timeout.tv_usec = (config.timeout % 1000) * 1000;

    FD_ZERO(&fds);
    FD_SET(pcap_fd, &fds);

    while (true) {
        int ret = select(pcap_fd + 1, &fds, NULL, NULL, &timeout);

        if (ret == 0) { 
            //std::cout << "Timeout reached for port " << target_port << " (" << config.timeout << " ms)\n";
            pcap_close(handle);
            return "filtered";
        }
        if (ret == -1) {  
            perror("select() error");
            pcap_close(handle);
            return "error";
        }

        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue; 
        if (res == -1 || res == -2) break;

        struct ether_header *eth_header = (struct ether_header *)packet;
        if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
            struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
            if (ip_header->ip_p == IPPROTO_TCP) {
                struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4));

                if ((tcp_header->th_flags & TH_ACK) && !(tcp_header->th_flags & TH_SYN) && !(tcp_header->th_flags & TH_RST)) {
                    continue;
                }

                //auto end_time = std::chrono::high_resolution_clock::now();
                //double response_time = std::chrono::duration<double, std::milli>(end_time - start_time).count();

                if ((tcp_header->th_flags & TH_SYN)) {
                    pcap_close(handle);
                    //std::cout << "          Response time for port " << target_port << ": " << response_time << " ms\n";
                    return "open";
                }

                if (tcp_header->th_flags & TH_RST) {
                    pcap_close(handle);
                    //std::cout << "              Response time for port " << target_port << ": " << response_time << " ms\n";
                    return "closed";
                }
            }
        }
    }

    pcap_close(handle);
    return "filtered";  // If there is no response
}

void scanTcpPorts(const ScanConfig &config, const std::string &resolvedIP, bool use_ipv6) {
    int sock = socket(use_ipv6 ? AF_INET6 : AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Error creating raw socket");
        return;
    }

    std::cout << "PORT STATE\n";

    for (int port : config.tcp_ports) {
        sendSynPacket(sock, config, resolvedIP, use_ipv6, port);
        std::string result = receiveResponse(config, port);
        std::cout << port << "/tcp " << result << std::endl;
        usleep(config.timeout * 1000);
    }

    close(sock);
}