#include "ipk-l4-scan.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>

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
    inet_pton(AF_INET, "0.0.0.0", &iph->ip_src);
    iph->ip_dst = target.sin_addr;
    iph->ip_sum = checksum((unsigned short *)packet, sizeof(struct ip));

    tcph->th_sport = htons(12345);
    tcph->th_dport = htons(port);
    tcph->th_flags = TH_SYN;
    tcph->th_sum = checksum((unsigned short *)tcph, sizeof(struct tcphdr));

    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&target, sizeof(target)) < 0) {
        perror("Error sending SYN packet");
    } else {
        std::cout << "Sent SYN to port " << port << std::endl;
    }
}

std::string receiveResponse(int sock, const ScanConfig &config) {
    char buffer[1024];
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    struct timeval timeout;
    timeout.tv_sec = config.timeout / 1000;
    timeout.tv_usec = (config.timeout % 1000) * 1000;

    int retval = select(sock + 1, &readfds, NULL, NULL, &timeout);
    if (retval == -1) {
        perror("Error in select()");
        return "error";
    } else if (retval == 0) {
        return "filtered"; 
    }

    int recv_bytes = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender, &sender_len);
    if (recv_bytes < 0) {
        perror("Error receiving packet");
        return "error";
    }

    struct ip *iph = (struct ip *)buffer;
    struct tcphdr *tcph = (struct tcphdr *)(buffer + iph->ip_hl * 4);

    std::cout << "Received packet from " << inet_ntoa(sender.sin_addr) << std::endl;
    std::cout << "TCP Flags: " << (int)tcph->th_flags << std::endl;

    if (ntohs(tcph->th_dport) == 12345) { 
        if (tcph->th_flags & TH_SYN && tcph->th_flags & TH_ACK) {
            return "open";
        } else if (tcph->th_flags & TH_RST) {
            return "closed"; 
        }
    }
    return "filtered"; 
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
        std::string result = receiveResponse(sock, config);
        std::cout << port << "/tcp " << result << std::endl;
        usleep(config.timeout * 1000);
    }

    close(sock);
}