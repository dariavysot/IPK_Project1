#ifndef IPK_L4_SCANNER
#define IPK_L4_SCANNER

#include <vector>
#include <string>

struct ScanConfig {
    std::string interface;
    std::vector<int> tcp_ports;
    std::vector<int> udp_ports;
    int timeout = 5000;
    std::string target;
};

std::vector<int> parsePortRanges(const std::string& ports);
void scanTcpPorts(const ScanConfig &config, const std::string &resolvedIP, bool use_ipv6);

#endif
