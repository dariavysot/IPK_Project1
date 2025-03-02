#ifndef IPK_L4_SCANNER
#define IPK_L4_SCANNER

#include <vector>
#include <string>

// Структура конфігурації (використовується у main і tcp_scanner)
struct ScanConfig {
    std::string interface;
    std::vector<int> tcp_ports;
    std::vector<int> udp_ports;
    int timeout = 5000;
    std::string target;
};

// Функція для запуску TCP-сканування
void scanTcpPorts(const ScanConfig &config);

#endif
