#include <iostream>
#include <getopt.h>
#include <string>
#include <vector>
#include <set>
#include <ifaddrs.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "ipk-l4-scan.h"

void printUsage(const char* progName) {
    std::cout << "Usage: " << progName 
              << " [-i interface | --interface interface] "
              << "[--pu port-ranges | --pt port-ranges | -u port-ranges | -t port-ranges] "
              << "{-w timeout} [domain-name | ip-address]" 
              << std::endl;
    std::cout << "\nOptions:\n"
              << "  -i, --interface <interface>   Specify network interface\n"
              << "  -t, --pt <ports>             Specify TCP ports to scan (e.g., 22,80,443,1000-2000)\n"
              << "  -u, --pu <ports>             Specify UDP ports to scan\n"
              << "  -w <timeout>                 Timeout in milliseconds (default: 5000ms)\n"
              << "  -h, --help                   Show this help message\n"
              << "\nExample:\n"
              << "  " << progName << " -i eth0 -t 22,80,443 192.168.1.1\n";
}

void listInterfaces() {
    struct ifaddrs *ifap, *ifa;
    if (getifaddrs(&ifap) == 0) {
        std::set<std::string> interfaces;
        for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && (ifa->ifa_flags & IFF_UP)) {
                interfaces.insert(ifa->ifa_name);
            }
        }
        std::cout << "Available network interfaces:\n";
        for (const auto& iface : interfaces) {
            std::cout << "  " << iface << std::endl;
        }
        freeifaddrs(ifap);
    } else {
        std::cerr << "Error retrieving network interfaces." << std::endl;
    }
}

bool isIPv6(const std::string &address) {
    struct in6_addr ipv6;
    return inet_pton(AF_INET6, address.c_str(), &ipv6) == 1;
}

bool resolveHostname(const std::string &hostname, std::string &resolvedIP, bool &is_ipv6) {
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname.c_str(), nullptr, &hints, &res) != 0) {
        std::cerr << "Error: Unable to resolve hostname: " << hostname << std::endl;
        return false;
    }

    char ipStr[INET6_ADDRSTRLEN];
    if (res->ai_family == AF_INET) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &(ipv4->sin_addr), ipStr, sizeof(ipStr));
        is_ipv6 = false;
    } else if (res->ai_family == AF_INET6) {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)res->ai_addr;
        inet_ntop(AF_INET6, &(ipv6->sin6_addr), ipStr, sizeof(ipStr));
        is_ipv6 = true;
    }

    resolvedIP = std::string(ipStr);
    freeaddrinfo(res);
    return true;
}

std::vector<int> parsePortRanges(const std::string& ports) {
    std::vector<int> portList;
    size_t start = 0, end;
    while (start < ports.length()) {
        end = ports.find(',', start);
        std::string part = ports.substr(start, end - start);
        size_t dash = part.find('-');
        try {
            if (dash != std::string::npos) { 
                int range_start = std::stoi(part.substr(0, dash));
                int range_end = std::stoi(part.substr(dash + 1));
                if (range_start > range_end || range_start < 1 || range_end > 65535) {
                    throw std::out_of_range("Invalid port range");
                }
                for (int p = range_start; p <= range_end; ++p) {
                    portList.push_back(p);
                }
            } else {
                int port = std::stoi(part);
                if (port < 1 || port > 65535) {
                    throw std::out_of_range("Invalid port number");
                }
                portList.push_back(port);
            }
        } catch (...) {
            std::cerr << "Error: Invalid port input '" << part << "'. Use format: 22,80,1000-2000." << std::endl;
            exit(1);
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return portList;
}

int main(int argc, char* argv[]) {
    ScanConfig config;
    bool ports_specified = false;
    bool interface_provided = false;
    
    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"pt", required_argument, 0, 't'},
        {"pu", required_argument, 0, 'u'},
        {"wait", required_argument, 0, 'w'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i::t:u:w:h", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'h':
                printUsage(argv[0]);
                return 0;
            case 'i':
                interface_provided = true;
                if (optarg == nullptr && optind < argc && argv[optind][0] != '-') {
                    optarg = argv[optind++];
                }

                if (optarg == nullptr) {
                    std::cout << "No interface specified, listing available interfaces." << std::endl;
                    listInterfaces();
                    return 0;
                }

                config.interface = std::string(optarg);
                std::cout << "Interface provided: " << config.interface << std::endl;
                break;
            case 't':
                config.tcp_ports = parsePortRanges(optarg);
                ports_specified = true;
                break;
            case 'u':
                config.udp_ports = parsePortRanges(optarg);
                ports_specified = true;
                break;
            case 'w':
                if (!optarg) {
                    std::cerr << "Error: -w requires a timeout value." << std::endl;
                    return 1;
                }
                try {
                    config.timeout = std::stoi(optarg);
                    if (config.timeout <= 0) {
                        throw std::out_of_range("Timeout must be a positive integer");
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Error: Invalid timeout value '" << optarg << "'. It must be a positive integer." << std::endl;
                    return 1;
                }
                std::cout << "Timeout set to: " << config.timeout << " ms" << std::endl;
                break;
            default:
                printUsage(argv[0]);
                return 1;
        }
    }

    if (argc == 1) {
        std::cerr << "Error: No arguments provided!" << std::endl;
        printUsage(argv[0]);
        return 1;
    }
    
    if (!interface_provided) {
        std::cerr << "Error: No interface specified!" << std::endl;
        return 1;
    }
    
    if (optind < argc) {
        config.target = argv[optind];
    }
    
    if (config.target.empty()) {
        std::cerr << "Error: No target specified!" << std::endl;
        printUsage(argv[0]);
        return 1;
    }

    bool use_ipv6 = false;
    std::string resolvedIP = config.target;

    if (!resolveHostname(config.target, resolvedIP, use_ipv6)) {
        return 1;
    }

    std::cout << "Resolved IP: " << resolvedIP << " (" << (use_ipv6 ? "IPv6" : "IPv4") << ")\n";
    
    if (!ports_specified) {
        std::cerr << "Error: No ports specified!" << std::endl;
        return 1;
    }
    
    if (argc - optind > 1) {
        std::cerr << "Error: Too many targets specified!" << std::endl;
        return 1;
    }
    
    std::cout << "Scanning target: " << resolvedIP << " on interface: " << config.interface << std::endl;
    std::cout << "TCP Ports: ";
    for (int port : config.tcp_ports) std::cout << port << " ";
    std::cout << "\nUDP Ports: ";
    for (int port : config.udp_ports) std::cout << port << " ";
    std::cout << "\nTimeout: " << config.timeout << "ms" << std::endl;

    if (!config.tcp_ports.empty()) {
        scanTcpPorts(config /*use_ipv6*/);
    }

    return 0;
}