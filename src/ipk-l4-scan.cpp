#include <iostream>
#include <getopt.h>
#include <string>
#include <vector>
#include <set>
#include <ifaddrs.h>
#include <net/if.h>
#include "ipk-l4-scan.h"

void printUsage(const char* progName) {
    std::cout << "Usage: " << progName 
              << " [-i interface | --interface interface] "
              << "[--pu port-ranges | --pt port-ranges | -u port-ranges | -t port-ranges] "
              << "{-w timeout} [domain-name | ip-address]" 
              << std::endl;
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
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i::t:u:w:", long_options, nullptr)) != -1) {
        switch (opt) {
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
        listInterfaces();
        return 0;
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
    
    if (!ports_specified) {
        std::cerr << "Error: No ports specified!" << std::endl;
        return 1;
    }
    
    if (argc - optind > 1) {
        std::cerr << "Error: Too many targets specified!" << std::endl;
        return 1;
    }
    
    std::cout << "Scanning target: " << config.target << " on interface: " << config.interface << std::endl;
    std::cout << "TCP Ports: ";
    for (int port : config.tcp_ports) std::cout << port << " ";
    std::cout << "\nUDP Ports: ";
    for (int port : config.udp_ports) std::cout << port << " ";
    std::cout << "\nTimeout: " << config.timeout << "ms" << std::endl;

    if (!config.tcp_ports.empty()) {
        scanTcpPorts(config);
    }

    return 0;
}