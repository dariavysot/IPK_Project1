#include <iostream>
#include <getopt.h>
#include <string>
#include <vector>


// Structure to hold scan configuration settings
struct ScanConfig {
    std::string interface;      // Network interface to use
    std::vector<int> tcp_ports; // List of TCP ports to scan
    std::vector<int> udp_ports; // List of UDP ports to scan (not used in parsing)
    int timeout = 5000;         // Timeout in milliseconds (default: 5000ms)
    std::string target;         // Target domain or IP address
};

// Function to print the usage information for the program
void printUsage(const char* progName) {
    std::cout << "Usage: " << progName 
              << " [-i interface | --interface interface] "
              << "[--pu port-ranges | --pt port-ranges | -u port-ranges | -t port-ranges] "
              << "{-w timeout} [domain-name | ip-address]" 
              << std::endl;
}

// Function to parse a comma-separated list of port numbers into a vector
std::vector<int> parsePortRanges(const std::string& ports) {
    std::vector<int> portList;
    size_t start = 0, end;
    
    // Loop through the string and extract port numbers
    while ((end = ports.find(',', start)) != std::string::npos) {
        portList.push_back(std::stoi(ports.substr(start, end - start))); // Convert substring to integer
        start = end + 1;
    }
    portList.push_back(std::stoi(ports.substr(start))); // Add the last port number

    return portList;
}

int main(int argc, char* argv[]) {
    ScanConfig config; // Configuration structure to store user input

    // Define long options for command-line arguments
    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'}, // Network interface
        {"pt", required_argument, 0, 't'},       // TCP ports
        {"pu", required_argument, 0, 'u'},       // UDP ports
        {"wait", required_argument, 0, 'w'},     // Timeout
        {0, 0, 0, 0}                             // End of options
    };

    int opt;
    // Parse command-line arguments using getopt_long
    while ((opt = getopt_long(argc, argv, "i:t:u:w:", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'i': // Set network interface
                config.interface = optarg;
                break;
            case 't': // Set TCP ports
                config.tcp_ports = parsePortRanges(optarg);
                break;
            case 'u': // Set UDP ports
                config.udp_ports = parsePortRanges(optarg);
                break;
            case 'w': // Set timeout
                config.timeout = std::stoi(optarg);
                break;
            default: // Invalid argument, show usage
                printUsage(argv[0]);
                return 1;
        }
    }
    
    // Ensure a target is specified
    if (optind < argc) {
        config.target = argv[optind]; // Get the target (IP or domain)
    } else {
        std::cerr << "Error: No target specified!" << std::endl;
        printUsage(argv[0]);
        return 1;
    }
    
    // Debug output to show parsed configuration
    std::cout << "Scanning target: " << config.target << " on interface: " << config.interface << std::endl;
    std::cout << "TCP Ports: ";
    for (int port : config.tcp_ports) std::cout << port << " ";
    std::cout << "\nUDP Ports: ";
    for (int port : config.udp_ports) std::cout << port << " "; // Now correctly stores UDP ports
    std::cout << "\nTimeout: " << config.timeout << "ms" << std::endl;
    
    return 0;
}