// Example of cross-platform IP address handling
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <string>
#include <iostream>

class NetworkUtils {
public:
    static bool initializeNetworking() {
#ifdef WIN32
        WSADATA wsaData;
        int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
        return (result == 0);
#else
        return true; // No initialization needed on Unix
#endif
    }

    static void cleanupNetworking() {
#ifdef WIN32
        WSACleanup();
#endif
    }

    // Modern approach using inet_ntop (recommended)
    static std::string ipToString(const struct in_addr& addr) {
        char buffer[INET_ADDRSTRLEN];
#ifdef WIN32
        // inet_ntop is available on Windows Vista/Server 2008 and later
        if (inet_ntop(AF_INET, &addr, buffer, INET_ADDRSTRLEN) != nullptr) {
            return std::string(buffer);
        }
#else
        if (inet_ntop(AF_INET, &addr, buffer, INET_ADDRSTRLEN) != nullptr) {
            return std::string(buffer);
        }
#endif
        return "0.0.0.0";
    }

    // Legacy approach using inet_ntoa (deprecated but still works)
    static std::string ipToStringLegacy(const struct in_addr& addr) {
#ifdef WIN32
        // inet_ntoa is thread-unsafe and deprecated
        char* result = inet_ntoa(addr);
        return std::string(result ? result : "0.0.0.0");
#else
        char* result = inet_ntoa(addr);
        return std::string(result ? result : "0.0.0.0");
#endif
    }

    // IPv6 support
    static std::string ipv6ToString(const struct in6_addr& addr) {
        char buffer[INET6_ADDRSTRLEN];
#ifdef WIN32
        if (inet_ntop(AF_INET6, &addr, buffer, INET6_ADDRSTRLEN) != nullptr) {
            return std::string(buffer);
        }
#else
        if (inet_ntop(AF_INET6, &addr, buffer, INET6_ADDRSTRLEN) != nullptr) {
            return std::string(buffer);
        }
#endif
        return "::";
    }
};

// Example usage
int main() {
    if (!NetworkUtils::initializeNetworking()) {
        std::cerr << "Failed to initialize networking" << std::endl;
        return 1;
    }

    // Example IP address
    struct in_addr addr;
#ifdef WIN32
    inet_pton(AF_INET, "192.168.1.1", &addr);
#else
    inet_aton("192.168.1.1", &addr);
#endif

    // Modern way (recommended)
    std::string ip_modern = NetworkUtils::ipToString(addr);
    std::cout << "Modern way: " << ip_modern << std::endl;

    // Legacy way (for compatibility)
    std::string ip_legacy = NetworkUtils::ipToStringLegacy(addr);
    std::cout << "Legacy way: " << ip_legacy << std::endl;

    NetworkUtils::cleanupNetworking();
    return 0;
}