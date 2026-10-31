// Mrežne kartice: koja vodi do SmartLoggera, a koja na internet (isti pristup kao solar/network.py).
#pragma once

#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "config.hpp"

namespace sm {

class InterfaceError : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct Interface {
    std::string name;  // FriendlyName (npr. "Ethernet", "Wi-Fi")
    std::string ipv4;  // prva adresa koja nije 169.254.x.x (ako postoji)
    int prefix = 0;
    bool is_up = false;
    bool link_local_only = false;
    int speed_mbps = 0;
};

// RAII za Winsock (WSAStartup/WSACleanup)
class NetInit {
public:
    NetInit();
    ~NetInit();
    NetInit(const NetInit&) = delete;
    NetInit& operator=(const NetInit&) = delete;
};

std::vector<Interface> list_interfaces();
json to_json(const Interface& i);
std::optional<std::string> source_ip(const std::string& interface_name);  // nullopt = Windows bira; baca InterfaceError
std::optional<std::string> default_route_interface();
std::optional<std::string> interface_for_host(const std::string& host);
std::optional<bool> reaches(const std::string& interface_name, const std::string& host);
bool in_subnet(const std::string& ip, int prefix, const std::string& host);

}  // namespace sm
