#include "net.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <algorithm>

#include "i18n.hpp"
#include "util.hpp"

namespace sm {

NetInit::NetInit() {
    WSADATA data;
    WSAStartup(MAKEWORD(2, 2), &data);
}
NetInit::~NetInit() { WSACleanup(); }

namespace {
std::optional<uint32_t> parse_ipv4(const std::string& s) {
    in_addr a{};
    if (inet_pton(AF_INET, s.c_str(), &a) != 1) return std::nullopt;
    return ntohl(a.s_addr);
}
}  // namespace

bool in_subnet(const std::string& ip, int prefix, const std::string& host) {
    const auto a = parse_ipv4(ip), b = parse_ipv4(host);
    if (!a || !b || prefix <= 0 || prefix > 32) return false;
    const uint32_t mask = prefix == 32 ? 0xFFFFFFFFu : ~((1u << (32 - prefix)) - 1);
    return (*a & mask) == (*b & mask);
}

std::vector<Interface> list_interfaces() {
    ULONG size = 16 * 1024;
    std::vector<uint8_t> buf;
    ULONG rc = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 3 && rc == ERROR_BUFFER_OVERFLOW; ++attempt) {
        buf.resize(size);
        rc = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                  nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()), &size);
    }
    std::vector<Interface> out;
    if (rc != NO_ERROR) return out;
    for (auto* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()); a; a = a->Next) {
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK || a->IfType == IF_TYPE_TUNNEL) continue;
        Interface i;
        i.name = narrow(a->FriendlyName);
        i.is_up = a->OperStatus == IfOperStatusUp;
        i.speed_mbps = static_cast<int>(std::min<ULONG64>(a->TransmitLinkSpeed / 1'000'000, 1'000'000));
        std::string link_local;
        int link_prefix = 0;
        for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
            char text[INET_ADDRSTRLEN] = {};
            auto* sin = reinterpret_cast<sockaddr_in*>(u->Address.lpSockaddr);
            inet_ntop(AF_INET, &sin->sin_addr, text, sizeof text);
            const std::string ip = text;
            if (ip.rfind("169.254.", 0) == 0) {
                if (link_local.empty()) { link_local = ip; link_prefix = u->OnLinkPrefixLength; }
            } else if (i.ipv4.empty()) {
                i.ipv4 = ip;
                i.prefix = u->OnLinkPrefixLength;
            }
        }
        if (i.ipv4.empty() && !link_local.empty()) {
            i.ipv4 = link_local;
            i.prefix = link_prefix;
            i.link_local_only = true;
        }
        out.push_back(std::move(i));
    }
    // aktivne kartice s pravom adresom prve
    std::stable_sort(out.begin(), out.end(), [](const Interface& x, const Interface& y) {
        return std::tuple(!x.is_up, x.link_local_only, x.ipv4.empty()) < std::tuple(!y.is_up, y.link_local_only, y.ipv4.empty());
    });
    return out;
}

json to_json(const Interface& i) {
    return {{"name", i.name}, {"ipv4", i.ipv4.empty() ? json(nullptr) : json(i.ipv4)},
            {"prefix", i.prefix}, {"is_up", i.is_up}, {"link_local_only", i.link_local_only},
            {"speed_mbps", i.speed_mbps}};
}

std::optional<std::string> source_ip(const std::string& interface_name) {
    if (interface_name.empty()) return std::nullopt;
    for (const auto& i : list_interfaces()) {
        if (i.name != interface_name) continue;
        if (!i.is_up || i.ipv4.empty()) {
            throw InterfaceError(tr("Mrežna kartica „{name}“ nije spojena ili nema IP adresu.", {{"name", interface_name}}));
        }
        return i.ipv4;
    }
    throw InterfaceError(tr("Mrežna kartica „{name}“ ne postoji (promijenite je u postavkama).", {{"name", interface_name}}));
}

std::optional<std::string> default_route_interface() {
    // UDP "connect" ne šalje paket, samo odabire rutu – lokalna adresa otkriva karticu.
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return std::nullopt;
    sockaddr_in remote{};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(53);
    inet_pton(AF_INET, "1.1.1.1", &remote.sin_addr);
    std::optional<std::string> result;
    if (::connect(s, reinterpret_cast<sockaddr*>(&remote), sizeof remote) == 0) {
        sockaddr_in local{};
        int len = sizeof local;
        getsockname(s, reinterpret_cast<sockaddr*>(&local), &len);
        char text[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &local.sin_addr, text, sizeof text);
        for (const auto& i : list_interfaces()) if (i.ipv4 == text) result = i.name;
    }
    closesocket(s);
    return result;
}

std::optional<std::string> interface_for_host(const std::string& host) {
    for (const auto& i : list_interfaces()) if (in_subnet(i.ipv4, i.prefix, host)) return i.name;
    return std::nullopt;
}

std::optional<bool> reaches(const std::string& interface_name, const std::string& host) {
    if (!parse_ipv4(host)) return std::nullopt;
    for (const auto& i : list_interfaces()) {
        if (i.name != interface_name) continue;
        if (i.ipv4.empty()) return std::nullopt;
        return in_subnet(i.ipv4, i.prefix, host);
    }
    return std::nullopt;
}

}  // namespace sm
