// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <config/bitcoin-config.h> // IWYU pragma: keep

#include <util/netif.h>

#include <logging.h>
#include <netbase.h>
#include <util/check.h>
#include <util/sock.h>
#include <util/syserror.h>

#if defined(__linux__) || defined(__FreeBSD__)

#if defined(__linux__)
#include <linux/rtnetlink.h>
#elif defined(__FreeBSD__)
#include <netlink/netlink.h>
#include <netlink/netlink_route.h>
#endif

std::optional<CNetAddr> QueryDefaultGateway(Network network)
{
    Assume(network == NET_IPV4 || network == NET_IPV6);

    // Create a netlink socket.
    const int s{socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)};
    if (s < 0) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Error, "socket(AF_NETLINK): %s\n", SysErrorString(errno));
        return std::nullopt;
    }
    Sock sock{static_cast<SOCKET>(s)};

    // Send request.
    struct {
        nlmsghdr hdr; ///< Request header.
        rtmsg data; ///< Request data, a "route message".
        nlattr dst_hdr; ///< One attribute, conveying the route destination address.
        char dst_data[16]; ///< Route destination address. To query the default route we use 0.0.0.0/0 or [::]/0. For IPv4 the first 4 bytes are used.
    } request{};

    // Whether to use the first 4 or 16 bytes from request.attr_dst_data.
    const size_t dst_data_len = network == NET_IPV4 ? 4 : 16;

    request.hdr.nlmsg_type = RTM_GETROUTE;
    request.hdr.nlmsg_flags = NLM_F_REQUEST;
#ifdef __linux__
    request.hdr.nlmsg_flags |= NLM_F_DUMP;
#endif
    request.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg) + sizeof(nlattr) + dst_data_len);
    request.hdr.nlmsg_seq = 0; // Sequence number, used to match which reply is to which request. Irrelevant for us because we send just one request.
    request.data.rtm_family = network == NET_IPV4 ? AF_INET : AF_INET6;
    request.data.rtm_dst_len = 0; // Prefix length.
#ifdef __FreeBSD__
    request.data.rtm_flags = RTM_F_PREFIX;
#endif
    request.dst_hdr.nla_type = RTA_DST;
    request.dst_hdr.nla_len = sizeof(nlattr) + dst_data_len;

    if (sock.Send(&request, request.hdr.nlmsg_len, 0) != static_cast<ssize_t>(request.hdr.nlmsg_len)) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Error, "send() to netlink socket: %s\n", SysErrorString(errno));
        return std::nullopt;
    }

    // Receive response.
    char response[4096];
    ssize_t recv_result;
    do {
        recv_result = sock.Recv(response, sizeof(response), 0);
    } while (recv_result < 0 && (errno == EINTR || errno == EAGAIN));
    if (recv_result < 0) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Error, "recv() from netlink socket: %s\n", SysErrorString(errno));
        return std::nullopt;
    }

    size_t response_len = static_cast<size_t>(recv_result);
    for (nlmsghdr* hdr = (nlmsghdr*)response; NLMSG_OK(hdr, response_len); hdr = NLMSG_NEXT(hdr, response_len)) {
        rtmsg* r = (rtmsg*)NLMSG_DATA(hdr);
        int remaining_len = RTM_PAYLOAD(hdr);

        // Iterate over the attributes.
        rtattr *rta_gateway = nullptr;
        int scope_id = 0;
        for (rtattr* attr = RTM_RTA(r); RTA_OK(attr, remaining_len); attr = RTA_NEXT(attr, remaining_len)) {
            if (attr->rta_type == RTA_GATEWAY) {
                rta_gateway = attr;
            } else if (attr->rta_type == RTA_OIF) {
                Assume(sizeof(int) == RTA_PAYLOAD(attr));
                std::memcpy(&scope_id, RTA_DATA(attr), sizeof(scope_id));
            }
        }

        // Found gateway?
        if (rta_gateway != nullptr) {
            if (network == NET_IPV4) {
                Assume(sizeof(in_addr) == RTA_PAYLOAD(rta_gateway));
                in_addr gw;
                std::memcpy(&gw, RTA_DATA(rta_gateway), sizeof(gw));
                return CNetAddr(gw);
            } else if (network == NET_IPV6) {
                Assume(sizeof(in6_addr) == RTA_PAYLOAD(rta_gateway));
                in6_addr gw;
                std::memcpy(&gw, RTA_DATA(rta_gateway), sizeof(gw));
                return CNetAddr(gw, scope_id);
            }
        }
    }

    return std::nullopt;
}

#elif defined(WIN32)

#include <iphlpapi.h>

std::optional<CNetAddr> QueryDefaultGateway(Network network)
{
    NET_LUID interface_luid = {};
    SOCKADDR_INET destination_address = {};
    MIB_IPFORWARD_ROW2 best_route = {};
    SOCKADDR_INET best_source_address = {};
    DWORD best_if_idx = 0;
    DWORD status = 0;

    // Pass empty destination address of the requested type (:: or 0.0.0.0) to get interface of default route.
    Assume(network == NET_IPV4 || network == NET_IPV6);
    if (network == NET_IPV4) {
        destination_address.si_family = AF_INET;
    } else if(network == NET_IPV6) {
        destination_address.si_family = AF_INET6;
    } else {
        return std::nullopt;
    }

    status = GetBestInterfaceEx((sockaddr*)&destination_address, &best_if_idx);
    if (status != NO_ERROR) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Error, "Could not get best interface for default route: %s\n", SysErrorString(status));
        return std::nullopt;
    }

    // Get best route to default gateway.
    // Leave interface_luid at all-zeros to use interface index instead.
    status = GetBestRoute2(&interface_luid, best_if_idx, nullptr, &destination_address, 0, &best_route, &best_source_address);
    if (status != NO_ERROR) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Error, "Could not get best route for default route for interface index %d: %s\n",
                best_if_idx, SysErrorString(status));
        return std::nullopt;
    }

    if (network == NET_IPV4) {
        Assume(best_route.NextHop.si_family == AF_INET);
        return CNetAddr(best_route.NextHop.Ipv4.sin_addr);
    } else if(network == NET_IPV6) {
        Assume(best_route.NextHop.si_family == AF_INET6);
        return CNetAddr(best_route.NextHop.Ipv6.sin6_addr, best_route.InterfaceIndex);
    }
    return std::nullopt;
}

#elif defined(__APPLE__)

#include <net/route.h>
#include <sys/sysctl.h>

// Ensure correct alignment for sockaddrs.
#define ROUNDUP(a) \
    ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))

static std::optional<CNetAddr> FromSockAddr(const struct sockaddr* addr)
{
    // Fill in a CService from the sockaddr, then drop the port part.
    CService service;
    if (service.SetSockAddr(addr)) {
        return (CNetAddr)service;
    }
    return std::nullopt;
}

std::optional<CNetAddr> QueryDefaultGateway(Network network)
{
    // MacOS: Get default gateway from route table.
    // See man page for route(4) for the format.
    Assume(network == NET_IPV4 || network == NET_IPV6);
    int family;
    if (network == NET_IPV4) {
        family = AF_INET;
    } else if(network == NET_IPV6) {
        family = AF_INET6;
    } else {
        return std::nullopt;
    }

    // net.route.0.inet[6].flags.gateway
    int mib[] = {CTL_NET, PF_ROUTE, 0, family, NET_RT_FLAGS, RTF_GATEWAY};
    size_t l = 0;
    if (sysctl(mib, sizeof(mib) / sizeof(int), 0, &l, 0, 0) < 0) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Error, "Could not get sysctl length of routing table: %s\n", SysErrorString(errno));
        return std::nullopt;
    }
    std::vector<std::byte> buf(l);
    if (sysctl(mib, sizeof(mib) / sizeof(int), buf.data(), &l, 0, 0) < 0) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Error, "Could not get sysctl data of routing table: %s\n", SysErrorString(errno));
        return std::nullopt;
    }
    const struct rt_msghdr* rt = nullptr;
    for (const std::byte* p = buf.data(); p < buf.data() + buf.size(); p += rt->rtm_msglen) {
        // Iterate over routing entry addresses, get destination and gateway (if present).
        rt = (const struct rt_msghdr*)p;
        const struct sockaddr* sa = (const struct sockaddr*)(rt + 1);
        std::optional<CNetAddr> dst;
        std::optional<CNetAddr> gateway;
        for (int i = 0; i < RTAX_MAX; i++) {
            if (rt->rtm_addrs & (1 << i)) {
                if (i == RTAX_DST) {
                    dst = FromSockAddr(sa);
                } else if (i == RTAX_GATEWAY) {
                    gateway = FromSockAddr(sa);
                }
                sa = (const struct sockaddr*)((std::byte*)sa + ROUNDUP(sa->sa_len));
            }
        }
        if (dst && gateway && dst->IsBindAny()) { // Route to 0.0.0.0 or :: ?
            return *gateway;
        }
    }
    return std::nullopt;
}

#else

std::optional<CNetAddr> QueryDefaultGateway(Network network)
{
    Assume(network == NET_IPV4 || network == NET_IPV6);
    return std::nullopt;
}

#endif

std::vector<CNetAddr> GetLocalAddresses()
{
    std::vector<CNetAddr> addresses;
#ifdef WIN32
    char pszHostName[256] = "";
    if (gethostname(pszHostName, sizeof(pszHostName)) != SOCKET_ERROR)
    {
        addresses = LookupHost(pszHostName, 0, true);
    }
#elif (HAVE_DECL_GETIFADDRS && HAVE_DECL_FREEIFADDRS)
    struct ifaddrs* myaddrs;
    if (getifaddrs(&myaddrs) == 0)
    {
        for (struct ifaddrs* ifa = myaddrs; ifa != nullptr; ifa = ifa->ifa_next)
        {
            if (ifa->ifa_addr == nullptr) continue;
            if ((ifa->ifa_flags & IFF_UP) == 0) continue;
            if ((ifa->ifa_flags & IFF_LOOPBACK) != 0) continue;
            if (ifa->ifa_addr->sa_family == AF_INET)
            {
                struct sockaddr_in* s4 = (struct sockaddr_in*)(ifa->ifa_addr);
                addresses.emplace_back(s4->sin_addr);
            }
            else if (ifa->ifa_addr->sa_family == AF_INET6)
            {
                struct sockaddr_in6* s6 = (struct sockaddr_in6*)(ifa->ifa_addr);
                addresses.emplace_back(s6->sin6_addr);
            }
        }
        freeifaddrs(myaddrs);
    }
#endif
    return addresses;
}

