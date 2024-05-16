// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <util/pcp.h>

#include <crypto/common.h>
#include <logging.h>
#include <netaddress.h>
#include <random.h>
#include <util/netif.h>
#include <util/readwritefile.h>
#include <util/sock.h>
#include <util/strencodings.h>

// RFC 6887 Port Control Protocol (PCP) implementation.
// PCP uses network byte order (big-endian).
// References to sections and figures in the code below refer to https://datatracker.ietf.org/doc/html/rfc6887.

//! Mapping of PCP result code to string (7.4).
static const std::map<uint8_t, std::string> PCP_RESULT_STR{
    {0,  "SUCCESS"},
    {1,  "UNSUPP_VERSION"},
    {2,  "NOT_AUTHORIZED"},
    {3,  "MALFORMED_REQUEST"},
    {4,  "UNSUPP_OPCODE"},
    {5,  "UNSUPP_OPTION"},
    {6,  "MALFORMED_OPTION"},
    {7,  "NETWORK_FAILURE"},
    {8,  "NO_RESOURCES"},
    {9,  "UNSUPP_PROTOCOL"},
    {10, "USER_EX_QUOTA"},
    {11, "CANNOT_PROVIDE_EXTERNAL"},
    {12, "ADDRESS_MISMATCH"},
    {13, "EXCESSIVE_REMOTE_PEER"},
};

std::string PCPResultString(uint8_t result_code)
{
    auto result_i = PCP_RESULT_STR.find(result_code);
    return strprintf("%s (code %d)", result_i == PCP_RESULT_STR.end() ? "(unknown)" : result_i->second,  result_code);
}

//! Wrap address in IPv6 according to RFC. wrapped_addr needs to be able to store 16 bytes.
[[nodiscard]] static bool PCPWrapAddress(uint8_t *wrapped_addr, const CNetAddr &addr)
{
    if (addr.IsIPv4()) {
        struct in_addr addr4;
        if (!addr.GetInAddr(&addr4)) return false;
        // Section 5: "When the address field holds an IPv4 address, an IPv4-mapped IPv6 address [RFC4291] is used (::ffff:0:0/96)."
        std::memcpy(wrapped_addr, IPV4_IN_IPV6_PREFIX.data(), IPV4_IN_IPV6_PREFIX.size());
        std::memcpy(wrapped_addr + IPV4_IN_IPV6_PREFIX.size(), &addr4, ADDR_IPV4_SIZE);
        return true;
    } else if (addr.IsIPv6()) {
        struct in6_addr addr6;
        if (!addr.GetIn6Addr(&addr6)) return false;
        std::memcpy(wrapped_addr, &addr6, ADDR_IPV6_SIZE);
        return true;
    } else {
        return false;
    }
}

//! Unwrap PCP-encoded address.
static CNetAddr PCPUnwrapAddress(const uint8_t *wrapped_addr)
{
    if (std::memcmp(wrapped_addr, IPV4_IN_IPV6_PREFIX.data(), IPV4_IN_IPV6_PREFIX.size()) == 0) {
        struct in_addr addr4;
        std::memcpy(&addr4, wrapped_addr + IPV4_IN_IPV6_PREFIX.size(), ADDR_IPV4_SIZE);
        return CNetAddr(addr4);
    } else {
        struct in6_addr addr6;
        std::memcpy(&addr6, wrapped_addr, ADDR_IPV6_SIZE);
        return CNetAddr(addr6);
    }
}

std::optional<MappingResult> PCPRequestPortMap(const PCPMappingNonce &nonce, const CNetAddr &gateway, const CNetAddr &bind, uint16_t port, uint32_t lifetime, int num_tries, bool option_prefer_failure)
{
    struct sockaddr_storage dest_addr, bind_addr;
    socklen_t dest_addrlen = sizeof(struct sockaddr_storage), bind_addrlen = sizeof(struct sockaddr_storage);

    LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "pcp: Requesting port mapping for addr %s port %d from gateway %s\n", bind.ToStringAddr(), port, gateway.ToStringAddr());

    // Validate addresses, make sure they're the same network family.
    if (!CService(gateway, PCP_SERVER_PORT).GetSockAddr((struct sockaddr*)&dest_addr, &dest_addrlen)) return std::nullopt;
    if (!CService(bind, 0).GetSockAddr((struct sockaddr*)&bind_addr, &bind_addrlen)) return std::nullopt;
    if (dest_addr.ss_family != bind_addr.ss_family) return std::nullopt;

    // Create UDP socket (IPv4 or IPv6 based on provided gateway).
    SOCKET sock_fd = socket(dest_addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock_fd == INVALID_SOCKET) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Warning, "pcp: Could not create UDP socket: %s\n", NetworkErrorString(WSAGetLastError()));
        return std::nullopt;
    }
    Sock sock(sock_fd);

    // Make sure that we send from requested destination address, anything else will be
    // rejected by a security-conscious router.
    if (sock.Bind((struct sockaddr*)&bind_addr, bind_addrlen) != 0) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Warning, "pcp: Could not bind to address: %s\n", NetworkErrorString(WSAGetLastError()));
        return std::nullopt;
    }

    // Associate UDP socket to gateway.
    if (sock.Connect((struct sockaddr*)&dest_addr, dest_addrlen) != 0) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Warning, "pcp: Could not connect to gateway: %s\n", NetworkErrorString(WSAGetLastError()));
        return std::nullopt;
    }

    // Use getsockname to get the address toward the default gateway (the internal address),
    // in case we don't know what address to map
    // (this is only needed if bind is INADDR_ANY, but it doesn't hurt as an extra check).
    struct sockaddr_storage internal_addr;
    socklen_t internal_addrlen = sizeof(struct sockaddr_storage);
    if (sock.GetSockName((struct sockaddr*)&internal_addr, &internal_addrlen) != 0) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Warning, "pcp: Could not get sock name: %s\n", NetworkErrorString(WSAGetLastError()));
        return std::nullopt;
    }
    CService internal;
    if (!internal.SetSockAddr((struct sockaddr*)&internal_addr)) return std::nullopt;
    LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "pcp: Internal address after connect: %s\n", internal.ToStringAddr());

    // Build request packet. Make sure the packet is zeroed so that reserved fields are zero
    // as required by the spec (and not potentially leak data).
    // Make sure there's space for the request header, MAP specific request
    // data, and one option header.
    uint8_t request[PCP_REQUEST_HDR_SIZE + PCP_MAP_REQUEST_SIZE + PCP_OPTION_HDR_SIZE] = {};
    // Fill in request header, See Figure 2.
    size_t ofs = 0;
    request[ofs + 0] = PCP_VERSION;
    request[ofs + 1] = PCP_REQUEST | PCP_OP_MAP;
    WriteBE32(request + ofs + 4, lifetime);
    if (!PCPWrapAddress(request + ofs + 8, internal)) return std::nullopt;

    ofs += PCP_REQUEST_HDR_SIZE;

    // Fill in MAP request packet, See Figure 9.
    // Randomize mapping nonce (this is repeated in the response, to be able to
    // correlate requests and responses, and used to authenticate changes to the mapping).
    std::memcpy(request + ofs, nonce.data(), PCP_MAP_NONCE_SIZE);
    request[ofs + 12] = PCP_PROTOCOL_TCP;
    WriteBE16(request + ofs + 16, port);
    WriteBE16(request + ofs + 18, port);
    if (!PCPWrapAddress(request + ofs + 20, bind)) return std::nullopt;

    ofs += PCP_MAP_REQUEST_SIZE;

    if (option_prefer_failure) {
        // Fill in option header. See Figure 4.
        // Prefer failure to a different external address mapping than we expect.
        // TODO: decide if we want to pas this option or rather just handle different addresses/ports than we expect,
        // and advertise those as local address. This would be needed to handle IPv4 port mapping anyway.
        request[ofs] = PCP_OPTION_PREFER_FAILURE;
        // This option takes no data, rest of option header can be left as zero bytes.

        ofs += PCP_OPTION_HDR_SIZE;
    }

    // UDP is a potentially lossy protocol, so we try to send again a few times.
    bool got_response = false;
    uint8_t response[PCP_MAX_SIZE];
    for (int ntry = 0; !got_response && ntry < num_tries; ++ntry) {
        if (ntry > 0) {
            LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "pcp: Retrying (%d)\n", ntry);
        }
        // Dispatch packet to gateway.
        if (sock.Send(request, ofs, 0) != static_cast<ssize_t>(ofs)) {
            LogPrintLevel(BCLog::NET, BCLog::Level::Warning, "pcp: Could not send request: %s\n", NetworkErrorString(WSAGetLastError()));
            return std::nullopt; // Network-level error, probably no use retrying.
        }

        // Wait for response(s) until we get a valid response, a network error, or time out.
        while (true) {
            Sock::Event occured = 0;
            if (!sock.Wait(std::chrono::milliseconds(1000), Sock::RECV, &occured)) {
                LogPrintLevel(BCLog::NET, BCLog::Level::Warning, "pcp: Could not wait on socket: %s\n", NetworkErrorString(WSAGetLastError()));
                return std::nullopt; // Network-level error, probably no use retrying.
            }
            if (!occured) {
                LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "pcp: Timeout\n");
                break; // Retry.
            }

            // Receive response.
            int recvsz = sock.Recv(response, sizeof(response), MSG_DONTWAIT);
            if (recvsz < 0) {
                LogPrintLevel(BCLog::NET, BCLog::Level::Warning, "pcp: Could not receive response: %s\n", NetworkErrorString(WSAGetLastError()));
                return std::nullopt; // Network-level error, probably no use retrying.
            }
            LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "pcp: Received response of %d bytes: %s\n", recvsz, HexStr(Span(response, recvsz)));
            if (static_cast<size_t>(recvsz) < (PCP_RESPONSE_HDR_SIZE + PCP_MAP_RESPONSE_SIZE)) {
                LogPrintLevel(BCLog::NET, BCLog::Level::Warning, "pcp: Response too small\n");
                continue; // Wasn't response to what we expected, try receiving next packet.
            }
            if (response[0] != PCP_VERSION || response[1] != (PCP_RESPONSE | PCP_OP_MAP)) {
                LogPrintLevel(BCLog::NET, BCLog::Level::Warning, "pcp: Response to wrong command\n");
                continue; // Wasn't response to what we expected, try receiving next packet.
            }
            // Handle MAP opcode response. See Figure 10.
            // Check that returned mapping nonce matches our request.
            if (std::memcmp(response + PCP_RESPONSE_HDR_SIZE, request + PCP_REQUEST_HDR_SIZE, PCP_MAP_NONCE_SIZE) != 0) {
                LogPrintLevel(BCLog::NET, BCLog::Level::Warning, "pcp: Mapping nonce mismatch\n");
                continue; // Wasn't response to what we expected, try receiving next packet.
            }
            uint8_t protocol = response[PCP_RESPONSE_HDR_SIZE + 12];
            uint16_t internal_port = ReadBE16(response + PCP_RESPONSE_HDR_SIZE + 16);
            if (protocol != PCP_PROTOCOL_TCP || internal_port != port) {
                LogPrintLevel(BCLog::NET, BCLog::Level::Warning, "pcp: Response protocol or port doesn't match request\n");
                continue; // Wasn't response to what we expected, try receiving next packet.
            }
            got_response = true; // Got expected response, break from receive loop as well as from retry loop.
            break;
        }
    }
    if (!got_response) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "pcp: Giving up after %d tries\n", num_tries);
        return std::nullopt;
    }
    // If we get here, we got a valid MAP response to our request.
    // Check to see if we got the result we expected.
    uint8_t result_code = response[3];
    uint32_t lifetime_ret = ReadBE32(response + 4);
    uint16_t external_port = ReadBE16(response + PCP_RESPONSE_HDR_SIZE + 18);
    CNetAddr external_addr{PCPUnwrapAddress(response + PCP_RESPONSE_HDR_SIZE + 20)};
    if (result_code != PCP_RESULT_SUCCESS) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Warning, "pcp: Mapping failed with result %s\n", PCPResultString(result_code));
        return std::nullopt;
    }
    LogPrintLevel(BCLog::NET, BCLog::Level::Info, "pcp: Mapping successful: we got %s:%d for %d seconds.\n",
        external_addr.ToStringAddr(), external_port,
        lifetime_ret);

    return MappingResult(CService(internal, port), CService(external_addr, external_port), lifetime_ret);
}

