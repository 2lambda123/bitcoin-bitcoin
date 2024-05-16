// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_PCP_H
#define BITCOIN_UTIL_PCP_H

#include <netaddress.h>

#include <optional>

// RFC 6887 Port Control Protocol (PCP) implementation.
// PCP uses network byte order (big-endian).
// References to sections and figures in the code below refer to https://datatracker.ietf.org/doc/html/rfc6887.

// Protocol constants.
//! Maximum packet size in bytes (see section 7).
constexpr size_t PCP_MAX_SIZE = 1100;
//! PCP uses a fixed server port number (see section 19.1).
constexpr uint16_t PCP_SERVER_PORT = 5351;
//! Version byte. 0 is NAT-PMP, 1 is forbidden, 2 for PCP RFC-6887.
constexpr uint8_t PCP_VERSION = 2;
//! PCP Request Header. See section 7.1
constexpr uint8_t PCP_REQUEST = 0x00; // R = 0
//! PCP Response Header. See section 7.2
constexpr uint8_t PCP_RESPONSE = 0x80; // R = 1
//! Map opcode. See section 19.2
constexpr uint8_t PCP_OP_MAP = 0x01;
//! TCP protocol number (IANA).
constexpr uint16_t PCP_PROTOCOL_TCP = 6;
//! Option: prefer failure to half-functional mapping. See section 13.2.
constexpr uint8_t PCP_OPTION_PREFER_FAILURE = 2;
//! Request header size in bytes (see section 7.1).
constexpr size_t PCP_REQUEST_HDR_SIZE = 24;
//! Response header size in bytes (see section 7.2).
constexpr size_t PCP_RESPONSE_HDR_SIZE = 24;
//! Option header size in bytes (see section 7.2).
constexpr size_t PCP_OPTION_HDR_SIZE = 4;
//! Map request size in bytes (see section 11.1).
constexpr size_t PCP_MAP_REQUEST_SIZE = 36;
//! Map response size in bytes (see section 11.1).
constexpr size_t PCP_MAP_RESPONSE_SIZE = 36;
//! Mapping nonce size in bytes (see section 11.1).
constexpr size_t PCP_MAP_NONCE_SIZE = 12;
//! Result code representing SUCCESS status (7.4).
constexpr uint8_t PCP_RESULT_SUCCESS = 0;

//! PCP mapping nonce. Arbitrary data chosen by the client to identify a mapping.
typedef std::array<uint8_t, PCP_MAP_NONCE_SIZE> PCPMappingNonce;

/// Successful response to a PCP port mapping.
struct MappingResult {
    MappingResult(const CService &internal_in, const CService &external_in, uint32_t lifetime_in):
        internal(internal_in), external(external_in), lifetime(lifetime_in) {}
    //! Internal host:port.
    CService internal;
    //! External host:port.
    CService external;
    //! Granted lifetime of binding (seconds).
    uint32_t lifetime;
};

//! Return human-readable string from PCP result code.
std::string PCPResultString(uint8_t result_code);

//! Try to open a port using RFC 6887 Port Control Protocol (PCP).
//!
//! * gateway: Destination address for PCP requests (usually the default gateway).
//! * bind: Specific local bind address for IPv6 pinholing. Set this as INADDR_ANY for IPv4.
//! * port: Internal port, and desired external port.
//! * lifetime: Requested lifetime in seconds for mapping. The server may assign as shorter or longer lifetime. A lifetime of 0 deletes the mapping.
//! * num_tries: Number of tries in case of no response.
//! * prefer_failure: Add PREFER_FAILURE option. This means to prefer the request to fail instead of returning a different mapping than requested.
//!
//! Returns the external_ip:external_port of the mapping if successful, otherwise nullopt.
std::optional<MappingResult> PCPRequestPortMap(const PCPMappingNonce &nonce, const CNetAddr &gateway, const CNetAddr &bind, uint16_t port, uint32_t lifetime, int num_tries = 3, bool option_prefer_failure = false);

#endif // BITCOIN_UTIL_PCP_H
