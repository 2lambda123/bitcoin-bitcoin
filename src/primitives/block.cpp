// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2018 MicroBitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"
#include "versionbits.h"

uint256 CBlockHeader::GetHash() const
{
    if (IsMicroBitcoin())
    {
        XCoin::CGroestlHashWriter ss(SER_GETHASH, PROTOCOL_VERSION); //GRS
        ss << *this;
        return ss.GetHash();
        // return SerializeHash(*this);
    } else {
        return SerializeHash(*this);
    }
}

bool CBlockHeader::IsMicroBitcoin() const
{
    // Time is the end of CSV deployment
    return nTime > 1493596800 && nVersion & VERSIONBITS_MICROBITCOIN;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
