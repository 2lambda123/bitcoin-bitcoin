// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_TXMEMPOOL_H
#define BITCOIN_TXMEMPOOL_H

#include "uint256.h"

class CCoinsViewCache;
class CTransaction;
class CValidationState;
class CMinerPolicyEstimator;

/*
 * CTxMemPool stores these:
 */
class CTxMemPoolEntry
{
private:
    CTransaction tx;
    int64 nFee; // Cached to avoid expensive parent-transaction lookups
    size_t nTxSize; // ... and avoid recomputing tx size
    double dPriority; // Priority when entering the mempool
    unsigned int nHeight; // Chain height when entering the mempool

public:
    CTxMemPoolEntry(const CTransaction& _tx, int64 _nFee, double _dPriority,
                    unsigned int nHeight);
    CTxMemPoolEntry();
    CTxMemPoolEntry(const CTxMemPoolEntry& other);

    const CTransaction& getTx() const { return this->tx; }
    double getPriority(unsigned int currentHeight) const;
    int64 getFee() const { return nFee; }
    size_t getTxSize() const { return nTxSize; }
    unsigned int getHeight() const { return nHeight; }
};

/*
 * CTxMemPool stores valid-according-to-the-current-best-chain
 * transactions that may be included in the next block.
 * 
 * Transactions are added when they are seen on the network
 * (or created by the local node), but not all transactions seen
 * are added to the pool: if a new transaction double-spends
 * an input of a transaction in the pool, it is dropped,
 * as are non-standard transactions.
 */
class CTxMemPool
{
private:
    bool fSanityCheck; // Normally false, true if -checkmempool or -regtest
    CMinerPolicyEstimator* minerPolicyEstimator; // For estimating transaction fees

public:
    mutable CCriticalSection cs;
    std::map<uint256, CTxMemPoolEntry> mapTx;
    std::map<COutPoint, CInPoint> mapNextTx;

    CTxMemPool();
    ~CTxMemPool();
    
    /*
     * If sanity-checking is turned on, check makes sure the pool is
     * consistent (does not contain two transactions that spend the same inputs,
     * all inputs are in the mapNextTx array). If sanity-checking is turned off,
     * check does nothing.
     */
    void check(CCoinsViewCache *pcoins) const;
    void setSanityCheck(bool _fSanityCheck) { fSanityCheck = _fSanityCheck; }

    bool accept(CValidationState &state, const CTransaction &tx, bool fLimitFree,
                bool* pfMissingInputs, bool fRejectInsaneFee=false);
    bool addUnchecked(const uint256& hash, const CTxMemPoolEntry &entry);
    bool remove(const uint256 &hash, bool fRecursive = false, int nBlockHeight = -1);
    bool removeConflicts(const CTransaction &tx);
    void clear();
    void queryHashes(std::vector<uint256>& vtxid);
    void pruneSpent(const uint256& hash, CCoins &coins);
    void estimateFees(double dPriorityMedian, double& dPriority, double dFeeMedian, double& dFee);

    unsigned long size()
    {
        LOCK(cs);
        return mapTx.size();
    }

    bool exists(uint256 hash)
    {
        return (mapTx.count(hash) != 0);
    }

    bool lookup(uint256 hash, CTransaction& result) const;
};

extern CTxMemPool mempool;

#endif /* BITCOIN_TXMEMPOOL_H */
