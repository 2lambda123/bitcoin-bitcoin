// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <private_broadcast.h>
#include <util/check.h>

void PrivateBroadcast::Add(const CTransactionRef& tx) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
{
    const Txid& txid = tx->GetHash();
    LOCK(m_mutex);
    auto [pos, inserted] = m_by_txid.emplace(txid, TxWithPriority{.tx = tx, .priority = Priority{}});
    if (inserted) {
        m_by_priority.emplace(Priority{}, txid);
    }
}

std::optional<size_t> PrivateBroadcast::Remove(const CTransactionRef& tx) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
{
    LOCK(m_mutex);
    auto iters = Find(tx->GetHash());
    if (!iters) {
        return std::nullopt;
    }
    const size_t num_broadcasted{iters->by_priority->first.num_broadcasted};
    m_by_priority.erase(iters->by_priority);
    m_by_txid.erase(iters->by_txid);
    return num_broadcasted;
}

std::optional<CTransactionRef> PrivateBroadcast::GetTxForBroadcast() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
{
    LOCK(m_mutex);
    if (m_by_priority.empty()) {
        return std::nullopt;
    }
    const Txid& txid = m_by_priority.begin()->second;
    auto it = m_by_txid.find(txid);
    if (Assume(it != m_by_txid.end())) {
        return it->second.tx;
    }
    m_by_priority.erase(m_by_priority.begin());
    return std::nullopt;
}

void PrivateBroadcast::PushedToNode(const NodeId& nodeid, const Txid& txid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
{
    LOCK(m_mutex);
    m_by_nodeid.emplace(nodeid, txid);
}

bool PrivateBroadcast::BroadcastEnd(const NodeId& nodeid, bool confirmed_by_node) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
{
    LOCK(m_mutex);
    auto it = m_by_nodeid.find(nodeid);
    if (it == m_by_nodeid.end()) {
        return false;
    }
    const Txid txid{it->second};
    m_by_nodeid.erase(it);

    if (!confirmed_by_node) {
        return true;
    }

    // Update broadcast stats.

    auto iters = Find(txid);
    if (!iters) {
        return true;
    }
    Priority& priority = iters->by_txid->second.priority;

    ++priority.num_broadcasted;
    priority.last_broadcasted = GetTime<std::chrono::microseconds>();

    m_by_priority.erase(iters->by_priority);
    m_by_priority.emplace(priority, iters->by_txid->first);

    return true;
}

bool PrivateBroadcast::Priority::operator<(const Priority& other) const
{
    if (num_broadcasted < other.num_broadcasted) {
        return true;
    }
    return last_broadcasted < other.last_broadcasted;
}

std::optional<PrivateBroadcast::Iterators> PrivateBroadcast::Find(const Txid& txid) EXCLUSIVE_LOCKS_REQUIRED(m_mutex)
{
    AssertLockHeld(m_mutex);
    auto i = m_by_txid.find(txid);
    if (i == m_by_txid.end()) {
        return std::nullopt;
    }
    const Priority& priority = i->second.priority;
    for (auto j = m_by_priority.lower_bound(priority); j != m_by_priority.end(); ++j) {
        if (j->second == txid) {
            return Iterators{.by_txid = i, .by_priority = j};
        }
    }
    return std::nullopt;
}
