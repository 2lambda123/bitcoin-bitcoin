// Copyright (c) 2023 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef KEYRING_H
#define KEYRING_H

#include <blsct/public_key.h>
#include <blsct/private_key.h>
#include <sync.h>

namespace blsct {
class KeyRing {
public:
    using KeyMap = std::map<CKeyID, PrivateKey>;

    /**
     * Map of key id to unencrypted private keys known by the signing provider.
     * Map may be empty if the provider has another source of keys, like an
     * encrypted store.
     */
    KeyMap mapKeys GUARDED_BY(cs_KeyStore);
    mutable RecursiveMutex cs_KeyStore;

    PrivateKey viewKey;
    PublicKey viewPublicKey;
    PublicKey spendPublicKey;

    virtual bool AddKeyPubKey(const PrivateKey& key, const PublicKey &pubkey);
    virtual bool AddKey(const PrivateKey &key) { return AddKeyPubKey(key, key.GetPublicKey()); }
    virtual bool AddViewKey(const PrivateKey &key, const PublicKey& pubkey);
    virtual bool AddSpendKey(const PublicKey &pubkey);

    virtual ~KeyRing() = default;
};
}

#endif // KEYRING_H
