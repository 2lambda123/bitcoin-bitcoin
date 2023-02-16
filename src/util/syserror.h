// Copyright (c) 2010-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/licenses/MIT.

#ifndef BITCOIN_UTIL_SYSERROR_H
#define BITCOIN_UTIL_SYSERROR_H

#include <string>

/** Return system error string from errno value. Use this instead of
 * std::strerror, which is not thread-safe. For network errors use
 * NetworkErrorString from sock.h instead.
 */
std::string SysErrorString(int err);

#endif // BITCOIN_UTIL_SYSERROR_H
