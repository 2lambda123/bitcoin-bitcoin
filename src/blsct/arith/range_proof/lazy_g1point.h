// Copyright (c) 2022 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVCOIN_BLSCT_ARITH_RANGE_PROOF_LAZY_G1POINT_H
#define NAVCOIN_BLSCT_ARITH_RANGE_PROOF_LAZY_G1POINT_H

#include <blsct/arith/g1point.h>
#include <blsct/arith/scalar.h>

struct LazyG1Point {
public:
    LazyG1Point(const G1Point& base, const Scalar& exp): m_base(base.m_p), m_exp(exp.m_fr) {}

    const mclBnG1 m_base;
    const mclBnFr m_exp;
};

struct LazyG1Points {
public:
    void Add(const LazyG1Point& point);
    G1Point Sum() const;

private:
    std::vector<LazyG1Point> points;
};

#endif // NAVCOIN_BLSCT_ARITH_RANGE_PROOF_LAZY_G1POINT_H
