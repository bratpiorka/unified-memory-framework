// Copyright (C) 2023-2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <memory>

#include <umf/pools/pool_disjoint.h>

#include "pool.hpp"
#include "pool/pool_disjoint_internal.h"
#include "poolFixtures.hpp"
#include "provider.hpp"
#include "provider_null.h"
#include "provider_trace.h"

static constexpr size_t DEFAULT_DISJOINT_SLAB_MIN_SIZE = 4096;
static constexpr size_t DEFAULT_DISJOINT_MAX_POOLABLE_SIZE = 4096;
static constexpr size_t DEFAULT_DISJOINT_CAPACITY = 4;
static constexpr size_t DEFAULT_DISJOINT_MIN_BUCKET_SIZE = 64;

void *defaultPoolConfig() {
    umf_disjoint_pool_params_handle_t config = nullptr;
    umf_result_t res = umfDisjointPoolParamsCreate(&config);
    if (res != UMF_RESULT_SUCCESS) {
        throw std::runtime_error("Failed to create pool params");
    }
    res = umfDisjointPoolParamsSetSlabMinSize(config,
                                              DEFAULT_DISJOINT_SLAB_MIN_SIZE);
    if (res != UMF_RESULT_SUCCESS) {
        umfDisjointPoolParamsDestroy(config);
        throw std::runtime_error("Failed to set slab min size");
    }
    res = umfDisjointPoolParamsSetMaxPoolableSize(
        config, DEFAULT_DISJOINT_MAX_POOLABLE_SIZE);
    if (res != UMF_RESULT_SUCCESS) {
        umfDisjointPoolParamsDestroy(config);
        throw std::runtime_error("Failed to set max poolable size");
    }
    res = umfDisjointPoolParamsSetCapacity(config, DEFAULT_DISJOINT_CAPACITY);
    if (res != UMF_RESULT_SUCCESS) {
        umfDisjointPoolParamsDestroy(config);
        throw std::runtime_error("Failed to set capacity");
    }
    res = umfDisjointPoolParamsSetMinBucketSize(
        config, DEFAULT_DISJOINT_MIN_BUCKET_SIZE);
    if (res != UMF_RESULT_SUCCESS) {
        umfDisjointPoolParamsDestroy(config);
        throw std::runtime_error("Failed to set min bucket size");
    }

    return config;
}

umf_result_t poolConfigDestroy(void *config) {
    return umfDisjointPoolParamsDestroy(
        static_cast<umf_disjoint_pool_params_handle_t>(config));
}

using umf_test::test;
using namespace umf_test;

INSTANTIATE_TEST_SUITE_P(disjointPoolTests, umfPoolTest,
                         ::testing::Values(poolCreateExtParams{
                             umfDisjointPoolOps(), defaultPoolConfig,
                             poolConfigDestroy, &BA_GLOBAL_PROVIDER_OPS,
                             nullptr, nullptr}));

void *memProviderParams() { return (void *)&DEFAULT_DISJOINT_CAPACITY; }

INSTANTIATE_TEST_SUITE_P(
    disjointPoolTests, umfMemTest,
    ::testing::Values(std::make_tuple(
        poolCreateExtParams{umfDisjointPoolOps(), defaultPoolConfig,
                            poolConfigDestroy, &MOCK_OUT_OF_MEM_PROVIDER_OPS,
                            memProviderParams, nullptr},
        static_cast<int>(DEFAULT_DISJOINT_CAPACITY) / 2)));

INSTANTIATE_TEST_SUITE_P(disjointMultiPoolTests, umfMultiPoolTest,
                         ::testing::Values(poolCreateExtParams{
                             umfDisjointPoolOps(), defaultPoolConfig,
                             poolConfigDestroy, &BA_GLOBAL_PROVIDER_OPS,
                             nullptr, nullptr}));
