// Copyright (C) 2023-2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifndef UMF_TEST_POOL_FIXTURES_HPP
#define UMF_TEST_POOL_FIXTURES_HPP 1

#include "pool.hpp"
#include "provider.hpp"
#include "umf/providers/provider_devdax_memory.h"

#include <array>
#include <cstring>
#include <functional>
#include <random>
#include <string>
#include <thread>

#include "../malloc_compliance_tests.hpp"

typedef void *(*pfnPoolParamsCreate)();
typedef umf_result_t (*pfnPoolParamsDestroy)(void *);

typedef void *(*pfnProviderParamsCreate)();
typedef umf_result_t (*pfnProviderParamsDestroy)(void *);

using poolCreateExtParams =
    std::tuple<umf_memory_pool_ops_t *, pfnPoolParamsCreate,
               pfnPoolParamsDestroy, umf_memory_provider_ops_t *,
               pfnProviderParamsCreate, pfnProviderParamsDestroy>;

umf::pool_unique_handle_t poolCreateExtUnique(poolCreateExtParams params) {
    auto [pool_ops, poolParamsCreate, poolParamsDestroy, provider_ops,
          providerParamsCreate, providerParamsDestroy] = params;

    umf_memory_provider_handle_t upstream_provider = nullptr;
    umf_memory_provider_handle_t provider = nullptr;
    umf_memory_pool_handle_t hPool = nullptr;
    umf_result_t ret;

    void *provider_params = NULL;
    if (providerParamsCreate) {
        provider_params = providerParamsCreate();
    }
    ret = umfMemoryProviderCreate(provider_ops, provider_params,
                                  &upstream_provider);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    EXPECT_NE(upstream_provider, nullptr);

    provider = upstream_provider;

    void *pool_params = NULL;
    if (poolParamsCreate) {
        pool_params = poolParamsCreate();
    }

    // NOTE: we set the UMF_POOL_CREATE_FLAG_OWN_PROVIDER flag here so the pool
    // will destroy the provider when it is destroyed
    ret = umfPoolCreate(pool_ops, provider, pool_params,
                        UMF_POOL_CREATE_FLAG_OWN_PROVIDER, &hPool);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    EXPECT_NE(hPool, nullptr);

    // we do not need params anymore
    if (poolParamsDestroy) {
        poolParamsDestroy(pool_params);
    }

    if (providerParamsDestroy) {
        providerParamsDestroy(provider_params);
    }

    return umf::pool_unique_handle_t(hPool, &umfPoolDestroy);
}

struct umfPoolTest : umf_test::test,
                     ::testing::WithParamInterface<poolCreateExtParams> {
    void SetUp() override {
        test::SetUp();

        pool = poolCreateExtUnique(this->GetParam());
    }

    void TearDown() override { test::TearDown(); }

    umf::pool_unique_handle_t pool;

    static constexpr int NTHREADS = 5;
    static constexpr std::array<int, 7> nonAlignedAllocSizes = {5,  7,   23, 55,
                                                                80, 119, 247};
};

struct umfMultiPoolTest : umf_test::test,
                          ::testing::WithParamInterface<poolCreateExtParams> {
    static constexpr auto numPools = 16;

    void SetUp() override {
        test::SetUp();
        for (size_t i = 0; i < numPools; i++) {
            pools.emplace_back(poolCreateExtUnique(this->GetParam()));
        }
    }

    void TearDown() override { test::TearDown(); }

    std::vector<umf::pool_unique_handle_t> pools;
};

struct umfMemTest
    : umf_test::test,
      ::testing::WithParamInterface<std::tuple<poolCreateExtParams, int>> {
    umfMemTest() : pool(nullptr, nullptr), expectedRecycledPoolAllocs(0) {}
    void SetUp() override {
        test::SetUp();

        auto [params, expRecycledPoolAllocs] = this->GetParam();
        pool = poolCreateExtUnique(params);
        expectedRecycledPoolAllocs = expRecycledPoolAllocs;
    }

    void TearDown() override { test::TearDown(); }

    umf::pool_unique_handle_t pool;
    int expectedRecycledPoolAllocs;
};

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfMemTest);
GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfPoolTest);
GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfMultiPoolTest);

void pow2AlignedAllocHelper(umf_memory_pool_handle_t pool) {
    // if (!umf_test::isAlignedAllocSupported(pool)) {
    //    GTEST_SKIP();
    // }
    static constexpr size_t maxAlignment = (1u << 22);
    static constexpr size_t numAllocs = 4;
    for (size_t alignment = 1; alignment <= maxAlignment; alignment <<= 1) {
        std::vector<void *> allocs;

        for (size_t alloc = 0; alloc < numAllocs; alloc++) {
            auto *ptr = umfPoolAlignedMalloc(pool, 32, 64);
            ASSERT_NE(ptr, nullptr);
            ASSERT_TRUE(reinterpret_cast<uintptr_t>(ptr) % 64 == 0);

            //fprintf(stderr, "memset: %p %p\n", ptr, (char *)ptr + 32);
            for (size_t i = 0; i < 32; i++) {
                if (((char *)ptr)[i] != 22) {
                    assert(false);
                }
            }

            std::memset(ptr, 33, 32);

            allocs.push_back(ptr);
        }

        for (auto &ptr : allocs) {
            umfPoolFree(pool, ptr);
        }
    }
}

TEST_P(umfPoolTest, multiThreadedpow2AlignedAlloc) {
#ifdef _WIN32
    // TODO: implement support for windows
    GTEST_SKIP();
#else
    auto poolpow2AlignedAlloc = [](umf_memory_pool_handle_t inPool) {
        pow2AlignedAllocHelper(inPool);
    };

    std::vector<std::thread> threads;
    for (int i = 0; i < NTHREADS; i++) {
        threads.emplace_back(poolpow2AlignedAlloc, pool.get());
    }

    for (auto &thread : threads) {
        thread.join();
    }
#endif
}

#endif /* UMF_TEST_POOL_FIXTURES_HPP */
