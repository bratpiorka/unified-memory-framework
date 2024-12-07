# Copyright (C) 2023 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

if(UMF_BUILD_SHARED_LIBRARY)
    set(POOL_EXTRA_SRCS ${BA_SOURCES})
    set(POOL_EXTRA_LIBS $<BUILD_INTERFACE:umf_utils>)
endif()

set(POOL_COMPILE_DEFINITIONS ${UMF_COMMON_COMPILE_DEFINITIONS})

# libumf_pool_jemalloc
if(UMF_BUILD_LIBUMF_POOL_JEMALLOC)
    add_umf_library(
        NAME jemalloc_pool
        TYPE STATIC
        SRCS pool_jemalloc.c ${POOL_EXTRA_SRCS}
        LIBS jemalloc ${POOL_EXTRA_LIBS})
    target_include_directories(jemalloc_pool PRIVATE ${JEMALLOC_INCLUDE_DIRS})
    target_compile_definitions(jemalloc_pool
                               PRIVATE ${POOL_COMPILE_DEFINITIONS})
    add_library(${PROJECT_NAME}::jemalloc_pool ALIAS jemalloc_pool)
    install(TARGETS jemalloc_pool EXPORT ${PROJECT_NAME}-targets)
endif()
