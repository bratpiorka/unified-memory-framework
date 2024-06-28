/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

// disable warning 4100: "unreferenced formal parameter" thrown in hwloc.h, as
// we do not want to modify this file
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4100)
#endif // _MSC_VER

// disable Clang warnings: "unreferenced parameter" and "unreferenced variable"
// thrown in hwloc.h, as we do not want to modify this file
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wunused-variable"
#endif // __clang__

#include <hwloc.h>

#if defined(__clang__)
#pragma clang diagnostic pop
#endif // __clang__

#if defined(_MSC_VER)
#pragma warning(pop)
#endif // _MSC_VER
