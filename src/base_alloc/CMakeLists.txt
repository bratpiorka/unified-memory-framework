# Copyright (C) 2023-2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

include(${UMF_CMAKE_SOURCE_DIR}/cmake/helpers.cmake)
include(FindThreads)

set(UMF_BA_SOURCES_COMMON base_alloc_global.c base_alloc.c base_alloc_linear.c)

set(UMF_BA_SOURCES_LINUX base_alloc_linux.c)

set(UMF_BA_SOURCES_WINDOWS base_alloc_windows.c)

if(UMF_USE_VALGRIND)
    if(UMF_USE_ASAN
       OR UMF_USE_TSAN
       OR UMF_USE_UBSAN
       OR UMF_USE_MSAN)
        message(FATAL_ERROR "Cannot use valgrind and sanitizers together")
    endif()

    if(PkgConfig_FOUND)
        pkg_check_modules(VALGRIND valgrind)
    endif()
    if(NOT VALGRIND_FOUND)
        find_package(VALGRIND REQUIRED valgrind)
    endif()
endif()

if(LINUX OR MACOSX)
    set(UMF_BA_SOURCES ${UMF_BA_SOURCES_COMMON} ${UMF_BA_SOURCES_POSIX})
    set(UMF_BA_LIBS dl)

    if(LINUX)
        set(UMF_BA_SOURCES ${UMF_BA_SOURCES} ${UMF_BA_SOURCES_LINUX})
    endif()
elseif(WINDOWS)
    set(UMF_BA_SOURCES ${UMF_BA_SOURCES_COMMON} ${UMF_BA_SOURCES_WINDOWS})
endif()

add_library(umf_ba INTERFACE)
add_library(${PROJECT_NAME}::ba ALIAS umf_ba)

target_sources(umf_ba INTERFACE ${UMF_BA_SOURCES})
target_link_libraries(umf_ba INTERFACE ${UMF_BA_LIBS})

target_include_directories(
    umf_ba
    INTERFACE ${VALGRIND_INCLUDE_DIRS}
              $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
              $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)

if(UMF_USE_VALGRIND)
    set(UMF_BA_INTERFACE_DEFS "UMF_VG_ENABLED=1")
endif()

set(UMF_BA_INTERFACE_DEFS ${UMF_BA_INTERFACE_DEFS}
                          ${UMF_COMMON_COMPILE_DEFINITIONS})

target_compile_definitions(umf_ba INTERFACE ${UMF_BA_INTERFACE_DEFS})
