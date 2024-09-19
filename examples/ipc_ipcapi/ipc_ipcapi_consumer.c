/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
typedef int socklen_t;
typedef SSIZE_T ssize_t;
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <umf/ipc.h>
#include <umf/memory_pool.h>
#include <umf/pools/pool_scalable.h>
#include <umf/providers/provider_os_memory.h>

#define INET_ADDR "127.0.0.1"
#define SEND_BUFF_SIZE 256
#define RECV_BUFF_SIZE 32

// consumer's response message
#define CONSUMER_MSG                                                           \
    "This is the consumer. I just wrote a new number directly into your "      \
    "shared memory!"

int consumer_connect_to_producer(int port) {
#ifdef _WIN32
    WSADATA wsaData;
    SOCKET producer_socket, consumer_socket;
#else
    int producer_socket = -1;
    int consumer_socket = -1;
#endif

    struct sockaddr_in consumer_addr;
    struct sockaddr_in producer_addr;

    int producer_addr_len;
    int ret = -1;

#ifdef _WIN32
    // initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "Failed. Error Code : %d", WSAGetLastError());
        return -1;
    }
#endif

    // create a socket
    consumer_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (consumer_socket < 0) {
        fprintf(stderr, "[consumer] ERROR: creating socket failed\n");
        goto err_WSA_cleanup;
    }

    fprintf(stderr, "[consumer] Socket created\n");

    // set the IP address and the port
    consumer_addr.sin_family = AF_INET;
    consumer_addr.sin_port = htons((u_short)port);
    consumer_addr.sin_addr.s_addr = inet_addr(INET_ADDR);

    // bind to the IP address and the port
    if (bind(consumer_socket, (struct sockaddr *)&consumer_addr,
             sizeof(consumer_addr)) < 0) {
        fprintf(stderr, "[consumer] ERROR: cannot bind to the port\n");
        goto err_close_consumer_socket;
    }

    fprintf(stderr, "[consumer] Binding done\n");

    // listen for the producer
    if (listen(consumer_socket, 1) < 0) {
        fprintf(stderr, "[consumer] ERROR: listen() failed\n");
        goto err_close_consumer_socket;
    }

    fprintf(stderr, "[consumer] Listening for incoming connections ...\n");

    // accept an incoming connection
    producer_addr_len = sizeof(producer_addr);
    producer_socket = accept(consumer_socket, (struct sockaddr *)&producer_addr,
                             (socklen_t *)&producer_addr_len);
    if (producer_socket < 0) {
        fprintf(stderr, "[consumer] ERROR: accept() failed\n");
        goto err_close_consumer_socket;
    }

    fprintf(stderr, "[consumer] Producer connected at IP %s and port %i\n",
            inet_ntoa(producer_addr.sin_addr), ntohs(producer_addr.sin_port));

    ret = (int)producer_socket; // success

err_close_consumer_socket:
#ifdef _WIN32
    closesocket(consumer_socket);
#else
    close(consumer_socket);
#endif

err_WSA_cleanup:
#ifdef _WIN32
    WSACleanup();
#endif

    return ret;
}

int main(int argc, char *argv[]) {
    char send_buffer[SEND_BUFF_SIZE];
    char recv_buffer[RECV_BUFF_SIZE];
    int producer_socket;
    int ret = -1;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <port> [shm_name]\n", argv[0]);
        return -1;
    }

    int port = atoi(argv[1]);

    umf_memory_provider_handle_t OS_memory_provider = NULL;
    umf_os_memory_provider_params_t os_params;
    enum umf_result_t umf_result;

    os_params = umfOsMemoryProviderParamsDefault();
    os_params.visibility = UMF_MEM_MAP_SHARED;
    if (argc >= 3) {
        os_params.shm_name = argv[2];
    }

    // create OS memory provider
    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(), &os_params,
                                         &OS_memory_provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "[consumer] ERROR: creating OS memory provider failed\n");
        return -1;
    }

    umf_memory_pool_handle_t scalable_pool;
    umf_result = umfPoolCreate(umfScalablePoolOps(), OS_memory_provider, NULL,
                               0, &scalable_pool);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "[producer] ERROR: creating jemalloc UMF pool failed\n");
        goto err_destroy_OS_memory_provider;
    }

    // connect to the producer
    producer_socket = consumer_connect_to_producer(port);
    if (producer_socket < 0) {
        goto err_destroy_scalable_pool;
    }

    memset(recv_buffer, 0, RECV_BUFF_SIZE);

    // receive a size of the IPC handle from the producer's
    ssize_t recv_len = recv(producer_socket, recv_buffer, RECV_BUFF_SIZE, 0);
    if (recv_len < 0) {
        fprintf(
            stderr,
            "[consumer] ERROR: receiving a size of the IPC handle failed\n");
        goto err_close_producer_socket;
    }
    size_t len = (size_t)recv_len;

    size_t size_IPC_handle = *(size_t *)recv_buffer;

    fprintf(stderr,
            "[consumer] Received %zu bytes - the size of the IPC handle: %zu "
            "bytes\n",
            len, size_IPC_handle);

    // send received size to the producer as a confirmation
    recv_len = send(producer_socket, (const char *)&size_IPC_handle,
                    sizeof(size_IPC_handle), 0);
    if (recv_len < 0) {
        fprintf(stderr, "[consumer] ERROR: sending confirmation failed\n");
        goto err_close_producer_socket;
    }
    len = (size_t)recv_len;

    fprintf(stderr,
            "[consumer] Sent a confirmation to the producer (%zu bytes)\n",
            len);

    // allocate memory for IPC handle
    umf_ipc_handle_t IPC_handle = (umf_ipc_handle_t)calloc(1, size_IPC_handle);
    if (IPC_handle == NULL) {
        fprintf(stderr, "[consumer] ERROR: receiving the IPC handle failed\n");
        goto err_close_producer_socket;
    }

    // receive the IPC handle from the producer's
    recv_len = recv(producer_socket, IPC_handle, size_IPC_handle, 0);
    if (recv_len < 0) {
        fprintf(stderr, "[consumer] ERROR: receiving the IPC handle failed\n");
        goto err_free_IPC_handle;
    }
    len = (size_t)recv_len;

    if (len < size_IPC_handle) {
        fprintf(stderr,
                "[consumer] ERROR: receiving the IPC handle failed - received "
                "only %zu bytes (size of IPC handle is %zu bytes)\n",
                len, size_IPC_handle);
        goto err_free_IPC_handle;
    }

    fprintf(
        stderr,
        "[consumer] Received the IPC handle from the producer (%zi bytes)\n",
        len);

    void *SHM_ptr;
    umf_result = umfOpenIPCHandle(scalable_pool, IPC_handle, &SHM_ptr);
    if (umf_result == UMF_RESULT_ERROR_NOT_SUPPORTED) {
        fprintf(stderr,
                "[consumer] SKIP: opening the IPC handle is not supported\n");
        ret = 1; // SKIP

        // write the SKIP response to the send_buffer buffer
        strcpy(send_buffer, "SKIP");

        // send the SKIP response to the producer
        send(producer_socket, send_buffer, strlen(send_buffer) + 1, 0);

        goto err_free_IPC_handle;
    }
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "[consumer] ERROR: opening the IPC handle failed\n");
        goto err_free_IPC_handle;
    }

    fprintf(stderr,
            "[consumer] Opened the IPC handle received from the producer\n");

    // read the current value from the shared memory
    unsigned long long SHM_number_1 = *(unsigned long long *)SHM_ptr;
    fprintf(
        stderr,
        "[consumer] Read the number from the producer's shared memory: %llu\n",
        SHM_number_1);

    // calculate the new value
    unsigned long long SHM_number_2 = SHM_number_1 / 2;

    // write the new number directly to the producer's shared memory
    *(unsigned long long *)SHM_ptr = SHM_number_2;
    fprintf(stderr,
            "[consumer] Wrote a new number directly to the producer's shared "
            "memory: %llu\n",
            SHM_number_2);

    // write the response to the send_buffer buffer
    memset(send_buffer, 0, sizeof(send_buffer));
    strcpy(send_buffer, CONSUMER_MSG);

    // send response to the producer
    if (send(producer_socket, send_buffer, strlen(send_buffer) + 1, 0) < 0) {
        fprintf(stderr, "[consumer] ERROR: send() failed\n");
        goto err_CloseIPCHandle;
    }

    fprintf(stderr, "[consumer] Sent a response message to the producer\n");

    ret = 0; // SUCCESS

err_CloseIPCHandle:
    umf_result = umfCloseIPCHandle(SHM_ptr);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "[consumer] ERROR: closing the IPC handle failed\n");
    }

    fprintf(stderr,
            "[consumer] Closed the IPC handle received from the producer\n");

err_free_IPC_handle:
    free(IPC_handle);

err_close_producer_socket:
    close(producer_socket);

err_destroy_scalable_pool:
    umfPoolDestroy(scalable_pool);

err_destroy_OS_memory_provider:
    umfMemoryProviderDestroy(OS_memory_provider);

    if (ret == 0) {
        fprintf(stderr, "[consumer] Shutting down (status OK) ...\n");
    } else if (ret == 1) {
        fprintf(stderr, "[consumer] Shutting down (status SKIP) ...\n");
        ret = 0;
    } else {
        fprintf(stderr, "[consumer] Shutting down (status ERROR) ...\n");
    }

    return ret;
}
