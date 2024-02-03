/*
 * Copyright (c) 2015-2016, The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name of The Linux Foundation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This file was originally distributed by Qualcomm Atheros, Inc.
 * under proprietary terms before Copyright ownership was assigned
 * to the Linux Foundation.
 */

#ifndef DSRC_SOCK_H
#define DSRC_SOCK_H

#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <unistd.h>
#include <stdint.h>

/**
 * @file dsrc_sock.h
 * @brief Simplified socket interfaces for use with dsrc library.
 */

#include "dsrc_ocb.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup simplified_socket_interfaces
@{ */

/**
 * Opens a new socket and initializes the given sockaddr buffer.
 *
 * @param[in] iface_name Interface name to use, e.g., wlanocb0.
 * @param[out] socket On success, returns the socket descriptor. The caller must
 *        release this socket with close().
 * @param[out] sockaddr Given struct sockaddr_ll buffer, which will be initialized
 *        for subsequent use with bind() and sendto().
 *
 * @return
 * int returns 0 on success.
 * - EPERM -- socket() creation failed; check errno for further details.
 * - EAFNOSUPPORT -- Failed to find the interface.
 * - EACCES -- Failed to get the MAC address of the device.
 */
int dsrc_socket_open(const char* iface_name, int *socket,
                     struct sockaddr_ll *sockaddr);

/**
 * Closes the socket if it is open.
 *
 * @param[in] sock_fd Socket file descriptor
 *
 * @return
 * int
 */
static __inline
int dsrc_socket_closeif(int* sock_fd) {
    int rc = 0;
    int sock = *sock_fd;

    *sock_fd = -1;

    if (0 <= sock) {
        rc = close(sock);
    }
    return rc;
}

/**
 * Receives an Ethernet frame and optionally provides the
 * per-packet header, if present.
 *
 * @param[in] sock Socket from which to receive.
 * @param[in] buf Buffer for collecting the frame.
 * @param[in] len Length of the buffer; it must atleast be 0x600.
 * @param[in] flags Flag
 * @param[in] rx_stats Pointer to the Rx stats in buf.
 * @param[in] frame Pointer to the 802.3 frame in buf.
 * @param[in] frame_len Length of the frame.
 *
 * @return
 * ssize_t -ve value on error; on success, total bytes received
 * in buf.
 */
ssize_t dsrc_socket_recv_eth_frame_and_stats(int sock, uint8_t *buf, size_t len,
    int flags, struct dsrc_ocb_rx_stats_hdr** rx_stats,
    uint8_t** frame, ssize_t* frame_len);

/** @} */ /* end_addtogroup_simplified_socket_interfaces */

#ifdef __cplusplus
}
#endif
#endif /* !DSRC_SOCK_H */
