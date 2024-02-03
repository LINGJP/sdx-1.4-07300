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
#ifndef DSRC_OCB_H
#define DSRC_OCB_H

#include <stdint.h>

/**
 * @file dsrc_ocb.h
 * @brief OCB per-packet data headers.
 */

#define PACKED __attribute__ ((packed))

/** @addtogroup ocb_per_packet_data_headers
@{ */

/** @name
@{
This section describes the OCB per-packet data headers.

<b>UTC Time Macros</b>
*/

/** Size of the UTC time in bytes. */
#define DSRC_OCB_UTC_TIME_LEN (10)
/** Size of the UTC time error in bytes. */
#define DSRC_OCB_UTC_TIME_ERROR_LEN (5)

/** @} */ /* end_namegroup */

/**
 These values can be used in the data rate field of the Tx control header.

 This table shows the data rates yield in the context of a 20 Mhz bandwidth
 channel. Data rate yields will be proportionally lower in the context of
 10 MHz and 5 Mhz bandwidth channels. @vertspace{8}

| VALUE   |  DATA RATE (mbps)  |  MODULATION | CODING RATE |
|:-------:|:------------------:|:-----------:|:-----------:|
| 0       |  6                 |  BPSK       | 1/2         |
| 1       |  9                 |  BPSK       | 3/4         |
| 2       |  12                |  QPSK       | 1/2         |
| 3       |  18                |  QPSK       | 3/4         |
| 4       |  24                |  16-QAM     | 1/2         |
| 5       |  36                |  16-QAM     | 3/4         |
| 6       |  48                |  64-QAM     | 1/2         |
| 7       |  54                |  64-QAM     | 3/4         |
@vertspace{8}
For example, a value of 2 on a 10 Mhz bandwidth will result in a 6 Mbps data rate.
*/
enum dsrc_ocb_ofdm_datarate {
    dsrc_ocb_ofdm_datarate_6_mbps = 0,   /**< OCB OFDM data rate = 6 Mbps. */
    dsrc_ocb_ofdm_datarate_9_mbps = 1,   /**< OCB OFDM data rate = 9 Mbps. */
    dsrc_ocb_ofdm_datarate_12_mbps = 2,  /**< OCB OFDM data rate = 12 Mbps. */
    dsrc_ocb_ofdm_datarate_18_mbps = 3,  /**< OCB OFDM data rate = 18 Mbps. */
    dsrc_ocb_ofdm_datarate_24_mbps = 4,  /**< OCB OFDM data rate = 24 Mbps. */
    dsrc_ocb_ofdm_datarate_36_mbps = 5,  /**< OCB OFDM data rate = 36 Mbps. */
    dsrc_ocb_ofdm_datarate_48_mbps = 6,  /**< OCB OFDM data rate = 48 Mbps. */
    dsrc_ocb_ofdm_datarate_54_mbps = 7,  /**< OCB OFDM data rate = 54 Mbps. */
    dsrc_ocb_ofdm_datarate_max = 7,
};

/**
Tx control header.

When sending an OCB packet, the user application has
the option of including the following struct following an Ethernet header
with the proto field set to 0x8151. This struct includes various Tx
paramaters including, the Tx power and datarate.
*/
struct dsrc_ocb_tx_ctrl_hdr {
    uint16_t version;
    /**< Version; must be 1. */
    uint16_t length;
    /**< Length of this structure. */
    uint16_t channel_freq;
    /**< Center frequency for the packet. */

    /** Flags. */
    union {
        /** A convenient structure of all the flags. */
        struct {
            uint16_t
                valid_pwr:            1,
                /**< Bit 0; if set, the Tx power specification is valid. */
                valid_datarate:       1,
                /**< Bit 1; if set, the Tx MCS mask specification is valid. */
                valid_retries:        1,
                /**< Bit 2; if set, the Tx retries specification is valid. */
                valid_chain_mask:     1,
                /**< Bit 3; if set, the chain mask is valid. */
                valid_expire_tsf:     1,
                /**< Bit 4; if set, the Tx expire TSF specification is valid. */
                valid_tid:            1,
                /**< Bit 5; if set, TID is valid. */
                valid_eth_mode:       1,
                /**< Bit 6; if set, packet with 802.3 header. or 802.11 header */
                reserved0_15_7:       9;
                /**< Bits 15:6; unused, set to 0x0. */
        } b;
        /* the union of all flags */
        uint16_t all_flags;
    } flags;

    uint32_t expire_tsf_lo;
    /**< Tx expiry time (TSF) LSBs. */

    uint32_t expire_tsf_hi;
    /**< Tx expiry time (TSF) MSBs. */

    int8_t pwr;
    /**< Specify at what power the Tx frame needs to be transmitted.
     * The power, a signed (twos complement) value, is in units of 0.5 dBm.
     * The value must be appropriately sign-extended when extracting
     * the value from the message and storing it in a variable that is
     * larger than A_INT8.
     * If the transmission uses multiple Tx chains, this power specification
     * is the total transmit power, assuming an incoherent combination of
     * per-chain power to produce the total power. */

    uint8_t datarate;
    /**< The desired modulation and coding scheme. \n
     * See enum #dsrc_ocb_ofdm_datarate. */

    uint8_t retry_limit;
    /**< Specify the maximum number of transmissions, including the
     * initial transmission, to attempt before giving up if no ACK
     * is received.
     * If the Tx rate is specified, all retries must use the
     * same rate as the initial transmission.
     * If no Tx rate is specified, the target can choose whether to
     * retain the original rate during the retransmissions or to
     * fall back to a more robust rate. */

    uint8_t chain_mask;
    /**< Specify from which chains to transmit. */

    uint8_t ext_tid;
    /**< Extended traffic ID (0-15). */

    uint8_t reserved[3];
    /**< This is to ensure that the size of the structure is a multiple of 4. */
} PACKED;

/**
 * Rx stats header
 *
 * When receiving an OCB packet, the Rx stats are sent to the user application
 * so that the user application can do processing based on the Rx stats.
 * This structure is preceded by an Ethernet header with
 * the proto field set to 0x8152. This struct includes various Rx
 * paramaters, including RSSI, data rate, and center frequency.
 *
 * RSSI = Power - NF(Noise Floor), so we can get Power = RSSI + NF.
 */
struct dsrc_ocb_rx_stats_hdr {
    uint16_t version;
    /**< Version; must be 1. */
    uint16_t length;
    /**< Length of this structure. */
    uint16_t channel_freq;
    /**< Center frequency for the packet. */
    int16_t rssi_cmb;
    /**< Combined received signal strength indicator (RSSI) from all chains. */
    int16_t rssi[4];
    /**< RSSI for chains 0 through 3 (for 20 MHz bandwidth). */
    int8_t noise_floor[4];
    /**< Noise floor for chain 0-3, only chain0/1 valid for DSRC. */
    uint32_t tsf32;
    /**< Timestamp in TSF units. */
    uint32_t timestamp_microsec;
    /**< Timestamp in microseconds. */
    uint8_t datarate;
    /**< Modulation and coding scheme index of the received signal. \n
     *   See enum #dsrc_ocb_ofdm_datarate. */
    uint8_t timestamp_submicrosec;
    /**< Submicrosecond portion of the timestamp. */
    uint8_t ext_tid;
    /**< Extended Traffic ID (TID) of the received signal. */
    uint8_t reserved;
    /**< This ensures that the size of the structure is a multiple of 4 */
} PACKED;

/** @name OCB Access Class Macros
@{ */

#define DSRC_OCB_AC_BE  0     /**< Best effort access class for EDCA. */
#define DSRC_OCB_AC_BK  1     /**< Background access class for EDCA. */
#define DSRC_OCB_AC_VI  2     /**< Video access class for EDCA. */
#define DSRC_OCB_AC_VO  3     /**< Voice access class for EDCA. */

#define DSRC_OCB_NUM_AC 4     /**< Number of access classes. */

/** @} */ /* end_namegroup */

/**
 * Achieve EDCA priority QOS scheme as described in 802.11.
 *
 * Members provide the Arbitration Inter-Frame Spacing Number (AIFSN), and
 * Contention Window minimum (CWmin) and maximum (CWmax) settings.
 */
struct dsrc_ocb_qos_params {
    uint8_t aifsn;   /**< AIFSN parameters. Range: 2 to 15 .*/
    uint8_t cwmin;   /**< CWmin in exponential form. Range: 1 to 10. */
    uint8_t cwmax;   /**< CWmax in exponential form. Range: 1 to 10. */
};

/** @name OCB Access Class Macros
@{ */

/** Maximum number of channels for struct dsrc_ocb_sched.
 */
#define DSRC_OCB_CHANNEL_MAX 5

/** @} */ /* end_namegroup */

/**
 * DEPRECATED
 *
 * Channel description for OCB communications.
 */
struct dsrc_ocb_channel {
    uint32_t channel_freq;           /**< Channel center frequency (MHz). */
    uint32_t duration;               /**< Channel duration (ms). */
    uint32_t start_guard_interval;   /**< Start guard interval (ms). */
    uint32_t channel_bandwidth;      /**< Channel bandwidth as MHz (e.g., 5, 10, 20, 40). */
    uint32_t tx_power;               /**< Maximum Tx power (dBm) allowed. */
    uint32_t tx_rate;                /**< Tx data rate (mbit). */
    struct dsrc_ocb_qos_params qos_params[DSRC_OCB_NUM_AC]; /**< EDCA parameters as described
                                                                 by 802.11 for OCB operations. */
    uint32_t reserved;               /**< This must be 0. */
};

/**
 * DEPRECATED
 *
 * Channel scheduling information.
 */
struct dsrc_ocb_sched {
    uint32_t num_channels;           /**< Number of channels in the array channels[]. */
    struct dsrc_ocb_channel channels[DSRC_OCB_CHANNEL_MAX]; /**< Channels array. */
    uint32_t reserved;               /**< This must be 0. */
};

#ifdef __cplusplus
extern "C" {
#endif

/**
 * DEPRECATED. Use dsrc_ocb_set_config instead.
 *
 * Set the DSRC channel scheduler parameters.
 *
 * @param[in] interface Interface name.
 * @param[in] schedule Schedule parameters.
 * @return
 * 0 on success; negative value on failure.
 */
int dsrc_ocb_set_schedule(char *interface, struct dsrc_ocb_sched *schedule);

/**
 * Sets the UTC time for use with timing advertisement.
 *
 * @param[in] interface OCB interface name.
 * @param[in] time_value UTC time as a 10-byte value.
 * @param[in] time_error 5-byte time error as specified in 802.11p.
 *                   An estimate of error in time_value.
 * @return
 * Result of the command execution.
 */
int dsrc_ocb_set_utc_time(char *interface,
                          uint8_t time_value[DSRC_OCB_UTC_TIME_LEN],
                          uint8_t time_error[DSRC_OCB_UTC_TIME_ERROR_LEN]);

/**
 * Starts sending a time advertisement on a given channel and rate.
 *
 * @param[in] interface OCB interface name.
 * @param[in] channel_freq Channel frequency on which to send the TA frames.
 *                     This must be the channel already scheduled using
 *                     dsrc_ocb_set_schedule().
 * @param[in] repeat_rate Number of times to send the frames in a 5 second interval.
 *
 * @return
 * 0 on success; negative value on failure.
 */
int dsrc_ocb_start_timing_advert(char *interface, uint32_t channel_freq,
                                 uint32_t repeat_rate);

/**
 * Stops time advertisement on a given channel.
 *
 * @param[in] interface OCB interface name.
 * @param[in] channel_freq Channel frequency on which to stop sending TA frames.
 *
 * @return
 * Result of the command execution.
 */
int dsrc_ocb_stop_timing_advert(char *interface, uint32_t channel_freq);

/** @} */ /* end_addtogroup_ocb_per_packet_data_headers */

#ifdef __cplusplus
}
#endif

#endif /* DSRC_OCB_H */

