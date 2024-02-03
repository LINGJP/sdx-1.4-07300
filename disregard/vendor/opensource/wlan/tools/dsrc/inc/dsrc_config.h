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

/**
 * @file dsrc_config.h
 * @brief Prototypes for the dsrc_config APIs.
 *
 * Prototypes for the dsrc_config layer APIs. There is a method for each
 * DSRC control command.
 */

#ifndef DSRC_CONFIG_H
#define DSRC_CONFIG_H

#include "dsrc_dcc.h"
#include "dsrc_ocb.h"
#include <stdint.h>

#define OCB_CHANNEL_FLAG_DISABLE_RX_STATS_HDR	(1 << 0)

/** @addtogroup dsrc_config_apis
@{ */

/**
 * OCB channel information.
 *
 * This is used when configuring the host driver.
 */
typedef struct dsrc_ocb_config_channel {
    uint32_t chan_freq; /**< Channel center frequency in MHz. */
    uint32_t bandwidth; /**< Channel bandwidth in MHz (5, 10, or 20). */
    uint16_t flags; /**< Flags to be applied to this channel, such as OCB_CHANNEL_FLAG_DISABLE_RX_STATS_HDR. */
    uint8_t reserved[4]; /**< This must be 0. */
    struct dsrc_ocb_qos_params qos_params[DSRC_OCB_NUM_AC]; /**< QOS parameters. */
    uint32_t max_pwr; /**< Maximum allowed transmit power on this channel. */
    uint32_t min_pwr; /**< Minimum allowed transmit power on this channel. */
    uint32_t datarate; /** <Default TX data rate for this channel. */
    uint8_t mac_address[6]; /** < MAC address assigned for this channel used for Broadcast Frame. */
} dsrc_ocb_config_channel_t;

/** OCB schedule information.
 *
 *  This is used when configuring the host driver.
 */
typedef struct dsrc_ocb_config_sched {
    uint32_t chan_freq; /**< Channel center frequency. This must correspond to a configured channel. */
    uint32_t total_duration; /**< Total amount of time (including guard interval) to tune to this channel in ms. */
    uint32_t guard_interval; /**< Amount of time at the beginning of the interval to wait before transmitting. */
} dsrc_ocb_config_sched_t;

/** TSF timer composition. */
struct tsf_timer {
    uint32_t timer_high; /**< Most significant 4 bytes of the TSF. */
    uint32_t timer_low; /**< Least significant 4 bytes of the TSF. */
};

/** @} */ /* end_addtogroup dsrc_config_apis */

/** @addtogroup dsrc_config_apis
@{ */

/** Flag to indicate expiry time in TSF.
 *
 *  This flag is set if the expiry time in the Tx control header is to be
 *  interpreted as an absolute TSF time. If this flag is not set, the
 *  expiry time is interpreted as a relative time.
 */
#define OCB_CONFIG_FLAG_EXPIRY_TIME_IN_TSF	0x01

/** Flag to indicate 802.11 frame mode.
 *
 *  This flag if set if the user app will transmit 802.11 frames and will
 *  received 802.11 frames. If this flag is not set, the user app will
 *  send 802.3 frames and the FW will convert them to 802.11 frames,
 *  and the FW will receive 802.11 frames and convert them to 802.3 frames
 *  before propagating them to the user app.
 */
#define OCB_CONFIG_FLAG_80211_FRAME_MODE		0x02

/** @} */ /* end_addtogroup dsrc_config_apis */

/** @addtogroup dsrc_config_apis
@{ */

/**
 * Function: dsrc_channel_init
 * Description: Initialize DSRC channel parameters.
 * Input Parameters:
 *      params: dsrc_config_params structure to init.
 */
//void dsrc_channel_init(struct dsrc_config_params *params);

/**
 * Function: dsrc_channel_config_freq
 * Description: Set ocb channel frequence
 * Input parameters:
 *      chan: dsrc_chan structure for configuration.
 *      chan_num: ocb channel number to be used.
 * Return Value: 0 on success. -1 on failure.
 */
int dsrc_channel_config_freq(dsrc_ocb_config_channel_t *chan, int chan_num);

/**
 * Function: dsrc_channel_config_mac_address
 * Description: Assign MAC address for this ocb channel.
 *              It will be used SA in 80211 header for Broadcast Frame
 * Input Parameters:
 *      chan: dsrc_chan structure for configuration.
 *      mac_addr: MAC address to be set
 * Return Value: 0 on success. -1 on failure.
 */
int dsrc_channel_config_mac_address(dsrc_ocb_config_channel_t *chan, uint8_t *mac_addr);

/**
 * Function: dsrc_channel_config_datarate
 * Description: Set default datarate for this ocb channel.
 * Input Parameters:
 *      chan: dsrc_chan structure for configuration.
 *      datarate: mcs_index for datarate
 *              0:  6 MBPS
 *              1:  9 MBPS
 *              2: 12 MBPS
 *              3: 18 MBPS
 *              4: 24 MBPS
 *              5: 36 MBPS
 *              6: 48 MBPS
 *              7: 54 MBPS
 * Return Value: 0 on success. -1 on failure.
 */
int dsrc_channel_config_datarate(dsrc_ocb_config_channel_t *chan, int datarate);

/**
 * Sends a Set Config command and obtains a response via nl80211.
 *
 * @param[in] interface OCB interface name.
 * @param[in] num_channels Number of OCB channels.
 * @param[in] chan OCB channels information.
 * @param[in] ndl_chan DCC channels information.
 * @param[in] sched_size Channel schedule size.
 * @param[in] sched Channel schedule information.
 * @param[in] num_active_states Number of active states.
 * @param[in] state_cfg Active state array information.
 * @param[in] flags Configuration flags, such as OCB_CONFIG_FLAG_EXPIRY_TIME_IN_TSF.
 * @param[in] tx_ctrl_hdr default tx ctrl header parameter.
 * @param[in] ta_max_duration Max duration after last TA received.
 *
 * @return
 * Result of the command execution.
 */
int dsrc_ocb_set_config(char *interface, int num_channels,
    dsrc_ocb_config_channel_t *chan, dcc_ndl_chan *ndl_chan, int sched_size,
    dsrc_ocb_config_sched_t *sched, int num_active_states,
    dcc_ndl_active_state_config *state_cfg, unsigned int flags,
    struct dsrc_ocb_tx_ctrl_hdr *tx_ctrl_hdr, unsigned int ta_max_duration);

/**
 * Sends a DCC NDL update command via nl80211.
 *
 * @param[in] interface OCB interface name.
 * @param[in] num_channels Number of DCC channels.
 * @param[in] ndl_chan List of DCC channel information.
 * @param[in] num_active_states Number of active states.
 * @param[in] state_cfg Active state array.
 *
 * @return
 * Result of the command execution.
 */
int dsrc_ocb_dcc_ndl_update(char *interface, int num_channels,
    dcc_ndl_chan *ndl_chan, int num_active_states,
    dcc_ndl_active_state_config *state_cfg);

/**
 * Sends a DCC Get Stats command via nl80211 and prints the results.
 *
 * @param[in] interface OCB interface name.
 * @param[in] num_channels Number of DCC channels.
 * @param[in] stats_request Stats request array.
 *
 * @return
 * Result of the command execution.
 */
int dsrc_ocb_dcc_get_stats(char *interface, int num_channels,
                    dcc_channel_stats_request *stats_request);

/**
 * Enters a loop receiving DCC stats event messages and printing the stats.
 *
 * @param[in] interface OCB interface name.
 *
 * @return
 * None.
 */
void dsrc_ocb_dcc_stats_event(char *interface);

/**
 * Sends a DCC Clear Stats command via nl80211.
 *
 * @param[in] interface OCB interface name.
 * @param[in] dcc_stats_bitmap DCC stats bitmap.
 *
 * @return
 * Result of the command execution.
 */
int dsrc_ocb_dcc_clear_stats(char *interface, uint32_t dcc_stats_bitmap);

/**
 * Sends a get TSF Timer command and prints the timer value.
 *
 * @param[in] interface OCB interface name.
 *
 * @return
 * None.
 */
int dsrc_ocb_get_tsf_timer(char *interface);

/**
 * Enters a loop receiving VSA frames and printing the contents.
 *
 * @param[in] interface the OCB interface name
 *
 * @return
 * None.
 */
void dsrc_ocb_rx_vsa_frames(char *interface);

/**
 * Enters a loop receiving TA frames and printing the contents.
 *
 * @param[in] interface the OCB interface name
 *
 * @return
 * None.
 */
void dsrc_ocb_rx_ta_frames(char *interface);
/** @} */ /* end_addtogroup_dsrc_config_apis */

#endif /* DSRC_CONFIG_H */

