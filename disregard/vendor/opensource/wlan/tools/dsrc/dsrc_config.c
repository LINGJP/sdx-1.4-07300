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
 * @file dsrc_config.c
 * @brief Configuration commands for DSRC.
 *
 * Configuration commands are part of the 802.11p spec. This reads all the
 * user parameters for a control command, process those into a format exposed
 * by the dsrc_nl APIs and call nl80211 APIs that will do the actual
 * communication with the host driver.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>
#include "dsrc_nl.h"
#include "dsrc_util.h"

#define DCC_BITMAP_DEFAULT 0xff
#define TIME_ERROR_DEFAULT 0xff

#ifdef _ANDROID_
int getsubopt(char **optionp, char * const *tokens, char **valuep);
#endif

/**
 * @brief UTC time conversion constant.
 *
 * Number of seconds from Jan 1st 1958 to Jan 2nd 1970
 * This is needed to convert from the Linux UTC to 802.11
 * definition of UTC time
 */
#define SEC_1958_1970 378691200

#define DEFAULT_CONTROL_CHANNEL 5860
#define DEFAULT_SERVICE_CHANNEL 5900
#define DEFAULT_CCH_GUARD_MS 4
#define DEFAULT_SCH_GUARD_MS 4
#define DEFAULT_CCH_DURATION_MS 50
#define DEFAULT_SCH_DURATION_MS 50
#define DEFAULT_CCH_TX_POWER 17
#define DEFAULT_SCH_TX_POWER 17
#define DEFAULT_CCH_DATARATE 0
#define DEFAULT_SCH_DATARATE 0
#define DEFAULR_QOS_BE_AIFSN 6
#define DEFAULT_QOS_BE_CWMIN 4
#define DEFAULT_QOS_BE_CWMAX 10
#define DEFAULT_QOS_BK_AIFSN 9
#define DEFAULT_QOS_BK_CWMAX 10
#define DEFAULT_QOS_BK_CWMIN 4
#define DEFAULT_QOS_VI_AIFSN 3
#define DEFAULT_QOS_VI_CWMAX 4
#define DEFAULT_QOS_VI_CWMIN 3
#define DEFAULT_QOS_VO_AIFSN 2
#define DEFAULT_QOS_VO_CWMAX 4
#define DEFAULT_QOS_VO_CWMIN 2

#define OCB_HEADER_VERSION 1
#define MAX_DATARATE 7
#define MAX_TID 15

struct dsrc_channel {
    uint32_t frequency;
    uint32_t bandwidth;
    uint32_t datarate;
    uint32_t tx_power;
    uint32_t sched_duration;
    uint32_t sched_guard;
    uint8_t mac_address[6];
    uint16_t flags;
    struct dsrc_ocb_qos_params qos_params[DSRC_OCB_NUM_AC];
};

struct dsrc_config_params {
    char *cmd;
    char *interface;
    char *chan_opts;
    uint32_t num_channels;
    uint32_t enable_dcc;
    struct dsrc_channel channels[2];
    uint32_t repeat_rate;
    uint32_t flags;
    uint32_t max_duration;
};

/**
 * Prints the command line usage message.
 */
void dsrc_config_usage()
{
    printf("Usage: dsrc_config [-i <interface>] [-c <command>]\n");
    printf("    [-o <channel options>] [-d] [-r repeat rate>]\n");
    printf("Defaults: interface wlanocb0, channel 5860\n");
    printf("-c <command> : \n");
    printf("    set_config, ndl_update, get_stats, stats_event, \n");
    printf("    clear_stats, set_utc, start_ta, stop_ta, get_tsf, rx_vsa, rx_ta\n");
    printf("-o <channel options> : \n");
    printf("    Used for set_config, get_stats, start_ta and stop_ta. \n");
    printf("    num_channels={1|2} : \n");
    printf("       when 1 channel_freq0 and channel_bandwidth0 are needed.\n");
    printf("       when 2 same as 1, additionally freq1 and bandwidth1 are needed.\n");
    printf("    channel_freq0=<center frequency in MHz>\n");
    printf("    channel_bandwidth0=<bandwidth in MHz>\n");
    printf("    mac_address0=<xx:xx:xx:xx:xx:xx>\n");
    printf("    datarate0=<MCS index>\n");
    printf("       0:  6 MBPS\n");
    printf("       1:  9 MBPS\n");
    printf("       2: 12 MBPS\n");
    printf("       3: 18 MBPS\n");
    printf("       4: 24 MBPS\n");
    printf("       5: 36 MBPS\n");
    printf("       6: 48 MBPS\n");
    printf("       7: 54 MBPS\n");
    printf("    tx_power0=<max transmit power in dbm>\n");
    printf("    duration0=<channel schedule duration in ms>\n");
    printf("    guard0=<schedule start guard interval in ms>\n");
    printf("    disable_rx_stats0={0|1} : \n");
    printf("       when 0 (default) RX stats headers are added.\n");
    printf("       when 1 RX stats headers are not added.\n");
    printf("    channel_freq1=<center frequency in MHz>\n");
    printf("    channel_bandwidth1=<bandwidth in MHz>\n");
    printf("    tx_power1=<max transmit power on channel_freq1>\n");
    printf("    duration1=<channel schedule duration in ms>\n");
    printf("    guard1=<schedule start guard interval in ms>\n");
    printf("    disable_rx_stats1={0|1} : \n");
    printf("       when 0 (default) RX stats headers are added.\n");
    printf("       when 1 RX stats headers are not added.\n");
    printf("    expiry_tsf={0|1} : \n");
    printf("       when 0 (default) expiry time in TX options is relative.\n");
    printf("       when 1 expiry time in TX options is interpreted as a TSF time.\n");
    printf("    eth_mode={0|1} :\n");
    printf("       when 0 (default) the app must send 802.11 frames and firmware will not convert.\n");
    printf("       when 1 the firmware will convert 802.3 frames to 802.11.\n");
    printf("-d : \n");
    printf("    Enable DCC parameters if this option is present.\n");
    printf("    Used for the set_config command.\n");
    printf("-r <repeat rate> : \n");
    printf("    Number of times the TA frame will be sent in a 5 seconds interval.\n");
    printf("    Used for the start_ta command.\n");
    printf("-m <max duration> : \n");
    printf("    Max duration after last TA frame received that time is synced for scheduling channel switch.\n");
    printf("    Used for the set_config command.\n");
}

int dsrc_config_get_options(int argc, char *argv[],
    struct dsrc_config_params *params)
{
    int c;
    int rc = 0;

    /* defaults */
    params->interface = "wlanocb0";
    params->cmd = "set_config";

    while ((c = getopt(argc, argv, "c:i:o:df:r:m:h?")) != -1) {
        switch (c) {
            case 'c':
                params->cmd = optarg;
                break;
            case 'i':
                params->interface = optarg;
                break;
            case 'o':
                params->chan_opts = optarg;
                break;
            case 'd':
                params->enable_dcc = 1;
                break;
            case 'r':
                params->repeat_rate = strtoul(optarg, NULL, 10);
                break;
            case 'm':
                params->max_duration = strtoul(optarg, NULL, 10);
                break;
            case 'h':
            case '?':
            default:
                rc = -1;
                dsrc_config_usage();
                goto bail;
        }
    }

bail:
    return rc;
}

/**
 * Function: dsrc_channel_init
 * Description: Initialize DSRC channel parameters.
 * Input Parameters:
 *	params: dsrc_config_params structure to init.
 */

static void dsrc_channel_init(struct dsrc_config_params *params)
{
    params->num_channels = 1;
    params->flags = OCB_CONFIG_FLAG_80211_FRAME_MODE;

    params->channels[0].frequency = DEFAULT_CONTROL_CHANNEL;
    params->channels[0].bandwidth = 10;
    params->channels[0].datarate = DEFAULT_CCH_DATARATE;
    params->channels[0].sched_duration = DEFAULT_CCH_DURATION_MS;
    params->channels[0].sched_guard = DEFAULT_CCH_GUARD_MS;
    params->channels[0].tx_power = DEFAULT_CCH_TX_POWER;
    memset(params->channels[0].mac_address, 0, 6);
    params->channels[0].flags = 0;

    params->channels[0].qos_params[DSRC_OCB_AC_BE].aifsn = DEFAULR_QOS_BE_AIFSN;
    params->channels[0].qos_params[DSRC_OCB_AC_BE].cwmax = DEFAULT_QOS_BE_CWMAX;
    params->channels[0].qos_params[DSRC_OCB_AC_BE].cwmin = DEFAULT_QOS_BE_CWMIN;
    params->channels[0].qos_params[DSRC_OCB_AC_BK].aifsn = DEFAULT_QOS_BK_AIFSN;
    params->channels[0].qos_params[DSRC_OCB_AC_BK].cwmax = DEFAULT_QOS_BK_CWMAX;
    params->channels[0].qos_params[DSRC_OCB_AC_BK].cwmin = DEFAULT_QOS_BK_CWMIN;
    params->channels[0].qos_params[DSRC_OCB_AC_VI].aifsn = DEFAULT_QOS_VI_AIFSN;
    params->channels[0].qos_params[DSRC_OCB_AC_VI].cwmax = DEFAULT_QOS_VI_CWMAX;
    params->channels[0].qos_params[DSRC_OCB_AC_VI].cwmin = DEFAULT_QOS_VI_CWMIN;
    params->channels[0].qos_params[DSRC_OCB_AC_VO].aifsn = DEFAULT_QOS_VO_AIFSN;
    params->channels[0].qos_params[DSRC_OCB_AC_VO].cwmax = DEFAULT_QOS_VO_CWMAX;
    params->channels[0].qos_params[DSRC_OCB_AC_VO].cwmin = DEFAULT_QOS_VO_CWMIN;

    params->channels[1].frequency = DEFAULT_SERVICE_CHANNEL;
    params->channels[1].bandwidth = 10;
    params->channels[1].datarate = DEFAULT_SCH_DATARATE;
    params->channels[1].sched_duration = DEFAULT_SCH_DURATION_MS;
    params->channels[1].sched_guard = DEFAULT_SCH_GUARD_MS;
    params->channels[1].tx_power = DEFAULT_SCH_TX_POWER;
    memset(params->channels[1].mac_address, 0, 6);
    params->channels[1].flags = 0;

    params->channels[1].qos_params[DSRC_OCB_AC_BE].aifsn = DEFAULR_QOS_BE_AIFSN;
    params->channels[1].qos_params[DSRC_OCB_AC_BE].cwmax = DEFAULT_QOS_BE_CWMAX;
    params->channels[1].qos_params[DSRC_OCB_AC_BE].cwmin = DEFAULT_QOS_BE_CWMIN;
    params->channels[1].qos_params[DSRC_OCB_AC_BK].aifsn = DEFAULT_QOS_BK_AIFSN;
    params->channels[1].qos_params[DSRC_OCB_AC_BK].cwmax = DEFAULT_QOS_BK_CWMAX;
    params->channels[1].qos_params[DSRC_OCB_AC_BK].cwmin = DEFAULT_QOS_BK_CWMIN;
    params->channels[1].qos_params[DSRC_OCB_AC_VI].aifsn = DEFAULT_QOS_VI_AIFSN;
    params->channels[1].qos_params[DSRC_OCB_AC_VI].cwmax = DEFAULT_QOS_VI_CWMAX;
    params->channels[1].qos_params[DSRC_OCB_AC_VI].cwmin = DEFAULT_QOS_VI_CWMIN;
    params->channels[1].qos_params[DSRC_OCB_AC_VO].aifsn = DEFAULT_QOS_VO_AIFSN;
    params->channels[1].qos_params[DSRC_OCB_AC_VO].cwmax = DEFAULT_QOS_VO_CWMAX;
    params->channels[1].qos_params[DSRC_OCB_AC_VO].cwmin = DEFAULT_QOS_VO_CWMIN;
}

/**
 * Function: dsrc_channel_config_freq
 * Description: Set ocb channel frequence
 * Input parameters:
 *	chan: dsrc_chan structure for configuration.
 *	chan_num: ocb channel number to be used.
 * Return Value: 0 on success. -1 on failure.
 */
int dsrc_channel_config_freq(dsrc_ocb_config_channel_t *chan, int chan_num)
{
    int i, valid_chan_num = 0;
    int ocb_valid_channels[] = {
        172, 174, 175, 176,
        178, 180, 181, 182,
        184
    };

    if (chan == NULL)
        return -1;

    for (i = 0; i < sizeof(ocb_valid_channels) / sizeof(int); i++) {
        if (chan_num == ocb_valid_channels[i]) {
            valid_chan_num = 1;
            break;
        }
    }

    if (!valid_chan_num) {
        printf("invalid channel number %d\n", chan_num);
        return -1;
    }

    chan->chan_freq = 5000 + chan_num * 5;
    return 0;
}

/**
 * Function: dsrc_channel_config_mac_address
 * Description: Assign MAC address for this ocb channel.
 *		It will be used SA in 80211 header for Broadcast Frame
 * Input Parameters:
 *	chan: dsrc_chan structure for configuration.
 *	mac_addr: MAC address to be set
 * Return Value: 0 on success. -1 on failure.
 */
int dsrc_channel_config_mac_address(dsrc_ocb_config_channel_t *chan, uint8_t *mac_addr)
{
    if (chan == NULL || mac_addr == NULL)
        return -1;

    memcpy(chan->mac_address, mac_addr, 6);
    return 0;
}

/**
 * Function: dsrc_channel_config_datarate
 * Description: Set default datarate for this ocb channel.
 * Input Parameters:
 *	chan: dsrc_chan structure for configuration.
 *	datarate: mcs_index for datarate
 *		0:  6 MBPS
 *		1:  9 MBPS
 *		2: 12 MBPS
 *		3: 18 MBPS
 *		4: 24 MBPS
 *		5: 36 MBPS
 *		6: 48 MBPS
 *		7: 54 MBPS
 * Return Value: 0 on success. -1 on failure.
 */
int dsrc_channel_config_datarate(dsrc_ocb_config_channel_t *chan, int datarate)
{
    if (chan == NULL)
        return -1;

    if (datarate < 0 || datarate > 7) {
        printf("Invalid datarate index %d\n", datarate);
        return -1;
    }

    chan->datarate = datarate;
    return -1;
}

static int dsrc_parse_channel_options(struct dsrc_config_params *params)
{
    int rc = 0;
    enum {
        NUM_CHAN = 0,
        CHAN0, BW0, DATARATE0, PWR0, DUR0, GUARD0, MAC0, DISABLE_RX_STATS0,
        CHAN1, BW1, DATARATE1, PWR1, DUR1, GUARD1, MAC1, DISABLE_RX_STATS1,
        EXPIRY_TSF, ETH_MODE,
        THE_END
    };

    char *set_chan_opts[] = {
        [NUM_CHAN] = "num_channels",
        [CHAN0] = "channel_freq0",
        [BW0] = "channel_bandwidth0",
        [DATARATE0] = "datarate0",
        [PWR0] = "tx_power0",
        [DUR0] = "duration0",
        [GUARD0] = "guard0",
        [MAC0] = "mac_address0",
        [DISABLE_RX_STATS0] = "disable_rx_stats0",
        [CHAN1] = "channel_freq1",
        [BW1] = "channel_bandwidth1",
        [DATARATE1] = "datarate1",
        [PWR1] = "tx_power1",
        [DUR1] = "duration1",
        [GUARD1] = "guard1",
        [MAC1] = "mac_address1",
        [DISABLE_RX_STATS1] = "disable_rx_stats1",
        [EXPIRY_TSF] = "expiry_tsf",
        [ETH_MODE] = "eth_mode",
        [THE_END] = NULL
    };

    char *value;
    dsrc_channel_init(params);

    while (params->chan_opts && *(params->chan_opts) != '\0') {
        switch (getsubopt(&params->chan_opts, set_chan_opts, &value)) {
        case NUM_CHAN:
            if (value == NULL) {
                printf("Missing value for suboption '%s'\n",
                       set_chan_opts[NUM_CHAN]);
                break;
            }
            params->num_channels = strtol(value, NULL, 10);
            break;
        case CHAN0:
            if (value == NULL) {
                printf("Missing value for suboption '%s'\n",
                       set_chan_opts[CHAN0]);
                break;
            }
            params->channels[0].frequency = strtol(value, NULL, 10);
            break;
        case CHAN1:
            if (value == NULL) {
                printf("Missing value for suboption '%s'\n",
                       set_chan_opts[CHAN1]);
                break;
            }
            params->channels[1].frequency = strtol(value, NULL, 10);
            break;
        case BW0:
            if (value == NULL) {
                printf("Missing value for suboption '%s'\n",
                       set_chan_opts[BW0]);
                break;
            }
            params->channels[0].bandwidth = strtol(value, NULL, 10);
            break;
        case BW1:
            if (value == NULL) {
                printf("Missing value for suboption '%s'\n",
                       set_chan_opts[BW1]);
                break;
            }
            params->channels[1].bandwidth = strtol(value, NULL, 10);
            break;
        case DATARATE0:
            if (value == NULL) {
                printf("Missing value for suboption '%s'\n",
                       set_chan_opts[DATARATE0]);
                break;
            }
            params->channels[0].datarate = strtol(value, NULL, 10);
            break;
        case DATARATE1:
            if (value == NULL) {
                printf("Missing value for suboption '%s'\n",
                       set_chan_opts[DATARATE1]);
                break;
            }
            params->channels[1].datarate = strtol(value, NULL, 10);
            break;
        case PWR0:
            if (value == NULL) {
                printf("Missing value for suboption '%s'\n",
                       set_chan_opts[PWR0]);
                break;
            }
            params->channels[0].tx_power = strtol(value, NULL, 10);
            break;
        case PWR1:
            if (value == NULL) {
                printf("Missing value for suboption '%s'\n",
                       set_chan_opts[PWR1]);
                break;
            }
            params->channels[1].tx_power = strtol(value, NULL, 10);
            break;
        case DUR0:
            if (value == NULL) {
                printf("Missing value for suboption '%s'\n",
                       set_chan_opts[DUR0]);
                break;
            }
            params->channels[0].sched_duration = strtol(value, NULL, 10);
            break;
        case DUR1:
            if (value == NULL) {
                printf("Missing value for suboption '%s'\n",
                       set_chan_opts[DUR1]);
                break;
            }
            params->channels[1].sched_duration = strtol(value, NULL, 10);
            break;
        case GUARD0:
            if (value == NULL) {
                printf("Missing value for suboption '%s'\n",
                       set_chan_opts[GUARD0]);
                break;
            }
            params->channels[0].sched_guard = strtol(value, NULL, 10);
            break;
        case GUARD1:
            if (value == NULL) {
                printf("Missing value for suboption '%s'\n",
                       set_chan_opts[GUARD1]);
                break;
            }
            params->channels[1].sched_guard = strtol(value, NULL, 10);
            break;
        case MAC0:
            dsrc_mac_string_to_hex(params->channels[0].mac_address, value);
            break;
        case MAC1:
            dsrc_mac_string_to_hex(params->channels[1].mac_address, value);
            break;
        case DISABLE_RX_STATS0:
            if (value == NULL) {
                printf("Missing value for suboption '%s'\n",
                       set_chan_opts[DISABLE_RX_STATS0]);
                break;
            }

            if (strtol(value, NULL, 10))
                 params->channels[0].flags |=
                     OCB_CHANNEL_FLAG_DISABLE_RX_STATS_HDR;
            else
                 params->channels[0].flags &=
                     ~OCB_CHANNEL_FLAG_DISABLE_RX_STATS_HDR;
            break;
        case DISABLE_RX_STATS1:
            if (value == NULL) {
                printf("Missing value for suboption '%s'\n",
                       set_chan_opts[DISABLE_RX_STATS1]);
                break;
            }

            if (strtol(value, NULL, 10))
                 params->channels[1].flags |=
                     OCB_CHANNEL_FLAG_DISABLE_RX_STATS_HDR;
            else
                 params->channels[1].flags &=
                     ~OCB_CHANNEL_FLAG_DISABLE_RX_STATS_HDR;
            break;
        case EXPIRY_TSF:
            if (value == NULL) {
                printf("Missing value for suboption '%s'\n",
                       set_chan_opts[EXPIRY_TSF]);
                break;
            }
            if (strtol(value, NULL, 10))
                params->flags |= OCB_CONFIG_FLAG_EXPIRY_TIME_IN_TSF;
            else
                params->flags &= ~OCB_CONFIG_FLAG_EXPIRY_TIME_IN_TSF;
            break;
        case ETH_MODE:
            if (value == NULL) {
                printf("Missing value for suboption '%s'\n",
                       set_chan_opts[ETH_MODE]);
                break;
            }

            if (strtol(value, NULL, 10))
                params->flags &= ~OCB_CONFIG_FLAG_80211_FRAME_MODE;
            else
                params->flags |= OCB_CONFIG_FLAG_80211_FRAME_MODE;
            break;
        default:
            rc = -1;
            dsrc_config_usage();
            goto bail;
        }
    }

bail:
    return rc;
}

int dsrc_set_config(char *interface, unsigned char num_channels,
    struct dsrc_channel channels[2], int enable_dcc, unsigned int flags, unsigned int ta_max_duration)
{
    dsrc_ocb_config_channel_t chan[2] = { {0} };
    dsrc_ocb_config_sched_t sched[2] = { {0} };
    struct dsrc_ocb_tx_ctrl_hdr tx_ctrl_hdr[2] = { {0} };
    dcc_ndl_chan *dcc_chan = NULL;
    dcc_ndl_active_state_config *state_cfg = NULL;
    unsigned char num_active_states = 0;
    unsigned char num_dcc_channels = 0;
    unsigned char i = 0;

    /* Convert to host driver structs */
    chan[0].chan_freq = channels[0].frequency;
    chan[0].bandwidth = channels[0].bandwidth;
    chan[0].max_pwr = channels[0].tx_power;
    chan[0].min_pwr = 6;
    chan[0].flags = channels[0].flags;
    chan[0].datarate = (channels[0].datarate <= MAX_DATARATE) ?
                    channels[0].datarate : DEFAULT_CCH_DATARATE;
    memcpy(chan[0].mac_address, channels[0].mac_address, 6);
    sched[0].chan_freq = channels[0].frequency;
    sched[0].total_duration = channels[0].sched_duration;
    sched[0].guard_interval = channels[0].sched_guard;

    chan[0].qos_params[DSRC_OCB_AC_BE].aifsn =
        channels[0].qos_params[DSRC_OCB_AC_BE].aifsn;
    chan[0].qos_params[DSRC_OCB_AC_BE].cwmax =
        channels[0].qos_params[DSRC_OCB_AC_BE].cwmax;
    chan[0].qos_params[DSRC_OCB_AC_BE].cwmin =
        channels[0].qos_params[DSRC_OCB_AC_BE].cwmin;
    chan[0].qos_params[DSRC_OCB_AC_BK].aifsn =
        channels[0].qos_params[DSRC_OCB_AC_BK].aifsn;
    chan[0].qos_params[DSRC_OCB_AC_BK].cwmax =
        channels[0].qos_params[DSRC_OCB_AC_BK].cwmax;
    chan[0].qos_params[DSRC_OCB_AC_BK].cwmin =
        channels[0].qos_params[DSRC_OCB_AC_BK].cwmin;
    chan[0].qos_params[DSRC_OCB_AC_VI].aifsn =
        channels[0].qos_params[DSRC_OCB_AC_VI].aifsn;
    chan[0].qos_params[DSRC_OCB_AC_VI].cwmax =
        channels[0].qos_params[DSRC_OCB_AC_VI].cwmax;
    chan[0].qos_params[DSRC_OCB_AC_VI].cwmin =
        channels[0].qos_params[DSRC_OCB_AC_VI].cwmin;
    chan[0].qos_params[DSRC_OCB_AC_VO].aifsn =
        channels[0].qos_params[DSRC_OCB_AC_VO].aifsn;
    chan[0].qos_params[DSRC_OCB_AC_VO].cwmax =
        channels[0].qos_params[DSRC_OCB_AC_VO].cwmax;
    chan[0].qos_params[DSRC_OCB_AC_VO].cwmin =
        channels[0].qos_params[DSRC_OCB_AC_VO].cwmin;

    chan[1].qos_params[DSRC_OCB_AC_BE].aifsn =
        channels[1].qos_params[DSRC_OCB_AC_BE].aifsn;
    chan[1].qos_params[DSRC_OCB_AC_BE].cwmax =
        channels[1].qos_params[DSRC_OCB_AC_BE].cwmax;
    chan[1].qos_params[DSRC_OCB_AC_BE].cwmin =
        channels[1].qos_params[DSRC_OCB_AC_BE].cwmin;
    chan[1].qos_params[DSRC_OCB_AC_BK].aifsn =
        channels[1].qos_params[DSRC_OCB_AC_BK].aifsn;
    chan[1].qos_params[DSRC_OCB_AC_BK].cwmax =
        channels[1].qos_params[DSRC_OCB_AC_BK].cwmax;
    chan[1].qos_params[DSRC_OCB_AC_BK].cwmin =
        channels[1].qos_params[DSRC_OCB_AC_BK].cwmin;
    chan[1].qos_params[DSRC_OCB_AC_VI].aifsn =
        channels[1].qos_params[DSRC_OCB_AC_VI].aifsn;
    chan[1].qos_params[DSRC_OCB_AC_VI].cwmax =
        channels[1].qos_params[DSRC_OCB_AC_VI].cwmax;
    chan[1].qos_params[DSRC_OCB_AC_VI].cwmin =
        channels[1].qos_params[DSRC_OCB_AC_VI].cwmin;
    chan[1].qos_params[DSRC_OCB_AC_VO].aifsn =
        channels[1].qos_params[DSRC_OCB_AC_VO].aifsn;
    chan[1].qos_params[DSRC_OCB_AC_VO].cwmax =
        channels[1].qos_params[DSRC_OCB_AC_VO].cwmax;
    chan[1].qos_params[DSRC_OCB_AC_VO].cwmin =
        channels[1].qos_params[DSRC_OCB_AC_VO].cwmin;


    chan[1].chan_freq = channels[1].frequency;
    chan[1].bandwidth = channels[1].bandwidth;
    chan[1].max_pwr = channels[1].tx_power;
    chan[1].min_pwr = 6;
    chan[1].flags = channels[1].flags;
    chan[1].datarate = (channels[1].datarate <= MAX_DATARATE) ?
                    channels[1].datarate : DEFAULT_SCH_DATARATE;
    memcpy(chan[1].mac_address, channels[1].mac_address, 6);
    sched[1].chan_freq = channels[1].frequency;
    sched[1].total_duration = channels[1].sched_duration;
    sched[1].guard_interval = channels[1].sched_guard;

    /* Get NDL */
    if (enable_dcc) {
        dcc_get_config(&num_dcc_channels, &dcc_chan, &num_active_states,
                       &state_cfg);
        if (num_dcc_channels < num_channels) {
            printf("DCC enabled but NDL not provided\n");
            return -1;
        }
    }

    /* Set default TX ctrl Header*/
    for (i = 0; i < num_channels; i++) {
        tx_ctrl_hdr[i].version = OCB_HEADER_VERSION;
        tx_ctrl_hdr[i].length = sizeof(struct dsrc_ocb_tx_ctrl_hdr);
        tx_ctrl_hdr[i].channel_freq = chan[i].chan_freq;
        tx_ctrl_hdr[i].pwr = chan[i].max_pwr;
        tx_ctrl_hdr[i].flags.b.valid_pwr = 1;
        tx_ctrl_hdr[i].datarate = chan[i].datarate;
        tx_ctrl_hdr[i].flags.b.valid_datarate = 1;
    }

    /* Pass NDL chan and active states down. */
    return dsrc_ocb_set_config(interface, num_channels, chan, dcc_chan,
        num_channels, sched, num_active_states, state_cfg, flags,
        tx_ctrl_hdr, ta_max_duration);
}

int dsrc_update_ndl(char *interface)
{
    dcc_ndl_chan *dcc_chan;
    dcc_ndl_active_state_config *state_cfg;
    unsigned char num_channels, num_active_states;

    /*  Get NDL */
    dcc_get_config(&num_channels, &dcc_chan, &num_active_states, &state_cfg);

    /* Pass NDL chan and active states down. */
    return dsrc_ocb_dcc_ndl_update(interface, num_channels, dcc_chan,
        num_active_states, state_cfg);
}

int dsrc_get_stats(char *interface, uint32_t chan_freq1, uint32_t chan_freq2)
{
    unsigned int num_channels = 1;
    dcc_channel_stats_request stats_request[2];

    stats_request[0].chan_freq = chan_freq1;
    stats_request[0].dcc_stats_bitmap = DCC_BITMAP_DEFAULT;

    if (chan_freq2 != 0) {
        num_channels = 2;
        stats_request[1].chan_freq = chan_freq2;
        stats_request[1].dcc_stats_bitmap = DCC_BITMAP_DEFAULT;
    }

    return dsrc_ocb_dcc_get_stats(interface, num_channels, &stats_request[0]);
}

void dsrc_dcc_stats_event(char *interface)
{
    dsrc_ocb_dcc_stats_event(interface);
}

int dsrc_clear_stats(char *interface)
{
    return dsrc_ocb_dcc_clear_stats(interface, DCC_BITMAP_DEFAULT);
}

int dsrc_get_tsf_timer(char *interface)
{
    return dsrc_ocb_get_tsf_timer(interface);
}

int dsrc_set_utc_time(char *interface)
{
    uint8_t time_value[DSRC_OCB_UTC_TIME_LEN];
    uint8_t time_error[DSRC_OCB_UTC_TIME_ERROR_LEN];
    /* This is the UTC time in seconds from Jan 1st, 1958 */
    uint64_t seconds;
    uint64_t *time_ptr;

    /* Time error as sequence of 1s means it is undetermined */
    memset(time_error, TIME_ERROR_DEFAULT, DSRC_OCB_UTC_TIME_ERROR_LEN);

    /* Initialize time value */
    memset(time_value, 0, DSRC_OCB_UTC_TIME_LEN);

    /* UTC time is the number of nanoseconds since Jan 1st 1958 */
    seconds = (uint64_t)time(NULL);
    seconds += SEC_1958_1970;
    time_ptr = (uint64_t*)time_value;
    /* UTC time in IEEE spec is set in nanoseconds */
    *time_ptr = seconds*1000000;

    return dsrc_ocb_set_utc_time(interface, time_value, time_error);
}

int dsrc_start_timing_advert(char *interface, uint32_t chan_freq,
    uint32_t repeat_rate)
{
    return dsrc_ocb_start_timing_advert(interface, chan_freq, repeat_rate);
}

int dsrc_stop_timing_advert(char *interface, uint32_t chan_freq)
{
    return dsrc_ocb_stop_timing_advert(interface, chan_freq);
}

void dsrc_rx_vsa_frames(char *interface)
{
    dsrc_ocb_rx_vsa_frames(interface);
}

void dsrc_rx_ta_frames(char *interface)
{
    dsrc_ocb_rx_ta_frames(interface);
}

int main(int argc, char **argv)
{
    struct dsrc_config_params params = {0};
    int rc = -1;

    /* Process command line options */
    rc = dsrc_config_get_options(argc, argv, &params);
    if (rc) {
        goto exit;
    }

    /* Parse the channel options */
    rc = dsrc_parse_channel_options(&params);
    if (rc) {
        goto exit;
    }

    if (!strcmp(params.cmd, "set_config"))
        rc = dsrc_set_config(params.interface, params.num_channels,
            params.channels, params.enable_dcc, params.flags, params.max_duration);
    else if (!strcmp(params.cmd, "set_utc"))
        rc = dsrc_set_utc_time(params.interface);
    else if (!strcmp(params.cmd, "start_ta"))
        rc = dsrc_start_timing_advert(params.interface,
            params.channels[0].frequency, params.repeat_rate);
    else if (!strcmp(params.cmd, "stop_ta"))
        rc = dsrc_stop_timing_advert(params.interface,
            params.channels[0].frequency);
    else if (!strcmp(params.cmd, "ndl_update"))
        rc = dsrc_update_ndl(params.interface);
    else if (!strcmp(params.cmd, "get_stats"))
        rc = dsrc_get_stats(params.interface, params.channels[0].frequency,
            params.channels[1].frequency);
    else if (!strcmp(params.cmd, "stats_event"))
        dsrc_dcc_stats_event(params.interface);
    else if (!strcmp(params.cmd, "clear_stats"))
        rc = dsrc_clear_stats(params.interface);
    else if (!strcmp(params.cmd, "get_tsf"))
        rc = dsrc_get_tsf_timer(params.interface);
    else if (!strcmp(params.cmd, "rx_vsa"))
        dsrc_rx_vsa_frames(params.interface);
    else if (!strcmp(params.cmd, "rx_ta"))
        dsrc_rx_ta_frames(params.interface);
    else
        dsrc_config_usage();

    if (rc) {
        printf("Error executing command, ret=%d\n", rc);
    } else {
        printf("Success executing command\n");
    }

exit:
    return rc;
}
