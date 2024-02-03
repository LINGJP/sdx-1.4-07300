/*
 * Copyright (c) 2014-2016, The Linux Foundation. All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "dsrc_ocb.h"

#define DEFAULT_CONTROL_CHANNEL 5860
#define DEFAULT_SERVICE_CHANNEL 5900

#define DEFAULT_CCH_GUARD_MS 4
#define DEFAULT_SCH_GUARD_MS 4

#define DEFAULT_CCH_DURATION_MS 50
#define DEFAULT_SCH_DURATION_MS 50

#define DEFAULT_CCH_TX_POWER 17
#define DEFAULT_SCH_TX_POWER 17

#ifndef getsubopt
int getsubopt(char **optionp, char * const *tokens, char **valuep);
#endif

/*******************************************************************************
 * Usage message
 ******************************************************************************/
static
void dsrc_chan_usage(void)
{
    printf("Usage: dsrc_set_chan [-i <interface>] [-c <channel frequency>]\n");
    printf("    [-c <channel options>]\n");
    printf("Defaults: interface wlanocb0, channel 5860\n");
    printf("-c <channel options> : \n");
    printf("    num_channels={1|2} : \n");
    printf("       when 1 channel_freq0 and channel_bandwidth0 are needed.\n");
    printf("       when 2 same as 1, additionally freq1 and bandwidth1 are needed.\n");
    printf("    channel_freq0=<center frequency in MHz>\n");
    printf("    channel_bandwidth0=<bandwidth in MHz>\n");
    printf("    tx_power0=<max transmit power in dbm>\n");
    printf("    channel_freq1=<center frequency in MHz>\n");
    printf("    channel_bandwidth1=<bandwidth in MHz>\n");
    printf("    tx_power1=<max transmit power on channel_freq1>\n");
}

/*******************************************************************************
 * break the command arguments in to params.
 *
 * @param argc
 * @param argv
 * @param interface
 * @param chan_opts
 *
 * @return int
 ******************************************************************************/
static
int dsrc_chan_getopts(int argc, char *argv[], char **interface, char** chan_opts)
{
    int c;
    int rc = 0;

    /* defaults */
    *interface = "wlanocb0";
    *chan_opts = NULL;

    while ((c = getopt(argc, argv, "i:c:h?")) != -1) {
        switch(c) {
        case 'c':
            *chan_opts = optarg;
            break;
        case 'i':
            *interface = optarg;
            break;
        case 'h':
        case '?':
        default:
            rc = -1;
            dsrc_chan_usage();
            goto bail;
        }
    }

  bail:
    return rc;
}

/*******************************************************************************
 * initialize the schedule settings to accomodate up to 2 channels.
 * initialize only first channel setting.
 * process the chan_opts command line argument for simple form of single channel
 * configuration.
 *
 * @param chan_opts
 * @param sched
 *
 * @return int
 ******************************************************************************/
static
int dsrc_chan_init_schedule(char* chan_opts, struct dsrc_ocb_sched* sched)
{
    int chan = 0;
    int rc = 0;

    if (NULL != chan_opts) {
        chan = strtol(chan_opts, NULL, 10);
    }
    if (0 == chan) {
        rc = -1;
        chan = DEFAULT_CONTROL_CHANNEL;
    }
    memset(sched, 0, sizeof(struct dsrc_ocb_sched));
    sched->num_channels = 1;
    sched->channels[0].channel_freq = chan;
    sched->channels[0].duration = DEFAULT_CCH_DURATION_MS;
    sched->channels[0].start_guard_interval = DEFAULT_CCH_GUARD_MS;
    sched->channels[0].tx_power = DEFAULT_CCH_TX_POWER;

    sched->channels[1].channel_freq = DEFAULT_SERVICE_CHANNEL;
    sched->channels[1].duration = DEFAULT_SCH_DURATION_MS;
    sched->channels[1].start_guard_interval = DEFAULT_SCH_GUARD_MS;
    sched->channels[1].tx_power = DEFAULT_SCH_TX_POWER;

    /** Default qos values from the 802.11p spec */
    sched->channels[0].qos_params[DSRC_OCB_AC_BE].aifsn = 6;
    sched->channels[0].qos_params[DSRC_OCB_AC_BE].cwmax = 10;
    sched->channels[0].qos_params[DSRC_OCB_AC_BE].cwmin = 4;

    sched->channels[0].qos_params[DSRC_OCB_AC_BK].aifsn = 9;
    sched->channels[0].qos_params[DSRC_OCB_AC_BK].cwmax = 10;
    sched->channels[0].qos_params[DSRC_OCB_AC_BK].cwmin = 4;

    sched->channels[0].qos_params[DSRC_OCB_AC_VI].aifsn = 3;
    sched->channels[0].qos_params[DSRC_OCB_AC_VI].cwmax = 4;
    sched->channels[0].qos_params[DSRC_OCB_AC_VI].cwmin = 3;

    sched->channels[0].qos_params[DSRC_OCB_AC_VO].aifsn = 2;
    sched->channels[0].qos_params[DSRC_OCB_AC_VO].cwmax = 3;
    sched->channels[0].qos_params[DSRC_OCB_AC_VO].cwmin = 2;

    sched->channels[1].qos_params[DSRC_OCB_AC_BE].aifsn = 6;
    sched->channels[1].qos_params[DSRC_OCB_AC_BE].cwmax = 10;
    sched->channels[1].qos_params[DSRC_OCB_AC_BE].cwmin = 4;

    sched->channels[1].qos_params[DSRC_OCB_AC_BK].aifsn = 9;
    sched->channels[1].qos_params[DSRC_OCB_AC_BK].cwmax = 10;
    sched->channels[1].qos_params[DSRC_OCB_AC_BK].cwmin = 4;

    sched->channels[1].qos_params[DSRC_OCB_AC_VI].aifsn = 3;
    sched->channels[1].qos_params[DSRC_OCB_AC_VI].cwmax = 4;
    sched->channels[1].qos_params[DSRC_OCB_AC_VI].cwmin = 3;

    sched->channels[1].qos_params[DSRC_OCB_AC_VO].aifsn = 2;
    sched->channels[1].qos_params[DSRC_OCB_AC_VO].cwmax = 3;
    sched->channels[1].qos_params[DSRC_OCB_AC_VO].cwmin = 2;

    return rc;
}

/*******************************************************************************
 * translate the optional argument -c in to scheduling information.
 *
 * @param chan_opts
 * @param sched
 *
 * @return int <0 when failing to process the argument.
 ******************************************************************************/
static
int dsrc_chan_getopts_schedule(char* chan_opts, struct dsrc_ocb_sched* sched)
{
    int rc = 0;
    enum {
        NUM_CHAN = 0,
        CHAN0, BW0, PWR0,
        CHAN1, BW1, PWR1,
        THE_END
    };

    char *set_chan_opts[] = {
        [NUM_CHAN] = "num_channels",
        [CHAN0] = "channel_freq0",
        [BW0] = "channel_bandwidth0",
        [PWR0] = "tx_power0",
        [CHAN1] = "channel_freq1",
        [BW1] = "channel_bandwidth1",
        [PWR1] = "tx_power1",
        [THE_END] = NULL
    };

    char* value;

    /* backwards compatible */
    if (dsrc_chan_init_schedule(chan_opts, sched) < 0) {
        while (chan_opts && *chan_opts != '\0') {
            switch (getsubopt(&chan_opts, set_chan_opts, &value)) {
            case NUM_CHAN:
                if (value == NULL) {
                    printf("Missing value for suboption '%s'\n",
                           set_chan_opts[NUM_CHAN]);
                    break;
                }
                sched->num_channels = strtol(value, NULL, 10);
                break;
            case CHAN0:
                if (value == NULL) {
                    printf("Missing value for suboption '%s'\n",
                           set_chan_opts[CHAN0]);
                    break;
                }
                sched->channels[0].channel_freq = strtol(value, NULL, 10);
                break;
            case CHAN1:
                if (value == NULL) {
                    printf("Missing value for suboption '%s'\n",
                           set_chan_opts[CHAN1]);
                    break;
                }
                sched->channels[1].channel_freq = strtol(value, NULL, 10);
                break;
            case BW0:
                if (value == NULL) {
                    printf("Missing value for suboption '%s'\n",
                           set_chan_opts[BW0]);
                    break;
                }
                sched->channels[0].channel_bandwidth = strtol(value, NULL, 10);
                break;
            case BW1:
                if (value == NULL) {
                    printf("Missing value for suboption '%s'\n",
                           set_chan_opts[BW1]);
                    break;
                }
                sched->channels[1].channel_bandwidth = strtol(value, NULL, 10);
                break;
            case PWR0:
                if (value == NULL) {
                    printf("Missing value for suboption '%s'\n",
                           set_chan_opts[PWR0]);
                    break;
                }
                sched->channels[0].tx_power = strtol(value, NULL, 10);
                break;
            case PWR1:
                if (value == NULL) {
                    printf("Missing value for suboption '%s'\n",
                           set_chan_opts[PWR1]);
                    break;
                }
                sched->channels[1].tx_power = strtol(value, NULL, 10);
                break;
            default:
                rc = -1;
                dsrc_chan_usage();
                goto bail;
            }
        }
    }

  bail:
    return rc;
}

/*******************************************************************************
 * main entry point for this program. Process the arguments for interface
 * and channel parameters. Make an iocl request to the driver.
 * @param argc
 * @param argv
 * @return int
 ******************************************************************************/
int main(int argc, char **argv)
{
    int rc = 0;
    char *interface; /* -i option value */
    char *chan_opts; /* -c option value */
    struct dsrc_ocb_sched schedule;

    /* process command line options */
    rc = dsrc_chan_getopts(argc, argv, &interface, &chan_opts);
    if (rc < 0) {
        goto exit;
    }

    /* extract channel scheduling information */
    rc = dsrc_chan_getopts_schedule(chan_opts, &schedule);
    if (rc < 0) {
        printf("Error processing channel options\n");
        goto exit;
    }

    /* Set the channel scheduling info */
    if (dsrc_ocb_set_schedule(interface, &schedule)) {
        printf("Error setting channel!\n");
        rc = -1;
        goto exit;
    }

    printf("Num channels: %d. Channel", schedule.num_channels);
    if (2 == schedule.num_channels) {
        printf("s [1]:%d, ", schedule.channels[1].channel_freq);
    }
    printf("[0]:%d set successfully!\n", schedule.channels[0].channel_freq);

exit:
    return rc;
}

