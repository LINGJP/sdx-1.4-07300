/*
 * Copyright (c) 2017, The Linux Foundation. All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include "dsrc_util.h"

#define WLAN_DEBUGFS_DIR_PATH "/sys/kernel/debug/wlan_wcnss"
#define WLAN_DEBUGFS_CHAN_STATS "dsrc_chan_stats"
#define WLAN_DEBUGFS_TX_STATS "dsrc_tx_stats"

#define MAC_ADDRESS_STR "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ADDRESS_ARRAY(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]

#define INVALID_TX_POWER_VAL (255)
#define WLAN_DSRC_MAX_BUF_LEN 4096

static char wlan_debugfs_dir[64];
static unsigned long tx_stats_count = 0;

struct dsrc_tx_per_pkt_stats {
    uint32_t seq_no;
    uint32_t chan_freq;
    uint32_t bandwidth;
    uint8_t datarate;
    uint8_t tx_power;
    uint8_t mac_address[6];
};

struct dsrc_per_chan_stats {
    uint32_t chan_freq;
    uint32_t chan_busy_ratio;
    uint64_t measurement_period;
    uint64_t tx_duration_us;
    uint64_t rx_duration_us;
    uint64_t on_chan_us;
    uint32_t on_chan_ratio;
    uint32_t tx_mpdus;
    uint32_t tx_msdus;
    uint32_t rx_succ_pkts;
    uint32_t rx_fail_pkts;
};

struct dsrc_chan_stats {
    uint32_t chan_count;
    struct dsrc_per_chan_stats stats[2];
} __attribute__ ((packed));

struct dsrc_diag_opts {
    char *interface;
    char *tx_stats_cmd;
    char *channel_stats_cmd;
};

/*******************************************************************************
 * Usage message
 ******************************************************************************/
static void dsrc_diag_usage(void)
{
    printf("Usage: dsrc_diag [-c | -t] [-i <interface>] [-d <device>]\n");
    printf("Defaults: interface wlanocb0, print to stdout\n");
    printf("-i <interface> : interface name as found in listing by ifconfig\n");
    printf("-d <device> : chip name, for example, qca6584\n");
    printf("-c <enable|disable|read>: dsrc channel statistics command.\n");
    printf("-t <enable|disable|read>: dsrc tx per packet statistics command.\n");
}

/*******************************************************************************
 * break the command arguments in to params.
 *
 * @param argc
 * @param argv
 * @param opts
 *
 * @return int 0 on success; -1 on error
 ******************************************************************************/
static int dsrc_diag_getopts(int argc, char *argv[],
                             struct dsrc_diag_opts *opts)
{
#define OPT_STRING "i:d:c:t:h?"
    int c;
    int len;
    int rc = 0;

    /* defaults */
    opts->interface = "wlanocb0";
    len = snprintf(wlan_debugfs_dir, sizeof(wlan_debugfs_dir),
                   WLAN_DEBUGFS_DIR_PATH);

    if ((c = getopt(argc, argv, OPT_STRING)) != -1) {
         do {
            switch (c) {
            case 'i':
                opts->interface = optarg;
                break;
            case 'd':
                if (optarg)
                    snprintf(wlan_debugfs_dir + len,
                             sizeof(wlan_debugfs_dir) - len,
                             "%s", optarg);
                break;
            case 'c':
                opts->channel_stats_cmd = optarg;
                break;
            case 't':
                opts->tx_stats_cmd = optarg;
                break;
            case '?':
            case 'h':
            default:
                rc = -1;
                dsrc_diag_usage();
                goto exit;
            }
        } while ((c = getopt(argc, argv, OPT_STRING)) != -1);
    } else {
        rc = -1;
        dsrc_diag_usage();
    }

exit:
    return rc;
}

static void dsrc_diag_signal_handler(int sig_num)
{
    if(tx_stats_count) {
        printf("Got %lu per packet tx stats\n", tx_stats_count);
    }

    exit(sig_num);
}

static int dsrc_diag_enable_chan_stats(int fd)
{
    ssize_t count;

    /*DSRC debugfs command option:
     * [cmd_id] [cmd_param]
     * cmd_id=1 : config channel stats parameters:[enable|disable]
     * cmd_param=1 : enable dsrc channle statsticts.
     */
    count = write(fd, "1 1", 3);
    if (count < 0) {
        printf("Error enable wlan dsrc chan stats!\n");
        return -1;
    }

    return 0;
}

static int dsrc_diag_disable_chan_stats(int fd)
{
    ssize_t count;

    /*DSRC debugfs command option:
     * [cmd_id] [cmd_param]
     * cmd_id=1 : config channel stats parameters:[enable|disable]
     * cmd_param=0 : disable dsrc channle statsticts.
     */
    count = write(fd, "1 0", 3);
    if (count < 0) {
        printf("Error disable wlan dsrc chan stats!\n");
        return -1;
    }

    return 0;
}

static void dsrc_display_chan_stats(struct dsrc_chan_stats *chan_stats)
{
    char buf[WLAN_DSRC_MAX_BUF_LEN];
    int i, len;

    len = snprintf(buf, WLAN_DSRC_MAX_BUF_LEN - 1,
                   "DSRC Radio Channel Statistics\n");
    len += snprintf(buf + len, WLAN_DSRC_MAX_BUF_LEN - len - 1,
                    "Channel Count = %d\n", chan_stats->chan_count);
    for (i = 0; i < chan_stats->chan_count; i ++) {
       len += snprintf(buf + len, WLAN_DSRC_MAX_BUF_LEN - len - 1,
                       "channel_frequence=%d\n"
                       "measurement_period_us=%llu\n"
                       "on_channel_us=%llu\n"
                       "on_chan_ratio_percent=%d\n"
                       "tx_duration_us=%llu\n"
                       "rx_duration_us=%llu\n"
                       "channel_busy_ratio_percent=%d\n"
                       "tx_mpdus=%u\n"
                       "tx_msdus=%u\n"
                       "rx_success_packets=%u\n"
                       "rx_fail_packets=%u\n\n",
                       chan_stats->stats[i].chan_freq,
                       (unsigned long long)
                       chan_stats->stats[i].measurement_period,
                       (unsigned long long)
                       chan_stats->stats[i].on_chan_us,
                       chan_stats->stats[i].on_chan_ratio,
                       (unsigned long long)chan_stats->stats[i].tx_duration_us,
                       (unsigned long long)chan_stats->stats[i].rx_duration_us,
                       chan_stats->stats[i].chan_busy_ratio,
                       chan_stats->stats[i].tx_mpdus,
                       chan_stats->stats[i].tx_msdus,
                       chan_stats->stats[i].rx_succ_pkts,
                       chan_stats->stats[i].rx_fail_pkts);
    }
    buf[len] = '\0';
    printf("%s\n\n", buf);
}

static int dsrc_diag_read_chan_stats(int fd)
{
    ssize_t count;
    uint32_t chan_count;
    struct dsrc_chan_stats chan_stats_info = { 0 };

    /*DSRC debugfs command option:
     * [cmd_id] [cmd_param]. i.e.: "2 1 5860", "2 2".
     * cmd_id=2 : Request channel stats parameters
     * cmd_param=1 : Request one chan stats, need chan frequence provided.
     * cmd_param=2 : Rqquest all configured channel statsticts.
     */
    count = write(fd, "2 2", 3);
    if (count < 0) {
        printf("Error Request wlan dsrc chan stats!\n");
        return -1;
    }

    memset(&chan_stats_info, 0, sizeof(chan_stats_info));
    count = read(fd, &chan_stats_info, sizeof(chan_stats_info));
    if (count < 0) {
        printf("Error read wlan dsrc chan stats!\n");
        return -1;
    }

    chan_count = chan_stats_info.chan_count;
    if (!chan_count) {
        printf("Error channel count in statistics report.\n");
        return -1;
    }
    if (count != (chan_count * sizeof(struct dsrc_per_chan_stats) +
                  sizeof(chan_count))) {
        printf("Error buffer length in channel statistics report.");
        return -1;
    }

    dsrc_display_chan_stats(&chan_stats_info);

    return 0;
}

static int dsrc_diag_parse_channel_stats_cmd(const char *cmd)
{
    int ret = -1;
    int fd = -1;

    ret = chdir(wlan_debugfs_dir);
    if (ret) {
        printf("Error change to wlan debugfs dir %s!\n", wlan_debugfs_dir);
        goto exit;
    }

    fd = open(WLAN_DEBUGFS_CHAN_STATS, O_RDWR);
    if (fd < 0) {
        printf("Error open wlan debugfs %s!\n", WLAN_DEBUGFS_CHAN_STATS);
        goto exit;
    }

    if (!strcmp(cmd, "enable")) {
        ret = dsrc_diag_enable_chan_stats(fd);
    } else if (!strcmp(cmd, "disable")) {
        ret = dsrc_diag_disable_chan_stats(fd);
    } else if (!strcmp(cmd, "read")) {
        ret = dsrc_diag_read_chan_stats(fd);
    } else {
       printf("Not supported dsrc channel statistics command.\n");
       printf("DSRC Channel Staticts command usage:\n");
       printf("dsrc_diag -c [enable|disable|read]\n");
       ret = -1;
    }

exit:
    if (fd >= 0) {
        close(fd);
    }
    return ret;
}

static int dsrc_diag_enable_tx_stats(int fd, int enable)
{
    int ret = 0;
    ssize_t n;

    if (enable) {
        n = write(fd, "1", 1);
    } else {
        n = write(fd, "0", 1);
    }
    if (n < 0) {
        printf("Error enable wlan tx_stats!\n");
        ret = -1;
    }

    return ret;
}

static void dsrc_display_per_pkt_tx_stats(
    struct dsrc_tx_per_pkt_stats *stats)
{
    char buf[WLAN_DSRC_MAX_BUF_LEN];
    int len;

    len = snprintf(buf, WLAN_DSRC_MAX_BUF_LEN - 1,
                   "DSRC TX Packets Statistics\n");
    len += snprintf(buf + len, WLAN_DSRC_MAX_BUF_LEN - len - 1,
                    "tx_stats_count=%lu\n", tx_stats_count);
    len += snprintf(buf + len, WLAN_DSRC_MAX_BUF_LEN - len - 1,
                    "sequence_number=%u\n"
                    "channel_frequence=%u\n"
                    "data_rate=MCS%u\n",
                    stats->seq_no,
                    stats->chan_freq,
                    stats->datarate);
    if (INVALID_TX_POWER_VAL == stats->tx_power)
        len += snprintf(buf + len, WLAN_DSRC_MAX_BUF_LEN - len - 1,
                        "tx_power=invalid!\n");
    else
        len += snprintf(buf + len, WLAN_DSRC_MAX_BUF_LEN - len - 1,
                        "tx_power=%u\n", stats->tx_power);
    len += snprintf(buf + len, WLAN_DSRC_MAX_BUF_LEN - len - 1,
                    "channel_bandwidth=%u\n", stats->bandwidth);
    len += snprintf(buf + len, WLAN_DSRC_MAX_BUF_LEN - len - 1,
                    "MAC_address=" MAC_ADDRESS_STR,
                    MAC_ADDRESS_ARRAY(stats->mac_address));

    buf[len] = '\0';
    printf("%s\n\n", buf);
}

static int dsrc_diag_read_tx_stats(int fd)
{
    int ret = 0;
    ssize_t n = -1;
    struct dsrc_tx_per_pkt_stats stats = { 0 };

    do {
        n = read(fd, &stats, sizeof(stats));
        if (n < 0) {
            perror("Error read wlan tx_stats: ");
            ret = -1;
            goto exit;
        } else if (n == sizeof(stats)) {
            tx_stats_count++;
            dsrc_display_per_pkt_tx_stats(&stats);
        }
    } while (n > 0);

exit:
    return ret;
}

static int dsrc_diag_parse_tx_stats_cmd(const char *cmd)
{
    int ret = -1;
    int fd = -1;

    ret = chdir(wlan_debugfs_dir);
    if (ret) {
        printf("Error change to wlan debugfs dir %s!\n", wlan_debugfs_dir);
        goto exit;
    }

    fd = open(WLAN_DEBUGFS_TX_STATS, O_RDWR);
    if (fd < 0) {
        printf("Error open wlan debugfs %s!\n", WLAN_DEBUGFS_TX_STATS);
        goto exit;
    }

    if (!strcmp(cmd, "read")) {
        ret = dsrc_diag_read_tx_stats(fd);
    } else if (!strcmp(cmd, "enable")) {
        ret = dsrc_diag_enable_tx_stats(fd, 1);
    } else if (!strcmp(cmd, "disable")) {
        ret = dsrc_diag_enable_tx_stats(fd, 0);
    } else {
       printf("Not supported dsrc tx packets statistics command.\n");
       printf("DSRC TX Packets Staticts command usage:\n");
       printf("dsrc_diag -t [enable|disable|read]\n");
    }

exit:
    if (fd >= 0) {
        close(fd);
    }
    return ret;
}

int main(int argc, char *argv[])
{
    int rc = 0;
    struct dsrc_diag_opts opts = { 0 };

    signal(SIGINT, dsrc_diag_signal_handler);

    rc = dsrc_diag_getopts(argc, argv, &opts);
    if (rc < 0) {
        goto exit;
    }

    if (opts.channel_stats_cmd) {
        dsrc_diag_parse_channel_stats_cmd(opts.channel_stats_cmd);
    }

    if (opts.tx_stats_cmd) {
        dsrc_diag_parse_tx_stats_cmd(opts.tx_stats_cmd);
    }

exit:
    return rc;
}
