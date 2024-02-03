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

#ifndef WLAN_TS_H
#define WLAN_TS_H

#include <stdint.h>

enum wlan_ts_cmds {
    WLAN_TS_CMD_NONE,
    WLAN_TS_CMD_GET_PARAMS,
    WLAN_TS_CMD_GET_TEMP,
    WLAN_TS_CMD_SUSPEND,
    WLAN_TS_CMD_RESUME,
    WLAN_TS_CMD_LISTEN_EVENT,
    WLAN_TS_CMD_USER_POLL_SHUTDOWN,
};

enum wlan_ts_event_type {
    WLAN_TS_EVT_NONE,
    WLAN_TS_EVT_TEMPERATURE_IND,
    WLAN_TS_EVT_RESUME_COMP_IND,
};

struct wlan_ts_opts {
    char *interface;
    int ts_auto_enabled;
    int ts_cmd;
};

struct wlan_ts_event {
    int type;
    int32_t value;
};

struct wlan_ts_params {
    /* Thermal Shutdown feature is enabled or not. */
    uint8_t  shutdown_enabled;
    /* Thermal Shutdown is autonomous in driver or requested by user app. */
    uint8_t  shutdown_auto_enabled;
    int16_t resume_thresh;
    int16_t warning_thresh;
    int16_t suspend_thresh;
    /* period in ms to sample chip temperature. */
    int16_t sample_rate;
};

struct nl80211_state;

int wlan_get_temperature(char *interface, int32_t *temperature);
int wlan_get_thermal_params(char *interface, struct wlan_ts_params *params);

int wlan_thermal_suspend(char *interface, int suspend);

int wlan_thermal_event_init(char *interface,
        struct nl80211_state states[2],
        struct wlan_ts_event *event);
int wlan_thermal_event_recv(struct nl80211_state *state);
void wlan_thermal_event_deinit(struct nl80211_state states[2]);

#endif /* WLAN_TS_H */
