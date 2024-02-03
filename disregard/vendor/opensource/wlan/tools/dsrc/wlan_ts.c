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

/**
 * @file wlan_ts.c
 * @brief example commands for WLAN thermal shutdown feature.
 *
 * To protect chip avoiding too hot to die, this user tool demo the flow
 * control of WLAN thermal shutdown feature provided by Wi-Fi driver.
 * The WLAN thermal shutdown is a generic feature working under any mode,
 * including STA/SAP/OCB/P2P etc.
 */

#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include "dsrc_nl.h"
#include "wlan_ts.h"

/**
 * Prints the command line usage message.
 */
void wlan_ts_usage()
{
    printf("Usage: wlan_ts [-i <interface>] [-t | -s | -r | -l | -u]\n");
    printf("Default: interface wlanocb0\n");
    printf("-p: get thermal shutdown parameters setting in driver\n");
    printf("-t: get temperature of the chip\n");
    printf("-s: suspend the chip\n");
    printf("-r: resume the chip\n");
    printf("-l: listen thermal event from driver\n");
    printf("    just handle event if autonomous shutdown enabled in driver\n");
    printf("    suspend if autonomous shutdown disabled in driver\n");
    printf("-u: user program poll temperature to showdown the chip\n");
    printf("    use this if auto thermal shutdown disabled in driver\n");
}

int wlan_ts_get_options(int argc, char *argv[],
    struct wlan_ts_opts *opts)
{
    int c;
    int rc = 0;

    opts->interface = "wlanocb0";
    opts->ts_auto_enabled = 0;
    opts->ts_cmd = WLAN_TS_CMD_GET_PARAMS;

    while ((c = getopt(argc, argv, "i:ptsrluh?")) != -1) {
        switch (c) {
            case 'i':
                opts->interface = optarg;
                break;
            case 'p':
                opts->ts_cmd = WLAN_TS_CMD_GET_PARAMS;
                break;
            case 't':
                opts->ts_cmd = WLAN_TS_CMD_GET_TEMP;
                break;
            case 's':
                opts->ts_cmd = WLAN_TS_CMD_SUSPEND;
                break;
            case 'r':
                opts->ts_cmd = WLAN_TS_CMD_RESUME;
                break;
            case 'l':
                opts->ts_cmd = WLAN_TS_CMD_LISTEN_EVENT;
                break;
            case 'u':
                opts->ts_cmd = WLAN_TS_CMD_USER_POLL_SHUTDOWN;
                break;
            case 'h':
            case '?':
            default:
                rc = -1;
                wlan_ts_usage();
                goto bail;
        }
    }

bail:
    return rc;
}

int wlan_ts_get_temperature(char *interface, int32_t *temperature)
{
    return wlan_get_temperature(interface, temperature);
}

int wlan_ts_thermal_suspend(char *interface, int suspend, struct wlan_ts_params *params)
{
    if (!params->shutdown_enabled) {
        printf("Thermal shutdown feature is not enabled\n");
        return 0;
    }

    if (params->shutdown_auto_enabled) {
        printf("Autonomous thermal shutdown is enabled in driver\n");
        return 0;
    }

    return wlan_thermal_suspend(interface, suspend);
}

/*
 * Respond to the event and do suspend atcions. It is only resumed by driver
 * that is triggered by interrupt from FW in chip.
 */
int wlan_ts_user_shutdown(char *interface, int32_t temperature,
        struct wlan_ts_params *params, bool *suspended)
{
    if (temperature >= params->suspend_thresh) {
        if (*suspended)
            goto exit;
        *suspended = true;
        printf("Chip is going to shutdown, stop tx first\n");
        return wlan_ts_thermal_suspend(interface, 1, params);
    } else if (temperature >= params->warning_thresh) {
        printf("Chip is hot warning, reduce tx or neglect it\n");
    } else if (temperature < params->resume_thresh) {
        printf("Chip is cool down and resume to work\n");
    }

exit:
    return 0;
}

/* Just respond to the event. Don't do suspend/resume atcions. */
void wlan_ts_user_listen_handler(int32_t temperature, struct wlan_ts_params *params)
{
    if (temperature >= params->suspend_thresh)
        printf("Chip is going to shutdown, stop tx first\n");
    else if (temperature >= params->warning_thresh)
        printf("Chip is hot warning, reduce tx or neglect it\n");
    else if (temperature < params->resume_thresh)
        printf("Chip is cool down and resume to work\n");
}

int wlan_ts_thermal_event_loop(char *interface, struct wlan_ts_params *params)
{
    struct wlan_ts_event event = {0};
    struct nl80211_state states[2] = { {0}, };
    bool suspended = false;
    int ret = 0;

    if (!params->shutdown_enabled) {
        printf("Thermal shutdown feature is not enabled\n");
        goto exit;
    }

    wlan_thermal_event_init(interface, states, &event);
    printf("Listening events...\n");
    while (1) {
        ret = wlan_thermal_event_recv(&states[1]);
        if (ret) {
            errno = ret;
            perror("wlan_thermal_event_recv()");
            continue;
        }

        switch (event.type) {
        case WLAN_TS_EVT_TEMPERATURE_IND:
            printf("Temperature indication msg received\n");
            if (params->shutdown_auto_enabled) {
                wlan_ts_user_listen_handler(event.value, params);
            } else {
                ret = wlan_ts_user_shutdown(interface, event.value,
                                      params, &suspended);
                if (ret)
                    goto deinit;
            }
            break;
        case WLAN_TS_EVT_RESUME_COMP_IND:
            suspended = false;
            printf("###Thermal Resume completed\n");
            break;
        }

        event.type = WLAN_TS_EVT_NONE;
    }

deinit:
    wlan_thermal_event_deinit(states);
exit:
    return ret;
}

/*
 * Poll chip's temperature to launch suspend by app, and listen resume complete
 * event from driver indicates that we can restart working.
 */
int wlan_ts_user_poll_shutdown(char *interface, struct wlan_ts_params *params)
{
    struct wlan_ts_event event = {0};
    struct nl80211_state states[2] = { {0}, };
    int ret = 0;
    bool suspended = false;
    int32_t temperature = 0;

    if (!params->shutdown_enabled) {
        printf("Thermal shutdown feature is not enabled\n");
        goto exit;
    }

    if (params->shutdown_auto_enabled) {
        printf("Autonomous thermal shutdown is enabled in driver\n");
        goto exit;
    }

    wlan_thermal_event_init(interface, states, &event);
    while (1) {
        sleep(3);
        if (!suspended) {
            ret = wlan_ts_get_temperature(interface, &temperature);
            if (ret) {
                errno = ret;
                perror("wlan_ts_get_temperature()");
                sleep(2);
                continue;
            }
            printf("Polled temperature: %d C\n", temperature);

            ret = wlan_ts_user_shutdown(interface, temperature,
                                        params, &suspended);
            if (ret)
                goto deinit;
        } else {
            event.type = WLAN_TS_EVT_NONE;
            /* Can't get temperature if chip suspended, wait for resume event */
            ret = wlan_thermal_event_recv(&states[1]);
            if (ret) {
                errno = ret;
                perror("wlan_thermal_event_recv()");
            } else {
                if (event.type == WLAN_TS_EVT_TEMPERATURE_IND) {
                    printf("Indicated temperature: %d C\n", event.value);
                } else if (event.type == WLAN_TS_EVT_RESUME_COMP_IND) {
                    printf("###Thermal Resume completed\n");
                    suspended = false;
                } else {
                    printf("Should not reach here!\n");
                }
            }
        }
    }

deinit:
    wlan_thermal_event_deinit(states);
exit:
    return ret;
}

static int wlan_ts_exec_cmd(struct wlan_ts_opts *opts)
{
    int rc = 0;
    int32_t temperature = 0;
    struct wlan_ts_params params = {0};

    rc = wlan_get_thermal_params(opts->interface, &params);
    if (rc)
        goto exit;

    switch (opts->ts_cmd) {
    case WLAN_TS_CMD_GET_PARAMS:
        printf("Thermal shutdown params: enabled=%u,auto_enabled=%u\n"
               "Thresholds: resume=%d,warning=%d,suspend=%d\n"
               "Sample Rate: %d ms\n",
               params.shutdown_enabled, params.shutdown_auto_enabled,
               params.resume_thresh, params.warning_thresh,
               params.suspend_thresh, params.sample_rate);
        break;
    case WLAN_TS_CMD_GET_TEMP:
        rc = wlan_ts_get_temperature(opts->interface, &temperature);
        printf("temperature = %d\n", temperature);
        break;
    case WLAN_TS_CMD_SUSPEND:
        rc = wlan_ts_thermal_suspend(opts->interface, 1, &params);
        break;
    case WLAN_TS_CMD_RESUME:
        rc = wlan_ts_thermal_suspend(opts->interface, 0, &params);
        break;
    case WLAN_TS_CMD_LISTEN_EVENT:
        rc = wlan_ts_thermal_event_loop(opts->interface, &params);
        break;
    case WLAN_TS_CMD_USER_POLL_SHUTDOWN:
        rc = wlan_ts_user_poll_shutdown(opts->interface, &params);
        break;
    default:
        rc = -1;
        wlan_ts_usage();
        goto exit;
    }

exit:
    return rc;
}

int main(int argc, char **argv)
{
    struct wlan_ts_opts opts = {0};
    int rc = -1;

    rc = wlan_ts_get_options(argc, argv, &opts);
    if (rc) {
        goto exit;
    }

    rc = wlan_ts_exec_cmd(&opts);
    if (rc) {
        printf("Error executing command, ret=%d\n", rc);
    } else {
        printf("Success executing command\n");
    }

exit:
    return rc;
}
