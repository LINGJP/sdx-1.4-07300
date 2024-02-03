/*
 * Copyright (C) 2019-2021, The Linux Foundation. All rights reserved.
 *
 * Not a Contribution.
 *
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <regex>
#include <cutils/uevent.h>
#include <linux/usb/ch9.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <syslog.h>
#include <utils/Errors.h>

#define msg(format, ...)   syslog(LOG_ERR, format, ## __VA_ARGS__)
#define info(format, ...)   syslog(LOG_INFO, format, ## __VA_ARGS__)
#define dbg(format, ...)   syslog(LOG_DEBUG, format, ## __VA_ARGS__)

static int uevent_fd;
static int epollfd;
static std::string attributes;
static std::string power_op_mode;
static std::string max_power;

static int32_t readFile(const std::string &filename, std::string *contents) {
  FILE *fp;
  ssize_t read = 0;
  char *line = NULL;
  size_t len = 0;

  fp = fopen(filename.c_str(), "r");
  if (fp != NULL) {
    if ((read = getline(&line, &len, fp)) != -1) {
      char *pos;
      if ((pos = strchr(line, '\n')) != NULL) *pos = '\0';
      *contents = line;
    }
    free(line);
    fclose(fp);
    return 0;
  } else {
    msg("fopen failed in readFile %s, errno=%d", filename.c_str(), errno);
  }

  return -1;
}

static int32_t writeFile(const std::string &filename,
                         const std::string &contents) {
  FILE *fp;
  int ret;

  fp = fopen(filename.c_str(), "w");
  if (fp != NULL) {
    ret = fputs(contents.c_str(), fp);
    fclose(fp);
    if (ret == EOF) {
      msg("fputs failed in writeFile %s", filename.c_str());
      return -1;
    }
    return 0;
  } else {
    msg("fopen failed in writeFile %s, errno=%d", filename.c_str(), errno);
  }

  return -1;
}

static bool checkUsbInterfaceAutoSuspend(const std::string &devicePath,
					const std:: string &intf) {
    std::string bInterfaceClass;
    int interfaceClass, ret = -1;

    info("device: %s intf: %s\n", devicePath.c_str(), intf.c_str());
    ret = readFile(devicePath + "/" + intf + "/bInterfaceClass", &bInterfaceClass);
    if (ret)
	return false;

    interfaceClass = std::stoi(bInterfaceClass, 0, 16);

    switch (interfaceClass) {
	case USB_CLASS_AUDIO:
	case USB_CLASS_HUB:
	    info("Auto suspend usb device %s\n", devicePath.c_str());
	    ret = writeFile(devicePath + "/power/control", "auto");
	    if (ret)
		break;

	    ret = writeFile(devicePath + "/power/wakeup", "enabled");
	    break;
	default:
	    info("USB device does not support auto suspend %s\n",
							devicePath.c_str());
    }

    return ret ? false : true;
}

#define UEVENT_MSG_LEN 2048
static void uevent_event(uint32_t ep) {
    char msg[UEVENT_MSG_LEN+2];
    char *cp;
    int n;

    n = uevent_kernel_multicast_recv(uevent_fd, msg, UEVENT_MSG_LEN);
    if (n <= 0)
        return;
    if (n >= UEVENT_MSG_LEN)   /* overflow -- discard */
        return;

    msg[n] = '\0';
    msg[n+1] = '\0';
    cp = msg;

    dbg("Got uevent %s\n", msg);

    while (*cp) {
	std::cmatch match;

	if (std::regex_match(cp, match,
		    std::regex("bind@(/devices/platform/.*dwc3/xhci-hcd\\.\\d\\.auto/"
                     "usb\\d(?:/\\d-\\d)*(?:/[\\d\\.-]+)*)/([^/]*:[^/]*)"))) {
	  if (match.size() == 3) {
	      std::csub_match devpath = match[1];
	      std::csub_match intfpath = match[2];
	      checkUsbInterfaceAutoSuspend("/sys/" + devpath.str(), intfpath.str());
	  }
	} else if (!strncmp(cp, "DEVTYPE=typec_", strlen("DEVTYPE=typec_"))) {
	    std::string power_operation_mode;

	    if (!readFile("/sys/class/typec/port0/power_operation_mode", &power_operation_mode)) {
                if (power_operation_mode == power_op_mode) {
                    dbg("Got uevent for same mode %s\n", power_operation_mode.c_str());
                } else if (power_operation_mode == "usb_power_delivery") {
                    readFile("/sys/kernel/config/usb_gadget/g1/configs/c.1/MaxPower", &max_power);
		    readFile("/sys/kernel/config/usb_gadget/g1/configs/c.1/bmAttributes", &attributes);
		    writeFile("/sys/kernel/config/usb_gadget/g1/configs/c.1/MaxPower", "0");
		    writeFile("/sys/kernel/config/usb_gadget/g1/configs/c.1/bmAttributes", "0x80");
		} else {
		    writeFile("/sys/kernel/config/usb_gadget/g1/configs/c.1/MaxPower", max_power.c_str());
		    writeFile("/sys/kernel/config/usb_gadget/g1/configs/c.1/bmAttributes", attributes.c_str());
		}

                power_op_mode == power_operation_mode;
	    }
	}

	while (*cp++) {}
    }

    return;
}

#define MAX_EPOLL_EVENTS 40
int main(int argc, char **argv) {
    struct epoll_event ev;


    epollfd = epoll_create(MAX_EPOLL_EVENTS);
    if (epollfd == -1) {
	msg("Could not get epollfd\n");
	return 0;
    }

    // Scan for enumerated USB devices and enable autosuspend
    std::string usbdevices = "/sys/bus/usb/devices/";
    DIR *dp = opendir(usbdevices.c_str());
    if (dp != NULL) {
	struct dirent *deviceDir;
	struct dirent *intfDir;
	DIR *ip;

	while ((deviceDir = readdir(dp))) {
	    /*
	     * Iterate over all the devices connected over USB while skipping
	     * the interfaces.
	     */
	    if (deviceDir->d_type == DT_LNK && !strchr(deviceDir->d_name, ':')) {
		char buf[PATH_MAX];
		if (realpath((usbdevices + deviceDir->d_name).c_str(), buf)) {
		    ip = opendir(buf);
		    if (ip == NULL)
			continue;

		    while ((intfDir = readdir(ip))) {
			// Scan over all the interfaces that are part of the device
			if (intfDir->d_type == DT_DIR && strchr(intfDir->d_name, ':')) {
			    /*
			     * If the autosuspend is successfully enabled, no need
			     * to iterate over other interfaces.
			     */
			    if (checkUsbInterfaceAutoSuspend(buf, intfDir->d_name))
				break;
			}
		    }
		    closedir(ip);
		}
	    }
	}
	closedir(dp);
    }

    uevent_fd = uevent_open_socket(64*1024, true);
    if (uevent_fd < 0) {
	msg("Could not get ueventfd\n");
	return 0;
    }

    fcntl(uevent_fd, F_SETFL, O_NONBLOCK);

    ev.events = EPOLLIN | EPOLLWAKEUP;
    ev.data.ptr = (void *)uevent_event;

    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, uevent_fd, &ev) == -1) {
	msg("Could not add epoll ctl\n");
	return 0;
    }

    info("Successfuly started usb daemon\n");

    while (1) {
	struct epoll_event events[0];
	int nevents;

	nevents = epoll_wait(epollfd, events, 1, -1);
	if (nevents < 0 && errno == EINTR)
		continue;

	if (nevents < 0 && errno != EINTR) {
	    msg("epoll wait failed, errno:%d\n", errno);
	    exit(EXIT_FAILURE);
	}

        for (int n = 0; n < nevents; ++n) {
            if (events[n].data.ptr)
                (*(void (*)(int))events[n].data.ptr)(events[n].events);
        }
    }

    return 0;
}
