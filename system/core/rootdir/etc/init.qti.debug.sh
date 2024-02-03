#! /bin/sh
#Copyright (c) 2019, The Linux Foundation. All rights reserved.
#
#Redistribution and use in source and binary forms, with or without
#modification, are permitted provided that the following conditions are
#met:
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials provided
#      with the distribution.
#    * Neither the name of The Linux Foundation nor the names of its
#      contributors may be used to endorse or promote products derived
#      from this software without specific prior written permission.
#
#THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
#WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
#MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
#ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
#BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
#BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
#WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
#OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
#IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

enable_qcs40x_debug()
{
	echo "++++ $0 -> Target specific debug file" > /dev/kmsg
	echo "++++ $0 -> DCC-Enable START" > /dev/kmsg
	DCC_PATH="/sys/bus/platform/devices/b2000.dcc_v2"
	if [ ! -d $DCC_PATH ];
	then
		echo "++++ $0 -> Not a debug build. No DCC available" > /dev/kmsg
		echo "DCC does not exist on this build."
		return
	fi

	echo 0 > $DCC_PATH/enable
	echo 1 > $DCC_PATH/curr_list
	echo cap > $DCC_PATH/func_type
	echo sram > $DCC_PATH/data_sink
	echo 1 > $DCC_PATH/config_reset

	#GCC_BIMC
	echo 0x1823000 0x2 > $DCC_PATH/config
	echo 0x1823010 0x1 > $DCC_PATH/config
	echo 0x1823018 0x2 > $DCC_PATH/config
	echo 0x1823024 0x1 > $DCC_PATH/config

	#DCC_Power_Reg's
	echo 0xB08900C 0x1 > $DCC_PATH/config
	echo 0xB089030 0x1 > $DCC_PATH/config
	echo 0xB089038 0x1 > $DCC_PATH/config
	echo 0xB089008 0x1 > $DCC_PATH/config
	echo 0xB09900C 0x1 > $DCC_PATH/config
	echo 0xB099038 0x1 > $DCC_PATH/config
	echo 0xB099030 0x1 > $DCC_PATH/config
	echo 0xB099008 0x1 > $DCC_PATH/config
	echo 0xB0A900C 0x1 > $DCC_PATH/config
	echo 0xB0A9038 0x1 > $DCC_PATH/config
	echo 0xB0A9030 0x1 > $DCC_PATH/config
	echo 0xB0A9008 0x1 > $DCC_PATH/config
	echo 0xB0B900C 0x1 > $DCC_PATH/config
	echo 0xB0B9038 0x1 > $DCC_PATH/config
	echo 0xB0B9030 0x1 > $DCC_PATH/config
	echo 0xB0B9008 0x1 > $DCC_PATH/config
	echo 0xB01200C 0x1 > $DCC_PATH/config
	echo 0xB012038 0x1 > $DCC_PATH/config
	echo 0xB012030 0x1 > $DCC_PATH/config
	echo 0xB012014 0x1 > $DCC_PATH/config
	echo 0xB012008 0x1 > $DCC_PATH/config
	echo 0xB011264 0x1 > $DCC_PATH/config
	echo 0x0B011218 0x1 > $DCC_PATH/config
	echo 0x0B011234 0x1 > $DCC_PATH/config

	#DCC_NOC_Reg's
	echo 0xc0b7014 0x1 > $DCC_PATH/config
	echo 0xc0b701c 0x1 > $DCC_PATH/config
	echo 0xc0b7020 0x1 > $DCC_PATH/config
	echo 0xc0b7028 0x1 > $DCC_PATH/config
	echo 0xc0b702c 0x1 > $DCC_PATH/config
	echo 0xc0b7030 0x1 > $DCC_PATH/config
	echo 0xc0b7034 0x1 > $DCC_PATH/config
	echo 0xc0f6014 0x1 > $DCC_PATH/config
	echo 0xc0f601c 0x1 > $DCC_PATH/config
	echo 0xc0f6020 0x1 > $DCC_PATH/config
	echo 0xc0f6028 0x1 > $DCC_PATH/config
	echo 0xc0f602c 0x1 > $DCC_PATH/config
	echo 0xc0f6030 0x1 > $DCC_PATH/config
	echo 0xc0f6034 0x1 > $DCC_PATH/config
	echo 0xc2e3014 0x1 > $DCC_PATH/config
	echo 0xc2e301c 0x1 > $DCC_PATH/config
	echo 0xc2e3020 0x1 > $DCC_PATH/config
	echo 0xc2e3028 0x1 > $DCC_PATH/config
	echo 0xc2e302c 0x1 > $DCC_PATH/config
	echo 0xc2e3030 0x1 > $DCC_PATH/config
	echo 0xc2e3034 0x1 > $DCC_PATH/config
	echo 0x23014 0x1 > $DCC_PATH/config
	echo 0x2301c 0x1 > $DCC_PATH/config
	echo 0x23020 0x1 > $DCC_PATH/config
	echo 0x23028 0x1 > $DCC_PATH/config
	echo 0x2302c 0x1 > $DCC_PATH/config
	echo 0x23030 0x1 > $DCC_PATH/config
	echo 0x23034 0x1 > $DCC_PATH/config
	echo 0x24014 0x1 > $DCC_PATH/config
	echo 0x2401c 0x1 > $DCC_PATH/config
	echo 0x24020 0x1 > $DCC_PATH/config
	echo 0x24028 0x1 > $DCC_PATH/config
	echo 0x2402c 0x1 > $DCC_PATH/config
	echo 0x24030 0x1 > $DCC_PATH/config
	echo 0x24034 0x1 > $DCC_PATH/config
	echo 0x25000 0x1 > $DCC_PATH/config
	echo 0x25004 0x1 > $DCC_PATH/config
	echo 0x25008 0x1 > $DCC_PATH/config
	echo 0x2500c 0x1 > $DCC_PATH/config
	echo 0x25010 0x1 > $DCC_PATH/config
	echo 0x25014 0x1 > $DCC_PATH/config
	echo 0x2501c 0x1 > $DCC_PATH/config
	echo 0x25020 0x1 > $DCC_PATH/config
	echo 0x25028 0x1 > $DCC_PATH/config
	echo 0x2502c 0x1 > $DCC_PATH/config
	echo 0x25030 0x1 > $DCC_PATH/config
	echo 0x25034 0x1 > $DCC_PATH/config
	echo 0x26014 0x1 > $DCC_PATH/config
	echo 0x2601c 0x1 > $DCC_PATH/config
	echo 0x26020 0x1 > $DCC_PATH/config
	echo 0x26028 0x1 > $DCC_PATH/config
	echo 0x2602c 0x1 > $DCC_PATH/config
	echo 0x26030 0x1 > $DCC_PATH/config
	echo 0x26034 0x1 > $DCC_PATH/config
	echo 0x27014 0x1 > $DCC_PATH/config
	echo 0x2701c 0x1 > $DCC_PATH/config
	echo 0x27020 0x1 > $DCC_PATH/config
	echo 0x27028 0x1 > $DCC_PATH/config
	echo 0x2702c 0x1 > $DCC_PATH/config
	echo 0x27030 0x1 > $DCC_PATH/config
	echo 0x27034 0x1 > $DCC_PATH/config
	echo 0x29000 0x1 > $DCC_PATH/config
	echo 0x29004 0x1 > $DCC_PATH/config
	echo 0x29008 0x1 > $DCC_PATH/config
	echo 0x2900c 0x1 > $DCC_PATH/config
	echo 0x29010 0x1 > $DCC_PATH/config
	echo 0x29014 0x1 > $DCC_PATH/config
	echo 0x2901c 0x1 > $DCC_PATH/config
	echo 0x29020 0x1 > $DCC_PATH/config
	echo 0x29028 0x1 > $DCC_PATH/config
	echo 0x2902c 0x1 > $DCC_PATH/config
	echo 0x29030 0x1 > $DCC_PATH/config
	echo 0x29034 0x1 > $DCC_PATH/config
	echo 0x2a014 0x1 > $DCC_PATH/config
	echo 0x2a01c 0x1 > $DCC_PATH/config
	echo 0x2a020 0x1 > $DCC_PATH/config
	echo 0x2a028 0x1 > $DCC_PATH/config
	echo 0x2a02c 0x1 > $DCC_PATH/config
	echo 0x2a030 0x1 > $DCC_PATH/config
	echo 0x2a034 0x1 > $DCC_PATH/config
	echo 0x2b014 0x1 > $DCC_PATH/config
	echo 0x2b01c 0x1 > $DCC_PATH/config
	echo 0x2b020 0x1 > $DCC_PATH/config
	echo 0x2b028 0x1 > $DCC_PATH/config
	echo 0x2b02c 0x1 > $DCC_PATH/config
	echo 0x2b030 0x1 > $DCC_PATH/config
	echo 0x2b034 0x1 > $DCC_PATH/config
	echo 0x2c014 0x1 > $DCC_PATH/config
	echo 0x2c01c 0x1 > $DCC_PATH/config
	echo 0x2c020 0x1 > $DCC_PATH/config
	echo 0x2c028 0x1 > $DCC_PATH/config
	echo 0x2c02c 0x1 > $DCC_PATH/config
	echo 0x2c030 0x1 > $DCC_PATH/config
	echo 0x2c034 0x1 > $DCC_PATH/config
	echo 0x28014 0x1 > $DCC_PATH/config
	echo 0x2801c 0x1 > $DCC_PATH/config
	echo 0x28020 0x1 > $DCC_PATH/config
	echo 0x28028 0x1 > $DCC_PATH/config
	echo 0x2802c 0x1 > $DCC_PATH/config
	echo 0x28030 0x1 > $DCC_PATH/config
	echo 0x28034 0x1 > $DCC_PATH/config
	echo 0x30014 0x1 > $DCC_PATH/config
	echo 0x3001c 0x1 > $DCC_PATH/config
	echo 0x30020 0x1 > $DCC_PATH/config
	echo 0x30028 0x1 > $DCC_PATH/config
	echo 0x3002c 0x1 > $DCC_PATH/config
	echo 0x30030 0x1 > $DCC_PATH/config
	echo 0x30034 0x1 > $DCC_PATH/config
	echo 0x8801014 0x1 > $DCC_PATH/config
	echo 0x880101c 0x1 > $DCC_PATH/config
	echo 0x8801020 0x1 > $DCC_PATH/config
	echo 0x8801028 0x1 > $DCC_PATH/config
	echo 0x880102c 0x1 > $DCC_PATH/config
	echo 0x8801030 0x1 > $DCC_PATH/config
	echo 0x8801034 0x1 > $DCC_PATH/config
	echo 0x8800014 0x1 > $DCC_PATH/config
	echo 0x880001c 0x1 > $DCC_PATH/config
	echo 0x8800020 0x1 > $DCC_PATH/config
	echo 0x8800028 0x1 > $DCC_PATH/config
	echo 0x880002c 0x1 > $DCC_PATH/config
	echo 0x8800030 0x1 > $DCC_PATH/config
	echo 0x8800034 0x1 > $DCC_PATH/config
	echo 0x448120 0x1 > $DCC_PATH/config
	echo 0x448128 0x1 > $DCC_PATH/config
	echo 0x44812c 0x1 > $DCC_PATH/config
	echo 0x448130 0x1 > $DCC_PATH/config
	echo 0x448100 0x1 > $DCC_PATH/config
	echo 0x448020 0x1 > $DCC_PATH/config

	#GCC_SYSTEM_NOC
	echo 0x1826004 0x2 > $DCC_PATH/config

	echo 1 > $DCC_PATH/enable

	echo "++++ $0 -> DCC-Enable END" > /dev/kmsg

        echo "++++ $0 -> ENABLE-FTRACE START" > /dev/kmsg
        #Enable FTRACE_ENABLE on QCS40x
	#bail out if its perf config
	if [ ! -d /sys/module/msm_rtb ]
	then
		echo "++++ $0 -> Not a debug build. No RTB" > /dev/kmsg
		return
	fi

	#bail out if coresight isn't present
	if [ ! -d /sys/bus/coresight ]
	then
		echo "++++ $0 -> Not a debug build. No Coresight" > /dev/kmsg
		return
	fi

	#coresight
	echo sg > /sys/bus/coresight/devices/coresight-tmc-etr/mem_type

	echo 0 > /sys/kernel/debug/tracing/events/enable
	echo mem > /sys/bus/coresight/devices/coresight-tmc-etr/out_mode
	echo 1 > /sys/bus/coresight/devices/coresight-tmc-etr/enable_sink
	echo 1 > /sys/bus/coresight/devices/coresight-stm/enable_source
	echo 1 > /sys/kernel/debug/tracing/tracing_on

	#SoftIRQs
	echo 1 > /sys/kernel/debug/tracing/events/irq/enable
	#echo 1 > /sys/kernel/debug/tracing/events/irq/filter
	echo 1 > /sys/kernel/debug/tracing/events/irq/softirq_entry/enable
	echo 1 > /sys/kernel/debug/tracing/events/irq/softirq_exit/enable
	echo 1 > /sys/kernel/debug/tracing/events/irq/softirq_raise/enable
	#IRQs
	echo 1 > /sys/kernel/debug/tracing/events/irq/enable
	echo 1 > /sys/kernel/debug/tracing/events/irq/irq_handler_entry/enable
	echo 1 > /sys/kernel/debug/tracing/events/irq/irq_handler_exit/enable
	echo "++++ $0 -> FTRACE-Enable END" > /dev/kmsg

	echo "++++ $0 -> END" > /dev/kmsg
}
