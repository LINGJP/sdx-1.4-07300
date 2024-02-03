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

#ifndef _DSRC_DCC_H_
#define _DSRC_DCC_H_

/**
 * @file dsrc_dcc.h
 * @brief
 * This file describes the structures and data types used for the network
 * design limits used for the decentralized congestion control (DCC) algorithm.
 * This algorithm backs off the transmit parameters to reduce congestion on the
 * channel.
 */

 /** @addtogroup dcc_algorithm
 @{
 */

/**
@name
@{
This section describes the structures and data types used for the network
design limits used for the decentralized congestion control (DCC) algorithm.
This algorithm backs off the transmit parameters to reduce congestion on the
channel.

The following table lists the DCC types as described in ETSI TS 102 687. @vertspace{6}

| Type                   |  Format          | stepSize  | referenceValue  | numBits |
|:-----------------------|:-----------------|:----------|:----------------|:--------|
| ndlType_acPrio         | INTEGER (0...7)  | 1         | number          | 3       |
| ndlType_controlLoop    | INTEGER (0...7)  | 1         | 0               | 3       |
| ndlType_arrivalRate    | INTEGER (0..8191)| 0.01 /s   | 0               | 13      |
| ndlType_channelLoad    | INTEGER (0..1000)|0.1 %      | 0 %             | 10      |
| ndlType_channelUse     | INTEGER (0..8000)|0.0125 %   | 0 %             | 13      |
| ndlType_datarate       | INTEGER (0..7)   |           | Table 8         | 3       |
| ndlType_distance       | INTEGER (0..4095)| 1 m       | 0               | 12      |
| ndlType_numberElements | INTEGER (0..63)  |           | number          | 6       |
| ndlType_packetDuration | INTEGER (0..2047)| TSYM      | 0               | 11      |
| ndlType_packetInterval | INTEGER (0..1023)| 10 ms     | 0               | 10      |
| ndlType_pathloss       | INTEGER (0..31)  | 0.1       | 1.0             | 5       |
| ndlType_rxPower        | INTEGER (0..127) | -0.5 dB   | -40 dBm         | 7       |
| ndlType_snr            | INTEGER (0..127) | 0.5 dB    | -10 dB          | 7       |
| ndlType_timing         | INTEGER (0..4095)| 10 ms     | 0               | 12      |
| ndlType_txPower        | INTEGER (0..127) | 0.5 dB    | -20 dBm         | 7       |
| ndlType_ratio          | INTEGER (0..100) | 1 %       | 0 %             | 7       |
| ndlType_exponent       | INTEGER (0..100) | 0.1       | 0               | 7       |
| ndlType_queueStatus    | Enumeration      |           | Table A.2       | 1       |
| ndlType_dccMechanism   | Bitset           |           | Table A.2       | 6       |

@newpage

<b>Size Macros</b>

The following size macros (SIZE_NDLTYPE_ACPRIO through SIZE_BYTE)
cannot be changed without breaking DCC compatibility. The sizes are in number
of bits.

For each of the types, one additional bit is allocated. This
leftmost bit is used to indicate that the value is invalid.
*/

#define SIZE_NDLTYPE_ACPRIO         (1 + 3)  /**< Size of the ndlType_acPrio datatype. */
#define SIZE_NDLTYPE_CONTROLLOOP    (1 + 3)  /**< Size of the ndlType_controlLoop datatype. */
#define SIZE_NDLTYPE_ARRIVALRATE    (1 + 13) /**< Size of the ndlType_arrivalRate datatype. */
#define SIZE_NDLTYPE_CHANNELLOAD    (1 + 10) /**< Size of the ndlType_channelLoad datatype. */
#define SIZE_NDLTYPE_CHANNELUSE     (1 + 13) /**< Size of the ndlType_channelUse datatype. */
#define SIZE_NDLTYPE_DATARATE       (1 + 3)  /**< Size of the ndlType_datarate datatype. */
#define SIZE_NDLTYPE_DISTANCE       (1 + 12) /**< Size of the ndlType_distance datatype. */
#define SIZE_NDLTYPE_NUMBERELEMENTS (1 + 6)  /**< Size of the ndlType_numberElements datatype. */
#define SIZE_NDLTYPE_PACKETDURATION (1 + 11) /**< Size of the ndlType_packetDuration datatype. */
#define SIZE_NDLTYPE_PACKETINTERVAL (1 + 10) /**< Size of the ndlType_packetInterval datatype. */
#define SIZE_NDLTYPE_PATHLOSS       (1 + 5)  /**< Size of the ndlType_pathloss datatype. */
#define SIZE_NDLTYPE_RXPOWER        (1 + 7)  /**< Size of the ndlType_rxPower datatype. */
#define SIZE_NDLTYPE_SNR            (1 + 7)  /**< Size of the ndlType_snr datatype. */
#define SIZE_NDLTYPE_TIMING         (1 + 12) /**< Size of the ndlType_timing datatype. */
#define SIZE_NDLTYPE_TXPOWER        (1 + 7)  /**< Size of the ndlType_txPower datatype. */
#define SIZE_NDLTYPE_RATIO          (1 + 7)  /**< Size of the ndlType_ratio datatype. */
#define SIZE_NDLTYPE_EXPONENT       (1 + 7)  /**< Size of the ndlType_exponent datatype. */
#define SIZE_NDLTYPE_QUEUESTATUS    (1 + 1)  /**< Size of the ndlType_queueStatus datatype. */
#define SIZE_NDLTYPE_DCCMECHANISM   (1 + 6)  /**< Size of the ndlType_dccMechanism datatype. */
#define SIZE_BYTE                   (8)      /**< Size of a byte in bits. */

#define INVALID_ACPRIO          ((1 << SIZE_NDLTYPE_ACPRIO) - 1) /**< Value for invalid ndlType_acPrio. */
#define INVALID_CONTROLLOOP     ((1 << SIZE_NDLTYPE_CONTROLLOOP) - 1) /**< Value for invalid ndlType_controlLoop. */
#define INVALID_ARRIVALRATE     ((1 << SIZE_NDLTYPE_ARRIVALRATE) - 1) /**< Value for invalid ndlType_arrivalRate. */
#define INVALID_CHANNELLOAD     ((1 << SIZE_NDLTYPE_CHANNELLOAD) - 1) /**< Value for invalid ndlType_channelLoad. */
#define INVALID_CHANNELUSE      ((1 << SIZE_NDLTYPE_CHANNELUSE) - 1) /**< Value for invalid ndlType_channelUse. */
#define INVALID_DATARATE        ((1 << SIZE_NDLTYPE_DATARATE) - 1) /**< Value for invalid ndlType_dataRate. */
#define INVALID_DISTANCE        ((1 << SIZE_NDLTYPE_DISTANCE) - 1) /**< Value for invalid ndlType_distance. */
#define INVALID_NUMBERELEMENTS  ((1 << SIZE_NDLTYPE_NUMBERELEMENTS) - 1) /**< Value for invalid ndlType_numberElements. */
#define INVALID_PACKETDURATION  ((1 << SIZE_NDLTYPE_PACKETDURATION) - 1) /**< Value for invalid ndlType_packetDuration. */
#define INVALID_PACKETINTERVAL  ((1 << SIZE_NDLTYPE_PACKETINTERVAL) - 1) /**< Value for invalid ndlType_packetInterval. */
#define INVALID_PATHLOSS        ((1 << SIZE_NDLTYPE_PATHLOSS) - 1) /**< Value for invalid ndlType_pathLoss. */
#define INVALID_RXPOWER         ((1 << SIZE_NDLTYPE_RXPOWER) - 1) /**< Value for invalid ndlType_rxPower. */
#define INVALID_SNR             ((1 << SIZE_NDLTYPE_SNR) - 1) /**< Value for invalid ndlType_snr. */
#define INVALID_TIMING          ((1 << SIZE_NDLTYPE_TIMING) - 1) /**< Value for invalid ndlType_timing. */
#define INVALID_TXPOWER         ((1 << SIZE_NDLTYPE_TXPOWER) - 1) /**< Value for invalid ndlType_txPower. */
#define INVALID_RATIO           ((1 << SIZE_NDLTYPE_RATIO) - 1) /**< Value for invalid ndlType_ratio. */
#define INVALID_EXPONENT        ((1 << SIZE_NDLTYPE_EXPONENT) - 1) /**< Value for invalid ndlType_exponent. */
#define INVALID_QUEUESTATS      ((1 << SIZE_NDLTYPE_QUEUESTATUS) - 1) /**< Value for invalid ndlType_queueStats. */
#define INVALID_DCCMECHANISM    ((1 << SIZE_NDLTYPE_DCCMECHANISM) - 1) /**< Value for invalid ndlType_dccMechanism. */

 /** @} */ /* end_namegroup */

/**
Number of valid modulation and coding schemes (MCS).
The MCS_COUNT macro cannot be modified without breaking
DCC compatibility.
*/
#define MCS_COUNT               (8)

 /** @} */ /* end_addtogroup dcc_algorithm */

 /** @addtogroup dcc_algorithm
 @{ */

/** Access categories */
typedef enum {
   DCC_AC_VO  = 0, /**< Access category for voice. */
   DCC_AC_VI  = 1, /**< Access category for video. */
   DCC_AC_BE  = 2, /**< Access category for best effort. */
   DCC_AC_BK  = 3, /**< Access category for background. */
   DCC_AC_MAX = 4, /**< One greater than the last access category. */
} dcc_traffic_ac;

 /** @} */ /* end_addtogroup dcc_algorithm */

 /** @addtogroup dcc_algorithm
 @{ */

/** Number of access categories. */
#define WLAN_MAX_AC             (4)

/**
Gets the bits at the given index in a uint32_t value.

@param[out] _val The uint32_t value.
@param[in] _index Index of the first bit to read.
@param[in] _num_bits Number of bits to read.

@return
The value of the bits at the given index.
@hideinitializer
*/
#define DCC_GET_BITS(_val,_index,_num_bits)                         \
    (((_val) >> (_index)) & ((1 << (_num_bits)) - 1))

/**
Sets the bits at the given index in a uint32_t value.

@param[in] _var The uint32_t value.
@param[in] _index Index of the first bit to set.
@param[in] _num_bits Number of bits to set.
@param[in] _val Value to which to set the bits.

@return
None.
@hideinitializer
 */
#define DCC_SET_BITS(_var,_index,_num_bits,_val) do {               \
    (_var) &= ~(((1 << (_num_bits)) - 1) << (_index));              \
    (_var) |= (((_val) & ((1 << (_num_bits)) - 1)) << (_index));    \
    } while(0)

/**
Calculates the number of uint32_ts required to store the packed bit array.

@param[in] num_entries Number of elements in the packed bit array.
@param[in] bits_per_entry Size of each element in bits.

@return
The number of uit32_ts required to store the packed bit array.
@hideinitializer
*/
#define DCC_PACKED_ARR_SIZE(num_entries,bits_per_entry) \
    (((num_entries) / (32 / (bits_per_entry))) +            \
    (((num_entries) % (32 / (bits_per_entry))) ? 1 : 0))

 /** @} */ /* end_addtogroup dcc_algorithm */

 /** @addtogroup dcc_algorithm
 @{ */

/**
Returns the bits at the given index in a packed bit array.

@param[in] arr Variable containing the packed bit array.
@param[in] entry_index Index of the element to be read.
@param[in] bits_per_entry Number of bits of each element in the array.

@return
The value of the bits at the given index in the packed bit array.
*/
static inline unsigned long dcc_packed_arr_get_bits(unsigned long *arr,
    unsigned long entry_index, unsigned long bits_per_entry)
{
    unsigned long entries_per_uint = (32 / bits_per_entry);
    unsigned long uint_index = (entry_index / entries_per_uint);
    unsigned long num_entries_in_prev_uints = (uint_index * entries_per_uint);
    unsigned long index_in_uint = (entry_index - num_entries_in_prev_uints);
    unsigned long start_bit_in_uint = (index_in_uint * bits_per_entry);
    return ((arr[uint_index] >> start_bit_in_uint) &
            (( 1 << bits_per_entry) - 1));
}

/**
Sets the bits at the given index in a packed bit array.

@param[in] arr Variable containing the packed bit array.
@param[in] entry_index Index of the element to write.
@param[in] bits_per_entry Number of bits of each element of the array.
@param[in] val Value to set.

@return
None.
*/
static inline void dcc_packed_arr_set_bits(unsigned int *arr, unsigned int entry_index,
	unsigned int bits_per_entry, unsigned int val)

 {
	 unsigned int entries_per_uint = (32 / bits_per_entry);
	 unsigned int uint_index = (entry_index / entries_per_uint);
	 unsigned int num_entries_in_prev_uints = (uint_index * entries_per_uint);
	 unsigned int index_in_uint = (entry_index - num_entries_in_prev_uints);
	 unsigned int start_bit_in_uint = (index_in_uint * bits_per_entry);

	 arr[uint_index] &= ~(((1 << bits_per_entry) - 1) << start_bit_in_uint);
	 arr[uint_index] |=
		 ((val & ((1 << bits_per_entry) - 1)) << start_bit_in_uint);
 }


 /** @} */ /* end_addtogroup dcc_algorithm */

 /** @addtogroup dcc_algorithm
 @{ */

/** Flags for ndlType_dccMechanism. */
typedef enum {
    DCC_MECHANISM_TPC = 1, /**< Flag for transmit power control. */
    DCC_MECHANISM_TRC = 2, /**< Flag for transmit rate control. */
    DCC_MECHANISM_TDC = 4, /**< Flag for transmit datarate control. */
    DCC_MECHANISM_DSC = 8, /**< Flag for dynamic sensitivity control. */
    DCC_MECHANISM_TAC = 16, /**< Flag for transmit access control. */
    DCC_MECHANISM_RESERVED = 32, /**< Reserved. */
    DCC_MECHANISM_ALL = 0x3f, /**< Mask for all DCC mechanisms. */
} dcc_ndl_type_dcc_mechanism;

/** Values for ndlType_queueStatus. */
typedef enum {
    DCC_QUEUE_CLOSED = 0, /**< Queue is closed. */
    DCC_QUEUE_OPEN = 1,   /**< Queue is open. */
} dcc_ndl_type_queue_status;

/* For ndlType_acPrio, use the values in dcc_traffic_ac. */

/** Values for ndlType_datarate. */
typedef enum {
    DCC_DATARATE_3_MBPS = 0,    /**< Data rate 3 Mbps. */
    DCC_DATARATE_4_5_MBPS = 1,  /**< Data rate 4.5 Mbps. */
    DCC_DATARATE_6_MBPS = 2,    /**< Data rate 6 Mbps. */
    DCC_DATARATE_9_MBPS = 3,    /**< Data rate 9 Mbps. */
    DCC_DATARATE_12_MBPS = 4,   /**< Data rate 12 Mbps. */
    DCC_DATARATE_18_MBPS = 5,   /**< Data rate 18 Mbps. */
    DCC_DATARATE_24_MBPS = 6,   /**< Data rate 24 Mbps. */
    DCC_DATARATE_27_MBPS = 7,   /**< Data rate 27 Mbps. */
} dcc_ndl_type_datarate;


 /** @} */ /* end_addtogroup dcc_algorithm */

 /** @addtogroup dcc_algorithm
 @{ */

/** Data structure for active state configuration. */
 typedef struct {
	 unsigned int tlv_header;
	 /**< Reserved. This must be 0. */
	 unsigned int state_info;
	 /**< Active State ID and Channel Load.
	  *
	  * NDL_asStateId, ndlType_numberElements, 1+6 bits. <br>
	  * NDL_asChanLoad, ndlType_channelLoad, 1+10 bits.
	  */
	 unsigned int as_dcc[DCC_PACKED_ARR_SIZE(WLAN_MAX_AC, SIZE_NDLTYPE_DCCMECHANISM)];
	 /**< Enabled DCC mechanisms for each access category.
	  *
	  * NDL_asDcc(AC_BK), ndlType_dccMechanism, 1+6 bits. <br>
	  * NDL_asDcc(AC_BE), ndlType_dccMechanism, 1+6 bits. <br>
	  * NDL_asDcc(AC_VI), ndlType_dccMechanism, 1+6 bits. <br>
	  * NDL_asDcc(AC_VO), ndlType_dccMechanism, 1+6 bits.
	  */
	 unsigned int as_tx_power_ac[DCC_PACKED_ARR_SIZE(WLAN_MAX_AC, SIZE_NDLTYPE_TXPOWER)];
	 /**< Maximum TX power for each access category.
	  *
	  * NDL_asTxPower(AC_BK), ndlType_txPower, 1+7 bits. <br>
	  * NDL_asTxPower(AC_BE), ndlType_txPower, 1+7 bits. <br>
	  * NDL_asTxPower(AC_VI), ndlType_txPower, 1+7 bits. <br>
	  * NDL_asTxPower(AC_VO), ndlType_txPower, 1+7 bits.
	  */
	 unsigned int as_packet_interval_ac[DCC_PACKED_ARR_SIZE(WLAN_MAX_AC, SIZE_NDLTYPE_PACKETINTERVAL)];
	 /**< Minimum packet interval for each access category.
	  *
	  * NDL_asPacketInterval(AC_BK), ndlType_packetInterval, 1+10 bits. <br>
	  * NDL_asPacketInterval(AC_BE), ndlType_packetInterval, 1+10 bits. <br>
	  * NDL_asPacketInterval(AC_VI), ndlType_packetInterval, 1+10 bits. <br>
	  * NDL_asPacketInterval(AC_VO), ndlType_packetInterval, 1+10 bits.
	  */
	 unsigned int as_datarate_ac[DCC_PACKED_ARR_SIZE(WLAN_MAX_AC, SIZE_NDLTYPE_DATARATE)];
	 /**< Minimum datarate (MCS) for each access category.
	  *
	  * NDL_asDatarate(AC_BK), ndlType_datarate, 1+3 bits. <br>
	  * NDL_asDatarate(AC_BE), ndlType_datarate, 1+3 bits. <br>
	  * NDL_asDatarate(AC_VI), ndlType_datarate, 1+3 bits. <br>
	  * NDL_asDatarate(AC_VO), ndlType_datarate, 1+3 bits.
	  */
	 unsigned int as_carrier_sense_ac[DCC_PACKED_ARR_SIZE(WLAN_MAX_AC, SIZE_NDLTYPE_RXPOWER)];
	 /**< Carrier sense threshold for each access category.
	  *
	  * NDL_asCarrierSense(AC_BK), ndlType_rxPower, 1+7 bits. <br>
	  * NDL_asCarrierSense(AC_BE), ndlType_rxPower, 1+7 bits. <br>
	  * NDL_asCarrierSense(AC_VI), ndlType_rxPower, 1+7 bits. <br>
	  * NDL_asCarrierSense(AC_VO), ndlType_rxPower, 1+7 bits.
	  */
 } dcc_ndl_active_state_config;

 /** @} */ /* end_addtogroup dcc_algorithm */

 /** @addtogroup dcc_algorithm
 @{ */

 /**@name Macros to Read and Write to dcc_ndl_active_state_config
 @{ */

#define DCC_NDL_AS_STATE_ID_GET(ptr)                    DCC_GET_BITS((ptr)->state_info, 0, 7)
#define DCC_NDL_AS_STATE_ID_SET(ptr,val)                DCC_SET_BITS((ptr)->state_info, 0, 7, val)
#define DCC_NDL_AS_CHAN_LOAD_GET(ptr)                   DCC_GET_BITS((ptr)->state_info, 7, 11)
#define DCC_NDL_AS_CHAN_LOAD_SET(ptr,val)               DCC_SET_BITS((ptr)->state_info, 7, 11, val)
#define DCC_NDL_AS_DCC_GET(ptr,acprio)                  dcc_packed_arr_get_bits((ptr)->as_dcc, acprio, SIZE_NDLTYPE_DCCMECHANISM)
#define DCC_NDL_AS_DCC_SET(ptr,acprio,val)              dcc_packed_arr_set_bits((ptr)->as_dcc, acprio, SIZE_NDLTYPE_DCCMECHANISM, val)
#define DCC_NDL_AS_TX_POWER_GET(ptr,acprio)             dcc_packed_arr_get_bits((ptr)->as_tx_power_ac, acprio, SIZE_NDLTYPE_TXPOWER)
#define DCC_NDL_AS_TX_POWER_SET(ptr,acprio,val)         dcc_packed_arr_set_bits((ptr)->as_tx_power_ac, acprio, SIZE_NDLTYPE_TXPOWER, val)
#define DCC_NDL_AS_PACKET_INTERVAL_GET(ptr,acprio)      dcc_packed_arr_get_bits((ptr)->as_packet_interval_ac, acprio, SIZE_NDLTYPE_PACKETINTERVAL)
#define DCC_NDL_AS_PACKET_INTERVAL_SET(ptr,acprio,val)  dcc_packed_arr_set_bits((ptr)->as_packet_interval_ac, acprio, SIZE_NDLTYPE_PACKETINTERVAL, val)
#define DCC_NDL_AS_DATARATE_GET(ptr,acprio)             dcc_packed_arr_get_bits((ptr)->as_datarate_ac, acprio, SIZE_NDLTYPE_DATARATE)
#define DCC_NDL_AS_DATARATE_SET(ptr,acprio,val)         dcc_packed_arr_set_bits((ptr)->as_datarate_ac, acprio, SIZE_NDLTYPE_DATARATE, val)
#define DCC_NDL_AS_CARRIER_SENSE_GET(ptr,acprio)        dcc_packed_arr_get_bits((ptr)->as_carrier_sense_ac, acprio, SIZE_NDLTYPE_RXPOWER)
#define DCC_NDL_AS_CARRIER_SENSE_SET(ptr,acprio,val)    dcc_packed_arr_set_bits((ptr)->as_carrier_sense_ac, acprio, SIZE_NDLTYPE_RXPOWER, val)

 /** @} */ /* end_namegroup */

 /** @} */ /* end_addtogroup dcc_algorithm */

 /** @addtogroup dcc_algorithm
 @{ */

/** Data structure for DCC stats configuration per channel. */
typedef struct {
    unsigned long tlv_header;
    /**< Reserved. This must be 0. */
    unsigned long chan_info;
    /**< Channel frequency and stats bitmap.
     *
     * The channel for which this applies, 16 bits. <br>
     * The dcc_stats_bitmap, 8 bits. */

    unsigned long snr_backoff_mcs[DCC_PACKED_ARR_SIZE(MCS_COUNT,SIZE_NDLTYPE_SNR)];
    /**< Demodulation model parameters.
     *
     * NDL_snrBackoff(MCS0), ndlType_snr, 1+7 bits. <br>
     * NDL_snrBackoff(MCS1), ndlType_snr, 1+7 bits. <br>
     * NDL_snrBackoff(MCS2), ndlType_snr, 1+7 bits. <br>
     * NDL_snrBackoff(MCS3), ndlType_snr, 1+7 bits. <br>
     * NDL_snrBackoff(MCS4), ndlType_snr, 1+7 bits. <br>
     * NDL_snrBackoff(MCS5), ndlType_snr, 1+7 bits. <br>
     * NDL_snrBackoff(MCS6), ndlType_snr, 1+7 bits. <br>
     * NDL_snrBackoff(MCS7), ndlType_snr, 1+7 bits.
     */

    unsigned long tx_power_datarate;
    /**< Transmit power and datarate.
     *
     * tx_power, ndlType_txPower, 1+7 bits. <br>
     * datarate, ndlType_datarate, 1+3 bits.
     */
    unsigned long carrier_sense_est_comm_range;
    /**< Carrier sense range and estimated communication range.
     *
     * NDL_carrierSenseRange, ndlType_distance, 1+12 bits. <br>
     * NDL_estCommRange, ndlType_distance, 1+12 bits.
     */

    unsigned long dcc_stats;
    /**< Channel load measures.
     *
     * dccSensitivity, ndlType_rxPower, 1+7 bits. <br>
     * carrierSense, ndlType_rxPower, 1+7 bits. <br>
     * NDL_channelLoad, ndlType_channelLoad, 1+10 bits.
     */
    unsigned long packet_stats;
    /**< Packet arrival rate and average packet duration.
     *
     * NDL_packetArrivalRate, ndlType_arrivalRate, 1+13 bits. <br>
     * NDL_packetAvgDuration, ndlType_packetDuration, 1+11 bits.
     */
    unsigned long channel_busy_time;
    /**< Channel busy time.
     *
     * NDL_channelBusyTime, ndlType_channelLoad, 1+10 bits.
     */

    unsigned long tx_packet_arrival_rate_ac[DCC_PACKED_ARR_SIZE(WLAN_MAX_AC,SIZE_NDLTYPE_ARRIVALRATE)];
    /**< Packet arrival rate for each access category.
     *
     * NDL_txPacketArrivalRate(AC_BK), ndlType_arrivalRate, 1+13 bits. <br>
     * NDL_txPacketArrivalRate(AC_BE), ndlType_arrivalRate, 1+13 bits. <br>
     * NDL_txPacketArrivalRate(AC_VI), ndlType_arrivalRate, 1+13 bits. <br>
     * NDL_txPacketArrivalRate(AC_VO), ndlType_arrivalRate, 1+13 bits.
     */
    unsigned long tx_packet_avg_duration_ac[DCC_PACKED_ARR_SIZE(WLAN_MAX_AC,SIZE_NDLTYPE_PACKETDURATION)];
    /**< Average packet duration for each access category.
     *
     * NDL_txPacketAvgDuration(AC_BK), ndlType_packetDuration, 1+11 bits. <br>
     * NDL_txPacketAvgDuration(AC_BE), ndlType_packetDuration, 1+11 bits. <br>
     * NDL_txPacketAvgDuration(AC_VI), ndlType_packetDuration, 1+11 bits. <br>
     * NDL_txPacketAvgDuration(AC_VO), ndlType_packetDuration, 1+11 bits.
     */
    unsigned long tx_channel_use_ac[DCC_PACKED_ARR_SIZE(WLAN_MAX_AC,SIZE_NDLTYPE_CHANNELUSE)];
    /**< Channel use ratio for each access category.
     *
     * NDL_txChannelUse(AC_BK), ndlType_channelUse, 1+13 bits. <br>
     * NDL_txChannelUse(AC_BE), ndlType_channelUse, 1+13 bits. <br>
     * NDL_txChannelUse(AC_VI), ndlType_channelUse, 1+13 bits. <br>
     * NDL_txChannelUse(AC_VO), ndlType_channelUse, 1+13 bits.
     */
    unsigned long tx_signal_avg_power_ac[DCC_PACKED_ARR_SIZE(WLAN_MAX_AC,SIZE_NDLTYPE_TXPOWER)];
    /**< Average transmit signal power for each access category.
     *
     * NDL_txSignalAvgPower(AC_BK), ndlType_txPower, 1+7 bits. <br>
     * NDL_txSignalAvgPower(AC_BE), ndlType_txPower, 1+7 bits. <br>
     * NDL_txSignalAvgPower(AC_VI), ndlType_txPower, 1+7 bits. <br>
     * NDL_txSignalAvgPower(AC_VO), ndlType_txPower, 1+7 bits.
     */
} dcc_ndl_stats_per_channel;

 /** @} */ /* end_addtogroup dcc_algorithm */

 /** @addtogroup dcc_algorithm
 @{ */

 /**@name Macros to Read and Write to dcc_ndl_stats_per_channel
 @{ */

#define DCC_NDL_STATS_CHAN_FREQ_GET(ptr)            DCC_GET_BITS((ptr)->chan_info, 0, 16)
#define DCC_NDL_STATS_CHAN_FREQ_SET(ptr,val)        DCC_SET_BITS((ptr)->chan_info, 0, 16, val)
#define DCC_NDL_STATS_DCC_STATS_BITMAP_GET(ptr)     DCC_GET_BITS((ptr)->chan_info, 16, 8)
#define DCC_NDL_STATS_DCC_STATS_BITMAP_SET(ptr,val) DCC_SET_BITS((ptr)->chan_info, 16, 8, val)

#define DCC_NDL_STATS_SNR_BACKOFF_GET(ptr,mcs)      dcc_packed_arr_get_bits((ptr)->snr_backoff_mcs, mcs, SIZE_NDLTYPE_SNR)
#define DCC_NDL_STATS_SNR_BACKOFF_SET(ptr,mcs,val)  dcc_packed_arr_set_bits((ptr)->snr_backoff_mcs, mcs, SIZE_NDLTYPE_SNR, val)

#define DCC_TX_POWER_GET(ptr)                       DCC_GET_BITS((ptr)->tx_power_datarate, 0, 8)
#define DCC_TX_POWER_SET(ptr,val)                   DCC_SET_BITS((ptr)->tx_power_datarate, 0, 8, val)
#define DCC_TX_DATARATE_GET(ptr)                    DCC_GET_BITS((ptr)->tx_power_datarate, 0, 4)
#define DCC_TX_DATARATE_SET(ptr,val)                DCC_SET_BITS((ptr)->tx_power_datarate, 0, 4, val)
#define DCC_NDL_CARRIER_SENSE_RANGE_GET(ptr)        DCC_GET_BITS((ptr)->carrier_sense_est_comm_range, 0, 13)
#define DCC_NDL_CARRIER_SENSE_RANGE_SET(ptr,val)    DCC_SET_BITS((ptr)->carrier_sense_est_comm_range, 0, 13, val)
#define DCC_NDL_EST_COMM_RANGE_GET(ptr)             DCC_GET_BITS((ptr)->carrier_sense_est_comm_range, 13, 13)
#define DCC_NDL_EST_COMM_RANGE_SET(ptr,val)         DCC_SET_BITS((ptr)->carrier_sense_est_comm_range, 13, 13, val)

#define DCC_DCC_SENSITIVITY_GET(ptr)                DCC_GET_BITS((ptr)->dcc_stats, 0, 8)
#define DCC_DCC_SENSITIVITY_SET(ptr,val)            DCC_SET_BITS((ptr)->dcc_stats, 0, 8, val)
#define DCC_CARRIER_SENSE_GET(ptr)                  DCC_GET_BITS((ptr)->dcc_stats, 8, 8)
#define DCC_CARRIER_SENSE_SET(ptr,val)              DCC_SET_BITS((ptr)->dcc_stats, 8, 8, val)
#define DCC_NDL_CHANNEL_LOAD_GET(ptr)               DCC_GET_BITS((ptr)->dcc_stats, 16, 11)
#define DCC_NDL_CHANNEL_LOAD_SET(ptr,val)           DCC_SET_BITS((ptr)->dcc_stats, 16, 11, val)
#define DCC_NDL_PACKET_ARRIVAL_RATE_GET(ptr)        DCC_GET_BITS((ptr)->packet_stats, 0, 14)
#define DCC_NDL_PACKET_ARRIVAL_RATE_SET(ptr,val)    DCC_SET_BITS((ptr)->packet_stats, 0, 14, val)
#define DCC_NDL_PACKET_AVG_DURATION_GET(ptr)        DCC_GET_BITS((ptr)->packet_stats, 14, 12)
#define DCC_NDL_PACKET_AVG_DURATION_SET(ptr,val)    DCC_SET_BITS((ptr)->packet_stats, 14, 12, val)
#define DCC_NDL_CHANNEL_BUSY_TIME_GET(ptr)          DCC_GET_BITS((ptr)->channel_busy_time, 0, 11)
#define DCC_NDL_CHANNEL_BUSY_TIME_SET(ptr,val)      DCC_SET_BITS((ptr)->channel_busy_time, 0, 11, val)

#define DCC_NDL_TX_PACKET_ARRIVAL_RATE_GET(ptr,acprio)          dcc_packed_arr_get_bits((ptr)->tx_packet_arrival_rate_ac, acprio, SIZE_NDLTYPE_ARRIVALRATE)
#define DCC_NDL_TX_PACKET_ARRIVAL_RATE_SET(ptr,acprio,val)      dcc_packed_arr_set_bits((ptr)->tx_packet_arrival_rate_ac, acprio, SIZE_NDLTYPE_ARRIVALRATE, val)
#define DCC_NDL_TX_PACKET_AVG_DURATION_GET(ptr,acprio)          dcc_packed_arr_get_bits((ptr)->tx_packet_avg_duration_ac, acprio, SIZE_NDLTYPE_PACKETDURATION)
#define DCC_NDL_TX_PACKET_AVG_DURATION_SET(ptr,acprio,val)      dcc_packed_arr_set_bits((ptr)->tx_packet_avg_duration_ac, acprio, SIZE_NDLTYPE_PACKETDURATION, val)
#define DCC_NDL_TX_CHANNEL_USE_GET(ptr,acprio)                  dcc_packed_arr_get_bits((ptr)->tx_channel_use_ac, acprio, SIZE_NDLTYPE_CHANNELUSE)
#define DCC_NDL_TX_CHANNEL_USE_SET(ptr,acprio,val)              dcc_packed_arr_set_bits((ptr)->tx_channel_use_ac, acprio, SIZE_NDLTYPE_CHANNELUSE, val)
#define DCC_NDL_TX_SIGNAL_AVG_POWER_GET(ptr,acprio)             dcc_packed_arr_get_bits((ptr)->tx_signal_avg_power_ac, acprio, SIZE_NDLTYPE_TXPOWER)
#define DCC_NDL_TX_SIGNAL_AVG_POWER_SET(ptr,acprio,val)         dcc_packed_arr_set_bits((ptr)->tx_signal_avg_power_ac, acprio, SIZE_NDLTYPE_TXPOWER, val)

 /** @} */ /* end_namegroup */

 /** @} */ /* end_addtogroup dcc_algorithm */

 /** @addtogroup dcc_algorithm
 @{ */

/** Bitmap for DCC stats. */
typedef enum {
    DCC_STATS_DEMODULATION_MODEL = 1,        /**< Demodulation model. */
    DCC_STATS_COMMUNICATION_RANGES = 2,      /**< Communication ranges. */
    DCC_STATS_CHANNEL_LOAD_MEASURES = 4,     /**< Channel load measures. */
    DCC_STATS_TRANSMIT_PACKET_STATS = 8,     /**< Transmit packet stats. */
    DCC_STATS_TRANSMIT_MODEL_PARAMETER = 16, /**< Transmit model parameter. */
    DCC_STATS_ALL = 0xff,
} dcc_stats_bitmap;

 /** @} */ /* end_addtogroup dcc_algorithm */

 /** @addtogroup dcc_algorithm
 @{ */

/** Data structure for updating NDL per channel. */
typedef struct {
    unsigned int tlv_header;
    /**< Reserved. This must be 0. */

    unsigned int chan_info;
    /**< Channel frequency and number of active states.
     *
     * Channel frequency, 16 bits <br>
     * NDL_numActiveState, ndlType_numberElements, 1+6 bits
     */

    unsigned int ndl_min_dcc_sampling;
    /**< Maximum time interval between subsequent checks of the DCC rules.
     *
     *  NDL_minDccSampling, 10 bits.
     */

    unsigned int dcc_flags;
    /**< DCC flags.
     *
     * dcc_enable, 1 bit. <br>
     * dcc_stats_enable, 1 bit. <br>
     * dcc_stats_interval, 16 bits.
     */

    unsigned int general_config;
    /**< General DCC configuration.
     *
     * NDL_timeUp, ndlType_timing, 1+12 bits. <br>
     * NDL_timeDown, ndlType_timing, 1+12 bits.
     */

    /* see "ETSI TS 102 687" table above for units */
    unsigned int min_max_tx_power;
    /**< Transmit power thresholds.
     *
     * NDL_minTxPower, ndlType_txPower, 1+7 bits. <br>
     * NDL_maxTxPower, ndlType_txPower, 1+7 bits.
     */
    /* see "ETSI TS 102 687" table above for units */
    unsigned int def_tx_power_ac[DCC_PACKED_ARR_SIZE(WLAN_MAX_AC,SIZE_NDLTYPE_TXPOWER)];
    /**< Default Tx power for each access category.
     *
     * NDL_defTxPower(AC_BK), ndlType_txPower, 1+7 bits. <br>
     * NDL_defTxPower(AC_BE), ndlType_txPower, 1+7 bits. <br>
     * NDL_defTxPower(AC_VI), ndlType_txPower, 1+7 bits. <br>
     * NDL_defTxPower(AC_VO), ndlType_txPower, 1+7 bits.
     */

    unsigned int max_packet_duration_ac[DCC_PACKED_ARR_SIZE(WLAN_MAX_AC,SIZE_NDLTYPE_PACKETDURATION)];
    /**< Packet timing thresholds.
     *
     * NDL_maxPacketDuration(AC_BK), ndlType_packetDuration, 1+11 bits. <br>
     * NDL_maxPacketDuration(AC_BE), ndlType_packetDuration, 1+11 bits. <br>
     * NDL_maxPacketDuration(AC_VI), ndlType_packetDuration, 1+11 bits. <br>
     * NDL_maxPacketDuration(AC_VO), ndlType_packetDuration, 1+11 bits.
     */

    unsigned int min_max_packet_interval;
    /**< Minimum and maximum packet interval.
     *
     * NDL_minPacketInterval, ndlType_packetInterval, 1+10 bits. <br>
     * NDL_maxPacketInterval, ndlType_packetInterval, 1+10 bits.
     */

    unsigned int def_packet_interval_ac[DCC_PACKED_ARR_SIZE(WLAN_MAX_AC,SIZE_NDLTYPE_PACKETINTERVAL)];
    /**< Default packet interval for each access category.
     *
     * NDL_defPacketInterval(AC_BK), ndlType_packetInterval, 1+10 bits. <br>
     * NDL_defPacketInterval(AC_BE), ndlType_packetInterval, 1+10 bits. <br>
     * NDL_defPacketInterval(AC_VI), ndlType_packetInterval, 1+10 bits. <br>
     * NDL_defPacketInterval(AC_VO), ndlType_packetInterval, 1+10 bits.
     */

    unsigned int min_max_datarate;
    /**< Packet datarate thresholds.
     *
     * NDL_minDatarate, ndlType_datarate, 1+3 bits. <br>
     * NDL_maxDatarate, ndlType_datarate, 1+3 bits.
     */

    unsigned int def_datarate_ac[DCC_PACKED_ARR_SIZE(WLAN_MAX_AC,SIZE_NDLTYPE_DATARATE)];
    /**< Default datarate (MCS) for each access category.
     *
     * NDL_defDatarate(AC_BK), ndlType_datarate, 1+3 bits. <br>
     * NDL_defDatarate(AC_BE), ndlType_datarate, 1+3 bits. <br>
     * NDL_defDatarate(AC_VI), ndlType_datarate, 1+3 bits. <br>
     * NDL_defDatarate(AC_VO), ndlType_datarate, 1+3 bits.
     */

    unsigned int min_max_def_carrier_sense;
    /**< Receive signal thresholds.
     *
     * NDL_minCarrierSense, ndlType_rxPower, 1+7 bits. <br>
     * NDL_maxCarrierSense, ndlType_rxPower, 1+7 bits. <br>
     * NDL_defCarrierSense, ndlType_rxPower, 1+7 bits.
     */

    unsigned int receive_model_parameter;
    /**< Receive model parameters (DCC sensitivy, max carrier sense range,
     *  reference path loss).
     *
     * NDL_defDccSensitivity, ndlType_rxPower, 1+7 bits. <br>
     * NDL_maxCsRange, ndlType_distance, 1+12 bits. <br>
     * NDL_refPathLoss, ndlType_pathloss, 1+5 bits.
     */

    unsigned int receive_model_parameter_2;
    /**< Receive model paramters (minimum SNR).
     *
     * NDL_minSNR, ndlType_snr, 1+7 bits.
     */

    unsigned int snr_backoff_mcs[DCC_PACKED_ARR_SIZE(MCS_COUNT,SIZE_NDLTYPE_SNR)];
    /**< Demodulation model parameters (SNR backoff for each MCS).
     *
     * NDL_snrBackoff(MCS0), ndlType_snr, 1+7 bits. <br>
     * NDL_snrBackoff(MCS1), ndlType_snr, 1+7 bits. <br>
     * NDL_snrBackoff(MCS2), ndlType_snr, 1+7 bits. <br>
     * NDL_snrBackoff(MCS3), ndlType_snr, 1+7 bits. <br>
     * NDL_snrBackoff(MCS4), ndlType_snr, 1+7 bits. <br>
     * NDL_snrBackoff(MCS5), ndlType_snr, 1+7 bits. <br>
     * NDL_snrBackoff(MCS6), ndlType_snr, 1+7 bits. <br>
     * NDL_snrBackoff(MCS7), ndlType_snr, 1+7 bits.
     */

    unsigned int tm_packet_arrival_rate_ac[DCC_PACKED_ARR_SIZE(WLAN_MAX_AC, SIZE_NDLTYPE_ARRIVALRATE)];
    /**< Transmit model parameters (packet arrive rate for each access
     *  category).
     *
     * NDL_tmPacketArrivalRate(AC_BK), ndlType_arrivalRate, 1+13 bits. <br>
     * NDL_tmPacketArrivalRate(AC_BE), ndlType_arrivalRate, 1+13 bits. <br>
     * NDL_tmPacketArrivalRate(AC_VI), ndlType_arrivalRate, 1+13 bits. <br>
     * NDL_tmPacketArrivalRate(AC_VO), ndlType_arrivalRate, 1+13 bits.
     */

    unsigned int tm_packet_avg_duration_ac[DCC_PACKED_ARR_SIZE(WLAN_MAX_AC, SIZE_NDLTYPE_PACKETDURATION)];
    /**< Transmit model parameters (average packet duration for each access
     * category).
     *
     * NDL_tmPacketAvgDuration(AC_BK), ndlType_packetDuration, 1+11 bits. <br>
     * NDL_tmPacketAvgDuration(AC_BE), ndlType_packetDuration, 1+11 bits. <br>
     * NDL_tmPacketAvgDuration(AC_VI), ndlType_packetDuration, 1+11 bits. <br>
     * NDL_tmPacketAvgDuration(AC_VO), ndlType_packetDuration, 1+11 bits.
     */

    unsigned int tm_signal_avg_power_ac[DCC_PACKED_ARR_SIZE(WLAN_MAX_AC, SIZE_NDLTYPE_TXPOWER)];
    /**< Transmit model parameters (average signal power for each access
     * category).
     *
     * NDL_tmSignalAvgPower(AC_BK), ndlType_txPower, 1+7 bits. <br>
     * NDL_tmSignalAvgPower(AC_BE), ndlType_txPower, 1+7 bits. <br>
     * NDL_tmSignalAvgPower(AC_VI), ndlType_txPower, 1+7 bits. <br>
     * NDL_tmSignalAvgPower(AC_VO), ndlType_txPower, 1+7 bits.
     */

    unsigned int tm_max_channel_use;
    /**< Transmit model parameters (maximum channel use).
     * NDL_tmMaxChannelUse, ndlType_channelUse, 1+13 bits.
     */

    unsigned int tm_channel_use_ac[DCC_PACKED_ARR_SIZE(WLAN_MAX_AC, SIZE_NDLTYPE_CHANNELUSE)];
    /**< Transmit model parameters (channel use for each access category).
     *
     * NDL_tmChannelUse(AC_BK), ndlType_channelUse, 1+13 bits. <br>
     * NDL_tmChannelUse(AC_BE), ndlType_channelUse, 1+13 bits. <br>
     * NDL_tmChannelUse(AC_VI), ndlType_channelUse, 1+13 bits. <br>
     * NDL_tmChannelUse(AC_VO), ndlType_channelUse, 1+13 bits.
     */

    unsigned int min_max_channel_load;
    /**< Channel load thresholds.
     *
     * NDL_minChannelLoad, ndlType_channelLoad, 1+10 bits. <br>
     * NDL_maxChannelLoad, ndlType_channelLoad, 1+10 bits.
     */

    unsigned int transmit_queue_parameters;
    /**< Transmit queue parameters (number of queues and queue status for each
     *  access category).
     *
     * NDL_numQueue, ndlType_acPrio, 1+3 bits. <br>
     * NDL_refQueueStatus(AC_BK), ndlType_queueStatus, 1+1 bit. <br>
     * NDL_refQueueStatus(AC_BE), ndlType_queueStatus, 1+1 bit. <br>
     * NDL_refQueueStatus(AC_VI), ndlType_queueStatus, 1+1 bit. <br>
     * NDL_refQueueStatus(AC_VO), ndlType_queueStatus, 1+1 bit.
     */

    unsigned int numberElements[DCC_PACKED_ARR_SIZE(WLAN_MAX_AC, SIZE_NDLTYPE_NUMBERELEMENTS)];
    /**< Transmit queue parameters (queue length for each access category).
     * NDL_refQueueLen(AC_BK), ndlType_numberElements, 1+6 bits. <br>
     * NDL_refQueueLen(AC_BE), ndlType_numberElements, 1+6 bits. <br>
     * NDL_refQueueLen(AC_VI), ndlType_numberElements, 1+6 bits. <br>
     * NDL_refQueueLen(AC_VO), ndlType_numberElements, 1+6 bits.
     */

} dcc_ndl_chan;

/** @} */ /* end_addtogroup dcc_algorithm */

 /** @addtogroup dcc_algorithm
 @{ */

 /**@name Macros to Read and Write to dcc_ndl_chan
 @{ */

#define DCC_CHAN_FREQ_GET(ptr)                  DCC_GET_BITS((ptr)->chan_info, 0, 16)
#define DCC_CHAN_FREQ_SET(ptr,val)              DCC_SET_BITS((ptr)->chan_info, 0, 16, val)
#define DCC_NDL_NUM_ACTIVE_STATE_GET(ptr)       DCC_GET_BITS((ptr)->chan_info, 16, 7)
#define DCC_NDL_NUM_ACTIVE_STATE_SET(ptr,val)   DCC_SET_BITS((ptr)->chan_info, 16, 7, val)

#define DCC_NDL_MIN_DCC_SAMPLING_GET(ptr)       DCC_GET_BITS((ptr)->ndl_min_dcc_sampling, 0, 10)
#define DCC_NDL_MIN_DCC_SAMPLING_SET(ptr,val)   DCC_SET_BITS((ptr)->ndl_min_dcc_sampling, 0, 10, val)
#define DCC_NDL_MEASURE_INTERVAL_GET(ptr)       DCC_GET_BITS((ptr)->ndl_min_dcc_sampling, 10, 16)
#define DCC_NDL_MEASURE_INTERVAL_SET(ptr,val)   DCC_SET_BITS((ptr)->ndl_min_dcc_sampling, 10, 16, val)

#define DCC_NDL_DCC_ENABLE_GET(ptr)             DCC_GET_BITS((ptr)->dcc_flags, 0, 1)
#define DCC_NDL_DCC_ENABLE_SET(ptr,val)         DCC_SET_BITS((ptr)->dcc_flags, 0, 1, val)
#define DCC_NDL_DCC_STATS_ENABLE_GET(ptr)       DCC_GET_BITS((ptr)->dcc_flags, 1, 1)
#define DCC_NDL_DCC_STATS_ENABLE_SET(ptr,val)   DCC_SET_BITS((ptr)->dcc_flags, 1, 1, val)
#define DCC_NDL_DCC_STATS_INTERVAL_GET(ptr)     DCC_GET_BITS((ptr)->dcc_flags, 2, 16)
#define DCC_NDL_DCC_STATS_INTERVAL_SET(ptr,val) DCC_SET_BITS((ptr)->dcc_flags, 2, 16, val)

#define DCC_NDL_TIME_UP_GET(ptr)                DCC_GET_BITS((ptr)->general_config, 0, 13)
#define DCC_NDL_TIME_UP_SET(ptr,val)            DCC_SET_BITS((ptr)->general_config, 0, 13, val)
#define DCC_NDL_TIME_DOWN_GET(ptr)              DCC_GET_BITS((ptr)->general_config, 13, 13)
#define DCC_NDL_TIME_DOWN_SET(ptr,val)          DCC_SET_BITS((ptr)->general_config, 13, 13, val)

#define DCC_NDL_MIN_TX_POWER_GET(ptr)       DCC_GET_BITS((ptr)->min_max_tx_power, 0, 8)
#define DCC_NDL_MIN_TX_POWER_SET(ptr,val)   DCC_SET_BITS((ptr)->min_max_tx_power, 0, 8, val)
#define DCC_NDL_MAX_TX_POWER_GET(ptr)       DCC_GET_BITS((ptr)->min_max_tx_power, 8, 8)
#define DCC_NDL_MAX_TX_POWER_SET(ptr,val)   DCC_SET_BITS((ptr)->min_max_tx_power, 8, 8, val)

#define DCC_NDL_DEF_TX_POWER_GET(ptr,acprio)        dcc_packed_arr_get_bits((ptr)->def_tx_power_ac, acprio, SIZE_NDLTYPE_TXPOWER)
#define DCC_NDL_DEF_TX_POWER_SET(ptr,acprio,val)    dcc_packed_arr_set_bits((ptr)->def_tx_power_ac, acprio, SIZE_NDLTYPE_TXPOWER, val)

#define DCC_NDL_MAX_PACKET_DURATION_GET(ptr,acprio)     dcc_packed_arr_get_bits((ptr)->max_packet_duration_ac, acprio, SIZE_NDLTYPE_PACKETDURATION)
#define DCC_NDL_MAX_PACKET_DURATION_SET(ptr,acprio,val) dcc_packed_arr_set_bits((ptr)->max_packet_duration_ac, acprio, SIZE_NDLTYPE_PACKETDURATION, val)
#define DCC_NDL_MIN_PACKET_INTERVAL_GET(ptr)            DCC_GET_BITS((ptr)->min_max_packet_interval, 0, 11)
#define DCC_NDL_MIN_PACKET_INTERVAL_SET(ptr,val)        DCC_SET_BITS((ptr)->min_max_packet_interval, 0, 11, val)
#define DCC_NDL_MAX_PACKET_INTERVAL_GET(ptr)            DCC_GET_BITS((ptr)->min_max_packet_interval, 11, 11)
#define DCC_NDL_MAX_PACKET_INTERVAL_SET(ptr,val)        DCC_SET_BITS((ptr)->min_max_packet_interval, 11, 11, val)
#define DCC_NDL_DEF_PACKET_INTERVAL_GET(ptr,acprio)     dcc_packed_arr_get_bits((ptr)->def_packet_interval_ac, acprio, SIZE_NDLTYPE_PACKETINTERVAL)
#define DCC_NDL_DEF_PACKET_INTERVAL_SET(ptr,acprio,val) dcc_packed_arr_set_bits((ptr)->def_packet_interval_ac, acprio, SIZE_NDLTYPE_PACKETINTERVAL, val)

#define DCC_NDL_MIN_DATARATE_GET(ptr)               DCC_GET_BITS((ptr)->min_max_datarate, 0, 4)
#define DCC_NDL_MIN_DATARATE_SET(ptr,val)           DCC_SET_BITS((ptr)->min_max_datarate, 0, 4, val)
#define DCC_NDL_MAX_DATARATE_GET(ptr)               DCC_GET_BITS((ptr)->min_max_datarate, 4, 4)
#define DCC_NDL_MAX_DATARATE_SET(ptr,val)           DCC_SET_BITS((ptr)->min_max_datarate, 4, 4, val)
#define DCC_NDL_DEF_DATARATE_GET(ptr,acprio)        dcc_packed_arr_get_bits((ptr)->def_datarate_ac, acprio, SIZE_NDLTYPE_DATARATE)
#define DCC_NDL_DEF_DATARATE_SET(ptr,acprio,val)    dcc_packed_arr_set_bits((ptr)->def_datarate_ac, acprio, SIZE_NDLTYPE_DATARATE, val)

#define DCC_NDL_MIN_CARRIER_SENSE_GET(ptr)      DCC_GET_BITS((ptr)->min_max_def_carrier_sense, 0, 8)
#define DCC_NDL_MIN_CARRIER_SENSE_SET(ptr,val)  DCC_SET_BITS((ptr)->min_max_def_carrier_sense, 0, 8, val)
#define DCC_NDL_MAX_CARRIER_SENSE_GET(ptr)      DCC_GET_BITS((ptr)->min_max_def_carrier_sense, 8, 8)
#define DCC_NDL_MAX_CARRIER_SENSE_SET(ptr,val)  DCC_SET_BITS((ptr)->min_max_def_carrier_sense, 8, 8, val)
#define DCC_NDL_DEF_CARRIER_SENSE_GET(ptr)      DCC_GET_BITS((ptr)->min_max_def_carrier_sense, 16, 8)
#define DCC_NDL_DEF_CARRIER_SENSE_SET(ptr,val)  DCC_SET_BITS((ptr)->min_max_def_carrier_sense, 16, 8, val)

#define DCC_NDL_DEF_DCC_SENSITIVITY_GET(ptr)        DCC_GET_BITS((ptr)->receive_model_parameter, 0, 8)
#define DCC_NDL_DEF_DCC_SENSITIVITY_SET(ptr,val)    DCC_SET_BITS((ptr)->receive_model_parameter, 0, 8, val)
#define DCC_NDL_MAX_CS_RANGE_GET(ptr)               DCC_GET_BITS((ptr)->receive_model_parameter, 8, 13)
#define DCC_NDL_MAX_CS_RANGE_SET(ptr,val)           DCC_SET_BITS((ptr)->receive_model_parameter, 8, 13, val)
#define DCC_NDL_REF_PATH_LOSS_GET(ptr)              DCC_GET_BITS((ptr)->receive_model_parameter, 21, 6)
#define DCC_NDL_REF_PATH_LOSS_SET(ptr,val)          DCC_SET_BITS((ptr)->receive_model_parameter, 21, 6, val)

#define DCC_NDL_MIN_SNR_GET(ptr)                    DCC_GET_BITS((ptr)->receive_model_parameter_2, 0, 8)
#define DCC_NDL_MIN_SNR_SET(ptr,val)                DCC_SET_BITS((ptr)->receive_model_parameter_2, 0, 8, val)

#define DCC_NDL_SNR_BACKOFF_GET(ptr,mcs)        dcc_packed_arr_get_bits((ptr)->snr_backoff_mcs, mcs, SIZE_NDLTYPE_SNR)
#define DCC_NDL_SNR_BACKOFF_SET(ptr,mcs,val)    dcc_packed_arr_set_bits((ptr)->snr_backoff_mcs, mcs, SIZE_NDLTYPE_SNR, val)

#define DCC_NDL_TM_PACKET_ARRIVAL_RATE_GET(ptr,acprio)      dcc_packed_arr_get_bits((ptr)->tm_packet_arrival_rate_ac, acprio, SIZE_NDLTYPE_ARRIVALRATE)
#define DCC_NDL_TM_PACKET_ARRIVAL_RATE_SET(ptr,acprio,val)  dcc_packed_arr_set_bits((ptr)->tm_packet_arrival_rate_ac, acprio, SIZE_NDLTYPE_ARRIVALRATE, val)
#define DCC_NDL_TM_PACKET_AVG_DURATION_GET(ptr,acprio)      dcc_packed_arr_get_bits((ptr)->tm_packet_avg_duration_ac, acprio, SIZE_NDLTYPE_PACKETDURATION)
#define DCC_NDL_TM_PACKET_AVG_DURATION_SET(ptr,acprio,val)  dcc_packed_arr_set_bits((ptr)->tm_packet_avg_duration_ac, acprio, SIZE_NDLTYPE_PACKETDURATION, val)
#define DCC_NDL_TM_SIGNAL_AVG_POWER_GET(ptr,acprio)         dcc_packed_arr_get_bits((ptr)->tm_signal_avg_power_ac, acprio, SIZE_NDLTYPE_TXPOWER)
#define DCC_NDL_TM_SIGNAL_AVG_POWER_SET(ptr,acprio,val)     dcc_packed_arr_set_bits((ptr)->tm_signal_avg_power_ac, acprio, SIZE_NDLTYPE_TXPOWER, val)
#define DCC_NDL_TM_MAX_CHANNEL_USE_GET(ptr)                 DCC_GET_BITS((ptr)->tm_max_channel_use, 0, 14)
#define DCC_NDL_TM_MAX_CHANNEL_USE_SET(ptr,val)             DCC_SET_BITS((ptr)->tm_max_channel_use, 0, 14, val)
#define DCC_NDL_TM_CHANNEL_USE_GET(ptr,acprio)              dcc_packed_arr_get_bits((ptr)->tm_channel_use_ac, acprio, SIZE_NDLTYPE_CHANNELUSE)
#define DCC_NDL_TM_CHANNEL_USE_SET(ptr,acprio,val)          dcc_packed_arr_set_bits((ptr)->tm_channel_use_ac, acprio, SIZE_NDLTYPE_CHANNELUSE, val)

#define DCC_NDL_MIN_CHANNEL_LOAD_GET(ptr)       DCC_GET_BITS((ptr)->min_max_channel_load, 0, 11)
#define DCC_NDL_MIN_CHANNEL_LOAD_SET(ptr,val)   DCC_SET_BITS((ptr)->min_max_channel_load, 0, 11, val)
#define DCC_NDL_MAX_CHANNEL_LOAD_GET(ptr)       DCC_GET_BITS((ptr)->min_max_channel_load, 11, 11)
#define DCC_NDL_MAX_CHANNEL_LOAD_SET(ptr,val)   DCC_SET_BITS((ptr)->min_max_channel_load, 11, 11, val)

#define DCC_NDL_NUM_QUEUE_GET(ptr)                      DCC_GET_BITS((ptr)->transmit_queue_parameters, 0, 4)
#define DCC_NDL_NUM_QUEUE_SET(ptr,val)                  DCC_SET_BITS((ptr)->transmit_queue_parameters, 0, 4, val)
#define DCC_NDL_REF_QUEUE_STATUS_GET(ptr,acprio)        DCC_GET_BITS((ptr)->transmit_queue_parameters, (4 + (acprio * 2)), 2)
#define DCC_NDL_REF_QUEUE_STATUS_SET(ptr,acprio,val)    DCC_SET_BITS((ptr)->transmit_queue_parameters, (4 + (acprio * 2)), 2, val)
#define DCC_NDL_REF_QUEUE_LEN_GET(ptr,acprio)           dcc_packed_arr_get_bits((ptr)->numberElements, acprio, SIZE_NDLTYPE_NUMBERELEMENTS)
#define DCC_NDL_REF_QUEUE_LEN_SET(ptr,acprio,val)       dcc_packed_arr_set_bits((ptr)->numberElements, acprio, SIZE_NDLTYPE_NUMBERELEMENTS, val)

 /** @} */ /* end_namegroup */

 /** @} */ /* end_addtogroup dcc_algorithm */

 /** @addtogroup dcc_algorithm
 @{ */

/** Data structure for requesting the DCC channel stats. */
typedef struct {
    unsigned long tlv_header;
    /**< Reserved. This must be 0. */

    unsigned long chan_freq;
    /**< The channel frequency (in MHz) for which this applies. */

    unsigned long dcc_stats_bitmap;
    /**< The DCC stats being requested. */
} dcc_channel_stats_request;

/** @} */ /* end_addtogroup dcc_algorithm */

 /** @addtogroup dcc_algorithm
 @{ */

#define DCC_STRING(x)   #x

#ifdef DCC_ENABLE_DEBUG_PRINT
#define DCC_DEBUG_PRINT(x,...)   printf(x,__VA_ARGS__)
#else
#define DCC_DEBUG_PRINT(x,...)
#endif

#define DCC_PRINT(x,...)   printf(x,__VA_ARGS__)

#define DCC_CFG_FILE       "./dcc.dat"

#define DCCTLV_SET_HDR(tlv_buf, tag, len) (((unsigned long *)(tlv_buf))[0]) = ((tag << 16) | (len & 0x0000FFFF))

/** @} */ /* end_addtogroup dcc_algorithm */

 /** @addtogroup dcc_algorithm
 @{ */

/**
 * Reads the DCC configuration from the the dcc.dat configuration file.
 *
 * @param[out] num_channels Number of channels in dcc.dat.
 * @param[out] chan Array of structures describing the parameters for each
 *                  channel. This array has length num_channels. The caller
 *                  must not free this array.
 * @param[out] num_active_states Total number of active states for all
 *                  channels.
 * @param[out] state_cfg Array of active states. This array has length
 *                  num_active_states. The caller must not free this array.
 *
 * @return
 * None.
 */
void dcc_get_config(unsigned char *num_channels, dcc_ndl_chan **chan,
                    unsigned char *num_active_states, dcc_ndl_active_state_config **state_cfg);

/**
 * Prints the DCC stats that were returned by the host driver for the
 * QCA_NL80211_VENDOR_SUBCMD_DCC_GET_STATS command.
 *
 * @param[in] num_channels Size of the stats array.
 * @param[in] stats Array containing the stats returned from the
 *                      QCA_NL80211_VENDOR_SUBCMD_DCC_GET_STATS command
 *
 * @return
 * None.
 */
void dcc_print_stats(unsigned char num_channels, dcc_ndl_stats_per_channel *stats);

/** @} */ /* end_addtogroup_dcc_algorithm */

#endif /* _DCC_UTIL_H_ */
