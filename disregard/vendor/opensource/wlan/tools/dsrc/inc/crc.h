/*
 * Copyright (c) 1991-2016, The Linux Foundation. All rights reserved.
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

#ifndef __CRC_H__
#define __CRC_H__
/** @file crc.h
*/

/** @addtogroup crc_services
@{ */

/**
* When crc_16_l_calc() is applied to the
* unchanged entire buffer, it returns CRC_16_L_OK.
*/
#define CRC_16_L_OK             0x0F47

/** Size of crc_16 in octets. */
#define CRC_16_SIZE             2

/** @} */ /* end_addtogroup crc_services */

#ifdef __cplusplus
extern "C" {
#endif

/*===========================================================================

                      FUNCTION DECLARATIONS

===========================================================================*/

/** @addtogroup crc_services
@{ */

/**

Calculates an LSB-first 16-bit CRC over a specified number
of data bits. This function can be used to produce a CRC or to check a CRC.

@param[in] buf_ptr Pointer to bytes containing the data to CRC. The bitstream
                  starts in the LS bit of the first byte.
@param[in] len Number of data bits over which to calculate the CRC.

@return
  Returns an unsigned short holding 16 bits, which are the contents of the CRC
  register as calculated over the specified data bits. If this
  function is being used to check a CRC, the return value will be
  equal to CRC_16_L_OK (defined in crc.h) if the CRC checks correctly.
*/
extern unsigned short crc_16_l_calc (unsigned char *buf_ptr, unsigned short len);

/** @} */ /* end_addtogroup crc_services */

#ifdef __cplusplus
}
#endif

#endif /* __CRC_H__ */
