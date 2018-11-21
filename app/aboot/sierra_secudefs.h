/************
 *
 * Filename:  sierra_secudefs.h
 *
 * Purpose:   external definitions for secboot package
 *
 * NOTES:
 *
 * Copyright: (C) 2017 Sierra Wireless, Inc.
 *            All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name of The Linux Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 ************/
#ifndef SIERRA_SECUDEFS_H
#define SIERRA_SECUDEFS_H

extern uint8_t *sierra_sec_oem_cert_hash_get(void);
extern boolean sierra_sec_oem_cert_verify(uint8_t *certp, uint8_t *extra_certp);
extern boolean sierra_sec_cert_page_read(
  struct ptentry *ptn,
  unsigned int offset,
  uint8_t *imagep,
  unsigned int page_size);

/*qfuse definition used by LK and kernel, see qfprom_hwioreg_v1.h*/
#define HWIO_QFPROM_CORR_OEM_SEC_BOOT_ROW0_LSB_ADDR       0x000A41d0
#define HWIO_SECURE_BOOTn_AUTH_EN_BMSK                    0x20
#define HWIO_QFPROM_RAW_SERIAL_NUM_ADDR                   0x000A4128
#define HWIO_JTAG_ID_ADDR                                 0x000A607c

#define HWIO_QFPROM_CORR_PK_HASH_ROWn_LSB_ADDR(n)         ( 0x000A41e0 + 0x8 * (n))
#define HWIO_QFPROM_CORR_PK_HASH_ROWn_MSB_ADDR(n)         ( 0x000A41e4 + 0x8 * (n))
#define OEM_PK_HASH_ROW_MAX                               5
#define HWIO_QFPROM_CORR_PK_HASH_BYTES_MAX                8 * OEM_PK_HASH_ROW_MAX
#define SHA256_HASH_LEN 32

#define HWIO_QFPROM_RAW_CUST_HASH_ROWn_LSB_ADDR(n)       (0x000A03c8 + (n * 8))
#define HWIO_QFPROM_RAW_CUST_HASH_ROWn_MSB_ADDR(n)       (0x000A03cc + (n * 8))

#define HWIO_QFPROM_CORR_CUST_SEC_BOOT_ROW_LSB_ADDR       0x000A43B8

#define HWIO_SECURE_BOOT_HYBRID_AUTH_EN_BMSK              0x1
#define HWIO_SECURE_BOOT_HYBRID_AUTH_EN_SHFT              0x0

#define HWIO_SECURE_BOOT_IMA_FLG_BMSK                     0x40
#define HWIO_SECURE_BOOT_IMA_FLG_SHFT                     0x6


#define HWIO_SECURE_BOOT_HYBRID_AUTH_LEVEL_BMSK           0xE
#define HWIO_SECURE_BOOT_HYBRID_AUTH_LEVEL_SHFT           0x1

#define SECBOOT_HYBRID_KERNEL_AUTH_LEVEL                  0x2


#define SECBOOT_SWI_APPS_SW_TYPE  14  /* should match with secboot_sw_type */

#define SHA1_SIZE      16
#define SHA256_SIZE    32

/* Image type definition. Should match with the definition
   in boot_images/core/boot/secboot3/src/mibib.h */
typedef enum
{
  NONE_IMG = 0,
  OEM_SBL_IMG,
  AMSS_IMG,
  QCSBL_IMG,
  HASH_IMG,
  APPSBL_IMG,
  APPS_IMG,
  HOSTDL_IMG,
  DSP1_IMG,
  FSBL_IMG,
  DBL_IMG,
  OSBL_IMG,
  DSP2_IMG,
  EHOSTDL_IMG,
  NANDPRG_IMG,
  NORPRG_IMG,
  RAMFS1_IMG,
  RAMFS2_IMG,
  ADSP_Q5_IMG,
  APPS_KERNEL_IMG,
  BACKUP_RAMFS_IMG,
  SBL1_IMG,
  SBL2_IMG,
  RPM_IMG,
  SBL3_IMG,
  TZ_IMG,
  SSD_KEYS_IMG,
  GEN_IMG,
  DSP3_IMG,
  /* add above */
  MAX_IMG = 0x7FFFFFFF
}image_type;

/* Below definitions should match the one in boot_images/core/boot/secboot3/src/miheader.h */
typedef struct
{
  image_type image_id;
  uint32 header_vsn_num;
  uint32 image_src;
  uint8* image_dest_ptr;
  uint32 image_size;
  uint32 code_size;
  uint8* signature_ptr;
  uint32 signature_size;
  uint8* cert_chain_ptr;
  uint32 cert_chain_size;
} mi_boot_image_header_type;

/* Below definitions should match with the one in boot_images/core/api/securemsm/secboot/secboot.h*/
typedef struct secboot_image_info_type
{
  const uint8* header_ptr_1;
  uint32       header_len_1;
  const uint8* code_ptr_1;
  uint32       code_len_1;
  const uint8* x509_chain_ptr;
  uint32       x509_chain_len;
  const uint8* signature_ptr;
  uint32       signature_len;
  uint32       sw_type;
  uint32       sw_version;
} secboot_image_info_type;

typedef struct secboot_code_hash_info_type
{
  uint32   code_address;
  uint32   code_length;
  uint32   image_hash_length;
  uint8    image_hash[SHA256_SIZE];
}secboot_image_hash_info_type;

typedef struct secboot_verified_info_type
{
  uint32                       version_id;
  uint64                       sw_id;
  uint64                       msm_hw_id;
  uint32                       enable_debug;
  secboot_image_hash_info_type image_hash_info;
  uint32                       enable_crash_dump;
} secboot_verified_info_type;

/************
*
* Name:     image_authenticate
*
* Purpose:  verify certchain and auth image signature.
*
* Parms:    secboot_info_ptr[in]     --- input image info to authenticate
*
*           verified_info_ptr[out]   --- Data returned from a successful authentication
*
* Return:   TRUE on success.
*           FALSE on failure.
*
* Abort:    none
*
* Notes:    The source code of this API define in libsecboot.a
*
************/
extern boolean image_authenticate(secboot_image_info_type* secboot_info_ptr, secboot_verified_info_type* verified_info_ptr);

/************
 *
 * Name:     boot_swi_lk_verify_kernel
 *
 * Purpose:  verify image hash and authenticate signature if secure boot enabled.
 *
 * Parms:    ptn  --- struct ptentry for kernel iamge
 *
 *           image_addr  --- Kernel image start address in RAM.
 *
 *           imagesize  ---- Kernel image size
 *
 * Return:   TRUE if auth succeed.
 *           FALSE if auth failed.
 *
 * Abort:    none
 *
 * Notes:    For secure boot disabled device, just check image hash(if ENABLE_HASH_CHECK defined);
 *           For seucre boot enabled device, authenticate signature and check image hash.
 *
 ************/
extern boolean swi_lk_verify_kernel(unsigned char *image_addr,unsigned imagesize);

/************
 *
 * Name:     swi_lk_load_and_verify_kernel
 *
 * Purpose:  verify image hash and authenticate signature if secure boot enabled.
 *
 * Parms:    ptn  --- struct ptentry for read kernel iamge from NAND flash
 *
 *           image_addr  --- Kernel image start address in RAM.
 *
 *           imagesize  ---- Andriod image size, which don't include "mbn header","image hash",...
 *
 * Return:   TRUE if load and verify succeed.
 *           FALSE if load and verify failed.
 *
 * Abort:    none
 *
 * Notes:    SWI appended "mbn header" and "kernel hash" to kernel image for data integrity check;
 *           If kernel image is signed, "signature" and "certificate chain" also been appended to
 *           part of the image. Load all these data to RAM and then verify it.
 *
 ************/
extern boolean swi_lk_load_and_verify_kernel(struct ptentry *ptn,unsigned char *image_addr,unsigned imagesize);

/************
 *
 * Name:     sierra_lk_enable_kernel_verify
 *
 * Purpose:  check whether need to verify image
 *
 * Parms:    NONE
 *
 * Return:   TRUE  - need to verify image
 *           FALSE - otherwise.
 *
 * Abort:    None
 *
 * Notes:    verify image include check image hash and
 *           authenticate image signature if secure boot enabled.
 *
 ************/
extern boolean sierra_lk_enable_kernel_verify(void);
#endif

