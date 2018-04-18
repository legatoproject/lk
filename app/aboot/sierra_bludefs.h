/************
 *
 * Filename:  sierra_bludefs.h
 *
 * Purpose:   external definitions for BL package
 *
 * NOTES:
 *
 * Copyright: (C) 2015 Sierra Wireless, Inc.
 *            All rights reserved
 *
 ************/

#ifndef bludefs_h
#define bludefs_h

extern int sierra_smem_boothold_mode_set();
extern bool sierra_is_fastboot_disabled(void);
extern bool sierra_is_bootquiet_disabled(void);

/* check for dual system on WP with IMA support in aboot.c */
extern bool is_dual_system_supported(void);

/* stubs for dual system build support on WP with IMA support in aboot.c */
int reboot_swap;
struct ds_flag_s {
  int bad_image;
};

extern bool sierra_ds_smem_write_bad_image_and_swap(int stub);
extern uint8_t sierra_ds_smem_get_ssid_linux_index();
extern bool sierra_ds_get_full_data(int stub);
/* end stubs */

#define BL_MODEM2_PARTI_NAME "modem2"

/************
 *
 * Name:     blresultcode - list of BL error/result codes
 *
 * Purpose:  List of BL result codes
 *
 * Members:  see below
 *
 * Notes:    error codes below 0x10 uses same define as QCT
 *           These values cannot be changed as host uses the same define
 *
 ************/
enum blresultcode
{
  /* QCT DONE RESP error codes */
  BLRESULT_OK                       = 0x00,
  BLRESULT_AUTHENTICATION_ERROR     = 0x01,
  BLRESULT_FLASH_WRITE_ERROR        = 0x02,
  BLRESULT_QCT_MAX = BLRESULT_FLASH_WRITE_ERROR,

  /* Sierra specific error codes, must be sequencial to match bl_result_code_str */
  BLRESULT_SIERRA_START             = 0x80,
  BLRESULT_IMAGE_TYPE_INVALID       = BLRESULT_SIERRA_START,
  BLRESULT_PRODUCT_TYPE_INVALID     = 0x81,
  BLRESULT_IMGSIZE_MISMATCH_ERROR   = 0x82,
  BLRESULT_IMGSIZE_OUT_OF_RANGE     = 0x83,
  BLRESULT_APPL_NOT_COMPATIBLE      = 0x84,
  BLRESULT_BOOT_NOT_COMPATIBLE      = 0x85,
  BLRESULT_PKG_NOT_COMPATIBLE       = 0x86,
  BLRESULT_SIGNATURE_INVALID        = 0x87,
  BLRESULT_FLASH_READ_ERROR         = 0x88,
  BLRESULT_CRC32_CHECK_ERROR        = 0x89,
  BLRESULT_CRC16_CHECK_ERROR        = 0x8A,
  BLRESULT_CWE_HEADER_ERROR         = 0x8B,
  BLRESULT_DECOMPRESSION_ERROR      = 0x8C,
  BLRESULT_MEMORY_MAP_ERROR         = 0x8D,
  BLRESULT_DECRYPTION_ERROR         = 0x8E,
  BLRESULT_UNSPECIFIED              = 0x8F,
  BLRESULT_IMAGE_SLOT_ERROR         = 0x90,
  BLRESULT_SECBOOT_IMAGE_NOT_SIGNED           = 0x91,
  BLRESULT_SECBOOT_CERT_CHAIN_VERIFY_FAIL     = 0x92,
  BLRESULT_SECBOOT_CODE_SIG_VERIFY_FAIL       = 0x93,
  BLRESULT_SECBOOT_OTHER_ERROR                = 0x94,
  BLRESULT_SIERRA_MAX = BLRESULT_SECBOOT_OTHER_ERROR,
};

#endif /* bludefs_h */

