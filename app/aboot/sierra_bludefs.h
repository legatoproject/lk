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

#include <sys/types.h>
#include "sierra_cweudefs.h"

/* Constants and enumerated types */

/* Types of images that can be programmed */
typedef enum {
  FLASH_PROG_NO_IMG = 0,
  FLASH_PROG_QCSBLHD_CONFIGDAT_IMG,
  FLASH_PROG_QCSBL_IMG,
  FLASH_PROG_OEMSBL_IMG,
  FLASH_PROG_AMSS_IMG,
  FLASH_PROG_APPS_BOOT_IMG,
  FLASH_PROG_APPS_IMG,
  FLASH_PROG_FOTAUI_IMG,
  FLASH_PROG_MODEM_CEFS_IMG,
  FLASH_PROG_APPS_CEFS_IMG,
  FLASH_PROG_WM_IMG,
  FLASH_PROG_DSP1_IMG,
  FLASH_PROG_DSP2_IMG,
  FLASH_PROG_CUSTOM_IMG,
  FLASH_PROG_RAW_IMG,
  FLASH_PROG_FACTORY_IMG,
  FLASH_PROG_DBL_IMG,
  FLASH_PROG_FSBL_IMG,
  FLASH_PROG_OSBL_IMG,
  FLASH_PROG_ROFS1_IMG,
  FLASH_PROG_ROFS2_IMG,
  FLASH_PROG_ROFS3_IMG,
  FLASH_PROG_OSBL_UPDATE_IMG,
  FLASH_PROG_AMSS_UPDATE_IMG,
  FLASH_PROG_DSP_UPDATE_IMG,
  FLASH_PROG_ADSP_IMG,
  FLASH_PROG_SINGLE_IMG,
  FLASH_PROG_SBL1_IMG,
  FLASH_PROG_SBL2_IMG,
  FLASH_PROG_RPM_IMG,
  FLASH_PROG_DSP3_IMG,
  FLASH_PROG_FOTA_IMG,
  FLASH_PROG_YAFFS_IMG,
  FLASH_PROG_FILE_IMG,
  FLASH_PROG_USDATA_IMG,
  FLASH_PROG_USAPP_IMG,
  FLASH_PROG_UNKNOWN_IMG
  } flash_prog_img_type_t;

#define BL_SBL_PARTI_NAME "sbl"
#define BL_MIBIB_PARTI_NAME "mibib"
#define BL_ABOOT_PARTI_NAME "aboot"
#define BL_LINUX_BOOT_PARTI_NAME "boot"
#define BL_LINUX_UDATA_PARTI_NAME "userdata"
#define BL_LINUX_UAPP_PARTI_NAME "userapp"
#define BL_LINUX_SYSTEM_PARTI_NAME "system"
#define BL_TZ_PARTI_NAME "tz"
#define BL_MODEM_PARTI_NAME "modem"
#define BL_RPM_PARTI_NAME "rpm"
#define BL_BACKUP_PARTI_NAME "backup"

#define BL_PRODUCT_ID                  0x39583238       /* "9X28" */

/* SWI LK will store Boot.cwe in 0x88000000 */
/* fastboot of LK will use "SCRATCH_REGION2:0x88000000" as download region, 
  for feature to update boot_parti_update.cwe in SBL, we use this address to store image,
  then SBL will update module with update boot_parti_update.cwe */
#define BL_BOOT_IMG_STORED_BY_LK         0x88000000


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

/************
 *
 * Name:     blif_type
 *
 * Purpose:  Enumerated list of interface types that this boot loader will look for
 *           serial i/o on. These are used to identify the active interface type
 *           for serial traffic.
 *
 * Notes:
 *
 ************/
enum blif_type
{
  BLIF_UNKNOWN,        /* Initial value of interface after startup      */
  BLIF_USB             /* Active interface is USB                       */
};

/************
 *
 * Name:      blCtrlBlk
 *
 * Purpose:   This is the main control block for the BL package. It defines all
 *            the information required by the BL package.
 *
 * Notes:
 *
 ************/
struct blCtrlBlk
{
  enum blif_type bliftype;      /* Identifies the active interface in use, UART or USB */
  uint16 blchcksum;             /* Accumulator for computed checksum during download process */
  uint32 blcrc32;               /* Running crc value */
  uint8 *blcbufp;               /* Pointer to next location in memory for writing the download image */
  uint32 blbytesleft;           /* Number of bytes remaining to be downloaded */
  boolean blramimage;              /* Flag indicating whether the downloaded image is RAM or FLASH based */
  uint8 blLaunchCode;           /* Optional host-originated launch code. Passed to application on startup */
  uint32 blunknowns;            /* Statistic to count unknown packets received */
  uint32 blmodemsync;           /* Statistic to count data link Sync packets */
  struct cwe_header_s blhd;     /* Structure for storing the application header (CWE header) */
  boolean blallowusbd;             /* TRUE when USBD image download is allowed */
  boolean blcominited;             /* Flag indicating whether the communication interfaces have been initialized */
  enum cwe_image_type_e imagetype; /* Type of image read from top-level CWE header */
  uint8 dload_reason;              /* reason for going to bootloader */
};

extern bool to_update_mibib;

extern int sierra_smem_boothold_mode_set();
extern bool sierra_is_fastboot_disabled(void);
extern bool sierra_if_enter_fastboot(void);
extern unsigned int sierra_smem_err_count_get(void);
extern void sierra_smem_err_count_set(unsigned int err_cnt);
extern void sierra_smem_reset_type_set(unsigned int reset_type);

enum blresultcode  blProcessFastbootImage(unsigned char *bufp, unsigned int image_size);
void sierra_check_mibib_state_clear(void);

#endif /* bludefs_h */
