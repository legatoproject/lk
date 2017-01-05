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
/* BACKUP partition is divided into 3 logcial partitions below.
 * |    DEDB(6.5M)    |    SEDB(3M)    |    LOG(4M)    |
 */
#define LOGICAL_PARTITION_DEDB_SIZE    6815744   /* 0x680000 = 6.5M */
#define LOGICAL_PARTITION_SEDB_SIZE    3145728   /* 0x300000 = 3M */
#define LOGICAL_PARTITION_LOG_SIZE     4194304   /* 0x400000 = 4M */

/* ENUM for logical partition types in physical BACKUP partition */
typedef enum
{
  LOGICAL_PARTITION_NONE,
  LOGICAL_PARTITION_DEDB,
  LOGICAL_PARTITION_SEDB,
  LOGICAL_PARTITION_LOG,
  LOGICAL_PARTITION_INVALID,
} backup_logical_partition_type;

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
#define BL_ABOOT2_PARTI_NAME "aboot2"
#define BL_LINUX_BOOT_PARTI_NAME "boot"
#define BL_LINUX_BOOT2_PARTI_NAME "boot2"
#define BL_LINUX_UDATA_PARTI_NAME "lefwkro"
#define BL_LINUX_UDATA2_PARTI_NAME "lefwkro2"
#define BL_LINUX_UAPP_PARTI_NAME "userapp"
#define BL_LINUX_SYSTEM_PARTI_NAME "system"
#define BL_LINUX_SYSTEM2_PARTI_NAME "system2"
#define BL_TZ_PARTI_NAME "tz"
#define BL_MODEM_PARTI_NAME "modem"
#define BL_MODEM2_PARTI_NAME "modem2"
#define BL_RPM_PARTI_NAME "rpm"
#define BL_BACKUP_PARTI_NAME "backup"
#define BL_CUSTOMER0_PARTI_NAME "customer0"
#define BL_CUSTOMER1_PARTI_NAME "customer1"
#define BL_CUSTOMER2_PARTI_NAME "customer2"

#define BL_PRODUCT_ID                  0x39583238       /* "9X28" */
#define BL_HW_COMPAT_MASK   0x000000FFU
#define BL_FW_COMPAT_MASK   0x0000FF00U
/* Compatibility mask for the application */
#define BL_APP_COMPAT_MASK  (BL_HW_COMPAT_MASK | BL_FW_COMPAT_MASK)
/* Compatibility mask for the bootloader */
#define BL_BOOT_COMPAT_MASK (BL_HW_COMPAT_MASK)

#define BL_FW_COMPAT_BYTE_SHIFT     8


#define BL_FW_COMPAT_BYTE 0x00
#define BL_HW_COMPAT_BYTE 0x00

/* Compatibility Words */
#define BL_APP_COMPAT_WORD  (BL_HW_COMPAT_BYTE | \
                            (BL_FW_COMPAT_BYTE << BL_FW_COMPAT_BYTE_SHIFT))

#define BL_BOOT_COMPAT_WORD (BL_HW_COMPAT_BYTE)


/* SWI LK will store Boot.cwe in 0x88000000 */
/* fastboot of LK will use "SCRATCH_REGION2:0x88000000" as download region, 
  for feature to update boot_parti_update.cwe in SBL, we use this address to store image,
  then SBL will update module with update boot_parti_update.cwe */
#define BL_BOOT_IMG_STORED_BY_LK         0x88000000

#define BLRXBUFSZ         2000  /* maximum allowed by data link protocol */
#define BLTXBUFSZ         2000  /* maximum allowed by data link protocol; must
                                 * match RX buffer for loopback to work properly
                                 */

/* protocol header sizes */
#define BLHEADERSZ        4     /* header is 4 bytes long (length x 2, cmd ID & code) */


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
 * Name:     bl_dld_seq_e
 *
 * Purpose:  Bootloader download sequence enum
 *
 * Members:  See below
 *
 * Notes:    Update bl_dld_seq_str when this is changed 
 *
 ************/
enum bl_dld_seq_e
{
  BL_DLD,               /* Download to RAM */
  BL_DLD_FLASH,         /* Flash write to NAND */
  BL_DLD_VERIFY,        /* Verification after download to RAM */
  BL_DLD_PREDLD_VERIFY, /* Verification before download to RAM */
};

/************
 *
 * Name:     bluistateE
 *
 * Purpose:  List of UI states
 *
 * Members:  see below
 *
 * Notes:    None
 *
 ************/
enum bluistateE
{
  BLUISTATE_IDLE,        /* Idle */
  BLUISTATE_DOWNLOADING, /* Downloading */
  BLUISTATE_UPDATING,    /* Updating */
  BLUISTATE_ERROR,       /* Error */
};


/************
 *
 * Name:     bl_update_system_e
 *
 * Purpose:  Update system enum
 *
 * Members:  See below
 *
 * Notes:  None 
 *
 ************/
enum bl_update_system_e
{
  BL_UPDATE_NONE,         /* Nothing */
  BL_UPDATE_SYSTEM1,      /* Only update system1 */
  BL_UPDATE_SYSTEM2,      /* Only update system2 */
  BL_UPDATE_DUAL_SYSTEM,  /* Update both systems */
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
  uint8 blcrxbuf[BLRXBUFSZ + BLHEADERSZ]; /* Buffer for storing newly received packets from the host */
  uint8 bltxbuf[BLTXBUFSZ];     /* Storage for responses to be transmitted to the host during download */
  boolean blcominited;             /* Flag indicating whether the communication interfaces have been initialized */
  enum cwe_image_type_e imagetype; /* Type of image read from top-level CWE header */
  uint8 dload_reason;              /* reason for going to bootloader */
};

extern bool to_update_mibib;
extern enum bl_update_system_e update_which_system;
extern uint8 *second_ubi_images;

extern unsigned char *sierra_smem_base_addr_get(void);
extern int sierra_smem_boothold_mode_set();
extern bool sierra_is_fastboot_disabled(void);
extern bool sierra_if_enter_fastboot(void);
extern unsigned int sierra_smem_err_count_get(void);
extern void sierra_smem_err_count_set(unsigned int err_cnt);
extern void sierra_smem_reset_type_set(unsigned int reset_type);
extern boolean swipart_get_logical_partition_from_backup(
  uint32 block_size,
  backup_logical_partition_type logical_partition,
  uint32 *start_block,
  uint32 *end_block);
extern bool is_dual_system_supported(void);
extern bool sierra_is_bootquiet_disabled(void);
enum blresultcode blprocessdldcontinue(uint8 *payloadp, uint32 tlen, uint32 *bytesleftp);
enum blresultcode blprocessdldend(void);
enum blresultcode blprocessdldstart(uint8 *cwehdrp, uint32 tlen);

uint8 *blgetrxbuf(void);
void bluisetstate(enum bluistateE state);
void blReset(void);
enum blresultcode  blProcessFastbootImage(unsigned char *bufp, unsigned int image_size);
void sierra_check_mibib_state_clear(void);
enum blresultcode blredundancy_sbl_program(
  uint8 * bufp,
  unsigned int write_size);

#endif /* bludefs_h */
