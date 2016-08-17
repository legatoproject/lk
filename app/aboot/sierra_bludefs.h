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

/* Image type definition */
/************************************************************/
/*  Image Type Enum definition is moved from miheader.h     */
/************************************************************/

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

 /******************************************************/
 /* Always add enums at the end of the list. there are */
 /*  hard dependencies on this enum in apps builds     */
 /*  which DONOT SHARE this definition file            */
 /******************************************************/

  /* add above */
  MAX_IMG = 0x7FFFFFFF
}image_type;


typedef struct
{
  image_type image_id;       /* Identifies the type of image this header
                                 represents (OEM SBL, AMSS, Apps boot loader,
                                 etc.). */
  uint32 header_vsn_num;     /* Header version number. */
  uint32 image_src;          /* Location of image in flash: Address of
                                 image in NOR or page/sector offset to image
                                 from page/sector 0 in NAND/SUPERAND. */
  uint8* image_dest_ptr;     /* Pointer to location to store image in RAM.
                                 Also, entry point at which image execution
                                 begins. */
  uint32 image_size;         /* Size of complete image in bytes */
  uint32 code_size;          /* Size of code region of image in bytes */
  uint8* signature_ptr;      /* Pointer to images attestation signature */
  uint32 signature_size;     /* Size of the attestation signature in
                                 bytes */
  uint8* cert_chain_ptr;     /* Pointer to the chain of attestation
                                 certificates associated with the image. */
  uint32 cert_chain_size;    /* Size of the attestation chain in bytes */

} mi_boot_image_header_type;

/*---------------------------------------------------------------------------
  Software Type identifiying image being authenticated. These values
  correspond to the code signing tools (CSMS) Software ID field which has
  lower 32 bits for Software type and upper 32 bits for Software version.
---------------------------------------------------------------------------*/
typedef enum
{
  SECBOOT_SBL_SW_TYPE                = 0,
  SECBOOT_SBL1_SW_TYPE               = 0,
  SECBOOT_AMSS_SW_TYPE               = 1, 
  SECBOOT_DMSS_SW_TYPE               = 1,
  SECBOOT_MBA_SW_TYPE                = 1, /* Modem boot authenticator image */
  SECBOOT_AMSS_HASH_TABLE_SW_TYPE    = 2,
  SECBOOT_FLASH_PRG_SW_TYPE          = 3,
  SECBOOT_EHOSTD_SW_TYPE             = 3,
  SECBOOT_DSP_HASH_TABLE_SW_TYPE     = 4,
  SECBOOT_LPASS_HASH_TABLE_TYPE      = 4, /* Lpass hash table */
  SECBOOT_SBL2_SW_TYPE               = 5,
  SECBOOT_SBL3_SW_TYPE               = 6,
  SECBOOT_TZ_KERNEL_SW_TYPE          = 7, /* TZBSP Image */
  SECBOOT_QSEE_SW_TYPE               = 7, /* TZ is now called QSEE */
  SECBOOT_HOSTDL_SW_TYPE             = 8,
  SECBOOT_APPSBL_SW_TYPE             = 9,
  SECBOOT_RPM_FW_SW_TYPE             = 10,
  SECBOOT_SPS_HASH_TABLE_TYPE        = 11,
  SECBOOT_TZ_EXEC_HASH_TABLE_TYPE    = 12, /* Playready or TZ Executive Image */
  SECBOOT_RIVA_HASH_TABLE_TYPE       = 13,
  SECBOOT_APPS_HASH_TABLE_TYPE       = 14, /* Apps Image */
  SECBOOT_SWI_APPS_SW_TYPE           = 14, /* SWI apps(kernel) image in "binary" format */
  SECBOOT_WDT_SW_TYPE                = 18, /* Wdog debug image */
  SECBOOT_QHEE_SW_TYPE               = 0x15,
  SECBOOT_MAX_SW_TYPE                = 0x7FFFFFFF /* force to 32 bits*/
} secboot_sw_type;

/**
 * @brief Information about the image to be authenticated
 */
typedef struct secboot_image_info_type
{
  const uint8* header_ptr_1;   /**< Pointer to the header */
  uint32       header_len_1;   /**< Length in bytes of the image header */
  const uint8* code_ptr_1;     /**< Pointer to the code */
  uint32       code_len_1;     /**< Length in bytes of the image */
  const uint8* x509_chain_ptr; /**< Pointer to the certificate chain */
  uint32       x509_chain_len; /**< Length in bytes of the certificate chain */
  const uint8* signature_ptr;  /**< Pointer to the signature */
  uint32       signature_len;  /**< Length in bytes of the  signature */
  uint32       sw_type;        /**< Type of the image being authenticated - SBL1, TZ etc */
  uint32       sw_version;     /**< Minimum version of the image that can be executed (for rollback prevention) */
} secboot_image_info_type;


#define BL_SBL_PARTI_NAME "sbl"
#define BL_MIBIB_PARTI_NAME "mibib"
#define BL_ABOOT_PARTI_NAME "aboot"
#define BL_LINUX_BOOT_PARTI_NAME "boot"
#define BL_LINUX_UDATA_PARTI_NAME "lefwkro"
#define BL_LINUX_UAPP_PARTI_NAME "userapp"
#define BL_LINUX_SYSTEM_PARTI_NAME "system"
#define BL_TZ_PARTI_NAME "tz"
#define BL_MODEM_PARTI_NAME "modem"
#define BL_RPM_PARTI_NAME "rpm"
#define BL_BACKUP_PARTI_NAME "backup"

#define BL_PRODUCT_ID                  0x39583430       /* "9X40" */
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

extern unsigned char *sierra_smem_base_addr_get(void);
extern int sierra_smem_boothold_mode_set();
extern bool sierra_is_fastboot_disabled(void);
extern bool sierra_if_enter_fastboot(void);
extern unsigned int sierra_smem_err_count_get(void);
extern void sierra_smem_err_count_set(unsigned int err_cnt);
extern void sierra_smem_reset_type_set(unsigned int reset_type);
extern boolean sierra_smem_get_auth_en(void);
extern boolean image_authenticate(secboot_image_info_type* secboot_info_ptr);

enum blresultcode blprocessdldcontinue(uint8 *payloadp, uint32 tlen, uint32 *bytesleftp);
enum blresultcode blprocessdldend(void);
enum blresultcode blprocessdldstart(uint8 *cwehdrp, uint32 tlen);

uint8 *blgetrxbuf(void);
void bluisetstate(enum bluistateE state);
void blReset(void);
enum blresultcode  blProcessFastbootImage(unsigned char *bufp, unsigned int image_size);
void sierra_check_mibib_state_clear(void);

#endif /* bludefs_h */
