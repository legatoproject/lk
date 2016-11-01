/************
 *
 * Filename:  sierra_cweudefs.h
 *
 * Purpose:   external definitions for CWE package
 *
 * NOTES:
 *
 * Copyright: (C) 2015 Sierra Wireless, Inc.
 *            All rights reserved
 *
 ************/

#ifndef cweudefs_h
#define cweudefs_h

#include <stdint.h>

/* Constants and enumerated types */

#define _global
#define _local
#define _package

/* constants for image header */
#define CWE_HEADER_VER                          03  /* Current header version      */
#define CWE_VER_STR_SZ                          84  /* size of version string      */
#define CWE_REL_DATE_SZ                          8  /* size of release date string */
#define CWE_PROD_BUF_SZ                        256  /* size of the product buffer  */
#define CWE_IMAGE_TYP_SZ                         4  /* size of the image type      */
#define CWE_PROD_TYP_SZ                          4  /* size of the product type    */
#define CWE_HEADER_SZ                       0x0190

/* header field offset constants (relative to the first byte of image in flash) */
#define CWE_OFFSET_PSB                      0x0000
#define CWE_OFFSET_PSB_CRC                  0x0100
#define CWE_OFFSET_HDR_REV                  0x0104
#define CWE_OFFSET_CRC_IND                  0x0108
#define CWE_OFFSET_IMG_TYPE                 0x010C
#define CWE_OFFSET_PROD_TYPE                0x0110
#define CWE_OFFSET_IMG_SIZE                 0x0114
#define CWE_OFFSET_CRC32                    0x0118
#define CWE_OFFSET_VERSION                  0x011C
#define CWE_OFFSET_REL_DATE                 0x0170
#define CWE_OFFSET_COMPAT                   0x0178
#define CWE_OFFSET_MISC_OPTS                0x017C
#define CWE_OFFSET_RESERVED                 0x017D
#define CWE_OFFSET_STOR_ADDR                0x0180
#define CWE_OFFSET_PROG_ADDR                0x0184
#define CWE_OFFSET_ENTRY_PT                 0x0188
#define CWE_OFFSET_SIGNATURE                0x018C

/* Misc Options Field Bit Map */
#define CWE_MISC_OPTS_COMPRESS                0x01  /* image is compressed */
#define CWE_MISC_OPTS_ENCRYPT                 0x02  /* image is encrypyted */
#define CWE_MISC_OPTS_SIGNED                  0x04  /* image is signed */
#define CWE_MISC_OPTS_UNUSED4                 0x08
#define CWE_MISC_OPTS_UNUSED3                 0x10
#define CWE_MISC_OPTS_UNUSED2                 0x20
#define CWE_MISC_OPTS_UNUSED1                 0x40
#define CWE_MISC_OPTS_UNUSED0                 0x80

/* delimiter in bcVersion */
#define CWE_VERSION_STR_DELIM "_"

/* Bitmasks for parsing bcVersion string */
#define CWE_VER_SUBFIELD_PARENT_SKUID_M 0x00000001
#define CWE_VER_SUBFIELD_SKUID_M        0x00000002
#define CWE_VER_SUBFIELD_PARTNO_M       0x00000004
#define CWE_VER_SUBFIELD_DEVICE_M       0x00000008
#define CWE_VER_SUBFIELD_FWVER_M        0x00000010
#define CWE_VER_SUBFIELD_BOOTBLK_M      0x00000020
#define CWE_VER_SUBFIELD_CARRIER_M      0x00000040
#define CWE_VER_SUBFIELD_PRIVER_M       0x00000080
#define CWE_VER_SUBFIELD_PKGVER_M       0x00000100

#define CWE_SIGNATURE_APP               0x00000001

#define CWE_ADDR_UNINIT                 0xFFFFFFFF   /* address field uninitialized */

/* CWE trailer signatures */
#define CWE_TRAILER_SIGNATURE_UINT32    0x77735753
#define CWE_TRAILER_SIGNATURE_SIZE      4
/* "SBL1" in uint32 format for ARM */
#define CWE_IMAGE_TYPE_SBL1_UINT32      0x314C4253

/* Special SKU ID strings for SPKG and NVUP files */
#define CWE_VER_SKUID_INTERNAL          "INTERNAL"
#define CWE_VER_SKUID_CARRIER           "9999999"


/************
 *
 * Name:     cwe_image_type_e
 *
 * Purpose:  To enumerate all CWE image types
 *
 * Notes:    Not all types are supported on all devices
 *
 ************/
enum cwe_image_type_e
{
  CWE_IMAGE_TYPE_MIN = 0,
  CWE_IMAGE_TYPE_QPAR = CWE_IMAGE_TYPE_MIN,     /* partition                 */
  CWE_IMAGE_TYPE_SBL1,                          /* SBL1                      */
  CWE_IMAGE_TYPE_SBL2,                          /* SBL2                      */
  CWE_IMAGE_TYPE_DSP1,                          /* QDSP1 FW                  */
  CWE_IMAGE_TYPE_DSP2,                          /* QDSP2 SW                  */
  CWE_IMAGE_TYPE_DSP3,                          /* QDSP3 SW                  */
  CWE_IMAGE_TYPE_QRPM,                          /* QCT RPM image             */
  CWE_IMAGE_TYPE_BOOT,                          /* boot composite image      */
  CWE_IMAGE_TYPE_APPL,                          /* appl composite image      */
  CWE_IMAGE_TYPE_OSBL,                          /* OS Second boot loader     */
  CWE_IMAGE_TYPE_AMSS,                          /* amss                      */
  CWE_IMAGE_TYPE_APPS,                          /* apps                      */
  CWE_IMAGE_TYPE_APBL,                          /* apps bootloader           */
  CWE_IMAGE_TYPE_NVBF,                          /* NV Backup (factory)       */
  CWE_IMAGE_TYPE_NVBO,                          /* NV Backup (oem)           */
  CWE_IMAGE_TYPE_NVBU,                          /* NV Backup (user)          */
  CWE_IMAGE_TYPE_EXEC,                          /* Self-contained executable */
  CWE_IMAGE_TYPE_SWOC,                          /* Software on card image    */
  CWE_IMAGE_TYPE_FOTO,                          /* FOTO image                */
  CWE_IMAGE_TYPE_FILE,                          /* Generic file              */
  CWE_IMAGE_TYPE_SPKG,                          /* Super package             */
  CWE_IMAGE_TYPE_MODM,                          /* modem composite image     */
  CWE_IMAGE_TYPE_SYST,                          /* image for 0:SYSTEM        */
  CWE_IMAGE_TYPE_USER,                          /* image for 0:USERDATA      */
  CWE_IMAGE_TYPE_HDAT,                          /* image for 0:HDATA         */
  CWE_IMAGE_TYPE_NVBC,                          /* Cache NV Backup           */
  CWE_IMAGE_TYPE_SPLA,                          /* Splash screen image file  */
  CWE_IMAGE_TYPE_NVUP,                          /* NV UPdate file            */
  CWE_IMAGE_TYPE_QMBA,                          /* Modem Boot Authenticator  */
  CWE_IMAGE_TYPE_TZON,                          /* QCT Trust-Zone Image      */
  CWE_IMAGE_TYPE_QSDI,                          /* QCT System Debug Image    */
  CWE_IMAGE_TYPE_ARCH,                          /* Archive                   */
  CWE_IMAGE_TYPE_UAPP,                          /* USER APP Image               */
  CWE_IMAGE_TYPE_LRAM,                          /* Linux RAM image */
  CWE_IMAGE_TYPE_MAX  = CWE_IMAGE_TYPE_LRAM,    /* End of list               */
  CWE_IMAGE_TYPE_COUNT,                         /* Number of entries in list */
  CWE_IMAGE_TYPE_ANY = 0xFE,                    /* any image type            */
  CWE_IMAGE_TYPE_INVALID = 0xFF,                /* invalid image type        */
};

/* Structures */
/************
 *
 * Name:     cwe_header_s
 *
 * Purpose:  CWE Image Header
 *
 * Notes:    256 bytes of product specific buffer + 144 bytes of
 *           header fields
 *
 ************/
struct  cwe_header_s
{
  uint8   prod_buf[CWE_PROD_BUF_SZ];   /* +000: Prod specific buffer    */
  uint32  psb_crc;                     /* +100: CRC of Prod spec. bfr   */
  uint32  hdr_rev;                     /* +104: Header revision number  */
  uint32  crc_ind;                     /* +108: CRC valid indicator     */
  uint32  image_type;                  /* +10C: Image type              */
  uint32  prod_type;                   /* +110: Product type            */
  uint32  image_sz;                    /* +114: Application image size  */
  uint32  image_crc;                   /* +118: CRC32 of app'n image    */
  uint8   version[CWE_VER_STR_SZ];     /* +11C: Version/Time            */
  uint8   rel_date[CWE_REL_DATE_SZ];   /* +170: Release Date string     */
  uint32  compat;                      /* +178: Backward compat field   */
  uint8   misc_opts;                   /* +17C: Misc Options field      */
  uint8   reserved_1;                  /* +17D: Header reserved  3      */
  uint8   reserved_2;                  /* +17E: Header reserved  2      */
  uint8   reserved_3;                  /* +17F: Header reserved  1      */
  uint32  stor_addr;                   /* +180: Storage address         */
  uint32  prog_addr;                   /* +184: Program reloc. address  */
  uint32  entry_pt;                    /* +188: Entry Point address     */
  uint32  signature;                   /* +18C: Application "Signature" */
};


#define CRSTART_CRC32     ((uint32) 0xFFFFFFFFU)
uint32 crcrc32(uint8 *address, uint32 size, uint32 crc);

const char *cwe_image_string_get(enum cwe_image_type_e imagetype);
boolean cwe_image_type_validate(uint32 imagetype, enum cwe_image_type_e * enumvalue);
boolean cwe_header_load(uint8 * startp, struct cwe_header_s * hdp);
boolean cwe_image_validate(
  struct cwe_header_s * hdp,
  uint8               * data_p,
  enum cwe_image_type_e image_type,
  uint32                prod_type,
  boolean               validate_crc);
boolean cwe_version_validate(struct cwe_header_s * hdp);

#endif /* cweudefs_h */
