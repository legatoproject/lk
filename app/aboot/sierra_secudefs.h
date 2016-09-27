/************
 *
 * Filename:  sierra_secudefs.h
 *
 * Purpose:   external definitions for secboot package
 *
 * NOTES:
 *
 * Copyright: (C) 2015 Sierra Wireless, Inc.
 *            All rights reserved
 *
 ************/

#ifndef secudefs_h
#define secudefs_h

#include <sys/types.h>

/************ secboot lk auth kernel part definition start***********/

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

#define CEML_HASH_DIGEST_SIZE_SHA256  32

/**
 * @brief Hash information of the image
 */
typedef struct secboot_code_hash_info_type
{
  uint32   code_address;       /**< Address (pointer value) of the code that was hashed */
  uint32   code_length;        /**< the code length */
  uint32   image_hash_length;  /**< hash length - e.g 20 for SHA1, 32 for SHA256 */
  uint8    image_hash[CEML_HASH_DIGEST_SIZE_SHA256]; /**< hash of HEADER + CODE */
}secboot_image_hash_info_type;

/**
 * @brief Data returned from a successful authentication.
 */
typedef struct secboot_verified_info_type
{
  uint32                       version_id;   /**< The version id (define the secboot lib version) */
  uint64                       sw_id;        /**< The software id (upper 32 bits:version, lower 32 bits:type)
                                                  the image was signed with */
  uint64                       msm_hw_id;    /**< The constructed MSM HW ID value used to authenticate
                                                  the image */
  uint32                       enable_debug; /**< Value of the debug settings from the attestation cert i.e
                                                  SECBOOT_DEBUG_NOP, SECBOOT_DEBUG_DISABLE, SECBOOT_DEBUG_ENABLE */
  secboot_image_hash_info_type image_hash_info; /** Hash of the header + code */

  uint32                       enable_crash_dump; /**< Value of the crash dump settings from the attestation cert i.e
                                                       SECBOOT_CRASH_DUMP_DISABLE, SECBOOT_CRASH_DUMP_ENABLE */
} secboot_verified_info_type;

/* Public Key algorithms in the certificate */
typedef enum
{
  SECX509_PUBKEY_RSA = 0,
  SECX509_PUBKEY_DSA = 1,
  SECX509_PUBKEY_DH  = 2,
  SECX509_PUBKEY_MAX,               /* Last one, for error checking */
  SECX509_RESERVED_1 = 0x7FFFFFFF
} lk_secx509_pubkey_algo_type;

/* Certificate signature algorithm type */
typedef enum
{
  SECX509_md5WithRSAEncryption    = 0,
  SECX509_md2WithRSAEncryption    = 1,
  SECX509_sha1WithRSAEncryption   = 2,
  SECX509_sha256WithRSAEncryption = 3,  
  SECX509_SIG_ALGO_MAX,                 /* Last one, for error checking */
  SECX509_RESERVED_2            = 0x7FFFFFFF
} lk_secx509_sig_algo_type;

/* Maximum number of cert levels in a cert chain */
#define SECBOOT_MAX_NUM_CERTS    3

/* Minimum number of cert levels in a cert chain*/
#define SECBOOT_MIN_NUM_CERTS    2

/* Maximum number of Root Certs */
#define SECBOOT_MAX_ROOT_CERTS   16

/* Total number of certs including max root certs */
#define SECBOOT_TOTAL_MAX_CERTS  (SECBOOT_MAX_ROOT_CERTS + SECBOOT_MAX_NUM_CERTS - 1)


typedef struct secasn1_data_type
{
  const uint8 *data;
  const uint8 *data_bound;
  uint32       len;
} secasn1_data_type;

/* ASN.1 bit string data holder */
typedef struct secasn1_bit_string_type
{
  const uint8 *data;
  uint32       len;
  uint32       unused;
} secasn1_bit_string_type;


/* RSA public key parameters */
typedef struct lk_secx509_rsa_pubkey_type
{
  uint32  mod_len;
  const uint8   *mod_data;
  uint32  exp_e_len;
  const uint8   *exp_e_data;

} lk_secx509_rsa_pubkey_type;

/* Union of all the public key types */
typedef struct lk_secx509_pubkey_type
{
  lk_secx509_pubkey_algo_type  algo;
  union
  {
    lk_secx509_rsa_pubkey_type  rsa;
  }key;

} lk_secx509_pubkey_type;

/* Signature Structure */
typedef struct lk_secx509_signature_type
{
  lk_secx509_sig_algo_type   algo_id;
  secasn1_data_type           val;

} lk_secx509_signature_type;

/* Distinguished name structure */
typedef struct lk_secx509_dn_type
{
  uint32             num_attrib;
  secasn1_data_type  data;

} lk_secx509_dn_type;

/* Version structure */
typedef struct lk_secx509_version_type
{
  uint32             ver;
  secasn1_data_type  val;

} lk_secx509_version_type;

/* Time structure */
typedef struct lk_secx509_time_type
{
  uint32             time;
  secasn1_data_type  data;

} lk_secx509_time_type;

/* Authority Key Identifier structure */
typedef struct lk_secx509_auth_key_id_type
{
  boolean            set;
  secasn1_data_type  key_id;
  lk_secx509_dn_type    name;
  secasn1_data_type  serial_number;

} lk_secx509_auth_key_id_type;

/* Subject Key Identifier structure */
typedef struct lk_secx509_subject_key_id_type
{
  boolean            set;
  secasn1_data_type  key_id;

} lk_secx509_subject_key_id_type;

/* Key Usage structure */
typedef struct lk_secx509_key_usage_type
{
  uint32   val;
  boolean  set;

} lk_secx509_key_usage_type;

/* CA structure */
typedef struct lk_secx509_ca_type
{
  boolean  set;
  boolean  val;

} lk_secx509_ca_type;

/* Extension structure type */
typedef struct lk_secx509_ext_type
{
  boolean                          set;
  lk_secx509_auth_key_id_type     auth_key_id;
  lk_secx509_subject_key_id_type  subject_key_id;
  lk_secx509_key_usage_type       key_usage;
  lk_secx509_key_usage_type       ex_key_usage;
  int32                            path_len;
  lk_secx509_ca_type              ca;

} lk_secx509_ext_type;

/* Certificate information structure */
typedef struct lk_secx509_cert_info_type
{
  lk_secx509_version_type     version;
  secasn1_data_type            serial_number;
  lk_secx509_signature_type   algorithm;
  lk_secx509_dn_type          issuer;
  lk_secx509_time_type        not_before;
  lk_secx509_time_type        not_after;
  lk_secx509_dn_type          subject;
  secasn1_bit_string_type      issuer_unique_id;
  secasn1_bit_string_type      subject_unique_id;
  lk_secx509_ext_type         extension;

} lk_secx509_cert_info_type;

/* Certificate structure */
typedef struct lk_secx509_cert_type
{
  /* The cert_info needs to be the first member */
  lk_secx509_cert_info_type  cert_info;

  uint32                      cinf_offset; //where the certificate actually starts -
                                           //after the initial tag/len
  uint32                      cinf_byte_len; //length of where the certificate actually starts
                                             //upto (but not including) the certificate signature
  uint32                      asn1_size_in_bytes; //size of the entire certificate (including the initial tag/len)

  /* Signature info on the cert */
  lk_secx509_pubkey_type     pkey;
  lk_secx509_sig_algo_type   sig_algo;
  const uint8                *sig;
  uint32                      sig_len;
  
  /*For verification */
  uint8                       cert_hash[CEML_HASH_DIGEST_SIZE_SHA256];
} lk_secx509_cert_type;



/* Certificate list struct */
typedef struct lk_secx509_cert_list_struct
{
  lk_secx509_cert_type  cert[SECBOOT_MAX_NUM_CERTS];
  uint32               size;

} lk_secx509_cert_list_type;

/* certificate list context type */
typedef struct
{
  uint32                       purpose;
  uint32                       trust;
  uint32                       depth;
  lk_secx509_cert_list_type*  ca_list;

} lk_secx509_cert_ctx_type;

/* secboot lk auth kernel start */
typedef enum
{
  E_X509_SUCCESS = 0,
  E_X509_FAILURE,
  E_X509_NO_DATA,
  E_X509_DATA_INVALID,
  E_X509_BAD_DATA,
  E_X509_DATA_TOO_LARGE,
  E_X509_DATA_EXPIRED,
  E_X509_NO_MEMORY,
  E_X509_INVALID_ARG,
  E_X509_NOT_SUPPORTED,
  E_X509_OU_FIELD_NOT_FOUND,
  E_X509_RESERVED       = 0x7FFFFFFF
} secx509_errno_enum_type;

typedef enum
{
  E_X509_CODE_HASH_NOT_SPECIFIED = 0,
  E_X509_CODE_HASH_SHA1,
  E_X509_CODE_HASH_SHA256,
  E_X509_CODE_HASH_RESERVED       = 0x7FFFFFFF
}secx509_code_hash_algo_type;

/*typedef struct secx509_ou_field_info_type
{
  uint64                      debug_enable;
  uint64                      sw_id;  
  uint64                      hw_id;
  secx509_code_hash_algo_type code_hash_algo;
  uint64                      crash_dump_enable;
} secx509_ou_field_info_type;*/

typedef struct secx509_ou_field_info_type
{
  uint64                      debug_enable; /* for ou field, DEBUG */
  uint64                      sw_id; /* for ou field, SW_ID */
  uint64                      hw_id; /* for ou field, HW_ID */
  secx509_code_hash_algo_type code_hash_algo; /* for ou field, SHA1/SHA256 */
  uint64                      crash_dump_enable; /* for ou field, CRASH_DUMP */
  uint64                      rot_ou_field; /* for ou field, ROT_EN */
  uint64                      in_use_soc_hw_version; /* for ou field, IN_USE_SOC_HW_VERSION */
  uint16                      ou_use_serial_num; /* for ou field, USE_SERIAL_NUMBER_IN_SIGNING */
} secx509_ou_field_info_type;


/**
 * @brief Error codes specific to secboot
 */
typedef enum secboot_error_type
{
  E_SECBOOT_SUCCESS                = 0,   /**< Operation was successful. */
  E_SECBOOT_FAILURE                = 1,   /**< General failure. */
  E_SECBOOT_INVALID_PARAM          = 2,   /**< Invalid parameter passed into function. */
  E_SECBOOT_INVALID_DATA           = 3,   /**< Data is invalid. */
  E_SECBOOT_UNSUPPORTED            = 4,   /**< Option not supported. */
  E_SECBOOT_RSA_FAIL               = 5,   /**< Failure occured for RSA. */
  E_SECBOOT_HASH_FAIL              = 6,   /**< Failure occured for hash. */
  E_SECBOOT_HW_FAIL                = 7,   /**< Failure occured for HW. */
  E_SECBOOT_X509_FAIL              = 8,   /**< Failure occured during cert chain parsing. */
  E_SECBOOT_INVALID_CERT           = 9,   /**< Cert chain validation checks failed. */
  E_SECBOOT_INVALID_CERT_SIG       = 10,  /**< Cert chain signature validation failed. */
  E_SECBOOT_UNTRUSTED_ROOT         = 11,   /**< Root certificate is not the root of trust. */
  E_SECBOOT_INVALID_IMAGE_SIG      = 12,  /**< Invalid image signature. */
  E_SECBOOT_INVALID_SW_TYPE        = 13,  /**< Unexpected software type. */
  E_SECBOOT_INVALID_SW_VERSION     = 14,  /**< Image has been signed with an older version */
  E_SECBOOT_INVALID_MSM_HW_ID      = 15,  /**< Image has been signed for a different hw id */
  E_SECBOOT_INVALID_DEBUG          = 16,  /**< Invalid debug cert */
  E_SECBOOT_INIT                   = 17,  /**< Initialization failed */
  E_SECBOOT_DEINIT                 = 18,  /**< De-initialization failed */
  E_SECBOOT_INVALID_ROOT_SEL       = 19,  /**< Root selection failed */
  E_SECBOOT_INVALID_CRASH_DUMP     = 20,  /**< Invalid crash dump cert */
  E_SECBOOT_MAX                    = 0x7FFFFFFF /**< Force to 32 bits */
} secboot_error_type;

typedef enum
{
  CEML_HASH_ALGO_SHA1               = 0x1,
  CEML_HASH_ALGO_SHA256             = 0x2
} CeMLHashAlgoType;

typedef struct clk_julian_type
{
  uint32  year;
  uint32  month;
  uint32  day;
  uint32  hour;
  uint32  minute;
  uint32  second;
} clk_julian_type;

/* Key Usage Masks */
#define SECX509_KEY_USAGE_DIG_SIG   (0x0100) /* digital signature */
#define SECX509_KEY_USAGE_NON_REP   (0x0080) /* non-repudiation   */
#define SECX509_KEY_USAGE_KEY_ENC   (0x0040) /* key encipherment  */
#define SECX509_KEY_USAGE_DAT_ENC   (0x0020) /* data encipherment */
#define SECX509_KEY_USAGE_KEY_ARG   (0x0010) /* key agreement     */
#define SECX509_KEY_USAGE_KEY_CRT   (0x0008) /* key cert sign     */
#define SECX509_KEY_USAGE_CRL_SIG   (0x0004) /* CRL sign          */
#define SECX509_KEY_USAGE_ENC_OLY   (0x0002) /* encipher only     */
#define SECX509_KEY_USAGE_DEC_OLY   (0x0001) /* decipher only     */
/* Extended Key Usage Masks */
#define SECX509_EX_KEY_USAGE_SAUTH  (0x0001) /* TLS Web Server Authentication*/
#define SECX509_EX_KEY_USAGE_CAUTH  (0x0002) /* TLS Web Client Authentication*/
#define SECX509_EX_KEY_USAGE_CODE   (0x0004) /* Downloadable Code Signing    */
#define SECX509_EX_KEY_USAGE_EMAIL  (0x0008) /* Email Protection             */
#define SECX509_EX_KEY_USAGE_TIME   (0x0010) /* Time Stamping                */
#define SECX509_EX_KEY_USAGE_SGC    (0x0020) /* Secured Gated Crypto         */

#define SECASN1_NO_TYPE_CHECK         (0x00)
#define SECASN1_BOOLEAN_TYPE          (0x01)
#define SECASN1_INTEGER_TYPE          (0x02)
#define SECASN1_BIT_STRING_TYPE       (0x03)
#define SECASN1_OCTET_STRING_TYPE     (0x04)
#define SECASN1_NULL_TYPE             (0x05)
#define SECASN1_OID_TYPE              (0x06)
#define SECASN1_SEQUENCE_TYPE         (0x10)
#define SECASN1_SET_TYPE              (0x11)
#define SECASN1_PRINTABLE_STRING_TYPE (0x13)
#define SECASN1_TELETEX_STRING_TYPE   (0x14)
#define SECASN1_UTC_TYPE              (0x17)

#define SECASN1_MAX_LEN               0xFFFFU  /* allows SECASN1_UNDEFINED_LEN to be legal */ 

#define SECBOOT_MAX_KEY_SIZE_IN_BITS 4096 /* Secmath has to support this size */
#define SECBOOT_MIN_KEY_SIZE_IN_BITS 2048 /* Secmath has to support this size */
#define SECBOOT_MAX_PUB_EXP_KEY_SIZE_IN_BITS 32 /* in bits, but we expect only exp=3 (2 bits) or worst 65537 (17 bits)
                                    ** the generic case would be = SECBOOT_MAX_KEY_SIZE_IN_BITS but for
                                    ** memory reasons
                                    ** we stick to a small size to save memory whereever possible */


/**
  ASN.1 Error Codes
*/
typedef enum
{
  E_ASN1_SUCCESS = 0,
  E_ASN1_INVALID_TAG,
  E_ASN1_NO_DATA,
  E_ASN1_INVALID_DATA,
  E_ASN1_INVALID_ARG
} secasn1_err_type;

/* we stick to a small size to save memory whereever possible */
#define ATTEST_CERT_INDEX        0
#define CA_CERT_INDEX            1
#define ROOT_CERT_INDEX          2

#define CHECK_DATA_BOUND(p, len, bound)                     \
( ( ((uint32)(p) + (uint32)(len)) >= (uint32)(p) ) &&       \
  ( ((uint32)(p) + (uint32)(len)) <= (uint32)(bound) ) )    \


/* Error log structure to store constant data describing error location */
typedef struct secboot_error_log_type
{
  uint32                   linenum;
  uint32                   data1;
  uint32                   data2;
  uint32                   data3;
} secboot_error_log_type;

/* store the root cert selection information */
typedef struct secboot_root_cert_fuse_info_type
{
  uint32   is_root_sel_enabled;  /* Is Root Cert Selection enabled */
  uint32   root_cert_sel;        /* valid only if root cert selection is enabled */
  uint32   num_root_certs;       /* valid only if root cert selection is enabled */
} secboot_root_cert_fuse_info_type;


typedef struct secboot_fuse_info_type
{
  uint8        root_of_trust[CEML_HASH_DIGEST_SIZE_SHA256]; /**< sha256 hash of the root certificate */
  uint64       msm_hw_id;             
  uint32       auth_use_serial_num;
  uint32       serial_num;
  boolean      use_root_of_trust_only; /**< Caller sets this variable to TRUE if 
                                            secboot needs to use only root of trust from the 
                                            supplied fuses */
  secboot_root_cert_fuse_info_type    root_sel_info;
} secboot_fuse_info_type;


//Make sure this structure is uint32 aligned
typedef struct secboot_context_type
{
    uint32                         magic_number;
    //secboot_crypto_hash_ftbl_type  crypto_hash_ftbl;
    uint32                         version; //version of secboot release
    secboot_error_log_type         error_log;      
    secboot_fuse_info_type         fuses;
    boolean                        use_supplied_fuses; /* This value will be set to TRUE,
                                                     if fuse values are supplied from externally */
}secboot_context_type;

extern  secboot_error_type secboot_calc_and_cmp_hash
(
  CeMLHashAlgoType                  hash_algo,
  const uint8*                      data1_to_hash,
  uint32                            data1_len,
  const uint8*                      data2_to_hash,
  uint32                            data2_len,
  const uint8*                      hash_to_cmp
);

extern boolean sierra_smem_get_auth_en(void);
extern boolean sierra_smem_get_hw_fuses(secboot_fuse_info_type*  fuse_info_ptr);
extern boolean image_authenticate(secboot_image_info_type* secboot_info_ptr, secboot_verified_info_type* verified_info_ptr);

extern boolean boot_swi_lk_auth_kernel(struct ptentry *ptn,boot_img_hdr *hdr);
#endif

