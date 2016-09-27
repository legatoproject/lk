/************
 *
 * Filename:  sierra_sec.c
 *
 * Purpose:   Sierra Little Kernel changes for secure boot           
 *
 * Copyright: (c) 2015 Sierra Wireless, Inc.
 *            All rights reserved
 *
 * Note:       
 *
 ************/

#include <lib/ptable.h>
#include <dev/flash.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <crc32.h>
#include "bootimg.h"
#include "mach/sierra_smem.h"
#include "sierra_bludefs.h"
#include "sierra_secudefs.h"

/*#define  SWI_SECBOOT_DEBUG_EN */   /* Macro to control print debug info */
#ifdef SWI_SECBOOT_DEBUG_EN
#define SECBOOT_PRINT printf
#else
#define SECBOOT_PRINT
#endif

/* Define ASN.1 and SEC.X509 to parse and verify certifiction chain; port from QTI ref code. */

#define SECASN1_TAG_CLAS_MASK   (0xC0L)
#define SECASN1_TAG_UNIV_VAL    (0x00L)
#define SECASN1_TAG_CTXT_VAL    (0x80L)
#define SECASN1_TAG_EXT_MASK    (0x80L)
#define SECASN1_TAG_MULB_MASK   (0x1FL)
#define SECASN1_TAG_SUBEXT_MASK (0x7FL)
        
#define SECASN1_LENGTH_MASK     (0x80L)
#define SECASN1_LENGTH_EXT_MASK (0x7FL)
#define SECASN1_LENGTH_FACTOR   256L


#define SECX509_SECONDS_PER_YEAR        31536000

/* ASN.1 Tag Ids */
#define SECX509_VERSION_TAG             (0xA0)
#define SECX509_ISSUER_ID_TAG           (0x81)
#define SECX509_SUBJECT_ID_TAG          (0x82)
#define SECX509_EXTENSION_TAG           (0xA3)

#define SECX509_AUTH_KID_TAG            (0x80)
#define SECX509_AUTH_ISS_TAG            (0xA1)
#define SECX509_AUTH_SER_TAG            (0x82)
#define SECX509_AUTH_ISS_NAME_TAG       (0xA4)
#define OU_FIELD_VALUE_STRING_LEN       (16)
#define OU_FIELD_VALUE_STRING_SPACE_LEN (OU_FIELD_VALUE_STRING_LEN + 1)


#define SECX509_OU_FIELD_VALUE_MAX_BYTES          (0x10) /* the max supported length for parsing OU field value string */
#define SECX509_OU_SHIFT_BIT_NUM_FOR_BYTE_IN_CERT (0x4) /* the number of bits to shift for converting char to int */
#define SECX509_OU_FIELD_INDEX_LEN                (0x2) /* the length of chars for the OU field index */
#define SECX509_OU_FIELD_SPACE_LEN                (0x1) /* the length of the space char*/

#define SECBOOT_DEBUG_NOP     0x0 /**< Bit value 00 - No operation needs to be performed */
#define SECBOOT_DEBUG_DISABLE 0x2 /**< Bit value 10-  Write 0 to one-time override registers */                                     
#define SECBOOT_DEBUG_ENABLE  0x3 /**< Bit value 11 - Write 1 to one-time override registers*/

/* Maximum Cert Chain Size */
#define SECBOOT_MAX_CERT_SIZE       (3072)
#define SECBOOT_MAX_CERT_CHAIN_SIZE (SECBOOT_TOTAL_MAX_CERTS * SECBOOT_MAX_CERT_SIZE)

#define SECBOOT_MAX_KEY_SIZE_IN_BITS 4096 /* Secmath has to support this size */


/* X.509 Certificate Objects */
#define SECX509_ASN1_OBJ_UNIT_NAME \
  {0x55, 0x04, 0x0B }

#define SECX509_ASN1_OBJ_ORG_NAME \
  {0x55, 0x04, 0x0A }

#define SECX509_ASN1_OBJ_COMMON_NAME \
  {0x55, 0x04, 0x03 }

#define SECX509_ASN1_OBJ_RSA \
  {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 }

#define SECX509_ASN1_OBJ_SHA1WITHRSAENCRYPTION \
  {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05 }

#define SECX509_ASN1_OBJ_SHA256WITHRSAENCRYPTION \
  {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B }

/* X.509 Extension Objects */
#define SECX509_EXT_AUTH_KEY_ID \
  {0x55, 0x1D, 0x23 }

#define SECX509_EXT_SUB_KEY_ID \
  {0x55, 0x1D, 0x0E }

#define SECX509_EXT_KEY_USAGE \
  {0x55, 0x1D, 0x0F }

#define SECX509_EXT_SUB_ALT_NAME \
  {0x55, 0x1D, 0x11 }

#define SECX509_EXT_BASIC_CONSTRAINT \
  {0x55, 0x1D, 0x13 }

#define SECX509_EXT_NAME_CONSTRAINT \
  {0x55, 0x1D, 0x1E }

#define SECX509_EXT_POLICY_CONSTRAINT \
  {0x55, 0x1D, 0x24 }

#define SECX509_EXT_EX_KEY_USAGE \
  {0x55, 0x1D, 0x25 }

#define SECX509_EXT_CERT_POLICIES \
  {0x55, 0x1D, 0x20 }

/* Extended Key Usage Objects */
#define SECX509_EX_KEY_SAUTH \
  {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 }

#define SECX509_EX_KEY_CAUTH \
  {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 }

#define SECX509_EX_KEY_CODE \
  {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03 }

#define SECX509_EX_KEY_EMAIL \
  {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04 }

#define SECX509_EX_KEY_TIME \
  {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08 }

#define SECX509_EX_KEY_MS_SGC \
  {0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0A, 0x03, 0x03 }

#define SECX509_EX_KEY_NS_SGC \
  {0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42, 0x04, 0x01 }

#define SECX509_ASN1_OBJ_SHA1 \
  { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, \
    0x1A, 0x05, 0x00, 0x04, 0x14 }

#define SECX509_ASN1_OBJ_SHA256 \
  { 0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, \
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 }

#define SECX509_ASN1_OBJ_SHA384 \
  { 0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, \
    0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 }

#define SECX509_ASN1_OBJ_SHA512 \
  { 0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, \
    0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 }

#define BREAKIF_SETERR(cond, err) \
        if (cond)                    \
        {                         \
           err = E_ASN1_INVALID_DATA; \
           break;                          \
        }

#define SECX509_UPDATE_OU_FIELD_VALUE(status, ou_field_value_to_update, parsed_value) \
    if (E_X509_SUCCESS == status) \
    { \
      ou_field_value_to_update = parsed_value; \
    } \
    else if (E_X509_OU_FIELD_NOT_FOUND == status) \
    { \
      status = E_X509_SUCCESS; \
    } \
    else \
    { \
      break; \
    }

/* Parse x509 subject DN */
#define BLOAD8(x) ((uint32)(*((uint8*)(x))))
#define BSTOR8(x,y) (*((uint8*)(x))) = (uint8)(y)

#define ROUND_TO_PAGE(x,y) (((x) + (y)) & (~(y)))

#define convert_to_binary(ptr) \
              if ((BLOAD8(ptr)>=0x41)&&(BLOAD8(ptr)<=0x46)) \
                BSTOR8 (ptr , (BLOAD8(ptr)-55)); \
              else if ((BLOAD8(ptr)>=0x30)&&(BLOAD8(ptr)<=0x39)) \
                BSTOR8 (ptr , (BLOAD8(ptr)-48)); \
              else \
                break; \
              BSTOR8 (ptr , (BLOAD8(ptr)&0x0F)); \

static const uint8 debug_string[]="DEBUG";
#define OU_DEBUG_STRING_LEN (0x5)
#define OU_DEBUG_VALUE_LEN (0x10)
              static const uint8 crash_dump_string[]="CRASH_DUMP";
#define OU_CRASH_DUMP_STRING_LEN (0x0A)
#define OU_CRASH_DUMP_VALUE_LEN (0x10)
              static const uint8 rot_string[]="ROT_EN";
#define OU_ROT_STRING_LEN (0x6)
#define OU_ROT_VALUE_LEN (0x10)
              static const uint8 use_serial_num_string[]="USE_SERIAL_NUMBER_IN_SIGNING";
#define OU_USE_SERIAL_NUM_STRING_LEN (0x1C)
#define OU_USE_SERIAL_NUM_VALUE_LEN (0x04)

static const uint8 sw_id_string[]="SW_ID";
#define OU_SW_ID_STRING_LEN (0x5)
#define OU_SW_ID_VALUE_LEN (0x10)
              static const uint8 hw_id_string[]="HW_ID";
#define OU_HW_ID_STRING_LEN (0x5)
#define OU_HW_ID_VALUE_LEN (0x10)
              static const uint8 sha1_codehash_str[] = "SHA1";
#define OU_SHA1_STRING_LEN (0x4)
#define OU_SHA1_VALUE_LEN (0x4)
              static const uint8 sha256_codehash_str[] = "SHA256";
#define OU_SHA256_STRING_LEN (0x6)
#define OU_SHA256_VALUE_LEN (0x4)
              static const uint8 in_use_soc_hw_version_string[] = "IN_USE_SOC_HW_VERSION";
#define OU_IN_USE_SOC_HW_VER_STRING_LEN (0x15)
#define OU_IN_USE_SOC_HW_VER_VALUE_LEN (0x4)


/* ASN.1 Objects for Extensions */
static const uint8 lk_secx509_ext_auth_key_id[] = SECX509_EXT_AUTH_KEY_ID;
static const uint8 lk_secx509_ext_sub_key_id[] = SECX509_EXT_SUB_KEY_ID;
static const uint8 lk_secx509_ext_key_usage[] = SECX509_EXT_KEY_USAGE;
static const uint8 lk_secx509_ext_sub_alt_name[] = SECX509_EXT_SUB_ALT_NAME;
static const uint8 lk_secx509_ext_basic_constraint[] = 
  SECX509_EXT_BASIC_CONSTRAINT;
static const uint8 lk_secx509_ext_name_constraint[] = 
  SECX509_EXT_NAME_CONSTRAINT;
static const uint8 lk_secx509_ext_policy_constraint[] =
                                                SECX509_EXT_POLICY_CONSTRAINT;
static const uint8 lk_secx509_ext_ex_key_usage[] = SECX509_EXT_EX_KEY_USAGE;
static const uint8 lk_secx509_ext_cert_policies[] = SECX509_EXT_CERT_POLICIES;
/* ASN.1 Object for Extended Key Usage */
static const uint8 lk_secx509_ex_key_sauth[] = SECX509_EX_KEY_SAUTH;
static const uint8 lk_secx509_ex_key_cauth[] = SECX509_EX_KEY_CAUTH;
static const uint8 lk_secx509_ex_key_code[] = SECX509_EX_KEY_CODE;
static const uint8 lk_secx509_ex_key_email[] = SECX509_EX_KEY_EMAIL;
static const uint8 lk_secx509_ex_key_time[] = SECX509_EX_KEY_TIME;
static const uint8 lk_secx509_ex_key_ms_sgc[] = SECX509_EX_KEY_MS_SGC;
static const uint8 lk_secx509_ex_key_ns_sgc[] = SECX509_EX_KEY_NS_SGC;


static const uint8 lk_secx509_asn1_oid_obj_unit[] = SECX509_ASN1_OBJ_UNIT_NAME;
static const uint8 lk_secx509_asn1_rsa[] = SECX509_ASN1_OBJ_RSA;

static const uint8 lk_secx509_sha1WithRSAEncryption[] =
SECX509_ASN1_OBJ_SHA1WITHRSAENCRYPTION;
static const uint8 lk_secx509_sha256WithRSAEncryption[] =
SECX509_ASN1_OBJ_SHA256WITHRSAENCRYPTION;

#define CEML_HASH_DIGEST_SIZE_SHA1    20

/* zero indicates an error */
#define SECBOOT_HASH_LEN(hashtype) \
((hashtype) == CEML_HASH_ALGO_SHA1 ? CEML_HASH_DIGEST_SIZE_SHA1 : \
((hashtype) == CEML_HASH_ALGO_SHA256 ? CEML_HASH_DIGEST_SIZE_SHA256 : \
0))


#define BREAKIF(cond)  { if (cond) break; }

/*===========================================================================
MACRO SECX509_NEXT_FIELD

DESCRIPTION
  This macro parses the next data field in the certificate.  If there is an
  error parsing the field, the ret_status will be set and the current scope
  will be broken from

DEPENDENCIES
  To call this macro a secerrno_enum_type ret_status must be defined and
  this must be called within a loop or switch statement so it can break
  from execution.

PARAMETERS
  data_ptr - pointer to the next certificate data and its length
  ret_ptr  - pointer to the inner certificate field that is to be parsed
  tag_id   - tag value to verifify the inner tag is proper

SIDE EFFECTS
  If no error occurs during processing the data_ptr->data will be advanced
  to the next field and data_ptr->len will be decremented by the amount the
  pointer was increased.  If an errror occurs in parsing then data_ptr will
  remain unchanged.
===========================================================================*/
#define SECX509_NEXT_FIELD( data_ptr, ret_ptr, tag_id ) \
  if ( lk_secasn1_next_field( data_ptr, ret_ptr, tag_id ) \
       != E_ASN1_SUCCESS ) { \
        ret_status = E_X509_DATA_INVALID; \
        break; \
    }

/*===========================================================================
MACRO SECX509_OPEN_SEQUENCE

DESCRIPTION
  This macro parses open the next ASN.1 sequence of values, all this macro
  does is call SECX509_NEXT_FIELD with a sequence tag, but it has been
  defined so there should always be matching SECX509_OPEN_SEQUENCE and
  SECX509_CLOSE_SEQUENCE

DEPENDENCIES
  To call this macro a secerrno_enum_type ret_status must be defined and
  this must be called within a loop or switch statement so it can break
  from execution.

PARAMETERS
  outer - the outer pointer containing the data to be parsed
  inner - the inner pointer which will hold the parsed data

SIDE EFFECTS
  If no error occurs during processing the outer->data will be advanced
  to the next field and outer->len will be decremented by the amount the
  pointer was increased.  If an errror occurs in parsing then outer will
  remain unchanged.
===========================================================================*/
#define SECX509_OPEN_SEQUENCE( outer, inner ) \
    SECX509_NEXT_FIELD( outer, inner, SECASN1_SEQUENCE_TYPE )


/*===========================================================================

FUNCTION SECASN1_CLOSE_SEQUENCE

DESCRIPTION
  This function verifies that all the data in the inner sequence has
  been processed.  The outer sequence is included in the case that
  a sequence has an undefined length. The ASN.1 indefinite length is 
  not supported.

DEPENDENCIES
  lk_secasn1_next_field() to start a sequence value has been called

PARAMETERS
  outer - pointer to the outer sequence
  inner - pointer to the inner sequence

RETURN VALUE
  E_ASN1_SUCCESS - if the sequence was successful closed
  E_ASN1_INVALID_ARG - if a pointer argument has a NULL value
  E_ASN1_INVALID_DATA - otherwise

SIDE EFFECTS
  None
===========================================================================*/
secasn1_err_type lk_secasn1_close_sequence
(
  secasn1_data_type *outer,
  secasn1_data_type *inner
)
{
   secasn1_err_type _errno = E_ASN1_SUCCESS;
  /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -*/

  do
  {
    if ( inner == NULL ||
         outer == NULL )
    {
      _errno = E_ASN1_INVALID_ARG;
      break;
    }

    // Normal case:  All the inner data should have been parsed, hence 
    // inner->len should be zero, and inner->data and 
    // outer _data should be at the same address.
    if ( inner->len != 0 || inner->data != outer->data) {
        _errno = E_ASN1_INVALID_DATA;
        break;
      }
  }/*lint -e(717) */ while (FALSE);
  return _errno;

} /* lk_secasn1_close_sequence */



/*===========================================================================
MACRO SECX509_CLOSE_SEQUENCE

DESCRIPTION
  This macro verifies that the end of

DEPENDENCIES
  To call this macro a secerrno_enum_type ret_status must be defined and
  this must be called within a loop or switch statement so it can break
  from execution.

PARAMETERS
  outer - the outer pointer containing the data to be parsed
  inner - the inner pointer which will hold the parsed data

SIDE EFFECTS
  If no error occurs during processing the outer->data will be advanced
  to the next field and outer->len will be decremented by the amount the
  pointer was increased.  If an errror occurs in parsing then outer will
  remain unchanged.
===========================================================================*/
#define SECX509_CLOSE_SEQUENCE( outer, inner ) \
    if ( lk_secasn1_close_sequence( outer, inner ) != E_ASN1_SUCCESS ) { \
        ret_status = E_X509_DATA_INVALID; \
        break; \
    }

    
#define CHECK_ASN1_INVARIANTS(s) \
      ((s).len <= SECASN1_MAX_LEN && \
       CHECK_DATA_BOUND((s).data, (s).len, (s).data_bound))    \

/*===========================================================================

FUNCTION SECASN1_DECODE_TAG

DESCRIPTION
  This function decodes the tag of the current ASN.1 DER encoded field.

  Assumes that all primitive tags have a tag_id of less then 31, from
  Documentation I have read, this is true.  Assumes that we will never
  encounter a tag identifier greater then 2^14 - 1, If we encounter a
  tag with a greater identifier, the value E_ASN1_INVALID_DATE is returned,
  this prevents the searching through all of memory.  Assumes that for
  a SEQUENCE there is at most 32 optional fields.

DEPENDENCIES
  None

PARAMETERS
  data       - pointer to pointer to the tag to be decoded (*data is updated by the parsing)
  data_bound - pointer to after the data (for catching bogus length)
  tag_id     - where the tag value is returned

RETURN VALUE
  If successful, E_ASN1_SUCCESS is returned with the tag_id pointer set with
  the tag_id of the universal tag or set with the entire value if the
  tag is a context-tag for optional fields.

SIDE EFFECTS
  None
===========================================================================*/
secasn1_err_type lk_secasn1_decode_tag
(
  const uint8 **data,
  const uint8  *data_bound,
  uint32       *tag_id
)
{
  uint32 tag_class;                     /* first 2 bits of first tag byte */
  const uint8 *data_ptr;                /* pointer to the data            */
  uint32 tag;          
  secasn1_err_type _errno = E_ASN1_SUCCESS;
  /*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
  do
  {
    // Check for null pointers and zero tags.  Check that we can read one
    // byte at *data.  No need to check data_bound, as it is never dereferenced.
    BREAKIF_SETERR( ( (data == NULL) || (*data == NULL) || (tag_id == NULL) ||
       (!CHECK_DATA_BOUND(*data, 1, data_bound)) ), _errno)
    tag = BLOAD8 (*data);
    data_ptr = *data + 1; //advance    
    
   *tag_id = 0;

    /* We don't support multi-byte tag's */
    if ( ( tag & SECASN1_TAG_MULB_MASK ) == SECASN1_TAG_MULB_MASK )
    {
          _errno = E_ASN1_INVALID_DATA;
          break;
    }


    tag_class = tag & SECASN1_TAG_CLAS_MASK;

    if ( tag_class == SECASN1_TAG_UNIV_VAL )
    {
      /* Tag is a universal tag */
      *tag_id = (tag & SECASN1_TAG_MULB_MASK);
    }
    else if ( tag_class == SECASN1_TAG_CTXT_VAL )
    {
      /* Tag is a context-specific (optional) tag */
      *tag_id = tag;
    }
    else
    {
      _errno = E_ASN1_INVALID_DATA;
      break;
    }

    *data = data_ptr;
  }/*lint -e(717) */ while (FALSE);
  return _errno;
} /* lk_secasn1_decode_tag */

/*===========================================================================

FUNCTION SECASN1_DECODE_LENGTH

DESCRIPTION
  This function decodes the length of the current ASN.1 DER encoded field.
  When this function is called, data_ptr must be pointing at the first
  byte in the length field.

DEPENDENCIES
  Assumes that no field being parsed is has a value of size more than 64K

PARAMETERS
  data   - pointer to the length data
  data_bound - pointer to after the data (for catching bogus length)
  length - where the length value is returned

RETURN VALUE
  If successful, E_ASN1_SUCCESS is returned with the length pointer set with
  the number of bytes that are contained in the value.  If the length field
  has a length longer then 64K E_ASN1_INVALID_DATA is returned

SIDE EFFECTS
  None
===========================================================================*/
secasn1_err_type lk_secasn1_decode_length
(
  const uint8 **data,
  const uint8  *data_bound,
  uint32       *length
)
{
  uint32 num_bytes = 0;                     /* number of bytes in the tag */
  const uint8 *data_ptr;                    /* pointer to the data        */
  uint32 loc_length = 0;
  secasn1_err_type _errno = E_ASN1_SUCCESS;
  /*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -*/
  /* Sanity Check on pointer arguments */
  if ( (data == NULL) || (*data == NULL) || (length == NULL) )
  {
    return E_ASN1_INVALID_ARG;
  }

  *length = 0;
  data_ptr = *data;

  do
  {
    // about to access 1 byte (first byte of length, so check
    BREAKIF_SETERR(!CHECK_DATA_BOUND(data_ptr, 1, data_bound), _errno)
    if ( BLOAD8(data_ptr) & SECASN1_LENGTH_MASK )
    {
      /* Length bytes are in the long form */
      // Just checked above, and data_ptr has not advanced.  
      // No need to check again.
      num_bytes = BLOAD8(data_ptr) & SECASN1_LENGTH_EXT_MASK;
      /* Per spec the value '11111111'b shall not be used. */
      /* Just need to check for for 0x7F as the 8th bit we */
      /* know is already 1 */
      BREAKIF_SETERR(num_bytes == SECASN1_LENGTH_EXT_MASK, _errno);
      // advance data_ptr over byte just read.  Already checked.
      data_ptr++;
      if ( num_bytes == 0 )
      {
        /* The ASN.1 indefinite length is not supported. */
        _errno = E_ASN1_INVALID_DATA;
        break;
      }

      /* Calculate the size of the value.  The check is inside the loop 
         in case the size is really large. */
      while ( num_bytes != 0 )
      {
        loc_length *= SECASN1_LENGTH_FACTOR;
        // Check before reading 1 byte.
        BREAKIF_SETERR(!CHECK_DATA_BOUND(data_ptr, 1, data_bound), _errno)
        loc_length += BLOAD8(data_ptr);
        if (loc_length > SECASN1_MAX_LEN)
        {
          _errno = E_ASN1_INVALID_DATA;
          break;
        }
        data_ptr++;  // advance over byte just read
        --num_bytes;
      }
      if(_errno != E_ASN1_SUCCESS)
      {
        break;
      }
    }
    else
    {
      /* Length bytes are in the short form; can't overflow  */
      // Check that we can read one byte.
      BREAKIF_SETERR(!CHECK_DATA_BOUND(data_ptr, 1, data_bound), _errno)
      loc_length = BLOAD8(data_ptr);
      data_ptr++;
    }

    /* Final check for consistency */
    /* Make sure we could actually read loc_length bytes */
    BREAKIF_SETERR(!CHECK_DATA_BOUND(data_ptr, loc_length, data_bound), _errno)

    *data = data_ptr;
    *length = loc_length; 

  }while(FALSE);

  return _errno;
} /* lk_secasn1_decode_length */


/*===========================================================================

FUNCTION SECASN1_START

DESCRIPTION
  Starts an ASN.1 DER encoding by creating an initial container for the
  next_field() function

DEPENDENCIES
  None

PARAMETERS
  data    - pointer to the data
  data_bound - pointer to after the data (for catching bogus length)
  ret_ptr - pointer to the returned data to start the ASN.1 block

RETURN VALUE
  E_ASN1_SUCCESS - if the sequence is properly started
  E_ASN1_INVALID_ARG - if the pointer arguments have a NULL value
  E_ASN1_INVALID_TAG - if it is not a sequence tag at the beginning
  E_ASN1_INVALID_DATA - if the top-level object would extend beyond
                        data bound

SIDE EFFECTS
  None
===========================================================================*/
secasn1_err_type lk_secasn1_start
(
  const uint8 *data,
  const uint8 *data_bound,
  secasn1_data_type *ret_ptr
)
{
  uint32 tag_id;                                     /* current tag id     */
  secasn1_err_type _errno = E_ASN1_INVALID_ARG;
  /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -*/
  do
  {
    /* Make sure data and ret_ptr are non-null */
    if ( (data == NULL) || (ret_ptr == NULL) || 
            !CHECK_DATA_BOUND(data, 0, data_bound) ) break;

    /* Decode the tag and advance the data_ptr */
    /* lk_scasn1_decode tag does its own checking */
    _errno = lk_secasn1_decode_tag( &data, data_bound, &tag_id );
    if (_errno != E_ASN1_SUCCESS ) break;

    /* Verify the tag is for a sequence object */
    if ( tag_id != SECASN1_SEQUENCE_TYPE )
    {
      _errno =  E_ASN1_INVALID_TAG;
      break;
    }

    /* Decode the length of the field and advance the data_ptr */
    /* lk_secasn1_decode_length() does its own checking */
    _errno = lk_secasn1_decode_length( &data, data_bound, &ret_ptr->len );
    if (_errno != E_ASN1_SUCCESS ) break;

    /* check that length is within our limits */
    if (ret_ptr->len > SECASN1_MAX_LEN) {
      _errno = E_ASN1_INVALID_DATA;
      break;
    }

    /* Set the data and data_bound fields in the output structure.  */
    ret_ptr->data = data;
    ret_ptr->data_bound = data_bound;

    /* Final check for consistency */
    if (!CHECK_ASN1_INVARIANTS(*ret_ptr)) {
      _errno = E_ASN1_INVALID_DATA;
      break;
    }

  }/*lint -e(717) */ while (FALSE);
  return _errno;
} /* lk_secasn1_start */

/*===========================================================================

FUNCTION SECASN1_END

DESCRIPTION
  closes and verifies an ASN.1 DER encoding, by checking that no data
  has been left unprocessed at the end of the stream

DEPENDENCIES
  None

PARAMETERS
  data_ptr - pointer to the end of the data holder

RETURN VALUE
  E_ASN1_SUCCESS - if the document has been closed successfully
  E_ASN1_INVALID_ARG - if the pointer argument has a NULL value
  E_ASN1_INVALID_DATA - all the data was not processed

SIDE EFFECTS
  None
===========================================================================*/
secasn1_err_type lk_secasn1_end
(
  const secasn1_data_type *data_ptr
)
{
  secasn1_err_type _errno = E_ASN1_SUCCESS;
  /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
  do
  {
    if ( data_ptr == NULL )
    {
      _errno = E_ASN1_INVALID_ARG;
      break;
    }
    /* Check that we have consumed all the data. */
       if ( data_ptr->len != 0 )
       {
         _errno = E_ASN1_INVALID_DATA;
         break;
       }

    /* check that data has not passed data_bound */
    BREAKIF_SETERR(!CHECK_DATA_BOUND(data_ptr->data, 0, data_ptr->data_bound),
       _errno)

  }/*lint -e(717) */ while (FALSE);

  return _errno;
} /* lk_secasn1_end */

secasn1_err_type lk_secasn1_next_field
(
  secasn1_data_type *data_ptr,
  secasn1_data_type *ret_ptr,
  uint32             verify_tag_id
)
{
  uint32 tag_id;                                 /* Tag Id of current tag  */
  secasn1_data_type init_data;                   /* original data */
/*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

  secasn1_err_type _errno = E_ASN1_SUCCESS;
  /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -*/

  do
  {
    /* Make sure ret_ptr and data is okay*/
    if ( ret_ptr == NULL ||
         data_ptr == NULL  || 
         !CHECK_ASN1_INVARIANTS(*data_ptr))
    {
      _errno = E_ASN1_INVALID_ARG;
      break;
    }

    /* save orginal data */
    init_data = *data_ptr;

    /* Check to see if there is no data left */
    if ( data_ptr->len == 0 )
    {
      _errno = E_ASN1_NO_DATA;
      break;
    }

    /* Decode the tag and advance the data_ptr, checking that the data
     pointer is not advancing out of the outer field. (Checking is
     done in lk_secasn1_decode_tag.) */
    _errno = lk_secasn1_decode_tag( &data_ptr->data, data_ptr->data_bound, 
                                     &tag_id );
    if ( _errno != E_ASN1_SUCCESS )
    {
      // restore original content
      *data_ptr = init_data;
      break;
    }
    /* Check if the tag_id needs to be verified */
    if ( verify_tag_id != SECASN1_NO_TYPE_CHECK &&
         verify_tag_id != tag_id )
    {
      *data_ptr = init_data;
      _errno = E_ASN1_INVALID_TAG;
      break;
    }

    /* Decode the length of the field and advance the data_ptr.  Fails
     if length > SECASN1_MAX_LEN */
    _errno = lk_secasn1_decode_length( &data_ptr->data, data_ptr->data_bound,
                                        &ret_ptr->len );
    if ( _errno != E_ASN1_SUCCESS )
    {
      *data_ptr = init_data;
      break;
    }


    /* Copy data field from data_ptr struct */
    ret_ptr->data = data_ptr->data;

    /* check that we can advance data_ptr->data by ret_ptr->len */
    if (!CHECK_DATA_BOUND(data_ptr->data, ret_ptr->len, 
      data_ptr->data_bound))
    {
      _errno = E_ASN1_INVALID_DATA;
      break;        
    }
    data_ptr->data += ret_ptr->len;

    /* Decrease the outer length by the amount that the data field has 
       advanced. */
    data_ptr->len -= (data_ptr->data - init_data.data);
    /* Check for underflow in CHECK_ASN_INVARANTS below */
    /* Set up data_bound for ret_ptr */
    /* This pulls data_bound for the inner object to just off the end
       of the inner object.  The add cannot overflow because the
       check a few lines up ensures that the value of data_ptr->data at
       that point could have ret_ptr->len added to it safely.  And
       ret_ptr->data is the same as data_ptr->data was at the time.
    */
    ret_ptr->data_bound = MIN(init_data.data_bound, 
                               ret_ptr->data + ret_ptr->len);

    /* Final checks. */
    if (!CHECK_ASN1_INVARIANTS(*data_ptr) || 
        !CHECK_ASN1_INVARIANTS(*ret_ptr)) {
       _errno = E_ASN1_INVALID_DATA;
       break;
    }
  }/*lint -e(717) */ while (FALSE);
  return _errno;
} /* lk_secasn1_next_field */

/*===========================================================================

FUNCTION SECASN1_DECODE_BIT_STRING

DESCRIPTION
  This function takes a data pointer and decodes it to a bit_string pointer
  In the ASN.1 DER encoding, the first byte of a bit string indicates, how
  many unused bits are at the end of the string.  Assumes that the bit_ptr
  has been pre-allocated.

DEPENDENCIES
  None

PARAMETERS
  data_ptr - pointer to the bit string field
  bit_ptr  - where the decoded bit string will be returned


RETURN VALUE
  If successful, E_ASN1_SUCCESS will be returned and bit_ptr will be updated
  to contain the bit string.  If an error occurs during the conversion
  the appropriate error will be returned.

SIDE EFFECTS
  None.  The data_ptr->data and data_ptr->len values are not updated.
===========================================================================*/
secasn1_err_type lk_secasn1_decode_bit_string
(
  const secasn1_data_type *data_ptr,
  secasn1_bit_string_type *bit_ptr
)
{
  uint8 unused_bits;         /* Number of unused bits   */
  secasn1_err_type _errno = E_ASN1_SUCCESS;
  /*- - -- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -*/

  do
  {
    /* Check that each of the parameters have been pre-allocated */
    if ( data_ptr == NULL ||
         bit_ptr == NULL)
    {
      _errno = E_ASN1_INVALID_ARG;
      break;
    }

    /* Check that the data field contains at least 1 byte (for the unused) */
    if ( data_ptr->len == 0 || data_ptr->data == NULL)
    {
      _errno = E_ASN1_INVALID_DATA;
      break;
    }

    // check all the memory space of data_ptr->len is accessable in this function
    BREAKIF_SETERR((!CHECK_DATA_BOUND(data_ptr->data, data_ptr->len, data_ptr->data_bound)), _errno);
    unused_bits = BLOAD8(data_ptr->data);
    if ( ( unused_bits > 7 ) || ( ( data_ptr->len == 1 ) && unused_bits > 0) )
    {
      /* At most there can only be 7 unused bits in a byte and no unused bits in a 0 len string */
      _errno = E_ASN1_INVALID_DATA;
      break;
    }

    /* Valid Bit String */
    /* Already checked that we can add data_ptr->len to data_ptr->data, and 
       data->pointer->len >= 1, so the add is is safe and the subtract is 
       safe. */
    bit_ptr->unused = unused_bits;
    bit_ptr->data = data_ptr->data + 1;
    bit_ptr->len = data_ptr->len - 1;

  }/*lint -e(717) */ while (FALSE);
  return (_errno);
} /* lk_secasn1_decode_bit_string */

/*===========================================================================

FUNCTION SECASN1_DECODE_BOOLEAN

DESCRIPTION
  This function takes a data pointer and decodes it to a boolean pointer
  In the ASN.1 DER encoding, the boolean data should only be a single byte,
  with 0x00 meaning FALSE and anything else being true

DEPENDENCIES
  None

PARAMETERS
  data_ptr - pointer to the boolean field
  b_ptr - pointer where the boolean value will be returned

RETURN VALUE
  If successful, E_ASN1_SUCCESS will be returned and the boolean pointer will
  will be set.  If the data_ptr contains more than a single byte
  E_ASN1_INVALID_DATA will be returned

SIDE EFFECTS
  None
===========================================================================*/
secasn1_err_type lk_secasn1_decode_boolean
(
  const secasn1_data_type *data_ptr,
  boolean *b_val
)
{
  secasn1_err_type _errno = E_ASN1_SUCCESS;
  /*- - -- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -*/

  do
  {
    /* Check that each of the parameters have been pre-allocated */
    if ( data_ptr == NULL ||
         b_val == NULL )
    {
      _errno = E_ASN1_INVALID_ARG;
      break;
    }

    /* Check that the data field contains only one byte and is non-null */
    if ( data_ptr->len != 1 || data_ptr->data == NULL)
    {
      _errno = E_ASN1_INVALID_DATA;
      break;
    }

    /* Check that it is safe to read one byte */
    BREAKIF_SETERR(!CHECK_DATA_BOUND(data_ptr->data, 1, data_ptr->data_bound),
       _errno);
    
    /* Valid boolean encoding */
    if ( BLOAD8(data_ptr->data) == 0 )
    {
      *b_val = FALSE;
    }
    else
    {
      *b_val = TRUE;
    }
  }/*lint -e(717) */ while (FALSE);
  return _errno;
} /* lk_secasn1_decode_boolean */

/*===========================================================================

FUNCTION SECX509_PARSE_BASIC_CONSTRAINT

DESCRIPTION
  Parses a basic constraint extension, the basic contraint holds two pieces
  of key information:
  1) Whether the certificate is a CA certificate (End Entity)
  2) if it is a CA certificate then path length is the maximum number of
     CA certificates that may follow

  The default value for CA is FALSE meaning that the path length does not
  matter and it is set to -1

DEPENDENCIES
  None

PARAMETERS
  data_ptr - current data holder position
  ext_ptr  - where the returned information will be held

RETURN VALUE
  E_X509_SUCCESS - if the basic constraint is parsed correctly
  E_INVALID_DATA - otherwise

SIDE EFFECTS
  None
===========================================================================*/
secx509_errno_enum_type lk_secx509_parse_basic_constraint
(
  secasn1_data_type *data_ptr,
  lk_secx509_ext_type *ext_ptr
)
{
  secasn1_data_type   seq;                        /* sequence holder       */
  secasn1_data_type   data;                       /* data holder           */
  boolean             ca;                         /* whether it is a CA    */
  secasn1_err_type    err;                        /* ASN.1 error code      */
  secx509_errno_enum_type ret_status = E_X509_SUCCESS; /* Return Status         */
  /*-----------------------------------------------------------------------*/

  /* Sanity Check on pointer arguments */
  if ( (data_ptr == NULL) || (ext_ptr == NULL) )
  {
    return E_X509_INVALID_ARG;
  }

  do
  {
    SECX509_OPEN_SEQUENCE( data_ptr, &seq );

    /* Check that the sequence is not empty */
    if ( seq.len == 0 )
    {
      ext_ptr->ca.set = TRUE;
      ext_ptr->ca.val = FALSE;
      ext_ptr->path_len = -1;
    }
    else
    {

      err = lk_secasn1_next_field( &seq, &data, SECASN1_BOOLEAN_TYPE );

      if ( err == E_ASN1_SUCCESS )
      {
        if ( lk_secasn1_decode_boolean( &data, &ca ) != E_ASN1_SUCCESS )
        {
          ret_status = E_X509_DATA_INVALID;
          break;
        }
      }
      else if ( err == E_ASN1_INVALID_TAG )
      {
        ca = FALSE;
      }
      else
      {
        ret_status = E_X509_DATA_INVALID;
        break;
      }

      /* Set the CA value */
      ext_ptr->ca.set = TRUE;
      ext_ptr->ca.val = ca;

      err = lk_secasn1_next_field( &seq, &data, SECASN1_INTEGER_TYPE );

      if ( err == E_ASN1_SUCCESS )
      {
        // BLOAD for only one byte.
        if (data.len != 1)
        {
          ret_status = E_X509_DATA_INVALID;
          break;
        }
        else
        {
          ext_ptr->path_len = BLOAD8(data.data);
        }
      }
      else if (( err == E_ASN1_INVALID_TAG) || (err == E_ASN1_NO_DATA ))
      {
        ext_ptr->path_len = -1;
      }
      else
      {
        ret_status = E_X509_DATA_INVALID;
        break;
      }
    }

    SECX509_CLOSE_SEQUENCE( data_ptr, &seq );

  }/*lint -e(717) */ while ( FALSE );

  /* return E_X509_SUCCESS; ?? must return correct return status !! - SID */
  return ret_status;

} /* lk_secx509_parse_basic_constraint */

/*===========================================================================

FUNCTION SECX509_PARSE_KEY_USAGE

DESCRIPTION
  Parses a key usage extension.

DEPENDENCIES
  None

PARAMETERS
  data_ptr - current data holder position
  val      - where the key usage bits are returned

RETURN VALUE
  E_X509_SUCCESS - if the key usage is parsed correctly
  E_INVALID_DATA - otherwise

SIDE EFFECTS
  None
===========================================================================*/
secx509_errno_enum_type lk_secx509_parse_key_usage
(
  secasn1_data_type *data_ptr,
  uint32 *val
)
{
  secasn1_data_type dat;                          /* data holder           */
  secasn1_bit_string_type bt;                     /* bit string holder     */
  secx509_errno_enum_type ret_status = E_X509_SUCCESS; /* Return Status         */
  /*-----------------------------------------------------------------------*/

  /* Sanity Check on pointer arguments */
  if ( (data_ptr == NULL) || (val == NULL) )
  {
    return E_X509_INVALID_ARG;
  }

  do
  {
    SECX509_NEXT_FIELD( data_ptr, &dat, SECASN1_BIT_STRING_TYPE );

    if ( lk_secasn1_decode_bit_string( &dat, &bt ) != E_ASN1_SUCCESS )
    {
      ret_status = E_X509_DATA_INVALID;
      break;
    }

    /* Looking at the spec from rfc2459 and examples this is what */
    /* I think is occuring. If there are 2 bytes in the bit string*/
    /* then there should be 7 unused bits, but if there is only   */
    /* one byte, the unused bits can be ignored with the 0 bit    */
    /* being the first bit */

    /* can we read the first byte? */
    if (bt.len < 1) {
      ret_status = E_X509_DATA_INVALID;
      break;
    }
    *val = BLOAD8(bt.data) << 1;
    if ( bt.len == 2 )
    {
      bt.data++;
      if ( BLOAD8(bt.data) & 0x80L )
      {
        *val |= 0x01L;
      }
    }

  }/*lint -e(717) */ while ( FALSE );

  /* return E_X509_SUCCESS; must return correct status ! - SID*/
  return ret_status;

} /* lk_secx509_parse_key_usage */

/*===========================================================================

FUNCTION SECX509_PARSE_EX_KEY_USAGE

DESCRIPTION
  Parses an extended key usage extension.  This is a sequence of OIDs that
  give specific key usages, but this function and RFC 2459 only looks for the
  following extended key usages:

    TLS Web Server authentication, TLS Web Client Authentication, Downloadable
    Code Signing, Email Protection, Time Stamping and Secured Gated Crypto.

DEPENDENCIES
  None

PARAMETERS
  data_ptr - current data holder position
  val      - where the returned extended key information will be held

RETURN VALUE
  E_X509_SUCCESS - if the version is extended key extension is parsed correctly
  E_INVALID_DATA - otherwise

SIDE EFFECTS
  None
===========================================================================*/
secx509_errno_enum_type lk_secx509_parse_ex_key_usage
(
  secasn1_data_type *data_ptr,
  uint32 *val
)
{
  secasn1_data_type seq;                          /* sequence holder       */
  secasn1_data_type oid;                          /* object Id holder      */
  secx509_errno_enum_type ret_status = E_X509_SUCCESS; /* Return Status         */
  /*-----------------------------------------------------------------------*/

  /* Sanity Check on pointer arguments */
  if ( (data_ptr == NULL) || (val == NULL) )
  {
    return E_X509_INVALID_ARG;
  }

  do
  {
    SECX509_OPEN_SEQUENCE( data_ptr, &seq );

    *val = 0;

    while ( seq.len > 0 )
    {
      SECX509_NEXT_FIELD( &seq, &oid, SECASN1_OID_TYPE );


      if ( (sizeof(lk_secx509_ex_key_sauth) == oid.len) &&
            (!memcmp( lk_secx509_ex_key_sauth,
                          oid.data,
                          oid.len ) ) )
      {
        /* Server Authentication */
        *val |= SECX509_EX_KEY_USAGE_SAUTH;
      }
      else if ( (sizeof(lk_secx509_ex_key_cauth) == oid.len) &&
                (!memcmp( lk_secx509_ex_key_cauth,
                               oid.data,
                               oid.len ) ) )
      {
        /* Client Authentication */
        *val |= SECX509_EX_KEY_USAGE_CAUTH;
      }
      else if ( (sizeof(lk_secx509_ex_key_code) == oid.len) &&
                (!memcmp( lk_secx509_ex_key_code,
                               oid.data,
                               oid.len ) ) )
      {
        /* Downloadable Code Signing */
        *val |= SECX509_EX_KEY_USAGE_CODE;
      }
      else if ( (sizeof(lk_secx509_ex_key_email) == oid.len) &&
                (!memcmp( lk_secx509_ex_key_email,
                               oid.data,
                               oid.len ) ) )
      {
        /* Email Proctection */
        *val |= SECX509_EX_KEY_USAGE_EMAIL;
      }
      else if ( (sizeof(lk_secx509_ex_key_time) == oid.len) &&
                (!memcmp( lk_secx509_ex_key_time,
                               oid.data,
                               oid.len ) ) )
      {
        /* Time Stamping */
        *val |= SECX509_EX_KEY_USAGE_TIME;
      }
      else if ( (sizeof(lk_secx509_ex_key_ns_sgc) == oid.len) &&
                (!memcmp( lk_secx509_ex_key_ns_sgc,
                               oid.data,
                               oid.len ) ) )
      {
        /* Secured Gated Crypto */
        *val |= SECX509_EX_KEY_USAGE_SGC;
      }
      else if ( (sizeof(lk_secx509_ex_key_ms_sgc) == oid.len) &&
                (!memcmp( lk_secx509_ex_key_ms_sgc,
                               oid.data,
                               oid.len ) ) )
      {
        /* Secured Gated Crypto */
        *val |= SECX509_EX_KEY_USAGE_SGC;
      }
    }

    if ( ret_status != E_X509_SUCCESS )
    {
      break;
    }

    SECX509_CLOSE_SEQUENCE( data_ptr, &seq );

  }/*lint -e(717) */ while ( FALSE );

  return ret_status;

} /* lk_secx509_parse_ex_key_usage */

/*===========================================================================

FUNCTION SECX509_PARSE_VERSION

DESCRIPTION
  Parse the version of the certificate.  Valid version values are
  0, 1, 2 mapping to version 1, 2, 3.  If the version is not specified
  the default value is version 1.

DEPENDENCIES
  None

PARAMETERS
  data_ptr - current data holder position
  ver_ptr  - where the returned version information will be held

RETURN VALUE
  E_X509_SUCCESS - if the version is parsed correctly
  E_INVALID_DATA - otherwise

SIDE EFFECTS
  None
===========================================================================*/
secx509_errno_enum_type lk_secx509_parse_version
(
  secasn1_data_type *data_ptr,
  lk_secx509_version_type *ver_ptr
)
{
  secasn1_data_type d1;                           /* Temporary Data Holder */
  secasn1_err_type err;                           /* ASN.1 error type      */
  secx509_errno_enum_type ret_status = E_X509_SUCCESS; /* Return Status         */
  /*-----------------------------------------------------------------------*/

  SECBOOT_PRINT( "X509: Parsing Version ...");

  /* Sanity Check on pointer arguments */
  if ( (data_ptr == NULL) || (ver_ptr == NULL) )
  {
    return E_X509_INVALID_ARG;
  }

  /* Enter a new scope for macro use */
  do
  {
    err = lk_secasn1_next_field( data_ptr, &d1, SECX509_VERSION_TAG );
    if ( err == E_ASN1_SUCCESS )
    {
      /* Found Version Number */
      SECX509_NEXT_FIELD( &d1, &ver_ptr->val, SECASN1_INTEGER_TYPE );
      /* post condition of lk_secasn1_next_field() is that the return value
         is readable out through its length */

      /* Check to see that the version is only 1 byte long */
      if ( ver_ptr->val.len == 1 )
      {
        ver_ptr->ver = BLOAD8(ver_ptr->val.data);
      }
      else
      {
        ret_status = E_X509_DATA_INVALID;
        break;
      }
    }
    else 
    {
      /* Version not specified */
      ver_ptr->ver = 0;
      ret_status = E_X509_DATA_INVALID;
    }

    if ( ver_ptr->ver > 2 )
    {
      /* An invalid version number */
      ret_status = E_X509_DATA_INVALID;
      break;
    }

  }/*lint -e(717) */ while ( FALSE );

  return ret_status;
} /* lk_secx509_parse_version */

/*==============================================================
  FUNCTION PBL_CLK_JULIAN_TO_SECS
  
  ARGS
    A clk_julian_type structure.

  RETURNS
    In integer, the time in secs since Jan 6 1980, the CDMA epoc
    or 0, to indicate in invalid value.  (This means that the very
    first second in the CDMA epoc is invalid.)

  DEPENDENCIES
    None.  A completely self-contained function that depends
    only on its argument.

===============================================================*/
uint32 lk_clk_julian_to_secs(const clk_julian_type *jts) 
{
   uint32       result;
   uint32       isLeapYear = 0;
   int          yearsGoneBy, daysGoneBy;
    
   /*   Four gigaseconds --> 126.75 years; so it will cover the 120 years */
   /*   that we are attempting to validate here */

   /*  Basic Sanity checks - more specific ones to follow */
   /*   We only allow years in the range 1980.. 2099 */
   /*   Note: All fields are unsigned */
   if (   (jts == NULL) || (jts->year   < 1980) || (jts->year   > 2099)
          || (jts->month  <    1) || (jts->month  >   12) 
          || (jts->day    <    1) || (jts->day    >   31) 
          || (jts->hour   >   23) || (jts->minute >   59)
          || (jts->second >   59))
      return 0;

   /*   if "valid" but before the start of the CDMA epoch, return 0 */
   if ((jts->year == 1980) && (jts->month==1) && (jts->day<6))
    return 0;

   /*   Thirty days hath September, April, June and November */
   if ((jts->day > 30) &&
       ((jts->month == 4) || (jts->month == 6) || 
        (jts->month == 9) || (jts->month == 11 )))
    return 0;

   /*   Check for too many days in February - */
   /*   Note that we handle only 1980 -- 2099, so we can use a simple check. */
   isLeapYear = jts->year % 4 == 0 ? 1 : 0;
   if ((jts->month == 2) && (jts->day > ( 28 + isLeapYear )))
      return 0;
                
   /*   Ok, now we know that we have a valid date */
   /*   So we start by calculating the number of days */
   /*   since "the dawn of time" to the start of this year */
   /*   Add in "leap days", one for each four years + 1 for 1980 */
   yearsGoneBy = jts->year - 1980;
   daysGoneBy  = yearsGoneBy * 365 + (( yearsGoneBy + 3 ) / 4 );

   /*   Add in the days to the start of the correct month */    
   switch (jts->month) {
    case  1: /* do nothing */                 break;
    case  2: daysGoneBy +=  31;               break;
    case  3: daysGoneBy +=  59;               break;
    case  4: daysGoneBy +=  90;               break;
    case  5: daysGoneBy += 120;               break;
    case  6: daysGoneBy += 151;               break;
    case  7: daysGoneBy += 181;               break;
    case  8: daysGoneBy += 212;               break;
    case  9: daysGoneBy += 243;               break;
    case 10: daysGoneBy += 273;               break;
    case 11: daysGoneBy += 304;               break;
    case 12: daysGoneBy += 334;               break;
    default:                                  return 0; /* can't happen */
  }

   /*   If we're a leap year, we have an extra day in February. */
   /*   Add it in - but only if the month comes after February. */
   if ( isLeapYear && jts->month > 2 )
      daysGoneBy += 1;

   /*   Add in the days of the month; remember that days start with one */
   daysGoneBy += jts->day - 1;
                
   /*   However, the epoch did not start on Jan 1, 1980, but on Jan 6th */
   daysGoneBy -= 5;

   /*   Convert days --> hours */
   result = daysGoneBy * 24 + jts->hour;
        
   /*   Convert hours --> minutes */
   result = result * 60 + jts->minute;
        
   /*   Convert minutes --> seconds */
   return result * 60 + jts->second;
}


/*===========================================================================

FUNCTION SECASN1_DECODE_TIME

DESCRIPTION
  This function takes a data pointer representing time and decodes it to
  the number of seconds since CDMA epoch time of Jan 6th, 1980.  If the time
  occurs before this date, the time is adjusted to 0.

DEPENDENCIES
  None

PARAMETERS
  data_ptr - pointer to the time data field
  time     - pointer where the time in seconds is returned
  utc_time - whether the time is in UTC time format

RETURN VALUE
  If successful, E_ASN1_SUCCESS will be returned and the time pointer will
  will be set.  E_ASN1_INVALID_DATA is returned if an invalid format is
  encountered.

SIDE EFFECTS
  None
===========================================================================*/
secasn1_err_type lk_secasn1_decode_time
(
  const secasn1_data_type *data_ptr,
  uint32  *time,
  boolean utc_time
)
{
  const uint8 *str;                         /* pointer to the time string */
  int i;                                    /* counter variable */
  clk_julian_type jts;                      /* julian clock variable */
  secasn1_err_type _errno = E_ASN1_SUCCESS;
  /*- - -- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -*/

  do
  {
    /* Check that each of the parameters have been pre-allocated */
    if ( data_ptr == NULL ||
         time == NULL )
    {
      _errno = E_ASN1_INVALID_ARG;
      break;
    }

    // Check that we can read the entire structure
    BREAKIF_SETERR((!CHECK_DATA_BOUND(data_ptr->data, data_ptr->len, data_ptr->data_bound)),
                   _errno);

    i = data_ptr->len;
    str = data_ptr->data;

    /* Verify the length of the data and calculate the 4-digit year */
    if ( utc_time )
    {
      //YYMMDDHHMMSSZ
      if ( (i != 13) ) return E_ASN1_INVALID_DATA;

      jts.year = (BLOAD8(str)-0x30L)*10;
      str++;

      jts.year +=  (BLOAD8(str)-0x30L);
      str++;

      /* Adjust the year as specified in RFC 2459 */
      /* if year >= 50 ==> 19YY else ==> 20YY     */
      if ( jts.year >= 50 )
      {
        jts.year += 1900;
      }
      else
      {
        jts.year += 2000;
      }
    }
    else
    {
      //YYYYMMDDHHMMSSZ
      if ( i != 15 )
      {
        _errno = E_ASN1_INVALID_DATA;
        break;
      }
      //jts.year = (BLOAD8(str++)-0x30L) * 1000 + (BLOAD8(str++)-0x30L) *
      //         100 + (BLOAD8(str++)-0x30L) * 10 + (BLOAD8(str++)-0x30L);


      jts.year = (BLOAD8(str)-0x30L) * 1000;
      str++;

      jts.year = jts.year + (BLOAD8(str)-0x30L) * 100;
      str++;

      jts.year = jts.year + (BLOAD8(str)-0x30L) * 10;
      str++;

      jts.year = jts.year + (BLOAD8(str)-0x30L);
      str++;

    }

    /* Calculate the month */
    // jts.month = (BLOAD8(str++)-0x30L) * 10 + (BLOAD8(str++)-0x30L);
    jts.month = (BLOAD8(str)-0x30L) * 10;
    str++;

    jts.month = jts.month + (BLOAD8(str)-0x30L);
    str++;

    /* Calculate the day */
    //jts.day = (BLOAD8(str++)-0x30L) * 10 + (BLOAD8(str++)-0x30L);
    jts.day = (BLOAD8(str)-0x30L) * 10;
    str++;

    jts.day = jts.day + (BLOAD8(str)-0x30L);
    str++;

    /* Calculate the hour */
    //jts.hour = (BLOAD8(str++)-0x30L) * 10 + (BLOAD8(str++)-0x30L);

    jts.hour = (BLOAD8(str)-0x30L) * 10;
    str++;

    jts.hour = jts.hour + (BLOAD8(str)-0x30L);
    str++;

    /* Calculate the minute */
    //jts.minute = (BLOAD8(str++)-0x30L) * 10 + (BLOAD8(str++)-0x30L);

    jts.minute = (BLOAD8(str)-0x30L) * 10;
    str++;
    jts.minute = jts.minute + (BLOAD8(str)-0x30L);
    str++;

    /* Calculate the second */
    jts.second = (BLOAD8(str)-0x30L) * 10;
    str++;

    jts.second +=  (BLOAD8(str)-0x30L);
    str++;

    /* Calculate the time offset */
    if ( BLOAD8(str) != 'Z' )
    {
      _errno = E_ASN1_INVALID_DATA;
      break;
    }

    *time = lk_clk_julian_to_secs(&jts);

  }/*lint -e(717) */ while (FALSE);

  return _errno;
} /* lk_secasn1_decode_time */


/*===========================================================================

FUNCTION SECX509_PARSE_VALIDITY

DESCRIPTION
  Parses the validity, which is made up of two fields, not_before and
  not_after time.  The time value is stored as an integer corresponding
  to the number of seconds from 01/06/1980 and the time will also be
  stored in the printable version found within the certificate.

  The validity information is stored in cert->not_before and
  cert->not_after.

DEPENDENCIES
  None

PARAMETERS
  data_ptr - current data holder position
  cert     - where the validity information will be stored

RETURN VALUE
  E_X509_SUCCESS - if the validity is parsed correctly
  E_INVALID_DATA - otherwise

SIDE EFFECTS
  None
===========================================================================*/
secx509_errno_enum_type lk_secx509_parse_validity
(
  secasn1_data_type *data_ptr,
  lk_secx509_cert_info_type *cert
)
{
  secasn1_data_type seq;                          /* temporary seq holder  */
  secasn1_err_type err;                           /* ASN.1 error type      */
  secx509_errno_enum_type ret_status = E_X509_SUCCESS; /* Return Status         */
  /*-----------------------------------------------------------------------*/
  SECBOOT_PRINT( "X509: Parsing Validity ...");

  /* Sanity Check on pointer arguments */
  if ( (data_ptr == NULL) || (cert == NULL) )
  {
    return E_X509_INVALID_ARG;
  }

  do
  {
    SECX509_OPEN_SEQUENCE( data_ptr, &seq );

    /* Parse the not before time */
    err = lk_secasn1_next_field( &seq, &cert->not_before.data,
                                  SECASN1_UTC_TYPE );
    if ( err == E_ASN1_SUCCESS )
    {
      /* UTC Time format */
      /* lk_secasn1_decode_time checks data_bound */
      if ( lk_secasn1_decode_time( &cert->not_before.data,
                                &cert->not_before.time, TRUE )
           != E_ASN1_SUCCESS )
      {
        ret_status = E_X509_DATA_INVALID;
        break;
      }
    }
    else if ( err == E_ASN1_INVALID_TAG )
    {
      /* General Time format */
      SECX509_NEXT_FIELD( &seq, &cert->not_before.data,
                          SECASN1_NO_TYPE_CHECK );

      if ( lk_secasn1_decode_time( &cert->not_before.data,
                                &cert->not_before.time, FALSE )
           != E_ASN1_SUCCESS )
      {
        ret_status = E_X509_DATA_INVALID;
        break;
      }

    }
    else
    {
      ret_status = E_X509_DATA_INVALID;
      break;
    }

    /* Parse the not after time */
    err = lk_secasn1_next_field( &seq, &cert->not_after.data,
                                  SECASN1_UTC_TYPE );
    if ( err == E_ASN1_SUCCESS )
    {
      /* UTC Time format */
      if ( lk_secasn1_decode_time( &cert->not_after.data,
                                &cert->not_after.time, TRUE ) !=
           E_ASN1_SUCCESS )
      {
        ret_status = E_X509_DATA_INVALID;
        break;
      }
    }
    else if ( err == E_ASN1_INVALID_TAG )
    {
      /* General Time format */
      SECX509_NEXT_FIELD( &seq, &cert->not_after.data, SECASN1_NO_TYPE_CHECK );

      if ( lk_secasn1_decode_time( &cert->not_after.data,
                                &cert->not_after.time, FALSE )
           != E_ASN1_SUCCESS )
      {
        ret_status = E_X509_DATA_INVALID;
        break;
      }
    }
    else
    {
      ret_status = E_X509_DATA_INVALID;
      break;
    }

    SECX509_CLOSE_SEQUENCE( data_ptr, &seq );

  }/*lint -e(717) */ while ( FALSE );

  return ret_status;
} /* lk_secx509_parse_validity */

/*===========================================================================
FUNCTION lk_secx509_parse_ou_field

DESCRIPTION
  Parse OU field data and return the value as integer for the ou field.

DEPENDENCIES
  None

PARAMETERS
  *data_ptr           - Pointer to the searched data
  *ou_field_value     - Pointer to the returned ou field value
  ou_field_value_len  - Length of the ou field value (in bytes)
  *ou_field_string    - Pointer to the queried ou field string
  ou_field_string_len - Length of the queried ou field string (in bytes)

RETURN VALUE
  E_SUCCESS         - if no error
  x509 error number   - x509 error secx509_errno_enum_type

SIDE EFFECTS
  None
===========================================================================*/
static secx509_errno_enum_type lk_secx509_parse_ou_field
(
  secasn1_data_type           *data_ptr,
  uint64                      *ou_field_value,
  uint32                      ou_field_value_len,
  const uint8                 *ou_field_string,
  uint32                      ou_field_string_len
)
{
  uint64 ou_value = 0;
  uint8  mask_byte[SECX509_OU_FIELD_VALUE_MAX_BYTES];
  uint8  *mask_ptr = mask_byte;
  uint32 lshift = 0;
  uint32 j;
  const uint8  *ou_value_data_ptr;
  const uint8  *ou_string_data_ptr;

  if ((NULL == data_ptr) || (NULL == ou_field_value) || (NULL == ou_field_string))
  {
    return E_X509_INVALID_ARG;
  }

  if (ou_field_value_len > SECX509_OU_FIELD_VALUE_MAX_BYTES)
  {
    return E_X509_DATA_TOO_LARGE;
  }

  /* ==========================================================  */
  /* OU field format: <index> <OU FIELD VAlUE> <OU FIELD STRING> */
  /* <index> has alway 2 chars followed by space.                */
  /* <OU FIELD VAlUE> has as many as 16 chars followed by space. */
  /* <OU FIELD STRING> has char num that varies on definitions.  */
  /* ==========================================================  */

  /* the len of searched data should match the input argument. If not, the ou field */
  /* is not what is being asked for in the query.                                   */                                              
  if ((0 == ou_field_value_len) || 
      (data_ptr->len != SECX509_OU_FIELD_INDEX_LEN + SECX509_OU_FIELD_SPACE_LEN + ou_field_value_len
                         + SECX509_OU_FIELD_SPACE_LEN + ou_field_string_len))
  {
    return E_X509_OU_FIELD_NOT_FOUND;
  }

  if (CHECK_DATA_BOUND(data_ptr->data, (SECX509_OU_FIELD_INDEX_LEN + SECX509_OU_FIELD_SPACE_LEN),
                       data_ptr->data_bound) == FALSE)
  {
    return E_X509_BAD_DATA;
  }
  ou_value_data_ptr = data_ptr->data + SECX509_OU_FIELD_INDEX_LEN + SECX509_OU_FIELD_SPACE_LEN;

  if (CHECK_DATA_BOUND(ou_value_data_ptr, (ou_field_value_len + SECX509_OU_FIELD_SPACE_LEN),
                       data_ptr->data_bound) == FALSE)
  {
    return E_X509_BAD_DATA;
  }
  ou_string_data_ptr = ou_value_data_ptr + ou_field_value_len + SECX509_OU_FIELD_SPACE_LEN;

  if (CHECK_DATA_BOUND(ou_string_data_ptr, ou_field_string_len, data_ptr->data_bound) == FALSE)
  {
    return E_X509_BAD_DATA;
  }

  if (memcmp(ou_string_data_ptr, ou_field_string, ou_field_string_len) == 0)
  {
    /* calcaulate bit number to shift for converting char in cert to int. */
    /* (ou_field_value_len - 1) for skipping the first char byte.         */
    lshift = (ou_field_value_len - 1) * SECX509_OU_SHIFT_BIT_NUM_FOR_BYTE_IN_CERT;
    
    for (j = 0; j < ou_field_value_len; j ++)
    {
      /* COPY the value string to local variable. load/store data with byte addressing,  */ 
      /* which could be platform dependent. So keep BSTORE8/BLOAD8, which is defined by  */
      /* image as per platform required. (equal to mask_ptr[j] = ou_value_data_ptr[j])   */
      BSTOR8 (mask_ptr + j , BLOAD8(ou_value_data_ptr + j));
      /* convert the ascii of 0-9 and A-F to binary */              
      convert_to_binary(mask_ptr+j);
  
      /* This shifts each digit in. Each digit represents 4 bits */
      ou_value += ((uint64)BLOAD8(mask_ptr+j)) << lshift;
      /* lshift is the multiple of SECX509_OU_SHIFT_BIT_NUM_FOR_BYTE_IN_CERT. It will be */
      /* 0 in the last iteration, where the below minus oper is not needed to avoid      */
      /* integer underflow. */
      if (lshift != 0)
      {
        lshift -= SECX509_OU_SHIFT_BIT_NUM_FOR_BYTE_IN_CERT;
      }
    }
    
    *ou_field_value = ou_value;

    return E_X509_SUCCESS; 
  }

  return E_X509_OU_FIELD_NOT_FOUND;
}

/*===========================================================================
FUNCTION lk_secx509_check_oid_type

DESCRIPTION
  query oid type with input arguments. It return TRUE in output argument, if
  the searched string data match the input query string.

DEPENDENCIES
  None

PARAMETERS
  *data_ptr           - Pointer to the searched data
  *oid_string         - Pointer to array of the query oid string
  oid_string_len      - Length of the query string
  *found_oid_type     - boolean to determine if the oid string is found

RETURN VALUE
  E_X509_SUCCESS      - if no error
  E_X509_INVALID_ARG  - input argument has NULL pointer

SIDE EFFECTS
  None
===========================================================================*/
static secx509_errno_enum_type lk_secx509_check_oid_type
(
  secasn1_data_type           *data_ptr,
  const uint8                 *oid_type_ptr,
  uint32                      oid_type_len,
  boolean                     *found_oid_type
)
{
  if ((NULL == data_ptr) || (NULL == oid_type_ptr) || (NULL == found_oid_type))
  {
    return E_X509_INVALID_ARG;
  }

  *found_oid_type = FALSE;
  /* Found the queried oid type, if oid type string matches */
  if (memcmp(data_ptr->data, oid_type_ptr, oid_type_len) == 0)
  {
    *found_oid_type = TRUE;
  }

  return E_X509_SUCCESS;
}

/*===========================================================================

FUNCTION SECX509_PARSE_DN

DESCRIPTION
    Parse a distinguished name(DN) field of an X509 certificate.  Since a
    DN name may have many different attributes this function will verify that
    the fields are valid and it will record the number of attributes.

DEPENDENCIES
  None

PARAMETERS
  data_ptr          - current data holder position
  dn                - where the parsed dn field will be stored
  ou_field_info_ptr - pointer to store OU Field values

RETURN VALUE
  E_X509_SUCCESS - if the version is parsed correctly
  E_INVALID_DATA - otherwise

SIDE EFFECTS
  Since this function has been verified the data in the DN, when functions
  lk_secx509_get_name_certificate, lk_secx509_get_concat_name and
  lk_secx509_get_dn_object_string are called they will never be parsing errors
===========================================================================*/
secx509_errno_enum_type lk_secx509_parse_dn
(
  secasn1_data_type           *data_ptr,
  lk_secx509_dn_type         *dn,
  secx509_ou_field_info_type  *ou_field_info_ptr
)
{
  secasn1_data_type seq;                          /* sequence holder       */
  secasn1_data_type set;                          /* set holder            */
  secasn1_data_type att;                          /* attributes holder     */
  secasn1_data_type dat;                          /* data holder           */
  uint32 num_attrib = 0;                          /* num of dn attributes  */
  secx509_errno_enum_type ret_status = E_X509_SUCCESS; /* Return Status         */
  boolean found_ou_field = FALSE;
  uint64 ou_field_value = 0;
  /*-----------------------------------------------------------------------*/
  SECBOOT_PRINT( "X509: Parsing Distinguished Name ...");

  /* Sanity Check on pointer arguments */
  if ( (data_ptr == NULL) || (dn == NULL) )
  {
    return E_X509_INVALID_ARG;
  }

  /* set SECBOOT_DEBUG_DISABLE to default. It will be updated later     */
  /* So missing DEUBG OU field means the debug feature disabled.        */
  /* (This is not a check of missing ou field)                          */
  if (ou_field_info_ptr != NULL)
  {
    ou_field_info_ptr->debug_enable = SECBOOT_DEBUG_DISABLE;
  }

  do
  {
    SECX509_OPEN_SEQUENCE( data_ptr, &seq );

    /* Set the marker to the beginning of the attributes */
    dn->data.data = seq.data;
    dn->data.len = seq.len;

    /* Parse all the attributes */
    while ( seq.len > 0 )
    {

      SECX509_NEXT_FIELD( &seq, &set, SECASN1_SET_TYPE );
      SECX509_OPEN_SEQUENCE( &set, &att );
      num_attrib++;

      /* We check to see if an object Identifier and value exists */
      /* This allows us to be sure that when items are attempted  */
      /* to be pulled from the DN (distinguished name) field, the */
      /* structure will be able to be parsed with no errors.      */
      SECX509_NEXT_FIELD( &att, &dat, SECASN1_OID_TYPE );
  
      /* We check if this OID type is an OU field */
      found_ou_field = FALSE;
      ret_status = lk_secx509_check_oid_type(&dat, 
                                              lk_secx509_asn1_oid_obj_unit, 
                                              sizeof(lk_secx509_asn1_oid_obj_unit),
                                              &found_ou_field);
      if (E_X509_SUCCESS != ret_status)
              {
              break;
            }

      SECX509_NEXT_FIELD( &att, &dat, SECASN1_NO_TYPE_CHECK );

      /* Handle only OU field query */
      if (found_ou_field && (NULL != ou_field_info_ptr))
          {
            /* ========================================================== */
        /* "01 xxxxxxxxxxxxxxxx SW_ID"                                */
        /* Search the ou field string in ascii and extract the value. */
            /* ========================================================== */
        ou_field_value = 0;
        ret_status = lk_secx509_parse_ou_field(&dat, 
                                                &ou_field_value,
                                                OU_SW_ID_VALUE_LEN,
                                                sw_id_string,
                                                OU_SW_ID_STRING_LEN);
  
        SECX509_UPDATE_OU_FIELD_VALUE(ret_status,
                                      ou_field_info_ptr->sw_id, 
                                      ou_field_value);
  
              /* ========================================================== */
        /* "02 xxxxxxxxxxxxxxxx HW_ID"                                */
        /* Search the ou field string in ascii and extract the value. */
              /* ========================================================== */
        ou_field_value = 0;
        ret_status = lk_secx509_parse_ou_field(&dat, 
                                                &ou_field_value,
                                                OU_HW_ID_VALUE_LEN,
                                                hw_id_string,
                                                OU_HW_ID_STRING_LEN);
        
        SECX509_UPDATE_OU_FIELD_VALUE(ret_status,
                                      ou_field_info_ptr->hw_id, 
                                      ou_field_value);

            /* ========================================================== */
        /* "03 xxxxxxxxxxxxxxxx DEBUG"                                */
        /* Search the ou field string in ascii and extract the value. */
            /* ========================================================== */
        ou_field_value = 0;
        ret_status = lk_secx509_parse_ou_field(&dat, 
                                                &ou_field_value,
                                                OU_DEBUG_VALUE_LEN,
                                                debug_string,
                                                OU_DEBUG_STRING_LEN);
  
        SECX509_UPDATE_OU_FIELD_VALUE(ret_status,
                                      ou_field_info_ptr->debug_enable, 
                                      ou_field_value);
  
              /* ========================================================== */
        /* "07 xxxx SHA1/SHA256"                                      */
        /* Search the ou field string in ascii and extract the value. */
              /* ========================================================== */
        ou_field_value = 0;
        ret_status = lk_secx509_parse_ou_field(&dat, 
                                                &ou_field_value,
                                                OU_SHA1_VALUE_LEN,
                                                sha1_codehash_str,
                                                OU_SHA1_STRING_LEN);
        
        SECX509_UPDATE_OU_FIELD_VALUE(ret_status,
                                      ou_field_info_ptr->code_hash_algo, 
                                      E_X509_CODE_HASH_SHA1);

        ou_field_value = 0;
        ret_status = lk_secx509_parse_ou_field(&dat, 
                                                &ou_field_value,
                                                OU_SHA256_VALUE_LEN,
                                                sha256_codehash_str,
                                                OU_SHA256_STRING_LEN);
        
        SECX509_UPDATE_OU_FIELD_VALUE(ret_status,
                                      ou_field_info_ptr->code_hash_algo, 
                                      E_X509_CODE_HASH_SHA256);
  
              /* ========================================================== */
        /* "09 xxxxxxxxxxxxxxxx CRASH_DUMP"                           */
        /* Search the ou field string in ascii and extract the value. */
              /* ========================================================== */
        ou_field_value = 0;
        ret_status = lk_secx509_parse_ou_field(&dat, 
                                                &ou_field_value,
                                                OU_CRASH_DUMP_VALUE_LEN,
                                                crash_dump_string,
                                                OU_CRASH_DUMP_STRING_LEN);
  
        SECX509_UPDATE_OU_FIELD_VALUE(ret_status,
                                      ou_field_info_ptr->crash_dump_enable, 
                                      ou_field_value);
  
          /* ========================================================== */
        /* "10 xxxxxxxxxxxxxxxx ROT_EN"                               */
        /* Search the ou field string in ascii and extract the value. */
          /* ========================================================== */
        ou_field_value = 0;
        ret_status = lk_secx509_parse_ou_field(&dat, 
                                                &ou_field_value,
                                                OU_ROT_VALUE_LEN,
                                                rot_string,
                                                OU_ROT_STRING_LEN);

        SECX509_UPDATE_OU_FIELD_VALUE(ret_status,
                                      ou_field_info_ptr->rot_ou_field, 
                                      ou_field_value);

        /* ========================================================== */
        /* "13 xxxx IN_USE_SOC_HW_VERSION"                            */
        /* Search the ou field string in ascii and extract the value. */
        /* ========================================================== */
        ou_field_value = 0;
        ret_status = lk_secx509_parse_ou_field(&dat, 
                                                &ou_field_value,
                                                OU_IN_USE_SOC_HW_VER_VALUE_LEN,
                                                in_use_soc_hw_version_string,
                                                OU_IN_USE_SOC_HW_VER_STRING_LEN);

        SECX509_UPDATE_OU_FIELD_VALUE(ret_status,
                                      ou_field_info_ptr->in_use_soc_hw_version, 
                                      (uint16)ou_field_value);

        /* ========================================================== */
        /* "14 xxxx USE_SERIAL_NUMBER_IN_SIGNING"                     */
        /* Search the ou field string in ascii and extract the value. */
        /* ========================================================== */
        ou_field_value = 0;
        ret_status = lk_secx509_parse_ou_field(&dat, 
                                                &ou_field_value,
                                                OU_USE_SERIAL_NUM_VALUE_LEN,
                                                use_serial_num_string,
                                                OU_USE_SERIAL_NUM_STRING_LEN);
        
        SECX509_UPDATE_OU_FIELD_VALUE(ret_status,
                                      ou_field_info_ptr->ou_use_serial_num, 
                                      (uint16)ou_field_value);

      }
      
      SECX509_CLOSE_SEQUENCE( &set, &att );
    }

    if ( ret_status != E_X509_SUCCESS )
    {
      break;
    }

    SECX509_CLOSE_SEQUENCE( data_ptr, &seq );

    dn->num_attrib = num_attrib;

  }/*lint -e(717) */ while ( FALSE );

  if ( ret_status != E_X509_SUCCESS )
  {
    /* Clean up the dn structure being returned */
    dn->data.data = NULL;
    dn->data.len = 0;
    dn->num_attrib = 0;
  }

  return ret_status;
} /* lk_secx509_parse_dn */

/*===========================================================================

FUNCTION SECX509_PARSE_PUB_KEY

DESCRIPTION
  Parse the Public Key.  Currently we only support RSA Public Keys.  If the
  public key cannot be determined the returned public key type found in
  ptr->algo will be set to SECX509_PUBKEY_MAX

DEPENDENCIES
  None

PARAMETERS
  data_ptr - current data holder position
  ptr  - where the returned public key information will be held

RETURN VALUE
  E_X509_SUCCESS - if the version is parsed correctly
  E_INVALID_DATA - otherwise

SIDE EFFECTS
  None
===========================================================================*/
secx509_errno_enum_type lk_secx509_parse_pub_key
(
  secasn1_data_type*    data_ptr,
  lk_secx509_pubkey_type*  ptr
)
{
  secasn1_data_type       seq1;                  /* outer sequence holder  */
  secasn1_data_type       seq2;                  /* inner sequence holder  */
  secasn1_data_type       data;                  /* data holder            */
  secasn1_data_type       dmy;                   /* dummy value holder       */
  secasn1_bit_string_type bit_str_hldr;          /* bit string holder      */
  secasn1_data_type       bit_str;               /* decoded bit string     */
  secx509_errno_enum_type      ret_status = E_X509_SUCCESS;/* Return Status     */
  /*-----------------------------------------------------------------------*/
  SECBOOT_PRINT( "X509: Parsing Public Key ...");

  /* Sanity Check on pointer arguments */
  if ( (data_ptr == NULL) || (ptr == NULL) )
  {
    return E_X509_INVALID_ARG;
  }

  do
  {
    SECX509_OPEN_SEQUENCE( data_ptr, &seq1 );
    SECX509_OPEN_SEQUENCE( &seq1, &seq2 );
    SECX509_NEXT_FIELD( &seq2, &data, SECASN1_OID_TYPE );
    SECX509_NEXT_FIELD( &seq2, &dmy, SECASN1_NO_TYPE_CHECK );

    SECX509_CLOSE_SEQUENCE( &seq1, &seq2 );

    /* SET THIS TO NOT SUPPORTED PUBLIC KEY ALGORITHM in the beginning */
    /* to be safe if anything fails in this function */
    ptr->algo = SECX509_PUBKEY_MAX;

    if ( (sizeof(lk_secx509_asn1_rsa) == data.len ) &&
        ( !memcmp( lk_secx509_asn1_rsa,
                        data.data,
                        data.len ) ) )
    {


      /* Parse the public key */
      SECX509_NEXT_FIELD( &seq1, &data, SECASN1_BIT_STRING_TYPE );

      if ( lk_secasn1_decode_bit_string( &data, &bit_str_hldr ) !=
           E_ASN1_SUCCESS )
      {
        return E_X509_DATA_INVALID;
      }

      bit_str.data = bit_str_hldr.data;
      bit_str.len = bit_str_hldr.len;

      /* Ensure there can't be an integer overflow and that the bit string does not */
      /* overflow the containing structure */
      if (!CHECK_DATA_BOUND(bit_str_hldr.data, bit_str_hldr.len, data.data_bound)) 
      {
        return E_X509_DATA_INVALID;        
      }

      // Add is safe by the post condition of the above test
      bit_str.data_bound = bit_str_hldr.data + bit_str_hldr.len;

      SECX509_OPEN_SEQUENCE( &bit_str, &seq2 );
      SECX509_NEXT_FIELD( &seq2, &data, SECASN1_INTEGER_TYPE );

      if (data.len == 0)
      {
        return E_X509_DATA_INVALID;
      }

      /* Remove leading zeros from modulus. Per ASN.1 a leading zero byte */
      /* will be present if the actual value's first byte's MSB is 1.     */
      /* It's safe to remove all leading zero's as they are not applicable */
      while ( ( data.len > 0 ) && ( BLOAD8(data.data) == 0 ) )
      {
        data.data++;
        data.len--;
      }

      /* Remember the location of Public Key Modulus in the certificate memory */
      if ( data.len > (SECBOOT_MAX_KEY_SIZE_IN_BITS/8) )
      {
        return E_X509_DATA_INVALID;
      }

      ptr->key.rsa.mod_data =  data.data;
      ptr->key.rsa.mod_len = data.len;

      /* Parse the exponent */
      SECX509_NEXT_FIELD( &seq2, &data, SECASN1_INTEGER_TYPE );

      if (data.len == 0)
      {
        return E_X509_DATA_INVALID;
      }

      /* Remove leading zero's */
      while ( ( data.len > 0 ) && ( BLOAD8(data.data) == 0 ) )
      {
        data.data++;
        data.len--;
      }

      /* Remember the location of RSA Public Exponent in the certificate memory */
      if ( data.len > (SECBOOT_MAX_PUB_EXP_KEY_SIZE_IN_BITS/8) )
      {
        return E_X509_DATA_INVALID;
      }

      ptr->key.rsa.exp_e_data = data.data;
      ptr->key.rsa.exp_e_len = data.len;

      SECX509_CLOSE_SEQUENCE( &bit_str, &seq2 );

      ptr->algo = SECX509_PUBKEY_RSA;
    }

    SECX509_CLOSE_SEQUENCE( data_ptr, &seq1 );

  }/*lint -e(717) */ while ( FALSE );

  return ret_status;
} /* lk_secx509_parse_pub_key */

/*===========================================================================

FUNCTION SECX509_PARSE_UNIQUE_ID

DESCRIPTION
  Parses a unique ID.  Since both places a unique ID is found in the
  X509 structure, this function supplies an optional tag id to test, but
  if the optional tag id is not found, we will assume the unique ID is
  not present and still return a success.

DEPENDENCIES
  None

PARAMETERS
  data_ptr  - current data holder position
  bt        - bit string to store the unique Id
  op_tag_id - optional tag id that must be next in the data holder
              for the field to exists

RETURN VALUE
  E_X509_SUCCESS - if the data was parsed properly even if an ID is not found
  E_INVALID_DATA - otherwise

SIDE EFFECTS
  None
===========================================================================*/
secx509_errno_enum_type lk_secx509_parse_unique_id
(
  secasn1_data_type *data_ptr,
  secasn1_bit_string_type *bt,
  uint8 op_tag_id
)
{
  secasn1_data_type data;                         /* data holder           */
  secasn1_err_type err;                           /* ASN.1 error code      */
  secx509_errno_enum_type ret_status = E_X509_SUCCESS; /* Return Status         */
/*-------------------------------------------------------------------------*/
  SECBOOT_PRINT( "X509: Parsing Unique Id ...");

  do
  {

    err = lk_secasn1_next_field( data_ptr, &data, op_tag_id );
    //We allow E_ASN1_INVALID_TAG or E_ASN1_NO_DATA as this is an optional field
    if ( err >= E_ASN1_INVALID_DATA )
    {
      ret_status = E_X509_DATA_INVALID;
      break;
    }
    else if ( err == E_ASN1_SUCCESS )
    {
      /* Since this is an IMPLICIT field only need to */
      /* look for the optional tag                    */
      if ( lk_secasn1_decode_bit_string( &data, bt ) != E_ASN1_SUCCESS )
      {
        ret_status = E_X509_DATA_INVALID;
        break;
      }
    }

  }/*lint -e(717) */ while ( FALSE );

  return ret_status;
} /* lk_secx509_parse_unique_id */

/*===========================================================================

FUNCTION SECX509_PARSE_SIG_ALGORITHM

DESCRIPTION
  Parses the signature algorithm.  If the signature algorithm is not
  recognized algo is set to SECX509_SIG_ALGO_MAX

DEPENDENCIES
  None

PARAMETERS
  data_ptr - current data holder position
  algo     - where the returned signature algo will be held

RETURN VALUE
  E_X509_SUCCESS - if the signature algorithm is parsed correctly
  E_INVALID_DATA - otherwise

SIDE EFFECTS
  None
===========================================================================*/
secx509_errno_enum_type lk_secx509_parse_sig_algorithm
(
  secasn1_data_type *data_ptr,
  lk_secx509_sig_algo_type *algo
)
{
  secasn1_data_type data;                         /* data holder           */
  secasn1_data_type oid;                          /* object id holder      */
  secasn1_data_type dmy;                          /* dummy value holder    */
  secx509_errno_enum_type ret_status = E_X509_SUCCESS;      /* Return Status    */
  /*-----------------------------------------------------------------------*/
  SECBOOT_PRINT( "X509: Parsing Signature Algorithm ...");

  /* Sanity Check on pointer arguments */
  if ( (data_ptr == NULL) || (algo == NULL) )
  {
    return E_X509_INVALID_ARG;
  }

  do
  {

    SECX509_OPEN_SEQUENCE( data_ptr, &data );
    SECX509_NEXT_FIELD( &data, &oid, SECASN1_OID_TYPE );
    SECX509_NEXT_FIELD( &data, &dmy, SECASN1_NO_TYPE_CHECK );

    /* Determine the signature algorithm used */
    if ( (sizeof(lk_secx509_sha1WithRSAEncryption) == oid.len) &&
              (!memcmp( lk_secx509_sha1WithRSAEncryption,
                             oid.data,
                             oid.len ) ) )
    {
      *algo = SECX509_sha1WithRSAEncryption;
    }
    else if ( (sizeof(lk_secx509_sha256WithRSAEncryption) == oid.len) &&
              (!memcmp( lk_secx509_sha256WithRSAEncryption,
                             oid.data,
                             oid.len ) ) )
    {
      *algo = SECX509_sha256WithRSAEncryption;
    }
    else
    {
      *algo = SECX509_SIG_ALGO_MAX;
    }

    SECX509_CLOSE_SEQUENCE( data_ptr, &data );

  }/*lint -e(717) */ while ( FALSE );

  return ret_status;
} /* lk_secx509_parse_sig_algorithm */


/*===========================================================================

FUNCTION SECX509_PARSE_SIGNATURE

DESCRIPTION
  Parses the signature and creates pointers to the data in
  cert->cert->algorithm and does an actually copy to the locations
  cert->sig.

DEPENDENCIES
  None

PARAMETERS
  data_ptr - current data holder position
  cert     - certificate to store the signature

RETURN VALUE
  E_X509_SUCCESS - if the signature is parsed correctly
  E_INVALID_DATA - otherwise

SIDE EFFECTS
  None
===========================================================================*/
secx509_errno_enum_type lk_secx509_parse_signature
(
  secasn1_data_type*  data_ptr,
  lk_secx509_cert_type*  cert
)
{
  secasn1_data_type        data;                   /* data holder          */
  secasn1_bit_string_type  bit_string;             /* bit string holder    */
  uint32                   sig_len;                /* signature length     */
  const uint8*             sig_ptr;                /* signature pointer    */
  secx509_errno_enum_type       ret_status = E_X509_SUCCESS; /* Return Status   */
  /*-----------------------------------------------------------------------*/
  SECBOOT_PRINT( "X509: Parsing Signature ...", 0, 0, 0 );

  /* Sanity Check on pointer arguments */
  if ( (data_ptr == NULL) || (cert == NULL) )
  {
    return E_X509_INVALID_ARG;
  }

  do
  {
    if ( lk_secx509_parse_sig_algorithm( data_ptr, &cert->sig_algo ) !=
         E_X509_SUCCESS )
    {
      ret_status = E_X509_DATA_INVALID;
      break;
    }

    if ( cert->sig_algo >= SECX509_SIG_ALGO_MAX )
    {
      ret_status = E_X509_NOT_SUPPORTED;
      break;
    }

    /* Checks to make sure that the sig algorithm within the            */
    /* certificate is consistent with the algorithm identifier          */
    /* within the signed certificate, as RFC2459, 4.1.1.2  says         */
    /* This field MUST contain the same algorithm identifier as the     */
    /* signature field in the sequence tbsCertificate (see sec. 4.1.2.3)*/
    if ( cert->sig_algo != cert->cert_info.algorithm.algo_id )
    {
      SECBOOT_PRINT( "X509: Outer sig algorithm does not match inner sig algorithm", 0, 0, 0 );
      ret_status = E_X509_DATA_INVALID;
      break;
    }

    /* Parse the signature data */
    SECX509_NEXT_FIELD( data_ptr, &data, SECASN1_BIT_STRING_TYPE );

    if ( lk_secasn1_decode_bit_string( &data, &bit_string ) !=
         E_ASN1_SUCCESS )
    {
      ret_status = E_X509_DATA_INVALID;
      break;
    }

    /* Remove any leading 0's on the signature */
    sig_ptr = bit_string.data;
    sig_len = bit_string.len;

    #if 0 /*need below logic? remove below logic, since we may get sig_len = 383*/
    while ( ( sig_len > 0 ) && ( BLOAD8(sig_ptr) == 0 ) )
    {
      sig_len--;
      sig_ptr++;
    }
    #endif

    cert->cert_info.algorithm.val.data = sig_ptr;
    cert->cert_info.algorithm.val.len = sig_len;
    /* Signature size same as key length */
    if ( sig_len > (SECBOOT_MAX_KEY_SIZE_IN_BITS/8) )
    {
      return E_X509_DATA_INVALID;
    }
    cert->sig = sig_ptr;
    cert->sig_len = sig_len;

  }/*lint -e(717) */ while ( FALSE );

  return ret_status;

} /* lk_secx509_parse_signature */


/*===========================================================================

FUNCTION SECX509_NAME_CMP

DESCRIPTION
  Compares two distinguished names by doing a memory comparision

DEPENDENCIES
  None

PARAMETERS
  subject - a DN name to be compared
  issuer  - a DN name to be compared

RETURN VALUE
  0     - if DN names are identical
  non 0 - otherwise

SIDE EFFECTS
  None
===========================================================================*/
int lk_secx509_name_cmp
(
  const lk_secx509_dn_type *subject,
  const lk_secx509_dn_type *issuer
)
{
  /*-----------------------------------------------------------------------*/

  /* Sanity Check on pointer arguments */
  if ( (subject == NULL) || (issuer == NULL) )
  {
    return 1;
  }

  if ( issuer->data.len != subject->data.len )
  {
    return issuer->data.len - subject->data.len;
  }

  return memcmp( issuer->data.data, subject->data.data, issuer->data.len );
} /* lk_secx509_name_cmp */

/*===========================================================================

FUNCTION lk_secx509_check_issued

DESCRIPTION
  Compares a certificate with an issuer certificate to determine if the
  issuer certificate issued the certificate

DEPENDENCIES
  None

PARAMETERS
  issuer  - certificate that will be check as the issuer
  subject - certificate that will check to see if the issuer issued it

RETURN VALUE
  0     - if the issuer issued the certificate
  non 0 - otherwise

SIDE EFFECTS
  None
===========================================================================*/
int lk_secx509_check_issued
(
  const lk_secx509_cert_info_type* issuer,
  const lk_secx509_cert_info_type* subject
)
{
  int ret_val;
  /*-----------------------------------------------------------------------*/
  /* Sanity Check on pointer arguments */
  if ( (issuer == NULL) || (subject == NULL) )
  {
    return 1;
  }

  ret_val = lk_secx509_name_cmp( &issuer->subject, &subject->issuer );

  if ( ret_val != 0 ) return ret_val;

  /* Check the authority key identifier */
  if ( subject->extension.auth_key_id.set )
  {

    /* Check if the key ids are present */
    if ( subject->extension.auth_key_id.key_id.len &&
         issuer->extension.subject_key_id.set )
    {

      /* Compare the key ids */
      if ( subject->extension.auth_key_id.key_id.len !=
           issuer->extension.subject_key_id.key_id.len )
      {

        return 1;
      }

      ret_val = memcmp( subject->extension.auth_key_id.key_id.data,
                        issuer->extension.subject_key_id.key_id.data,
                        issuer->extension.subject_key_id.key_id.len );

      if ( ret_val != 0 )
      {
        return ret_val;
      }
    }

    /* Check the Serial number */
    if ( subject->extension.auth_key_id.serial_number.len != 0 )
    {
      if ( subject->extension.auth_key_id.serial_number.len !=
           issuer->serial_number.len )
      {

        return 1;
      }

      ret_val = memcmp( subject->extension.auth_key_id.serial_number.data,
                        issuer->serial_number.data,
                        issuer->serial_number.len );

      if ( ret_val != 0 )
      {
        return ret_val;
      }
    }

    /* Compare the issuers name */
    if ( subject->extension.auth_key_id.name.num_attrib != 0 )
    {
      ret_val = lk_secx509_name_cmp( &issuer->issuer,
                                  &subject->extension.auth_key_id.name );
       if (ret_val != 0) {
          return (ret_val);
       }
    }
  }

  /* Check key usage of the issuer key */
  if ( issuer->extension.key_usage.set )
  {
    if ( !( issuer->extension.key_usage.val & SECX509_KEY_USAGE_KEY_CRT ) )
    {
      return -1;
    }
  }

  return 0;

} /* lk_secx509_check_issued */

/*===========================================================================

FUNCTION lk_secx509_check_purpose

DESCRIPTION
  This function checks the purposes of the certificate.  Currently we
  only support an ssl server check.

DEPENDENCIES
  None

PARAMETERS
  cert - pointer to the certificate
  id   - what category the certificate is being checked against
  ca   - CA value

RETURN VALUE
  1 if the certificate is valid for the purpose
  0 otherwise

SIDE EFFECTS
  None
===========================================================================*/
int lk_secx509_check_purpose
(
  const lk_secx509_cert_info_type *cert,
  int id,
  int ca
)
{
  int ret_val=0;                                    /* return value        */
  /*-----------------------------------------------------------------------*/

  /* Sanity Check on pointer arguments */
  if ( cert == NULL )
  {
    return 0;
  }

  /* If we have an id of -1 do not check the purpose */
  if ( id == -1 || !cert->extension.set )
  {
    return 1;
  }

  if ((cert->extension.key_usage.val & id)!=0)
  {
      ret_val = 1;
  }
  else
  {
    //cert purpose does not match what is expected
    ret_val = 0;
  }

  return ret_val;

} /* lk_secx509_check_purpose */

/*===========================================================================

FUNCTION SECX509_PARSE_GEN_NAME_FOR_DIR

DESCRIPTION
  Parses a general name structure for a directory name.  Since the
  general name structure is a list we will use the first directory
  name we find.  If there are more then one directory names, the others
  will be ignored.  If there are no directory names present name will
  contain an empty DN with 0 attributes.

DEPENDENCIES
  None

PARAMETERS
  data_ptr - current data holder position
  name     - where the DN from the directory name will be stored

RETURN VALUE
  E_X509_SUCCESS - if the general name is parsed correctly
  E_INVALID_DATA - otherwise

SIDE EFFECTS
  None
===========================================================================*/
secx509_errno_enum_type lk_secx509_parse_gen_name_for_dir
(
  secasn1_data_type *data_ptr,
  lk_secx509_dn_type *name
)
{
  secasn1_data_type tag;                          /* tag data holder       */
  secasn1_err_type err;                           /* ASN.1 error code      */
  secx509_errno_enum_type ret_status = E_X509_SUCCESS;      /* Return Status    */

  /* Sanity Check on pointer arguments */
  if ( (name == NULL) || (data_ptr == NULL) )
  {
    return E_X509_INVALID_ARG;
  }

  /*-----------------------------------------------------------------------*/
  /* Initialize the name, so if we don't find a directory name */
  /* it will be set correctly */
  name->num_attrib = 0;

  while (data_ptr->len > 0)
  {
    err = lk_secasn1_next_field( data_ptr, &tag, SECX509_AUTH_ISS_NAME_TAG );
    if ( err == E_ASN1_SUCCESS )
    {
      /* Found a directory name parse it */
      ret_status = lk_secx509_parse_dn( &tag, name, NULL );
      break;
    }
    else if ( err >= E_ASN1_INVALID_DATA)
    {
      //We allow E_ASN1_INVALID_TAG or E_ASN1_NO_DATA as this is an optional field
      ret_status = E_X509_DATA_INVALID;
      break;
    }

  }

  /* We may not have found a directory name, but that is still OK, since */
  /* there may not be one */
  return ret_status;

} /* lk_secx509_parse_gen_name_for_dir */

/*===========================================================================
 
 FUNCTION SECX509_PARSE_AUTH_KEY_ID
 
 DESCRIPTION
   Parse an Authority Key Identifier.  This extension should
   never be marked critical so the certificate will be marked as invalid
   if this extension is marked critical.
 
 DEPENDENCIES
   None
 
 PARAMETERS
   data_ptr - current data holder position
   akid     - where the returned authority key id is stored
   critical - whether the extension is marked critical
 
 RETURN VALUE
   E_X509_SUCCESS - if the authority key id is parsed correctly
   E_INVALID_DATA - otherwise
 
 SIDE EFFECTS
   None
 ===========================================================================*/
 secx509_errno_enum_type lk_secx509_parse_auth_key_id
 (
   secasn1_data_type *data_ptr,
   lk_secx509_auth_key_id_type *akid,
   boolean critical
 )
 {
   secasn1_data_type seq;                          /* sequence holder       */
   secasn1_data_type data;                         /* data holder           */
   secasn1_err_type  err;                          /* ASN.1 error code      */
   secx509_errno_enum_type ret_status = E_X509_SUCCESS; /* Return Status         */
   /*-----------------------------------------------------------------------*/
   SECBOOT_PRINT( "X509: Parsing Authority Key Identifier ..." );
 
   do
   {
     /* Rules are taken from RFC 2459 sec 4.2.1.1 */
     if ( critical || akid == NULL )
     {
       /* Cannot be marked critical*/
       ret_status = E_X509_DATA_INVALID;
       break;
     }
 
     akid->set = TRUE;
 
     SECX509_OPEN_SEQUENCE( data_ptr, &seq );
 
     /* These 3 tags are optional fields per the spec */
 
     /* Try to parse the key identifier */
     err = lk_secasn1_next_field( &seq,
                               &akid->key_id,
                               SECX509_AUTH_KID_TAG );
 
     //We allow E_ASN1_INVALID_TAG or E_ASN1_NO_DATA as this is an optional field
     if ( err >= E_ASN1_INVALID_DATA ) 
     {
       ret_status = E_X509_DATA_INVALID;
       break;
     }
 
     /* Try to parse the authority cert issuer */
     err = lk_secasn1_next_field( &seq, &data, SECX509_AUTH_ISS_TAG );
 
     if ( err == E_ASN1_SUCCESS )
     {
       if ( lk_secx509_parse_gen_name_for_dir( &data, &akid->name )
            != E_X509_SUCCESS )
       {
         ret_status = E_X509_DATA_INVALID;
         break;
       }
     }
     //We allow E_ASN1_INVALID_TAG or E_ASN1_NO_DATA as this is an optional field
     else if ( err >= E_ASN1_INVALID_DATA ) 
     {
       return E_X509_DATA_INVALID;
     }
 
     /* Try to parse the authority certificate serial number */
     err = lk_secasn1_next_field( &seq, &akid->serial_number,
                                SECX509_AUTH_SER_TAG );
     //We allow E_ASN1_INVALID_TAG or E_ASN1_NO_DATA as this is an optional field
     if ( err >= E_ASN1_INVALID_DATA)
     {
       ret_status = E_X509_DATA_INVALID;
       break;
     }
 
     SECX509_CLOSE_SEQUENCE( data_ptr, &seq );
 
   }/*lint -e(717) */ while ( FALSE );
   return ret_status;
 } /* lk_secx509_parse_auth_key_id */


/*===========================================================================
 
 FUNCTION SECX509_PARSE_EXTENSIONS
 
 DESCRIPTION
   Parses the extensions of the X509 certificate.  According to RFC 2459, it
   highly recommends that the following extensions be understood:
 
     key usage, certificate policies, subject alternative name, basic
     constraint, name constraints, policy constraints, extended key
     identifier, authority key identifier and subject key identifier.
 
   Currently all these extensions are parsed and checked for the critical flag,
   but beyond that the following extensions are just ignored:
 
     certificate policies, name constraints, policy constraints
 
   The rest of the extensions are fully parsed.  Also if an unknown extension
   is found that is marked critical, the certificate must be found invalid
   according to RFC 2459.
 
   Since the extensions are an optional field, this function accepts the
   optional tag id which it checks against the next tag.
 
 DEPENDENCIES
   This function should only be called for version 3 certificates
 
 PARAMETERS
   data_ptr  - current data holder position
   cert      - certificate to store the extensions
   op_tag_id - optional tag id that must be next in the data holder
               for the field to exists
 
 RETURN VALUE
   E_X509_SUCCESS - if the extensions are parsed correctly
   E_INVALID_DATA - otherwise
 
 SIDE EFFECTS
   None
 ===========================================================================*/
 secx509_errno_enum_type lk_secx509_parse_extensions
 (
   secasn1_data_type *data_ptr,
   lk_secx509_cert_info_type *cert,
   uint8 op_tag_id
 )
 {
   secasn1_data_type opt;                          /* optional field holder */
   secasn1_data_type seq1;                         /* outer sequence holder */
   secasn1_data_type seq2;                         /* inner sequence holder */
   secasn1_data_type oid;                          /* object id holder      */
   secasn1_data_type val;                          /* oid value holder      */
   secasn1_err_type err;                           /* ASN.1 error code      */
   secasn1_data_type dat;                          /* temp data holder      */
   boolean critical;                               /* Whether the current   */
                                                   /* extension is critical */
   lk_secx509_cert_info_type *cert_ptr;           /* certificate pointer   */
   secx509_errno_enum_type ret_status = E_X509_SUCCESS; /* Return Status         */
   /*-----------------------------------------------------------------------*/
 
   SECBOOT_PRINT( "X509: Parsing Extensions ...");
 
   /* Sanity Check on pointer arguments */
   if ( (data_ptr == NULL) || (cert == NULL) )
   {
     return E_X509_INVALID_ARG;
   }
 
   cert_ptr = cert;
 
   /* Mark all the extension to not be set */
   cert_ptr->extension.auth_key_id.set = FALSE;
   cert_ptr->extension.subject_key_id.set = FALSE;
   cert_ptr->extension.key_usage.set = FALSE;
   cert_ptr->extension.ex_key_usage.set = FALSE;
   cert_ptr->extension.ca.set = FALSE;
 
   do
   {
 
     err = lk_secasn1_next_field( data_ptr, &opt, op_tag_id );
     //We allow E_ASN1_INVALID_TAG or E_ASN1_NO_DATA as this is an optional field
     if ( err >= E_ASN1_INVALID_DATA )
     {
       /* ERROR has occurred */
       ret_status = E_X509_DATA_INVALID;
     }
     else if ( err == E_ASN1_SUCCESS )
     {
       SECBOOT_PRINT( "X509: Found Extensions ...");
 
       cert->extension.set = TRUE;
 
       /* Extensions are present */
       SECX509_OPEN_SEQUENCE( &opt, &seq1 );
 
       while ( seq1.len > 0 )
       {
         SECX509_OPEN_SEQUENCE( &seq1, &seq2 );
 
         /* Parse the object identifier */
         SECX509_NEXT_FIELD( &seq2, &oid, SECASN1_OID_TYPE );
 
         /* Parse the whether the value is critical */
         err = lk_secasn1_next_field( &seq2, &dat, SECASN1_BOOLEAN_TYPE );
         if ( err == E_ASN1_SUCCESS )
         {
           if ( lk_secasn1_decode_boolean( &dat, &critical ) !=
                E_ASN1_SUCCESS )
           {
             ret_status = E_X509_DATA_INVALID;
             break;
           }
         }
         else 
         {
           /* If a boolean tag is not present it is false */
           critical = FALSE;
         }
 
         /* Parse the value */
         SECX509_NEXT_FIELD( &seq2, &val, SECASN1_NO_TYPE_CHECK );
 
         /* We have the extension object identifier */
         if ( (sizeof(lk_secx509_ext_auth_key_id) == oid.len) &&
              ( !memcmp( lk_secx509_ext_auth_key_id,
                             oid.data,
                             oid.len ) ) )
         {
           /* Authority Key Identifier */
           SECBOOT_PRINT( "X509: Authority Key Identifier Extension");
 
           if ( lk_secx509_parse_auth_key_id( &val,
                                           &cert_ptr->extension.auth_key_id,
                                           critical ) != E_X509_SUCCESS )
           {
             ret_status = E_X509_DATA_INVALID;
           }
         }
         else if ( (sizeof(lk_secx509_ext_sub_key_id) == oid.len) &&
                   (!memcmp( lk_secx509_ext_sub_key_id,
                                  oid.data,
                                  oid.len ) ) )
         {
           /* Subject Key Identifier */
           SECBOOT_PRINT("X509: Subject Key Identifier Extension");
 
           if ( critical )
           {
             ret_status = E_X509_DATA_INVALID;
           }
 
           /* Try to parse the key identifier */
           err = lk_secasn1_next_field( &val,
                               &cert_ptr->extension.subject_key_id.key_id,
                               SECASN1_OCTET_STRING_TYPE );
           //We allow E_ASN1_INVALID_TAG or E_ASN1_NO_DATA as this is an optional field
           if ( err >= E_ASN1_INVALID_DATA )
           {
             ret_status = E_X509_DATA_INVALID;
             break;
           }
 
           cert_ptr->extension.subject_key_id.set = TRUE;
         }
         else if ( (sizeof(lk_secx509_ext_key_usage) == oid.len) &&
                   (!memcmp( lk_secx509_ext_key_usage,
                                  oid.data,
                                  oid.len ) ) )
         {
           /* Key Usage Extension (Does not matter if it is critical) */
           SECBOOT_PRINT( "X509: Key Usage Extension");
 
           cert->extension.key_usage.set = TRUE;
 
           if ( lk_secx509_parse_key_usage( &val,
                                             &cert->extension.key_usage.val )
                != E_X509_SUCCESS )
           {
             ret_status = E_X509_DATA_INVALID;
           }
 
         }
         else if ( (sizeof(lk_secx509_ext_ex_key_usage) == oid.len) &&
                   (!memcmp( lk_secx509_ext_ex_key_usage,
                                  oid.data,
                                  oid.len ) ) )
         {
           /* Key Usage Extension (Does not matter if it is critical) */
           SECBOOT_PRINT( "X509: Extended Key Usage Extension");
 
           cert_ptr->extension.ex_key_usage.set = TRUE;
 
           if ( lk_secx509_parse_ex_key_usage( &val,
                                            &cert->extension.ex_key_usage.val )
                != E_X509_SUCCESS )
           {
             ret_status = E_X509_DATA_INVALID;
           }
         }
         else if ( (sizeof(lk_secx509_ext_sub_alt_name) == oid.len) &&
                   (!memcmp( lk_secx509_ext_sub_alt_name,
                                  oid.data,
                                  oid.len ) ) )
         {
           /* Subject Alternative Name */
           SECBOOT_PRINT( "X509: Subject Alternate Name Extension");
 
           /* If no subject Distinguished name had no attributes  */
           /* this field better be marked critical, this is the   */
           /* only time we will try to parse the object           */
           if ( cert->subject.num_attrib == 0 )
           {
             if ( critical )
             {
               if ( lk_secx509_parse_gen_name_for_dir( &val,
                                                    &cert->subject )
                    != E_X509_SUCCESS )
               {
                 ret_status = E_X509_DATA_INVALID;
               }
             }
             else
             {
               ret_status = E_X509_DATA_INVALID;
             }
 
           }
         }
         else if ( (sizeof(lk_secx509_ext_basic_constraint) == oid.len) &&
                   (!memcmp( lk_secx509_ext_basic_constraint,
                                  oid.data,
                                  oid.len ) ) )
         {
           /* Basic Constraints */
           if ( lk_secx509_parse_basic_constraint( &val,
                                                &cert->extension )
                != E_X509_SUCCESS )
           {
             ret_status = E_X509_DATA_INVALID;
           }
 
         }
         else if ( (sizeof(lk_secx509_ext_name_constraint) == oid.len) &&
                   (!memcmp( lk_secx509_ext_name_constraint,
                                  oid.data,
                                  oid.len ) ) )
         {
 
           /* Name Constraints */
           SECBOOT_PRINT( "X509: Name Constraint Extension");
         }
         else if ( (sizeof(lk_secx509_ext_policy_constraint) == oid.len) &&
                   (!memcmp( lk_secx509_ext_policy_constraint,
                                  oid.data,
                                  oid.len ) ) )
         {
 
           /* Policy Constraints */
           SECBOOT_PRINT( "X509: Policy Constraint Extension");
         }
         else if ( (sizeof(lk_secx509_ext_cert_policies) == oid.len) &&
                   (!memcmp( lk_secx509_ext_cert_policies,
                                  oid.data,
                                  oid.len ) ) )
         {
           /* Certificate Policies */
           SECBOOT_PRINT( "X509: Certificate Policies Extension");
         }
         else
         {
           /* Unknown Extension */
           if ( critical )
           {
             /* As stated in RFC 2459 if an extension is marked */
             /* critical and cannot be parsed then the cert     */
             /* must be rejected.                               */
             ret_status = E_X509_DATA_INVALID;
           }
           else
           {
             SECBOOT_PRINT( "X509: Unrecoginized Non-Critical Extension", 0, 0, 0 );
           }
         }
 
         if (ret_status != E_X509_SUCCESS)
         {
           /* An error has occurred in the processing, leave the */
           /* loop that parses the extensions */
           break;
         }
 
         SECX509_CLOSE_SEQUENCE( &seq1, &seq2 );
       }
 
       if (ret_status != E_X509_SUCCESS)
       {
         break;
       }
 
       SECX509_CLOSE_SEQUENCE( &opt, &seq1 );
     }
 
   }/*lint -e(717) */ while ( FALSE );
   return ret_status;
 
 } /* lk_secx509_parse_extensions */


/*===========================================================================

FUNCTION SECX509_PARSE_CERTIFICATE

DESCRIPTION
  Parses an X509 certificate from the data_ptr, if *cert == NULL then the
  certificate is allocated from the memory pool, if the certificate is
  already allocated then the function just uses the pre-allocated memory

DEPENDENCIES
  None

PARAMETERS
  data_ptr          - pointer to the raw certificate data
  data_bound        - address beyond which the certificate does not cross into
  cert              - pointer to the certificate
  ou_field_info_ptr - pointer to store OU Field values

RETURN VALUE
  E_X509_SUCCESS if the certificate is parsed properly
  E_X509_DATA_INVALID if the certificate cannot be parsed properly
  E_X509_NO_MEMORY if no more memory slots are available for the certs
  E_X509_NOT_SUPPORTED if an algorithm found in the cert is not supported
  E_X509_INVALID_ARG if a pointer argument is NULL
  E_X509_FAILURE if the *cert is pre-allocated but not *cert->cert or if the
            certificate data length does not match cert_len

SIDE EFFECTS
  None
===========================================================================*/
secx509_errno_enum_type lk_secx509_parse_certificate
(
  const uint8*                 data_ptr,
  const uint8*                 data_bound,
  lk_secx509_cert_type*       main_cert_ptr,
  secx509_ou_field_info_type*  ou_field_info_ptr
)
{
  lk_secx509_cert_info_type*  cert_ptr;      /* X509 certificate pointer   */
  secasn1_data_type        cert_data;     /* data holder for the cert data  */
  secasn1_data_type        tbs_cert_data; /* tbs cert data holder           */
  secx509_errno_enum_type       ret_status = E_X509_SUCCESS; /* return status    */
  /*-----------------------------------------------------------------------*/

  /* Sanity Check on pointer arguments */
  /* No need to check data_bound for NULL, since it is 
     never dereferenced.  */ 
  if ( (main_cert_ptr == NULL) || (data_ptr == NULL) ||
          !CHECK_DATA_BOUND(data_ptr, 0, data_bound) )
  {
    return E_X509_INVALID_ARG;
  }

  cert_ptr = &(main_cert_ptr->cert_info);

  /* Loop so we can break when an error occurs */
  do
  {
    /* This call will fail if data_ptr > data_bound */
    if ( lk_secasn1_start( data_ptr, data_bound, &cert_data ) != 
          E_ASN1_SUCCESS 
       )
    {
      ret_status = E_X509_DATA_INVALID;
      break;
    }
    /* A post condition of a successful call to lk_secasn1_start is
       that cert_data is valid */
    /* Set where the certificate information starts */
    main_cert_ptr->cinf_offset = (cert_data.data - data_ptr);
    if (main_cert_ptr->cinf_offset > SECASN1_MAX_LEN)
    {
      ret_status = E_X509_DATA_INVALID;
      break;
    }

    /* record the size */
    main_cert_ptr->asn1_size_in_bytes = cert_data.len +
          main_cert_ptr->cinf_offset;
    /* check integer overflow and SECASN1 boundary*/
    if ( (main_cert_ptr->asn1_size_in_bytes < cert_data.len) || 
         (main_cert_ptr->asn1_size_in_bytes > SECASN1_MAX_LEN) )
    {
      ret_status = E_X509_DATA_INVALID;
      break;
    }

    SECX509_OPEN_SEQUENCE( &cert_data, &tbs_cert_data );

    /* Parse the version number */
    if ( lk_secx509_parse_version( &tbs_cert_data, &cert_ptr->version )
         != E_X509_SUCCESS )
    {
      ret_status = E_X509_DATA_INVALID;
      break;
    }

    /* Parse the serial number */
    SECX509_NEXT_FIELD( &tbs_cert_data,
                        &cert_ptr->serial_number,
                        SECASN1_INTEGER_TYPE );

    /* Parse the signature since we check with outside field */
    if ( lk_secx509_parse_sig_algorithm( &tbs_cert_data,
                                      &cert_ptr->algorithm.algo_id )
         != E_X509_SUCCESS )
    {
      ret_status = E_X509_DATA_INVALID;
      break;
    }

    /* Parse the Issuers Distinguished Name */
    if ( lk_secx509_parse_dn( &tbs_cert_data, &cert_ptr->issuer, NULL ) !=
         E_X509_SUCCESS )
    {
      ret_status = E_X509_DATA_INVALID;
      break;
    }

    /* Parse the Validity */
    if ( lk_secx509_parse_validity( &tbs_cert_data, cert_ptr ) !=
         E_X509_SUCCESS )
    {
      ret_status = E_X509_DATA_INVALID;
      break;
    }

    /* Parse the Subject Distinguished Name */
    if ( lk_secx509_parse_dn( &tbs_cert_data, &cert_ptr->subject, ou_field_info_ptr ) !=
         E_X509_SUCCESS )
    {
      ret_status = E_X509_DATA_INVALID;
      break;
    }

    /* Parse Subject Public Key Info */
    if ( lk_secx509_parse_pub_key( &tbs_cert_data, &main_cert_ptr->pkey )
         != E_X509_SUCCESS )
    {
      ret_status = E_X509_DATA_INVALID;
      break;
    }

    if ( main_cert_ptr->pkey.algo != SECX509_PUBKEY_RSA )
    {
      ret_status = E_X509_NOT_SUPPORTED;
      break;
    }

    /* Initialize extension data */
    cert_ptr->extension.set = FALSE;
    cert_ptr->extension.path_len = -1;

    /* For Version 1 (value 0), only basic fields are present
       For Version 2 (value 1), no extensions are present, but a UniqueIdentifier is present
       For Version 3 (value 2), extensions are used
    */
    if ( cert_ptr->version.ver > 0 )
    {

      /* Version 2 or above, look for Optional Information */

      /* Attempt to parse Issuer Unique Id */
      if ( lk_secx509_parse_unique_id( &tbs_cert_data,
                                    &cert_ptr->issuer_unique_id,
                                    SECX509_ISSUER_ID_TAG )
           != E_X509_SUCCESS )
      {
        ret_status = E_X509_DATA_INVALID;
        break;
      }

      /* Attempt to parse Subject Unique Id */
      if ( lk_secx509_parse_unique_id( &tbs_cert_data,
                                    &cert_ptr->subject_unique_id,
                                    SECX509_SUBJECT_ID_TAG )
           != E_X509_SUCCESS )
      {
        ret_status = E_X509_DATA_INVALID;
        break;
      }

      if ( cert_ptr->version.ver == 2 )
      {
        /* 2 means version 3, the version number is 0 based */
        /* Version 3, check for extensions */
        if ( lk_secx509_parse_extensions( &tbs_cert_data,
                                       cert_ptr,
                                       SECX509_EXTENSION_TAG )
             != E_X509_SUCCESS )
        {
          ret_status = E_X509_DATA_INVALID;
          break;
        }
      }

    } /* cert_ptr->version.ver > 0 */

    SECX509_CLOSE_SEQUENCE( &cert_data, &tbs_cert_data );

    /* These two checks verify that the two subtractions below will not overflow. */
    if ((uint32)cert_data.data < (uint32)data_ptr ||
  ((uint32)cert_data.data - (uint32)data_ptr) < main_cert_ptr->cinf_offset)
    {
      ret_status = E_X509_DATA_INVALID;
      break;      
    }

    /* Calculate the byte length of the actual certificate data */
    /* By the above tests, this arithmetic is safe */
    main_cert_ptr->cinf_byte_len = ((uint32)cert_data.data - (uint32)data_ptr) -
      main_cert_ptr->cinf_offset;
    /* Check that our size limits are not violated */
    if (main_cert_ptr->cinf_byte_len > SECASN1_MAX_LEN) {
      ret_status = E_X509_DATA_INVALID;
      break;
    }

    /* Parse the signature */
    if ( lk_secx509_parse_signature( &cert_data, main_cert_ptr ) !=
         E_X509_SUCCESS )
    {
      ret_status = E_X509_DATA_INVALID;
      break;
    }
    if ( cert_ptr->algorithm.algo_id >= SECX509_SIG_ALGO_MAX )
    {
      ret_status = E_X509_NOT_SUPPORTED;
      break;
    }

    /* Check to make sure the parsing has looked at the entire certificate */
    if ( lk_secasn1_end( &cert_data ) != E_ASN1_SUCCESS )
    {
      ret_status = E_X509_DATA_INVALID;
      break;
    }

  }/*lint -e(717) */ while (FALSE);
  return ret_status;
} /* lk_secx509_parse_certificate */


/*===========================================================================
FUNCTION lk_secx509_parse_cert_buffer

DESCRIPTION
  Parses binary x509 certificates from memory into the buffer.
  parsing is done in order (attest cert first, CA cert next and
  root cert last).

DEPENDENCIES
  None

PARAMETERS
  cert_chain_ptr          - points to x509 certificate chain (in Flash)
                            CA cert and Attestation cert are here
  cert_chain_len          - upper bound on length of chain (parse fails
                            if chain appears to cross exceed this length,
                or if the space between the last cert and
                this length has any bytes that are not 0xFF).
  lk_secx509_cert_list   - destination for all the certificates
                            after they have been parsed in order of chaining.
  ou_field_info_ptr       - pointer to store OU Field values                            

RETURN VALUE
  E_X509_SUCCESS on successful parsing of all certs
  E_X509_FAILURE on unsuccessful parsing of all certs
  E_X509_INVALID_ARG on invalid arguments

SIDE EFFECTS
  None
===========================================================================*/
secx509_errno_enum_type lk_secx509_parse_cert_buffer
(
  const uint8*                 cert_chain_ptr,
  uint32                             cert_chain_len, /* including tail padding */
  lk_secx509_cert_list_type*  lk_secx509_cert_list,
  secx509_ou_field_info_type*  ou_field_info_ptr
)
{
 secx509_errno_enum_type return_value=E_X509_FAILURE;
  const uint8*       cert_chain_bound;
  uint32             cert_idx = 0;
  lk_secx509_cert_type  *cert_ptr = 0;

  /*-----------------------------------------------------------------------*/
  /* Sanity Check on pointer arguments */
  if ( (cert_chain_ptr == NULL) || (lk_secx509_cert_list == NULL)
        || (cert_chain_len == 0) || (ou_field_info_ptr == NULL))
  {
    return E_X509_INVALID_ARG;
  }

  /* Parse the certs one by one */
  do
  {
    /* check for buffer overflow */
    if (((uint32)cert_chain_ptr + cert_chain_len) < (uint32)cert_chain_ptr) 
    {
      return_value = E_X509_FAILURE;
      break;
    }

    /* Set the boundary. Parsing of all the certificates should be contained within */
    /* this boundary.  The above test ensures that this does not overflow. */
    cert_chain_bound = cert_chain_ptr + cert_chain_len;

    lk_secx509_cert_list->size = 0;

    /* Parse the chained certificates, we can have minimum 2 certs in the                 */
    /* chain i.e attestation and root                                                     */
    /* Or the cert chain has a total of 18 certs of which a maximum of three will be used */
    /* i.e attesation, ca, root                                                           */
    for (cert_idx = 0; cert_idx < SECBOOT_MAX_NUM_CERTS; cert_idx++)
    {
      /* size is the counter, incrementing in every iteration */
      cert_ptr = &lk_secx509_cert_list->cert[lk_secx509_cert_list->size];

      /* Parse the certificate */
      return_value = lk_secx509_parse_certificate( cert_chain_ptr,
                                                    cert_chain_bound,
                                                    cert_ptr,
                                                    ou_field_info_ptr);
      if (return_value!=E_X509_SUCCESS) break;
      
      /* Only the attestation cert which is the first cert in the chain */
      /* contains OU fields, so make sure we don't spend time during */
      /* parsing trying to find OU fields for the other certs */
      ou_field_info_ptr = NULL;

      /* Check if advancing the pointer will go off the end */
      if (!CHECK_DATA_BOUND(cert_chain_ptr, cert_ptr->asn1_size_in_bytes, cert_chain_bound))
      {
          return_value = E_X509_FAILURE;
          break;
      }

      SECBOOT_PRINT("L%d_%s(): cert[%d].cinf_offset=%d,cinf_byte_len=%d,asn1_size=%d,sig_len=%d\n", 
        __LINE__,__func__,cert_idx, cert_ptr->cinf_offset, 
        cert_ptr->cinf_byte_len, cert_ptr->asn1_size_in_bytes, cert_ptr->sig_len);

      /* advance pointer */
      cert_chain_ptr += cert_ptr->asn1_size_in_bytes;

      /* another certificate parsed and added ... */
      lk_secx509_cert_list->size++;

      /* check if this is a root cert */
      if ( ( cert_ptr->cert_info.issuer.data.len ==
             cert_ptr->cert_info.subject.data.len ) && 
          ( memcmp( cert_ptr->cert_info.issuer.data.data,
                    cert_ptr->cert_info.subject.data.data,
                    cert_ptr->cert_info.subject.data.len ) == 0) )
      {
        // self-signed cert found (root), we're done
        // i.e if there are 2 certs in the chain instead of 3 we can stop here
        SECBOOT_PRINT("L%d_%s(): found rootca.\n",__LINE__, __func__);
        break;
      }
    }

    if (return_value != E_X509_SUCCESS) break;
    if (lk_secx509_cert_list->size == 1)
    {
      // We don't allow just 1 cert (root cert).
      return_value = E_X509_FAILURE;
      break;
    }

    /* Check that any trailing space/end padding is all FF's */
    for (; cert_chain_ptr < cert_chain_bound; ++cert_chain_ptr) 
    {
      if (BLOAD8(cert_chain_ptr) != 0xFF) 
      {
        return_value = E_X509_FAILURE;
        /* don't bother to break out of this loop, since the normal 
         case goes clear to the end. */
      } 
    }
 
  }/*lint -e(717) */ while (FALSE);
  return return_value;
} /* lk_secx509_parse_cert_buffer */

/*===========================================================================
FUNCTION lk_secx509_check_cert_list

DESCRIPTION
  Simply checks if the certificate information, over the whole chain
  is valid and that the issuer and subject ID's are chained consecutively.
  Cryptographic signature verification down the chain is _NOT_ done here.

DEPENDENCIES
  None

PARAMETERS
  *cert_list_ptr  - Pointer to array of parsed certificates
  *check_ctx              - Sets of the parameters for the checking process

RETURN VALUE
  E_SUCCESS       - if no error
  E_DATA_INVALID  - Invalid Data
  E_NOT_SUPPORTED - Unknown Data

SIDE EFFECTS
  None
===========================================================================*/
secx509_errno_enum_type lk_secx509_check_cert_list
(
  const lk_secx509_cert_list_type *cert_list_ptr,
  const lk_secx509_cert_ctx_type  *check_ctx
)
{
  uint32 curr_cert_num;
  secx509_errno_enum_type _errno = E_X509_SUCCESS;
  /*-----------------------------------------------------------------------*/

  /* Basic Sanity check */
  if ( (cert_list_ptr == NULL) || (check_ctx == NULL) ||
       (cert_list_ptr->size == 0) )
  {
    return E_X509_DATA_INVALID;
  }

  for ( curr_cert_num = 0; curr_cert_num < cert_list_ptr->size;
        curr_cert_num++ )
  {

    /* Check the certificate purpose */
    if (check_ctx->purpose > 0)
    {
      if (check_ctx->depth == curr_cert_num)
      {
        if ( !lk_secx509_check_purpose( &(cert_list_ptr->
                                         cert[curr_cert_num].cert_info),
                                         check_ctx->purpose,
                                         curr_cert_num ) )
        {
          _errno = E_X509_DATA_INVALID;
          break;
        }
      }

      /* Check pathlen */
      if ( (curr_cert_num > 0) &&
           (cert_list_ptr->
            cert[curr_cert_num].cert_info.extension.path_len != -1) &&
            /* cast depends on current cert number not exceeding INT_MAX */
           (((int) curr_cert_num) > (cert_list_ptr->
            cert[curr_cert_num].cert_info.extension.path_len + 1)) )
      {
         _errno = E_X509_DATA_INVALID;
         break;
      }
    }

    /* All but last root cert ... */
    /* note, we don't process the root cert */
    /* This did read: if(curr_cert_num < cert_list_ptr->size - 1)...
       But ...->size is unsigned, and subtracting 1 could
       make a very large number.  So we rearrange the arithmetic. */
    if ( curr_cert_num + 1 < cert_list_ptr->size )
    {
      /* See if the issuer and subject ID's are correct and in order */
      if ( lk_secx509_check_issued (&(cert_list_ptr->
                                     cert[curr_cert_num+1].cert_info),
                                     &(cert_list_ptr->
                                     cert[curr_cert_num].cert_info)) )
      {
        _errno = E_X509_DATA_INVALID;
        break;
      }
    }
  } /* end of 'for' */
  return _errno;
} /* lk_secx509_check_cert_list */


 /**
  * @brief This function ensures the exponent is 3 or 65537
  *
  * @param[in]         buf         Buffer containing exponent value
  *
  * @param[in]         buflen      Length of the buffer
  *                                         
  * @return E_SECBOOT_SUCCESS on success. Appropriate error code on failure.
  *
  * @dependencies None
  *
  * @sideeffects  None
  *           
  * @see None
  *
  */
 static secboot_error_type secboot_verify_exponent(const uint8* buf, uint32 buflen)
 {
   uint32 index = 0;
 
   if ( (buflen == 0) || (buf == NULL) )
   {
     return E_SECBOOT_FAILURE;
   }
 
   //Skip any leading zero's
   while ((index < buflen) && (buf[index] == 0))
   {
     index++;
   }
 
   //Check for exponent 3
   if ( (index+1 == buflen) && (buf[index] == 3) )
   {
     return E_SECBOOT_SUCCESS;
   }
 
   //Check for exponent 65537 - 0x010001
   if ( (index+3 == buflen) && (buf[index] == 1) &&  (buf[index+1] == 0) && (buf[index+2] == 1) )
   {
     return E_SECBOOT_SUCCESS;
   }
 
   return E_SECBOOT_FAILURE;
 }

 /**
  * @brief This function hash two part data to get hash with software way.
  *        Currently HW crypto enginee hash not support, consider to support in future.
  *
  * @param[in]         hash_algo         hash algo
  *
  * @param[in]         data1_in_ptr      Buffer containing the first part data to hash
  *
  * @param[in]         data1_len         Length of the buffer
  *
  * @param[On]         digest_ptr        output hash buffer
  *
  * @return E_SECBOOT_SUCCESS on success. Appropriate error code on failure.
  *
  * @dependencies None
  *
  * @sideeffects  None
  *           
  * @see None
  *
  */
 secboot_error_type secboot_hash
(
  CeMLHashAlgoType                  hash_algo,
  const uint8*                      data1_in_ptr,
  uint32                            data1_len,
  const uint8*                      data2_in_ptr,
  uint32                            data2_len,
  uint8*                            digest_ptr
)
{
   secboot_error_type ret = E_SECBOOT_HASH_FAIL;

  if(CEML_HASH_ALGO_SHA256 == hash_algo)
  {
   SHA256_CTX c;
   SHA256_Init(&c);
   if(data1_in_ptr && data1_len)
   {
     SHA256_Update(&c,data1_in_ptr,data1_len);
   }
   
   if(data2_in_ptr && data2_len)
   {
     SHA256_Update(&c,data2_in_ptr,data2_len);
   }    
   SHA256_Final(digest_ptr,&c);
   OPENSSL_cleanse(&c,sizeof(c));
   ret = E_SECBOOT_SUCCESS;
  }
  else if (CEML_HASH_ALGO_SHA1 == hash_algo)
  {
   SHA_CTX c;
   SHA1_Init(&c);
   if(data1_in_ptr && data1_len)
   {
     SHA1_Update(&c,data1_in_ptr,data1_len);
   }
   
   if(data2_in_ptr && data2_len)
   {
     SHA1_Update(&c,data2_in_ptr,data2_len);
   }    
   SHA1_Final(digest_ptr,&c);
   OPENSSL_cleanse(&c,sizeof(c));
   ret = E_SECBOOT_SUCCESS;
  }
  return ret;
}

/**
* @brief This function hash two part data to get hash and compare with the input hash value.
*
* @param[in]         hash_algo         hash algo
*
* @param[in]         data1_to_hash     Buffer containing the first part data to hash
*
* @param[in]         data1_len         Length of the first part buffer
*
* @param[in]         data2_to_hash     Buffer containing the second part data to hash
*
* @param[in]         data2_len         Length of the second part buffer
*
* @param[in]         hash_to_cmp       hash value to compare
*
* @return E_SECBOOT_SUCCESS on success. Appropriate error code on failure.
*
* @dependencies None
*
* @sideeffects  None
*
* @see None
*
*/
 secboot_error_type secboot_calc_and_cmp_hash
(
  CeMLHashAlgoType                  hash_algo,
  const uint8*                      data1_to_hash,
  uint32                            data1_len,
  const uint8*                      data2_to_hash,
  uint32                            data2_len,
  const uint8*                      hash_to_cmp
)
{ 
  unsigned char  image_hash[CEML_HASH_DIGEST_SIZE_SHA256] = {0};

  if(hash_to_cmp == NULL)
  {
    return E_SECBOOT_INVALID_PARAM;
  }

  secboot_hash(CEML_HASH_ALGO_SHA256, data1_to_hash, data1_len, data2_to_hash,data2_len,image_hash);
  if (memcmp( (uint8*) hash_to_cmp,
              (uint8*) image_hash,
              SECBOOT_HASH_LEN(hash_algo) ) == 0)
  {
    return E_SECBOOT_SUCCESS;
  }
  else
  {
    return E_SECBOOT_INVALID_IMAGE_SIG;
  }
}
 

/**
 * @brief This function hashes each certificate and stores the hash of each cert
 *        in the cert structure
 *
 * @param[in]         secboot_hash_handle_ptr    Pointer to the hash handle.
 * 
 * @param[in]         x509_cert_chain_ptr        Pointer to start of the certificate chain buffer
 *
 * @param[in]         x509_cert_list_ptr         Pointer to the parsed certificates
 *
 * @return E_SECBOOT_SUCCESS on success. Appropriate error code on failure.
 *
 * @dependencies Caller should ensure all pointers and lengths passed in are valid
 *
 * @sideeffects  None
 *           
 * @see None
 *
 */
static secboot_error_type secboot_hash_certificates
(
  const uint8*                       x509_cert_chain_ptr,
  const lk_secx509_cert_list_type*  x509_cert_list_ptr
)
{
  secboot_error_type     ret_val = E_SECBOOT_SUCCESS;
  uint32                 curr_cert_num = 0;
  const uint8*           data_ptr;
  uint32                 data_len;
  CeMLHashAlgoType       hash_algo;
  lk_secx509_cert_type* cert_ptr = NULL;

  do
  {
    if ((NULL == x509_cert_chain_ptr) ||
        (NULL == x509_cert_list_ptr))
    {
      ret_val = E_SECBOOT_INVALID_PARAM;
      break;
    }
    
    cert_ptr = (lk_secx509_cert_type* )&(x509_cert_list_ptr->cert[curr_cert_num]);
    //find the hash algorithm to use
    if (curr_cert_num == x509_cert_list_ptr->size - 1)
    {
      //This is the root certificiate.        
      //We validate this certificate by hashing the ENTIRE cert (start to the end of the cert sig)
      //using SHA256. This will later on be compared with the hash of the trusted root certificate
      hash_algo = CEML_HASH_ALGO_SHA256;
      data_ptr = x509_cert_chain_ptr;
      data_len = x509_cert_list_ptr->cert[curr_cert_num].asn1_size_in_bytes;
    }
    else
    {
      if (x509_cert_list_ptr->cert[curr_cert_num].sig_algo == SECX509_sha1WithRSAEncryption)
      {
        hash_algo = CEML_HASH_ALGO_SHA1;
      }
      else if (x509_cert_list_ptr->cert[curr_cert_num].sig_algo
              == SECX509_sha256WithRSAEncryption)
      {
        hash_algo = CEML_HASH_ALGO_SHA256;
      }
      else
      {
        ret_val = E_SECBOOT_UNSUPPORTED;
        break;
      }

      //For non-root certificates, we validate the certificate by hashing the certificate
      //from start of the certificate to the start of the certificate signature,
      //as the hash will be compared later on with the hash in the signature
      data_ptr = x509_cert_chain_ptr + cert_ptr->cinf_offset;
      data_len = cert_ptr->cinf_byte_len;
    }

    secboot_hash(hash_algo, (const unsigned char *)data_ptr, data_len, NULL,0,cert_ptr->cert_hash);

    //move to the start of next certificate
    x509_cert_chain_ptr += x509_cert_list_ptr->cert[curr_cert_num].asn1_size_in_bytes;
   
    //increment cert number
    curr_cert_num++;
  }while (curr_cert_num < x509_cert_list_ptr->size);
  return ret_val;
}

#define SIGNATURE_SIZE 384   /*signature size of RSA3072 is 384*/


 /*
  * Returns -1 if decryption failed otherwise size of plain_text in bytes
  */
 int secboot_decrypt_signature_rsa(unsigned char *signature_ptr,
     unsigned char *plain_text, RSA *rsa_key)
 {
   int ret = -1;
   char err_msg[128] = {0};
   if (rsa_key == NULL) {
     SECBOOT_PRINT("ERROR: Boot Invalid, RSA_KEY is NULL!\n");
     return ret;
   }
   ret = RSA_public_decrypt(SIGNATURE_SIZE, signature_ptr, plain_text,
          rsa_key, RSA_NO_PADDING);

   if(-1 == ret)
  {
    ERR_error_string(ERR_get_error(),err_msg);
    dprintf(CRITICAL,"%d_%s(): DEBUG openssl: error = %s\n",__LINE__, __func__, err_msg);
  }
 
   return ret;
 }

/**
* @brief This function call openssl to decrypt signature to get hash value
*
* @param[in]         signature_ptr        Pointer to signature data
*
* @param[in]         cert_ptr             Attestion certificate to decrypt signature
*
* @param[in]         cert_size            Attestion certificate size
*
* @param[out]        plain_text           Decypted out signature data
*
* @return 0 on success. -1 on failure.
*
* @dependencies None
*
* @sideeffects  None
*
* @see None
*
*/
 int secboot_decrypt_signature(
    unsigned char *signature_ptr,
    unsigned char *cert_ptr,
    uint32 cert_size,
    unsigned char *plain_text)

{
  X509 *x509_certificate = NULL;
  EVP_PKEY *pub_key = NULL;
  RSA *rsa_key = NULL;
  //CeMLHashAlgoType hash_algo;
  int ret = -1;
  unsigned char decrypt_data[SIGNATURE_SIZE]={0}; 
 
  if ((x509_certificate = ( X509 *)d2i_X509(NULL, (const unsigned char **)&cert_ptr, cert_size)) == NULL)
  {
    dprintf(CRITICAL,"ERROR: Image Invalid, X509_Certificate is NULL!\n");
    goto cleanup;
  }
  
  pub_key = X509_get_pubkey(x509_certificate);
  if (pub_key == NULL) {
    dprintf(CRITICAL, "ERROR: Boot Invalid, PUB_KEY is NULL!\n");
    goto cleanup;
  }
  
  rsa_key = EVP_PKEY_get1_RSA(pub_key);
  if (rsa_key == NULL) {
    dprintf(CRITICAL, "ERROR: Boot Invalid, RSA_KEY is NULL!\n");
    goto cleanup;
  }

  dprintf(INFO,"L%d_%s(): will call image_decrypt_signature_rsa.\n", __LINE__,__func__);
  ret = secboot_decrypt_signature_rsa(signature_ptr, decrypt_data, rsa_key);
  dprintf(INFO,"L%d_%s():DEBUG openssl: Return of RSA_public_decrypt = %d\n", __LINE__,__func__, ret);

  memcpy(plain_text, decrypt_data + ret-32, 32); /* remove padding, and get last valid 32bits hash data  */

cleanup:
  if (rsa_key != NULL)
  RSA_free(rsa_key);
  if (x509_certificate != NULL)
  X509_free(x509_certificate);
  if (pub_key != NULL)
  EVP_PKEY_free(pub_key);
  return ret;

}
/**
 * @brief This function verifies a certificate's signature using the public RSA key
 *        in the certificate that signed it
 *
 * @param[in]         cert_list_ptr        Pointer to the list of parsed certificates
 * 
 * @param[in]         verifier_index       Index of the certificate in the cert list
 *                                         that should be used to verify the verifee
 *                                         certificates signature
 *
 * @param[in]         verifier_index       Index of the certificate in the cert list
 *                                         whose signature needs to be verified
 *
 * @return E_SECBOOT_SUCCESS on success. Appropriate error code on failure.
 *
 * @dependencies None
 *
 * @sideeffects  None
 *           
 * @see None
 *
 */
static secboot_error_type secboot_verify_cert_signature
(
  const lk_secx509_cert_list_type*  cert_list_ptr,
  uint8*                             cert_ptr,   /*add to get cert offset*/
  uint32                             verifier_index,
  uint32                             verifiee_index
)
{
  secboot_error_type ret_val = E_SECBOOT_FAILURE;
  uint8 ret = -1;
  //uint32           j;
  uint8 plain_text[32];
  CeMLHashAlgoType hash_algo;
  int i = 0; /* debug purpose.*/ 
  /* Sanity check the parameters */
  if ( (cert_list_ptr == NULL)
       ||
       (verifier_index >= SECBOOT_MAX_NUM_CERTS)
       ||
       (verifiee_index >= SECBOOT_MAX_NUM_CERTS) )
  {
    return E_SECBOOT_INVALID_PARAM;
  }
  if (cert_list_ptr->cert[verifiee_index].sig_algo == SECX509_sha1WithRSAEncryption)
  {
    hash_algo = CEML_HASH_ALGO_SHA1;
  }
  else if (cert_list_ptr->cert[verifiee_index].sig_algo == SECX509_sha256WithRSAEncryption)
  {
    hash_algo = CEML_HASH_ALGO_SHA256;
  }
  else
  {
    ret_val = E_SECBOOT_UNSUPPORTED;
    return ret_val;//break;
  }

  ret = secboot_decrypt_signature((unsigned char *)cert_list_ptr->cert[verifiee_index].sig,
    (unsigned char *)cert_ptr, //(unsigned char *)&(cert_list_ptr->cert[verifier_index].cert_info),
    cert_list_ptr->cert[verifier_index].asn1_size_in_bytes,
    plain_text);
    
  if(0 < ret)
  {
    if ( memcmp( (uint8*) plain_text,
                 (uint8*) cert_list_ptr->cert[verifiee_index].cert_hash,
                 SECBOOT_HASH_LEN(hash_algo) ) == 0)
    {
      /* So far - so good ... */
      ret_val = E_SECBOOT_SUCCESS;
    }
  }
  return ret_val;
}


/**
 * @brief This function verifies the certificate chain
 *
 * @param[in]         x509_cert_list_ptr        Pointer to list of parsed certificates, starting
 *                                              with the attestation certificate
 *
 * @param[in]         root_of_trust_ptr         Pointer to the root of trust to validate the
 *                                              certificate chain's root cert against
 *
 *
 * @return E_SECBOOT_SUCCESS on success. Appropriate error code on failure.
 *
 * @dependencies Caller should ensure all pointers and lengths passed in are valid
 *
 * @sideeffects  None
 *           
 * @see None
 *
 */
static secboot_error_type secboot_verify_cert_chain
(
  const uint8*                 x509_cert_chain_ptr,  /*added by szhang */
  lk_secx509_cert_list_type*  x509_cert_list_ptr,
  const uint8*                 root_of_trust_ptr
)
{
  secboot_error_type         ret_val = E_SECBOOT_SUCCESS;
  lk_secx509_cert_ctx_type  boot_x509_ctx;
  uint32                     curr_cert_num = 0;
  uint32                     num_cert_sigs_to_verify;
  secx509_errno_enum_type    x509_result;
  uint8*  cert_ptr = (uint8* )x509_cert_chain_ptr;
  
  do
  {

    if ((NULL == x509_cert_list_ptr) ||
        /*(NULL == root_of_trust_ptr) ||*/
        (x509_cert_list_ptr->size < SECBOOT_MIN_NUM_CERTS) ||
        (x509_cert_list_ptr->size > SECBOOT_MAX_NUM_CERTS))
    {
      ret_val = E_SECBOOT_INVALID_PARAM;
      break;
    }

    //We verify the root certificate by comparing the hash of the entire root certificate
    //to the known root of trust. The remaining certs are verified through their signatures
    //so by default number of cert signatures to verify is total number of certs - the root cert
    num_cert_sigs_to_verify = x509_cert_list_ptr->size - 1;

    // Set up the X.509 context for the cert parser
    boot_x509_ctx.ca_list = NULL;
    boot_x509_ctx.purpose = SECX509_KEY_USAGE_DIG_SIG;
    boot_x509_ctx.depth   = ATTEST_CERT_INDEX;

    // Check if certificates are valid
    x509_result = lk_secx509_check_cert_list( x509_cert_list_ptr,
                                               &boot_x509_ctx );
    if (E_X509_SUCCESS != x509_result)
    {
      ret_val = E_SECBOOT_INVALID_CERT;
      break;
    }

    for ( curr_cert_num = 0;  curr_cert_num < num_cert_sigs_to_verify;  curr_cert_num++)
    {
      cert_ptr += x509_cert_list_ptr->cert[curr_cert_num].asn1_size_in_bytes;
      if (secboot_verify_cert_signature(x509_cert_list_ptr,
                                        cert_ptr,  /* added by szhang, cert address. auth by openssl api */
                                        curr_cert_num + 1,
                                        curr_cert_num) != E_SECBOOT_SUCCESS)
      {
        ret_val = E_SECBOOT_INVALID_CERT_SIG;
        break;
      }
    }
    if (E_SECBOOT_SUCCESS != ret_val)
    {
      dprintf(CRITICAL,"L%d_%s(): ret_val=%d\n", __LINE__,__func__,ret_val);
      break;
    }

    //ALWAYS ALWAYS ensure the root certificate is trusted
    ret_val = memcmp(x509_cert_list_ptr->cert[x509_cert_list_ptr->size - 1].cert_hash, root_of_trust_ptr, 
                     CEML_HASH_DIGEST_SIZE_SHA256) == 0 ? E_SECBOOT_SUCCESS : E_SECBOOT_UNTRUSTED_ROOT;

  }while (0);
  return ret_val;
}

/**
 * @brief This function verifies an image signature
 *
 * @param[in,out]     attestation_cert_info_ptr Pointer to the attestation certificate.
 *
 * @param[in]         secboot_hash_handle_ptr   Pointer to the hash handle
 *
 * @param[in]         image_info_ptr            Pointer to the image
 *
 * @param[in]         msm_hw_id                 Pointer to the msm hardware id as constructed
 *                                              from the fuses
 *
 * @param[in]         ou_sw_id                  Pointer to the software id in the OU field
 *                                              of the attestation certificate
 *
 * @param[in,out]     image_hash_info_ptr       Pointer to a structure to be populated.
 *                                              with the hash of the image
 *
 * @return E_SECBOOT_SUCCESS on success. Appropriate error code on failure.
 *
 * @dependencies Caller should ensure all pointers and lengths passed in are valid
 *
 * @sideeffects  None
 *           
 * @see None
 *
 */
static secboot_error_type secboot_verify_image_signature
(
  const lk_secx509_cert_type*     attestation_cert_info_ptr,
  const secboot_image_info_type*   image_info_ptr,
  uint64                           msm_hw_id,
  uint64                           ou_sw_id,
  secx509_code_hash_algo_type      code_hash_algo,
  secboot_image_hash_info_type*    image_hash_info_ptr
)
{
  unsigned char   image_hash[CEML_HASH_DIGEST_SIZE_SHA256] = {0};
  unsigned char   inner_hash[CEML_HASH_DIGEST_SIZE_SHA256] = {0};
  unsigned char   outer_hash[CEML_HASH_DIGEST_SIZE_SHA256] = {0};
  unsigned char   work_buff[40];   /* big enough for ipad and opad stuff */
  uint32   ipad      = 0x36;
  uint32   opad      = 0x5c;
  unsigned char   sw_id[8]  = {0};
  unsigned char   msm_id[8] = {0};
  uint32          i;
  secboot_error_type  ret_val = E_SECBOOT_FAILURE;
  CeMLHashAlgoType algo = CEML_HASH_ALGO_SHA1; //we default to SHA1
  unsigned char   decrypt_sig[32]={0};
  unsigned char   *decrypt_sig_prt = NULL;

  decrypt_sig_prt = decrypt_sig;
  /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
  do /* To break on errors */
  {
    if ((NULL == attestation_cert_info_ptr) ||
        (NULL == image_info_ptr) ||
        (NULL == image_hash_info_ptr))
    {
      ret_val = E_SECBOOT_INVALID_PARAM;
      break;
    }

    //In order for SHA256 to be used it needs to be in the attestation certs
    //hash algo OU field. We default to SHA1 otherwise, for legacy reasons
    if (E_X509_CODE_HASH_SHA256==code_hash_algo)
    {
      algo = CEML_HASH_ALGO_SHA256;
    }
    
    /* Hash the image */
    secboot_hash(algo, image_info_ptr->header_ptr_1,image_info_ptr->header_len_1,
      image_info_ptr->code_ptr_1, image_info_ptr->code_len_1, image_hash);


    /* assign the code address that we hashed for UEFI use later in the */
    /* boot chain */
    image_hash_info_ptr->code_address = (uint32)image_info_ptr->code_ptr_1;
    image_hash_info_ptr->code_length = image_info_ptr->code_len_1;
    image_hash_info_ptr->image_hash_length = SECBOOT_HASH_LEN(algo);
    if (sizeof(image_hash_info_ptr->image_hash) < image_hash_info_ptr->image_hash_length)
    {
      ret_val = E_SECBOOT_INVALID_PARAM;
      break;      
    }
    memcpy(image_hash_info_ptr->image_hash, image_hash, image_hash_info_ptr->image_hash_length);

    /* Compute inner hash.                                              */
    /* Consult design doc for details on this non-standard hash usage.  */
    /* In short, sbl_proc_hash =                                        */
    /*   H[(MSM ID ^ opad) || H[(SWID ^ ipad) || H(code image)] ],      */
    /* where H = the hash specificed by signature hash type             */
    memset( work_buff, 0 , sizeof( work_buff ) );
    memcpy( (uint8*) msm_id, (uint8*) &msm_hw_id, sizeof( msm_hw_id ) );
    memcpy( (uint8*) sw_id, (uint8*) &ou_sw_id, sizeof( ou_sw_id ) );

    /* 'Si' first added in the front */
    for ( i=0; i < 8; i++)
    {
      BSTOR8( work_buff+i, ipad ^ BLOAD8(sw_id+7-i) );
    }

    /* Process (SWID ^ ipad) */ 
    /* Process H(code image) */    
    secboot_hash(algo,(const uint8 *) work_buff, 8, (const uint8 *)image_hash,sizeof(image_hash),inner_hash);

    /* Compute outer hash function. */
    memset( work_buff, 0 , sizeof(work_buff) );

    /* 'So' pad first added in the front */
    for (i = 0; i < 8; i++)
    {
      BSTOR8( work_buff+i, opad ^ BLOAD8(msm_id+7-i) );
    }

    secboot_hash(algo,(const uint8 *)work_buff,8,(const uint8 *)inner_hash,sizeof(inner_hash),outer_hash);

    /* Now H[(MSM ID ^ opad) || H[(SWID ^ ipad) || H(code image)] ]
         is in hash_out */

    /* using <= combines the check for integer overflow and the check of length equal to 0. */
    if ( (NULL == attestation_cert_info_ptr->pkey.key.rsa.mod_data) ||
         ((uint32)attestation_cert_info_ptr->pkey.key.rsa.mod_data +
            attestation_cert_info_ptr->pkey.key.rsa.mod_len <= 
              (uint32)attestation_cert_info_ptr->pkey.key.rsa.mod_data) ||
         (attestation_cert_info_ptr->pkey.key.rsa.mod_len > SECBOOT_MAX_KEY_SIZE_IN_BITS/8) ||
         (NULL == attestation_cert_info_ptr->pkey.key.rsa.exp_e_data) ||
         ((uint32)attestation_cert_info_ptr->pkey.key.rsa.exp_e_data +
            attestation_cert_info_ptr->pkey.key.rsa.exp_e_len <=
              (uint32)attestation_cert_info_ptr->pkey.key.rsa.exp_e_data) ||
         (attestation_cert_info_ptr->pkey.key.rsa.exp_e_len > 4) )
    {
      ret_val = E_SECBOOT_INVALID_DATA;
      break;
    }

    //Check that the exponent is 3 or 65537
    ret_val = secboot_verify_exponent(attestation_cert_info_ptr->pkey.key.rsa.exp_e_data, 
                                      attestation_cert_info_ptr->pkey.key.rsa.exp_e_len);
    if (E_SECBOOT_SUCCESS != ret_val)
    {
      //MSG_ERROR( "secboot: invalid exponent", 0, 0, 0 );
      ret_val = E_SECBOOT_INVALID_DATA;
      break;
    }


    /*** Verify the hash with signature ***/
    secboot_decrypt_signature((unsigned char *)image_info_ptr->signature_ptr,
    (unsigned char *)image_info_ptr->x509_chain_ptr, 
    attestation_cert_info_ptr->asn1_size_in_bytes,
    decrypt_sig_prt);
   
    /* Last step - Code to byte compare decrypted signature and hash */
    if (memcmp( (uint8*) outer_hash,
                (uint8*) decrypt_sig_prt,
                SECBOOT_HASH_LEN(algo) ) == 0)
    {
      ret_val = E_SECBOOT_SUCCESS;
    }
    else
    {
      ret_val = E_SECBOOT_INVALID_IMAGE_SIG;
    }

  }/*lint -e(717) */ while (FALSE);

  return ret_val;

}   /* secboot_verify_image_signature() */

/************
 *
 * Name:     sierra_smem_get_auth_en
 *
 * Purpose:  get AUTH_EN flag from share memory
 *
 * Parms:    NONE
 *
 * Return:   TRUE if secure boot enable
 *           FALSE if secure boot not enalbe.
 *
 * Abort:    GEt smem address failed
 *
 * Notes:    none
 *
 ************/
boolean sierra_smem_get_auth_en(void)
{
  struct bs_smem_secboot_info *secbinfop = NULL;
  unsigned char *virtual_addr = NULL;
  int auth_en = 0;
  uint32_t calc_crc= 0;

  virtual_addr = sierra_smem_base_addr_get();
  if (virtual_addr)
  {
    virtual_addr += BSMEM_SECB_OFFSET;

    secbinfop = (struct bs_smem_secboot_info *)virtual_addr;
    if (secbinfop == NULL) {
      dprintf(CRITICAL, "ERROR: can't get secboot smem data\n");
      ASSERT(0);
    }
    calc_crc = crcrc32((uint8 *)secbinfop, (sizeof(struct bs_smem_secboot_info) - sizeof(uint32_t)), (uint32)CRSTART_CRC32);
    if (secbinfop->magic_beg == BS_SMEM_SECBOOT_MAGIC_BEG &&
      secbinfop->magic_end == BS_SMEM_SECBOOT_MAGIC_BEG &&
      secbinfop->crc32 == calc_crc)
    {
      auth_en = secbinfop->auth_enable;
    }

    dprintf(INFO, "magic_beg=0x%x,magic_end=0x%x,auth_en=%d,crc32=0x%x,calc_crc=0x%x\n",
    secbinfop->magic_beg, secbinfop->magic_end, auth_en, secbinfop->crc32, calc_crc);
  }

  return auth_en;
}

/************
 *
 * Name:     sierra_smem_get_hw_fuses
 *
 * Purpose:  get HW fuses from share memory
 *
 * Parms:    NONE
 *
 * Return:   TRUE if Get HW fuses succeed.
 *           FALSE if Get HW fuses failed.
 *
 * Abort:    GEt smem address failed
 *
 * Notes:    none
 *
 ************/
boolean sierra_smem_get_hw_fuses(secboot_fuse_info_type*  fuse_info_ptr)
{
  struct bs_smem_secboot_info *secbinfop = NULL;
  unsigned char *virtual_addr = NULL;
  boolean ret = FALSE;
  uint32_t calc_crc= 0;

  virtual_addr = sierra_smem_base_addr_get();
  if (virtual_addr)
  {
    virtual_addr += BSMEM_SECB_OFFSET;

    secbinfop = (struct bs_smem_secboot_info *)virtual_addr;
    if (secbinfop == NULL) {
      dprintf(CRITICAL, "ERROR: can't get secboot smem data\n");
      ASSERT(0);
    }
    calc_crc = crcrc32((uint8 *)secbinfop, (sizeof(struct bs_smem_secboot_info) - sizeof(uint32_t)), (uint32)CRSTART_CRC32);
    if (secbinfop->magic_beg == BS_SMEM_SECBOOT_MAGIC_BEG &&
      secbinfop->magic_end == BS_SMEM_SECBOOT_MAGIC_BEG &&
      secbinfop->crc32 == calc_crc)
    {
      fuse_info_ptr->msm_hw_id = secbinfop->fuse_info.msm_hw_id;
      fuse_info_ptr->serial_num = secbinfop->fuse_info.serial_num;
      memcpy(fuse_info_ptr->root_of_trust, secbinfop->fuse_info.root_of_trust, CEML_HASH_DIGEST_SIZE_SHA256);
      ret = TRUE;
    }
  }
  return ret;
}


/************
*
* Name:     boot_swi_lk_auth_kernel
*
* Purpose:  get image data and call image_authenticate to auth kernel image.
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
* Notes:    none
*
************/
boolean image_authenticate(secboot_image_info_type* secboot_info_ptr, secboot_verified_info_type* verified_info_ptr)
{
  boolean ret = FALSE;
  secboot_error_type           ret_val    = E_SECBOOT_FAILURE;
  secx509_errno_enum_type      x509_result = E_X509_FAILURE;
  lk_secx509_cert_list_type   lk_secx509_cert_list;  
  secx509_ou_field_info_type   ou_field_info;
  secboot_fuse_info_type       fuse_info;
  uint32 secboot_handle[128]={0}; /**< 512 byte buffer needed by secboot for it's operations */
  
  
  dprintf(INFO,"sw_id:0x%x, hdr_size:0x%x, code_szie:0x%x, sig_size:0x%x, certs_size:0x%x\n",secboot_info_ptr->sw_type,
   secboot_info_ptr->header_len_1, secboot_info_ptr->code_len_1, secboot_info_ptr->signature_len,secboot_info_ptr->x509_chain_len);

  do
  {
    //Check Pointers ,Lengths, Boundary and Integer overflows (wrap around)
        // using <= combines the check for integer overflow and the check of length equal to 0
    if ((secboot_info_ptr == NULL) ||
        (verified_info_ptr == NULL) ||
        (secboot_info_ptr->header_ptr_1 == NULL) ||
        ((uint32)secboot_info_ptr->header_ptr_1 + secboot_info_ptr->header_len_1 <= (uint32)secboot_info_ptr->header_ptr_1) ||
        (secboot_info_ptr->code_ptr_1 == NULL) ||
        ((uint32)secboot_info_ptr->code_ptr_1 + secboot_info_ptr->code_len_1 <= (uint32)secboot_info_ptr->code_ptr_1) ||
        (secboot_info_ptr->x509_chain_ptr == NULL) ||
        ((uint32)secboot_info_ptr->x509_chain_ptr + secboot_info_ptr->x509_chain_len <= (uint32)secboot_info_ptr->x509_chain_ptr) ||
        (secboot_info_ptr->x509_chain_len > SECBOOT_MAX_CERT_CHAIN_SIZE) ||
        (secboot_info_ptr->signature_ptr == NULL) ||
        ((uint32)secboot_info_ptr->signature_ptr + secboot_info_ptr->signature_len <= (uint32)secboot_info_ptr->signature_ptr) ||
        (secboot_info_ptr->signature_len > (SECBOOT_MAX_KEY_SIZE_IN_BITS/8))
        )
    {
      ret_val = E_SECBOOT_INVALID_PARAM;
      break;
    }
    
    memset((uint8*)verified_info_ptr, 0, sizeof(secboot_verified_info_type));
    memset((uint8*)&lk_secx509_cert_list, 0 , sizeof(lk_secx509_cert_list));
    memset((uint8*)&ou_field_info, 0, sizeof(ou_field_info));
    memset((uint8*)&fuse_info, 0, sizeof(fuse_info));


    //fuse_info, get from sharememeory
    sierra_smem_get_hw_fuses(&fuse_info);
    dprintf(INFO,"get hw fuse, hw_id=0x%llx,sn=0x%xd.\n", fuse_info.msm_hw_id,fuse_info.serial_num);
    
    //parse the certificate chain 
    dprintf(INFO,"start to parese cert.\n");
    x509_result = lk_secx509_parse_cert_buffer(secboot_info_ptr->x509_chain_ptr,
                                                 secboot_info_ptr->x509_chain_len,
                                                 &lk_secx509_cert_list,
                                                 &ou_field_info);

     dprintf(INFO, "cert size=%d, cert1_size:%d,cert2_size:%d,cert3_size:%d\n", 
      lk_secx509_cert_list.size, lk_secx509_cert_list.cert[0].asn1_size_in_bytes ,
      lk_secx509_cert_list.cert[1].asn1_size_in_bytes,lk_secx509_cert_list.cert[2].asn1_size_in_bytes);

    if (E_X509_SUCCESS != x509_result)
    {
      ret_val = E_SECBOOT_X509_FAIL;
      break;
    }

    //Ensure the software is what the caller is expecting.
    if ((secboot_info_ptr->sw_type & 0xFFFF0000) != 0)
    {
      //caller gave us 2 software types to allow
      if (! ( (((uint32)ou_field_info.sw_id) == (secboot_info_ptr->sw_type >> 16)) ||
              (((uint32)ou_field_info.sw_id) == (secboot_info_ptr->sw_type & 0xFFFF))
            ))
      {
        ret_val = E_SECBOOT_INVALID_SW_TYPE;
        break;
      }      
    }
    else
    {
        //caller gave us 1 software types to allow
        if (((uint32)ou_field_info.sw_id) != secboot_info_ptr->sw_type)
        {
          ret_val = E_SECBOOT_INVALID_SW_TYPE;
          break;
        }
    }
      
    //Check for anti-rollback i.e image is not older than what is supported
    if ((ou_field_info.sw_id >> 32) < (secboot_info_ptr->sw_version))
    {
      ret_val = E_SECBOOT_INVALID_SW_VERSION;
      break;
    }

    //hash the certificates
    dprintf(INFO,"start to hash certs.\n");
    ret_val = secboot_hash_certificates(secboot_info_ptr->x509_chain_ptr,
                                        &lk_secx509_cert_list);
    dprintf(INFO,"hash certs ret_val=%d\n", ret_val);
    BREAKIF(E_SECBOOT_SUCCESS != ret_val);
    
    //verify the certificate chain along with the root certificate
    ret_val = secboot_verify_cert_chain(secboot_info_ptr->x509_chain_ptr, /*add by stan*/
                                        &lk_secx509_cert_list,
                                        fuse_info.root_of_trust);
    dprintf(INFO,"verify certchain ret_val=%d\n",ret_val);
    BREAKIF(E_SECBOOT_SUCCESS != ret_val);

    //verify the image signature
    ret_val = secboot_verify_image_signature(lk_secx509_cert_list.cert,
                                             secboot_info_ptr,
                                             ou_field_info.hw_id,
                                             ou_field_info.sw_id,
                                             ou_field_info.code_hash_algo,
                                             &(verified_info_ptr->image_hash_info));
    dprintf(INFO,"verify signature, ret_val=%d\n", ret_val);
    BREAKIF(E_SECBOOT_SUCCESS != ret_val);
    
    verified_info_ptr->sw_id = ou_field_info.sw_id;
    verified_info_ptr->msm_hw_id = ou_field_info.hw_id;//fuse_info.msm_hw_id;
    
    // Set debug to disable, as missing debug ou is equal to debug disabled
    verified_info_ptr->enable_debug = SECBOOT_DEBUG_DISABLE;

    // We've come this far without any errors
    ret_val = E_SECBOOT_SUCCESS;
  } while (0);
  dprintf(INFO,"ret=%d, sw_id:0x%llx,\n", ret_val, ou_field_info.sw_id);
  if(E_SECBOOT_SUCCESS == ret_val)
  {
    ret = TRUE;
  }
  return ret;
}

/************
 *
 * Name:     boot_swi_lk_auth_kernel
 *
 * Purpose:  get image data and call image_authenticate to auth kernel image.
 *
 * Parms:    ptn  --- struct ptentry for kernel iamge
 *
 *           hdr  --- Kernel image header.
 *
 * Return:   TRUE if auth succeed.
 *           FALSE if auth failed.
 *
 * Abort:    none
 *
 * Notes:    none
 *
 ************/
boolean boot_swi_lk_auth_kernel(struct ptentry *ptn,boot_img_hdr *hdr)
{
  unsigned kernel_actual;
  unsigned ramdisk_actual;
  unsigned second_actual;
  unsigned dt_actual;
  unsigned offset = 0;
  unsigned image_total_size = 0;
  unsigned read_size = 0;
  mi_boot_image_header_type *mbn_header_ptr = 0;
  unsigned char *image_addr = NULL;
  secboot_image_info_type secboot_image_info;
  secboot_verified_info_type verified_info;
  unsigned page_size = 0;
  unsigned page_mask = 0;

  page_size = flash_page_size();
  page_mask = page_size - 1;

  memset((void*)&secboot_image_info, 0, sizeof(secboot_image_info));
  secboot_image_info.sw_type = SECBOOT_SWI_APPS_SW_TYPE;

  /*Get some temp buff for auth. use buffer from half of SCRATCH_REGION2 */
  image_addr = (unsigned char *)target_get_scratch_address();
  mbn_header_ptr = (mi_boot_image_header_type *)(image_addr + target_get_max_flash_size()/2);

  /*Get acutal size of each segments */
  kernel_actual = ROUND_TO_PAGE(hdr->kernel_size, page_mask);
  ramdisk_actual = ROUND_TO_PAGE(hdr->ramdisk_size, page_mask);
  second_actual = ROUND_TO_PAGE(hdr->second_size, page_mask);
  dt_actual = ROUND_TO_PAGE(hdr->dt_size, page_mask);

  /* Get MBN header offset, kernel image have aligned to page size */
  offset = page_size + kernel_actual + ramdisk_actual + second_actual + dt_actual;
  image_total_size = offset;

  /* Read MBN head page, it will also read out siganture and part of cert chain */
  if(flash_read(ptn, offset,(void *)mbn_header_ptr, page_size)) 
  {
    dprintf(CRITICAL, "ERROR: Cannot read mbn header, mbn_hdrp = 0x%x\n",(unsigned int)mbn_header_ptr);
    return FALSE;
  }

  dprintf(INFO, "mbn header offset:0x%x, code_szie:0x%x, sig_size:0x%x, certs_size:0x%x\n",
      offset, mbn_header_ptr->code_size, secboot_image_info.signature_len, secboot_image_info.x509_chain_len);

  /* Check whether have MBN header; only signed image have MBN header + signature + certification chain */
  if((mbn_header_ptr->image_id == APPS_IMG)&&(mbn_header_ptr->image_size != 0)&&(mbn_header_ptr->image_size = 
      mbn_header_ptr->code_size+ mbn_header_ptr->signature_size + mbn_header_ptr->cert_chain_size) )
  { /* have MBN header*/
    secboot_image_info.header_ptr_1 = (const uint8*)mbn_header_ptr;
    secboot_image_info.header_len_1 = sizeof(mi_boot_image_header_type);
    secboot_image_info.signature_len = mbn_header_ptr->signature_size;
    secboot_image_info.x509_chain_len = mbn_header_ptr->cert_chain_size;
    secboot_image_info.code_len_1 = mbn_header_ptr->code_size;
  }
  else /*have not MBN header, mean image not signed*/
  {
    dprintf(CRITICAL, "MBN header is NULL\n");
    return FALSE;
  }

  /*Continue to read rest part of cert chain.*/
  image_addr= (unsigned char *)mbn_header_ptr;

  if(mbn_header_ptr->code_size > CEML_HASH_DIGEST_SIZE_SHA256) 
  /* Still support old format: Andriod + mbnhdr + sig(mbnhdr + Andriod) + certchain. */
  {
    read_size = secboot_image_info.header_len_1 + secboot_image_info.signature_len
      + secboot_image_info.x509_chain_len - page_size;

    secboot_image_info.signature_ptr = secboot_image_info.header_ptr_1 + secboot_image_info.header_len_1;
    secboot_image_info.x509_chain_ptr = secboot_image_info.signature_ptr + secboot_image_info.signature_len;
  }
  else /* new fomrat: Android + mbnhdr + Hash(Andirod) + sig(mbnhdr +Hash(Andriod)) + certchain */
  {
    read_size = secboot_image_info.header_len_1 + secboot_image_info.code_len_1 
        + secboot_image_info.signature_len + secboot_image_info.x509_chain_len - page_size;
    secboot_image_info.code_ptr_1 = secboot_image_info.header_ptr_1 + secboot_image_info.header_len_1;
    secboot_image_info.signature_ptr = secboot_image_info.code_ptr_1 + secboot_image_info.code_len_1;
    secboot_image_info.x509_chain_ptr = secboot_image_info.signature_ptr + secboot_image_info.signature_len;
  }
  read_size = ROUND_TO_PAGE(read_size, page_mask);
  offset += page_size;  /*we have read out one page data for mbn header.*/

  if(flash_read(ptn, offset,(void *)(image_addr + page_size), read_size)) {
  dprintf(CRITICAL, "ERROR: Cannot read rest of sign + cert chain.\n");
  return FALSE;
  }

  /*Start to read out image data. move or read all kernel image data together to RAM */
  image_addr = (unsigned char *)mbn_header_ptr + page_size +read_size; /*offset one page size from start address */
  if(mbn_header_ptr->code_size > CEML_HASH_DIGEST_SIZE_SHA256) 
  { 
    secboot_image_info.code_ptr_1 = (const uint8 *)image_addr;
  }
  /*First read boot_img_hdr page*/
  offset = 0;
  if(flash_read(ptn, offset, (void *)image_addr, page_size)) 
  {
    dprintf(CRITICAL, "ERROR: Cannot read kernel image header\n");
    return FALSE;
  }

  /* kernel and ramdisk have been read out to correct address, now collect them together to buff */
  offset +=  page_size;
  memmove((void*) (image_addr + page_size), (char *)hdr->kernel_addr, kernel_actual);
  offset += kernel_actual;
  memmove((void*) (image_addr + page_size + kernel_actual), (char *)hdr->ramdisk_addr, ramdisk_actual);
  offset += ramdisk_actual;

  /*for other image(e.g. device tree), just read from FLASH*/
  if(image_total_size - offset)
  {
    if(flash_read(ptn, offset,(void *)(image_addr + offset), image_total_size - offset)) 
    {
      dprintf(CRITICAL, "ERROR: Cannot read device tree, offset=0x%x, read_size=0x%x\n",offset,read_size);
      return FALSE;
    }
  }

  /* auth kernel image */
  if(!image_authenticate(&secboot_image_info,&verified_info))
  {
    dprintf(CRITICAL, "ERROR: authenticate image failed\n");
    return FALSE;
  }
  else
  {
    if(mbn_header_ptr->code_size == CEML_HASH_DIGEST_SIZE_SHA256) /* still to check hash */
    {
      if(E_SECBOOT_SUCCESS !=secboot_calc_and_cmp_hash(CEML_HASH_ALGO_SHA256, image_addr, 
      image_total_size, NULL,0,secboot_image_info.code_ptr_1) )
      {
        dprintf(CRITICAL, "ERROR: Check andriod image hash failed\n");
        return FALSE;        
      }
    }
    dprintf(INFO,"%d_%s: authenticate image succeed.\n",__LINE__,__func__);
    return TRUE;
  }
}

