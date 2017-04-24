/************
 *
 * Filename:  sierra_sec.c
 *
 * Purpose:   Sierra Little Kernel changes for secure boot           
 *
 * Copyright: (c) 2017 Sierra Wireless, Inc.
 *            All rights reserved
 *
 * Note:       
 *
 ************/
#include <stdint.h>
#include <string.h>
#include <target.h>
#include <debug.h>
#include <board.h>
#include <crypto_hash.h>
#include <openssl/x509.h>

#include "aaglobal_linux.h"
#include "aadebug_linux.h"
#include "sec_ssmem_structure.h"
#include "ssmemudefs.h"

/************
 *
 * Name:     sierra_sec_oem_cert_hash_get
 *
 * Purpose:  get OEM cert hash from SSMEM
 *
 * Parms:    none
 *
 * Return:   pointer to OEM cert hash
 *           or NULL if not exists
 *
 * Abort:    none
 *
 * Notes:    none
 *
 ************/
_global uint8_t *sierra_sec_oem_cert_hash_get(
  void)
{
  struct sec_ssmem_s *secp;
  int size;

  /* get from SSMEM */
  secp = ssmem_get(SSMEM_RG_ID_KEYS, SEC_SSMEM_VER, &size);
  if (secp)
  {
    return secp->cert_hash;
  }
  else
  {
    return NULL;
  }
}

/************
 *
 * Name:     sierra_sec_oem_cert_verify
 *
 * Purpose:  Verify if provided cert matches OEM cert
 *
 * Parms:    certp - cert pointer
 *
 * Return:   TRUE if match
 *           FALSE otherwise
 *
 * Abort:    none
 *
 * Notes:    none
 *
 ************/
_global boolean sierra_sec_oem_cert_compare(
  uint8_t *certp)
{
  uint8_t hash[SEC_SHA256_HASH_LEN], *cert_hashp;
  unsigned int size;
  X509 *cert;
  boolean retval = FALSE;

  do
  {
    cert_hashp = sierra_sec_oem_cert_hash_get();
    if (!cert_hashp)
    {
      /* auth not enabled, success */
      retval = TRUE;
      break;
    }

    if (!certp)
    {
      break;
    }

    cert = (X509 *)certp;

    /* calculate cert hash and compare with the injected one */
    if(!X509_digest(cert, EVP_sha256(), hash, &size))
    {
      SWI_PRINT(SWI_ERROR,"SWI: cert compare: Fail to hash cert\n");
      break;
    }

    if (memcmp(hash, cert_hashp, SEC_SHA256_HASH_LEN))
    {
      SWI_PRINT(SWI_ERROR,"SWI: oem cert hash not match\n");
    }
    else
    {
      retval = TRUE;
    }
  } while (0);

  return retval;
}
