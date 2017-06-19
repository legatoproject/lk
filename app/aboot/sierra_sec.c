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
#include <boot_verifier.h>
#include <crypto_hash.h>
#include <dev/flash.h>
#include <openssl/x509.h>

#include "aaglobal_linux.h"
#include "aadebug_linux.h"
#include "sec_ssmem_structure.h"
#include "ssmemudefs.h"

#define PAGE_SZ_MAX           4096
#define CERT_CHAIN_SZ_MAX     3
/* 3 cert * 2K + signature: 8KB */
#define CERT_PAGE_MAX         4

/************
 *
 * Name:     cert_chain_info_s
 *
 * Purpose:  cert chain info structure
 *
 * Notes:    none
 *
 ************/
struct cert_chain_info_s
{
  X509 *cert_list[CERT_CHAIN_SZ_MAX];
  unsigned int num_cert;
};


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
 * Name:     sierra_sec_cert_chain_verify
 *
 * Purpose:  Verify a cert against a public key
 *
 * Parms:    certp  - cert to be verified
 *           pkeyp  - public key
 *
 * Return:   TRUE if verfied
 *           FALSE otherwise
 *
 * Abort:    none
 *
 * Notes:    cert signature must use sha256RSA algorithm.
 *           some old cert uses sha1 which will not be supported.
 *           This is a reduced version of X509_verify and only support
 *           sha256 algorithm
 *
 ************/
_local boolean sierra_sec_x509_verify(
  X509     *certp,
  EVP_PKEY *pkeyp)
{
  unsigned char *buf_in=NULL;
  RSA *rsa = NULL;
  int inl;
  boolean retval = FALSE;

  do
  {
    inl = ASN1_item_i2d((void *)certp->cert_info, &buf_in,
                        ASN1_ITEM_rptr(X509_CINF));
    if (!buf_in)
    {
      SWI_PRINT(SWI_ERROR, "SWI: cannot allocate buf_in\n");
    }

    rsa = EVP_PKEY_get1_RSA(pkeyp);
    if (!rsa)
    {
      SWI_PRINT(SWI_ERROR, "SWI: cannot get rsa from pkey\n");
      break;
    }

    retval = boot_verify_compare_sha256(buf_in, inl, certp->signature->data, rsa);
    if (!retval)
    {
      SWI_PRINT(SWI_ERROR, "SWI: signature verify error\n");
      break;
    }

  } while (0);

  if (buf_in)
  {
    OPENSSL_free(buf_in);
  }

  if (rsa)
  {
    RSA_free(rsa);
  }

  return retval;
}

/************
 *
 * Name:     sierra_sec_cert_chain_verify
 *
 * Purpose:  Verify cert chain
 *
 * Parms:    cert_listp  - cert list
 *
 * Return:   TRUE if verfied
 *           FALSE otherwise
 *
 * Abort:    none
 *
 * Notes:    none
 *
 ************/
_global boolean sierra_sec_cert_chain_verify(
  struct cert_chain_info_s *cert_chainp)
{
  unsigned int index;
  EVP_PKEY *pkeyp = NULL;
  boolean retval = TRUE;

  for (index = 1; index < cert_chainp->num_cert; index++)
  {
    /* get public key from cert[index] */
    pkeyp = X509_get_pubkey(cert_chainp->cert_list[index]);
    if (!pkeyp)
    {
      SWI_PRINT(SWI_ERROR, "SWI: cannot get pkey from cert %d\n", index);
      retval = FALSE;
      break;
    }

    /* user pkey to very cert[index - 1]
     * X509_verify will link lots of files which are not enabled in LK so
     * use a reduced version instead
     */
    retval = sierra_sec_x509_verify(cert_chainp->cert_list[index - 1], pkeyp);
	EVP_PKEY_free(pkeyp);
    if (!retval)
    {
      SWI_PRINT(SWI_ERROR, "SWI: signature error for cert %d\n", index - 1);
      break;
    }
  }

  return retval;
}

/************
 *
 * Name:     sierra_sec_oem_cert_verify
 *
 * Purpose:  Verify if provided cert matches OEM cert
 *
 * Parms:    certp  - signing cert pointer (already in X509 format)
 *           extra_certp - additional cert pointer in DER format
 *
 * Return:   TRUE if match
 *           FALSE otherwise
 *
 * Abort:    none
 *
 * Notes:    none
 *
 ************/
_global boolean sierra_sec_oem_cert_verify(
  uint8_t *certp,
  uint8_t *extra_certp)
{
  uint8_t hash[SEC_SHA256_HASH_LEN];
  const uint8_t *cert_datap, *cert_hashp;
  unsigned int size, index, cert_size;
  struct cert_chain_info_s cert_chain;
  boolean retval = FALSE;

  do
  {
    memset(&cert_chain, 0, sizeof(cert_chain));

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

    /* fill in the cert list */
    cert_chain.cert_list[0] = (X509 *)certp;
    cert_chain.num_cert = 1;

    /* optional additial certs */
    if (extra_certp)
    {
      for (index = 1; index < CERT_CHAIN_SZ_MAX; index++)
      {
        /* get next cert size */
        cert_size = read_der_message_length(extra_certp, PAGE_SZ_MAX);
        if (!cert_size)
        {
          /* not a valid cert */
          SWI_PRINT(SWI_ERROR, "SWI: invalid der message for cert %d\n", index);
          break;
        }

        cert_datap = extra_certp;
        cert_chain.cert_list[index] = d2i_X509(NULL, &cert_datap, cert_size);
        if (!cert_chain.cert_list[index])
        {
          /* invalid cert */
          SWI_PRINT(SWI_ERROR, "SWI: cannot load cert %d\n", index);
          break;
        }

        extra_certp += cert_size;
        cert_chain.num_cert++;
      }
    }

    /* verify cert chain if required */
    if (cert_chain.num_cert > 1)
    {
      if (!sierra_sec_cert_chain_verify(&cert_chain))
      {
        break;
      }
    }

    /* check root cert or the last cert against the injected hash */
    if(!X509_digest(cert_chain.cert_list[cert_chain.num_cert - 1],
                    EVP_sha256(), hash, &size))
    {
      SWI_PRINT(SWI_ERROR, "SWI: cert compare: Fail to hash cert\n");
      break;
    }

    if (memcmp(hash, cert_hashp, SEC_SHA256_HASH_LEN))
    {
      SWI_PRINT(SWI_ERROR, "SWI: oem cert hash not match\n");
    }
    else
    {
      SWI_PRINT(SWI_ERROR, "SWI: cert verification success\n");
      retval = TRUE;
    }
  } while (0);

  /* release certs buffered from extra_certs */
  for (index = 1; index < cert_chain.num_cert; index++)
  {
    if (cert_chain.cert_list[index])
    {
      X509_free(cert_chain.cert_list[index]);
    }
  }

  return retval;
}

/************
 *
 * Name:     sierra_sec_cert_page_read
 *
 * Purpose:  read more pages from partition for possible extra certs
 *
 * Parms:    ptn         - partition entry handle
 *           extra_certp - additional cert pointer in binary format
 *           imagep      - image RAM address to be saved to
 *           page_size   - page size per read
 *
 * Return:   TRUE if read OK
 *           FALSE otherwise
 *
 * Abort:    none
 *
 * Notes:    best effort read, these pages may not contain data
 *           and the first page (if 4KB) may already contains all the
 *           signature and cert chain data
 *           offset is the signature page and read will start at
 *           (offset + page size) and save to (imagep + page size)
 *
 ************/
_global boolean sierra_sec_cert_page_read(
  struct ptentry *ptn,
  unsigned int offset,
  uint8_t *imagep,
  unsigned int page_size)
{
  unsigned int page_index;

  for (page_index = 1; page_index < CERT_PAGE_MAX; page_index++)
  {
    if (flash_read(ptn, offset + (page_index * page_size),
                   (void *)(imagep + (page_index * page_size)),
                   page_size))
    {
      /* cannot read next page, normal condition, exit */
      break;
    }
  }

  return TRUE;
}
