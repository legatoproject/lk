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
#include <stdint.h>
#include <string.h>
#include <target.h>
#include <lib/ptable.h>
#include <dev/flash.h>
#include <debug.h>

#include <crypto_hash.h>

#include "bootimg.h"
#include "mach/sierra_smem.h"
#include "sierra_bludefs.h"
#include "sierra_secudefs.h"

#define ROUND_TO_PAGE(x,y) (((x) + (y)) & (~(y)))

/************
 *
 * Name:     sierra_smem_get_auth_en
 *
 * Purpose:  get AUTH_EN flag
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
boolean sierra_sec_get_auth_en(void)
{
  return *(uint32*)HWIO_QFPROM_CORR_OEM_SEC_BOOT_ROW0_LSB_V2_ADDR
      &HWIO_SECURE_BOOTn_V2_AUTH_EN_BMSK;
}

/************
 *
 * Name:     sierra_lk_enable_hash_check
 *
 * Purpose:  check whether need to check hash to validate image integrity
 *
 * Parms:    NONE
 *
 * Return:   TRUE  - check image hash
 *           FALSE - otherwise.
 *
 * Abort:    None
 *
 * Notes:    This function determines whether or not image hash verification should be
 *   skipped. Default behavior is to check hash to verify data.
 *   If secure boot is enabled, hash checking is forced active.
 *
 ************/

static boolean sierra_lk_enable_hash_check(void)
{
  if (sierra_sec_get_auth_en())
  {
    return TRUE;
  }
  else
  {
#ifdef ENABLE_HASH_CHECK
    return TRUE;
#else
    return FALSE;
#endif
  }
}

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
boolean sierra_lk_enable_kernel_verify(void)
{
  if(sierra_lk_enable_hash_check()|| sierra_sec_get_auth_en())
  {
    return TRUE;
  }
  else
  {
    return FALSE;
  }
}


/************
 *
 * Name:     sierra_sec_calc_and_cmp_hash
 *
 * Purpose:  hash data to get hash and compare with the input hash value
 *
 * Parms:    hash_algo          hash algo
 *           data_to_hash       Buffer containing data to hash
 *           data_len           Length of the data buffer
 *           hash_to_cmp        hash value to compare
 *
 * Return:   TRUE if hash matched
 *           FALSE if other
 *
 * Abort:    none
 *
 * Notes:    none
 *
 ************/
 boolean sierra_sec_calc_and_cmp_hash
(
  crypto_auth_alg_type              hash_algo,
  const uint8*                      data_to_hash,
  uint32                            data_len,
  const uint8*                      hash_to_cmp
)
{
  int hash_size;
  unsigned char  image_hash[SHA256_SIZE] = {0};

  if(data_to_hash == NULL || hash_to_cmp == NULL)
  {
    dprintf(CRITICAL,"Wrong data to hash or wrong hash to compare.\n");
    return FALSE;
  }

  hash_find((unsigned char *)data_to_hash,data_len,image_hash, hash_algo);

  hash_size = (hash_algo == CRYPTO_AUTH_ALG_SHA256) ? SHA256_SIZE : SHA1_SIZE;

  if (memcmp( (uint8*) hash_to_cmp,
              (uint8*) image_hash,
              hash_size) == 0)
  {
    return TRUE;
  }
  else
  {
    dprintf(CRITICAL,"compare hash not matched.\n");
    return FALSE;
  }
}

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
boolean boot_swi_lk_verify_kernel(struct ptentry *ptn,unsigned char *image_addr,unsigned imagesize)
{
  unsigned offset = 0;
  unsigned read_size = 0;
  mi_boot_image_header_type *mbn_header_ptr = 0;
  secboot_image_info_type secboot_image_info;
  secboot_verified_info_type verified_info;
  unsigned page_size = 0;
  unsigned page_mask = 0;
  uint8* kernel_hash = NULL;

  if(NULL == ptn || NULL == image_addr )
  {
    dprintf(CRITICAL, "boot_swi_lk_auth_kernel: wrong input params.\n");
    return FALSE;
  }

  page_size = flash_page_size();
  page_mask = page_size - 1;

  memset((void*)&secboot_image_info, 0, sizeof(secboot_image_info));
  secboot_image_info.sw_type = SECBOOT_SWI_APPS_SW_TYPE;

  mbn_header_ptr = (mi_boot_image_header_type *)(image_addr + imagesize);

  offset = imagesize;

  /* Read MBN head page and hash of kernel image which in first page after kernel data */
  if(0 != flash_read(ptn, offset,(void *)mbn_header_ptr, page_size)) 
  {
    dprintf(CRITICAL, "ERROR: Cannot read mbn header, mbn_hdrp = 0x%x\n",(unsigned int)mbn_header_ptr);
    return FALSE;
  }

  dprintf(INFO, "mbn header offset:0x%x, code_szie:0x%x, sig_size:0x%x, certs_size:0x%x\n",
      offset, mbn_header_ptr->code_size, mbn_header_ptr->signature_size, mbn_header_ptr->cert_chain_size);

  /* Check whether have MBN header; and santiy check MBN header data */
  if((APPS_IMG == mbn_header_ptr->image_id)&&(mbn_header_ptr->image_size == 
      mbn_header_ptr->code_size+ mbn_header_ptr->signature_size + mbn_header_ptr->cert_chain_size)
      &&(mbn_header_ptr->code_size > 0))
  { /* have MBN header*/
    dprintf(INFO, "Sanity check kernel image format ok.\n");
  }
  else /* have not MBN header, we treat it as illegal image or bad image */
  {
    dprintf(CRITICAL, "Bad kernel image format, MBN header is NULL\n");
    return FALSE;
  }
  /* Check kernel hash size is right. The size must be 32 bytes */
  if(SHA256_SIZE != mbn_header_ptr->code_size)
  {
    dprintf(CRITICAL, "Bad kernel image format, wrong hash size: 0x%d.\n",mbn_header_ptr->code_size);
    return FALSE;
  }

  /*Kernel hash is closed to mbn header */
  kernel_hash = ( uint8* )mbn_header_ptr + sizeof(mi_boot_image_header_type);

  /* auth image signature */
  if(sierra_sec_get_auth_en())
  {
    /* we have read one page before, read rest part of signature +certchain */
    read_size = sizeof(mi_boot_image_header_type) + mbn_header_ptr->code_size 
              + mbn_header_ptr->signature_size + mbn_header_ptr->cert_chain_size;
    if(read_size > page_size)
    {
      read_size -= page_size;

      read_size = ROUND_TO_PAGE(read_size, page_mask);
      offset += page_size;  /*we have read out one page data for mbn header.*/

      if(0 != flash_read(ptn, offset,(void *)(image_addr + offset), read_size))
      {
        dprintf(CRITICAL, "ERROR: Cannot read rest of sign + cert chain.\n");
        return FALSE;
      }
    }

    secboot_image_info.header_ptr_1 = (const uint8*)mbn_header_ptr;
    secboot_image_info.header_len_1 = sizeof(mi_boot_image_header_type);
    secboot_image_info.code_ptr_1 = kernel_hash;
    secboot_image_info.code_len_1 = mbn_header_ptr->code_size;
    secboot_image_info.signature_ptr = secboot_image_info.code_ptr_1 + secboot_image_info.code_len_1;
    secboot_image_info.signature_len = mbn_header_ptr->signature_size;
    secboot_image_info.x509_chain_ptr = secboot_image_info.signature_ptr + secboot_image_info.signature_len;
    secboot_image_info.x509_chain_len = mbn_header_ptr->cert_chain_size;

    if(!image_authenticate(&secboot_image_info,&verified_info))
    {
      dprintf(CRITICAL, "ERROR: authenticate image failed\n");
      return FALSE;
    }
  }

  /* verify image hash */
  if(!sierra_sec_calc_and_cmp_hash(CRYPTO_AUTH_ALG_SHA256, image_addr, imagesize, kernel_hash))
  {
    dprintf(CRITICAL, "ERROR: Check andriod image hash failed\n");
    return FALSE;
  }
  dprintf(CRITICAL,"Auth kernel image succeeded.\n");
  return TRUE;
}

