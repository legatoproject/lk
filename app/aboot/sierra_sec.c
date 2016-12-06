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
#include <board.h>

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
  return *(uint32*)HWIO_QFPROM_CORR_OEM_SEC_BOOT_ROW0_LSB_ADDR
      &HWIO_SECURE_BOOTn_AUTH_EN_BMSK;
}

/************
 *
 * Name:     blsec_oem_auth_en_get
 *
 * Purpose:  check if OEM image auth is enabled
 *
 * Parms:    NONE
 *
 * Return:   TRUE if OEM image auth enabled
 *           FALSE otherwise
 *
 * Abort:    none
 *
 * Notes:    kernel is part of OEM images, only auth kernel
 *           if OEM image authentication is turned on
 *
 ************/
static boolean sierra_oem_auth_en(void)
{
  if (board_hardware_subtype() == SWI_WP_BOARD)
  {
    /* check OEM auth related settings to decide if OEM image auth is enabled */
    /* We will add logic to check OEM root and auth setting later
     * For now authentication of OEM images are disabled
     */
    return FALSE;
  }
  else
  {
    /* kernel and other OEM image auth is always enabled */
    return TRUE;
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

  if(NULL == ptn || NULL == hdr)
  {
    dprintf(CRITICAL, "boot_swi_lk_auth_kernel: wrong input params.\n");
    return FALSE;
  }

  if(!sierra_sec_get_auth_en() ||
     !sierra_oem_auth_en())
  {
    /*TBD: verify kernel hash even secboot not enabled */
    dprintf(CRITICAL, "secboot not enabled, return TRUE.\n");
    return TRUE;
  }

  page_size = flash_page_size();
  page_mask = page_size - 1;

  memset((void*)&secboot_image_info, 0, sizeof(secboot_image_info));
  secboot_image_info.sw_type = SECBOOT_SWI_APPS_SW_TYPE;

  /*Get some temp buff for auth. use buffer from half of SCRATCH_REGION2 */
  image_addr = (unsigned char *)target_get_scratch_address();
  mbn_header_ptr = (mi_boot_image_header_type *)image_addr;

  /*Get acutal size of each segments */
  kernel_actual = ROUND_TO_PAGE(hdr->kernel_size, page_mask);
  ramdisk_actual = ROUND_TO_PAGE(hdr->ramdisk_size, page_mask);
  second_actual = ROUND_TO_PAGE(hdr->second_size, page_mask);
  dt_actual = ROUND_TO_PAGE(hdr->dt_size, page_mask);

  /* Get MBN header offset, kernel image have aligned to page size */
  offset = page_size + kernel_actual + ramdisk_actual + second_actual + dt_actual;
  image_total_size = offset;

  /* Read MBN head page, it will also read out siganture and part of cert chain */
  if(0 != flash_read(ptn, offset,(void *)mbn_header_ptr, page_size)) 
  {
    dprintf(CRITICAL, "ERROR: Cannot read mbn header, mbn_hdrp = 0x%x\n",(unsigned int)mbn_header_ptr);
    return FALSE;
  }

  dprintf(INFO, "mbn header offset:0x%x, code_szie:0x%x, sig_size:0x%x, certs_size:0x%x\n",
      offset, mbn_header_ptr->code_size, secboot_image_info.signature_len, secboot_image_info.x509_chain_len);

  /* Check whether have MBN header; only signed image have MBN header + signature + certification chain */
  if((APPS_IMG == mbn_header_ptr->image_id)&&(mbn_header_ptr->image_size == 
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

  read_size = secboot_image_info.header_len_1 + secboot_image_info.signature_len
      + secboot_image_info.x509_chain_len; /* total szie of mbnhdr + sig + certchain */

  if(mbn_header_ptr->code_size > SHA256_SIZE) 
  /* Still support old format: Andriod + mbnhdr + sig(mbnhdr + Andriod) + certchain. */
  {
    secboot_image_info.signature_ptr = secboot_image_info.header_ptr_1 + secboot_image_info.header_len_1;
    secboot_image_info.x509_chain_ptr = secboot_image_info.signature_ptr + secboot_image_info.signature_len;
  }
  else /* new fomrat: Android + mbnhdr + Hash(Andirod) + sig(mbnhdr +Hash(Andriod)) + certchain */
  {
    read_size += secboot_image_info.code_len_1; /* Also read out 32bytes Hash(Andirod) */
    secboot_image_info.code_ptr_1 = secboot_image_info.header_ptr_1 + secboot_image_info.header_len_1;
    secboot_image_info.signature_ptr = secboot_image_info.code_ptr_1 + secboot_image_info.code_len_1;
    secboot_image_info.x509_chain_ptr = secboot_image_info.signature_ptr + secboot_image_info.signature_len;
  }

  /* we have read one page before */
  if(read_size > page_size)
  {
    read_size -= page_size;
  }
  else
  {
    ASSERT(0); /* shouldn't happened. mbnhdr + sig + certchain must be large than 4k */
  }

  read_size = ROUND_TO_PAGE(read_size, page_mask);
  offset += page_size;  /*we have read out one page data for mbn header.*/

  if(0 != flash_read(ptn, offset,(void *)(image_addr + page_size), read_size))
  {
    dprintf(CRITICAL, "ERROR: Cannot read rest of sign + cert chain.\n");
    return FALSE;
  }

  /*Start to read out image data. move or read all kernel image data together to RAM */
  image_addr = (unsigned char *)mbn_header_ptr + page_size +read_size; /*offset one page size from start address */
  if(mbn_header_ptr->code_size > SHA256_SIZE) 
  {
    secboot_image_info.code_ptr_1 = (const uint8 *)image_addr;
  }
  /* read out the whole unsigned Andriod image */
  if(0 != flash_read(ptn, 0, (void *)image_addr, image_total_size))
  {
    dprintf(CRITICAL, "ERROR: Cannot read kernel image header\n");
    return FALSE;
  }

  /* auth kernel image */
  if(!image_authenticate(&secboot_image_info,&verified_info))
  {
    dprintf(CRITICAL, "ERROR: authenticate image failed\n");
    return FALSE;
  }
  else
  {
    if(mbn_header_ptr->code_size == SHA256_SIZE) /* still to check hash */
    {
      if(!sierra_sec_calc_and_cmp_hash(CRYPTO_AUTH_ALG_SHA256, image_addr, 
      image_total_size,secboot_image_info.code_ptr_1) )
      {
        dprintf(CRITICAL, "ERROR: Check andriod image hash failed\n");
        return FALSE;
      }
    }
    dprintf(CRITICAL,"Auth kernel image succeeded.\n");
    return TRUE;
  }
}

