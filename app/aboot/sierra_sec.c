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
#include <boot_stats.h>

#include <crypto_hash.h>

#include "bootimg.h"
#include "mach/sierra_smem.h"
#include "sierra_bludefs.h"
#include "sierra_secudefs.h"

#define ROUND_TO_PAGE(x,y) (((x) + (y)) & (~(y)))

extern unsigned boot_into_recovery;

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
  boolean auth_en = FALSE;
  boolean hybrid_auth_en = FALSE;
  uint32 auth_level = 0;
  auth_en = *(uint32*)HWIO_QFPROM_CORR_OEM_SEC_BOOT_ROW0_LSB_ADDR
      &HWIO_SECURE_BOOTn_AUTH_EN_BMSK;

  hybrid_auth_en = (*(uint32*)HWIO_QFPROM_CORR_CUST_SEC_BOOT_ROW_LSB_ADDR 
      & HWIO_SECURE_BOOT_HYBRID_AUTH_EN_BMSK) >> HWIO_SECURE_BOOT_HYBRID_AUTH_EN_SHFT;

  dprintf(INFO,"%s_%d: spare reg18 fuse:0x%x\n",__func__,__LINE__,*(uint32*)HWIO_QFPROM_CORR_CUST_SEC_BOOT_ROW_LSB_ADDR);

  auth_level = (*(uint32*)HWIO_QFPROM_CORR_CUST_SEC_BOOT_ROW_LSB_ADDR 
      & HWIO_SECURE_BOOT_HYBRID_AUTH_LEVEL_BMSK) >> HWIO_SECURE_BOOT_HYBRID_AUTH_LEVEL_SHFT;

  dprintf(INFO,"%s_%d: auth_en=%d, hybrid_en=%d,auth_level=%d\n",__func__,__LINE__,auth_en,hybrid_auth_en,auth_level);
  if((auth_en && !hybrid_auth_en)||(hybrid_auth_en && (auth_level >= SECBOOT_HYBRID_KERNEL_AUTH_LEVEL)))
  {
    dprintf(INFO,"%s_%d: auth_level=%d, return TRUE.\n",__func__,__LINE__,auth_level);
    return TRUE;
  }
  else 
  {
    dprintf(INFO,"%s_%d: return FALSE.\n",__func__,__LINE__);
    return FALSE;
  }
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
    dprintf(INFO,"%s_%d: secure boot enabled.\n",__func__,__LINE__);
    return TRUE;
  }
  else
  {
#ifdef ENABLE_HASH_CHECK
    dprintf(INFO,"%s_%d: define ENABLE_HASH_CHECK\n",__func__,__LINE__);
    return TRUE;
#else
    dprintf(INFO,"%s_%d: not define ENABLE_HASH_CHECK\n",__func__,__LINE__);
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
 * Name:     swi_lk_verify_kernel
 *
 * Purpose:  verify image hash and authenticate signature if secure boot enabled.
 *
 * Parms:    image_addr  --- Kernel image start address in RAM.
 *
 *           imagesize  ---- Andriod image size, which don't include "mbn header","image hash",[signature + cert chain]
 *
 * Return:   TRUE if verify succeed.
 *           FALSE if verify failed.
 *
 * Abort:    none
 *
 * Notes:    Please make sure all image data include "mbn header","image hash",... has been load to image_addr
 *           For secure boot disabled device, just check image hash(if ENABLE_HASH_CHECK defined);
 *           For seucre boot enabled device, authenticate signature and check image hash.
 *
 ************/
boolean swi_lk_verify_kernel(unsigned char *image_addr,unsigned imagesize)
{
  mi_boot_image_header_type *mbn_hdr_ptr = NULL;
  secboot_image_info_type secboot_image_info;
  secboot_verified_info_type verified_info;
  uint8* kernel_hash = NULL;

  if((NULL == image_addr)||(!imagesize))
  {
    dprintf(CRITICAL, "ERROR: lk verify kernel, image_addr is NULL or imagesize is 0.\n");
    return FALSE;
  }
  memset((void*)&secboot_image_info, 0, sizeof(secboot_image_info));
  memset((void*)&verified_info, 0, sizeof(verified_info));
  secboot_image_info.sw_type = SECBOOT_SWI_APPS_SW_TYPE;

  /* MBN header follow kernel image data */
  mbn_hdr_ptr = (mi_boot_image_header_type *)(image_addr + imagesize);
  /*Kernel hash is closed to mbn header */
  kernel_hash = ( uint8* )mbn_hdr_ptr + sizeof(mi_boot_image_header_type);

  /* Check whether have MBN header; and santiy check MBN header data */
  if((NULL == mbn_hdr_ptr)
    ||(NULL == kernel_hash)
    ||(APPS_IMG != mbn_hdr_ptr->image_id)
    ||(mbn_hdr_ptr->image_size != mbn_hdr_ptr->code_size+ mbn_hdr_ptr->signature_size + mbn_hdr_ptr->cert_chain_size))
  {
    dprintf(CRITICAL, "%s_%d: Image format is illegal\n",__func__,__LINE__);
    return FALSE;
  }

  /* auth image signature and cert chain */
  if(sierra_sec_get_auth_en())
  {
     secboot_image_info.header_ptr_1 = (const uint8*)mbn_hdr_ptr;
     secboot_image_info.header_len_1 = sizeof(mi_boot_image_header_type);
     secboot_image_info.code_ptr_1 = kernel_hash;
     secboot_image_info.code_len_1 = mbn_hdr_ptr->code_size;
     secboot_image_info.signature_ptr = secboot_image_info.code_ptr_1 + secboot_image_info.code_len_1;
     secboot_image_info.signature_len = mbn_hdr_ptr->signature_size;
     secboot_image_info.x509_chain_ptr = secboot_image_info.signature_ptr + secboot_image_info.signature_len;
     secboot_image_info.x509_chain_len = mbn_hdr_ptr->cert_chain_size;
    if(!image_authenticate(&secboot_image_info,&verified_info))
    {
      dprintf(CRITICAL, "ERROR: authenticate image signature and cert chain failed\n");
      return FALSE;
    }
  }

  /* verify image hash */
  if(!sierra_sec_calc_and_cmp_hash(CRYPTO_AUTH_ALG_SHA256, image_addr, imagesize, kernel_hash))
  {
    dprintf(CRITICAL, "ERROR: Check andriod image hash failed\n");
    return FALSE;
  }
  dprintf(CRITICAL,"LK verify kernel image succeeded.\n");
  return TRUE;
}

/************
 *
 * Name:     swi_lk_load_and_verify_kernel
 *
 * Purpose:  verify image hash and authenticate signature if secure boot enabled.
 *
 * Parms:    ptn  --- struct ptentry for read kernel iamge from NAND flash
 *
 *           image_addr  --- Kernel image start address in RAM.
 *
 *           imagesize  ---- Andriod image size, which don't include "mbn header","image hash",...
 *
 * Return:   TRUE if load and verify succeed.
 *           FALSE if load and verify failed.
 *
 * Abort:    none
 *
 * Notes:    SWI appended "mbn header" and "kernel hash" to kernel image for data integrity check;
 *           If kernel image is signed, "signature" and "certificate chain" also been appended to
 *           part of the image. Load all these data to RAM and then verify it.
 *
 ************/
boolean swi_lk_load_and_verify_kernel(struct ptentry *ptn,unsigned char *image_addr,unsigned imagesize)
{
  unsigned offset = 0;
  unsigned read_size = 0;
  mi_boot_image_header_type *mbn_header_ptr = 0;
  unsigned page_size = 0;
  unsigned page_mask = 0;

  if(NULL == ptn || NULL == image_addr )
  {
    dprintf(CRITICAL, "boot_swi_lk_auth_kernel: wrong input params.\n");
    return FALSE;
  }

  page_size = flash_page_size();
  page_mask = page_size - 1;

  /* Read kernel(Andriod) image and one more page to include MBN head */
  if(0 != flash_read(ptn, offset,(void *)image_addr, imagesize + page_size))
  {
    dprintf(CRITICAL, "ERROR: Cannot read mbn header, mbn_hdrp = 0x%x\n",(unsigned int)mbn_header_ptr);
    return FALSE;
  }

  mbn_header_ptr = (mi_boot_image_header_type *)(image_addr + imagesize);
  /* Check kernel hash size is right. The size must be 32 bytes */
  if(NULL == mbn_header_ptr ||SHA256_SIZE != mbn_header_ptr->code_size)
  {
    dprintf(CRITICAL, "Bad kernel image format, wrong hash size: 0x%d.\n",mbn_header_ptr->code_size);
    return FALSE;
  }

  /* Check whether need to read rest part of signature +certchain */
  read_size = sizeof(mi_boot_image_header_type) + mbn_header_ptr->code_size
            + mbn_header_ptr->signature_size + mbn_header_ptr->cert_chain_size;
  if(read_size > page_size)
  {
    read_size -= page_size;

    read_size = ROUND_TO_PAGE(read_size, page_mask);
    offset = imagesize + page_size;
    if(0 != flash_read(ptn, offset,(void *)(image_addr + offset), read_size))
    {
      dprintf(CRITICAL, "ERROR: Cannot read rest of sign + cert chain.\n");
      return FALSE;
    }
  }
  dprintf(INFO, "Loading (%s) image (%d): done\n",
    (!boot_into_recovery ? "boot" : "recovery"), imagesize);
  bs_set_timestamp(BS_KERNEL_LOAD_DONE);

  /* separate verification part, then "fastboot continue" can call it directly. */
  return swi_lk_verify_kernel(image_addr,imagesize);
}

