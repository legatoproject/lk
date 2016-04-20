/************
 *
 * Filename:  sierra_bl.c
 *
 * Purpose:   Sierra Little Kernel changes
 *
 * Copyright: (c) 2015 Sierra Wireless, Inc.
 *            All rights reserved
 *
 * Note:
 *
 ************/

#include <string.h>
#include <reg.h>
#include <debug.h>
#include <platform.h>
#include <platform/iomap.h>
#include <arch/ops.h>
#include <arch/arm/mmu.h>
#include <crc32.h>
#include <dev/flash.h>
#include <dev/flash-ubi.h>

#include "mach/sierra_smem.h"
#include "sierra_bludefs.h"

/*
 *  externs
 */


/*
 *  Local variables
 */
_local struct cwe_header_s temphdr;

_local uint32 flash_write_addr = 0;

_local char *custom_part_name;

_local struct blCtrlBlk blc;

bool to_update_mibib = FALSE; /* Indicates modem should warm reset to SBL, to update MIBIB. */

/* Smart Error Recovery Thresholds: */
#define BLERRTHRESHOLD_FASTBOOT  6  /* enter into fastboot mode */


uint8 bl_yaffs2_header[] =
{
0x03,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0xFF,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xED,0x41,0x00,0x00
};

#define BL_YAFFS2_MAGIC      bl_yaffs2_header
#define BL_YAFFS2_MAGIC_SIZE sizeof(bl_yaffs2_header)

#define BL_UBI_MAGIC      "UBI#"
#define BL_UBI_MAGIC_SIZE 0x04

#define BL_SQH_MAGIC      "hsqs"
#define BL_SQH_MAGIC_SIZE 0x04



/* 
 * Local functions 
 */

/************
 *
 * Name:     sierra_smem_base_addr_get
 *
 * Purpose:  get SMEM base address
 *
 * Parms:    none
 *
 * Return:   Sierra SMEM base address
 *
 * Abort:    none
 *
 * Notes:    will also map SMEM region if needed
 *
 ************/
unsigned char *sierra_smem_base_addr_get(void)
{
  static bool mmu_inited = false;

  if (!mmu_inited)
  {
    mmu_inited = true;

    /* map SMEM virtual = phy addr. the follow function will map 1MB
     * assuming SIERRA_SMEM_SIZE is less or equal to 1MB
     */
    arm_mmu_map_section(SIERRA_SMEM_BASE_PHY,
                        SIERRA_SMEM_BASE_PHY,
                        (MMU_MEMORY_TYPE_DEVICE_SHARED |
                         MMU_MEMORY_AP_READ_WRITE |
                         MMU_MEMORY_XN));

  }

  return (unsigned char *)SIERRA_SMEM_BASE_PHY;
}

/************
 *
 * Name:     sierra_smem_b2a_flags_get
 *
 * Purpose:  get b2a flags from SMEM
 *
 * Parms:    none
 *
 * Return:   b2a flags
 *
 * Abort:    none
 *
 * Notes:    none
 *
 ************/
unsigned int sierra_smem_b2a_flags_get(void)
{
  struct bc_smem_message_s *b2amsgp;
  unsigned char *virtual_addr;
  int flags = 0;

  virtual_addr = sierra_smem_base_addr_get();
  if (virtual_addr)
  {
    /*  APPL mailbox */
    virtual_addr += BSMEM_MSG_APPL_MAILBOX_OFFSET;

    b2amsgp = (struct bc_smem_message_s *)virtual_addr;

    if (b2amsgp->magic_beg == BC_SMEM_MSG_MAGIC_BEG &&
        b2amsgp->magic_end == BC_SMEM_MSG_MAGIC_END &&
        (b2amsgp->version < BC_SMEM_MSG_CRC32_VERSION_MIN ||
         b2amsgp->crc32 == crc32(~0, (void *)b2amsgp, BC_MSG_CRC_SZ)))
    {
      flags = b2amsgp->in.flags;
    }
  }

  return flags;
}

/************
 *
 * Name:     sierra_smem_err_count_get
 *
 * Purpose:  get error count from SMEM
 *
 * Parms:    none
 *
 * Return:   error count
 *
 * Abort:    none
 *
 * Notes:    none
 *
 ************/
unsigned int sierra_smem_err_count_get(void)
{
  struct bc_smem_message_s *b2amsgp;
  unsigned char *virtual_addr;
  unsigned int err_count = 0;

  virtual_addr = sierra_smem_base_addr_get();
  if (virtual_addr)
  {
    /*  APPL mailbox */
    virtual_addr += BSMEM_MSG_APPL_MAILBOX_OFFSET;

    b2amsgp = (struct bc_smem_message_s *)virtual_addr;

    if (b2amsgp->magic_beg == BC_SMEM_MSG_MAGIC_BEG &&
        b2amsgp->magic_end == BC_SMEM_MSG_MAGIC_END &&
        (b2amsgp->version < BC_SMEM_MSG_CRC32_VERSION_MIN ||
         b2amsgp->crc32 == crc32(~0, (void *)b2amsgp, BC_MSG_CRC_SZ)))
    {
      err_count = b2amsgp->in.recover_cnt;
    }
  }

  return err_count;
}

/************
 *
 * Name:     sierra_smem_err_count_set
 *
 * Purpose:  set error count to SMEM
 *
 * Parms:    none
 *
 * Return:   error count
 *
 * Abort:    none
 *
 * Notes:    none
 *
 ************/
void sierra_smem_err_count_set(unsigned int err_cnt)
{
  struct bc_smem_message_s *b2amsgp;
  unsigned char *virtual_addr;

  virtual_addr = sierra_smem_base_addr_get();
  if (virtual_addr)
  {
    /*  APPL mailbox */
    virtual_addr += BSMEM_MSG_APPL_MAILBOX_OFFSET;
    b2amsgp = (struct bc_smem_message_s *)virtual_addr;

    b2amsgp->out.recover_cnt = err_cnt;
    b2amsgp->crc32 = crc32(~0, (void *)b2amsgp, BC_MSG_CRC_SZ);
  }

  return;
}

/************
 *
 * Name:     sierra_smem_reset_type_set
 *
 * Purpose:  set reset type to SMEM
 *
 * Parms:    none
 *
 * Return:   error count
 *
 * Abort:    none
 *
 * Notes:    none
 *
 ************/
void sierra_smem_reset_type_set(unsigned int reset_type)
{
  struct bc_smem_message_s *b2amsgp;
  unsigned char *virtual_addr;

  virtual_addr = sierra_smem_base_addr_get();
  if (virtual_addr)
  {
    /*  APPL mailbox */
    virtual_addr += BSMEM_MSG_APPL_MAILBOX_OFFSET;
    b2amsgp = (struct bc_smem_message_s *)virtual_addr;

    b2amsgp->out.reset_type = reset_type;
    b2amsgp->out.brstsetflg = BS_BCMSG_RTYPE_IS_SET;
    b2amsgp->crc32 = crc32(~0, (void *)b2amsgp, BC_MSG_CRC_SZ);
  }

  return;
}


/************
 *
 * Name:     sierra_smem_boothold_mode_set
 *
 * Purpose:  set boot & hold flag
 *
 * Parms:    none
 *
 * Return:   0 if success
 *           -1 otherwise
 *
 * Abort:    none
 *
 * Notes:    this is a duplicate of sierra_smem_boothold_mode_set
 *           in sierra_smem_msg.c
 *           SWI_TBD bdu - 20151005 DEV78033 - harmonize sierra_smem_msg.c
 *
 ************/
int sierra_smem_boothold_mode_set(void)
{
        struct bc_smem_message_s *a2bmsgp;
        uint64_t a2bflags = 0;
        unsigned char *virtual_addr;

        virtual_addr = sierra_smem_base_addr_get();
        if (virtual_addr) {

                /*  APPL mailbox */
                virtual_addr += BSMEM_MSG_APPL_MAILBOX_OFFSET;
        }
        else {

                return -1;
        }

        a2bmsgp = (struct bc_smem_message_s *)virtual_addr;

        if (a2bmsgp->magic_beg == BC_SMEM_MSG_MAGIC_BEG &&
            a2bmsgp->magic_end == BC_SMEM_MSG_MAGIC_END &&
            (a2bmsgp->version < BC_SMEM_MSG_CRC32_VERSION_MIN ||
             a2bmsgp->crc32 == crc32(~0, (void *)a2bmsgp, BC_MSG_CRC_SZ))) {

                a2bflags = a2bmsgp->out.flags;
        }
        else {

                memset((void *)a2bmsgp, 0, sizeof(struct bc_smem_message_s));
                a2bmsgp->in.launchcode  = BC_MSG_LAUNCH_CODE_INVALID;
                a2bmsgp->in.recover_cnt = BC_MSG_RECOVER_CNT_INVALID;
                a2bmsgp->in.hwconfig    = BC_MSG_HWCONFIG_INVALID;
                a2bmsgp->in.usbdescp    = BC_MSG_USB_DESC_INVALID;
                a2bmsgp->out.launchcode  = BC_MSG_LAUNCH_CODE_INVALID;
                a2bmsgp->out.recover_cnt = BC_MSG_RECOVER_CNT_INVALID;
                a2bmsgp->out.hwconfig    = BC_MSG_HWCONFIG_INVALID;
                a2bmsgp->out.usbdescp    = BC_MSG_USB_DESC_INVALID;
                a2bmsgp->version   = BC_SMEM_MSG_VERSION;
                a2bmsgp->magic_beg = BC_SMEM_MSG_MAGIC_BEG;
                a2bmsgp->magic_end = BC_SMEM_MSG_MAGIC_END;
                a2bflags = 0;
        }

        a2bflags |= BC_MSG_A2B_BOOT_HOLD;
        a2bmsgp->out.flags = a2bflags;
        a2bmsgp->crc32 = crc32(~0, (void *)a2bmsgp, BC_MSG_CRC_SZ);

        return 0;
}

/************
 *
 * Name:     sierra_is_fastboot_disabled
 *
 * Purpose:  check if fastboot disabled
 *
 * Parms:    none
 *
 * Return:   TRUE - if disabled
 *           FALSE - otherwise
 *
 * Abort:    none
 *
 * Notes:    none
 *
 ************/
bool sierra_is_fastboot_disabled(
  void)
{
  return (sierra_smem_b2a_flags_get() & BC_MSG_B2A_ADB_EN) ? false : true;
}

/************
 *
 * Name:     sierra_if_enter_fastboot
 *
 * Purpose:  check if enter into fastboot mode
 *
 * Parms:    none
 *
 * Return:   TRUE - enter fastboot mode
 *           FALSE - otherwise
 *
 * Abort:    none
 *
 * Notes:    none
 *
 ************/
bool sierra_if_enter_fastboot(void)
{
  return (sierra_smem_err_count_get() >= BLERRTHRESHOLD_FASTBOOT) ? true : false;
}


/************
 *
 * Name:     sierra_check_mibib_state_clear
 *
 * Purpose:  Clear mibib state
 *
 * Parms:    none
 *
 * Return:   void
 *
 * Abort:    none
 *
 * Notes:    none
 *
 ************/
void sierra_check_mibib_state_clear(void)
{
  struct mibib_smem_s *mibibp = NULL;
  unsigned char *virtual_addr = NULL;

  virtual_addr = sierra_smem_base_addr_get();
  if (NULL != virtual_addr)
  {
    /* MIBIB region address */
    mibibp = (struct mibib_smem_s *)(virtual_addr + BSMEM_MIBIB_OFFSET);
    memset(mibibp, 0, sizeof(struct mibib_smem_s));
  }
  
  return;
}

/************
 *
 * Name:     sierra_check_mibib_smart_update_allow
 *
 * Purpose:  Check mibib state, to decide if we should process MIBIB image of current package
 *
 * Parms:    none
 *
 * Return:   void
 *
 * Abort:    none
 *
 * Notes:    none
 *
 ************/
bool sierra_check_mibib_smart_update_allow(void)
{
  struct mibib_smem_s *mibibp = NULL;
  unsigned char *virtual_addr = NULL;
  uint32 crc32 = 0;

  virtual_addr = sierra_smem_base_addr_get();
  if (NULL != virtual_addr)
  {
    /* MIBIB region address */
    mibibp = (struct mibib_smem_s *)(virtual_addr + BSMEM_MIBIB_OFFSET);

    if ((mibibp->magic_beg == MIBIB_SMEM_MAGIC_BEG) &&
        (mibibp->magic_end == MIBIB_SMEM_MAGIC_END) &&
        ((mibibp->update_flag == MIBIB_TO_UPDATE_IN_SBL) ||
         (mibibp->update_flag == MIBIB_UPDATED_IN_SBL) ||
         (mibibp->update_flag == MIBIB_TO_UPDATE_IN_SBL_PHASE1)))
    {
      crc32 = crcrc32((uint8 *)mibibp, (sizeof(struct mibib_smem_s) - sizeof(uint32_t)), (uint32)CRSTART_CRC32);
      if (mibibp->crc32 == crc32)
      {
        dprintf(CRITICAL, "not allow MIBIB smart update\n");
        return false;
      }
      else
      {
        dprintf(CRITICAL, "allow MIBIB smart update\n");
        return true;
      }
    }
    else
    {
      dprintf(CRITICAL, "allow MIBIB smart update\n");
      return true;
    }
  }
  else
  {
    dprintf(CRITICAL, "allow MIBIB smart update\n");
    return true;
  }
}

/************
 *
 * Name:     sierra_smem_mibib_set_flag
 *
 * Purpose:  Set MIBIB update flag to SM
 *
 * Parms:    update_flag
 *
 * Return:   TRUE if success
 *               FALSE otherwise
 *
 * Abort:    none
 *
 * Notes:    none
 *
 ************/
bool sierra_smem_mibib_set_flag(uint32 update_flag)
{
  struct mibib_smem_s *mibibp = NULL;
  unsigned char *virtual_addr = NULL;

  virtual_addr = sierra_smem_base_addr_get();
  if (NULL != virtual_addr)
  {
    /* MIBIB region address */
    mibibp = (struct mibib_smem_s *)(virtual_addr + BSMEM_MIBIB_OFFSET);

    /* Clear total mibib region before writting */
    memset((void *)mibibp, 0, sizeof(struct mibib_smem_s));

    mibibp->magic_beg = MIBIB_SMEM_MAGIC_BEG;
    mibibp->magic_end = MIBIB_SMEM_MAGIC_END;
    mibibp->update_flag = update_flag;
    mibibp->crc32 = crcrc32((uint8 *)mibibp, (sizeof(struct mibib_smem_s) - sizeof(uint32_t)), (uint32)CRSTART_CRC32);

    dprintf(CRITICAL, "Save MIBIB to SIERRA SMEM successfully\n");

    return TRUE;
  }
  else
  {
    dprintf(CRITICAL, "Can't get SIERRA SMEM base address\n");
    return FALSE;
  }
}

/************
 *
 * Name:     blGetcbp
 *
 * Purpose:  Get a pointer to the BL control block
 *
 * Params:   None
 *
 * Return:   cbp - Pointer to the static BL package control block
 *
 * Notes:
 *
 * Abort:
 *
 ************/
_package struct blCtrlBlk *blGetcbp(
  void)
{
  return &blc;
}

/************
 *
 * Name:     blsetcustompartition
 *
 * Purpose:  set partition name for FLASH_PROG_CUSTOM_IMG.
 *
 * Parms:    part_name - partition name
 *
 * Return:   TRUE  - success
 *           FALSE - fail
 *
 * Abort:    none
 *
 * Notes:    None
 *
 ************/
_local boolean blsetcustompartition(
  const char *part_name)
{
  custom_part_name = (char *)part_name;
  return TRUE;
}

/************
 *
 * Name:     blgetcustompartition
 *
 * Purpose:  get partition name for FLASH_PROG_CUSTOM_IMG.
 *
 * Parms:    none
 *
 * Return:   partition name pointer
 *
 * Abort:    none
 *
 * Notes:    None
 *
 ************/
_local char *blgetcustompartition(
  void)
{
  return custom_part_name;
}


/************
 *
 * Name:     blSearchCWEImage
 *
 * Purpose:  This function will search downloaded CWE image for a particular
 *           subimage.
 *
 * Parms:    subimagetype - Subimage type to search for
 *           searchbufp   - start search address
 *           searchbuflen - length of buffer to search
 *
 * Return:   Start address of the subimage CWE header, if found
 *           NULL if not found
 *
 * Abort:    none
 *
 * Notes:    CWE header of the subimage found will be stored in temphdr
 *
 ************/
_local uint8 *blSearchCWEImage(
  enum cwe_image_type_e subimagetype,
  uint8 * searchbufp,
  uint32  searchbuflen)
{
  uint8 *bufp;
  enum cwe_image_type_e subtype;

  bufp = searchbufp;

  do
  {
    /* Read the first CWE sub-header */
    (void)cwe_header_load(bufp, &temphdr);

    /* validate the image type from the CWE sub-header */
    if (cwe_image_type_validate(temphdr.image_type, &subtype) == FALSE)
    {
      break;
    }

    /* check if subimage type match */
    if (subimagetype == subtype)
    {
      return bufp;
    }
    bufp += sizeof(struct cwe_header_s);
    bufp += temphdr.image_sz;
  } while (bufp < searchbufp + searchbuflen);

  return NULL;
}

/************
 *
 * Name:     blGoCweFile
 *
 * Purpose:  Check if there is a cwe file, and return file length.
 *
 * Parms:    buf      - pointer data buf to check
 *           len - buf length
 *           
 *
 * Return:   cwe file length(including cwe header header)
 *
 * Abort:    none
 *
 * Notes:    none
 *
 ************/
unsigned int blGoCweFile(unsigned char *buf, unsigned int len)
{
  unsigned int ret;
  if((len < CWE_HEADER_SZ) || (!cwe_header_load(buf, &temphdr)))
  {
    return 0;
  }

  if (TRUE != cwe_image_validate(&temphdr, 
                                                          buf + sizeof(struct cwe_header_s), 
                                                          CWE_IMAGE_TYPE_ANY, 
                                                          BL_PRODUCT_ID, 
                                                          FALSE))
  {
    return 0;
  }

  ret = temphdr.image_sz + CWE_HEADER_SZ;
  return ret;
}

/************
 *
 * Name:     blProgramFileImgToFlash
 *
 * Purpose:  This function will program file image to flash.
 *
 * Parms:    bufp      - pointer data block to be written
 *                       to flash. If this is the first write, bufp will point to
 *                        start of CWE image (CWE header)
 *           image_type - image type
 *           write_size - size of the bufp (may include CWE header which might
 *                        need to be skipped)
 *           bytesleft  - there will be another flash write to image if it is not 0
 *           
 *
 * Return:   result code (as defined in 'enum blresultcode')
 *
 * Abort:    none
 *
 * Notes:    The same image_type may need to write several times to complete:
 *           - use flash_write_addr to set logical relative address to write in partition
 *           - if flash_write_addr = 0, need to call bl_do_flash_init 
 *           - use bytesleft to know if image write complete. 
 *             Need to bl_do_flash_finalize if it is 0
 *
 ************/
_local enum blresultcode blProgramFileImgToFlash(
  uint8 * bufp,
  uint32 image_type,
  uint32 write_size,
  uint32 bytesleft)
{
  uint8  *hdr_datap;
  
  struct ptentry *ptn;
  struct ptable *ptable;
  unsigned extra = 0;

  dprintf(CRITICAL, "blProgramFileImgToFlash(), type:%d, size:%d\n", image_type, write_size);
  if(image_type != FLASH_PROG_FILE_IMG)
  {
    return BLRESULT_IMAGE_TYPE_INVALID;
  }

  hdr_datap = (uint8 *)blgetcustompartition();

  ptable = flash_get_ptable();
  if (ptable == NULL) {
    dprintf(CRITICAL, "sierra_bl: flash_get_ptable failed\n");
    return BLRESULT_FLASH_WRITE_ERROR;
  }

  ptn = ptable_find(ptable, (const char *)hdr_datap);
  if (ptn == NULL) {
    dprintf(CRITICAL, "sierra_bl: ptable_find failed: %s\n", hdr_datap);
    return BLRESULT_FLASH_WRITE_ERROR;
  }

  if (write_size > 0)
  {
    dprintf(CRITICAL, "writing size:%d\n", write_size);
    if (flash_write_sierra_file_img(ptn, extra, (const void *)bufp, (unsigned)write_size, blGoCweFile)) {
      dprintf(CRITICAL, "flash write failure\n");
      return BLRESULT_FLASH_WRITE_ERROR;
    }
    else
    {
      dprintf(CRITICAL, "blProgramFlash OK!\n");
    }
  }
  
  return BLRESULT_OK;
}

/************
 *
 * Name:     blProgramImage
 *
 * Purpose:  This function will program a type of image to flash.
 *
 * Parms:    bufp      - pointer data block to be written
 *                       to flash. If this is the first write, bufp will point to
 *                        start of CWE image (CWE header)
 *           image_type - image type
 *           write_size - size of the bufp (may include CWE header which might
 *                        need to be skipped)
 *           bytesleft  - there will be another flash write to image if it is not 0
 *           
 *
 * Return:   result code (as defined in 'enum blresultcode')
 *
 * Abort:    none
 *
 * Notes:    The same image_type may need to write several times to complete:
 *           - use flash_write_addr to set logical relative address to write in partition
 *           - if flash_write_addr = 0, need to call bl_do_flash_init 
 *           - use bytesleft to know if image write complete. 
 *             Need to bl_do_flash_finalize if it is 0
 *
 ************/
_local enum blresultcode blProgramFlash(
  uint8 * bufp,
  uint32 image_type,
  uint32 write_size,
  uint32 bytesleft)
{
  uint8  *hdr_datap;
  int auth_hdr_size = 0;
  
  struct ptentry *ptn;
  struct ptable *ptable;
  unsigned extra = 0;

  if(image_type == FLASH_PROG_CUSTOM_IMG 
       || image_type == FLASH_PROG_SBL1_IMG
       || image_type == FLASH_PROG_DSP2_IMG
       || image_type == FLASH_PROG_USDATA_IMG
       || image_type == FLASH_PROG_USAPP_IMG
       || image_type == FLASH_PROG_ROFS1_IMG)
  {
    hdr_datap = (uint8 *)blgetcustompartition();
  }
  else
  {
    /* hdr_datap can be used for flash init where CWE header
     * will be saved for future use. Set it anyway here
     */

    hdr_datap = bufp;
  }
    
  if (flash_write_addr == 0)
  {
    /* Skip CWE header and auth hdr, auth hdr size is 0 for most of images */
    bufp += (CWE_HEADER_SZ + auth_hdr_size);
    write_size -= (CWE_HEADER_SZ + auth_hdr_size);
  }

  ptable = flash_get_ptable();
  if (ptable == NULL) {
    dprintf(CRITICAL, "sierra_bl: flash_get_ptable failed\n");
    return BLRESULT_FLASH_WRITE_ERROR;
  }

  ptn = ptable_find(ptable, (const char *)hdr_datap);
  if (ptn == NULL) {
    dprintf(CRITICAL, "sierra_bl: ptable_find failed: %s\n", hdr_datap);
    return BLRESULT_FLASH_WRITE_ERROR;
  }

  if (write_size > 0)
  {
    dprintf(CRITICAL, "writing size:%d\n", write_size);
    /* only write to flash if requested */
    if (image_type == FLASH_PROG_DSP2_IMG
       || image_type == FLASH_PROG_USDATA_IMG
       || image_type == FLASH_PROG_USAPP_IMG
       || image_type == FLASH_PROG_ROFS1_IMG)
    {
      /* dectet image format dynamiclly */
      if (!memcmp((void *)(bufp), BL_UBI_MAGIC, BL_UBI_MAGIC_SIZE))
      {
        /* UBI image */
        if (flash_ubi_img(ptn, (void *)bufp, (unsigned)write_size)) 
        {
          dprintf(CRITICAL, "flash_ubi_img failed!\n");
          return BLRESULT_FLASH_WRITE_ERROR;
        }
        else
        {
          dprintf(INFO, "flash_ubi_img OK!\n");
        }
      }
      else if (!memcmp((void *)(bufp), BL_YAFFS2_MAGIC, BL_YAFFS2_MAGIC_SIZE))
      {
        /* YAFFS image */
        extra = 1;
        if (flash_write_sierra(ptn, extra, (const void *)bufp, (unsigned)write_size)) 
        {
          dprintf(CRITICAL, "flash write failure\n");
          return BLRESULT_FLASH_WRITE_ERROR;
        }
        else
        {
          dprintf(INFO, "flash_write_sierra YAFFS OK\n");
        }
      }
      else if (!memcmp((void *)(bufp), BL_SQH_MAGIC, BL_SQH_MAGIC_SIZE))
      {
        /* squashfs image */
        if (flash_write_sierra(ptn, extra, (const void *)bufp, (unsigned)write_size)) 
        {
          dprintf(CRITICAL, "flash write failure\n");
          return BLRESULT_FLASH_WRITE_ERROR;
        }
        else
        {
          dprintf(INFO, "flash_write_sierra SQH OK!\n");
        }
      }
      else
      {
        /* bad image */
        dprintf(CRITICAL, "Image(DSP2, USER, UAPP, SYST) should be in format (yaffs2, UBI, squashfs)\n");
        return BLRESULT_IMAGE_TYPE_INVALID;
      }
      
    }
    else
    {
      /* raw image */
      if (flash_write_sierra(ptn, extra, (const void *)bufp, (unsigned)write_size)) 
      {
        dprintf(CRITICAL, "flash write failure\n");
        return BLRESULT_FLASH_WRITE_ERROR;
      }
      else
      {
        dprintf(INFO, "flash_write_sierra raw OK!\n");
      }
    }
  }

  flash_write_addr += write_size;

  if(bytesleft == 0)        /* last call */
  {
    /* We need to reset the flash_write_addr for the next image */
    flash_write_addr = 0;
  }
  
  return BLRESULT_OK;
}

/************
 *
 * Name:     blProgramImage
 *
 * Purpose:  This function will program a type of image to flash.
 *
 * Parms:    bufp - pointer to the image start (CWE header)
 *           image_type - image type
 *           image_size - CWE image size (excluding CWE header)
 *
 * Return:   result code (as defined in 'enum blresultcode')
 *
 * Abort:    none
 *
 * Notes:    The image might be compressed, need to check compression bit
 *           in CWE header:
 *           - if not compressed, just write the buffer to flash
 *           - if compressed, need to:
 *             1. uncompress and check CRC since CRC in CWE header is for uncompressed
 *             2. Write the uncompressed image 
 *                (may need several writes if decompression buffer is not big enough)
 *
 ************/
_local enum blresultcode blProgramImage(
  uint8 * bufp,
  uint32 image_type,
  uint32 image_size)
{
  enum blresultcode result;

  if(!cwe_header_load(bufp, &temphdr))
  {
    /* this should not happen since it is checked before */
    dprintf(CRITICAL, "BLRESULT_CWE_HEADER_ERROR\n");
    return BLRESULT_CWE_HEADER_ERROR;
  }

  if (TRUE != cwe_image_validate(&temphdr, 
                                                          bufp + sizeof(struct cwe_header_s), 
                                                          CWE_IMAGE_TYPE_ANY, 
                                                          BL_PRODUCT_ID, 
                                                          TRUE))
  {
    dprintf(CRITICAL, "BLRESULT_CRC32_CHECK_ERROR\n");
    return BLRESULT_CRC32_CHECK_ERROR;
  }

  flash_write_addr = 0;
  if(temphdr.misc_opts & CWE_MISC_OPTS_COMPRESS)
  {
    dprintf(CRITICAL, "BLRESULT_DECOMPRESSION_ERROR\n");
    result = BLRESULT_DECOMPRESSION_ERROR;
  } /* end if compressed image */
  else if (image_type != FLASH_PROG_FILE_IMG)
  {
    result = blProgramFlash(bufp, image_type, 
                            image_size + CWE_HEADER_SZ, 0); 
  }
  else
  {
    /* program NVUP file here */
    result = blProgramFileImgToFlash(bufp, image_type, 
                            image_size + CWE_HEADER_SZ, 0); 
  }

  /* flash write completed, reset */
  flash_write_addr = 0;

  return result;
}

/************
 *
 * Name:     blProgramBootImage
 *
 * Purpose:  This function will program the MODEM image into flash.
 *
 * Params:   hdr - point to MODEM image header struct
 *                startbufp - point to MODEM image data region
 *
 * Return:   result code (as defined in 'enum blresultcode')
 *
 * Abort:    none
 *
 * Notes:    The sub-CWE images may be in any order however they must
 *           contain the correct content.
 *
 ************/
enum blresultcode blProgramModemImage(struct cwe_header_s *hdr, uint8 *startbufp)
{
  uint8         *bufp;
  enum blresultcode result = BLRESULT_FLASH_WRITE_ERROR;

  /*                    -------------------
   * MODM image format: | MODM CWE header |
   *                    -------------------
   *                    | DSP2 CWE hdr    |
   *                    -------------------
   *                    | DSP2 image      |
   *                    -------------------
   *  (all the images are optional)
   */
     
  /* no partition given, apply the default one */
  /* erase RPM partition first so that device will stay in boot & hold if
   * one of the following image write failed
   * bl_do_flash_init will erase the flash.
   * swipart_partition_erase is not used since it will cause memory leak
   */

  /* Program DSP2 image, (maybe in format .yaffs2, UBI, squashfs) */
  bufp = blSearchCWEImage(CWE_IMAGE_TYPE_DSP2, startbufp, hdr->image_sz);
  if (bufp != NULL)
  {
    /* Program DSP2 image */
    blsetcustompartition(BL_MODEM_PARTI_NAME);
    result = blProgramImage(bufp, FLASH_PROG_DSP2_IMG, temphdr.image_sz);
    if (result != BLRESULT_OK)
    {
      dprintf(CRITICAL, "blProgramModemImage CWE_IMAGE_TYPE_DSP2 failed, ret:%d\n", result);
      return result;
    }
  }
  
  return result;
}

/************
 *
 * Name:     blProgramBootImage
 *
 * Purpose:  This function will program the APPL image into flash.
 *
 * Params:   hdr - point to APPL image header struct
 *                startbufp - point to APPL image data region
 *
 * Return:   result code (as defined in 'enum blresultcode')
 *
 * Abort:    none
 *
 * Notes:    The sub-CWE images may be in any order however they must
 *           contain the correct content.
 *
 ************/
enum blresultcode blProgramApplImage(struct cwe_header_s *hdr, uint8 *startbufp)
{
  uint8         *bufp;
  enum blresultcode result = BLRESULT_FLASH_WRITE_ERROR;

  /*                    -------------------
   * APPL image format: | APPL CWE header |
   * (Linux)            -------------------
   *                    | SYST CWE hdr    |
   *                    -------------------
   *                    | SYST image      |  (Linux rootfs)
   *                    -------------------
   *                    | USER CWE hdr    |
   *                    -------------------
   *                    | USER image      |  (Linux usrfs)
   *                    -------------------
   *                    | APPS CWE hdr    |
   *                    -------------------
   *                    | APPS image      |  (Linux kernel)
   *                    -------------------
   *                    | USDATA CWE hdr    |
   *                    -------------------
   *                    | USDATA image      |  (userdata)
   *                    -------------------
   *                    | UAPP CWE hdr    |
   *                    -------------------
   *                    | UAPP image      |  (userapp)   
   *                    -------------------
   *  (all the images can be optional)
   */
     
  /* Program Linux SYSTEM image, (maybe in format .yaffs2, UBI, squashfs) */
  bufp = blSearchCWEImage(CWE_IMAGE_TYPE_SYST, startbufp, hdr->image_sz);
  if (bufp != NULL)
  {
    blsetcustompartition(BL_LINUX_SYSTEM_PARTI_NAME);
    result = blProgramImage(bufp, FLASH_PROG_ROFS1_IMG, temphdr.image_sz);
    if (result != BLRESULT_OK)
    {
      dprintf(CRITICAL, "blProgramApplImage CWE_IMAGE_TYPE_SYST failed, ret:%d\n", result);
      return result;
    }
  }

  /* Program Linux USERDATA image, (maybe in format .yaffs2, UBI, squashfs) */
  bufp = blSearchCWEImage(CWE_IMAGE_TYPE_USER, startbufp, hdr->image_sz);
  if (bufp != NULL)
  {
    blsetcustompartition(BL_LINUX_UDATA_PARTI_NAME);
    result = blProgramImage(bufp, FLASH_PROG_USDATA_IMG, temphdr.image_sz);
    if (result != BLRESULT_OK)
    {
      dprintf(CRITICAL, "blProgramApplImage CWE_IMAGE_TYPE_USER failed, ret:%d\n", result);
      return result;
    }
  }

  /* Program Linux USERAPP image, (maybe in format .yaffs2, UBI, squashfs) */
  bufp = blSearchCWEImage(CWE_IMAGE_TYPE_UAPP, startbufp, hdr->image_sz);
  if (bufp != NULL)
  {
    blsetcustompartition(BL_LINUX_UAPP_PARTI_NAME);
    result = blProgramImage(bufp, FLASH_PROG_USAPP_IMG, temphdr.image_sz);
    if (result != BLRESULT_OK)
    {
      dprintf(CRITICAL, "blProgramApplImage CWE_IMAGE_TYPE_UAPP failed, ret:%d\n", result);
      return result;
    }
  }

  /* program Linux APPS (kernel) image */
  bufp = blSearchCWEImage(CWE_IMAGE_TYPE_APPS, startbufp, hdr->image_sz);
  if (bufp != NULL)
  {
    blsetcustompartition(BL_LINUX_BOOT_PARTI_NAME);
    result = blProgramImage(bufp, FLASH_PROG_CUSTOM_IMG, temphdr.image_sz);
    if (result != BLRESULT_OK)
    {
      dprintf(CRITICAL, "blProgramApplImage CWE_IMAGE_TYPE_APPS failed, ret:%d\n", result);
      return result;
    }
  }

  return result;
}

/************
 *
 * Name:     blProgramBootImage
 *
 * Purpose:  This function will program the BOOT image into flash.
 *
 * Params:   hdr - point to BOOT image header struct
 *                startbufp - point to BOOT image data region
 *
 * Return:   result code (as defined in 'enum blresultcode')
 *
 * Abort:    none
 *
 * Notes:    The sub-CWE images may be in any order however they must
 *           contain the correct content.
 *
 ************/
enum blresultcode blProgramBootImage(struct cwe_header_s *hdr, uint8 *startbufp)
{
  uint8         *bufp;
  enum blresultcode result = BLRESULT_FLASH_WRITE_ERROR;

  /*                    -------------------
   * BOOT image format: | BOOT CWE header |
   *                    -------------------
   *                    | Parti CWE hdr   |
   *                    -------------------
   *                    | Parti image     |  
   *                    -------------------
   *                    | SBL1 CWE hdr     |
   *                    -------------------
   *                    | SBL1 image       | 
   *                    -------------------
   *                    | TZ CWE hdr      |
   *                    -------------------
   *                    | TZ image        |
   *                    -------------------
   *                    | RPM CWE hdr     |
   *                    -------------------
   *                    | RPM image       |
   *                    -------------------
   *                    | APBL CWE hdr    |
   *                    -------------------
   *                    | APBL image      |  (Linux boot loader)
   *                    -------------------
   *  (All the images are optional)
   */

  bufp = blSearchCWEImage(CWE_IMAGE_TYPE_QPAR, startbufp, hdr->image_sz);
  if (bufp != NULL)
  { 
    if (sierra_check_mibib_smart_update_allow())
    {
      /* MIBIB image(partition image) found. LK can't write MIBIB image. */
      if(!sierra_smem_mibib_set_flag(MIBIB_TO_UPDATE_IN_SBL))
      {
        result = BLRESULT_MEMORY_MAP_ERROR;
        dprintf(CRITICAL, "write MIBIB to SMEM failed, ret:%d\n", result);
        return result;
      }
      else
      {
        /* set the global varible to true for modem reset */
        to_update_mibib = TRUE;
        return BLRESULT_OK;
      }
    }
  }

  bufp = blSearchCWEImage(CWE_IMAGE_TYPE_SBL1, startbufp, hdr->image_sz);
  if (bufp != NULL)
  {
    /* SBL1 image is optional, only program if found */
    /* Program SBL image */
    blsetcustompartition(BL_SBL_PARTI_NAME);
    result = blProgramImage(bufp, FLASH_PROG_SBL1_IMG, temphdr.image_sz);
    if (result != BLRESULT_OK)
    {
      dprintf(CRITICAL, "blProgramBootImage CWE_IMAGE_TYPE_SBL1 failed, ret:%d\n", result);
      return result;
    }
  }

  bufp = blSearchCWEImage(CWE_IMAGE_TYPE_TZON, startbufp, hdr->image_sz);
  if (bufp != NULL)
  {
    /* Program TZ image */
    blsetcustompartition(BL_TZ_PARTI_NAME);
    result = blProgramImage(bufp, FLASH_PROG_CUSTOM_IMG, temphdr.image_sz);
    if (result != BLRESULT_OK)
    {
      dprintf(CRITICAL, "blProgramBootImage CWE_IMAGE_TYPE_TZON failed, ret:%d\n", result);
      return result;
    }
  }

  /* program RPM at very last */
  bufp = blSearchCWEImage(CWE_IMAGE_TYPE_QRPM, startbufp, hdr->image_sz);
  if (bufp != NULL)
  {
    /* Program RPM image  */
    blsetcustompartition(BL_RPM_PARTI_NAME);
    result = blProgramImage(bufp, FLASH_PROG_CUSTOM_IMG, temphdr.image_sz);
    if (result != BLRESULT_OK)
    {
      dprintf(CRITICAL, "blProgramBootImage CWE_IMAGE_TYPE_QRPM failed, ret:%d\n", result);
      return result;
    }
  }

  /* program APBL last */
  bufp = blSearchCWEImage(CWE_IMAGE_TYPE_APBL, startbufp, hdr->image_sz);
  if (bufp != NULL)
  {
    /* Program APBL image */
    blsetcustompartition(BL_ABOOT_PARTI_NAME);
    result = blProgramImage(bufp, FLASH_PROG_CUSTOM_IMG, temphdr.image_sz);
    if (result != BLRESULT_OK)
    {
      dprintf(CRITICAL, "blProgramBootImage CWE_IMAGE_TYPE_APBL failed, ret:%d\n", result);
      return result;
    }
  }
  return result;
}

/************
 *
 * Name:     blProgramImageFile
 *
 * Purpose:  This function will program the File image to flash.
 *
 * Parms:    imagetype - File type
 *           bufp      - pointer to data block to be written
 *                      to flash (CWE header)
 *           buf_size  - size of the data block to be written to flash
 *                      (including CWE header)
 *
 * Return:   result code (as defined in 'enum blresultcode')
 *
 * Abort:    none
 *
 * Notes:    Since this function needs to know the structure and format of the
 *           CUST partition, does not need to modify the MIBIB partition, and
 *           will not need to be downloaded via JTAG, we will use the
 *           flash device driver directly to program the flash rather than the
 *           nand programmer routines.
 *
 ************/
_local enum blresultcode blProgramImageFile(
  enum cwe_image_type_e imagetype,
  uint8 * bufp,
  uint32 buf_size)
{
  enum blresultcode result = BLRESULT_OK;

  if (CWE_IMAGE_TYPE_FILE != imagetype)
  {
    return BLRESULT_IMAGE_TYPE_INVALID;
  }

  blsetcustompartition(BL_BACKUP_PARTI_NAME);

  result = blProgramImage(bufp, FLASH_PROG_FILE_IMG, buf_size);
  if (result != BLRESULT_OK)
  {
    dprintf(CRITICAL, "blProgramImageFile CWE_IMAGE_TYPE_FILE failed, ret:%d\n", result);
    return result;
  }

  return result;
}

/************
 *
 * Name:     blProgramCWEImage
 *
 * Purpose:  This function will program the CWE image into flash.
 *
 * Params:   cbp - pointer to the download handler control block
 *
 * Return:   result code (as defined in 'enum blresultcode')
 *
 * Abort:    none
 *
 * Notes:    The sub-CWE images may be in any order however they must
 *           contain the correct content.
 *
 ************/
_global enum blresultcode blProgramCWEImage(
  struct cwe_header_s *hdr,
  uint8 *dloadbufp,
  uint32 dloadsize,
  uint32 bytesleft)
{
  uint8         *bufp, *startbufp, *startbuf_search_2nd_appl;
  enum cwe_image_type_e imagetype, flog_imgtype = CWE_IMAGE_TYPE_INVALID;
  enum blresultcode result = BLRESULT_FLASH_WRITE_ERROR;
  char flog_typestr[CWE_IMAGE_TYP_SZ+1];
  const char *imagep;
  struct cwe_header_s spkg_sub_img_header;
  uint32 buflen_search_2nd_appl;
  
  /* validate the image type from the CWE sub-header */
  if (cwe_image_type_validate(hdr->image_type, &imagetype) == FALSE)
  {
    dprintf(CRITICAL, "BLRESULT_CWE_HEADER_ERROR\n");
    return BLRESULT_CWE_HEADER_ERROR;
  }

  /* Set the buffer pointer to the first CWE sub-header */
  startbufp = dloadbufp + sizeof(struct cwe_header_s);

  do                            /* break out of this loop in case of failure */
  {
    memmove((void *)&temphdr, (void *)hdr, sizeof(temphdr));

    if (imagetype == CWE_IMAGE_TYPE_MODM)
    {
      if (blProgramModemImage(hdr, startbufp) != BLRESULT_OK)
      {
        break;
      }
    } /* CWE_IMAGE_TYPE_MODM */
    else if (imagetype == CWE_IMAGE_TYPE_APPL)
    {
      if (blProgramApplImage(hdr, startbufp) != BLRESULT_OK)
      {
        break;
      }
    } /* CWE_IMAGE_TYPE_APPL */
    else if (imagetype == CWE_IMAGE_TYPE_BOOT)
    {
      if (blProgramBootImage(hdr, startbufp) != BLRESULT_OK)
      {
        break;
      }

      /* 1, If found QPAR image, */
      if (to_update_mibib == TRUE)
      {
        /* 1.1 then copy whole BOOT image to  SCRATCH_REGION2:0x88000000 */
        /* In this case FULL BOOT image has already been stored in SCRATCH_REGION2:0x88000000 */
        /* 1.2 MIBIB smart update, should go to sbl now */
        return BLRESULT_OK;
      }
    } /* CWE_IMAGE_TYPE_BOOT */

    /*                    -------------------
     * File image format: | FILE CWE header |
     *                    -------------------
     *                    | FILE image      |
     *                    -------------------
     */
    else if (imagetype == CWE_IMAGE_TYPE_FILE)
    {
      bufp = dloadbufp;

      /* Program CUST image */
      if (blProgramImageFile(imagetype, bufp, hdr->image_sz) != BLRESULT_OK)
      {
         break;
      }
    } /* CWE_IMAGE_TYPE_FILE */
    /* Program Linux USERDATA image, (maybe in format .yaffs2, UBI, squashfs) */
    else if (imagetype == CWE_IMAGE_TYPE_USER)
    {
      bufp = dloadbufp;
      blsetcustompartition(BL_LINUX_UDATA_PARTI_NAME);
      if (blProgramImage(bufp, FLASH_PROG_USDATA_IMG, hdr->image_sz) != BLRESULT_OK)
      {
        dprintf(CRITICAL, "blProgramApplImage CWE_IMAGE_TYPE_USER failed, ret:%d\n", result);
        break;
      }
    }
    /* Program Linux USERAPP image, (maybe in format .yaffs2, UBI, squashfs) */
    else if (imagetype == CWE_IMAGE_TYPE_UAPP)
    {
      bufp = dloadbufp;
      blsetcustompartition(BL_LINUX_UAPP_PARTI_NAME);
      if (blProgramImage(bufp, FLASH_PROG_USAPP_IMG, hdr->image_sz) != BLRESULT_OK)
      {
        dprintf(CRITICAL, "blProgramApplImage CWE_IMAGE_TYPE_UAPP failed, ret:%d\n", result);
        break;
      }
    }
    /* Sierra package processing */
    else if (imagetype == CWE_IMAGE_TYPE_SPKG)
    {
      bufp = blSearchCWEImage(CWE_IMAGE_TYPE_BOOT, startbufp, hdr->image_sz);
      if (bufp != NULL)
      {
        memcpy((void *)&spkg_sub_img_header, (void *)&temphdr, sizeof(temphdr));
        if (blProgramBootImage(&spkg_sub_img_header, bufp + sizeof(struct cwe_header_s)) != BLRESULT_OK)
        {
          break;
        }

        /* 1, If found QPAR image, */
        if (to_update_mibib == TRUE)
        {
          /* 1.1 then copy whole BOOT image to  SCRATCH_REGION2:0x88000000 */
          memmove((void *)BL_BOOT_IMG_STORED_BY_LK, (void *)bufp, sizeof(struct cwe_header_s) + spkg_sub_img_header.image_sz);
          
          /* 1.2 MIBIB smart update, should go to sbl now */
          return BLRESULT_OK;
        }
      }

      bufp = blSearchCWEImage(CWE_IMAGE_TYPE_MODM, startbufp, hdr->image_sz);
      if (bufp != NULL)
      {
        memcpy((void *)&spkg_sub_img_header, (void *)&temphdr, sizeof(temphdr));
        if (blProgramModemImage(&spkg_sub_img_header, bufp + sizeof(struct cwe_header_s)) != BLRESULT_OK)
        {
          break;
        }
      }

      bufp = blSearchCWEImage(CWE_IMAGE_TYPE_APPL, startbufp, hdr->image_sz);
      if (bufp != NULL)
      {
        /* Got first APPL image here, Program it. */
        memcpy((void *)&spkg_sub_img_header, (void *)&temphdr, sizeof(temphdr));
        if (blProgramApplImage(&spkg_sub_img_header, bufp + sizeof(struct cwe_header_s)) != BLRESULT_OK)
        {
          break;
        }
        else
        {
          /* There may be 2nd APPL image in one SPKG file */
          startbuf_search_2nd_appl = bufp + sizeof(struct cwe_header_s) + spkg_sub_img_header.image_sz;
          buflen_search_2nd_appl = hdr->image_sz - (startbuf_search_2nd_appl - startbufp);

          bufp = blSearchCWEImage(CWE_IMAGE_TYPE_APPL, startbuf_search_2nd_appl, buflen_search_2nd_appl);
          if (bufp != NULL)
          {
            memcpy((void *)&spkg_sub_img_header, (void *)&temphdr, sizeof(temphdr));
            if (blProgramApplImage(&spkg_sub_img_header, bufp + sizeof(struct cwe_header_s)) != BLRESULT_OK)
            {
              break;
            }
          }
        }
      }

      bufp = blSearchCWEImage(CWE_IMAGE_TYPE_FILE, startbufp, hdr->image_sz);
      if (bufp != NULL)
      {
        memcpy((void *)&spkg_sub_img_header, (void *)&temphdr, sizeof(temphdr));
        if (blProgramImageFile(CWE_IMAGE_TYPE_FILE, bufp, temphdr.image_sz) != BLRESULT_OK)
        {
          break;
        }
      }
    }
    else
    {
      /* unsupported image, break and return error */
      break;
    }

    blsetcustompartition(NULL);

    return BLRESULT_OK;

  } while (0);

  if (flog_imgtype == CWE_IMAGE_TYPE_INVALID)
  {
    /* try to get image type from last processed CWE header */
    (void)cwe_image_type_validate(temphdr.image_type, &flog_imgtype);
  }

  memset(flog_typestr, 0, CWE_IMAGE_TYP_SZ + 1);
  imagep = cwe_image_string_get(flog_imgtype);
  if (imagep)
  {
    strncpy(flog_typestr, imagep, CWE_IMAGE_TYP_SZ);
  }
  else
  {
  }

  return result;

}

/************
 *
 * Name:     blProcessFastbootImage
 *
 * Purpose:  This function will process image from Fastboot.
 *
 * Params:   bufp - pointer to the download image buffer.
 *                image_size - image data length
 *
 * Return:   result code (as defined in 'enum blresultcode')
 *
 * Abort:    none
 *
 * Notes:    
 *           
 *
 ************/
_global enum blresultcode blProcessFastbootImage(unsigned char *bufp, unsigned int image_size)
{

  enum blresultcode result;
  /* ptr to control block structure */
  struct blCtrlBlk *cbp = blGetcbp(); 

  if ((bufp == NULL) || (image_size <= CWE_HEADER_SZ))
  {
    dprintf(CRITICAL, "BLRESULT_IMAGE_TYPE_INVALID\n");
    return BLRESULT_IMAGE_TYPE_INVALID;
  }

  (void)cwe_header_load(bufp, &cbp->blhd); /* extract the header */

  if (TRUE != cwe_image_validate(&cbp->blhd, 
                                                          bufp + sizeof(struct cwe_header_s), 
                                                          CWE_IMAGE_TYPE_ANY, 
                                                          BL_PRODUCT_ID, 
                                                          TRUE))
  {
    dprintf(CRITICAL, "BLRESULT_CRC32_CHECK_ERROR\n");
    return BLRESULT_CRC32_CHECK_ERROR;
  }

  /* Not used in this case, so set to 0 */
  cbp->blbytesleft = 0;
  
  result = blProgramCWEImage(&cbp->blhd,
                                                     bufp,
                                                     image_size,
                                                     cbp->blbytesleft);
  if (result != BLRESULT_OK)
  {
    dprintf(CRITICAL, "BLRESULT_FLASH_WRITE_ERROR\n");
  }
  else
  {
    dprintf(CRITICAL, "blProcessFastbootImage BLRESULT_OK\n");
  }

  return result;
}

