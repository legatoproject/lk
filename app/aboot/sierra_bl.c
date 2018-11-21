/************
 *
 * Filename:  sierra_bl.c
 *
 * Purpose:   Sierra Little Kernel changes
 *
 * Copyright: (c) 2015 Sierra Wireless, Inc.
 *            All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name of The Linux Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
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
#include <sierra/api/cowork_ssmem_structure.h>
#include <sierra/api/ssmemudefs.h>
#include <target.h>

/*
 *  externs
 */


/*
 *  Local variables
 */

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
 * Name:     sierra_is_bootquiet_disabled
 *
 * Purpose:  get bootquiet enable/disable from SMEM
 *
 * Parms:    none
 *
 * Return:   true : bootquiet disable
 *           false: bootquiet enable
 *
 * Abort:    none
 *
 * Notes:    none
 *
 ************/
bool sierra_is_bootquiet_disabled(void)
{
  struct cowork_ssmem_s *coworkp;
  bool is_disable = false;

  coworkp = ssmem_cowork_get();
  if (!coworkp)
  {
    return false;
  }
  is_disable = coworkp->boot_quiet ? true : false;

  return is_disable;
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
 * Name:     is_dual_system_supported
 *
 * Purpose:  Find the partition "modem2" in the partition table, it is AR, other is WP
 *
 * Parms:    None
 *
 * Return:   TRUE  - success ar
 *           FALSE - fail wp
 *
 * Abort:    None
 *
 * Notes:    None
 *
 ************/

bool is_dual_system_supported(void)
{
    /* ASCII : AR*/
    uint32 product_flag, product_name = 0x4152;
    struct ptable *ptable;
    struct ptentry *lptn;

    /* If can find the partition "modem2" in the partition table, we think it is AR.*/
    /* Otherwise, we think it is WP.*/
    ptable = flash_get_ptable();
    if (ptable == NULL)
    {
        dprintf(CRITICAL, "flash_write_sierra_file_img: flash_get_ptable failed\n");
        return BLRESULT_FLASH_WRITE_ERROR;
    }

    lptn = ptable_find(ptable, (const char *)BL_MODEM2_PARTI_NAME);
    if (lptn == NULL)
    {
        /* Can't find "modem2", we think it is WP.*/
        product_flag = 0;
        dprintf(CRITICAL, "is_dual_system_supported: ptable_find can't find: %s\n", BL_MODEM2_PARTI_NAME);
    }
    else
    {
        product_flag = product_name;
    }

    if (product_name == product_flag)
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
 * Name:     sierra_ds_smem_write_bad_image_and_swap
 *
 * Purpose:  Stub for compile purposes on WP, without needing to bring in additional
 *           dual system files.
 *
 * Parms:    None
 *
 * Return:   FALSE - fail wp
 *
 * Abort:    None
 *
 * Notes:    Stub
 *
 ************/

bool sierra_ds_smem_write_bad_image_and_swap(int stub){
  return FALSE;
}


/************
 *
 * Name:     sierra_ds_smem_get_ssid_linux_index
 *
 * Purpose:  Stub for compile purposes on WP, without needing to bring in additional
 *           dual system files.
 *
 * Parms:    None
 *
 * Return:   0 - wp
 *
 * Abort:    None
 *
 * Notes:    Stub
 *
 ************/

uint8_t sierra_ds_smem_get_ssid_linux_index(){
  return 0;
}


/************
 *
 * Name:     sierra_ds_get_full_data
 *
 * Purpose:  Stub for compile purposes on WP, without needing to bring in additional
 *           dual system files.
 *
 * Parms:    None
 *
 * Return:   FALSE - fail wp
 *
 * Abort:    None
 *
 * Notes:    Stub
 *
 ************/

bool sierra_ds_get_full_data(int stub){
  return FALSE;
}