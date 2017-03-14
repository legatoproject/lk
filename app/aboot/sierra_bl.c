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
#include "sierra_dsudefs.h"
#include <target.h>

/*
 *  externs
 */
extern void boot_linux_from_ram(void *data, unsigned sz);


/*
 *  Local variables
 */
_local struct cwe_header_s temphdr;

_local uint32 flash_write_addr = 0;

_local char *custom_part_name;

_local struct blCtrlBlk blc;

_local uint16 program_spkg_contain_image_mask = 0;

bool to_update_mibib = FALSE; /* Indicates modem should warm reset to SBL, to update MIBIB. */

enum bl_update_system_e update_which_system = BL_UPDATE_NONE; /* Indicates to write which system */

uint8 *second_ubi_images = NULL; /* Point to second UBI images during writing dual system */

/* Smart Error Recovery Thresholds: */
#define BLERRTHRESHOLD_FASTBOOT  6  /* enter into fastboot mode */

#define CRCCHUNKSIZE        500 /* Chunk size for successive calls to CRC
                                 * computation */


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

struct ds_flag_s bl_dsflag_s;


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

#ifdef SIERRA
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
  struct bscoworkmsg *msgp;
  unsigned char *virtual_addr;
  bool is_disable = false;

  virtual_addr = sierra_smem_base_addr_get();
  if (NULL != virtual_addr)
  {
    virtual_addr += BSMEM_COWORK_OFFSET;

    msgp = (struct bscoworkmsg *)virtual_addr;

    if (msgp->magic_beg == BS_SMEM_COWORK_MAGIC_BEG &&
        msgp->magic_end == BS_SMEM_COWORK_MAGIC_END &&
        msgp->crc32 == crcrc32((void *)msgp, BS_COWORK_CRC_SIZE, CRSTART_CRC32))
    {
      is_disable = msgp->bsbootquiet ? true : false;
    }
  }
  return is_disable;
}
#endif

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
  bool fastboot_mode = false;

  if(is_dual_system_supported())
  {
    if((sierra_smem_b2a_flags_get() & BC_MSG_B2A_DLOAD_MODE) &&
       (sierra_smem_err_count_get() > BLERRTHRESHOLD_FASTBOOT))
    {
      fastboot_mode = true;
      sierra_smem_err_count_set(0);
    }

    return fastboot_mode;
  }
  else
  {
    return (sierra_smem_err_count_get() > BLERRTHRESHOLD_FASTBOOT) ? true : false;
  }
}

/************
 *
 * Name:     swipart_get_logical_partition_from_backup
 *
 * Purpose:  Get the start block and end block of logical partition
 *                from physical 0:BACKUP partition
 *
 * Parms:    (IN) block_size -block size
 *               (IN) logical_partition - logical partition ID
 *               (OUT) start_block - start block of logical partition
 *               (OUT) end_block - end block of logical partition
 *
 * Return:   TRUE  - success
 *           FALSE - fail
 *
 * Abort:    None
 *
 * Notes:    None
 *
 ************/
boolean swipart_get_logical_partition_from_backup(
  uint32 block_size,
  backup_logical_partition_type logical_partition,
  uint32 *start_block,
  uint32 *end_block)
{
  uint32 dedb_block_count, sedb_block_count, log_block_count;

  /* Make sure it is not NULL in order to get correct 'block_size' */
  if ((end_block == NULL) || (start_block == NULL))
  {
    dprintf(CRITICAL, "swipart_get_logical_partition_from_backup, bad parameter\n");
    return FALSE;
  }

  if((logical_partition <= LOGICAL_PARTITION_NONE) || 
    (logical_partition >= LOGICAL_PARTITION_INVALID))
  {
    dprintf(CRITICAL, "wrong logical partition ID(%d)", logical_partition);
    return FALSE;
  }

  /* Calculate block count for every logical partition */
  dedb_block_count = LOGICAL_PARTITION_DEDB_SIZE/block_size;
  sedb_block_count = LOGICAL_PARTITION_SEDB_SIZE/block_size;
  log_block_count = LOGICAL_PARTITION_LOG_SIZE/block_size;

  /* Get start block and end block of logcial partition */
  *start_block = 0;
  *end_block = 0;
  switch(logical_partition)
  {
    case LOGICAL_PARTITION_DEDB:
      *start_block = 0;
      *end_block = dedb_block_count - 1;
      break;

    case LOGICAL_PARTITION_SEDB:
      *start_block = dedb_block_count;
      *end_block = dedb_block_count + sedb_block_count - 1;
      break;

    case LOGICAL_PARTITION_LOG:
      *start_block = dedb_block_count + sedb_block_count;
      *end_block = dedb_block_count + sedb_block_count + log_block_count - 1;
      break;

    default:
      dprintf(CRITICAL, "wrong logical partition ID(%d)", logical_partition);
      return FALSE;
  }

  return TRUE;
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
 * Name:     blgetrxbuf
 *
 * Purpose:  Get a pointer to rxbuf in BL control block
 *
 * Params:   None
 *
 * Return:   Pointer to the static Rx buffer
 *
 * Notes:
 *
 * Abort:
 *
 ************/
_global uint8 *blgetrxbuf(
  void)
{
  return blc.blcrxbuf;
}

/************
 *
 * Name:     bluisetstate
 *
 * Purpose:  Set the UI state
 *
 * Params:   state - UI state
 *
 * Return:   None
 *
 * Notes:    None
 *
 * Abort:    None
 *
 ************/
_global void bluisetstate(
  enum bluistateE state)
{
/* Just a stub function for porting source code */
}


/************
 *
 * Name:     blReset
 *
 * Purpose:  Internal BL function for Resetting
 *
 * Params:   None
 *
 * Return:   None
 *
 * Notes:    None
 *
 * Abort:
 *
 ************/
_global void blReset(
  void)
{
  reboot_device(0);
}


/************
 *
 * Name:     blCrcCheck
 *
 * Purpose:  Internal BL function for checking the CRC of a region of memory.
 *           This function is needed to wrap the CR package's CRC computing
 *           routine. It breaks what might be a long-duration call into several
 *           shorter-duration calls so the Watchdog can be kicked in between. The
 *           existing CR package routines do not know about the Watchdog.
 *
 * Params:   startaddp - Pointer to the address in memory to start computing the CRC from
 *           Length    - Number bytes to read in computing the CRC
 *           seed      - starting CRC seed
 *
 * Return:   crc32 - The 32-bit CRC corresponding to the region of memory specified in the
 *                   calling arguments
 *
 * Notes:    None
 *
 * Abort:
 *
 ************/
_local uint32 blCrcCheck(
  uint8 * address,
  uint32 length,
  uint32 seed)
{
  uint32 numbytes;              /* Number of bytes to call CRC routine with */

  if (address == NULL)
  {
    return seed;
  }

  /* Every CRCCHUNKSIZE bytes worth, kick the dog */
  while (length)
  {

    if (length != 0)
    {
      if (length > CRCCHUNKSIZE)
      {
        numbytes = CRCCHUNKSIZE;
        length -= CRCCHUNKSIZE;
      }
      else
      {
        numbytes = length;
        length = 0;
      }

      /* Set up to call CRC computation with next chunk */
      seed = crcrc32(address, numbytes, seed);

      /* Advance address pointer to next chunk */
      address += numbytes;
    }
  }
  return seed;
}


/************
 *
 * Name:     blsave2dloadram
 *
 * Purpose:  Copy buffer to RAM, update crc and download variables
 *
 * Params:   startflag - if this payload is CWE header
 *                       (CWE header should be skipped for CRC32 calculation)
 *           payloadp  - image payload
 *           tlen      - payload length 
 *
 * Return:   result code (as defined in 'enum blresultcode')
 *
 * Notes:    This function will be use by both Sirra boot downloader and QCT
 *           boot downloader
 *
 * Abort:
 *
 ************/
_local enum blresultcode blsave2dloadram(
  boolean startflag,
  uint8 *payloadp,
  uint32 tlen)
{
  /* ptr to control block structure */
  struct blCtrlBlk *cbp = blGetcbp(); 

  if ((payloadp == NULL) || (cbp == NULL))
  {
    return BLRESULT_UNSPECIFIED;
  }

  memmove(cbp->blcbufp, payloadp, tlen);

  /* In order to support partial flash writes during the download, start
   * calculating the crc as soon as any part of the image has arrived */
  if (startflag && tlen > sizeof(struct cwe_header_s))
  {
    cbp->blcrc32 = blCrcCheck(cbp->blcbufp + sizeof(struct cwe_header_s), tlen - sizeof(struct cwe_header_s), cbp->blcrc32);
  }
  else if (!startflag)
  {
    cbp->blcrc32 = blCrcCheck(cbp->blcbufp, tlen, cbp->blcrc32);
  }

  cbp->blcbufp += tlen;
  if (cbp->blbytesleft >= tlen)
  {
    cbp->blbytesleft -= tlen;
  }
  else
  {
    return BLRESULT_IMGSIZE_MISMATCH_ERROR;
  }

  return BLRESULT_OK;
}

/************
 *
 * Name:     blcallerror
 *
 * Purpose:  Process error condition
 *
 * Params:   error - error code
 *
 * Return:   error code
 *
 * Notes:
 *
 * Abort:
 *
 ************/
_package enum blresultcode blcallerror(
  enum blresultcode error,
  enum bl_dld_seq_e seq)
{
  return error;
}


/************
 *
 * Name:     blprocessdldcontinue - process Download Continue payload
 *
 * Purpose:  save payload to RAM, write to flash if necessary
 *
 * Params:   payloadp   - image payload
 *           tlen       - payload length 
 *           bytesleftp - output buffer to return number of bytes left for image
 *
 * Return:   process result code, see 'enum blresultcode'
 *
 * Notes:
 *
 * Abort:
 *
 ************/
_global enum blresultcode blprocessdldcontinue(
  uint8 *payloadp,
  uint32 tlen,
  uint32 *bytesleftp)
{
  /* ptr to control block structure */
  struct blCtrlBlk *cbp = blGetcbp(); 
  enum blresultcode result;

  if ((payloadp == NULL) || (cbp == NULL))
  {
    return BLRESULT_UNSPECIFIED;
  }

  /* make sure there is data to program */
  if (tlen)
  {
#if defined(SSDP_OVER_SPI)
    /* SPI special process here, because SPI won't get exact data len:  */
    tlen = tlen > cbp->blbytesleft ? cbp->blbytesleft:tlen;
#endif
    if (tlen > cbp->blbytesleft)
    {
      return blcallerror(BLRESULT_IMGSIZE_MISMATCH_ERROR, BL_DLD);
    }

    /* Copy buffer to RAM, update crc and download variables */
    result = blsave2dloadram(FALSE, payloadp, tlen);
    if (result != BLRESULT_OK)
    {
      return blcallerror(result, BL_DLD);
    }
  }

  if (bytesleftp)
  {
    *bytesleftp = cbp->blbytesleft;
  }
  return BLRESULT_OK;
}

/************
 *
 * Name:     bl_dload_area_start_get
 *
 * Purpose:  Returns the start of the download RAM area
 *
 * Params:   cbp - pointer to the download handler control block
 *
 * Return:   Start of download RAM area
 *
 * Notes:    None
 *
 * Abort:
 *
 ************/
_package uint8 *bl_dload_area_start_get(
  struct blCtrlBlk *cbp)
{
  return ((uint8 *)target_get_scratch_address());
}


/************
 *
 * Name:     bl_dload_area_used_size_get
 *
 * Purpose:  Get number of bytes already used in download area.
 *
 * Params:   cbp - pointer to the download handler control block
 *
 * Return:   Number of bytes used
 *
 * Notes:    Will use downloaded image size as 'used' size.
 *           Buffer after the downloaded image will be free to use 
 *           (as temp buffer for inflation for example) 
 *
 * Abort:
 *
 ************/
_package uint32 bl_dload_area_used_size_get(
  struct blCtrlBlk * cbp)
{
  if((uint32)(cbp->blcbufp) > (uint32)bl_dload_area_start_get(cbp))
  { 
    return ((uint32)(cbp->blcbufp) - (uint32)bl_dload_area_start_get(cbp));
  }
  else
  {
    return 0;
  }
}

/************
 *
 * Name:     blpkgchkver
 *
 * Purpose:  Check if package downloaded compatible with target
 *
 * Parms:    pkgverp - package version string from package CWE header
 *
 * Return:   TRUE if package version check passed, FALSE otherwise
 *
 * Abort:    none
 *
 * Notes:    SKU from package version string will be checked against 
 *           SKU set in the device, SKU is a UINT32 number:
 *           - if match, check pass;
 *           - if device SKU not set, check pass
 *           - if package version string is "INTERNAL_...", check pass
 *           otherwise check failed
 *
 ************/
_package boolean blpkgchkver(
  char *pkgverp)
{
/* SWI_TBD imorrison 14:08:26 - bcnvreadfromuserbackram not yet ported */
#if 1
  return TRUE;
#else
  static const char str_INTERNAL[] = "INTERNAL";
  uint32 pkgsku, devicesku, nvitemlen;
  uint8 *nvitemp;

  if(!pkgverp)
  {
    return FALSE;
  }

  /* Referring to "INTERNAL" directly seems causing problems and SPKG download speed becomes slow
   * and fail in the middle:
   * strncmp(pkgverp, "INTERNAL"...)
   */
  if(strncmp(pkgverp, str_INTERNAL, strlen(str_INTERNAL)) == 0)
  {
    /* generic package with only firmware, can work with any SKU */
    return TRUE;
  }

  /* if image switching is enabled, don't check SKU ID */
  bcnvreadfromuserbackram(NVMMT_TYPE_SWINV, 0, 0, FALSE, "CUST_GOBIIMEN", &nvitemp, &nvitemlen);
  if(nvitemp && nvitemlen == sizeof(uint8))
  {
    if(*nvitemp == NVCSTGOBIIM_ENABLE)
    {
      return TRUE;
    }
  }

  /* get package SKU, slatol will read the number until a non-digit char */
  pkgsku = slatol(pkgverp);  
  /* invalid SKU in package version, fail the check */
  if(!pkgsku)
  {
    return FALSE;
  }      

  if(pkgsku == BL_SPKG_TEST_SKU_NUM)
  {
    /* test SKU, accept anyway */  
    return TRUE;
  }

  /* read device SKU from NVBU area 
   * specify NV name diretctly since we don't want to link NV package into boot 
   */
  bcnvreadfromuserbackram(NVMMT_TYPE_SWINV, 0, 0, FALSE, "PRODUCT_SKU", &nvitemp, &nvitemlen);

  if(nvitemp && nvitemlen == sizeof(uint32))
  {
    /* note that nvitemp since it is might be 4 byte aligned */  
    memmove((void *)&devicesku, nvitemp, sizeof(uint32));
    if(devicesku == pkgsku)
    {
      return TRUE;
    }
  }
  else
  {
    /* no SKU set in device, pass the check */
    return TRUE;
  }

  return FALSE;
#endif
}

/*************
 *
 * Name:     bl_compatibility_test
 *
 * Purpose:  Tests whether the given compatibility value 
 *           matches the expected compatibility value for the 
 *           given image type
 *
 * Parms:    value - compatibility value to be compared with expected
 *           imagetype - image type for compatibility test
 *
 * Return:   TRUE - given compatibility value matches expected value
 *           FALSE - invalid image type or mismatched compatibility values
 *
 * Abort:    None
 *
 * Notes:    None
 *
 **************/
_package boolean bl_compatibility_test(uint32 value, enum cwe_image_type_e imagetype)
{
  boolean retVal = FALSE;

  switch (imagetype)
  {
    case CWE_IMAGE_TYPE_EXEC:    /* hardware compatibility only */
      if ((value & BL_HW_COMPAT_MASK) == BL_HW_COMPAT_BYTE)
      {
        retVal = TRUE;
      }
      break;

    case CWE_IMAGE_TYPE_BOOT:
    case CWE_IMAGE_TYPE_OSBL:
      if ((value & BL_BOOT_COMPAT_MASK) == BL_BOOT_COMPAT_WORD)
      {
        retVal = TRUE;
      }
      break;

    case CWE_IMAGE_TYPE_APPL:    /* Firmware (boot-app) compatibility */
    case CWE_IMAGE_TYPE_AMSS:
    case CWE_IMAGE_TYPE_APPS:
    case CWE_IMAGE_TYPE_APBL:
    case CWE_IMAGE_TYPE_DSP2:
    case CWE_IMAGE_TYPE_MODM:
      if ((value & BL_APP_COMPAT_MASK) == BL_APP_COMPAT_WORD)
      {
        retVal = TRUE;
      }
      break;

    case CWE_IMAGE_TYPE_SWOC:    /* no compatibility requirement */
    case CWE_IMAGE_TYPE_FOTO:
    case CWE_IMAGE_TYPE_HDAT:
      retVal = TRUE;
      break;

    default:                    /* all other image types just return FALSE */
      retVal = FALSE;
      break;

  }

  if (imagetype == CWE_IMAGE_TYPE_FILE)
  {
    /* no compatibility requirement for file types */
    retVal = TRUE;
  }

  return retVal;
}


/************
 *
 * Name:     bl_dload_area_size_get
 *
 * Purpose:  Returns the size of the download RAM area
 *
 * Params:   cbp - pointer to the download handler control block
 *
 * Return:   Size of download RAM area
 *
 * Notes:    None 
 *
 * Abort:
 *
 ************/
_package uint32 bl_dload_area_size_get(
  struct blCtrlBlk * cbp)
{

  return ((uint32)target_get_max_flash_size());
}

/************
 *
 * Name:     blprocessdldstart
 *
 * Purpose:  Verify CWE header from Download Start Request message.
 *           Extract the header info, validate it and save the related info
 *           to control block.
 *
 * Params:   cwehdrp  - CWE header pointer from Download Start Request message
 *           tlen     - cwehdrp buffer length (payload len of Download Start Request) 
 *           errmsgpp - error message to be returned if validate failed
 *
 * Return:   process result code, see 'enum blresultcode'
 *
 * Notes:    This function will be use by both Sirra boot downloader and QCT
 *           boot downloader
 *
 * Abort:
 *
 ************/
_global enum blresultcode blprocessdldstart(
  uint8 *cwehdrp,
  uint32 tlen)
{
  enum blresultcode result;
  /* ptr to control block structure */
  struct blCtrlBlk *cbp = blGetcbp(); 

  if ((cwehdrp == NULL) || (cbp == NULL))
  {
    return BLRESULT_UNSPECIFIED;
  }

  /* Firmware Device Update Logging Feature */
  char typeStr[CWE_IMAGE_TYP_SZ + 1];
  char bcVerStr[CWE_VER_STR_SZ + 1];
  const char *imagep;

  if (tlen < sizeof(struct cwe_header_s))
  {
    /* wrong header length */
    return blcallerror(BLRESULT_CWE_HEADER_ERROR, BL_DLD_PREDLD_VERIFY);
  }

  /* Firmware Device Update Logging Feature */
  memset(typeStr, 0, CWE_IMAGE_TYP_SZ + 1);
  memset(bcVerStr, 0, CWE_VER_STR_SZ + 1);
  (void)strncpy(bcVerStr, (char *)cwehdrp + CWE_OFFSET_VERSION, CWE_VER_STR_SZ);


  /* clear checksum counter and reset CRC seed */
  cbp->blchcksum = 0;
  cbp->blcrc32 = CRSTART_CRC32;

  (void)cwe_header_load(cwehdrp, &cbp->blhd); /* extract the header */

  /* validate the image type from the CWE header */
  if (cwe_image_type_validate(cbp->blhd.image_type, &cbp->imagetype) == FALSE)
  {
     return blcallerror(BLRESULT_IMAGE_TYPE_INVALID, BL_DLD_PREDLD_VERIFY);
  }

  imagep = cwe_image_string_get(cbp->imagetype);
  if (imagep)
  {
    (void)strncpy(typeStr, imagep, CWE_IMAGE_TYP_SZ);
  }
  else
  {
  }

  /* For most images, validate the product type from the CWE header. Some,
   * such as SWoC can be universal */
  switch (cbp->imagetype)
  {
    case CWE_IMAGE_TYPE_SWOC:
    case CWE_IMAGE_TYPE_HDAT:
      break;

    default:
      if (cbp->blhd.prod_type != BL_PRODUCT_ID)
      {
        /* wrong file for this product */
        return blcallerror(BLRESULT_PRODUCT_TYPE_INVALID, BL_DLD_PREDLD_VERIFY);
      }
      break;
  }

  /* With NAND flash, we prefer to download as much of the image as possible
   * to SDRAM before programming flash.  We now ignore the store address in
   * the CWE header (mainly an artifact of NOR flash support) and use a
   * hardcoded value. */
  cbp->blcbufp = bl_dload_area_start_get(cbp);

  /* Determine the total number of bytes remaining in the download and check
   * we haven't already received too many */
  cbp->blbytesleft = cbp->blhd.image_sz + sizeof(struct cwe_header_s);
  if (tlen > cbp->blbytesleft)
  {
    return blcallerror(BLRESULT_IMGSIZE_MISMATCH_ERROR, BL_DLD_PREDLD_VERIFY);
  }

  /* Image must fit into the RAM download area */
  if (cbp->blbytesleft > bl_dload_area_size_get(cbp))
  {
    return blcallerror(BLRESULT_IMGSIZE_OUT_OF_RANGE, BL_DLD_PREDLD_VERIFY);
  }

  /* Test compatibility bytes according to image type */
  if (bl_compatibility_test(cbp->blhd.compat, cbp->imagetype) == FALSE)
  {
    switch (cbp->imagetype)
    {
      case CWE_IMAGE_TYPE_APPL:
        return blcallerror(BLRESULT_APPL_NOT_COMPATIBLE, BL_DLD_PREDLD_VERIFY);

      case CWE_IMAGE_TYPE_EXEC:
        return blcallerror(BLRESULT_BOOT_NOT_COMPATIBLE, BL_DLD_PREDLD_VERIFY);

      default:
        break;
    }
  }

  /* Check signature if imagetype is an application */
  if (cbp->imagetype == CWE_IMAGE_TYPE_APPL)
  {
    if (cbp->blhd.signature != CWE_SIGNATURE_APP)
    {
      return blcallerror(BLRESULT_SIGNATURE_INVALID, BL_DLD_PREDLD_VERIFY);
    }
  }
  else if (cbp->imagetype == CWE_IMAGE_TYPE_SPKG)
  {
    /* check SPKG compatibility */
    if (!blpkgchkver((char *)cbp->blhd.version))
    {
      return blcallerror(BLRESULT_PKG_NOT_COMPATIBLE, BL_DLD_PREDLD_VERIFY);
    }  
  }

  /* Initialize blflash */

  /* would not allow smart recovery in the middle of firmware upgrade */

  /* Set UI state to DOWNLOADING */
  bluisetstate(BLUISTATE_DOWNLOADING);

  /* save payload to DLOAD RAM area */
  result = blsave2dloadram(TRUE, cwehdrp, tlen);

  if (result != BLRESULT_OK)
  {
    blcallerror(result, BL_DLD);
  }
  return result;
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
_global boolean blGoCweFile(unsigned char *buf, unsigned int len)
{
  unsigned int ret;
  if((len < CWE_HEADER_SZ) || (!cwe_header_load(buf, &temphdr)))
  {
    return FALSE;
  }

  if (TRUE != cwe_image_validate(&temphdr,
                                                          buf + sizeof(struct cwe_header_s),
                                                          CWE_IMAGE_TYPE_FILE,
                                                          0,
                                                          FALSE))
  {
    return FALSE;
  }

  return TRUE;
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
    if (flash_write_sierra_file_img(ptn, extra, (const void *)bufp, (unsigned)write_size)) {
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

  if(image_type == FLASH_PROG_SBL1_IMG)
  {
    /* SBL image need special processing for boot redundancy */
    if(flash_write_addr != 0 || bytesleft != 0)
    {
      /* complete image only */
      return BLRESULT_IMGSIZE_OUT_OF_RANGE;
    }
    
    return blredundancy_sbl_program(bufp, write_size);
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
      if((0 == strcmp(ptn->name, BL_TZ_PARTI_NAME))
         || (0 == strcmp(ptn->name, BL_RPM_PARTI_NAME)))
      {
        if (0 != flash_write_sierra_tz_rpm(ptn, 
                                           (void *)bufp, 
                                           (unsigned)write_size,
                                           (uint8_t)update_which_system)) 
        {
          dprintf(CRITICAL, "flash write dual TZ or RPM failure\n");
          return BLRESULT_FLASH_WRITE_ERROR;
        }
        else
        {
          dprintf(INFO, "flash_write_sierra_dual_tz_rpm raw OK!\n");
        }
      }
      else
      {
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

/* SWI_TBD [jaliu:2016-10-18]: QTI9X40-911, remove the image validation in here in order to
* save time in SIERRA factory.
* 1. There is already image validation in function blProcessFastbootImage().
* 2. Integration team will make sure each sub image valid before SW update.
* 3. MFT team will make sure system1 and system2 can works normally before module leave 
* SIERRA factory.
* 4.due to 9x40 use #if 0 cancel.I think reliability should cancel,
*/
  if(!is_dual_system_supported())
  {
    if (TRUE != cwe_image_validate(&temphdr, 
                                                            bufp + sizeof(struct cwe_header_s), 
                                                            CWE_IMAGE_TYPE_ANY, 
                                                            BL_PRODUCT_ID, 
                                                            TRUE))
    {
      dprintf(CRITICAL, "BLRESULT_CRC32_CHECK_ERROR\n");
      return BLRESULT_CRC32_CHECK_ERROR;
    }
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
 * Name:     blProgramModemImage
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
    /*clear program_spkg_contain_image_mask modem flag*/
    program_spkg_contain_image_mask &= (~SPKG_IMAGE_MODEM);
    switch(update_which_system)
    {
      case BL_UPDATE_DUAL_SYSTEM:
        /* Store second DSP2 image as flash_ubi_img() will modify the image with UBI format */
        memcpy(second_ubi_images, bufp, temphdr.image_sz + sizeof(struct cwe_header_s));

        /* Program DSP2 image to modem2 partition */
        blsetcustompartition(BL_MODEM2_PARTI_NAME);
        result = blProgramImage(second_ubi_images, FLASH_PROG_DSP2_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_MODEM_2);
          dprintf(CRITICAL, "blProgramModemImage CWE_IMAGE_TYPE_DSP2 to modem2 failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_MODEM_2);
        }

        /* Program DSP1 image to modem partition*/
        blsetcustompartition(BL_MODEM_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_DSP2_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_MODEM_1);
          dprintf(CRITICAL, "blProgramModemImage CWE_IMAGE_TYPE_DSP2 to modem failed, ret:%d\n", result);
          return result;
        }
        else
        {
          program_spkg_contain_image_mask |= SPKG_IMAGE_MODEM;
          bl_dsflag_s.bad_image &= (~DS_IMAGE_MODEM_1);
        }
        break;

      case BL_UPDATE_SYSTEM1:
        /* Program DSP2 image to modem partition*/
        blsetcustompartition(BL_MODEM_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_DSP2_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_MODEM_1);
          dprintf(CRITICAL, "blProgramModemImage CWE_IMAGE_TYPE_DSP2 to modem failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_MODEM_1);
        }
        break;

      case BL_UPDATE_SYSTEM2:
        /* Program DSP2 image to modem2 partition*/
        blsetcustompartition(BL_MODEM2_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_DSP2_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_MODEM_2);
          dprintf(CRITICAL, "blProgramModemImage CWE_IMAGE_TYPE_DSP2 to modem2 failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_MODEM_2);
        }
        break;

      default:
        dprintf(CRITICAL, "blProgramModemImage, wrong parameter update_which_system:%d\n", update_which_system);
        break;
    }
  }

  return result;
}

/************
 *
 * Name:     blProgramApplImage
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
  uint8         *bufp2;
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
    /*clear program_spkg_contain_image_mask system flag*/
    program_spkg_contain_image_mask &= (~SPKG_IMAGE_SYSTEM);
    switch(update_which_system)
    {
      case BL_UPDATE_DUAL_SYSTEM:
        /* Store second SYSTEM image as flash_ubi_img() will modify the image with UBI format */
        memcpy(second_ubi_images, bufp, temphdr.image_sz + sizeof(struct cwe_header_s));

        blsetcustompartition(BL_LINUX_SYSTEM2_PARTI_NAME);
        result = blProgramImage(second_ubi_images, FLASH_PROG_ROFS1_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_SYSTEM_2);
          dprintf(CRITICAL, "blProgramApplImage CWE_IMAGE_TYPE_SYST to system2 failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_SYSTEM_2);
        }

        blsetcustompartition(BL_LINUX_SYSTEM_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_ROFS1_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_SYSTEM_1);
          dprintf(CRITICAL, "blProgramApplImage CWE_IMAGE_TYPE_SYST to system failed, ret:%d\n", result);
          return result;
        }
        else
        {
          program_spkg_contain_image_mask |= SPKG_IMAGE_SYSTEM;
          bl_dsflag_s.bad_image &= (~DS_IMAGE_SYSTEM_1);
        }
        break;

      case BL_UPDATE_SYSTEM1:
        blsetcustompartition(BL_LINUX_SYSTEM_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_ROFS1_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_SYSTEM_1);
          dprintf(CRITICAL, "blProgramApplImage CWE_IMAGE_TYPE_SYST to system failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_SYSTEM_1);
        }
        break;

      case BL_UPDATE_SYSTEM2:
        blsetcustompartition(BL_LINUX_SYSTEM2_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_ROFS1_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_SYSTEM_2);
          dprintf(CRITICAL, "blProgramApplImage CWE_IMAGE_TYPE_SYST to system2 failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_SYSTEM_2);
        }
        break;

      default:
        dprintf(CRITICAL, "blProgramApplImage, wrong parameter update_which_system:%d\n", update_which_system);
        break;
    }
  }

  /* Program Linux USERDATA image, (maybe in format .yaffs2, UBI, squashfs) */
  bufp = blSearchCWEImage(CWE_IMAGE_TYPE_USER, startbufp, hdr->image_sz);
  if (bufp != NULL)
  {
    switch(update_which_system)
    {
      /*clear program_spkg_contain_image_mask legato flag*/
      program_spkg_contain_image_mask &= (~SPKG_IMAGE_LEGATO);
      case BL_UPDATE_DUAL_SYSTEM:
        /* Store second LEFWKRO image as flash_ubi_img() will modify the image with UBI format */
        memcpy(second_ubi_images, bufp, temphdr.image_sz + sizeof(struct cwe_header_s));

        blsetcustompartition(BL_LINUX_UDATA2_PARTI_NAME);
        result = blProgramImage(second_ubi_images, FLASH_PROG_USDATA_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_USERDATA_2);
          dprintf(CRITICAL, "blProgramApplImage CWE_IMAGE_TYPE_USER to lefwkro2 failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_USERDATA_2);
        }

        blsetcustompartition(BL_LINUX_UDATA_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_USDATA_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_USERDATA_1);
          dprintf(CRITICAL, "blProgramApplImage CWE_IMAGE_TYPE_USER to lefwkro failed, ret:%d\n", result);
          return result;
        }
        else
        {
          program_spkg_contain_image_mask |= SPKG_IMAGE_LEGATO;
          bl_dsflag_s.bad_image &= (~DS_IMAGE_USERDATA_1);
        }
        break;

      case BL_UPDATE_SYSTEM1:
        blsetcustompartition(BL_LINUX_UDATA_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_USDATA_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_USERDATA_1);
          dprintf(CRITICAL, "blProgramApplImage CWE_IMAGE_TYPE_USER to lefwkro failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_USERDATA_1);
        }
        break;

      case BL_UPDATE_SYSTEM2:
        blsetcustompartition(BL_LINUX_UDATA2_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_USDATA_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_USERDATA_2);
          dprintf(CRITICAL, "blProgramApplImage CWE_IMAGE_TYPE_USER to lefwkro2 failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_USERDATA_2);
        }
        break;

      default:
        dprintf(CRITICAL, "blProgramApplImage, wrong parameter update_which_system:%d\n", update_which_system);
        break;
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
    /*clear program_spkg_contain_image_mask kernel flag*/
    program_spkg_contain_image_mask &= (~SPKG_IMAGE_KERNEL);
    switch(update_which_system)
    {
      case BL_UPDATE_DUAL_SYSTEM:
        bufp2 = bufp;
        blsetcustompartition(BL_LINUX_BOOT2_PARTI_NAME);
        result = blProgramImage(bufp2, FLASH_PROG_CUSTOM_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_BOOT_2);
          dprintf(CRITICAL, "blProgramApplImage CWE_IMAGE_TYPE_APPS to boot2 failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_BOOT_2);
        }

        blsetcustompartition(BL_LINUX_BOOT_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_CUSTOM_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_BOOT_1);
          dprintf(CRITICAL, "blProgramApplImage CWE_IMAGE_TYPE_APPS to boot failed, ret:%d\n", result);
          return result;
        }
        else
        {
          program_spkg_contain_image_mask |= SPKG_IMAGE_KERNEL;
          bl_dsflag_s.bad_image &= (~DS_IMAGE_BOOT_1);
        }
        break;

      case BL_UPDATE_SYSTEM1:
        blsetcustompartition(BL_LINUX_BOOT_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_CUSTOM_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_BOOT_1);
          dprintf(CRITICAL, "blProgramApplImage CWE_IMAGE_TYPE_APPS to boot failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_BOOT_1);
        }
        break;

      case BL_UPDATE_SYSTEM2:
        blsetcustompartition(BL_LINUX_BOOT2_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_CUSTOM_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_BOOT_2);
          dprintf(CRITICAL, "blProgramApplImage CWE_IMAGE_TYPE_APPS to boot2 failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_BOOT_2);
        }
        break;

      default:
        dprintf(CRITICAL, "blProgramApplImage, wrong parameter update_which_system:%d\n", update_which_system);
        break;
    }
  }

  /*program customer image*/
  switch(update_which_system)
  {
    case BL_UPDATE_DUAL_SYSTEM:
      /* program Linux image */
      bufp = blSearchCWEImage(CWE_IMAGE_TYPE_CUS0, startbufp, hdr->image_sz);
      if (bufp != NULL)
      {
        /* program Linux CUS0(CUSTOMER0) image */
        blsetcustompartition(BL_CUSTOMER0_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_USAPP_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_CUSTOMERAPP_1);
          dprintf(CRITICAL, "blProgramApplImage sierra-dual-system CWE_IMAGE_TYPE_CUS0 to customer0 failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_CUSTOMERAPP_1);
        }
        /* program Linux CUS0(CUSTOMER1) image */
        blsetcustompartition(BL_CUSTOMER1_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_USAPP_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_CUSTOMERAPP_2);
          dprintf(CRITICAL, "blProgramApplImage sierra-dual-system CWE_IMAGE_TYPE_CUS0 to customer1 failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_CUSTOMERAPP_2);
        }
      }

      /* program Linux image */
      bufp = blSearchCWEImage(CWE_IMAGE_TYPE_CUS1, startbufp, hdr->image_sz);
      if (bufp != NULL)
      {
        /* program Linux CUS1(CUSTOMER0) image */
        blsetcustompartition(BL_CUSTOMER0_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_USAPP_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_CUSTOMERAPP_1);
          dprintf(CRITICAL, "blProgramApplImage sierra-dual-system CWE_IMAGE_TYPE_CUS1 to customer0 failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_CUSTOMERAPP_1);
        }
        /* program Linux CUS1(CUSTOMER1) image */
        blsetcustompartition(BL_CUSTOMER1_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_USAPP_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_CUSTOMERAPP_2);
          dprintf(CRITICAL, "blProgramApplImage sierra-dual-system CWE_IMAGE_TYPE_CUS1 to customer1 failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_CUSTOMERAPP_2);
        }
      }

      /* program Linux CUS2(CUSTOMER2) image */
      bufp = blSearchCWEImage(CWE_IMAGE_TYPE_CUS2, startbufp, hdr->image_sz);
      if (bufp != NULL)
      {
        blsetcustompartition(BL_CUSTOMER2_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_USAPP_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_CUSTOMERAPP_3);
          dprintf(CRITICAL, "blProgramApplImage sierra-dual-system CWE_IMAGE_TYPE_CUS2 to customer2 failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_CUSTOMERAPP_3);
        }
      }
      break;

    case BL_UPDATE_SYSTEM1:
      /* program Linux CUS0(CUSTOMER0) image */
      bufp = blSearchCWEImage(CWE_IMAGE_TYPE_CUS0, startbufp, hdr->image_sz);
      if (bufp != NULL)
      {
        blsetcustompartition(BL_CUSTOMER0_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_USAPP_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_CUSTOMERAPP_1);
          dprintf(CRITICAL, "blProgramApplImage sierra1 CWE_IMAGE_TYPE_CUS0 to customer0 failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_CUSTOMERAPP_1);
        }
      }

      /* program Linux CUS1(CUSTOMER0) image */
      bufp = blSearchCWEImage(CWE_IMAGE_TYPE_CUS1, startbufp, hdr->image_sz);
      if (bufp != NULL)
      {
        blsetcustompartition(BL_CUSTOMER0_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_USAPP_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_CUSTOMERAPP_1);
          dprintf(CRITICAL, "blProgramApplImage sierra1 CWE_IMAGE_TYPE_CUS1 to customer0 failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_CUSTOMERAPP_1);
        }
      }

      /* program Linux CUS2(CUSTOMER2) image */
      bufp = blSearchCWEImage(CWE_IMAGE_TYPE_CUS2, startbufp, hdr->image_sz);
      if (bufp != NULL)
      {
        blsetcustompartition(BL_CUSTOMER2_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_USAPP_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_CUSTOMERAPP_3);
          dprintf(CRITICAL, "blProgramApplImage sierra1 CWE_IMAGE_TYPE_CUS2 to customer2 failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_CUSTOMERAPP_3);
        }
      }
      break;

    case BL_UPDATE_SYSTEM2:
      /* program Linux CUS0(CUSTOMER0) image */
      bufp = blSearchCWEImage(CWE_IMAGE_TYPE_CUS0, startbufp, hdr->image_sz);
      if (bufp != NULL)
      {
        blsetcustompartition(BL_CUSTOMER1_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_USAPP_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_CUSTOMERAPP_2);
          dprintf(CRITICAL, "blProgramApplImage sierra2 CWE_IMAGE_TYPE_CUS0 to customer1 failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_CUSTOMERAPP_2);
        }
      }

      /* program Linux CUS0(CUSTOMER1) image */
      bufp = blSearchCWEImage(CWE_IMAGE_TYPE_CUS1, startbufp, hdr->image_sz);
      if (bufp != NULL)
      {
        blsetcustompartition(BL_CUSTOMER1_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_USAPP_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_CUSTOMERAPP_2);
          dprintf(CRITICAL, "blProgramApplImage sierra2 CWE_IMAGE_TYPE_CUS1 to customer1 failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_CUSTOMERAPP_2);
        }
      }

      /* program Linux CUS2(CUSTOMER2) image */
      bufp = blSearchCWEImage(CWE_IMAGE_TYPE_CUS2, startbufp, hdr->image_sz);
      if (bufp != NULL)
      {
        blsetcustompartition(BL_CUSTOMER2_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_USAPP_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_CUSTOMERAPP_3);
          dprintf(CRITICAL, "blProgramApplImage sierra2 CWE_IMAGE_TYPE_CUS2 to customer2 failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_CUSTOMERAPP_3);
        }
      }
      break;

    default:
      dprintf(CRITICAL, "blProgramApplImage, program customer wrong parameter update_which_system:%d\n", update_which_system);
      break;
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
  uint8         *bufp2;
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
      bl_dsflag_s.bad_image |= (DS_IMAGE_SBL);
      dprintf(CRITICAL, "blProgramBootImage CWE_IMAGE_TYPE_SBL1 failed, ret:%d\n", result);
      return result;
    }
    else
    {
      bl_dsflag_s.bad_image &= (~DS_IMAGE_SBL);
    }
  }

  bufp = blSearchCWEImage(CWE_IMAGE_TYPE_TZON, startbufp, hdr->image_sz);
  if (bufp != NULL)
  {
    /*clear program_spkg_contain_image_mask tz flag*/
    program_spkg_contain_image_mask &= (~SPKG_IMAGE_TZ);
    /* Program TZ image */
    blsetcustompartition(BL_TZ_PARTI_NAME);
    result = blProgramImage(bufp, FLASH_PROG_CUSTOM_IMG, temphdr.image_sz);
    if (result != BLRESULT_OK)
    {
      switch(update_which_system)
      {
        case BL_UPDATE_DUAL_SYSTEM:
          bl_dsflag_s.bad_image |= (DS_IMAGE_TZ_2);

        case BL_UPDATE_SYSTEM1:
          bl_dsflag_s.bad_image |= (DS_IMAGE_TZ_1);
          break;

        case BL_UPDATE_SYSTEM2:
          bl_dsflag_s.bad_image |= (DS_IMAGE_TZ_2);
          break;

        default:
          dprintf(CRITICAL, "blProgramBootImage, wrong parameter update_which_system:%d\n", update_which_system);
          break;
      }
      dprintf(CRITICAL, "blProgramBootImage CWE_IMAGE_TYPE_TZON failed, ret:%d\n", result);
      return result;
    }
    else
    {
      switch(update_which_system)
      {
        case BL_UPDATE_DUAL_SYSTEM:
          program_spkg_contain_image_mask |= SPKG_IMAGE_TZ;
          bl_dsflag_s.bad_image &= (~DS_IMAGE_TZ_2);
          bl_dsflag_s.bad_image &= (~DS_IMAGE_TZ_1);
          break;

        case BL_UPDATE_SYSTEM1:
          bl_dsflag_s.bad_image &= (~DS_IMAGE_TZ_1);
          break;

        case BL_UPDATE_SYSTEM2:
          bl_dsflag_s.bad_image &= (~DS_IMAGE_TZ_2);
          break;

        default:
          dprintf(CRITICAL, "blProgramBootImage, wrong parameter update_which_system:%d\n", update_which_system);
          break;
      }
    }
  }

  /* program RPM at very last */
  bufp = blSearchCWEImage(CWE_IMAGE_TYPE_QRPM, startbufp, hdr->image_sz);
  if (bufp != NULL)
  {
    /*clear program_spkg_contain_image_mask rpm flag*/
    program_spkg_contain_image_mask &= (~SPKG_IMAGE_RPM);
    /* Program RPM image  */
    blsetcustompartition(BL_RPM_PARTI_NAME);
    result = blProgramImage(bufp, FLASH_PROG_CUSTOM_IMG, temphdr.image_sz);
    if (result != BLRESULT_OK)
    {
      switch(update_which_system)
      {
        case BL_UPDATE_DUAL_SYSTEM:
          bl_dsflag_s.bad_image |= (DS_IMAGE_RPM_2);

        case BL_UPDATE_SYSTEM1:
          bl_dsflag_s.bad_image |= (DS_IMAGE_RPM_1);
          break;

        case BL_UPDATE_SYSTEM2:
          bl_dsflag_s.bad_image |= (DS_IMAGE_RPM_2);
          break;

        default:
          dprintf(CRITICAL, "blProgramBootImage, wrong parameter update_which_system:%d\n", update_which_system);
          break;
      }
      dprintf(CRITICAL, "blProgramBootImage CWE_IMAGE_TYPE_QRPM failed, ret:%d\n", result);
      return result;
    }
    else
    {
      switch(update_which_system)
      {
        case BL_UPDATE_DUAL_SYSTEM:
          program_spkg_contain_image_mask |= SPKG_IMAGE_RPM;
          bl_dsflag_s.bad_image &= (~DS_IMAGE_RPM_2);
          bl_dsflag_s.bad_image &= (~DS_IMAGE_RPM_1);
          break;

        case BL_UPDATE_SYSTEM1:
          bl_dsflag_s.bad_image &= (~DS_IMAGE_RPM_1);
          break;

        case BL_UPDATE_SYSTEM2:
          bl_dsflag_s.bad_image &= (~DS_IMAGE_RPM_2);
          break;

        default:
          dprintf(CRITICAL, "blProgramBootImage, wrong parameter update_which_system:%d\n", update_which_system);
          break;
      }
    }
  }

  /* program APBL last */
  bufp = blSearchCWEImage(CWE_IMAGE_TYPE_APBL, startbufp, hdr->image_sz);
  if (bufp != NULL)
  {
    /*clear program_spkg_contain_image_mask lk flag*/
    program_spkg_contain_image_mask &= (~SPKG_IMAGE_LK);
    switch(update_which_system)
    {
      case BL_UPDATE_DUAL_SYSTEM:
        bufp2 = bufp;
        /* Program APBL image to aboot2*/
        blsetcustompartition(BL_ABOOT2_PARTI_NAME);
        result = blProgramImage(bufp2, FLASH_PROG_CUSTOM_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_ABOOT_2);
          dprintf(CRITICAL, "blProgramBootImage CWE_IMAGE_TYPE_APBL to aboot2 failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_ABOOT_2);
        }

        /* Program APBL image to aboot */
        blsetcustompartition(BL_ABOOT_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_CUSTOM_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_ABOOT_1);
          dprintf(CRITICAL, "blProgramBootImage CWE_IMAGE_TYPE_APBL to aboot failed, ret:%d\n", result);
          return result;
        }
        else
        {
          program_spkg_contain_image_mask |= SPKG_IMAGE_LK;
          bl_dsflag_s.bad_image &= (~DS_IMAGE_ABOOT_1);
        }
        break;

      case BL_UPDATE_SYSTEM1:
        /* Program APBL image to aboot */
        blsetcustompartition(BL_ABOOT_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_CUSTOM_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_ABOOT_1);
          dprintf(CRITICAL, "blProgramBootImage CWE_IMAGE_TYPE_APBL to aboot failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_ABOOT_1);
        }
        break;

      case BL_UPDATE_SYSTEM2:
        /* Program APBL image to aboot2*/
        blsetcustompartition(BL_ABOOT2_PARTI_NAME);
        result = blProgramImage(bufp, FLASH_PROG_CUSTOM_IMG, temphdr.image_sz);
        if (result != BLRESULT_OK)
        {
          bl_dsflag_s.bad_image |= (DS_IMAGE_ABOOT_2);
          dprintf(CRITICAL, "blProgramBootImage CWE_IMAGE_TYPE_APBL to aboot2 failed, ret:%d\n", result);
          return result;
        }
        else
        {
          bl_dsflag_s.bad_image &= (~DS_IMAGE_ABOOT_2);
        }
        break;

      default:
        dprintf(CRITICAL, "blProgramBootImage, wrong parameter update_which_system:%d\n", update_which_system);
        break;
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

  /*blprogram CWE Image,read out of sync flag, if out of sync flag set sync,set mask flag*/
  if(sierra_ds_check_if_ds_is_sync())
  {
    program_spkg_contain_image_mask |= SPKG_IMAGE_TZ;
    program_spkg_contain_image_mask |= SPKG_IMAGE_RPM;
    program_spkg_contain_image_mask |= SPKG_IMAGE_LK;
    program_spkg_contain_image_mask |= SPKG_IMAGE_KERNEL;
    program_spkg_contain_image_mask |= SPKG_IMAGE_SYSTEM;
    program_spkg_contain_image_mask |= SPKG_IMAGE_MODEM;
    program_spkg_contain_image_mask |= SPKG_IMAGE_LEGATO;
  }

  /* validate the image type from the CWE sub-header */
  if (cwe_image_type_validate(hdr->image_type, &imagetype) == FALSE)
  {
    dprintf(CRITICAL, "BLRESULT_CWE_HEADER_ERROR\n");
    return BLRESULT_CWE_HEADER_ERROR;
  }

  sierra_ds_get_full_data(&bl_dsflag_s);

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

    /* We consider program done, so we should update bad image flag */
    /* To make it easy, we make it out of sync if any FW image update */
    if((SPKG_IMAGE_TZ & program_spkg_contain_image_mask)
      &&(SPKG_IMAGE_RPM & program_spkg_contain_image_mask)
      &&(SPKG_IMAGE_LK & program_spkg_contain_image_mask)
      &&(SPKG_IMAGE_KERNEL & program_spkg_contain_image_mask)
      &&(SPKG_IMAGE_SYSTEM & program_spkg_contain_image_mask)
      &&(SPKG_IMAGE_MODEM & program_spkg_contain_image_mask)
      &&(SPKG_IMAGE_LEGATO & program_spkg_contain_image_mask))
    {
      bl_dsflag_s.out_of_sync = DS_IS_SYNC;
    }
    else
    {
      bl_dsflag_s.out_of_sync = DS_OUT_OF_SYNC;
    }
    sierra_ds_update_ssdata(&bl_dsflag_s, NULL);

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

  /* We consider program done, so we should update bad image flag */
  /* To make it easy, we make it out of sync if any FW image update */
  bl_dsflag_s.out_of_sync = DS_OUT_OF_SYNC;
  sierra_ds_update_ssdata(&bl_dsflag_s, NULL);
  
  return result;

}

/************
 *
 * Name:     blprocessdldend - process Download done
 *
 * Purpose:  Process the host's Download done image and write image to flash
 *
 * Params:   none
 *
 * Return:   result code (as defined in 'enum blresultcode')
 *
 * Notes:
 *
 * Abort:
 *
 ************/
_global enum blresultcode blprocessdldend(
  void)
{
  enum blresultcode result = BLRESULT_OK;
  /* ptr to control block structure */
  struct blCtrlBlk *cbp = blGetcbp(); 

  /* ensure file size is ok */
  if (cbp->blbytesleft != 0)
  {
    return blcallerror(BLRESULT_IMGSIZE_MISMATCH_ERROR, BL_DLD_VERIFY);
  }

  if ((cbp->blhd.misc_opts & CWE_MISC_OPTS_COMPRESS) == 0 &&
      cbp->blhd.image_crc != cbp->blcrc32)
  {
    /* only check CRC for uncompressed image. Will check CRC after decompression */ 
    return blcallerror(BLRESULT_CRC32_CHECK_ERROR, BL_DLD_VERIFY);
  }

  result = blProgramCWEImage(&cbp->blhd,
                             bl_dload_area_start_get(cbp),
                             bl_dload_area_used_size_get(cbp),
                             cbp->blbytesleft);

  if (result != BLRESULT_OK)
  {
    blcallerror(result, BL_DLD_FLASH);
  }

  return (result);
}

/************
 *
 * Name:     blProgramCWERecoveryImage
 *
 * Purpose:  This function will program the CWE Recovery image into flash.
 *
 * Params:   cbp - pointer to the download handler control block
 *
 * Return:   image mask for those image has already been processed by this round
 *
 * Abort:    none
 *
 * Notes:    The sub-CWE images may be in any order however they must
 *           contain the correct content.
 *
 ************/
_global uint32 blProgramCWERecoveryImage(
  struct cwe_header_s *hdr,
  uint8 *dloadbufp,
  uint32 dloadsize,
  uint32 bytesleft,
  enum blmodulestate modulestate)
{
  uint8         *bufp, *startbufp;
  enum cwe_image_type_e imagetype, flog_imgtype = CWE_IMAGE_TYPE_INVALID;
  char flog_typestr[CWE_IMAGE_TYP_SZ+1];
  uint32 ret = 0;
  const char *imagep;

  /* validate the image type from the CWE sub-header */
  if (cwe_image_type_validate(hdr->image_type, &imagetype) == FALSE)
  {
    dprintf(CRITICAL, "SUBIMAGE=INVALID");
    return ret;
  }

  /* Set UI state to UPDATING */
  bluisetstate(BLUISTATE_UPDATING);

  /* Set the buffer pointer to the first CWE sub-header */
  startbufp = dloadbufp + sizeof(struct cwe_header_s);

  do                            /* break out of this loop in case of failure */
  {
    memmove((void *)&temphdr, (void *)hdr, sizeof(temphdr));
    bufp = startbufp;
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
    if ((imagetype == CWE_IMAGE_TYPE_APPL) || 
        (imagetype == CWE_IMAGE_TYPE_SPKG) ||
        (modulestate == BLSTATE_REQ_LINUX_RAM))
    {
      /* BLSTATE_REQ_LINUX_RAM will be supported in LK */
      /* BLSTATE_REQ_FULL will be supported in LINUX_RAM, not LK */
      bufp = blSearchCWEImage(CWE_IMAGE_TYPE_LRAM, startbufp, hdr->image_sz);
      if (bufp != NULL)
      {
        dprintf(CRITICAL, "Boot up RAM kernel now!!!!!!!!!!!!!!!!!!!!!!!!\n");
        boot_linux_from_ram((void *)(bufp+sizeof(struct cwe_header_s)), (unsigned)hdr->image_sz);
        ret = ret | BLPRIMAGE_MASK_KN;
      }
    } /* CWE_IMAGE_TYPE_BOOT */
    else
    {
      /* We won't support other state in LK */
      /* unsupported image, break and return error */
      break;
    }

    blsetcustompartition(NULL);
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

  return ret;
}

/************
 *
 * Name:     blprocessrecoveryimage - process recovery image
 *
 * Purpose:  process recovery image
 *
 * Params:   none
 *
 * Return:   image mask for those image has already been processed by this round
 *
 * Notes:
 *
 * Abort:
 *
 ************/
uint32 blprocessrecoveryimage(enum blmodulestate modulestate)
{
  uint32 ret = 0;
  /* ptr to control block structure */
  struct blCtrlBlk *cbp = blGetcbp(); 

  /* ensure file size is ok */
  if (cbp->blbytesleft != 0)
  {
    blcallerror(BLRESULT_IMGSIZE_MISMATCH_ERROR, BL_DLD_VERIFY);
    return ret;
  }

  if ((cbp->blhd.misc_opts & CWE_MISC_OPTS_COMPRESS) == 0 &&
      cbp->blhd.image_crc != cbp->blcrc32)
  {
    /* only check CRC for uncompressed image. Will check CRC after decompression */ 
    blcallerror(BLRESULT_CRC32_CHECK_ERROR, BL_DLD_VERIFY);
    return ret;
  }

  ret = blProgramCWERecoveryImage(&cbp->blhd,
                             bl_dload_area_start_get(cbp),
                             bl_dload_area_used_size_get(cbp),
                             cbp->blbytesleft,
                             modulestate);
  if (ret == 0)
  {
    /* Didn't program any image yet. */
    blcallerror(BLRESULT_FLASH_WRITE_ERROR, BL_DLD_FLASH);
  }

  return (ret);
}

/************
 *
 * Name:     bldlend - process Download done
 *
 * Purpose:  Process the host's Download done image and write image to flash
 *
 * Params:   modulestate - module state
 *
 * Return:   result code (as defined in 'enum blresultcode')
 *
 * Notes:
 *
 * Abort:
 *
 ************/
_global enum blresultcode bldlend(enum blmodulestate modulestate)
{
  enum blresultcode ret = BLRESULT_FLASH_WRITE_ERROR;
  uint32 primageret = 0;

  switch (modulestate)
  {
    case BLSTATE_NORMAL:
      ret = blprocessdldend();
      break;
    case BLSTATE_REQ_OCU3SBL:
      /* We should get SBL image in this branch */
      primageret = blprocessrecoveryimage(modulestate);
      if (primageret & BLPRIMAGE_MASK_SBL)
      {
         ret = BLRESULT_OK;
      }
      break;
    case BLSTATE_REQ_TZ_RPM_LK:
      /* We should get TZ_RPM_LK image in this branch */
      primageret = blprocessrecoveryimage(modulestate);
      if ((primageret & BLPRIMAGE_MASK_TZ) &&
           (primageret & BLPRIMAGE_MASK_RPM) &&
           (primageret & BLPRIMAGE_MASK_LK))
      {
        ret = BLRESULT_OK;
      }
      break;
    case BLSTATE_REQ_LINUX_RAM:
      /* We should get Kernel image in this branch */
      primageret = blprocessrecoveryimage(modulestate);
      if (primageret & BLPRIMAGE_MASK_LR)
      {
        ret = BLRESULT_OK;
      }
      break;
    case BLSTATE_REQ_FULL:
      /* We should get SBL,TZ_RPM_LK,Kernel,system image in this branch */
      primageret = blprocessrecoveryimage(modulestate);
      if ((primageret & BLPRIMAGE_MASK_SBL) &&
           (primageret & BLPRIMAGE_MASK_TZ) &&
           (primageret & BLPRIMAGE_MASK_RPM) &&
           (primageret & BLPRIMAGE_MASK_LK) &&
           (primageret & BLPRIMAGE_MASK_KN) &&
           (primageret & BLPRIMAGE_MASK_SYS) &&
           (primageret & BLPRIMAGE_MASK_LG))
      {
        ret = BLRESULT_OK;
      }
      break;
  }

  return ret;
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

  if (TRUE == is_dual_system_supported())
  {
    if (TRUE != cwe_version_validate(&cbp->blhd))
    {
      dprintf(CRITICAL, "BLRESULT_PKG_NOT_COMPATIBLE\n");
      return BLRESULT_PKG_NOT_COMPATIBLE;
    }
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
 * Name:     sierra_smem_reset_type_get
 *
 * Purpose:  get reset type from SMEM
 *
 * Parms:    none
 *
 * Return:   reset type enum
 *
 * Abort:    none
 *
 * Notes:    none
 *
 ************/
unsigned int sierra_smem_reset_type_get(void)
{
  struct bc_smem_message_s *b2amsgp;
  unsigned char *virtual_addr;
  unsigned int reset_type = 0;

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
      reset_type = b2amsgp->in.reset_type;
    }
  }

  return reset_type;
}

/************
 *
 * Name:     sierra_smem_bcfuntions_get
 *
 * Purpose:  get bcfunctions from SMEM
 *
 * Parms:    none
 *
 * Return:   bsfunction
 *
 * Abort:    none
 *
 * Notes:    none
 *
 ************/
unsigned int sierra_smem_bcfuntions_get(void)
{
  struct bscoworkmsg *mp;
  unsigned char *virtual_addr;
  unsigned int bitmask = 0;

  virtual_addr = sierra_smem_base_addr_get();
  if (virtual_addr)
  {
    virtual_addr += BSMEM_COWORK_OFFSET;
    mp = (struct bscoworkmsg *)virtual_addr;

    if (mp->magic_beg == BS_SMEM_COWORK_MAGIC_BEG &&
        mp->magic_end == BS_SMEM_COWORK_MAGIC_END &&
        mp->crc32 == crc32(~0, (void *)mp, BS_COWORK_CRC_SIZE))
    {
      bitmask = mp->bsfunctions;
    }
  }

  dprintf(CRITICAL, "sierra_smem_bcfuntions_get: bcfunctions=0x%x\n", bitmask);

  return bitmask;
}
