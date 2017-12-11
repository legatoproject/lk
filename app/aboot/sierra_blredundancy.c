/************
 *
 * Filename:  sierra_blredundancy.c
 *
 * Purpose:   Boot programming redundancy logic
 *
 * Copyright: (c) 2015 Sierra Wireless, Inc.
 *            All rights reserved
 *
 * Note:      reference: flash_scrub_boot_code.c
 *
 * This feature will handle reliablity during SBL update.
 * SBL static code retention during run time will be handled by SBL scrub.
 * PBL (or boot ROM) supports reading the boot (SBL) image from anywhere in the
 * first 15 blocks of flash (or first 8 blocks for 4k page flash). 
 * This feature allows multiple SBLs programmed within 0:SBL partition during
 * during firmware update time, in case boot update is failed on one SBL,
 * PBL can boot up the other one. The fist 10KB of SBL image is preamble with
 * magic numbers so that PBL can detect the start of SBL image in flash.
 *
 * The requirements of PBL to handle power down safe during firmware update
 * is that the first page of the first block of the image must be the last
 * page to be programmed.
 * For this reason, the images are written from the last block to the first
 * block.
 *
 * To work with SBL scrub feature, the redundant SBL will be removed at the
 * end of SBL upgrade. Even if there are two SBLs inside 0:SBL partition,
 * PBL will only try to load the first one (after finding the magic preamble).
 * If the first SBL load failed, PBL will not try to load the 2nd one so
 * there is no point to keep two copies of SBL inside 0:SBL partition. 
 *
 * PBL reads the sectors sequentially. In the diagram below, it will load
 * SBL_A, where SBL_A spans two blocks.
 *  ------------------------------------------------------------------
 * | SBL_A_1 | SBL_A_2 | erased | erased | erased | SBL_B_1 | SBL_B_2 |
 *  ------------------------------------------------------------------
 *
 * Blocks 0 have to be erased in order to boot from SBL_B. The diagram
 * above will be condensed to:
 * A-E-B: SBL_A followed by erased blocks, then SBL_B. boot up from A
 * A-E-E: SBL_A all other blocks are erased. boot up from A
 * E-E-B: SBL_B is at the end of the the partition, all other blocks are erased.
 *        boot up from B
 *
 * To upgrade SBL, here is the procedure:
 * 1. Get current SBL (A or B, LOW or HIGH) the device is booting up
 *    (start block and size in flash)
 * 2. Preserve current SBL, erase all other blocks in the partition
 *    After this step, only one SBL is valid/left
 * 3. On the opposite side of SBL (HIGH or LOW) partition, program the  
 *    new SBL image. Image is written from the last block to the first
 *    block. If image written is interrupted, the new SBL will not be valid
 *    since the first block is not valid (there are preambles in 1st block)
 *    and the device will still boot up from old SBL
 * 4. After new SBL image is programmed, erase current SBL.
 *    If erasure is interrupted, current SBL will be invalid
 *    since the first block of SBL image will be erased first and device will
 *    boot up from new SBL
 * 5. On current SBL location (LOW or HIGH), program new SBL.
 *    Image is written from the last block to the first
 *    block. If image written is interrupted, the new SBL will not be valid
 *    since the first block/first page is not valid and device will boot up
 *    from the other SBL
 * 6. Only keep the current SBL and erase the other SBL. If this is interrupted,
 *    there will be two copies of SBL and the first copy will be used to boot.
 *    SBL scrub code will handle the case if two copies of SBL exist in 0:SBL.
 *
 ************/
#include <string.h>
#include <debug.h>
#include <dev/flash.h>
#include <qpic_nand.h>
#include "sierra_bludefs.h"
#include "sierra_swipartudefs.h"

/* Local constants and enumerated types */
/* case 02531263 - PBL can only search block 0 - 7 for preamble magic
 * for 4k page size NAND flash
 */
#define LAST_SEARCHABLE_BLOCK      7

#define BL_SBL_IMG_MAX_SIZE   ((512*1024) - 1)

#define NAND_READ_BUF_SZ  4096


/*
 *  Local variables
 */
uint8 nand_read_buf[NAND_READ_BUF_SZ];


/* 
 * functions 
 */
/************
 *
 * Name:     blredundancy_one_good_block_back
 *
 * Purpose:  Returns the next good block before 'block_num', it does not check
 *           if block_num is good
 *
 * Parms:    nand_handle  - nand partition handle
 *           block_num  - start block to move back
 *           good_blockp  - output block number
 *
 * Return:   TRUE if found success, FALSE otherwise
 *
 * Abort:    none
 *
 * Notes:    code reference: move_back_to_good_block in flash_scrub_boot_code.c
 *           block_num will not be checked 
 *           so if block_num = maxblock (last block number in partition + 1)
 *           then last good block number in partition will be returned
 *
 ************/
_local boolean blredundancy_one_good_block_back (
  struct ptentry *nand_handle,
  unsigned int block_num,
  unsigned int *good_blockp)
{
  nand_result_t result;

  do
  {
    if (block_num == 0)
    {
      return FALSE;
    }

    block_num--;

    result = qpic_nand_block_isbad((nand_handle->start + block_num) * flash_num_pages_per_blk());

  } while (result == NANDC_RESULT_BAD_BLOCK);

  *good_blockp = block_num;
  return TRUE;
}
 
 
/************
 *
 * Name:     blredundancy_n_good_blocks_forward
 *
 * Purpose:  move forward n good blocks from current block 
 *
 * Parms:    nand_handle  - nand partition handle
 *           block_start  - start block to move forward. This is the
 *                          physical block number in partition starting from 0
 *           block_count  - number of good blocks to move forward, must >= 1
 *           block_limit  - total number of blocks in partition
 *           good_blockp  - output block number
 *
 * Return:   TRUE if find success, FALSE otherwise
 *
 * Abort:    none
 *
 * Notes:    code reference: move_forward_n_good_blocks in flash_scrub_boot_code.c
 *           block_start will be checked and count as 1 block if it is good
 *           so if block_start = 0 and if it is good and block_count = 1 
 *           then returned block is 0
 *
 ************/
_local boolean blredundancy_n_good_blocks_forward (
  struct ptentry *nand_handle,
  unsigned int block_start,
  unsigned int block_count,
  unsigned int block_limit,
  unsigned int *good_blockp)
{
  unsigned int block_num;

  for (block_num = block_start; block_num < block_limit; block_num++)
  {
    if (NANDC_RESULT_SUCCESS == qpic_nand_block_isbad((nand_handle->start + block_num) * flash_num_pages_per_blk()))
    {
      block_count--;
      if (block_count == 0)
      {
        *good_blockp = block_num;
        return TRUE;
      }
    }
  }

  return FALSE;
}

/************
 *
 * Name:     blredundancy_sbl_image_program
 *
 * Purpose:  program SBL image on the specified location
 *
 * Parms:    nand_handle       - nand partition handle
 *           program_current   - TRUE if reprogram current SBL image
 *                               FALSE if program SBL at the other end of
 *                               SBL partition 
 *           current_sbl_startp- point to current SBL image start physical block
 *                               This function can update the start block for
 *                               newly programmed image
 *           current_sbl_endp  - point to current SBL image end physical block
 *                               This function can update the end block for
 *                               newly programmed image
 *           bufp              - pointer of data block to be written
 *                               to flash. Note that it is initially point to
 *                               start of CWE image and CWE header should be
 *                               skipped for programming
 *                               Note this is the logical address and need to be
 *                               converted to physical addr first
 *           write_size        - size of the bufp including CWE header which
 *                               need to be skipped
 *
 * Return:   TRUE if program success, FALSE otherwise
 *
 * Abort:    none
 *
 * Notes:    none
 *
 ************/
_local enum blresultcode blredundancy_sbl_image_program(
  struct ptentry *nand_handle,
  boolean program_current,
  unsigned int *current_sbl_startp,
  unsigned int *current_sbl_endp,
  uint8 *bufp,
  unsigned int write_size)
{
  uint8 *physical_addr, *write_bufp;
  unsigned int program_block, maxblock, noblocks, blocksize;
  uint32 physical_len;
  boolean program_at_start, last_block;

  physical_addr = bufp;
  physical_len = write_size;

  /* number of blocks needed for the image */
  maxblock = nand_handle->length;
  blocksize = flash_block_size();
  noblocks = (physical_len + blocksize - 1) / blocksize;

  /* decide where to program SBL, start or end of SBL partition */
  if (*current_sbl_startp >  (maxblock / 2))
  {
    if (program_current)
    {
      /* current sbl at the end, replace current sbl, will program at the end */
      program_at_start = FALSE;
    }
    else
    {
      /* program at the beginning of partition */
      program_at_start = TRUE;
    }
  }
  else
  {
    if (program_current)
    {
      /* current sbl at the beginning, will reprogram at the start */
      program_at_start = TRUE;
    }
    else
    {
      /* program at the end of partition*/
      program_at_start = FALSE;
    }
  }

  /* now program from image last block to 1st block, calculate last block # */
  if (program_at_start)
  {
    /* find nth good block starting from block 0 */
    if (!blredundancy_n_good_blocks_forward(nand_handle,
                                            0,
                                            noblocks,
                                            maxblock,
                                            &program_block))
    {
      return BLRESULT_FLASH_WRITE_ERROR;
    }
  }
  else
  {
    /* max possible block if image is programmed at LAST_SEARCHABLE_BLOCK */ 
    if (maxblock > (LAST_SEARCHABLE_BLOCK + noblocks))
    {
      maxblock = LAST_SEARCHABLE_BLOCK + noblocks;
    }

    if (!blredundancy_one_good_block_back (nand_handle, maxblock,
                                           &program_block))
    {
      return BLRESULT_FLASH_WRITE_ERROR;
    }
  }

  if (program_current)
  {
    *current_sbl_endp = program_block;
  }

  /* start programming block by block backwards */
  while (noblocks > 0)
  {
    /* calculate RAM buf and size to program for the block */
    noblocks--;
    write_bufp = physical_addr + (noblocks * blocksize);
    write_size = physical_len - (noblocks * blocksize);
    if (write_size > blocksize)
    {
      write_size = blocksize;
    }

    if (noblocks == 0)
    {
      last_block = TRUE;
    }
    else
    {
      last_block = FALSE;
    }
    
    /* when writing last block (1st block of image), write
     * 1st page last to make sure preamble_in_block is written last
     */
    if (!swipart_block_program(nand_handle, program_block, 0,
                                     write_bufp, write_size, last_block))
    {
      return BLRESULT_FLASH_WRITE_ERROR;
    }

    /* now go back one block */
    if (!last_block &&
        !blredundancy_one_good_block_back (nand_handle, program_block,
                                           &program_block))
    {
      return BLRESULT_FLASH_WRITE_ERROR;
    }
  }

  if (program_current)
  {
    *current_sbl_startp = program_block;
  }
 
  return BLRESULT_OK;
}

/************
 *
 * Name:     blredundancy_sbl_erase
 *
 * Purpose:  Erase SBL partition/image 
 *
 * Parms:    nand_handle       - nand partition handle
 *           erase_current     - TRUE if erase current SBL image,
 *                               FALSE if erase all 0:SBL partition except
 *                               current SBL image 
 *           current_sbl_start - current SBL image start physical block
 *           current_sbl_end   - current SBL image end physical block
 *
 * Return:   TRUE if erase success, FALSE otherwise
 *
 * Abort:    none
 *
 * Notes:    none
 *
 ************/
_local boolean blredundancy_sbl_erase(
  struct ptentry *nand_handle,
  boolean erase_current,
  unsigned int  current_sbl_start,
  unsigned int  current_sbl_end)

{
  unsigned int blockno, maxblock;

  maxblock = nand_handle->length;

  for (blockno = 0; blockno < maxblock; blockno++)
  {
    if (erase_current && (blockno < current_sbl_start ||
                          blockno > current_sbl_end))
    {
      continue;
    } 

    if (!erase_current && (blockno >= current_sbl_start &&
                           blockno <= current_sbl_end))
    {
      continue;
    }

    /* erase the block if not bad */
    if (NANDC_RESULT_BAD_BLOCK == qpic_nand_block_isbad((nand_handle->start + blockno) * flash_num_pages_per_blk()))
    {
      continue;
    }

    /* now erase the block, don't abort even if current erase failed */
    qpic_nand_blk_erase((nand_handle->start + blockno) * flash_num_pages_per_blk());
  }

  return TRUE;
}

/************
 *
 * Name:     blredundancy_current_sbl_get
 *
 * Purpose:  get current SBL flash block start and end block number
 *           input is current SBL logical byte address in partition and its size 
 *
 * Parms:    nand_handle       - nand partition handle
 *           sbl_start_address - SBL image start logical byte address
 *                               in the partition 
 *           sbl_image_size    - SBL image size in bytes
 *           block_startp      - translated SBL physical start block number
 *           block_endp        - translated SBL physical end block number
 *
 * Return:   TRUE if translate success, FALSE otherwise
 *
 * Abort:    none
 *
 * Notes:    sbl logical address in flash partition is calculated during boot
 *           process in blddrimage.c. Translate it to block numbers which will
 *           be used in this file and swipart.c
 *
 ************/
_local boolean blredundancy_current_sbl_get(
  struct ptentry *nand_handle,
  unsigned int  sbl_start_address,
  unsigned int  sbl_image_size,
  unsigned int *block_startp,
  unsigned int *block_endp)
{
  unsigned int blockno, maxblock, blocksize;

  maxblock = nand_handle->length;
  blocksize = flash_block_size();

  /* get image start block, blockno is good logical block number
   * starting from 1
   */
  blockno = (sbl_start_address / blocksize) + 1;

  if (!blredundancy_n_good_blocks_forward(nand_handle, 
                                          0, 
                                          blockno,
                                          maxblock,
                                          block_startp))
  {
    return FALSE;
  }

  /* get image end block, derive from SBL end address */
  blockno = ((sbl_start_address + sbl_image_size - 1) / blocksize) + 1;

  if (!blredundancy_n_good_blocks_forward(nand_handle, 
                                          0, 
                                          blockno,
                                          maxblock,
                                          block_endp))
  {
    return FALSE;
  }

  return TRUE;
}

/************
 *
 * Name:     blredundancy_sbl_program
 *
 * Purpose:  program SBL, entry point of this module
 *
 * Parms:    bufp       - pointer to data block to be written to flash. 
 *           write_size - size of the bufp
 *
 * Return:   result code (as defined in 'enum blresultcode')
 *
 * Abort:    none
 *
 * Notes:    none
 *
 ************/
_package enum blresultcode blredundancy_sbl_program(
  uint8 * bufp,
  unsigned int write_size)
{
  /* swipart_handle_t nand_devp = (swipart_handle_t)FS_NO_DEVICE; */
  struct ptentry *ptn;
  struct ptable *ptable;
  enum blresultcode result = BLRESULT_FLASH_WRITE_ERROR;
  unsigned int current_sbl_start, current_sbl_end;
  uint32 flash_sbl_start_address;

  ASSERT(bufp);

  dprintf(CRITICAL, "redundancy sbl program\n");

  do
  {
    /* open 0:SBL partition */
    ptable = flash_get_ptable();
    if (ptable == NULL) {
      dprintf(CRITICAL, "sierra_bl: flash_get_ptable failed\n");
      break;
    }

    ptn = ptable_find(ptable, (const char *)BL_SBL_PARTI_NAME);
    if (ptn == NULL) {
      dprintf(CRITICAL, "sierra_bl: ptable_find failed: %s\n", BL_SBL_PARTI_NAME);
      break;
    }

    /* calculate current SBL location */
    flash_sbl_start_address = swipart_findsbl(ptn, nand_read_buf, NAND_READ_BUF_SZ);
       
    if (!blredundancy_current_sbl_get(ptn,
                                      flash_sbl_start_address,
                                      BL_SBL_IMG_MAX_SIZE,
                                      &current_sbl_start,
                                      &current_sbl_end))
    {
      break;
    }

    /* erase 0:SBL partition but preserve current SBL */
    if (!blredundancy_sbl_erase(ptn, FALSE,
                                current_sbl_start,
                                current_sbl_end))
    {
      break;
    }
    
    /* write new SBL image to the other end of SBL */
    result = blredundancy_sbl_image_program(ptn, 
                                            FALSE,
                                            &current_sbl_start,
                                            &current_sbl_end,
                                            bufp,
                                            write_size);
    if (result != BLRESULT_OK)
    {
      break;
    }
    

    /* reset result from OK to default */
    result = BLRESULT_FLASH_WRITE_ERROR;

    /* erase current SBL */
    if (!blredundancy_sbl_erase(ptn, TRUE,
                                current_sbl_start,
                                current_sbl_end))
    {
      break;
    }
    
    /* replace current SBL  */
    result = blredundancy_sbl_image_program(ptn, 
                                            TRUE,
                                            &current_sbl_start,
                                            &current_sbl_end,
                                            bufp,
                                            write_size);
    if (result != BLRESULT_OK)
    {
      break;
    }

    /* erase the other SBL so that only SBL will be kept;
     * this is to work with SBL scrub feature
     */
    if (!blredundancy_sbl_erase(ptn, FALSE,
                                current_sbl_start,
                                current_sbl_end))
    {
      result = BLRESULT_FLASH_WRITE_ERROR;
      break;
    }

    result =  BLRESULT_OK;

  } while (0);


  return result;
}

