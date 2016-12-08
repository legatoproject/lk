/************
 *
 * Filename:   sierra_swipart.c
 *
 * Purpose:    Functions shared by the boot loader and the application.
 *             For accessing the generic partitions.
 *
 * Copyright:  (c) 2015 Sierra Wireless, Inc.
 *             All rights reserved
 *
 ************/
 
/* Include files */
#include <string.h>
#include <debug.h>
#include <dev/flash.h>
#include <qpic_nand.h>
#include "sierra_bludefs.h"

/* Local constants and enumerated types */
/* The magic byte sequence will be found every 2048 bytes of the first 10K. */
#define BL_BOOT_PREAMBLE_MAGIC_OFFSET         (2048)
#define BL_BOOT_PREAMBLE_SIZE_BYTES           (8 * 1024)

/* Local variables */
const uint8 bl_boot_preamble_magic[] =
{ 0xD1, 0xDC, 0x4B, 0x84, 0x34, 0x10, 0xD7, 0x73 };

/* Local structures and functions */
/************
 *
 * Name:     swipart_next_good_block_get
 *
 * Purpose:  get the next good block
 *
 * Parms:    (IN) handle         - partition handle
 *           (IN) logical_partition - logical partition ID
 *           (IN) currentblock   - curent physical block
 *           (OUT)nextblockp     - next good physical block to return
 *
 * Return:   TRUE if success
 *           FALSE otherwise
 *
 * Abort:    None
 *
 * Notes:    none
 *
 ************/
_global boolean swipart_next_good_block_get(
  struct ptentry *fs_devicep,
  unsigned int currentblock,
  unsigned int *nextblockp)
{
  unsigned int maxblock, nextblock;
  boolean found = FALSE;

  ASSERT(fs_devicep);

  nextblock = currentblock + 1;

  maxblock = fs_devicep->length;

  /* if moved to next block, check if next block is bad or out of partition
   * boundary
   */
  while (nextblock < maxblock)
  {
    if (qpic_nand_block_isbad((fs_devicep->start + nextblock) * flash_num_pages_per_blk()) == NANDC_RESULT_BAD_BLOCK)
    {
      nextblock++;
    }
    else
    {
      /* found */
      found = TRUE;
      *nextblockp = nextblock;
      break;
    }
  }

  return found;
}

/************
 *
 * Name:     swipart_next_good_pg_get
 *
 * Purpose:  get the next good page number to read/write
 *
 * Parms: 
 *           (IN) currentpage  - currrent page no
 *           (IN) fs_devicep   - pointer to the nand device
 *
 * Return:   next good page number or 0 if couldn't find next good page
 *
 * Abort:    None
 *
 * Notes:    The current page number is a good page number, some checks have been
 *           done before calling this function.
 *           Next page no is the next page to be read (with the skip of bad block),
 *           If next good page is out of partition boudary, it will be set to 0.
 *
 ************/
_global unsigned int swipart_next_good_pg_get(
  struct ptentry *fs_devicep,
  unsigned int     currentpage)
{
  unsigned int nextpage, blockpages, nextblock;

  ASSERT(fs_devicep);

  nextpage = currentpage + 1;
  blockpages = flash_num_pages_per_blk();

  if ((nextpage % blockpages) == 0)
  {
    if (swipart_next_good_block_get(fs_devicep, currentpage / blockpages, &nextblock))
    {
      nextpage = nextblock * blockpages;  
    }
    else
    {
      nextpage = 0;
    }
  }

  return nextpage;
}

/************
 *
 * Name:     swipart_pg_write
 *
 * Purpose:  write current page and get the next page number to write
 *
 * Parms: 
 *           (IN) writepage    - page no to write
 *           (OUT) nextpage    - next page no to write
 *           (IN/OUT) pagebuf  - read page buffer
 *           (IN) fs_devicep   - pointer to the nand device
 *           (IN) write_spare  - flag to indicate if spare area in page should be used
 *
 * Return:   none
 *
 * Abort:    None
 *
 * Notes:    The write page number is a good page number, some checks have been
 *           done before calling this function.
 *           Next page no is the next page to be write (with the skip of bad block),
 *           If next good page is out of partition boudary, it will be set to 0.
 *
 ************/
_global boolean swipart_pg_write(
  struct ptentry *fs_devicep,
  unsigned int     writepage,
  unsigned int    *nextpage,
  uint8_t         *pagebuf,
  boolean          write_spare)
{
  ASSERT(fs_devicep);

  if (NANDC_RESULT_SUCCESS != qpic_nand_write_page_spare_sierra(writepage, pagebuf, write_spare))
  {
    return FALSE;
  }
  else
  {
    *nextpage = swipart_next_good_pg_get(fs_devicep, writepage);
    return TRUE;
  }
}

/************
 *
 * Name:     swipart_block_program
 *
 * Purpose:  Program one block in partition
 *
 * Parms:    (IN) fs_devicep    - pointer to the nand device
 *           (IN) blockno          - physical block number to program
 *           (IN) pageno           - pageno in the block to start programming
 *           (IN) imagep           - image pointer
 *           (IN) imagesize        - image size 
 *           (IN) program_backward - if program pages in descending order
 *
 * Return:   TRUE if the program was successful
 *           FALSE otherwise
 *
 * Abort:    None
 *
 * Notes:    Caller must make sure that the block is erased already
 *           Image might not fill in full block;
 *           The last page written to flash may contain garbage data
 *           after the end of the image
 *
 ************/
_global boolean swipart_block_program(
  struct ptentry *fs_devicep,
  unsigned int blockno,
  unsigned int pageno,
  uint8_t *imagep,
  unsigned int imagesize,
  boolean program_backward)
{
  unsigned int pagecount, pagestowrite, pagesize, blockpages;
  unsigned int startpage, writepage, nextpage;
  uint8_t *writeaddrp;

  ASSERT(fs_devicep);

  pagesize = flash_page_size();
  blockpages = flash_num_pages_per_blk();
  pagestowrite = (imagesize + pagesize - 1) / pagesize; /* round up */

  if (pagestowrite + pageno > blockpages || pagestowrite == 0)
  {
    dprintf(CRITICAL, "cannot write %d pages to block", pagestowrite);
    return FALSE;
  }

  startpage = (blockno * blockpages) + pageno;

  /* Start write data, one page size at a time.
   * NOTE: The last page written to flash may contain garbage data
   * after the end of the image.  The API doesn't allow us to write a
   * partial page. 
   */
  for (pagecount = 0; pagecount < pagestowrite; pagecount++)
  {
    dprintf(INFO, "Read %d bytes, writing to page: %d of %d", pagesize,
              pagecount, pagestowrite - 1);

    if (!program_backward)
    {
      /* write first page first */
      writepage = startpage + pagecount;
      writeaddrp = imagep + (pagecount * pagesize);
    }
    else
    {
      /* write last page first */
      writepage = startpage + (pagestowrite - pagecount - 1);
      writeaddrp = imagep + ((pagestowrite - pagecount - 1) * pagesize);
    }

    /* write one page to flash */
    if (swipart_pg_write(fs_devicep, 
                               writepage,
                               &nextpage,
                               writeaddrp,
                               FALSE) != TRUE)
    {
      dprintf(CRITICAL, "Flash write error page:%d", writepage);
      return (FALSE);
    }
  }

  return TRUE;
}

/************
 *
 * Name:     swipart_find_preamble_in_block
 *
 * Purpose:  find the boot image preamble in the block
 *
 * Parms:    trans_ifp - flash trans if
 *           byte_offset - logical byte offset from start of partition
 *                         The offset actually points to the start of a block
 *           scratch_bufp - scratch area buffer pointer
 *           scratch_buflen - scratch buffer len
 *
 * Return:   SBL start address in 0:SBL partition
 *
 * Abort:    on flash access failure
 *
 * Notes:    code reference: scrub_boot_check_preamble_in_block
 *
 ************/
_local boolean swipart_find_preamble_in_block(
  struct ptentry *trans_ifp,
  uint32 byte_offset,
  uint8 * scratch_bufp,
  uint32 scratch_buflen)
{
  /* byte_offset = start of block; block_offset = offset inside the block */
  uint32 block_offset;
  boolean success;

  /* adjust scratch_bufp to make sure it is 4 byte aligned */
  ASSERT(scratch_buflen >= sizeof(bl_boot_preamble_magic));

  for (block_offset = 0; block_offset < BL_BOOT_PREAMBLE_SIZE_BYTES;
       block_offset += flash_page_size())
  {
    success = flash_read(trans_ifp,
                          byte_offset + block_offset,
                          scratch_bufp,
                          flash_page_size());

    ASSERT(success == 0);

    if (flash_page_size() > BL_BOOT_PREAMBLE_MAGIC_OFFSET)
    {
      /* 4K page */
      if ((memcmp((void *)scratch_bufp, (void *)bl_boot_preamble_magic, sizeof(bl_boot_preamble_magic)))
          || (memcmp((void *)&scratch_bufp[BL_BOOT_PREAMBLE_MAGIC_OFFSET], (void *)bl_boot_preamble_magic, sizeof(bl_boot_preamble_magic))))
      {
        /* not match, return error */
        return FALSE;
      }
    }
    else
    {
      /* 2K page */
      if (memcmp((void *)scratch_bufp, (void *)bl_boot_preamble_magic, sizeof(bl_boot_preamble_magic)))
      {
        /* not match, return error */
        return FALSE;
      }
    }
    
  }

  /* all check passed, TRUE */
  return TRUE;
}

/************
 *
 * Name:     swipart_findsbl
 *
 * Purpose:  find the booting up SBL image in flash
 *
 * Parms:    trans_ifp - flash trans if
 *           scratch_bufp - scratch area buffer pointer
 *           scratch_buflen - scratch buffer len
 *
 * Return:   SBL start address in 0:SBL partition
 *
 * Abort:    if bl_shared_data is not valid, on flash access failure
 *
 * Notes:    boot_flash_* API couldn't detect if a block is erased or not,
 *           it also couldn't tell if a page is written
 *           If a block is erased and boot_flash_trans_read is used to read
 *           a whole page, it will abort. However not reading whole pages
 *           will be OK.
 *
 ************/
uint32 swipart_findsbl(
  struct ptentry *trans_ifp,
  uint8 * scratch_bufp,
  uint32 scratch_buflen)
{
  uint32 block_count, block_size_bytes, byte_offset, block_no;
  block_count = trans_ifp->length;
  block_size_bytes = flash_block_size();

  for (block_no = 0; block_no < block_count; block_no++)
  {
    byte_offset = block_no * block_size_bytes;

    if (swipart_find_preamble_in_block(trans_ifp, byte_offset, scratch_bufp, scratch_buflen))
    {
      /* found preamlbe, we think found SBL; SBL1 in mdm9x40 is ELF format, will verify ELF header when loading */
      return byte_offset;
      /* else move to next block */
    }                           /* end if find preamble */
  }                             /* end for */

  /* can't find SBL image, consider 0 is start address */
  return 0;

}

