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
#include <debug.h>
#include <platform.h>
#include <crc32.h>
#include <malloc.h>
#include <qpic_nand.h>
#include "mach/sierra_smem.h"
#include "sierra_dsudefs.h"
#include "sierra_bludefs.h"

/*
 *  externs
 */


/*
 *  Local variables
 */
uint8 ds_page_buf[DS_MAX_PAGE_SIZE];
boolean ds_page_buf_available = TRUE;

/* 
 * Local functions 
 */

/************
 *
 * Name: sierra_ds_page_buf_allocate
 *
 * Purpose: Get ds page buf
 *
 * Parms: None
 *
 * Return: page buf pointer if available 
 *             NULL otherwise.
 *
 * Abort: None
 *
 * Notes:	None
 *
 ************/
uint8 *sierra_ds_page_buf_allocate(
  uint8 page_size)
{
  if (ds_page_buf_available)
  {
    ds_page_buf_available = FALSE;
    return ds_page_buf;
  }
  else
  {
    return NULL;
  }
}

/************
 *
 * Name:	 sierra_ds_page_buf_free
 *
 * Purpose:  Mark ds page as available
 *
 * Parms: None
 *
 * Return: None
 *
 * Abort: None
 *
 * Notes:	None
 *
 ************/
void sierra_ds_page_buf_free()
{
  ds_page_buf_available = TRUE;
}

/************
 *
 * Name:	sierra_ds_flag_init
 *
 * Purpose: Init dual system shared data
 *
 * Parms: ds_flag - dual system flag pointer
 *
 * Return: None
 *
 * Abort: None
 *
 * Notes: None
 *
 ************/
void sierra_ds_flag_init(
  struct ds_flag_s *ds_flag)
{
  ASSERT(ds_flag);

  memset((void *)ds_flag, 0, sizeof(struct ds_flag_s));
  ds_flag->ssid_modem_idx = DS_SSID_SUB_SYSTEM_1;
  ds_flag->ssid_lk_idx= DS_SSID_SUB_SYSTEM_1;
  ds_flag->ssid_linux_idx= DS_SSID_SUB_SYSTEM_1;
  ds_flag->swap_reason = DS_SWAP_REASON_NONE;
  ds_flag->sw_update_state = DS_SW_UPDATE_STATE_NORMAL;

  return;
}

/************
 *
 * Name:	sierra_ds_dssd_is_erased_page
 *
 * Purpose: Check if it is erased page
 *
 * Parms: page_buf - page buffer pointer
 *            page_size - page size
 *
 * Return: TRUE - if it is erased page
 *             FALSE - if it is  not erased page
 *
 * Abort: None
 *
 * Notes: None
 *
 ************/
bool sierra_ds_dssd_is_erased_page(
  uint8 *page_buf, 
  uint32 page_size)
{
  uint8 *page_buf_p = NULL;
  uint32 byte;

  ASSERT(page_buf);

  page_buf_p = page_buf;
  for(byte = 0; byte < page_size; byte++)
  {
    if((*page_buf_p) != 0xFF)
    {
      return FALSE;
    }
  }

  return TRUE;
}

/************
 *
 * Name:	sierra_ds_dssd_data_blocks_find
 *
 * Purpose: Search for all blocks with data.
 *
 * Parms: (IN) handle - pointer to the nand device
 *            (OUT) data_block - data blocks found
 *            (OUT) data_block_count - total data blocks
 *
 * Return: TRUE - if success
 *             FALSE - otherwise
 *
 * Abort:	None
 *
 * Notes:	None
 *
 ************/
bool sierra_ds_dssd_data_blocks_find(
  struct ptentry * handle,
  uint32 * data_block,
  uint32 * data_block_count)
{
  uint32 block_no, total_block, start_block_no, max_block_no, block_size, page_size, page_no;
  uint8 * page_buf_p = NULL;
  struct ds_shared_data_s *data_p;

  ASSERT(handle);
  ASSERT(data_block);
  ASSERT(data_block_count);

  total_block = handle->length;
  start_block_no = handle->start;
  max_block_no = start_block_no + total_block - 1;
  page_size = flash_page_size_sierra();
  block_size = flash_num_pages_per_block_sierra();

#ifdef SIERRA_DUAL_SYSTEM_TEST
  dprintf(CRITICAL, "sierra_ds_dssd_data_blocks_find(): total_block=%d, page_size=%d, block_size=%d\n", 
                    total_block, page_size, block_size);
#endif /* SIERRA_DUAL_SYSTEM_TEST */

  page_buf_p = sierra_ds_page_buf_allocate(page_size);
  if(NULL == page_buf_p)
  {
    dprintf(CRITICAL, "sierra_ds_dssd_data_blocks_find(): can't allocate page buf\n");
    return FALSE;
  }

  /* Start to find from first block to last block */
  *data_block_count = 0;
  for (block_no = start_block_no; block_no <= max_block_no; block_no++)
  {
#ifdef SIERRA_DUAL_SYSTEM_TEST
    dprintf(CRITICAL, "sierra_ds_dssd_data_blocks_find(): block_no = %d\n", block_no);
#endif /* SIERRA_DUAL_SYSTEM_TEST */

    /* Check if the block is bad block */
    page_no = block_no * block_size;
    if(qpic_nand_block_isbad(page_no))
    {
      dprintf(CRITICAL, "sierra_ds_dssd_data_blocks_find(): found bad block %d\n", block_no);
      continue;
    }

    /* Read the first page of the block */
    memset(page_buf_p, 0, DS_MAX_PAGE_SIZE);
    if(0 != qpic_nand_read_page_sierra(page_no, page_buf_p))
    {
      /* Page read failed */
      dprintf(CRITICAL, "sierra_ds_dssd_data_blocks_find(): page read fail on block: %d\n", block_no);
    }
    else
    {
#ifdef SIERRA_DUAL_SYSTEM_TEST
      dprintf(CRITICAL, "sierra_ds_dssd_data_blocks_find(): Page(%d) read OK \n", block_no*block_size);
#endif /* SIERRA_DUAL_SYSTEM_TEST */

      /* Page read OK */
      data_p = (struct ds_shared_data_s *)page_buf_p;
      if((DS_MAGIC_NUMBER == data_p->magic_beg) || (DS_MAGIC_NUMBER == data_p->magic_end))
      {
#ifdef SIERRA_DUAL_SYSTEM_TEST
        dprintf(CRITICAL, "sierra_ds_dssd_data_blocks_find(): block %d is data block\n", block_no);
#endif /* SIERRA_DUAL_SYSTEM_TEST */

        /* This block is data block, don't care if it is corrupted DS data or valid DS data at this time */
        data_block[*data_block_count] = block_no;
        (*data_block_count)++;
      }
    }
  }/* end for ... */

  sierra_ds_page_buf_free();
#ifdef SIERRA_DUAL_SYSTEM_TEST
  dprintf(CRITICAL, "sierra_ds_dssd_data_blocks_find(): find %d data blocks\n", *data_block_count);
#endif
  return TRUE;
}

/************
 *
 * Name:	sierra_ds_dssd_free_block_find
 *
 * Purpose: Search for free block
 *
 * Parms: (IN) handle -pointer to the nand device
 *            (IN) start_search_block	-start search from the block number 
 *
 * Return: Free block number or -1
 *
 * Abort: None
 *
 * Notes: 'start_search_block' must be after data block
 *
 ************/
int32 sierra_ds_dssd_free_block_find(
  struct ptentry * handle,
  uint32 start_search_block)
{
  uint32 total_block, start_block_no, max_block_no, block_no, block_size, page_no;
  int32 result = DS_NO_FREE_BLOCK;

  ASSERT(handle);

  total_block = handle->length;
  start_block_no = handle->start;
  max_block_no = start_block_no + total_block - 1;
  block_size = flash_num_pages_per_block_sierra();

  /* Start to search */
  for (block_no = start_block_no; block_no <= max_block_no; block_no++, start_search_block++)
  {
#ifdef SIERRA_DUAL_SYSTEM_TEST
    dprintf(CRITICAL, "sierra_ds_dssd_free_block_find(): Start to search block %d\n", start_search_block);
#endif /* SIERRA_DUAL_SYSTEM_TEST */

    if((start_search_block > max_block_no) || (start_search_block < start_block_no))
    {
#ifdef SIERRA_DUAL_SYSTEM_TEST
      dprintf(CRITICAL, "sierra_ds_dssd_free_block_find(): Arrives max block, trim the search block\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

      /* Arrives max block, trim the search block */
      start_search_block = start_block_no;
    }

    /* Check if the block is bad block */
    page_no = start_search_block * block_size;
    if(qpic_nand_block_isbad(page_no))
    {
      dprintf(CRITICAL, "sierra_ds_dssd_free_block_find(): found bad block: %d\n", block_no);
      continue;
    }

    /* There is no block erase checking interface in LK. Directly erase block to get free block */
    if(qpic_nand_blk_erase(page_no))
    {
      dprintf(CRITICAL, "sierra_ds_dssd_free_block_find():  block erase failed. %d\n", start_search_block);
      continue;
    }

    /* Find one free block, exit the loop */
#ifdef SIERRA_DUAL_SYSTEM_TEST
    dprintf(CRITICAL, "sierra_ds_dssd_free_block_find(): Find one free block, exit the loop\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */
    result = start_search_block;
    break;
  }

  return result;
}

/************
 *
 * Name:	sierra_ds_dssd_free_blocks_write
 *
 * Purpose: Write data to first page of two free blocks
 *
 * Parms: (IN) handle - pointer to the nand device
 *            (IN) start_search_block	-start search from the block number 
 *            (IN) data_block_count - data block counter
 *            (IN) data_block - data blocks
 *            (IN) page_buf	 -page buffer to write
 *
 * Return: TRUE - if success
 *             FALSE - otherwise
 *
 * Abort: None
 *
 * Notes:	None
 *
 ************/
bool sierra_ds_dssd_free_blocks_write(
  struct ptentry * handle,
  uint32 start_search_block,
  uint32 data_block_count,
  uint32 * data_block,
  uint8 * page_buf)
{
  int32 free_block = DS_NO_FREE_BLOCK;
  uint32 block_size, start_page, block_no, data_block_no, total_block, start_block_no, max_block_no;

  ASSERT(handle);
  ASSERT(data_block);
  ASSERT(page_buf);

  total_block = handle->length;
  start_block_no = handle->start;
  max_block_no = start_block_no + total_block - 1;
  block_size = flash_num_pages_per_block_sierra();

  for(block_no = 1; block_no <= DSSD_MAX_DATA_BLOCK; block_no++)
  {
    /* Find the free block */
    if(block_no == 1)
    {
      /* Find the first free block */
      free_block = sierra_ds_dssd_free_block_find(handle, start_search_block);
    }
    else
    {
      start_search_block = free_block + 1;
      free_block = sierra_ds_dssd_free_block_find(handle, start_search_block);
    }

    if(((uint32)free_block < start_block_no) || ((uint32)free_block > max_block_no))
    {
      dprintf(CRITICAL, "ds_dssd_free_blocks_write(): no free block found\n");
      return FALSE;
    }
    else
    {
      /* Check if free block is data block found */
      for(data_block_no = 0; data_block_no < data_block_count; data_block_no++)
      {
        if((uint32)free_block == data_block[data_block_no])
        {
#ifdef SIERRA_DUAL_SYSTEM_TEST
          dprintf(CRITICAL, "sierra_ds_dssd_free_blocks_write(): free block(%d) is data block, mark the data block as erased\n", 
                            (uint32)free_block);
#endif /* SIERRA_DUAL_SYSTEM_TEST */
          data_block[data_block_no] = DS_DATA_BLOCK_ERASED;
          break;
        }
      }
    }

    /* Write data to first page of free block */
    start_page = free_block * block_size;
    if(qpic_nand_write_page_sierra(start_page, page_buf))
    {
      dprintf(CRITICAL, "ds_dssd_free_blocks_write(): write data failed in the first page of data block\n");

      if(block_no >= DSSD_MAX_DATA_BLOCK)
      {
        return FALSE;
      }
      else
      {
        /* Continue to write other data block */
        continue;
      }
    }
  }

  return TRUE;
}

/************
 *
 * Name:	sierra_ds_dssd_last_valid_data_page_find
 *
 * Purpose: Search for the last page with valid data
 *
 * Parms: (IN) handle - pointer to the nand device
 *            (IN) data_block - block number
 *            (OUT) data_page_no - valid data page found
 *            (OUT) ds_data - DS message pointer
 *
 * Return: TRUE - if success
 *             FALSE - otherwise
 *
 * Abort: None
 *
 * Notes: None
 *
 ************/
bool sierra_ds_dssd_last_valid_data_page_find(
  struct ptentry * handle,
  const uint32 data_block,
  uint32 * data_page_no,
  struct ds_shared_data_s * ds_data)
{
  uint32 total_block, start_block_no, max_block_no, block_size;
  uint32 start_page, last_page, page_size, page_no;
  uint8 * page_buf_p = NULL;
  struct ds_shared_data_s *data_p;
  bool result = FALSE;

  ASSERT(handle);
  ASSERT(data_page_no);

  page_no = DS_PAGE_SERACH_NOT_START;
  total_block = handle->length;
  start_block_no = handle->start;
  max_block_no = start_block_no + total_block - 1;
  block_size = flash_num_pages_per_block_sierra();
  page_size = flash_page_size_sierra();

  if(data_block > max_block_no)
  {
    dprintf(CRITICAL, "sierra_ds_dssd_last_valid_data_page_find(): block number %d is out of scope\n", data_block);
    *data_page_no = page_no;
    return FALSE;	 
  }

  page_buf_p = sierra_ds_page_buf_allocate(page_size);
  if(NULL == page_buf_p)
  {
    dprintf(CRITICAL, "sierra_ds_dssd_last_valid_data_page_find(): can't allocate page buf\n");
    *data_page_no = page_no;
    return FALSE;
  }

  /* Start to find from last page to start page */
  start_page = block_size * data_block;
  last_page = start_page + block_size - 1;

  for(page_no = last_page; page_no >= start_page; page_no--)
  {
    /* Read the page */
    memset(page_buf_p, 0, DS_MAX_PAGE_SIZE);
    if(0 != qpic_nand_read_page_sierra(page_no, page_buf_p))
    {
      /* Page read failed */
      dprintf(CRITICAL, "sierra_ds_dssd_last_valid_data_page_find(): page(%d) read failed\n", page_no);
      continue;
    }
    else
    {
#ifdef SIERRA_DUAL_SYSTEM_TEST
      dprintf(CRITICAL, "sierra_ds_dssd_last_valid_data_page_find(): Page(%d) read OK\n", page_no);
#endif /* SIERRA_DUAL_SYSTEM_TEST */

      /* Page read OK */
      data_p = (struct ds_shared_data_s *)page_buf_p;
      if((DS_MAGIC_NUMBER == data_p->magic_beg) 
          && (DS_MAGIC_NUMBER == data_p->magic_end)
          && (data_p->crc32 == crcrc32((void *)page_buf_p, (sizeof(struct ds_shared_data_s) - sizeof(uint32)), CRSTART_CRC32)))
      {
#ifdef SIERRA_DUAL_SYSTEM_TEST
        dprintf(CRITICAL, "sierra_ds_dssd_last_valid_data_page_find(): It is valid DS data in the page\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

        /* It is valid DS data in the page */
        if(NULL != ds_data)
        {
#ifdef SIERRA_DUAL_SYSTEM_TEST
          dprintf(CRITICAL, "sierra_ds_dssd_last_valid_data_page_find(): Store valid DS data\n");
#endif
          /* Store valid DS data */
          memcpy((void *)ds_data, (void *)data_p, sizeof(struct ds_shared_data_s));
        }
#ifdef SIERRA_DUAL_SYSTEM_TEST
        else
        {
          dprintf(CRITICAL, "sierra_ds_dssd_last_valid_data_page_find(): ds_data pointer is NULL\n");
        }
#endif /* SIERRA_DUAL_SYSTEM_TEST */

        result = TRUE;
        break;
      }
      else
      {
        if(sierra_ds_dssd_is_erased_page(page_buf_p, page_size))
        {
          continue;
        }
        else
        {	  
          /* DS data corrupted */
          dprintf(CRITICAL, "ds_dssd_last_valid_data_page_find(): DS data corrupted in page %d\n", page_no);
          result = FALSE;
          break;
        }
      }
    } /* end of page read OK */
  }

  if((!result) && (page_no < start_page))
  {
    /* No data page found, should not be here if 'block_no' is data block */
    page_no = DS_PAGE_SERACH_NOT_START;
  }

  sierra_ds_page_buf_free();
  *data_page_no = page_no;

  return result;
}

/************
 *
 * Name:	sierra_ds_dssd_partition_read
 *
 * Purpose: Read out the valid data from DSSD partition
 *
 * Parms: ds_data - DS message pointer
 *            request_result - return result
 *
 * Return: None
 *
 * Abort: None
 *
 * Notes: None
 *
 ************/
void sierra_ds_dssd_partition_read(
  struct ds_shared_data_s * ds_data,
  bool * request_result)
{
  uint32 data_block[DSSD_MAX_DATA_BLOCK] = {0};
  uint32 last_data_page[DSSD_MAX_DATA_BLOCK] = {0};
  uint32 total_block, data_block_count, data_block_no;
  struct ptentry * ptn = NULL;
  struct ptable * ptable = NULL;

  ASSERT(ds_data);
  ASSERT(request_result);

  *request_result = FALSE;

  /* 1. Get DSSD partition handler */
  ptable = flash_get_ptable();
  if (ptable == NULL) 
  {
    dprintf(CRITICAL, "sierra_ds_dssd_partition_read(): flash_get_ptable failed\n");
    return;
  }

  ptn = ptable_find(ptable, (const char *)BL_SSDATA_PARTI_NAME);
  if (ptn == NULL)
  {
    dprintf(CRITICAL, "sierra_ds_dssd_partition_read(): ptable_find 'dssd' partition failed\n");
    return;
  }

  total_block = ptn->length;

  /* 2. Find all blocks with DS data */
  if((!sierra_ds_dssd_data_blocks_find(ptn, data_block, &data_block_count))
     || (data_block_count > total_block))
  {
    dprintf(CRITICAL, "sierra_ds_dssd_partition_read(): failed to find data blocks\n");
    return;
  }

#ifdef SIERRA_DUAL_SYSTEM_TEST
  dprintf(CRITICAL, "sierra_ds_dssd_partition_read(): data_block[0]=%d, data_block[1]=%d\n",
                     data_block[0], data_block[1]);
#endif /* SIERRA_DUAL_SYSTEM_TEST */

  /* 3. Read DS data according to different cases */
  switch(data_block_count)
  {
    case 0:
      /* 3.0 No data block found */
#ifdef SIERRA_DUAL_SYSTEM_TEST
      dprintf(CRITICAL, "sierra_ds_dssd_partition_read(): No data block found\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

      break;

    default:
      /* 3.n Data block found. */
#ifdef SIERRA_DUAL_SYSTEM_TEST
      dprintf(CRITICAL, "sierra_ds_dssd_partition_read(): find %d data blocks\n", data_block_count);
#endif /* SIERRA_DUAL_SYSTEM_TEST */

      /* Find the one last valid data page from the data blocks */
      for(data_block_no = 0; data_block_no < data_block_count; data_block_no++)
      {
        if(sierra_ds_dssd_last_valid_data_page_find(ptn, data_block[data_block_no], 
                                                    &last_data_page[data_block_no], ds_data))
        {
          /* Already find one last valid data page and store DS data, exit the loop */
#ifdef SIERRA_DUAL_SYSTEM_TEST
          dprintf(CRITICAL, "sierra_ds_dssd_partition_read(): Find valid data page\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

          *request_result = TRUE;
          break;
        }
      }

      break;
  }

  return;
}

/************
 *
 * Name:	sierra_ds_dssd_partition_write
 *
 * Purpose: Write DS data to DSSD partition
 *
 * Parms: ds_data - DS message pointer
 *            request_result - return result
 *
 * Return: None
 *
 * Abort: None
 *
 * Notes:	None
 *
 ************/
void sierra_ds_dssd_partition_write(
  struct ds_shared_data_s * ds_data,
  bool * request_result)
{
  uint32 data_block[DSSD_MAX_DATA_BLOCK] = {0};
  uint32 last_data_page[DSSD_MAX_DATA_BLOCK] = {0};
  uint32 total_block, start_block_no, max_block_no, block_size, start_search_block, data_block_no, data_block_count;
  uint32 start_page, last_page, page_size;
  uint8 * page_buf_p = NULL;
  struct ptentry * ptn = NULL;
  struct ptable * ptable = NULL;

  ASSERT(request_result);
  ASSERT(ds_data);

  *request_result = FALSE;

  /* 1. Get DSSD partition handler */
  ptable = flash_get_ptable();
  if (ptable == NULL) 
  {
    dprintf(CRITICAL, "sierra_ds_dssd_partition_write(): flash_get_ptable failed\n");
    return;
  }

  ptn = ptable_find(ptable, (const char *)BL_SSDATA_PARTI_NAME);
  if (ptn == NULL)
  {
    dprintf(CRITICAL, "sierra_ds_dssd_partition_write(): ptable_find 'dssd' partition failed\n");
    return;
  }

  total_block = ptn->length;
  start_block_no = ptn->start;
  max_block_no = start_block_no + total_block - 1;
  block_size = flash_num_pages_per_block_sierra();
  page_size = flash_page_size_sierra();

  /* 2. Find all blocks with DS data */
  if((!sierra_ds_dssd_data_blocks_find(ptn, data_block, &data_block_count))
     || (data_block_count > total_block))
  {
    dprintf(CRITICAL, "sierra_ds_dssd_partition_write(): failed to find data blocks\n");
    return;
  }

#ifdef SIERRA_DUAL_SYSTEM_TEST
  dprintf(CRITICAL, "sierra_ds_dssd_partition_write(): data_block[0]=%d, data_block[1]=%d\n",
                     data_block[0], data_block[1]);
#endif /* SIERRA_DUAL_SYSTEM_TEST */

  /* 3. Write DS data according to different cases. Make sure there are 2 data copies stored. */
  switch(data_block_count)
  {
    case 0:
      /* 3.0 It is the first time to write DS data. Find the first and second free blocks and write data to them. */
#ifdef SIERRA_DUAL_SYSTEM_TEST
      dprintf(CRITICAL, "sierra_ds_dssd_partition_write(): No data block found\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

      /* 3.0.1 Prepare for the DS data to write */
      page_buf_p = sierra_ds_page_buf_allocate(page_size);
      if(NULL == page_buf_p)
      {
        dprintf(CRITICAL, "sierra_ds_dssd_partition_write(): can't allocate page buf\n");
        return;
      }
      memset(page_buf_p, 0, DS_MAX_PAGE_SIZE);
      memcpy((void *)page_buf_p, (void *)ds_data, sizeof(struct ds_shared_data_s));

      /* 3.0.2 Write DS data to two free blocks */
      start_search_block = start_block_no;
      if(!sierra_ds_dssd_free_blocks_write(ptn, start_search_block, 
                                           data_block_count, data_block, page_buf_p))
      {
        dprintf(CRITICAL, "sierra_ds_dssd_partition_write(): Write data to two free blocks failed\n");
        sierra_ds_page_buf_free();
        return;
      }

      /* 3.0.3 Free the DS page buffer */
      sierra_ds_page_buf_free();

      break;

    case 2:
      /* 3.2 It is expected case. */
#ifdef SIERRA_DUAL_SYSTEM_TEST
      dprintf(CRITICAL, "sierra_ds_dssd_partition_write(): find %d data blocks\n", data_block_count);
#endif /* SIERRA_DUAL_SYSTEM_TEST */

      /* 3.2.1 Find the last data page from the two data blocks */
      for(data_block_no = 0; data_block_no < data_block_count; data_block_no++)
      {
        sierra_ds_dssd_last_valid_data_page_find(ptn, data_block[data_block_no], 
                                                 &last_data_page[data_block_no], NULL);
      }

      if((DS_PAGE_SERACH_NOT_START == last_data_page[0]) && (DS_PAGE_SERACH_NOT_START == last_data_page[1]))
      {
        /* Should not be here */
        dprintf(CRITICAL, "sierra_ds_dssd_partition_write(): fail to find last data page\n");
        return;
      }

      /* 3.2.2 Prepare for the DS data to write */
      page_buf_p = sierra_ds_page_buf_allocate(page_size);
      if(NULL == page_buf_p)
      {
        dprintf(CRITICAL, "sierra_ds_dssd_partition_write(): can't allocate page buf\n");
        return;
      }
      memset(page_buf_p, 0, DS_MAX_PAGE_SIZE);
      memcpy((void *)page_buf_p, (void *)ds_data, sizeof(struct ds_shared_data_s));

      /* 3.2.3 Start to write data */
      if((last_data_page[0] == (data_block[0] + 1) * block_size - 1) 
         || (last_data_page[1] == (data_block[1] + 1) * block_size - 1))
      {
        /* 3.2.3.1 If data page is the last page of the block, no free page for new DS data in this block.
                * Find two free blocks for new DS data, erase outdated two data blocks.
                */
#ifdef SIERRA_DUAL_SYSTEM_TEST
        dprintf(CRITICAL, "sierra_ds_dssd_partition_write(): data page is the last page of the block\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

        start_search_block = data_block[data_block_count - 1] + 1;
        if(!sierra_ds_dssd_free_blocks_write(ptn, start_search_block, 
                                             data_block_count, data_block, page_buf_p))
        {
          dprintf(CRITICAL, "sierra_ds_dssd_partition_write(): Write data to two free blocks failed\n");
          sierra_ds_page_buf_free();
          return;
        }

        /* Erase outdated two data blocks */
        for(data_block_no = 0; data_block_no < data_block_count; data_block_no++)
        {
          if((DS_DATA_BLOCK_ERASED == data_block[data_block_no]) 
             || (data_block[data_block_no] < start_block_no) 
             || (data_block[data_block_no] > max_block_no))
          {
            dprintf(CRITICAL, "sierra_ds_dssd_partition_write(): data block erased or out of scope\n");
            continue;
          }

          if(qpic_nand_blk_erase(data_block[data_block_no] * block_size))
          {
            dprintf(CRITICAL, "sierra_ds_dssd_partition_write():  block erase failed. %d\n", data_block[data_block_no]);
          }
        }
      }
      else
      {
        /* 3.2.3.2 If the data page is not the last page, write data to page 'last_data_page[n]+1' */
#ifdef SIERRA_DUAL_SYSTEM_TEST
        dprintf(CRITICAL, "sierra_ds_dssd_partition_write(): data page is not the last page of the block\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

        for(data_block_no = 0; data_block_no < data_block_count; data_block_no++)
        {
          start_page = data_block[data_block_no] * block_size;
          last_page = start_page + block_size - 1;

#ifdef SIERRA_DUAL_SYSTEM_TEST
          dprintf(CRITICAL, "sierra_ds_dssd_partition_write(): start_page=%d, last_page=%d, last_data_page[data_block_no]=%d\n", 
                             start_page, last_page, last_data_page[data_block_no]);
#endif /* SIERRA_DUAL_SYSTEM_TEST */

          if((last_data_page[data_block_no] >= start_page) && (last_data_page[data_block_no] < last_page))
          {
#ifdef SIERRA_DUAL_SYSTEM_TEST
            dprintf(CRITICAL, "sierra_ds_dssd_partition_write(): Write the data to %d\n", last_data_page[data_block_no]+1);
#endif /* SIERRA_DUAL_SYSTEM_TEST */

            /* Write the data to last_data_page[data_block_no]+1 */
            if(qpic_nand_write_page_sierra((last_data_page[data_block_no]+1), page_buf_p))
            {
              sierra_ds_page_buf_free();
              return;
            }
          }
          else
          {
            dprintf(CRITICAL, "sierra_ds_dssd_partition_write(): last data page %d is out of scope\n", last_data_page[data_block_no]);
            sierra_ds_page_buf_free();
            return;
          }
        }
      }

      /* 3.2.4 Free the DS page buffer */
      sierra_ds_page_buf_free();

      break;

    default:
      /* 3.n It is abnormal case(data_block_count: 1, 3~max_block_no). Try to trim the data blocks.
            * Find two free blocks and write new DS data to them, and erase all data blocks.
            */
#ifdef SIERRA_DUAL_SYSTEM_TEST
      dprintf(CRITICAL, "sierra_ds_dssd_partition_write(): find %d data blocks\n", data_block_count);
#endif /* SIERRA_DUAL_SYSTEM_TEST */

      /* 3.n.1 Prepare for the DS data to write */
      page_buf_p = sierra_ds_page_buf_allocate(page_size);
      if(NULL == page_buf_p)
      {
        dprintf(CRITICAL, "sierra_ds_dssd_partition_write(): can't allocate page buf\n");
        return;
      }
      memset(page_buf_p, 0, DS_MAX_PAGE_SIZE);
      memcpy((void *)page_buf_p, (void *)ds_data, sizeof(struct ds_shared_data_s));

      /* 3.n.2 Find two free blocks and write new DS data to them */
      start_search_block = data_block[data_block_count - 1] + 1;
      if(!sierra_ds_dssd_free_blocks_write(ptn, start_search_block, 
                                    data_block_count, data_block, page_buf_p))
      {
        dprintf(CRITICAL, "sierra_ds_dssd_partition_write(): Write data to two free blocks failed\n");
        sierra_ds_page_buf_free();
        return;
      }

      /* 3.n.3 Erase outdated data blocks */
      for(data_block_no = 0; data_block_no < data_block_count; data_block_no++)
      {
        if((DS_DATA_BLOCK_ERASED == data_block[data_block_no]) 
           || (data_block[data_block_no] < start_block_no) 
           || (data_block[data_block_no] > max_block_no))
        {
          dprintf(CRITICAL, "sierra_ds_dssd_partition_write(): data block erased or out of scope\n");
          continue;
        }

        if(qpic_nand_blk_erase(data_block[data_block_no] * block_size))
        {
          dprintf(CRITICAL, "sierra_ds_dssd_partition_write():	block erase failed. %d\n", data_block[data_block_no]);
        }
      }

      /* 3.n.4 Free the DS page buffer */
      sierra_ds_page_buf_free();

      break;
  }

  *request_result = TRUE;
  return;
}

/************
 *
 * Name:	sierra_ds_init_flag_to_not_set
 *
 * Purpose: Sync all flags with DS data
 *
 * Parms: ds_flag - dual system flag pointer
 *
 * Return: None
 *
 * Abort: None
 *
 * Notes: None
 *
 ************/
void sierra_ds_init_flag_to_not_set(
  struct ds_flag_s *ds_flag)
{
  ASSERT(ds_flag);

  ds_flag->ssid_modem_idx = DS_SSID_NOT_SET;
  ds_flag->ssid_lk_idx = DS_SSID_NOT_SET;
  ds_flag->ssid_linux_idx = DS_SSID_NOT_SET;
  ds_flag->swap_reason = DS_FLAG_NOT_SET;
  ds_flag->sw_update_state = DS_FLAG_NOT_SET;
  ds_flag->out_of_sync = DS_FLAG_NOT_SET;
  ds_flag->efs_corruption_in_sw_update = DS_FLAG_NOT_SET;
  ds_flag->edb_in_sw_update = DS_FLAG_NOT_SET;
  ds_flag->bad_image = DS_IMAGE_FLAG_NOT_SET;

  return;
}

/************
 *
 * Name: sierra_ds_data_to_flag_sync
 *
 * Purpose: Sync all flags with DS data
 *
 * Parms: ds_data -dual system shared data pointer
 *            ds_flag - dual system flag pointer
 *
 * Return: None
 *
 * Abort: None
 *
 * Notes: None
 *
 ************/
void sierra_ds_data_to_flag_sync(
  struct ds_shared_data_s *ds_data,
  struct ds_flag_s *ds_flag)
{
  ASSERT(ds_data);
  ASSERT(ds_flag);

  ds_flag->ssid_modem_idx = ds_data->ssid_modem_idx;
  ds_flag->ssid_lk_idx = ds_data->ssid_lk_idx;
  ds_flag->ssid_linux_idx = ds_data->ssid_linux_idx;
  ds_flag->swap_reason = ds_data->swap_reason;
  ds_flag->sw_update_state = ds_data->sw_update_state;
  ds_flag->out_of_sync = ds_data->out_of_sync;
  ds_flag->efs_corruption_in_sw_update = ds_data->efs_corruption_in_sw_update;
  ds_flag->edb_in_sw_update = ds_data->edb_in_sw_update;
  ds_flag->bad_image = ds_data->bad_image;

  return;
}

/************
 *
 * Name: sierra_ds_get_full_data
 *
 * Purpose: Read DS data from DSSD partition
 *
 * Parms: ds_flag - dual system flag pointer
 *
 * Return: TRUE - request successfully
 *             FALSE - otherwise
 *
 * Abort: None
 *
 * Notes: Get initial DS data if ds_dssd_partition_read() failed
 *
 ************/
bool sierra_ds_get_full_data(
  struct ds_flag_s *ds_flag)
{
  struct ds_shared_data_s ds_data;
  bool result = FALSE;

  ASSERT(ds_flag);

  sierra_ds_dssd_partition_read(&ds_data , &result);

  if(!result)
  {
    /* In case reading failed, try to set DS data with default value */
#ifdef SIERRA_DUAL_SYSTEM_TEST
    dprintf(CRITICAL, "sierra_ds_get_full_data(): Read failed and init flag\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

    sierra_ds_flag_init(ds_flag);
  }
  else
  {
#ifdef SIERRA_DUAL_SYSTEM_TEST
    dprintf(CRITICAL, "sierra_ds_get_full_data(): Read successfully, sync ds data to ds flag\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

    sierra_ds_data_to_flag_sync(&ds_data, ds_flag);
  }

  return result;
}

/************
 *
 * Name: sierra_ds_set_full_data
 *
 * Purpose: Write DS data to DSSD partition
 *
 * Parms: ds_flag - dual system flag pointer
 *
 * Return: TRUE - request successfully
 *             FALSE - otherwise
 *
 * Abort: None
 *
 * Notes: None
 *
 ************/
bool sierra_ds_set_full_data(
struct ds_flag_s *ds_flag)
{
  struct ds_flag_s ds_flag_source;
  struct ds_shared_data_s ds_data_destination;
  bool result = FALSE;

  ASSERT(ds_flag);

  /* Get current full data */
  sierra_ds_get_full_data(&ds_flag_source);

  /* Clear destination ds data structure */
  memset((void *)&ds_data_destination, 0, sizeof(struct ds_shared_data_s));

  /* Deal with the flags according to different cases */
  /* 1. SSID modem index */
  if(DS_SSID_NOT_SET != ds_flag->ssid_modem_idx)
  {
    ds_data_destination.ssid_modem_idx = ds_flag->ssid_modem_idx;
  }
  else
  {
#ifdef SIERRA_DUAL_SYSTEM_TEST
    dprintf(CRITICAL, "sierra_ds_set_full_data(): SSID modem index flag is not set\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

    ds_data_destination.ssid_modem_idx = ds_flag_source.ssid_modem_idx;
  }

  /* 2. SSID LK index */
  if(DS_SSID_NOT_SET != ds_flag->ssid_lk_idx)
  {
    ds_data_destination.ssid_lk_idx = ds_flag->ssid_lk_idx;
  }
  else
  {
#ifdef SIERRA_DUAL_SYSTEM_TEST
    dprintf(CRITICAL, "sierra_ds_set_full_data(): SSID LK index flag is not set\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

    ds_data_destination.ssid_lk_idx = ds_flag_source.ssid_lk_idx;
  }

  /* 3. SSID Linux index */
  if(DS_SSID_NOT_SET != ds_flag->ssid_linux_idx)
  {
    ds_data_destination.ssid_linux_idx = ds_flag->ssid_linux_idx;
  }
  else
  {
#ifdef SIERRA_DUAL_SYSTEM_TEST
    dprintf(CRITICAL, "sierra_ds_set_full_data(): SSID Linux index flag is not set\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

    ds_data_destination.ssid_linux_idx = ds_flag_source.ssid_linux_idx;
  }

  /* 4. dual system swap reason */
  if(DS_FLAG_NOT_SET != ds_flag->swap_reason)
  {
    ds_data_destination.swap_reason = ds_flag->swap_reason;
  }
  else
  {
#ifdef SIERRA_DUAL_SYSTEM_TEST
    dprintf(CRITICAL, "sierra_ds_set_full_data(): swap reason flag is not set\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

    ds_data_destination.swap_reason = ds_flag_source.swap_reason;
  }

  /* 5. SW update state */
  if(DS_FLAG_NOT_SET != ds_flag->sw_update_state)
  {
    ds_data_destination.sw_update_state = ds_flag->sw_update_state;
  }
  else
  {
#ifdef SIERRA_DUAL_SYSTEM_TEST
    dprintf(CRITICAL, "sierra_ds_set_full_data(): SW update state flag is not set\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

    ds_data_destination.sw_update_state = ds_flag_source.sw_update_state;
  }

  /* 6. Out of sync flag */
  if(DS_FLAG_NOT_SET != ds_flag->out_of_sync)
  {
    ds_data_destination.out_of_sync = ds_flag->out_of_sync;
  }
  else
  {
#ifdef SIERRA_DUAL_SYSTEM_TEST
    dprintf(CRITICAL, "sierra_ds_set_full_data(): out of sync flag is not set\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

    ds_data_destination.out_of_sync = ds_flag_source.out_of_sync;
  }

  /* 7. EFS corruption in SW update */
  if(DS_FLAG_NOT_SET != ds_flag->efs_corruption_in_sw_update)
  {
    ds_data_destination.efs_corruption_in_sw_update = ds_flag->efs_corruption_in_sw_update;
  }
  else
  {
#ifdef SIERRA_DUAL_SYSTEM_TEST
    dprintf(CRITICAL, "sierra_ds_set_full_data(): EFS corruption in SW update flag is not set\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

    ds_data_destination.efs_corruption_in_sw_update = ds_flag_source.efs_corruption_in_sw_update;
  }

  /* 8. EDB in SW update */
  if(DS_FLAG_NOT_SET != ds_flag->edb_in_sw_update)
  {
    ds_data_destination.edb_in_sw_update = ds_flag->edb_in_sw_update;
  }
  else
  {
#ifdef SIERRA_DUAL_SYSTEM_TEST
    dprintf(CRITICAL, "sierra_ds_set_full_data(): EDB in SW update flag is not set\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

    ds_data_destination.edb_in_sw_update = ds_flag_source.edb_in_sw_update;
  }

  /* 9. Bad image flag  */
  if(DS_IMAGE_CLEAR_FLAG == ds_flag->bad_image)
  {
#ifdef SIERRA_DUAL_SYSTEM_TEST
    dprintf(CRITICAL, "sierra_ds_set_full_data(): bad image flag is clear\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

    ds_data_destination.bad_image = DS_IMAGE_CLEAR_FLAG;
  }
  else if(DS_IMAGE_FLAG_NOT_SET == ds_flag->bad_image)
  {
#ifdef SIERRA_DUAL_SYSTEM_TEST
    dprintf(CRITICAL, "sierra_ds_set_full_data(): bad image flag is not set\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

    ds_data_destination.bad_image = ds_flag_source.bad_image;
  }
  else
  {
    ds_data_destination.bad_image = ds_flag->bad_image;
    ds_data_destination.bad_image |= ds_flag_source.bad_image;
  }

  ds_data_destination.magic_beg = DS_MAGIC_NUMBER;
  ds_data_destination.magic_end = DS_MAGIC_NUMBER;
  ds_data_destination.crc32 = crcrc32((void *)(&ds_data_destination), (sizeof(struct ds_shared_data_s) - sizeof(uint32)), CRSTART_CRC32);

  sierra_ds_dssd_partition_write(&ds_data_destination,&result);

#ifdef SIERRA_DUAL_SYSTEM_TEST
  if(result)
  {
    dprintf(CRITICAL, "sierra_ds_set_full_data(): Write successfully");
  }
  else
  {
    dprintf(CRITICAL, "sierra_ds_set_full_data(): Write failed");
  }
#endif /* SIERRA_DUAL_SYSTEM_TEST */

  return result;
}

/************
 *
 * Name: sierra_ds_set_new_data
 *
 * Purpose: Write DS data to DSSD partition
 *
 * Parms: ds_flag - dual system flag pointer
 *
 * Return: TRUE - request successfully
 *             FALSE - otherwise
 *
 * Abort: None
 *
 * Notes: Different to sierra_ds_set_full_data(): 
 *           - This function will update ssdata fully by ds_flag.
 *           - Caller should make sure all of data is correct in ds_flag.
 *
 ************/
void sierra_ds_set_new_data(
struct ds_flag_s *ds_flag)
{
  struct ds_shared_data_s ds_data_destination;
  bool result = FALSE;

  ASSERT(ds_flag);

  /* Clear destination ds data structure */
  memset((void *)&ds_data_destination, 0, sizeof(struct ds_shared_data_s));

  /* Deal with the flags according to different cases */
  /* 1. SSID modem index */
  ds_data_destination.ssid_modem_idx = ds_flag->ssid_modem_idx;

  /* 2. SSID LK index */
  ds_data_destination.ssid_lk_idx = ds_flag->ssid_lk_idx;

  /* 3. SSID Linux index */
  ds_data_destination.ssid_linux_idx = ds_flag->ssid_linux_idx;

  /* 4. dual system swap reason */
  ds_data_destination.swap_reason = ds_flag->swap_reason;

  /* 5. SW update state */
  ds_data_destination.sw_update_state = ds_flag->sw_update_state;

  /* 6. Out of sync flag */
  ds_data_destination.out_of_sync = ds_flag->out_of_sync;

  /* 7. EFS corruption in SW update */
  ds_data_destination.efs_corruption_in_sw_update = ds_flag->efs_corruption_in_sw_update;

  /* 8. EDB in SW update */
  ds_data_destination.edb_in_sw_update = ds_flag->edb_in_sw_update;

  /* 9. Bad image flag	*/
  ds_data_destination.bad_image = ds_flag->bad_image;

  ds_data_destination.magic_beg = DS_MAGIC_NUMBER;
  ds_data_destination.magic_end = DS_MAGIC_NUMBER;
  ds_data_destination.crc32 = crcrc32((void *)(&ds_data_destination), (sizeof(struct ds_shared_data_s) - sizeof(uint32)), CRSTART_CRC32);

  sierra_ds_dssd_partition_write(&ds_data_destination, &result);

  return;
}

/************
 *
 * Name: sierra_ds_check_if_out_of_sync
 *
 * Purpose: Check if dual system is out of sync
 *
 * Parms: None
 *
 * Return: TRUE - Out of sync
 *             FALSE - system is sync
 *
 * Abort: None
 *
 * Notes: None
 *
 ************/
bool sierra_ds_check_if_out_of_sync(
  void)
{
  struct ds_flag_s ds_flag;

  sierra_ds_get_full_data(&ds_flag);

  if(DS_OUT_OF_SYNC == ds_flag.out_of_sync)
  {
#ifdef SIERRA_DUAL_SYSTEM_TEST
    dprintf(CRITICAL, "Dual system is out of sync\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

    return TRUE;
  }
  else
  {
#ifdef SIERRA_DUAL_SYSTEM_TEST
    dprintf(CRITICAL, "Dual system is sync\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

    return FALSE;
  }
}

/************
 *
 * Name: sierra_ds_check_if_ds_is_sync
 *
 * Purpose: Check if dual system is ds is sync
 *
 * Parms: None
 *
 * Return: TRUE - ds is sync
 *             FALSE - out of sync
 *
 * Abort: None
 *
 * Notes: None
 *
 ************/
bool sierra_ds_check_if_ds_is_sync(
  void)
{
  struct ds_flag_s ds_flag;

  sierra_ds_get_full_data(&ds_flag);

  if(DS_IS_SYNC == ds_flag.out_of_sync)
  {
#ifdef SIERRA_DUAL_SYSTEM_TEST
    dprintf(CRITICAL, "Dual system is ds is sync\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

    return TRUE;
  }
  else
  {
#ifdef SIERRA_DUAL_SYSTEM_TEST
    dprintf(CRITICAL, "Dual system is out of sync\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

    return FALSE;
  }
}

/************
 *
 * Name: sierra_ds_check_is_recovery_phase1
 *
 * Purpose: Check if it is recovery_phase1
 *
 * Parms: None
 *
 * Return: TRUE - it is recovery phase1
 *             FALSE - not recovery phase1
 *
 * Abort: None
 *
 * Notes: None
 *
 ************/
bool sierra_ds_check_is_recovery_phase1(void)
{
  struct ds_flag_s ds_flag;

  sierra_ds_get_full_data(&ds_flag);

  if(DS_SW_UPDATE_STATE_RECOVERY_PHASE_1 == ds_flag.sw_update_state)
  {
#ifdef SIERRA_DUAL_SYSTEM_TEST
    dprintf(CRITICAL, "It is RECOVERY_PHASE_1\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

    return TRUE;
  }
  else
  {
#ifdef SIERRA_DUAL_SYSTEM_TEST
    dprintf(CRITICAL, "It isn't RECOVERY_PHASE_1\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

    return FALSE;
  }
}

/************
 *
 * Name: sierra_ds_check_is_recovery_phase2
 *
 * Purpose: Check if it is recovery_phase2
 *
 * Parms: None
 *
 * Return: TRUE - it is recovery phase2
 *             FALSE - not recovery phase2
 *
 * Abort: None
 *
 * Notes: None
 *
 ************/
bool sierra_ds_check_is_recovery_phase2(void)
{
  struct ds_flag_s ds_flag;

  sierra_ds_get_full_data(&ds_flag);

  if(DS_SW_UPDATE_STATE_RECOVERY_PHASE_2 == ds_flag.sw_update_state)
  {
#ifdef SIERRA_DUAL_SYSTEM_TEST
    dprintf(CRITICAL, "It is RECOVERY_PHASE_2\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

    return TRUE;
  }
  else
  {
#ifdef SIERRA_DUAL_SYSTEM_TEST
    dprintf(CRITICAL, "It isn't RECOVERY_PHASE_2\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

    return FALSE;
  }
}

/************
 *
 * Name: sierra_ds_write_flags_in_lk
 *
 * Purpose: Write DS data to DSSD partition
 *
 * Parms: sw_update_state - SW update state, fill 'DS_IMAGE_FLAG_NOT_SET' if it is unnecessary to update it.
 *            out_of_sync - Out of Sync flag, fill 'DS_IMAGE_FLAG_NOT_SET' if it is unnecessary to update it.
 *            bad_image - bad image mask, fill 'DS_IMAGE_FLAG_NOT_SET' if it is unnecessary to update it.
 *
 * Return: TRUE - request successfully
 *             FALSE - otherwise
 *
 * Abort: None
 *
 * Notes: It is used in below cases:
 *           1. Write 'sw_update_state' during SW recovery
 *           2. Clear 'out_of_sync' flag after sync done in LK
 *           3. Write 'bad_image' before SW update in LK and clear it after SW update done
 *
 ************/
bool sierra_ds_write_flags_in_lk(
  uint32 sw_update_state,
  uint32 out_of_sync,
  uint64 bad_image)
{
  struct ds_flag_s ds_flag;

  if((sw_update_state < DS_SW_UPDATE_STATE_MIN) 
      || (sw_update_state > DS_SW_UPDATE_STATE_MAX))
  {
    dprintf(CRITICAL, "sierra_ds_write_flags_in_lk(): Invalid SW update state parameter 0x%d.\n", sw_update_state);
    return FALSE;
  }

  if((DS_OUT_OF_SYNC != out_of_sync) 
     && (DS_IS_SYNC != out_of_sync)
     && (0 != out_of_sync))
  {
    dprintf(CRITICAL, "sierra_ds_write_flags_in_lk(): Invalid sync parameter 0x%x.\n", out_of_sync);
    return FALSE;
  }

  sierra_ds_init_flag_to_not_set(&ds_flag);
  ds_flag.sw_update_state = sw_update_state;
  ds_flag.out_of_sync = out_of_sync;
  ds_flag.bad_image = bad_image;

  return sierra_ds_set_full_data(&ds_flag);
}

/************
 *
 * Name:     sierra_ds_smem_get_address
 *
 * Purpose:  Get DS SMEM base address
 *
 * Parms:   None 
 *
 * Return:   pointer to DSSD SMEM buffer
 *
 * Abort:    None
 *
 * Notes:    None
 *
 ************/
struct ds_smem_message_s * sierra_ds_smem_get_address(
  void)
{
  struct ds_smem_message_s *ds_smem_bufp = NULL;
  unsigned char *virtual_addr = NULL;

  virtual_addr = sierra_smem_base_addr_get();
  if(NULL != virtual_addr)
  {
    /* Get DS SMEM base address */
    virtual_addr += BSMEM_DSSD_OFFSET;
    ds_smem_bufp = (struct ds_smem_message_s *)virtual_addr;
  }

  return ds_smem_bufp;
}

/************
 *
 * Name:     sierra_ds_smem_is_valid
 *
 * Purpose:  Check if DS SMEM is valid or not
 *
 * Parms:    ds_smem_bufp - pointer to DSSD SMEM buffer
 *
 * Return:   TRUE if successful
 *               FALSE otherwise
 *
 * Abort:    None
 *
 * Notes:    None
 *
 ************/
bool sierra_ds_smem_is_valid(
  struct ds_smem_message_s * ds_smem_bufp)
{
  uint32 ds_smem_crc = 0;

  ASSERT(ds_smem_bufp);

  ds_smem_crc = crcrc32((uint8 *)ds_smem_bufp, sizeof(struct ds_smem_message_s) - sizeof(uint32), CRSTART_CRC32);
  if((DS_MAGIC_NUMBER == ds_smem_bufp->magic_beg) 
      && (DS_MAGIC_NUMBER == ds_smem_bufp->magic_end) 
      && (ds_smem_bufp->crc32 == ds_smem_crc))
  {
#ifdef SIERRA_DUAL_SYSTEM_TEST
    dprintf(CRITICAL, "sierra_ds_smem_is_valid(): DS SMEM is valid\n");
#endif /* SIERRA_DUAL_SYSTEM_TEST */

    return TRUE;
  }
  else
  {
#ifdef SIERRA_DUAL_SYSTEM_TEST
    dprintf(CRITICAL, "sierra_ds_smem_is_valid(): DS SMEM is not valid\n");
    dprintf(CRITICAL, "sierra_ds_smem_is_valid(): ds_smem_bufp->magic_beg=%x, ds_smem_bufp->magic_end=%x\n",
                      ds_smem_bufp->magic_beg, ds_smem_bufp->magic_end);
    dprintf(CRITICAL, "sierra_ds_smem_is_valid(): ds_smem_crc=%x, ds_smem_bufp->crc32=%x\n",
                      ds_smem_crc, ds_smem_bufp->crc32);
    dprintf(CRITICAL, "sierra_ds_smem_is_valid(): ds_smem_bufp->ssid_modem_idx=%u, ds_smem_bufp->ssid_lk_idx=%u\n",
                      ds_smem_bufp->ssid_modem_idx, ds_smem_bufp->ssid_lk_idx);
    dprintf(CRITICAL, "sierra_ds_smem_is_valid(): ds_smem_bufp->ssid_linux_idx=%u, ds_smem_bufp->swap_reason=%u\n",
                      ds_smem_bufp->ssid_linux_idx, ds_smem_bufp->swap_reason);
    dprintf(CRITICAL, "sierra_ds_smem_is_valid(): ds_smem_bufp->bad_image=%08X%08X\n",
                      (uint32)(ds_smem_bufp->bad_image >> 32), (uint32)ds_smem_bufp->bad_image);
    dprintf(CRITICAL, "sierra_ds_smem_is_valid(): ds_smem_bufp->is_changed=%x\n",
                      (ds_smem_bufp->is_changed));
#endif /* SIERRA_DUAL_SYSTEM_TEST */

    return FALSE;
  }
}

/************
 *
 * Name:     sierra_ds_smem_init
 *
 * Purpose:  Check if DS SMEM is valid or not
 *
 * Parms:    ds_smem_bufp - pointer to DSSD SMEM buffer
 *
 * Return:   TRUE if successful
 *               FALSE otherwise
 *
 * Abort:    None
 *
 * Notes:    None
 *
 ************/
void sierra_ds_smem_init(
  struct ds_smem_message_s * ds_smem_bufp)
{
  ASSERT(ds_smem_bufp);

  memset((void *)ds_smem_bufp, 0, sizeof(struct ds_smem_message_s));
  ds_smem_bufp->magic_beg = DS_MAGIC_NUMBER;
  ds_smem_bufp->ssid_modem_idx = DS_SSID_SUB_SYSTEM_1;
  ds_smem_bufp->ssid_lk_idx = DS_SSID_SUB_SYSTEM_1;
  ds_smem_bufp->ssid_linux_idx = DS_SSID_SUB_SYSTEM_1;
  ds_smem_bufp->magic_end = DS_MAGIC_NUMBER;
  ds_smem_bufp->crc32 = crcrc32((uint8 *)ds_smem_bufp, sizeof(struct ds_smem_message_s) - sizeof(uint32), CRSTART_CRC32);

  return;
}

/************
 *
 * Name:     sierra_ds_smem_get_ssid_linux_index
 *
 * Purpose:  Get current linux sub system
 *
 * Parms:   None
 *
 * Return:   current linux sub system
 *
 * Abort:    None
 *
 * Notes:   None
 *
 ************/
uint8 sierra_ds_smem_get_ssid_linux_index(
  void)
{
  struct ds_smem_message_s * ds_smem_bufp = NULL;

  /* Get DS SMEM region */
  ds_smem_bufp = sierra_ds_smem_get_address();
  if(NULL == ds_smem_bufp)
  {
    dprintf(CRITICAL, "sierra_ds_smem_get_ssid_linux_index(): Can't get DS SMEM region\n");
    return DS_SSID_SUB_SYSTEM_1;
  }

  /* Make sure it is valid DS SMEM */
  if(!sierra_ds_smem_is_valid(ds_smem_bufp))
  {
    sierra_ds_smem_init(ds_smem_bufp);
  }

  return ds_smem_bufp->ssid_linux_idx;
}

/************
 *
 * Name:     sierra_ds_smem_erestore_info_set
 *
 * Purpose:  Set efs restore_info in share memory
 *
 * Parms:    [IN] value_type - type of the member
 *           [OUT]value      - store value get from smem
 *
 * Return:   TRUE - set successfully
 *           FALSE- set failed
 *
 * Abort:    None
 *
 * Notes:    None
 *
 ************/
bool sierra_ds_smem_erestore_info_set(uint32 value_type, uint8 value)
{
  struct ds_smem_erestore_info *efs_restore = NULL;
  unsigned char *virtual_addr = NULL;

  virtual_addr = sierra_smem_base_addr_get();
  if(NULL != virtual_addr)
  {
    /* Get DS SMEM base address */
    virtual_addr += BSMEM_EFS_RESTORE_OFFSET;
    efs_restore = (struct ds_smem_erestore_info *)virtual_addr;

    /* Check if data in smem valid */
    if((DS_MAGIC_EFSB != efs_restore->magic_beg) ||
       (DS_MAGIC_EFSE != efs_restore->magic_end) ||
       (crcrc32((void *)efs_restore, DS_ERESTORE_CRC_SZ, CRSTART_CRC32) != efs_restore->crc32))
    {
      /* Initalize the BS_SMEM_REGION_EFS_RESTORE.
       * If cold-reset or smem-destroyed happend, initialize the region in defalt.
       */
      efs_restore->magic_beg          = DS_MAGIC_EFSB;
      efs_restore->magic_end          = DS_MAGIC_EFSE;
      efs_restore->erestore_t         = BL_RESTORE_INFO_INVALID_VALUE;
      efs_restore->errorcount         = BL_RESTORE_INFO_INVALID_VALUE;
      efs_restore->restored_flag      = BL_RESTORE_INFO_INVALID_VALUE;
      efs_restore->beroption          = BL_RESTORE_INFO_INVALID_VALUE;
      efs_restore->crc32              = crcrc32((void *)efs_restore, DS_ERESTORE_CRC_SZ, CRSTART_CRC32);
    }

    if(BL_RESTORE_INFO_RESTORE_TYPE == value_type)
    {
    /* Set efs restore info */
      efs_restore->magic_beg  = DS_MAGIC_EFSB;
      efs_restore->magic_end  = DS_MAGIC_EFSE;
      efs_restore->erestore_t = value;
      efs_restore->crc32      = crcrc32((void *)efs_restore, DS_ERESTORE_CRC_SZ, CRSTART_CRC32);
    }
    else if(BL_RESTORE_INFO_ECOUNT_BUF == value_type)
    {
    /* Backup error count. */
      efs_restore->magic_beg  = DS_MAGIC_EFSB;
      efs_restore->magic_end  = DS_MAGIC_EFSE;
      efs_restore->errorcount = value;
      efs_restore->crc32      = crcrc32((void *)efs_restore, DS_ERESTORE_CRC_SZ, CRSTART_CRC32);
    }
    else if(BL_RESTORE_INFO_BEROPTION_BUF == value_type)
    {
    /* Backup error count. */
      efs_restore->magic_beg  = DS_MAGIC_EFSB;
      efs_restore->magic_end  = DS_MAGIC_EFSE;
      efs_restore->beroption = value;
      efs_restore->crc32      = crcrc32((void *)efs_restore, DS_ERESTORE_CRC_SZ, CRSTART_CRC32);
    }
    else if(BL_RESTORE_INFO_RESTORE_DONE == value_type)
    {
      /* Save restore flag. */
      efs_restore->magic_beg = DS_MAGIC_EFSB;
      efs_restore->magic_end = DS_MAGIC_EFSE;
      efs_restore->restored_flag = value;
      efs_restore->crc32     = crcrc32((void *)efs_restore, DS_ERESTORE_CRC_SZ, CRSTART_CRC32);
    }

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
 * Purpose:  Write DS SMEM if bad image detected in LK
 *
 * Parms:   bad_image_mask - bad image mask
 *
 * Return:   None
 *
 * Abort:    None
 *
 * Notes:   Call it only if bad image detected in LK
 *
 ************/
void sierra_ds_smem_write_bad_image_and_swap(
  uint64 bad_image_mask)
{
  struct ds_smem_message_s * ds_smem_bufp = NULL;
  uint8 need_erestore_type;

  /* Get DS SMEM region */
  ds_smem_bufp = sierra_ds_smem_get_address();
  if(NULL == ds_smem_bufp)
  {
    dprintf(CRITICAL, "sierra_ds_smem_write_bad_image_and_swap(): Can't get DS SMEM region\n");
    return;
  }

  /* Make sure it is valid DS SMEM */
  if(!sierra_ds_smem_is_valid(ds_smem_bufp))
  {
    sierra_ds_smem_init(ds_smem_bufp);
  }

  /* Swap system next boot up when bad kernel image detected */
  if(DS_SSID_SUB_SYSTEM_1 == ds_smem_bufp->ssid_modem_idx)
  {
    ds_smem_bufp->ssid_modem_idx = DS_SSID_SUB_SYSTEM_2;
  }
  else
  {
    ds_smem_bufp->ssid_modem_idx = DS_SSID_SUB_SYSTEM_1;
  }

  if(DS_SSID_SUB_SYSTEM_1 == ds_smem_bufp->ssid_lk_idx)
  {
    ds_smem_bufp->ssid_lk_idx = DS_SSID_SUB_SYSTEM_2;
  }
  else
  {
    ds_smem_bufp->ssid_lk_idx = DS_SSID_SUB_SYSTEM_1;
  }

  if(DS_SSID_SUB_SYSTEM_1 == ds_smem_bufp->ssid_linux_idx)
  {
    ds_smem_bufp->ssid_linux_idx = DS_SSID_SUB_SYSTEM_2;
  }
  else
  {
    ds_smem_bufp->ssid_linux_idx = DS_SSID_SUB_SYSTEM_1;
  }

  if(DS_IMAGE_CLEAR_FLAG == bad_image_mask)
  {
    ds_smem_bufp->bad_image = DS_IMAGE_CLEAR_FLAG;
  }
  else if(DS_IMAGE_FLAG_NOT_SET == bad_image_mask)
  {
    /* Do nothing */
  }
  else
  {
    ds_smem_bufp->bad_image |= bad_image_mask;
  }

  ds_smem_bufp->swap_reason = DS_SWAP_REASON_BAD_IMAGE;
  ds_smem_bufp->is_changed = DS_BOOT_UP_CHANGED;
  ds_smem_bufp->crc32 = crcrc32((uint8 *)ds_smem_bufp, sizeof(struct ds_smem_message_s) - sizeof(uint32), CRSTART_CRC32);
  /* Bad image flag set, a system swap will happen. Set the efs restore flag to restore efs at the next warm-reboot. */
  need_erestore_type = DS_RESTORE_EFS_SANITY_FROM_LK;
  sierra_ds_smem_erestore_info_set(BL_RESTORE_INFO_RESTORE_TYPE, need_erestore_type);
  dprintf(CRITICAL, "sierra_ds_smem_write_bad_image_and_swap(): set efs-restore flag %d\n",need_erestore_type);

  return;
}

#ifdef SIERRA_DUAL_SYSTEM_TEST
/************
 *
 * Name:     sierra_ds_test
 *
 * Purpose:  Dual system related tests in LK
 *
 * Parms:   arg - test command
 *
 * Return:   None
 *
 * Abort:    None
 *
 * Notes:   
 *     Fastboot command: fastboot flash <test command> [file path]
 *     <test command>
 *     swi_ds_read - Get all dual system flags from DSSD partition and DS SMEM
 *     swi_dssd_write - Test function 'sierra_ds_write_flags_in_lk' to write a group of flags to DSSD partition
 *     swi_dssd_init -Test to init flags to DSSD partition
 *     swi_ds_smem_write - Test function 'sierra_ds_smem_write_bad_image_and_swap' to write bad image and swap to DS SMEM
 *    [file path]
 *    any file path
 *
 *    For example: fastboot flash swi_ds_read d:\file_for_lk_test
 *
 ************/
void sierra_ds_test(
  const char *arg)
{
  struct ds_flag_s ds_flag;
  struct ds_smem_message_s * ds_smem_bufp = NULL;
  uint32 sw_update_state, out_of_sync;
  uint64 bad_image_mask;

  ASSERT(arg);

  if (!strcmp(arg, "swi_ds_read"))
  {
    sierra_ds_get_full_data(&ds_flag);

    /* Display all flags */
    dprintf(CRITICAL, "Get all dual system related flags:\n");
    dprintf(CRITICAL, "  ssid_modem_idx: %u\n", ds_flag.ssid_modem_idx);
    dprintf(CRITICAL, "  ssid_lk_idx: %u\n", ds_flag.ssid_lk_idx);
    dprintf(CRITICAL, "  ssid_linux_idx: %u\n", ds_flag.ssid_linux_idx);
    dprintf(CRITICAL, "  swap_reason: %u\n", ds_flag.swap_reason);
    dprintf(CRITICAL, "  sw_update_state: %u\n", ds_flag.sw_update_state);
    dprintf(CRITICAL, "  out_of_sync: 0x%x\n", ds_flag.out_of_sync);
    dprintf(CRITICAL, "  efs_corruption_in_sw_update: 0x%x\n", ds_flag.efs_corruption_in_sw_update);
    dprintf(CRITICAL, "  edb_in_sw_update: 0x%x\n", ds_flag.edb_in_sw_update);
    dprintf(CRITICAL, "  bad_image: 0x%08X%08X\n",
                  (uint32)(ds_flag.bad_image >> 32), (uint32)ds_flag.bad_image);

    ds_smem_bufp = sierra_ds_smem_get_address();
    if(NULL == ds_smem_bufp)
    {
      dprintf(CRITICAL, "sierra_ds_test(): Can't get DS SMEM region\n");
      return;
    }

    if(sierra_ds_smem_is_valid(ds_smem_bufp))
    {
      dprintf(CRITICAL, "Get all DS SMEM related flags:\n");
      dprintf(CRITICAL, "  ssid_modem_idx: %u\n", ds_smem_bufp->ssid_modem_idx);
      dprintf(CRITICAL, "  ssid_lk_idx: %u\n", ds_smem_bufp->ssid_lk_idx);
      dprintf(CRITICAL, "  ssid_linux_idx: %u\n", ds_smem_bufp->ssid_linux_idx);
      dprintf(CRITICAL, "  swap_reason: %u\n", ds_smem_bufp->swap_reason);
      dprintf(CRITICAL, "  bad_image: 0x%08X%08X\n",
                    (uint32)(ds_smem_bufp->bad_image >> 32), (uint32)ds_smem_bufp->bad_image);
      dprintf(CRITICAL, "  is_changed: %x\n", ds_smem_bufp->is_changed);
    }
    else
    {
      dprintf(CRITICAL, "DS SMEM is invalid\n");
    }
  }
  else if (!strcmp(arg, "swi_dssd_write"))
  {
    /* Test function 'sierra_ds_write_flags_in_lk' to write a group of flags to DSSD partition */
    out_of_sync = DS_IS_SYNC;
    sw_update_state = DS_SW_UPDATE_STATE_RECOVERY_PHASE_2;
    bad_image_mask = 0x4444555500000000;

    sierra_ds_write_flags_in_lk(sw_update_state, out_of_sync, bad_image_mask);
  }
  else if (!strcmp(arg, "swi_dssd_init"))
  {
    /* Test to init flags to DSSD partition */
    ds_flag.ssid_modem_idx = DS_SSID_SUB_SYSTEM_1;
    ds_flag.ssid_lk_idx= DS_SSID_SUB_SYSTEM_1;
    ds_flag.ssid_linux_idx= DS_SSID_SUB_SYSTEM_1;
    ds_flag.swap_reason = DS_SWAP_REASON_NONE;
    ds_flag.sw_update_state = DS_SW_UPDATE_STATE_NORMAL;
    ds_flag.out_of_sync = 0;
    ds_flag.efs_corruption_in_sw_update = 0;
    ds_flag.edb_in_sw_update = 0;
    ds_flag.bad_image = 0;

    sierra_ds_set_full_data(&ds_flag);
  }
  else if(!strcmp(arg, "swi_ds_smem_write"))
  {
    /* Test function 'sierra_ds_smem_write_bad_image_and_swap' to write bad image and swap to DS SMEM */
    bad_image_mask = 0xffffeeee00000000;
    sierra_ds_smem_write_bad_image_and_swap(bad_image_mask);
  }
  return;
}
#endif /* SIERRA_DUAL_SYSTEM_TEST */

/************
 *
 * Name:     sierra_ds_update_ssdata
 *
 * Purpose:  Update ds_flag to ssdata, sync it to SM
 *
 * Parms:   in - ds_flag
 *          out - swapreset
 * Return:   TRUE when Done
 *           FALSE when Failed
 *              
 * Abort:    None
 *
 * Notes:   
 *     
 *
 *
 ************/
void sierra_ds_update_ssdata(struct ds_flag_s *ds_flag, bool *swapreset)
{
  struct ds_smem_message_s * ds_smem_bufp = NULL;
  bool sw_update_state_to_normal = TRUE; 

  ASSERT(ds_flag);

  /* sync it to SM */
  ds_smem_bufp = sierra_ds_smem_get_address();
  if(NULL == ds_smem_bufp)
  {
    dprintf(CRITICAL, "sierra_ds_update_ssdata(): Can't get DS SMEM region\n");
    /* SM excetpion, so we should consider a "swapreset", to recover the exception */
    if (swapreset)
    {
      *swapreset = TRUE;
    }
  }
  else
  {
    if ((ds_smem_bufp->ssid_modem_idx != ds_flag->ssid_modem_idx) ||
        (ds_smem_bufp->ssid_lk_idx != ds_flag->ssid_lk_idx) ||
        (ds_smem_bufp->ssid_linux_idx != ds_flag->ssid_linux_idx))
    {
      if (swapreset)
      {
        *swapreset = TRUE;
      }
    }
    else
    {
      if (swapreset)
      {
        *swapreset = FALSE;
      }
    }

    /* Swap reason in smem indicate the system last swap reason.
     * It is always newer than the flag in flash.
     * So it should not be updated from flash but sync to flash.
     */
    ds_smem_bufp->magic_beg = DS_MAGIC_NUMBER;
    ds_smem_bufp->ssid_modem_idx = ds_flag->ssid_modem_idx;
    ds_smem_bufp->ssid_lk_idx = ds_flag->ssid_lk_idx;
    ds_smem_bufp->ssid_linux_idx = ds_flag->ssid_linux_idx;
    ds_smem_bufp->is_changed = DS_BOOT_UP_CHANGED;
    ds_smem_bufp->bad_image = ds_flag->bad_image;
    ds_smem_bufp->swap_reason = DS_SWAP_REASON_NONE;
    ds_smem_bufp->magic_end = DS_MAGIC_NUMBER;
    ds_smem_bufp->crc32 = crcrc32((uint8 *)ds_smem_bufp, sizeof(struct ds_smem_message_s) - sizeof(uint32), CRSTART_CRC32);
  }

  /* Try to recover sw_update_state to normal */
  if (ds_flag->ssid_modem_idx == DS_SSID_SUB_SYSTEM_1)
  {
    if (!(ds_flag->bad_image & DS_IMAGE_TZ_1) && 
          !(ds_flag->bad_image & DS_IMAGE_RPM_1) && 
          !(ds_flag->bad_image & DS_IMAGE_MODEM_1))
    {
      /* Do nothing */
    }
    else
    {
      sw_update_state_to_normal = FALSE;
    }
  }
  else
  {
    if (!(ds_flag->bad_image & DS_IMAGE_TZ_2) && 
          !(ds_flag->bad_image & DS_IMAGE_RPM_2) && 
          !(ds_flag->bad_image & DS_IMAGE_MODEM_2))
    {
      /* Do nothing */
    }
    else
    {
      sw_update_state_to_normal = FALSE;
    }
  }

  if (ds_flag->ssid_lk_idx == DS_SSID_SUB_SYSTEM_1)
  {
    if (!(ds_flag->bad_image & DS_IMAGE_ABOOT_1))
    {
      /* Do nothing */
    }
    else
    {
      sw_update_state_to_normal = FALSE;
    }
  }
  else
  {
    if (!(ds_flag->bad_image & DS_IMAGE_ABOOT_2))
    {
      /* Do nothing */
    }
    else
    {
      sw_update_state_to_normal = FALSE;
    }
  }

  if (ds_flag->ssid_linux_idx == DS_SSID_SUB_SYSTEM_1)
  {
    if (!(ds_flag->bad_image & DS_IMAGE_BOOT_1) && 
          !(ds_flag->bad_image & DS_IMAGE_SYSTEM_1) && 
          !(ds_flag->bad_image & DS_IMAGE_USERDATA_1))
    {
      /* Do nothing */
    }
    else
    {
      sw_update_state_to_normal = FALSE;
    }
  }
  else
  {
    if (!(ds_flag->bad_image & DS_IMAGE_BOOT_2) && 
          !(ds_flag->bad_image & DS_IMAGE_SYSTEM_2) && 
          !(ds_flag->bad_image & DS_IMAGE_USERDATA_2))
    {
      /* Do nothing */
    }
    else
    {
      sw_update_state_to_normal = FALSE;
    }
  }

  if (sw_update_state_to_normal)
  {
    ds_flag->sw_update_state = DS_SW_UPDATE_STATE_NORMAL;
  }
  
  /* Update ds_flag to ssdata */
  sierra_ds_set_new_data(ds_flag);
  
  return;
}

/************
 *
 * Name:     sierra_ds_set_ssid
 *
 * Purpose:  Set ssid in LK
 *
 * Parms:   in - ssid_modem_idx
 *          in - ssid_lk_idx
 *          in - ssid_linux_idx
 *          out - swapreset
 *
 * Return:   TRUE when Done
 *               FALSE when Failed
 *              
 * Abort:    None
 *
 * Notes:   
 *     
 *
 *
 ************/
bool sierra_ds_set_ssid(uint8 ssid_modem_idx, uint8 ssid_lk_idx, uint8 ssid_linux_idx, bool *swapreset)
{
  struct ds_flag_s ds_flag;

  if (((ssid_modem_idx < DS_SSID_SUB_SYSTEM_1) || (ssid_modem_idx > DS_SSID_SUB_SYSTEM_2)) ||
  ((ssid_lk_idx < DS_SSID_SUB_SYSTEM_1) || (ssid_lk_idx > DS_SSID_SUB_SYSTEM_2)) ||
  ((ssid_linux_idx < DS_SSID_SUB_SYSTEM_1) || (ssid_linux_idx > DS_SSID_SUB_SYSTEM_2)))
  {
    /* Bad SSIDs */
    if (swapreset)
    {
      *swapreset = FALSE;
    }

    dprintf(CRITICAL, "sierra_ds_set_ssid(): SSID out of range \n");

    return FALSE;
  }
  else
  {
    sierra_ds_get_full_data(&ds_flag);
    ds_flag.ssid_modem_idx = ssid_modem_idx;
    ds_flag.ssid_lk_idx = ssid_lk_idx;
    ds_flag.ssid_linux_idx = ssid_linux_idx;
    sierra_ds_update_ssdata(&ds_flag, swapreset);
    /* set reset type to BS_BCMSG_RTYPE_SYSTEM_SWAP */
    sierra_smem_reset_type_set(BS_BCMSG_RTYPE_SYSTEM_SWAP);
    return TRUE;
  }
}

/************
 *
 * Name:     sierra_ds_smem_get
 *
 * Purpose:  Get dual system infomation from sierra smem
 *
 * Parms:   ds_smem_bufp dual system infomation buffer pointer
 *
 * Return:   None
 *
 * Abort:    None
 *
 * Notes:   None
 *
 ************/
void sierra_ds_smem_get(
  struct ds_smem_message_s * ds_infop)
{
  struct ds_smem_message_s * ds_smem_bufp;

  sierra_ds_smem_init(ds_infop);

  /* Get DS SMEM region */
  ds_smem_bufp = sierra_ds_smem_get_address();
  if (NULL == ds_smem_bufp)
  {
    dprintf(CRITICAL, "sierra_ds_smem_get(): Can't get DS SMEM region\n");
    return;
  }

  /* Make sure it is valid DS SMEM */
  if (sierra_ds_smem_is_valid(ds_smem_bufp))
  {
    memcpy((void *)ds_infop, (void *)ds_smem_bufp, sizeof(struct ds_smem_message_s));
  }

  return;
}

/************
 *
 * Name:     sierra_ds_smem_erestore_info_get
 *
 * Purpose:  Set efs restore_info in share memory
 *
 * Parms:    [[OUT]efs_restore_infop - efs restore info buffer
 *
 * Return:   None
 *
 * Abort:    None
 *
 * Notes:    None
 *
 ************/
void sierra_ds_smem_erestore_info_get(struct ds_smem_erestore_info *efs_restore_infop)
{
  struct ds_smem_erestore_info *efs_restore = NULL;
  unsigned char *virtual_addr = NULL;

  virtual_addr = sierra_smem_base_addr_get();
  if (NULL != virtual_addr)
  {
    /* Get EFS restore SMEM base address */
    virtual_addr += BSMEM_EFS_RESTORE_OFFSET;
    efs_restore = (struct ds_smem_erestore_info *)virtual_addr;

    /* Check if data in smem valid */
    if ((DS_MAGIC_EFSB == efs_restore->magic_beg) &&
       (DS_MAGIC_EFSE == efs_restore->magic_end) &&
       (crcrc32((void *)efs_restore, DS_ERESTORE_CRC_SZ, CRSTART_CRC32) == efs_restore->crc32))
    {
      /* Initalize the BS_SMEM_REGION_EFS_RESTORE.
       * If cold-reset or smem-destroyed happend, initialize the region in defalt.
       */
      memcpy((void *)efs_restore_infop, (void *)efs_restore, sizeof(struct ds_smem_erestore_info));
      return;
    }
  }

  /* Initalize the BS_SMEM_REGION_EFS_RESTORE.
  * If cold-reset or smem-destroyed happend, initialize the region in defalt.
  */
  efs_restore_infop->erestore_t         = BL_RESTORE_INFO_INVALID_VALUE;
  efs_restore_infop->errorcount         = BL_RESTORE_INFO_INVALID_VALUE;
  efs_restore_infop->restored_flag      = BL_RESTORE_INFO_INVALID_VALUE;
  efs_restore_infop->beroption          = BL_RESTORE_INFO_INVALID_VALUE;

  return;
}


