/************
 *
 * Filename:  dsidefs.h
 *
 * Purpose:   Internal definitions for DS package
 *
 * Copyright: (c) 2016 Sierra Wireless, Inc.
 *            All rights reserved
 *
 ************/
#ifndef SIERRA_DS_H
#define SIERRA_DS_H

/* Include files */
#include "sierra_cweudefs.h"

/* Constants and enumerated types */
//#define SIERRA_DUAL_SYSTEM_TEST  /* Only used for internal test */

/* Default value for flags */
#define DS_MAX_EVT_BUFS              8          /* Max number of queued event requests    */
#define DS_MAX_PAGE_SIZE             4096       /* Support 2K page and 4K page */
#define DSSD_MAX_BLOCK_NUM           24         /* DSSD partition is 3MB, max block number is 24 with 2K page */
#define DSSD_MAX_DATA_BLOCK          2          /* Only 2 blocks store valid data  */
#define DS_PAGE_SERACH_NOT_START     0xFFFFFFFF /* A invalid value for page_no not start to search */
#define DS_DATA_BLOCK_ERASED         0x66726565 /* "free" */
#define DS_NO_FREE_BLOCK             (-1)       /* All block are bad blocks in the partition, should not be happened */

#define BL_SSDATA_PARTI_NAME "ssdata"           /* Dual system shared data(DSSD) */

/************
 *
 * Name:     ds_event_e
 *
 * Purpose:  Defines events of ds task
 *
 * Members:  See below
 *
 * Notes:    None
 *
 ************/
enum ds_event_e
{
  DS_EVENT_MIN = 0,    /* Internal use only           */
  DS_EVENT_READ,
  DS_EVENT_WRITE,
  DS_EVENT_MAX,        /* Internal use only           */
};

/************
 *
 * Name:     ds_sw_update_state_e
 *
 * Purpose:  To enumerate all DS SW update states
 *
 * Notes:    None
 *
 ************/
enum ds_sw_update_state_e
{
  DS_SW_UPDATE_STATE_MIN = 1,
  DS_SW_UPDATE_STATE_NORMAL = DS_SW_UPDATE_STATE_MIN,            /* Normal state */
  DS_SW_UPDATE_STATE_SYNC,                                       /* Sync between active system and inactive system */
  DS_SW_UPDATE_STATE_SWAP_SYNC,                                  /* Sync and swap */
  DS_SW_UPDATE_STATE_RECOVERY_PHASE_1,                           /* SW recovery phase 1 */
  DS_SW_UPDATE_STATE_RECOVERY_PHASE_2,                           /* SW recovery phase 2 */
  DS_SW_UPDATE_STATE_MAX = DS_SW_UPDATE_STATE_RECOVERY_PHASE_2,  /* End */
};

/* Structures */
/************
 *
 * Name:     ds_flags_s
 *
 * Purpose:  Only flag part
 *
 * Notes:    
 *   1. It is different with ds_shared_data_s. 
 *   2. It is necesary to be sync with ds_shared_data_s.
 *
 ************/
struct ds_flag_s
{
  uint32  boot_system;           /* Boot system flag */
  uint32  swap_reason;           /* Dual system swap reasons */
  uint32  out_of_sync;           /* Out of sync flag */
  uint32  sw_update_state;       /* SW update state */
  uint64  updated_image;         /* Record updated images */
  uint64  bad_image;             /* Record bad images */
  uint64  refresh_image;         /* Record images which need to do refresh */
};

/************
 *
 * Name:     ds_shared_data_s
 *
 * Purpose:  Dual system shared data structure
 *
 * Notes:    None
 *
 ************/
struct ds_shared_data_s
{
  uint32  magic_beg;             /* Magic begin flag */
  uint32  boot_system;           /* Boot system flag */
  uint32  swap_reason;           /* Dual system swap reasons */
  uint32  out_of_sync;           /* Out of sync flag */
  uint64  updated_image;         /* Record updated images */
  uint64  bad_image;             /* Record bad images */
  uint64  refresh_image;         /* Record images which need to do refresh */
  uint32  sw_update_state;       /* SW update state */
  uint32  reserved;              /* Add it in order to keep 8 bytes align */
  uint32  magic_end;             /* Magic ending flag */
  uint32  crc32;                 /* CRC value */
};

extern bool sierra_ds_check_if_out_of_sync(void);
extern bool sierra_ds_write_flags_in_lk(
  uint32 sw_update_state,
  uint32 out_of_sync,
  uint64 updated_image,
  uint64 bad_image);
extern uint32 sierra_ds_smem_get_boot_system(void);
extern void sierra_ds_smem_write_bad_image_and_swap(uint64 bad_image_mask);
#ifdef SIERRA_DUAL_SYSTEM_TEST
extern void sierra_ds_test(const char *arg);
#endif /* SIERRA_DUAL_SYSTEM_TEST */

#endif /* SIERRA_DS_H */

