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
  uint8   ssid_modem_idx;                 /* SSID modem index flag */
  uint8   ssid_lk_idx;                    /* SSID LK index flag */
  uint8   ssid_linux_idx;                 /* SSID Linux index flag */
  uint8   reserved_8bits;                 /* Reserved for 8 bytes align */
  uint32  swap_reason;                    /* Dual system swap reasons */
  uint32  sw_update_state;                /* SW update state */
  uint32  out_of_sync;                    /* Out of sync flag */
  uint32  efs_corruption_in_sw_update;    /* EFS corruption in SW update flag */
  uint32  edb_in_sw_update;               /* EDB in SW update flag */
  uint64  bad_image;                      /* Bad image mask */
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
  uint32  magic_beg;                      /* Magic begin flag */
  uint8   ssid_modem_idx;                 /* SSID modem index flag */
  uint8   ssid_lk_idx;                    /* SSID LK index flag */
  uint8   ssid_linux_idx;                 /* SSID Linux index flag */
  uint8   reserved_8bits;                 /* Reserved for 8 bytes align */
  uint32  reserved_32bits;                /* Reserved for 8 bytes align */
  uint32  swap_reason;                    /* Dual system swap reasons */
  uint32  sw_update_state;                /* SW update state */
  uint32  out_of_sync;                    /* Out of sync flag */
  uint32  efs_corruption_in_sw_update;    /* EFS corruption in SW update flag */
  uint32  edb_in_sw_update;               /* EDB in SW update flag */
  uint64  bad_image;                      /* Bad image mask */
  uint32  magic_end;                      /* Magic ending flag */
  uint32  crc32;                          /* CRC value */
};

/* Information for EFS restore
*
* 1. The ds_efs_restore_type is the type of the EFS restore.
*   1.1, EFS sanity restore:
*     1.1.1, No need to restore for mirror systerm, should restore for non-mirror systerm.
*     1.1.2, The 4 efs sanity-restore types just be used to distinguish different efs restore requests from LK/KERNEL/SBL, etc.
*     1.1.3, DS_RESTORE_EFS_SANITY request efs restore for 6 times abnormal reset or other reasons lead to system swap. Need to swap system and restore efs.
*     1.1.4, DS_RESTORE_EFS_SANITY_FROM_LK request DS_RESTORE_EFS_SANITY for bad image detected in lk. Need to swap system and restore efs.
*     1.1.5, DS_RESTORE_EFS_SANITY_FROM_KERNEL request DS_RESTORE_EFS_SANITY for bad image detected in kernel. Need to swap system and restore efs.
*     1.1.6, DS_RESTORE_EFS_SANITY_FROM_SBL request DS_RESTORE_EFS_SANITY for bad image detected in sbl. Need to swap system and restore efs.
*   1.2, DS_RESTORE_EFS_ANYWAY:
*     1.2.1, Should restore efs no matter mirror/non-mirror systerm.
*
* 2. The ds_smem_erestore_info is used to store EFS restore info.
*/
#define DS_MAGIC_EFSB                       0x45465342  /* "EFSB" */
#define DS_MAGIC_EFSE                       0x45465345  /* "EFSE" */
enum ds_efs_restore_type
{
  DS_RESTORE_EFS_TYPE_MIN,
  DS_RESTORE_EFS_SANITY             = 1,    /* restore efs sanity, request for 6 times abnormal reset */
  DS_RESTORE_EFS_ANYWAY             = 2,    /* restore efs anyway */
  DS_RESTORE_EFS_SANITY_FROM_LK     = 3,    /* restore efs sanity, request from lk */
  DS_RESTORE_EFS_SANITY_FROM_KERNEL = 4,    /* restore efs sanity, request from kernel */
  DS_RESTORE_EFS_SANITY_FROM_SBL    = 5,    /* restore efs sanity, request from sbl */
  DS_RESTORE_EFS_TYPE_MAX,
};

enum bl_erestore_info_type
{
  BL_RESTORE_INFO_MIN = 1,
  BL_RESTORE_INFO_ECOUNT_BUF= BL_RESTORE_INFO_MIN,
  BL_RESTORE_INFO_RESTORE_DONE,
  BL_RESTORE_INFO_RESTORE_TYPE,
  BL_RESTORE_INFO_MAX = BL_RESTORE_INFO_RESTORE_TYPE,
};

struct ds_smem_erestore_info
{
  uint32  magic_beg;             /* Magic begin flag */
  uint8   erestore_t;            /* EFS restore type */
  uint8   errorcount;            /* backup errorcount */
  uint8   restored_flag;         /* efs-restore last booting */
  uint8   reserved;              /* reserved 8 bits */
  uint32  magic_end;             /* Magic ending flag */
  uint32  crc32;                 /* CRC32 of above fields */
};

#define BL_RESTORE_INFO_RESTORED 0x01
#define BL_RESTORE_INFO_INVALID_VALUE 0xFF
#define DS_ERESTORE_CRC_SZ (sizeof(struct ds_smem_erestore_info) - sizeof(uint32))

extern bool sierra_ds_check_if_out_of_sync(void);
extern bool sierra_ds_check_if_ds_is_sync(void);
extern bool sierra_ds_check_is_recovery_phase1(void);
extern bool sierra_ds_check_is_recovery_phase2(void);
extern bool sierra_ds_write_flags_in_lk(
  uint32 sw_update_state,
  uint32 out_of_sync,
  uint64 bad_image);
extern uint8 sierra_ds_smem_get_ssid_linux_index(void);
extern void sierra_ds_smem_write_bad_image_and_swap(uint64 bad_image_mask);
#ifdef SIERRA_DUAL_SYSTEM_TEST
extern void sierra_ds_test(const char *arg);
#endif /* SIERRA_DUAL_SYSTEM_TEST */

extern bool sierra_ds_get_full_data(struct ds_flag_s *ds_flag);
extern bool  sierra_ds_set_ssid(uint8 ssid_modem_idx, uint8 ssid_lk_idx, uint8 ssid_linux_idx, bool *swapreset);
extern void sierra_ds_update_ssdata(struct ds_flag_s *ds_flag, bool *swapreset);

#endif /* SIERRA_DS_H */

