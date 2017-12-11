/************
 *
 * Filename:  sierra_swipartudefs.h
 *
 * Purpose:   external definitions for sierra swipart package
 *
 * NOTES:
 *
 * Copyright: (C) 2015 Sierra Wireless, Inc.
 *            All rights reserved
 *
 ************/
#ifndef sierra_swipartudefs_h
#define sierra_swipartudefs_h

/* Prototypes */


/* SWI Partition methods */
_global boolean swipart_block_program(
  struct ptentry *fs_devicep,
  unsigned int blockno,
  unsigned int pageno,
  uint8_t *imagep,
  unsigned int imagesize,
  boolean program_backward);

uint32 swipart_findsbl(
  struct ptentry *trans_ifp,
  uint8 * scratch_bufp,
  uint32 scratch_buflen);

#endif /* sierra_swipartudefs_h */

