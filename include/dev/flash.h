/*
 * Copyright (c) 2014-2015, The Linux Foundation. All rights reserved.
 * Copyright (c) 2008, Google Inc.
 * All rights reserved.
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
 */


#ifndef __DEV_FLASH_H
#define __DEV_FLASH_H

#include <lib/ptable.h>

/* SWISTART */
#ifdef SIERRA
#define FLASH_PAGE_SIZE_2K	0x800
#define FLASH_PAGE_SIZE_4K	0x1000

#define LEB_SIZE_2K	(62*FLASH_PAGE_SIZE_2K)
#define LEB_SIZE_4K	(62*FLASH_PAGE_SIZE_4K)

#define BLOCK_SIZE_2K	(64*FLASH_PAGE_SIZE_2K)
#define BLOCK_SIZE_4K	(64*FLASH_PAGE_SIZE_4K)

#define CONVERTED_IMG_MEM_OFFSET (80*1024*1024)

#define ADD_PADDING_2048(pos) (FLASH_PAGE_SIZE_2K - ((pos) % FLASH_PAGE_SIZE_2K))
#define ADD_PADDING_4096(pos) (FLASH_PAGE_SIZE_4K - ((pos) % FLASH_PAGE_SIZE_4K))
#endif
/* SWISTOP */

enum nand_ecc_width
{
	NAND_WITH_4_BIT_ECC,
	NAND_WITH_8_BIT_ECC,
};

struct flash_info {
	unsigned id;
	unsigned id2;
	unsigned type;
	unsigned vendor;
	unsigned device;
	unsigned page_size;
	unsigned block_size;
	unsigned spare_size;
	unsigned num_blocks;
	enum nand_ecc_width ecc_width;
	unsigned num_pages_per_blk;
	unsigned num_pages_per_blk_mask;
	unsigned widebus;
	unsigned density;
	unsigned cw_size;
	unsigned cws_per_page;
	unsigned bad_blk_loc;
	unsigned blksize;
	unsigned dev_cfg;
};

void flash_init(void);
struct ptable *flash_get_ptable(void);
void flash_set_ptable(struct ptable *ptable);
struct flash_info *flash_get_info(void);

/* flash operations */
int flash_erase(struct ptentry *ptn);
int flash_read_ext(struct ptentry *ptn, unsigned extra_per_page,
		   unsigned offset, void *data, unsigned bytes);
int flash_write(struct ptentry *ptn, unsigned write_extra_bytes, const void *data,
		unsigned bytes);
/* SWISTART */
#ifdef SIERRA
typedef unsigned int (*go_cwe_file_func_type)(unsigned char *buf, unsigned int len);

int flash_write_sierra(struct ptentry *ptn, unsigned write_extra_bytes, const void *data,
		unsigned bytes);
int flash_write_sierra_dual_tz_rpm(struct ptentry *ptn,
			void *data,
			unsigned bytes);
int flash_write_sierra_file_img(struct ptentry *ptn,
			unsigned write_extra_bytes,
			const void *data,
			unsigned bytes,
			go_cwe_file_func_type gocwe);
#endif
/* SWISTOP */

static inline int flash_read(struct ptentry *ptn, unsigned offset, void *data,
			     unsigned bytes)
{
	return flash_read_ext(ptn, 0, offset, data, bytes);
}
unsigned flash_page_size(void);
unsigned flash_block_size(void);
unsigned flash_spare_size(void);
int flash_ecc_bch_enabled(void);


#endif /* __DEV_FLASH_H */
