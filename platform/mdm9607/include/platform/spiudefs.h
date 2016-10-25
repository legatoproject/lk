/************
 *
 * $Id$
 *
 * Filename:  spiudefs.h
 *
 * Purpose:   user definitions for SPI driver package
 *
 * Copyright: (c) 2009 Sierra Wireless, Inc.
 *            All rights reserved
 *
 ************/

#ifndef spiudefs_h
#define spiudefs_h

#include <stdint.h>


uint8_t spi_init(void);
int spi_write(unsigned char *wbuf, int buf_len);
int spi_read(unsigned char *rbuf, int buf_len);
uint8_t spi_read_write(unsigned char *wbuf, int *wbuf_len, unsigned char *rbuf, int *rbuf_len);




#endif
