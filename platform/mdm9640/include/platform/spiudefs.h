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

typedef  unsigned char      boolean;     /* Boolean value type. */

#ifndef TRUE
#define TRUE   1   /* Boolean true value. */
#endif

#ifndef FALSE
#define FALSE  0   /* Boolean false value. */
#endif

boolean spi_init(void);
int spi_write(unsigned char *wbuf, int buf_len);
int spi_read(unsigned char *rbuf, int buf_len);
boolean spi_read_write(unsigned char *wbuf, int *wbuf_len, unsigned char *rbuf, int *rbuf_len);




#endif
