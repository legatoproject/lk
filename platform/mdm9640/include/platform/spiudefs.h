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


boolean spi_init(void);
void spi_init_ex(boolean use_pid);
void spi_shutdown(void);
int spi_write(unsigned char *wbuf, int buf_len);
int spi_read(unsigned char *rbuf, int buf_len);
void spi_drain(void);
void spi_drain_timeout(uint32 timeout);
int spi_receive_byte(void);
void spi_transmit_byte(unsigned char data);
uint32 spi_receive_pkt(unsigned char **buf);
void spi_transmit_pkt (unsigned char *pkt, uint32 len);
boolean spi_read_write(unsigned char *wbuf, int *wbuf_len, unsigned char *rbuf, int *rbuf_len);




#endif
