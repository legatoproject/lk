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
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name of The Linux Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
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
 ************/

#ifndef spiudefs_h
#define spiudefs_h

#include <sys/types.h>

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
