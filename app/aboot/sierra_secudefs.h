/************
 *
 * Filename:  sierra_secudefs.h
 *
 * Purpose:   external definitions for secboot package
 *
 * NOTES:
 *
 * Copyright: (C) 2017 Sierra Wireless, Inc.
 *            All rights reserved
 *
 ************/
#ifndef SIERRA_SECUDEFS_H
#define SIERRA_SECUDEFS_H

extern uint8_t *sierra_sec_oem_cert_hash_get(void);
extern boolean sierra_sec_oem_cert_compare(uint8_t *certp);

#endif

