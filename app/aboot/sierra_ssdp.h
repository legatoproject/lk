/************
 *
 * Filename:  sierra_ssdp.h
 *
 * Purpose:   external definitions for sierra ssdp package
 *
 * NOTES:
 *
 * Copyright (C) 2015 Sierra Wireless, Inc.
 *
 ************/

#ifndef sierra_ssdp_h
#define sierra_ssdp_h

/* Constants and enumerated types */


/************
 *
 * Name:     swi_ssdp_entry
 *
 * Purpose:
 * This function initializes for the SPI boot feature and calls
 * the downloader function which will spin in a loop processing the
 * downloaded images received over SPI.
 * Received image will be store at ADDR:
 *
 * Params:   none
 *
 * Return:   none
 *
 * Abort:    none
 *
 * Notes:
 *
 ************/
void swi_ssdp_entry(void);

#endif /* sierra_ssdp_h */

