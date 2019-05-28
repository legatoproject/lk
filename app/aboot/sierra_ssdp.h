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

/**
 * NOTICE: For don't have copyright of SSDP, so we have to deliver SSDP stack as a lib.
 *
 * Step to generate libswissdp.a:
 * 1, Integrate modem_proc/sierra/ssdp/patch_mk_ssdp_lk_lib patch to /mdm9x28/apps_proc
 * 2, Go to root path of project.
 * 3, Run command:
 *  source poky/oe-init-build-env build_src
 *  bitbake -c cleanall lk
 *  bitbake lk
 * 4, Get libswissdp.a in path:
 *  \build_src\tmp\work\armv7a-vfp-neon-poky-linux-gnueabi\lk\1.3.0-r2\build\build-mdm9640\lib\libswi\libswissdp.a
 **/

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
 *
 ************/
void swi_ssdp_entry(void);

#endif /* sierra_ssdp_h */

