#Makefile to generate appsboot.mbn

ifeq ($(BOOTLOADER_OUT),.)
APPSBOOTOUT_DIR  := $(BUILDDIR)
else
APPSBOOTOUT_DIR := $(BOOTLOADER_OUT)/../..
endif

ABOOTMBN := appsboot.mbn
# SWISTART
ABOOTRAW = appsboot.raw
ifeq ($(ROOTFS_RW),true)
ABOOTMBN = appsboot_rw.mbn
ABOOTRAW = appsboot_rw.raw

ifeq ($(IMA_ENFORCE),true)
ABOOTMBN = appsboot_rw_ima.mbn
ABOOTRAW = appsboot_rw_ima.raw
endif

endif
# SWISTOP
APPSBOOTHEADER: $(ABOOTMBN)

$(ABOOTMBN): $(OUTELF_STRIP) $(OUTBIN)
	cp $(OUTBIN) $(APPSBOOTOUT_DIR)/$(ABOOTRAW)
	$(hide) cp -f $(OUTELF_STRIP) $(APPSBOOTOUT_DIR)/$(ABOOTMBN)
