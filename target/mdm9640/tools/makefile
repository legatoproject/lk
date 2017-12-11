#Makefile to generate appsboot.mbn

APPSBOOTOUT_DIR := $(BUILDDIR)

ABOOTMBN := appsboot.mbn
# SWISTART
ABOOTRAW = appsboot.raw
ifeq ($(ROOTFS_RW),true)
ABOOTMBN = appsboot_rw.mbn
ABOOTRAW = appsboot_rw.raw
endif
# SWISTOP
APPSBOOTHEADER: $(ABOOTMBN)

$(ABOOTMBN): $(OUTELF_STRIP)
	cp $(OUTBIN) $(APPSBOOTOUT_DIR)/$(ABOOTRAW)
	$(hide) cp -f $(OUTELF_STRIP) $(APPSBOOTOUT_DIR)/$(ABOOTMBN)
