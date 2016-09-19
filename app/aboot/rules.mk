LOCAL_DIR := $(GET_LOCAL_DIR)

INCLUDES += -I$(LK_TOP_DIR)/platform/msm_shared/include -I$(LK_TOP_DIR)/lib/zlib_inflate

DEFINES += ASSERT_ON_TAMPER=1

MODULES += lib/zlib_inflate

OBJS += \
	$(LOCAL_DIR)/aboot.o \
	$(LOCAL_DIR)/fastboot.o \
	$(LOCAL_DIR)/recovery.o

ifeq ($(ENABLE_UNITTEST_FW), 1)
OBJS += \
	$(LOCAL_DIR)/fastboot_test.o
	ifeq ($(ENABLE_MDTP_SUPPORT),1)
		OBJS += \
			$(LOCAL_DIR)/mdtp_lk_ut.o
	endif
endif

ifeq ($(ENABLE_MDTP_SUPPORT),1)
OBJS += \
	$(LOCAL_DIR)/mdtp.o \
	$(LOCAL_DIR)/mdtp_ui.o \
	$(LOCAL_DIR)/mdtp_fuse.o \
	$(LOCAL_DIR)/mdtp_defs.o \
	$(LOCAL_DIR)/mdtp_fs.o
endif

# SWISTART 
ifndef LINUX_KERNEL_DIR
  ifdef WORKSPACE
    LINUX_KERNEL_DIR="$(WORKSPACE)/../../kernel"
  else
    $(error "LINUX_KERNEL_DIR needs to point to kernel sources")
  endif
endif

INCLUDES += -I${LINUX_KERNEL_DIR}/arch/arm/mach-msm/include

OBJS += \
	$(LOCAL_DIR)/sierra_cwe.o \
	$(LOCAL_DIR)/sierra_ds.o \
	$(LOCAL_DIR)/sierra_bl.o
# SWISTOP
