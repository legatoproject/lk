LOCAL_DIR := $(GET_LOCAL_DIR)

INCLUDES += -I$(LK_TOP_DIR)/platform/msm_shared/include

DEFINES += ASSERT_ON_TAMPER=1

OBJS += \
	$(LOCAL_DIR)/aboot.o \
	$(LOCAL_DIR)/fastboot.o \
	$(LOCAL_DIR)/recovery.o

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
	$(LOCAL_DIR)/sierra_bl.o
# SWISTOP
