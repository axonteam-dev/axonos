# Split syscall layout (syscall/core, syscall/dispatch, …). Read before makefile.
include makefile

override CFLAGS += -Isyscall/internal

FIND_PRUNE := -path './build' -prune -o \
	-path './iso' -prune -o \
	-path './third_party' -prune -o \
	-path './tools' -prune -o \
	-path './userland' -prune -o \
	-path './core/nss_dns_shim' -prune -o \
	-path './core/nss_files_shim' -prune -o \
	-path './syscall64' -prune -o \
	-path './syscall64_split' -prune -o

CSRCS := $(shell find . $(FIND_PRUNE) -type f -name '*.c' -print | sed 's|^\./||')
COBJS := $(patsubst %.c,$(BUILD_DIR)/%.c.o,$(CSRCS))

SSRCS := $(shell find . $(FIND_PRUNE) -type f -name '*.S' -print | sed 's|^\./||')
SOBJS := $(patsubst %.S,$(BUILD_DIR)/%.S.o,$(SSRCS))

PAYLOAD_COBJS := $(filter-out $(STUB_OBJ),$(COBJS))

# Legacy syscall64/ on disk confuses make's implicit rules; drop stale objects.
$(shell rm -rf $(BUILD_DIR)/syscall64 2>/dev/null)

$(PAYLOAD_ELF): $(OTHER_ASM_OBJS) $(SOBJS) $(AP_TRAMP_OBJ) $(NSS_DNS_BLOB_OBJ) $(NSS_FILES_BLOB_OBJ) $(CA_TRUST_BLOB_OBJ) $(ASCII_PF2_BLOB_OBJ) $(PAYLOAD_COBJS)
	@mkdir -p $(BUILD_DIR)
	@echo "LD		$@"
	@ld -m elf_x86_64 -T linker.payload.ld -o $@ $(OTHER_ASM_OBJS) $(SOBJS) $(AP_TRAMP_OBJ) $(NSS_DNS_BLOB_OBJ) $(NSS_FILES_BLOB_OBJ) $(CA_TRUST_BLOB_OBJ) $(ASCII_PF2_BLOB_OBJ) $(PAYLOAD_COBJS)

