SHELL := /bin/bash

ASM := nasm
ASM_ELF_FLAGS := -f elf64
ASM_BIN_FLAGS := -f bin
BUILD_DIR := build
ISO_DIR := iso
ISO_BOOT := $(ISO_DIR)/boot
GRUB_DIR := $(ISO_BOOT)/grub
KERNEL_SRC := kernel.asm
KERNEL_OBJ := $(BUILD_DIR)/kernel.o
KERNEL_ELF := $(BUILD_DIR)/axonos.elf
PAYLOAD_ELF := $(BUILD_DIR)/axonos.payload.elf
PAYLOAD_LZ4 := $(BUILD_DIR)/payload.lz4
PAYLOAD_BLOB_OBJ := $(BUILD_DIR)/payload_blob.o
PAYLOAD_LZ4_SYM := $(subst -,_,$(subst .,_,$(subst /,_,$(PAYLOAD_LZ4))))
KERNEL_BIN := $(BUILD_DIR)/kernel.bin
MULTIBOOT_SRC := multiboot.asm
MULTIBOOT_OBJ := $(BUILD_DIR)/multiboot.o
MULTIBOOT_BIN := $(BUILD_DIR)/multiboot.bin
ISO_IMAGE := $(BUILD_DIR)/axonos.iso
STUB_SRC := boot/kzip_stub.c
STUB_OBJ := $(BUILD_DIR)/$(STUB_SRC:.c=.c.o)

# Linux-style kernel config (config.cfg → auto.conf + autoconf.h)
CONFIG_FILE ?= config.cfg
GENCONFIG := scripts/genconfig.sh
AUTOCONF_DIR := $(BUILD_DIR)/include
AUTO_CONF := $(AUTOCONF_DIR)/config/auto.conf
AUTOCONF_H := $(AUTOCONF_DIR)/generated/autoconf.h

# Sync auto.conf to CONFIG_FILE before -include (handles for-production switch).
$(shell mkdir -p $(AUTOCONF_DIR)/config $(AUTOCONF_DIR)/generated && \
	$(GENCONFIG) $(CONFIG_FILE) $(AUTOCONF_DIR) >/dev/null)
-include $(AUTO_CONF)

# y and m both mean "enabled / linked in" until real modules exist.
config_enabled = $(filter y m,$(1))

CC := gcc -m64
# Optional: make CFLAGS_EXTRA='-DDEVEL_DEBUG=1' still works as an override.
CFLAGS_EXTRA ?=
OPTFLAGS ?= -g
CFLAGS := $(OPTFLAGS) -ffreestanding -nostdlib -fno-builtin -fno-stack-protector -fno-pic -mno-red-zone -mcmodel=kernel \
	-Iinc -I$(AUTOCONF_DIR) -include kconfig.h -MMD -MP $(CFLAGS_EXTRA)

CSRCS := $(shell find . -path './build' -prune -o -path './iso' -prune -o -path './userland' -prune -o -path './core/nss_dns_shim' -prune -o -path './core/nss_files_shim' -prune -o -type f -name '*.c' -print | sed 's|^\./||')
COBJS := $(patsubst %.c,$(BUILD_DIR)/%.c.o,$(CSRCS))
DEPS := $(COBJS:.o=.d)

ASMSRCS := $(shell find . -path './build' -prune -o -path './iso' -prune -o -type f -name '*.asm' -print | sed 's|^\./||')
ASMOBJS := $(patsubst %.asm,$(BUILD_DIR)/%.asm.o,$(ASMSRCS))

# GAS (preprocessed) assembly sources
SSRCS := $(shell find . -path './build' -prune -o -path './iso' -prune -o -type f -name '*.S' -print | sed 's|^\./||')
SOBJS := $(patsubst %.S,$(BUILD_DIR)/%.S.o,$(SSRCS))

MULTIBOOT_SRC := $(shell find . -path './build' -prune -o -path './iso' -prune -o -type f -name 'multiboot.asm' -print | sed 's|^\./||')
MULTIBOOT_OBJ := $(if $(MULTIBOOT_SRC),$(BUILD_DIR)/$(MULTIBOOT_SRC:.asm=.asm.o),)
OTHER_ASM_OBJS := $(filter-out $(MULTIBOOT_OBJ) $(BUILD_DIR)/cpu/smp/ap_trampoline.asm.o,$(ASMOBJS))
PAYLOAD_COBJS := $(filter-out $(STUB_OBJ),$(COBJS))

AP_TRAMP_BIN := $(BUILD_DIR)/ap_trampoline.bin
AP_TRAMP_OBJ := $(BUILD_DIR)/ap_trampoline.bin.o
AP_TRAMP_BIN_SYM := $(subst -,_,$(subst .,_,$(subst /,_,$(AP_TRAMP_BIN))))

# Host-built glibc NSS shims; embedded into payload.
# Use a short path for ld -b binary so _binary_* symbols stay predictable; then
# rename via nm-discovered names (handles absolute $< paths / different linkers).
NSS_DNS_SHIM := $(BUILD_DIR)/nss_dns/shim
NSS_DNS_BLOB_OBJ := $(BUILD_DIR)/nss_dns/shim_blob.o
NSS_FILES_SHIM := $(BUILD_DIR)/nss_files/shim
NSS_FILES_BLOB_OBJ := $(BUILD_DIR)/nss_files/shim_blob.o
ASCII_PF2 := $(BUILD_DIR)/fonts/ascii.pf2
ASCII_PF2_BLOB_OBJ := $(BUILD_DIR)/fonts/ascii_pf2_blob.o
ASCII_PF2_SRC := $(firstword $(wildcard /usr/share/grub/ascii.pf2 /boot/grub/fonts/ascii.pf2))

.PHONY: all kernel iso clean run for-production config oldconfig

all: iso

# Regenerate autoconf when config.cfg changes (or on `make config`).
$(AUTO_CONF) $(AUTOCONF_H): $(CONFIG_FILE) $(GENCONFIG)
	@$(GENCONFIG) $(CONFIG_FILE) $(AUTOCONF_DIR)

config: $(AUTO_CONF)
	@echo "Active config: $(CONFIG_FILE)"
	@echo "  auto.conf:  $(AUTO_CONF)"
	@echo "  autoconf.h: $(AUTOCONF_H)"

for-production:
	@$(MAKE) CONFIG_FILE=config.production.cfg OPTFLAGS='-O0 -g0' iso

kernel: $(KERNEL_BIN)

$(BUILD_DIR)/%.asm.o: %.asm
	@mkdir -p $(dir $@)
	@echo "NASM		$<"
	@$(ASM) $(ASM_ELF_FLAGS) -o $@ $<

$(BUILD_DIR)/%.c.o: %.c $(AUTOCONF_H)
	@mkdir -p $(dir $@)
	@echo "CC		$<"
	@$(CC) $(CFLAGS) -c -o $@ $<

-include $(DEPS)

# Build rule for GAS .S files (with C preprocessor)
$(BUILD_DIR)/%.S.o: %.S $(AUTOCONF_H)
	@mkdir -p $(dir $@)
	@echo "CC		$<"
	@$(CC) $(CFLAGS) -c -o $@ $<

$(AP_TRAMP_BIN): cpu/smp/ap_trampoline.asm
	@mkdir -p $(dir $@)
	@echo "NASM(BIN)	$<"
	@$(ASM) $(ASM_BIN_FLAGS) -o $@ $<

$(AP_TRAMP_OBJ): $(AP_TRAMP_BIN)
	@echo "LD(BIN)	$<"
	@ld -r -b binary -o $@ $<
	@objcopy \
		--redefine-sym _binary_$(AP_TRAMP_BIN_SYM)_start=ap_trampoline_bin_start \
		--redefine-sym _binary_$(AP_TRAMP_BIN_SYM)_end=ap_trampoline_bin_end \
		"$@"

$(NSS_DNS_SHIM): core/nss_dns_shim/nss_dns.c
	@mkdir -p $(dir $@)
	@echo "HOST CC [nss_dns]	$<"
	@gcc -shared -fPIC -O2 -Wall -Wextra -Wl,-soname,libnss_dns.so.2 -o $@ $<

$(NSS_DNS_BLOB_OBJ): $(NSS_DNS_SHIM)
	@echo "LD(BIN) [nss_dns]	$<"
	@ld -r -b binary -o $@.tmp $< && \
	START=$$(nm $@.tmp | awk '$$3 ~ /^_binary_.*_start$$/ {print $$3; exit}') && \
	END=$$(nm $@.tmp | awk '$$3 ~ /^_binary_.*_end$$/ {print $$3; exit}') && \
	test -n "$$START" && test -n "$$END" && \
	objcopy --redefine-sym $$START=nss_dns_so_blob_start --redefine-sym $$END=nss_dns_so_blob_end $@.tmp $@ && \
	rm -f $@.tmp

# nostdlib — must not NEEDED libc.so.6 (static busybox dlopen).
$(NSS_FILES_SHIM): core/nss_files_shim/nss_files.c
	@mkdir -p $(dir $@)
	@echo "HOST CC [nss_files]	$<"
	@gcc -shared -fPIC -O2 -nostdlib -nodefaultlibs -fno-builtin -ffreestanding \
		-fno-tree-loop-distribute-patterns \
		-Wall -Wextra -Wl,-soname,libnss_files.so.2 -Wl,--no-undefined -o $@ $<

$(NSS_FILES_BLOB_OBJ): $(NSS_FILES_SHIM)
	@echo "LD(BIN) [nss_files]	$<"
	@ld -r -b binary -o $@.tmp $< && \
	START=$$(nm $@.tmp | awk '$$3 ~ /^_binary_.*_start$$/ {print $$3; exit}') && \
	END=$$(nm $@.tmp | awk '$$3 ~ /^_binary_.*_end$$/ {print $$3; exit}') && \
	test -n "$$START" && test -n "$$END" && \
	objcopy --redefine-sym $$START=nss_files_so_blob_start --redefine-sym $$END=nss_files_so_blob_end $@.tmp $@ && \
	rm -f $@.tmp

$(CA_TRUST_PEM): core/isrgrootx1.pem
	@mkdir -p $(dir $@)
	@cp $< $@

$(CA_TRUST_BLOB_OBJ): $(CA_TRUST_PEM)
	@echo "LD(BIN) [ca_trust]	$<"
	@ld -r -b binary -o $@.tmp $< && \
	START=$$(nm $@.tmp | awk '$$3 ~ /^_binary_.*_start$$/ {print $$3; exit}') && \
	END=$$(nm $@.tmp | awk '$$3 ~ /^_binary_.*_end$$/ {print $$3; exit}') && \
	test -n "$$START" && test -n "$$END" && \
	objcopy --redefine-sym $$START=ca_trust_pem_start --redefine-sym $$END=ca_trust_pem_end $@.tmp $@ && \
	rm -f $@.tmp

$(ASCII_PF2):
	@mkdir -p $(dir $@)
	@if [ -n "$(ASCII_PF2_SRC)" ] && [ -f "$(ASCII_PF2_SRC)" ]; then \
		cp "$(ASCII_PF2_SRC)" $@; \
	else \
		echo "warning: no host ascii.pf2 — font blob empty" >&2; \
		printf '' > $@; \
	fi

$(ASCII_PF2_BLOB_OBJ): $(ASCII_PF2)
	@echo "LD(BIN) [ascii.pf2]	$<"
	@ld -r -b binary -o $@.tmp $< && \
	START=$$(nm $@.tmp | awk '$$3 ~ /^_binary_.*_start$$/ {print $$3; exit}') && \
	END=$$(nm $@.tmp | awk '$$3 ~ /^_binary_.*_end$$/ {print $$3; exit}') && \
	test -n "$$START" && test -n "$$END" && \
	objcopy --redefine-sym $$START=ascii_pf2_blob_start --redefine-sym $$END=ascii_pf2_blob_end $@.tmp $@ && \
	rm -f $@.tmp

$(PAYLOAD_ELF): $(OTHER_ASM_OBJS) $(SOBJS) $(AP_TRAMP_OBJ) $(NSS_DNS_BLOB_OBJ) $(NSS_FILES_BLOB_OBJ) $(CA_TRUST_BLOB_OBJ) $(ASCII_PF2_BLOB_OBJ) $(PAYLOAD_COBJS)
	@mkdir -p $(BUILD_DIR)
	@echo "LD		$@"
	@ld -m elf_x86_64 -T linker.payload.ld -o $@ $^

$(PAYLOAD_LZ4): $(PAYLOAD_ELF)
	@echo "LZ4		$<"
	@lz4 -z -f --content-size "$<" "$@" >/dev/null

$(PAYLOAD_BLOB_OBJ): $(PAYLOAD_LZ4)
	@echo "LD(BIN)		$<"
	@ld -r -b binary -o "$@" "$<"
	@objcopy \
		--redefine-sym _binary_$(PAYLOAD_LZ4_SYM)_start=_binary_build_payload_lz4_start \
		--redefine-sym _binary_$(PAYLOAD_LZ4_SYM)_end=_binary_build_payload_lz4_end \
		--redefine-sym _binary_$(PAYLOAD_LZ4_SYM)_size=_binary_build_payload_lz4_size \
		"$@"

$(KERNEL_ELF): $(MULTIBOOT_OBJ) $(STUB_OBJ) $(PAYLOAD_BLOB_OBJ)
	@mkdir -p $(BUILD_DIR)
	@echo "LD		$@"
	@ld -m elf_x86_64 -T linker.stub.ld -o $@ $^

$(KERNEL_BIN): $(KERNEL_ELF)
	@objcopy -O binary $< $@

$(GRUB_DIR)/grub.cfg: | $(GRUB_DIR)
	

$(GRUB_DIR):
	@mkdir -p $(GRUB_DIR)




iso: $(KERNEL_ELF) $(GRUB_DIR)/grub.cfg archive
	@cp $(KERNEL_ELF) $(ISO_BOOT)/axonos.elf
	@mkdir -p $(GRUB_DIR)/fonts
	@if [ -f /usr/share/grub/ascii.pf2 ]; then cp /usr/share/grub/ascii.pf2 $(GRUB_DIR)/fonts/; fi
	@if [ -f /usr/share/grub/unicode.pf2 ]; then cp /usr/share/grub/unicode.pf2 $(GRUB_DIR)/fonts/; fi
	@if [ -f /usr/share/grub/euro.pf2 ]; then cp /usr/share/grub/euro.pf2 $(GRUB_DIR)/fonts/; fi
	@grub-mkrescue -o $(ISO_IMAGE) $(ISO_DIR) 2>/dev/null || { \
		@echo "grub-mkrescue failed: try installing grub-pc-bin or xorriso" >&2; exit 1; \
	}

run: archive iso
	@qemu-system-x86_64 -cdrom $(ISO_IMAGE) -m 2048M -smp 2 -serial stdio -boot d -hda ../disk.img -device e1000,netdev=net0 -netdev user,id=net0 -vga vmware

test-boot:
	@tools/headless-openrc-boot.sh

# Run with bridged networking (real IP from router) - requires sudo and br0 bridge
run-bridge: iso
	@echo "Note: Requires bridge 'br0' to be configured. Run with sudo."
	@qemu-system-x86_64 -cdrom $(ISO_IMAGE) -m 1024M -serial stdio -boot d -hda ../disk.img \
		-device e1000,netdev=net0 -netdev bridge,id=net0,br=br0

# Run with TAP networking (real IP from router) - requires sudo
run-tap: iso
	@echo "Creating TAP interface... (requires sudo)"
	@sudo ip tuntap add dev tap0 mode tap user $(USER) 2>/dev/null || true
	@sudo ip link set tap0 up 2>/dev/null || true
	@sudo ip link set tap0 master br0 2>/dev/null || echo "Warning: br0 not found, tap0 not bridged"
	@qemu-system-x86_64 -cdrom $(ISO_IMAGE) -m 1024M -serial stdio -boot d -hda ../disk.img \
		-device e1000,netdev=net0 -netdev tap,id=net0,ifname=tap0,script=no,downscript=no

debug: iso
	@qemu-system-x86_64 -cdrom $(ISO_IMAGE) -m 1024M -smp 2 -serial stdio -hda ../disk.img -boot d -s -S & gdb -ex "target remote localhost:1234" $(PAYLOAD_ELF)

disk:
	@dd if=/dev/zero of=../disk.img bs=1M count=10
	@mkfs.fat -F 32 ../disk.img

archive:
	@if [ ! -f iso/boot/initfs.cpio ]; then \
		wget -P build apm.axont.ru/Packages/initfs.tar.xz; \
		tar -xf build/initfs.tar.xz -C iso/boot/; \
		rm build/initfs.tar.xz; \
	fi

clean:
	@rm -rf $(BUILD_DIR)

# Show resolved options from the active config file.
oldconfig: config
	@grep -vE '^(# Generated|# m is|$)' $(AUTO_CONF) || true
