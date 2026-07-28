OUTPUT_FORMAT("elf64-x86-64")
ENTRY(kernel_main)

PHDRS
{
    low  PT_LOAD FLAGS(6); /* RW-  AP mailbox @ 0x9000 */
    text PT_LOAD FLAGS(5); /* R-X */
    data PT_LOAD FLAGS(6); /* RW- */
}

SECTIONS
{
    /* Fixed mailbox for AP trampoline (identity-mapped); see smp.c */
    . = 0x9000;
    .smp_mailbox : AT(0x9000) {
        KEEP(*(.smp_mailbox))
    } :low

    . = 0x100000;

    .text : {
        *(.text .text.*)
    } :text

    .rodata : {
        *(.rodata .rodata.*)
    } :text

    .data : {
        *(.data .data.*)
    } :data

    /* Must include COMMON and .bss.* or _end sits before real BSS end; RAM past _end
     * still belongs to the kernel and will overwrite the low initrd module (GRUB ~0x103000). */
    .bss : ALIGN(16) {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    . = ALIGN(16);
    _end = .; PROVIDE(end = .);

    /* Linux x86-64 static ET_EXEC images conventionally begin at 0x400000. */
    ASSERT(_end <= 0x400000, "kernel overlaps fixed-address user ET_EXEC range")
}
