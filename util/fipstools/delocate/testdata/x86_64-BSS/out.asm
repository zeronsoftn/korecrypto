.text
BORINGSSL_bcm_text_start:
.LBORINGSSL_bcm_text_start_local_target:
	# COFF (Windows / UEFI x86_64) analogue of in.s. The body is identical to
	# in.s; only the symbol-type directive differs (COFF .def/.scl/.type/.endef
	# instead of ELF .type @object), which is also what makes delocate treat this
	# input as COFF.
	.text
	movq %rax, %rax

	# BSS declarations emit accessors.
	.comm	aes_128_ctr_generic_storage,64,32
	.lcomm	aes_128_ctr_generic_storage2,64,32

	# BSS symbols may also be emitted in .bss sections.
	.section .bss,"awT",@nobits
	.align 4
	.globl x
	.def x; .scl 2; .type 0; .endef
	.size   x, 4
x:
.Lx_local_target:

	.zero 4
.Llocal:
	.quad 0
	.size .Llocal, 4

	# .bss handling is terminated by a .text directive.
	.text
.Lnot_bss1_local_target:
not_bss1:
	ret

	# The .bss directive can introduce BSS.
	.bss
test:
.Ltest_local_target:

	.quad 0
	.text
.Lnot_bss2_local_target:
not_bss2:
	ret

	.section .bss,"awT",@nobits
y:
.Ly_local_target:

	.quad 0

	# A .section directive also terminates BSS.
# WAS .section .rodata
.text
	.quad 0

	# The end of the file terminates BSS.
	.section .bss,"awT",@nobits
z:
.Lz_local_target:

	.quad 0
.text
BORINGSSL_bcm_text_end:
.LBORINGSSL_bcm_text_end_local_target:
aes_128_ctr_generic_storage_bss_get:
	leaq	aes_128_ctr_generic_storage(%rip), %rax
	ret
aes_128_ctr_generic_storage2_bss_get:
	leaq	aes_128_ctr_generic_storage2(%rip), %rax
	ret
test_bss_get:
	leaq	.Ltest_local_target(%rip), %rax
	ret
x_bss_get:
	leaq	.Lx_local_target(%rip), %rax
	ret
y_bss_get:
	leaq	.Ly_local_target(%rip), %rax
	ret
z_bss_get:
	leaq	.Lz_local_target(%rip), %rax
	ret
BORINGSSL_bcm_text_hash:
.LBORINGSSL_bcm_text_hash_local_target:
.byte 0xae
.byte 0x2c
.byte 0xea
.byte 0x2a
.byte 0xbd
.byte 0xa6
.byte 0xf3
.byte 0xec
.byte 0x97
.byte 0x7f
.byte 0x9b
.byte 0xf6
.byte 0x94
.byte 0x9a
.byte 0xfc
.byte 0x83
.byte 0x68
.byte 0x27
.byte 0xcb
.byte 0xa0
.byte 0xa0
.byte 0x9f
.byte 0x6b
.byte 0x6f
.byte 0xde
.byte 0x52
.byte 0xcd
.byte 0xe2
.byte 0xcd
.byte 0xff
.byte 0x31
.byte 0x80
