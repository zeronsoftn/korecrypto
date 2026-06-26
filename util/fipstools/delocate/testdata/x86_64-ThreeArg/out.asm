.text
BORINGSSL_bcm_text_start:
.LBORINGSSL_bcm_text_start_local_target:
	# COFF (Windows / UEFI x86_64) analogue of in.s. Same three-argument
	# instructions as in.s; the only differences are COFF symbol-type directives
	# (.def instead of ELF .type) and the operand form: COFF/PE has no GOT, so the
	# ELF @GOTPCREL references to the module symbol become plain rip-relative
	# references, which delocate rewrites to the symbol's local target.
	.def foo; .scl 2; .type 32; .endef
	.globl foo
.Lfoo_local_target:
foo:
	movq	%rax, %rax
# WAS shrxq	%rbx, kBoringSSLRSASqrtTwo(%rip), %rax
	shrxq	%rbx, .LkBoringSSLRSASqrtTwo_local_target(%rip), %rax
# WAS shrxq	kBoringSSLRSASqrtTwo(%rip), %rbx, %rax
	shrxq	.LkBoringSSLRSASqrtTwo_local_target(%rip), %rbx, %rax


	.def	kBoringSSLRSASqrtTwo; .scl 2; .type 0; .endef # @kBoringSSLRSASqrtTwo
# WAS .section	.rdata,"dr" # .rodata
.text
	.globl	kBoringSSLRSASqrtTwo
	.p2align	4
.LkBoringSSLRSASqrtTwo_local_target:
kBoringSSLRSASqrtTwo:
	.quad	-2404814165548301886    # 0xdea06241f7aa81c2
.text
BORINGSSL_bcm_text_end:
.LBORINGSSL_bcm_text_end_local_target:
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
