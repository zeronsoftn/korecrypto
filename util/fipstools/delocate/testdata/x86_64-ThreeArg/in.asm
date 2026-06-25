	# COFF (Windows / UEFI x86_64) analogue of in.s. Same three-argument
	# instructions as in.s; the only differences are COFF symbol-type directives
	# (.def instead of ELF .type) and the operand form: COFF/PE has no GOT, so the
	# ELF @GOTPCREL references to the module symbol become plain rip-relative
	# references, which delocate rewrites to the symbol's local target.
	.def foo; .scl 2; .type 32; .endef
	.globl foo
foo:
	movq	%rax, %rax
	shrxq	%rbx, kBoringSSLRSASqrtTwo(%rip), %rax
	shrxq	kBoringSSLRSASqrtTwo(%rip), %rbx, %rax


	.def	kBoringSSLRSASqrtTwo; .scl 2; .type 0; .endef # @kBoringSSLRSASqrtTwo
	.section	.rdata,"dr" # .rodata
	.globl	kBoringSSLRSASqrtTwo
	.p2align	4
kBoringSSLRSASqrtTwo:
	.quad	-2404814165548301886    # 0xdea06241f7aa81c2
