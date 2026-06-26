.text
.p2align 12
BORINGSSL_bcm_text_start:
.LBORINGSSL_bcm_text_start_local_target:
	# COFF (Windows / UEFI on ARM) analogue of in.s, exercising delocate's aarch64
	# support on a COFF object. The kept lines below are byte-identical to in.s.
	# The ELF-only constructs in in.s have no COFF form and are omitted rather
	# than approximated: the GOT loads (adrp :got: / ldr :got_lo12:) and the ELF
	# BSS-section declaration of bss_symbol (with its bl bss_symbol_bss_get). The
	# .type %function declaration becomes the COFF .def directive, which is also
	# what makes delocate treat this input as COFF.
	.def foo; .scl 2; .type 32; .endef
	.globl foo
.Lfoo_local_target:
foo:
	// aarch64 constants can be written with or without '#'.
	mov x1, #123
	mov x1, 123
	add x0, x1, x2, lsl #2
	add x0, x1, x2, lsl 2

	// Address load
// WAS adrp x0, .Llocal_data
	adrp x0, .Llocal_data
	add x0, x0, :lo12:.Llocal_data
// WAS add x1, x0, :lo12:.Llocal_data
	add	x1, x0, #0

// WAS adrp x0, .Llocal_data
	adrp x0, .Llocal_data
	add x0, x0, :lo12:.Llocal_data
// WAS add x1, x0, #:lo12:.Llocal_data
	add	x1, x0, #0

	// Address of local symbol with offset
// WAS adrp x10, .Llocal_data2+16
	adrp x10, .Llocal_data2+16
	add x10, x10, :lo12:.Llocal_data2+16
// WAS add x11, x10, :lo12:.Llocal_data2+16
	add	x11, x10, #0

// WAS adrp x10, .Llocal_data2+16
	adrp x10, .Llocal_data2+16
	add x10, x10, :lo12:.Llocal_data2+16
// WAS add x11, x10, #:lo12:.Llocal_data2+16
	add	x11, x10, #0

	// Address load with no-op add instruction
// WAS adrp x0, .Llocal_data
	adrp x0, .Llocal_data
	add x0, x0, :lo12:.Llocal_data
// WAS add x0, x0, :lo12:.Llocal_data

// WAS adrp x0, .Llocal_data
	adrp x0, .Llocal_data
	add x0, x0, :lo12:.Llocal_data
// WAS add x0, x0, #:lo12:.Llocal_data

	// Load from local symbol
// WAS adrp x10, .Llocal_data2
	adrp x10, .Llocal_data2
	add x10, x10, :lo12:.Llocal_data2
// WAS ldr q0, [x10, :lo12:.Llocal_data2]
	ldr	q0, [x10]
// WAS ldr q0, [x10, #:lo12:.Llocal_data2]
	ldr	q0, [x10]
// WAS ldr x0, [x10, :lo12:.Llocal_data2]
	ldr	x0, [x10]
// WAS ldr w0, [x10, :lo12:.Llocal_data2]
	ldr	w0, [x10]
// WAS ldrh w0, [x10, :lo12:.Llocal_data2]
	ldrh	w0, [x10]
// WAS ldrb w0, [x10, :lo12:.Llocal_data2]
	ldrb	w0, [x10]
// WAS ldrsw x0, [x10, :lo12:.Llocal_data2]
	ldrsw	x0, [x10]
// WAS ldrsh w0, [x10, :lo12:.Llocal_data2]
	ldrsh	w0, [x10]
// WAS ldrsb w0, [x10, :lo12:.Llocal_data2]
	ldrsb	w0, [x10]

	// Load from local symbol with offset
// WAS adrp x10, .Llocal_data2+16
	adrp x10, .Llocal_data2+16
	add x10, x10, :lo12:.Llocal_data2+16
// WAS ldr q0, [x10, :lo12:.Llocal_data2+16]
	ldr	q0, [x10]
// WAS ldr q0, [x10, #:lo12:.Llocal_data2+16]
	ldr	q0, [x10]
// WAS ldr x0, [x10, :lo12:.Llocal_data2+16]
	ldr	x0, [x10]
// WAS ldr w0, [x10, :lo12:.Llocal_data2+16]
	ldr	w0, [x10]
// WAS ldrh w0, [x10, :lo12:.Llocal_data2+16]
	ldrh	w0, [x10]
// WAS ldrb w0, [x10, :lo12:.Llocal_data2+16]
	ldrb	w0, [x10]
// WAS ldrsw x0, [x10, :lo12:.Llocal_data2+16]
	ldrsw	x0, [x10]
// WAS ldrsh w0, [x10, :lo12:.Llocal_data2+16]
	ldrsh	w0, [x10]
// WAS ldrsb w0, [x10, :lo12:.Llocal_data2+16]
	ldrsb	w0, [x10]

	// Different aarch64 addressing modes
	ldr x0, [x1]
	ldr x0, [x1, #123]
	ldr x0, [x1, 123]
	ldr x0, [x1, #123]!
	ldr x0, [x1, 123]!
	ldr x0, x1, #123
	ldr x0, x1, 123

// WAS bl local_function
	bl	.Llocal_function_local_target

// WAS bl remote_function
	bl	bcm_redirector_remote_function

	// Regression test for a two-digit index.
	ld1 { v1.b }[10], [x9]

	// Register range syntaxes
	st1 {v0.16b,v1.16b,v2.16b,v3.16b}, [x2], #64
	st1 { v0.16b , v1.16b , v2.16b , v3.16b }, [x2], #64
	st1 {v0.16b-v3.16b}, [x2], #64
	st1 { v0.16b - v3.16b }, [x2], #64

	// Ensure that registers aren't interpreted as symbols.
	add x0, x0
	add x12, x12
	add w0, x0
	add w12, x12
	add d0, d0
	add d12, d12
	add q0, q0
	add q12, q12
	add s0, s0
	add s12, s12
	add h0, h0
	add h12, h12
	add b0, b0
	add b12, b12

	// But 'y' is not a register prefix so far, so these should be
	// processed as symbols.
// WAS add y0, y0
	add	bcm_redirector_y0, bcm_redirector_y0
// WAS add y12, y12
	add	bcm_redirector_y12, bcm_redirector_y12

	// Make sure that the magic extension constants are recognised rather
	// than being interpreted as symbols.
	add w0, w1, b2, uxtb
	add w0, w1, b2, uxth
	add w0, w1, b2, uxtw
	add w0, w1, b2, uxtx
	add w0, w1, b2, sxtb
	add w0, w1, b2, sxth
	add w0, w1, b2, sxtw
	add w0, w1, b2, sxtx
	movi v0.4s, #3, msl #8

	// Aarch64 SVE2 added these forms:
	ld1d { z1.d }, p91/z, [x13, x11, lsl #3]
	ld1b { z11.b }, p15/z, [x10, #1, mul vl]
	st2d { z6.d, z7.d }, p0, [x12]
	// Check that "p22" here isn't parsed as the "p22" register.
// WAS bl p224_point_add
	bl	bcm_redirector_p224_point_add
	ptrue p0.d, vl1
	// The "#7" here isn't a comment, it's now valid Aarch64 assembly.
	cnth x8, all, mul #7

	// fcmp can compare against zero, which is expressed with a floating-
	// point zero literal in the instruction. Again, this is not a
	// comment.
	fcmp d0, #0.0

  # cnth allows a 4-bit immediate.
  cnth x10, all, mul #15

.Llocal_function_local_target:
local_function:
.text
BORINGSSL_bcm_text_end:
.LBORINGSSL_bcm_text_end_local_target:
.p2align 2
bcm_redirector_p224_point_add:
	hint #34 // bti c
	b p224_point_add
.p2align 2
bcm_redirector_remote_function:
	hint #34 // bti c
	b remote_function
.p2align 2
bcm_redirector_y0:
	hint #34 // bti c
	b y0
.p2align 2
bcm_redirector_y12:
	hint #34 // bti c
	b y12
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
