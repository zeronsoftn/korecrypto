.text
BORINGSSL_bcm_text_start:
.LBORINGSSL_bcm_text_start_local_target:
	# COFF (Windows / UEFI x86_64) analogue of in.s. The .file directives
	# (including the md5 checksum) are identical to in.s; a .def directive is
	# added because COFF detection requires one (in.s has no symbol-type
	# directive). The COFF emit path passes .file directives through and, unlike
	# the ELF path, does not insert its own .file/.loc.
	.file 10 "some/path/file.c" "file.c"
	.file 1000 "some/path/file2.c" "file2.c"
	.file 1001 "some/path/file_with_md5.c" "other_name.c" md5 0x5eba7844df6449a7f2fff1556fe7ba8d239f8e2f

	# An instruction is needed to satisfy the architecture auto-detection.
	.def probe; .scl 3; .type 32; .endef
.Lprobe_local_target:
probe:
        movq %rax, %rbx
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
