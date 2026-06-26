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
probe:
        movq %rax, %rbx
