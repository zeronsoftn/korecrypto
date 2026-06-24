// Copyright 2017 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// ELF/Mach-O 형식(리눅스/macOS) 어셈블리에 대한 delocate 처리. 공통 코드는
// delocate.go 에, COFF/PE(윈도우) 처리는 delocate_coff.go 에 있다.
package main

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"boringssl.googlesource.com/boringssl.git/util/fipstools/fipscommon"
)

func (d *delocation) processDirective(statement, directive *node32) (*node32, error) {
	assertNodeType(directive, ruleDirectiveName)
	directiveName := d.contents(directive)

	var args []string
	forEachPath(directive, func(arg *node32) {
		// If the argument is a quoted string, use the raw contents.
		// (Note that this doesn't unescape the string, but that's not
		// needed so far.
		if arg.up != nil {
			arg = arg.up
			assertNodeType(arg, ruleQuotedArg)
			if arg.up == nil {
				args = append(args, "")
				return
			}
			arg = arg.up
			assertNodeType(arg, ruleQuotedText)
		}
		args = append(args, d.contents(arg))
	}, ruleArgs, ruleArg)

	switch directiveName {
	case "addrsig", "addrsig_sym":
		// Remove .addrsig and .addrsig_sym tables.
		// Instead, consider all symbols inside the BCM address-significant
		// so the linker will not merge them with other symbols,
		// potentially breaking the integrity check of the BCM.
		d.writeCommentedNode(statement)
		break

	case "comm", "lcomm":
		if len(args) < 1 {
			return nil, errors.New("comm directive has no arguments")
		}
		d.bssAccessorsNeeded[args[0]] = args[0]
		d.writeNode(statement)

	case "data":
		// ASAN and some versions of MSAN are adding a .data section,
		// and adding references to symbols within it to the code. We
		// will have to work around this in the future.
		return nil, errors.New(".data section found in module")

	case "bss":
		d.writeNode(statement)
		return d.handleBSS(statement)

	case "section":
		section := args[0]

		if section == ".data.rel.ro" {
			// In a normal build, this is an indication of a
			// problem but any references from the module to this
			// section will result in a relocation and thus will
			// break the integrity check. ASAN can generate these
			// sections and so we will likely have to work around
			// that in the future.
			return nil, errors.New(".data.rel.ro section found in module")
		}

		sectionType, ok := sectionType(section)
		if !ok {
			// Unknown sections are permitted in order to be robust
			// to different compiler modes.
			d.writeNode(statement)
			break
		}

		switch sectionType {
		case ".rodata", ".text":
			// Move .rodata to .text so it may be accessed without
			// a relocation. GCC with -fmerge-constants will place
			// strings into separate sections, so we move all
			// sections named like .rodata. Also move .text.startup
			// so the self-test function is also in the module.
			d.writeCommentedNode(statement)
			d.output.WriteString(".text\n")

		case ".data":
			// See above about .data
			return nil, errors.New(".data section found in module")

		case ".init_array", ".fini_array", ".ctors", ".dtors":
			// init_array/ctors/dtors contains function
			// pointers to constructor/destructor
			// functions. These contain relocations, but
			// they're in a different section anyway.
			d.writeNode(statement)
			break

		case ".debug", ".note":
			d.writeNode(statement)
			break

		case ".bss":
			d.writeNode(statement)
			return d.handleBSS(statement)

		case ".llvm_addrsig":
			// Remove .llvm_addrsig sections.
			// Instead, consider all symbols inside the BCM address-significant
			// so the linker will not merge them with other symbols,
			// potentially breaking the integrity check of the BCM.
			d.writeCommentedNode(statement)
			d.output.WriteString(".section .discard_llvm_addrsig, \"e\", @progbits\n")
		}

	case "reloc":
		// The .reloc directive is used to emit custom relocations into the object
		// file. R_AARCH64_PATCHINST is a special relocation type used to implement
		// deactivation symbols, which are associated with LLVM's pointer field
		// protection feature. Because deactivation symbols are only defined in
		// special cases which don't apply to BoringSSL, we pass them through and
		// let the integrity check fail in the unexpected case that a symbol was
		// defined.
		if args[1] != "R_AARCH64_PATCHINST" {
			return nil, errors.New("unexpected .reloc directive")
		}
		args[0] = d.mapLocalSymbol(args[0])
		d.output.WriteString(".reloc " + strings.Join(args, ", ") + "\n")

	default:
		d.writeNode(statement)
	}

	return statement, nil
}

// Aarch64 support

// gotHelperName returns the name of a synthesised function that returns an
// address from the GOT.
func gotHelperName(symbol string) string {
	return ".Lboringssl_loadgot_" + symbol
}

// loadAarch64Address emits instructions to put the address of |symbol|
// (optionally adjusted by |offsetStr|) into |targetReg|.
func (d *delocation) loadAarch64Address(statement *node32, targetReg string, symbol string, offsetStr string) (*node32, error) {
	// There are two paths here: either the symbol is known to be local in which
	// case the address is simply loaded, or a GOT reference is really needed in
	// which case the code needs to jump to a helper function.
	//
	// A helper function is needed because using code appears to be the only way
	// to load a GOT value. On other platforms we have ".quad foo@GOT" outside of
	// the module, but on Aarch64 that results in a "COPY" relocation and linker
	// comments suggest it's a weird hack. So, for each GOT symbol needed, we emit
	// a function outside of the module that returns the address from the GOT in
	// x0.

	d.writeCommentedNode(statement)

	_, isKnown := d.symbols[symbol]
	isLocal := strings.HasPrefix(symbol, ".L")
	if isKnown || isLocal || isSynthesized(symbol) {
		if isLocal {
			symbol = d.mapLocalSymbol(symbol)
		} else if isKnown {
			symbol = localTargetName(symbol)
		}

		// Note the adrp instruction always emits a relocation, at least in
		// clang's assembler. Even when the symbol is defined in the same file,
		// the assembler cannot compute the adrp offset without knowing the PC's
		// page offset. We page-align the module, making this offset fixed and
		// the relocation safe. It will always produce the same offset.
		fmt.Fprintf(d.output, "\tadrp %s, %s%s\n", targetReg, symbol, offsetStr)
		fmt.Fprintf(d.output, "\tadd %s, %s, :lo12:%s%s\n", targetReg, targetReg, symbol, offsetStr)
		return statement, nil
	}

	if offsetStr != "" {
		panic("non-zero offset for helper-based reference")
	}

	// GOT helpers also dereference the GOT entry, thus the subsequent ldr
	// instruction, which would normally do the dereferencing, needs to be
	// dropped. GOT helpers have to include the dereference because the
	// assembler doesn't support ":got_lo12:foo" offsets except in an ldr
	// instruction.
	d.gotExternalsNeeded[symbol] = struct{}{}
	helperFunc := gotHelperName(symbol)

	// Clear the red-zone. I can't find a definitive answer about whether Linux
	// Aarch64 includes a red-zone, but Microsoft has a 16-byte one and Apple a
	// 128-byte one. Thus conservatively clear a 128-byte red-zone.
	d.output.WriteString("\tsub sp, sp, 128\n")

	// Save x0 (which will be stomped by the return value) and the link register
	// to the stack. Then save the program counter into the link register and
	// jump to the helper function.
	d.output.WriteString("\tstp x0, lr, [sp, #-16]!\n")
	d.output.WriteString("\tbl " + helperFunc + "\n")

	if targetReg == "x0" {
		// If the target happens to be x0 then restore the link register from the
		// stack and send the saved value of x0 to the zero register.
		d.output.WriteString("\tldp xzr, lr, [sp], #16\n")
	} else {
		// Otherwise move the result into place and restore registers.
		d.output.WriteString("\tmov " + targetReg + ", x0\n")
		d.output.WriteString("\tldp x0, lr, [sp], #16\n")
	}

	// Revert the red-zone adjustment.
	d.output.WriteString("\tadd sp, sp, 128\n")

	return statement, nil
}

func (d *delocation) processAarch64Instruction(statement, instruction *node32) (*node32, error) {
	assertNodeType(instruction, ruleInstructionName)
	instructionName := d.contents(instruction)

	argNodes := instructionArgs(instruction.next)

	switch instructionName {
	case "ccmn", "ccmp", "cinc", "cinv", "cneg", "csel", "cset", "csetm", "csinc", "csinv", "csneg":
		// These functions are special because they take a condition-code name as
		// an argument and that looks like a symbol reference.
		d.writeNode(statement)
		return statement, nil

	case "mrs":
		// Functions that take special register names also look like a symbol
		// reference to the parser.
		d.writeNode(statement)
		return statement, nil

	case "adrp":
		// adrp instructions are turned into either adrp/add pairs or calls to
		// helper functions, both of which load the full address. Later instructions,
		// which add the low 12 bits of offset, are tweaked to remove the offset since
		// it's already included. Loads of GOT symbols are slightly more complex
		// because it's not possible to avoid dereferencing a GOT entry with Clang's
		// assembler. Thus the later ldr instruction, which would normally do the
		// dereferencing, is dropped completely. (Or turned into a mov if it targets
		// a different register.)
		//
		// TODO(davidben): When loading a local symbol, there is no real need to
		// apply low 12 bits immediately. We could instead preserve the compiler's
		// choice of (slightly optimized) output by just converting the instructions
		// one-to-one.
		assertNodeType(argNodes[0], ruleRegisterOrConstant)
		targetReg := d.contents(argNodes[0])
		if !strings.HasPrefix(targetReg, "x") {
			panic("adrp targeting register " + targetReg + ", which has the wrong size")
		}

		var symbol, offset string
		switch argNodes[1].pegRule {
		case ruleGOTSymbolOffset:
			symbol = d.contents(argNodes[1].up)
		case ruleMemoryRef:
			assertNodeType(argNodes[1].up, ruleSymbolRef)
			node, empty := d.gatherOffsets(argNodes[1].up.up, "")
			if empty != "" {
				panic("prefix offsets found for adrp")
			}
			symbol = d.contents(node)
			_, offset = d.gatherOffsets(node.next, "")
		default:
			panic("Unhandled adrp argument type " + rul3s[argNodes[1].pegRule])
		}

		return d.loadAarch64Address(statement, targetReg, symbol, offset)
	}

	var args []string
	changed := false

	for _, arg := range argNodes {
		fullArg := arg

		switch arg.pegRule {
		case ruleRegisterOrConstant, ruleLocalLabelRef, ruleARMConstantTweak:
			args = append(args, d.contents(fullArg))

		case ruleGOTSymbolOffset:
			// These should only be arguments to adrp and thus unreachable.
			panic("unreachable")

		case ruleMemoryRef:
			ref := arg.up

			switch ref.pegRule {
			case ruleSymbolRef:
				// This is a branch. Either the target needs to be written to a local
				// version of the symbol to ensure that no relocations are emitted, or
				// it needs to jump to a redirector function.
				symbol, offset, _, didChange, symbolIsLocal, _ := d.parseMemRef(arg.up)
				changed = didChange

				if _, knownSymbol := d.symbols[symbol]; knownSymbol {
					symbol = localTargetName(symbol)
					changed = true
				} else if !symbolIsLocal && !isSynthesized(symbol) {
					redirector := redirectorName(symbol)
					d.redirectors[symbol] = redirector
					symbol = redirector
					changed = true
				} else if didChange && symbolIsLocal && len(offset) > 0 {
					// didChange is set when the inputFile index is not 0; which is the index of the
					// first file copied to the output, which is the generated assembly of bcm.c.
					// In subsequently copied assembly files, local symbols are changed by appending (BCM_ + index)
					// in order to ensure they don't collide. `index` gets incremented per file.
					// If there is offset after the symbol, append the `offset`.
					symbol = symbol + offset
				}

				args = append(args, symbol)

			case ruleARMBaseIndexScale:
				parts := ref.up
				assertNodeType(parts, ruleARMRegister)
				baseAddrReg := d.contents(parts)
				parts = skipWS(parts.next)

				// Only two forms need special handling. First there's memory references
				// like "[x*, :got_lo12:foo]". The base register here will have been the
				// target of an adrp instruction to load the page address, but the adrp
				// will have turned into loading the full address *and dereferencing it*,
				// above. Thus this instruction needs to be dropped otherwise we'll be
				// dereferencing twice.
				//
				// Second there are forms like "[x*, :lo12:foo]" where the code has used
				// adrp to load the page address into x*. That adrp will have been turned
				// into loading the full address so just the offset needs to be dropped.

				if parts != nil {
					if parts.pegRule == ruleARMGOTLow12 {
						if instructionName != "ldr" {
							panic("Symbol reference outside of ldr instruction")
						}

						if skipWS(parts.next) != nil || parts.up.next != nil {
							panic("can't handle tweak or post-increment with symbol references")
						}

						// The GOT helper already dereferenced the entry so, at most, just a mov
						// is needed to put things in the right register.
						d.writeCommentedNode(statement)
						if baseAddrReg != args[0] {
							d.output.WriteString("\tmov " + args[0] + ", " + baseAddrReg + "\n")
						}
						return statement, nil
					} else if parts.pegRule == ruleLow12BitsSymbolRef {
						switch instructionName {
						case "ldr", "ldrh", "ldrb", "ldrsw", "ldrsh", "ldrsb":
						default:
							panic("Symbol reference outside of load instruction")
						}

						// Suppress the offset; adrp loaded the full address. This assumes the
						// the compiler does not emit code like the following:
						//
						//   adrp x0, symbol
						//   ldr x1, [x0, :lo12:symbol]
						//   ldr x2, [x0, :lo12:symbol+4]
						//
						// Such code would only work if lo12(symbol+4) = lo12(symbol) + 4, but
						// this is true when symbol is sufficiently aligned.
						args = append(args, "["+baseAddrReg+"]")
						changed = true
						continue
					}
				}

				args = append(args, d.contents(fullArg))

			case ruleLow12BitsSymbolRef:
				// These are the second instruction in a pair:
				//   adrp x0, symbol           // Load the page address into x0
				//   add x1, x0, :lo12:symbol  // Adds the page offset.
				//
				// The adrp instruction will have been turned into a sequence that loads
				// the full address, above, thus the offset is turned into zero. If that
				// results in the instruction being a nop, then it is deleted.
				//
				// This assumes the compiler does not emit code like the following:
				//
				//   adrp x0, symbol
				//   add x1, x0, :lo12:symbol
				//   add x2, x0, :lo12:symbol+4
				//
				// Such code would only work if lo12(symbol+4) = lo12(symbol) + 4, but
				// this is true when symbol is sufficiently aligned.
				if instructionName != "add" {
					panic(fmt.Sprintf("unsure how to handle %q instruction using lo12", instructionName))
				}

				if !strings.HasPrefix(args[0], "x") || !strings.HasPrefix(args[1], "x") {
					panic("address arithmetic with incorrectly sized register")
				}

				if args[0] == args[1] {
					d.writeCommentedNode(statement)
					return statement, nil
				}

				args = append(args, "#0")
				changed = true

			default:
				panic(fmt.Sprintf("unhandled MemoryRef type %s", rul3s[ref.pegRule]))
			}

		default:
			panic(fmt.Sprintf("unknown instruction argument type %q", rul3s[arg.pegRule]))
		}
	}

	if changed {
		d.writeCommentedNode(statement)
		replacement := "\t" + instructionName + "\t" + strings.Join(args, ", ") + "\n"
		d.output.WriteString(replacement)
	} else {
		d.writeNode(statement)
	}

	return statement, nil
}

func (d *delocation) loadFromGOT(w stringWriter, destination, symbol, section string, redzoneCleared bool) wrapperFunc {
	d.gotExternalsNeeded[symbol+"@"+section] = struct{}{}

	return func(k func()) {
		if !redzoneCleared {
			w.WriteString("\tleaq -128(%rsp), %rsp\n") // Clear the red zone.
		}
		w.WriteString("\tpushf\n")
		w.WriteString(fmt.Sprintf("\tleaq %s_%s_external(%%rip), %s\n", symbol, section, destination))
		w.WriteString(fmt.Sprintf("\taddq (%s), %s\n", destination, destination))
		w.WriteString(fmt.Sprintf("\tmovq (%s), %s\n", destination, destination))
		w.WriteString("\tpopf\n")
		if !redzoneCleared {
			w.WriteString("\tleaq\t128(%rsp), %rsp\n")
		}
	}
}

func (d *delocation) processIntelInstruction(statement, instruction *node32) (*node32, error) {
	var prefix string
	if instruction.pegRule == ruleInstructionPrefix {
		prefix = d.contents(instruction)
		instruction = skipWS(instruction.next)
	}

	assertNodeType(instruction, ruleInstructionName)
	instructionName := d.contents(instruction)

	argNodes := instructionArgs(instruction.next)

	var wrappers wrapperStack
	var args []string
	changed := false

Args:
	for i, arg := range argNodes {
		fullArg := arg
		isIndirect := false

		if arg.pegRule == ruleIndirectionIndicator {
			arg = arg.next
			isIndirect = true
		}

		switch arg.pegRule {
		case ruleRegisterOrConstant, ruleLocalLabelRef:
			args = append(args, d.contents(fullArg))

		case ruleMemoryRef:
			symbol, offset, section, didChange, symbolIsLocal, memRef := d.parseMemRef(arg.up)
			changed = didChange

			switch section {
			case "":
				if _, knownSymbol := d.symbols[symbol]; knownSymbol {
					symbol = localTargetName(symbol)
					changed = true
				}

			case "PLT":
				if classifyInstruction(instructionName, argNodes) != instrJump {
					return nil, fmt.Errorf("Cannot rewrite PLT reference for non-jump instruction %q", instructionName)
				}

				if _, knownSymbol := d.symbols[symbol]; knownSymbol {
					symbol = localTargetName(symbol)
					changed = true
				} else if !symbolIsLocal && !isSynthesized(symbol) {
					// Unknown symbol via PLT is an
					// out-call from the module, e.g.
					// memcpy.
					d.redirectors[symbol+"@"+section] = redirectorName(symbol)
					symbol = redirectorName(symbol)
				}

				changed = true

			case "GOTPCREL":
				if len(offset) > 0 {
					return nil, errors.New("loading from GOT with offset is unsupported")
				}
				if !d.isRIPRelative(memRef) {
					return nil, errors.New("GOT access must be IP-relative")
				}

				useGOT := false
				if _, knownSymbol := d.symbols[symbol]; knownSymbol {
					symbol = localTargetName(symbol)
					changed = true
				} else if !isSynthesized(symbol) {
					useGOT = true
				}

				classification := classifyInstruction(instructionName, argNodes)
				if classification != instrThreeArg && classification != instrCompare && i != 0 {
					return nil, errors.New("GOT access must be source operand")
				}

				// Reduce the instruction to movq symbol@GOTPCREL, targetReg.
				var targetReg string
				var redzoneCleared bool
				switch classification {
				case instrPush:
					wrappers = append(wrappers, push(d.output))
					targetReg = "%rax"
				case instrConditionalMove:
					wrappers = append(wrappers, undoConditionalMove(d.output, instructionName))
					fallthrough
				case instrMove:
					assertNodeType(argNodes[1], ruleRegisterOrConstant)
					targetReg = d.contents(argNodes[1])
				case instrCompare:
					otherSource := d.contents(argNodes[i^1])
					saveRegWrapper, tempReg := saveRegister(d.output, []string{otherSource})
					redzoneCleared = true
					wrappers = append(wrappers, saveRegWrapper)
					if i == 0 {
						wrappers = append(wrappers, compare(d.output, instructionName, tempReg, otherSource))
					} else {
						wrappers = append(wrappers, compare(d.output, instructionName, otherSource, tempReg))
					}
					targetReg = tempReg
				case instrTransformingMove:
					assertNodeType(argNodes[1], ruleRegisterOrConstant)
					targetReg = d.contents(argNodes[1])
					wrappers = append(wrappers, finalTransform(d.output, instructionName, targetReg))
					if isValidLEATarget(targetReg) {
						return nil, errors.New("Currently transforming moves are assumed to target XMM registers. Otherwise we'll pop %rax before reading it to do the transform.")
					}
				case instrCombine:
					targetReg = d.contents(argNodes[1])
					if !isValidLEATarget(targetReg) {
						return nil, fmt.Errorf("cannot handle combining instructions targeting non-general registers")
					}
					saveRegWrapper, tempReg := saveRegister(d.output, []string{targetReg})
					redzoneCleared = true
					wrappers = append(wrappers, saveRegWrapper)

					wrappers = append(wrappers, combineOp(d.output, instructionName, tempReg, targetReg))
					targetReg = tempReg
				case instrMemoryVectorCombine:
					assertNodeType(argNodes[1], ruleRegisterOrConstant)
					targetReg = d.contents(argNodes[1])
					if isValidLEATarget(targetReg) {
						return nil, errors.New("target register must be an XMM register")
					}
					saveRegWrapper, tempReg := saveRegister(d.output, nil)
					wrappers = append(wrappers, saveRegWrapper)
					redzoneCleared = true
					wrappers = append(wrappers, memoryVectorCombineOp(d.output, instructionName, tempReg, targetReg))
					targetReg = tempReg
				case instrThreeArg:
					if n := len(argNodes); n != 3 {
						return nil, fmt.Errorf("three-argument instruction has %d arguments", n)
					}
					if i != 0 && i != 1 {
						return nil, errors.New("GOT access must be from source operand")
					}
					targetReg = d.contents(argNodes[2])

					otherSource := d.contents(argNodes[1])
					if i == 1 {
						otherSource = d.contents(argNodes[0])
					}

					saveRegWrapper, tempReg := saveRegister(d.output, []string{targetReg, otherSource})
					redzoneCleared = true
					wrappers = append(wrappers, saveRegWrapper)

					if i == 0 {
						wrappers = append(wrappers, threeArgCombineOp(d.output, instructionName, tempReg, otherSource, targetReg))
					} else {
						wrappers = append(wrappers, threeArgCombineOp(d.output, instructionName, otherSource, tempReg, targetReg))
					}
					targetReg = tempReg
				default:
					return nil, fmt.Errorf("Cannot rewrite GOTPCREL reference for instruction %q", instructionName)
				}

				if !isValidLEATarget(targetReg) {
					// Sometimes the compiler will load from the GOT to an
					// XMM register, which is not a valid target of an LEA
					// instruction.
					saveRegWrapper, tempReg := saveRegister(d.output, nil)
					wrappers = append(wrappers, saveRegWrapper)
					isAVX := strings.HasPrefix(instructionName, "v")
					wrappers = append(wrappers, moveTo(d.output, targetReg, isAVX, tempReg))
					targetReg = tempReg
					if redzoneCleared {
						return nil, fmt.Errorf("internal error: Red Zone was already cleared")
					}
					redzoneCleared = true
				}

				if useGOT {
					wrappers = append(wrappers, d.loadFromGOT(d.output, targetReg, symbol, section, redzoneCleared))
				} else {
					wrappers = append(wrappers, func(k func()) {
						d.output.WriteString(fmt.Sprintf("\tleaq\t%s(%%rip), %s\n", symbol, targetReg))
					})
				}
				changed = true
				break Args

			default:
				return nil, fmt.Errorf("Unknown section type %q", section)
			}

			if !changed && len(section) > 0 {
				panic("section was not handled")
			}
			section = ""

			argStr := ""
			if isIndirect {
				argStr += "*"
			}
			argStr += symbol
			argStr += offset

			for ; memRef != nil; memRef = memRef.next {
				argStr += d.contents(memRef)
			}

			for suffix := arg.next; suffix != nil; suffix = suffix.next {
				argStr += d.contents(suffix)
			}

			args = append(args, argStr)

		case ruleGOTAddress:
			if instructionName != "leaq" {
				return nil, fmt.Errorf("_GLOBAL_OFFSET_TABLE_ used outside of lea")
			}
			if i != 0 || len(argNodes) != 2 {
				return nil, fmt.Errorf("Load of _GLOBAL_OFFSET_TABLE_ address didn't have expected form")
			}
			if arg.next != nil {
				return nil, fmt.Errorf("unexpected argument suffix")
			}
			d.gotDeltaNeeded = true
			changed = true
			targetReg := d.contents(argNodes[1])
			args = append(args, ".Lboringssl_got_delta(%rip)")
			wrappers = append(wrappers, func(k func()) {
				k()
				d.output.WriteString(fmt.Sprintf("\taddq .Lboringssl_got_delta(%%rip), %s\n", targetReg))
			})

		case ruleGOTLocation:
			if instructionName != "movabsq" {
				return nil, fmt.Errorf("_GLOBAL_OFFSET_TABLE_ lookup didn't use movabsq")
			}
			if i != 0 || len(argNodes) != 2 {
				return nil, fmt.Errorf("movabs of _GLOBAL_OFFSET_TABLE_ didn't expected form")
			}
			if arg.next != nil {
				return nil, fmt.Errorf("unexpected argument suffix")
			}

			d.gotDeltaNeeded = true
			changed = true
			instructionName = "movq"
			assertNodeType(arg.up, ruleLocalSymbol)
			baseSymbol := d.mapLocalSymbol(d.contents(arg.up))
			targetReg := d.contents(argNodes[1])
			args = append(args, ".Lboringssl_got_delta(%rip)")
			wrappers = append(wrappers, func(k func()) {
				k()
				d.output.WriteString(fmt.Sprintf("\taddq $.Lboringssl_got_delta-%s, %s\n", baseSymbol, targetReg))
			})

		case ruleGOTSymbolOffset:
			if instructionName != "movabsq" {
				return nil, fmt.Errorf("_GLOBAL_OFFSET_TABLE_ offset didn't use movabsq")
			}
			if i != 0 || len(argNodes) != 2 {
				return nil, fmt.Errorf("movabs of _GLOBAL_OFFSET_TABLE_ offset didn't have expected form")
			}
			if arg.next != nil {
				return nil, fmt.Errorf("unexpected argument suffix")
			}

			assertNodeType(arg.up, ruleSymbolName)
			symbol := d.contents(arg.up)
			if strings.HasPrefix(symbol, ".L") {
				symbol = d.mapLocalSymbol(symbol)
			}
			targetReg := d.contents(argNodes[1])

			var prefix string
			isGOTOFF := strings.HasSuffix(d.contents(arg), "@GOTOFF")
			if isGOTOFF {
				prefix = "gotoff"
				d.gotOffOffsetsNeeded[symbol] = struct{}{}
			} else {
				prefix = "got"
				d.gotOffsetsNeeded[symbol] = struct{}{}
			}
			changed = true

			wrappers = append(wrappers, func(k func()) {
				// Even if one tries to use 32-bit GOT offsets, Clang's linker (at the time
				// of writing) emits 64-bit relocations anyway, so the following four bytes
				// get stomped. Thus we use 64-bit offsets.
				d.output.WriteString(fmt.Sprintf("\tmovq .Lboringssl_%s_%s(%%rip), %s\n", prefix, symbol, targetReg))
			})

		default:
			panic(fmt.Sprintf("unknown instruction argument type %q", rul3s[arg.pegRule]))
		}
	}

	if changed {
		d.writeCommentedNode(statement)
		replacement := "\t" + instructionName + "\t" + strings.Join(args, ", ") + "\n"
		if prefix != "" {
			replacement = "\t" + prefix + replacement
		}
		wrappers.do(func() {
			d.output.WriteString(replacement)
		})
	} else {
		d.writeNode(statement)
	}

	return statement, nil
}

func writeAarch64Function(w stringWriter, funcName string, writeContents func(stringWriter)) {
	w.WriteString(".p2align 2\n")
	w.WriteString(".hidden " + funcName + "\n")
	w.WriteString(".type " + funcName + ", @function\n")
	w.WriteString(funcName + ":\n")
	w.WriteString(".cfi_startproc\n")
	// We insert a landing pad (`bti c` instruction) unconditionally at the beginning of
	// every generated function so that they can be called indirectly (with `blr` or
	// `br x16/x17`). The instruction is encoded in the HINT space as `hint #34` and is
	// a no-op on machines or program states not supporting BTI (Branch Target Identification).
	// None of the generated function bodies call other functions (with bl or blr), so we only
	// insert a landing pad instead of signing and validating $lr with `paciasp` and `autiasp`.
	// Normally we would also generate a .note.gnu.property section to annotate the assembly
	// file as BTI-compatible, but if the input assembly files are BTI-compatible, they should
	// already have those sections so there is no need to add an extra one ourselves.
	w.WriteString("\thint #34 // bti c\n")
	writeContents(w)
	w.WriteString(".cfi_endproc\n")
	w.WriteString(".size " + funcName + ", .-" + funcName + "\n")
}

// emitModuleELF 는 ELF/Mach-O 대상에서 delocate 된 모듈 본문(.text 시작/끝 마커,
// redirector/accessor, GOT 보조 심볼, 무결성 해시 자리표시자)을 출력한다.
func (d *delocation) emitModuleELF(w stringWriter, inputs []inputFile, maxObservedFileNumber int, fileDirectivesContainMD5 bool) error {
	w.WriteString(".text\n")
	if d.processor == aarch64 {
		// Ensure the overall section to a page boundary. This allows us to safely emit ADRP
		// instructions. ADRP SYMBOL always emits a relocation because its offset is
		// (SYMBOL & ~4095) - (PC & ~4095). For this to be a link-independent constant, not
		// only must SYMBOL - PC be link-independent, so must both SYMBOL & 4095 and
		// PC & 4095.
		//
		// As of writing, there is already a page-aligned symbol in BCM, so this is a no-op,
		// but do not rely on this.
		w.WriteString(".p2align 12\n")
	}
	var fileTrailing string
	if fileDirectivesContainMD5 {
		fileTrailing = " md5 0x00000000000000000000000000000000"
	}
	w.WriteString(fmt.Sprintf(".file %d \"inserted_by_delocate.c\"%s\n", maxObservedFileNumber+1, fileTrailing))
	w.WriteString(fmt.Sprintf(".loc %d 1 0\n", maxObservedFileNumber+1))
	w.WriteString("BORINGSSL_bcm_text_start:\n")
	w.WriteString(localTargetName("BORINGSSL_bcm_text_start") + ":\n")

	for _, input := range inputs {
		if err := d.processInput(input); err != nil {
			return err
		}
	}

	w.WriteString(".text\n")
	w.WriteString(fmt.Sprintf(".loc %d 2 0\n", maxObservedFileNumber+1))
	w.WriteString("BORINGSSL_bcm_text_end:\n")
	w.WriteString(localTargetName("BORINGSSL_bcm_text_end") + ":\n")

	// Emit redirector functions. Each is a single jump instruction.
	var redirectorNames []string
	for name := range d.redirectors {
		redirectorNames = append(redirectorNames, name)
	}
	sort.Strings(redirectorNames)

	for _, name := range redirectorNames {
		redirector := d.redirectors[name]
		switch d.processor {
		case aarch64:
			writeAarch64Function(w, redirector, func(w stringWriter) {
				w.WriteString("\tb " + name + "\n")
			})

		case x86_64:
			w.WriteString(".type " + redirector + ", @function\n")
			w.WriteString(redirector + ":\n")
			w.WriteString("\tjmp\t" + name + "\n")
		}
	}

	var accessorNames []string
	for accessor := range d.bssAccessorsNeeded {
		accessorNames = append(accessorNames, accessor)
	}
	sort.Strings(accessorNames)

	// Emit BSS accessor functions. Each is a single LEA followed by RET.
	for _, name := range accessorNames {
		funcName := accessorName(name)
		target := d.bssAccessorsNeeded[name]

		switch d.processor {
		case x86_64:
			w.WriteString(".type " + funcName + ", @function\n")
			w.WriteString(funcName + ":\n")
			w.WriteString("\tleaq\t" + target + "(%rip), %rax\n\tret\n")

		case aarch64:
			writeAarch64Function(w, funcName, func(w stringWriter) {
				w.WriteString("\tadrp x0, " + target + "\n")
				w.WriteString("\tadd x0, x0, :lo12:" + target + "\n")
				w.WriteString("\tret\n")
			})
		}
	}

	switch d.processor {
	case aarch64:
		externalNames := sortedSet(d.gotExternalsNeeded)
		for _, symbol := range externalNames {
			writeAarch64Function(w, gotHelperName(symbol), func(w stringWriter) {
				w.WriteString("\tadrp x0, :got:" + symbol + "\n")
				w.WriteString("\tldr x0, [x0, :got_lo12:" + symbol + "]\n")
				w.WriteString("\tret\n")
			})
		}

	case x86_64:
		externalNames := sortedSet(d.gotExternalsNeeded)
		for _, name := range externalNames {
			parts := strings.SplitN(name, "@", 2)
			symbol, section := parts[0], parts[1]
			w.WriteString(".type " + symbol + "_" + section + "_external, @object\n")
			w.WriteString(".size " + symbol + "_" + section + "_external, 8\n")
			w.WriteString(symbol + "_" + section + "_external:\n")
			// Ideally this would be .quad foo@GOTPCREL, but clang's
			// assembler cannot emit a 64-bit GOTPCREL relocation. Instead,
			// we manually sign-extend the value, knowing that the GOT is
			// always at the end, thus foo@GOTPCREL has a positive value.
			w.WriteString("\t.long " + symbol + "@" + section + "\n")
			w.WriteString("\t.long 0\n")
		}

		if d.gotDeltaNeeded {
			w.WriteString(".Lboringssl_got_delta:\n")
			w.WriteString("\t.quad _GLOBAL_OFFSET_TABLE_-.Lboringssl_got_delta\n")
		}

		for _, name := range sortedSet(d.gotOffsetsNeeded) {
			w.WriteString(".Lboringssl_got_" + name + ":\n")
			w.WriteString("\t.quad " + name + "@GOT\n")
		}
		for _, name := range sortedSet(d.gotOffOffsetsNeeded) {
			w.WriteString(".Lboringssl_gotoff_" + name + ":\n")
			w.WriteString("\t.quad " + name + "@GOTOFF\n")
		}
	}

	w.WriteString(".type BORINGSSL_bcm_text_hash, @object\n")
	w.WriteString(".size BORINGSSL_bcm_text_hash, 32\n")
	w.WriteString("BORINGSSL_bcm_text_hash:\n")
	w.WriteString(localTargetName("BORINGSSL_bcm_text_hash") + ":\n")
	for _, b := range fipscommon.UninitHashValue {
		w.WriteString(".byte 0x" + strconv.FormatUint(uint64(b), 16) + "\n")
	}

	return nil
}
