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

// delocate performs several transformations of textual assembly code. See
// crypto/fipsmodule/FIPS.md for an overview.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"boringssl.googlesource.com/boringssl.git/util/ar"
)

// inputFile represents a textual assembly file.
type inputFile struct {
	path string
	// index is a unique identifier given to this file. It's used for
	// mapping local symbols.
	index int
	// isArchive indicates that the input should be processed as an ar
	// file.
	isArchive bool
	// contents contains the contents of the file.
	contents string
	// ast points to the head of the syntax tree.
	ast *node32
}

type stringWriter interface {
	io.Writer
	WriteString(string) (int, error)
}

type processorType int

const (
	x86_64 processorType = iota + 1
	aarch64
)

// objectFormat 는 입력 어셈블리의 오브젝트 파일 형식을 나타낸다. 형식에 따라
// 섹션/재배치 처리와 모듈 출력 방식이 달라진다.
type objectFormat int

const (
	// objectFormatELF 는 ELF/Mach-O (리눅스/macOS) 형식이다.
	objectFormatELF objectFormat = iota
	// objectFormatCOFF 는 COFF/PE (윈도우, x86_64-w64-windows-gnu) 형식이다.
	objectFormatCOFF
)

// delocation holds the state needed during a delocation operation.
type delocation struct {
	processor processorType
	format    objectFormat
	output    stringWriter
	// commentIndicator starts a comment, e.g. "//" or "#"
	commentIndicator string

	// symbols is the set of symbols defined in the module.
	symbols map[string]struct{}
	// redirectors maps from out-call symbol name to the name of a
	// redirector function for that symbol. E.g. “memcpy” ->
	// “bcm_redirector_memcpy”.
	redirectors map[string]string
	// bssAccessorsNeeded maps from a BSS symbol name to the symbol that
	// should be used to reference it. E.g. “P384_data_storage” ->
	// “P384_data_storage”.
	bssAccessorsNeeded map[string]string
	// gotExternalsNeeded is a set of symbol names for which we need
	// “delta” symbols: symbols that contain the offset from their location
	// to the memory in question.
	gotExternalsNeeded map[string]struct{}
	// gotDeltaNeeded is true if the code needs to load the value of
	// _GLOBAL_OFFSET_TABLE_.
	gotDeltaNeeded bool
	// gotOffsetsNeeded contains the symbols whose @GOT offsets are needed.
	gotOffsetsNeeded map[string]struct{}
	// gotOffOffsetsNeeded contains the symbols whose @GOTOFF offsets are needed.
	gotOffOffsetsNeeded map[string]struct{}

	// coffExternalPtrs is the set of external symbols (COFF 전용) whose 주소를
	// 모듈 밖 포인터(bcm_external_<sym>: .quad <sym>)를 통해 로드해야 하는
	// 경우의 집합이다. `leaq <external>(%rip)` 형태를 대체할 때 사용된다.
	coffExternalPtrs map[string]struct{}

	// coffSymbolRenames maps original symbol names to their per-file-unique
	// names (COFF 전용). 예: "se_handler" -> "vpaes_se_handler" (vpaes-x86_64.pl
	// 파일에서), "mul_handler" -> "mont_mul_handler" (x86_64-mont.pl).
	// perlasm이 생성하는 중복 가능한 심볼(SEH 핸들러 등)을 파일별로 개명한다.
	coffSymbolRenames map[string]string

	currentInput inputFile
}

func (d *delocation) contents(node *node32) string {
	return d.currentInput.contents[node.begin:node.end]
}

// writeNode writes out an AST node.
func (d *delocation) writeNode(node *node32) {
	if _, err := d.output.WriteString(d.contents(node)); err != nil {
		panic(err)
	}
}

func (d *delocation) writeCommentedNode(node *node32) {
	line := d.contents(node)
	if _, err := d.output.WriteString(d.commentIndicator + " WAS " + strings.TrimSpace(line) + "\n"); err != nil {
		panic(err)
	}
}

func locateError(err error, with *node32, in inputFile) error {
	posMap := translatePositions([]rune(in.contents), []int{int(with.begin)})
	var line int
	for _, pos := range posMap {
		line = pos.line
	}

	return fmt.Errorf("error while processing %q on line %d: %q", in.contents[with.begin:with.end], line, err)
}

func (d *delocation) processInput(input inputFile) (err error) {
	d.currentInput = input

	var origStatement *node32
	defer func() {
		if err := recover(); err != nil {
			panic(locateError(fmt.Errorf("%s", err), origStatement, input))
		}
	}()

	for statement := input.ast.up; statement != nil; statement = statement.next {
		assertNodeType(statement, ruleStatement)
		origStatement = statement

		node := skipWS(statement.up)
		if node == nil {
			d.writeNode(statement)
			continue
		}

		// COFF 형식에서 .def 지시자의 심볼을 개명한다.
		if d.format == objectFormatCOFF {
			line := d.contents(statement)
			if strings.HasPrefix(strings.TrimSpace(line), ".def") {
				// .def 지시자: ".def <symbol>; ..." 형식
				parts := strings.SplitN(line, ";", 2)
				if len(parts) >= 1 {
					defPart := strings.TrimSpace(parts[0])
					fields := strings.Fields(defPart)
					if len(fields) >= 2 {
						original := fields[1]
						renamed := d.mapCOFFSymbol(original)
						// AArch64 COFF 의 바레 'L' 로컬 라벨은 라벨/참조와 동일하게
						// 파일별로 개명해야 한다(그렇지 않으면 .def 가 정의되지 않은
						// 원본 이름을 선언해 미정의 심볼이 된다).
						if renamed == original && d.isAarch64LocalLabel(original) {
							renamed = d.mapLocalSymbol(original)
						}
						if renamed != original {
							// 개명된 이름으로 출력.
							newLine := strings.Replace(line, ".def\t"+original, ".def\t"+renamed, 1)
							newLine = strings.Replace(newLine, ".def "+original, ".def "+renamed, 1)
							d.writeCommentedNode(statement)
							d.output.WriteString(newLine)
							continue
						}
					}
				}
			}
		}

		switch node.pegRule {
		case ruleGlobalDirective, ruleComment, ruleLocationDirective:
			d.writeNode(statement)
		case ruleDirective:
			if d.format == objectFormatCOFF {
				statement, err = d.processDirectiveCOFF(statement, node.up)
			} else {
				statement, err = d.processDirective(statement, node.up)
			}
		case ruleLabelContainingDirective:
			statement, err = d.processLabelContainingDirective(statement, node.up)
		case rulePrefAlignDirective:
			statement, err = d.processPrefAlignDirective(statement, node.up)
		case ruleSymbolDefiningDirective:
			statement, err = d.processSymbolDefiningDirective(statement, node.up)
		case ruleLabel:
			statement, err = d.processLabel(statement, node.up)
		case ruleInstruction:
			switch d.processor {
			case x86_64:
				if d.format == objectFormatCOFF {
					statement, err = d.processCOFFInstruction(statement, node.up)
				} else {
					statement, err = d.processIntelInstruction(statement, node.up)
				}
			case aarch64:
				// aarch64 의 명령어 처리(심볼→로컬타깃, 외부분기→redirector,
				// adrp/:lo12: 로컬 주소적재, GOT 보조함수)는 오브젝트 형식과
				// 무관하다. ELF/COFF 모두 동일한 처리기를 쓰고, 형식별 차이는
				// 모듈 프레이밍(섹션 평탄화·마커·tail)에서만 다룬다.
				statement, err = d.processAarch64Instruction(statement, node.up)
			default:
				panic("unknown processor")
			}
		default:
			panic(fmt.Sprintf("unknown top-level statement type %q", rul3s[node.pegRule]))
		}

		if err != nil {
			return locateError(err, origStatement, input)
		}
	}

	return nil
}

func (d *delocation) processSymbolExpr(expr *node32, b *strings.Builder) bool {
	changed := false
	assertNodeType(expr, ruleSymbolExpr)

	for expr != nil {
		atom := expr.up
		assertNodeType(atom, ruleSymbolAtom)

		for term := atom.up; term != nil; term = skipWS(term.next) {
			if term.pegRule == ruleSymbolExpr {
				changed = d.processSymbolExpr(term, b) || changed
				continue
			}

			if term.pegRule != ruleLocalSymbol {
				b.WriteString(d.contents(term))
				continue
			}

			oldSymbol := d.contents(term)
			newSymbol := d.mapLocalSymbol(oldSymbol)
			if newSymbol != oldSymbol {
				changed = true
			}

			b.WriteString(newSymbol)
		}

		next := skipWS(atom.next)
		if next == nil {
			break
		}
		assertNodeType(next, ruleSymbolOperator)
		b.WriteString(d.contents(next))
		next = skipWS(next.next)
		assertNodeType(next, ruleSymbolExpr)
		expr = next
	}
	return changed
}

func (d *delocation) processLabelContainingDirective(statement, directive *node32) (*node32, error) {
	// The symbols within directives need to be mapped so that local
	// symbols in two different .s inputs don't collide.
	changed := false
	assertNodeType(directive, ruleLabelContainingDirectiveName)
	name := d.contents(directive)

	node := directive.next
	assertNodeType(node, ruleWS)

	node = node.next
	assertNodeType(node, ruleSymbolArgs)

	var args []string
	for node = skipWS(node.up); node != nil; node = skipWS(node.next) {
		assertNodeType(node, ruleSymbolArg)
		arg := node.up
		assertNodeType(arg, ruleSymbolExpr)

		var b strings.Builder
		changed = d.processSymbolExpr(arg, &b) || changed

		args = append(args, b.String())
	}

	if !changed {
		d.writeNode(statement)
	} else {
		d.writeCommentedNode(statement)
		d.output.WriteString("\t" + name + "\t" + strings.Join(args, ", ") + "\n")
	}

	return statement, nil
}

func (d *delocation) processPrefAlignDirective(statement, directive *node32) (*node32, error) {
	assertNodeType(directive, ruleWS)
	arg1 := directive.next
	assertNodeType(arg1, ruleArg)

	arg2 := skipWS(arg1.next)
	if arg2 == nil {
		d.writeNode(statement)
		return statement, nil
	}
	assertNodeType(arg2, ruleSymbolArg)

	arg3 := skipWS(arg2.next)
	assertNodeType(arg3, ruleArg)

	if arg3.next != nil {
		panic("unexpected nodes")
	}

	assertNodeType(arg2.up, ruleSymbolExpr)
	var b strings.Builder
	if d.processSymbolExpr(arg2.up, &b) {
		fmt.Fprintf(d.output, "\t.prefalign\t%s, %s, %s\n", d.contents(arg1), b.String(), d.contents(arg3))
	} else {
		d.writeNode(statement)
	}

	return statement, nil
}

func (d *delocation) processSymbolDefiningDirective(statement, directive *node32) (*node32, error) {
	changed := false

	var format string

	node := directive
	switch node.pegRule {
	case ruleSymbolDefiningDirectiveName:
		// .set a, b
		name := d.contents(node)
		format = fmt.Sprintf("\t%s\t%%s, %%s\n", name)
		node = node.next
		assertNodeType(node, ruleWS)
		node = node.next

	case ruleLocalSymbol, ruleSymbolName:
		// a = b
		format = "\t%s = %s\n"

	default:
		return nil, fmt.Errorf("unknown symbol defining directive type %q", rul3s[directive.pegRule])
	}

	symbol := d.contents(node)
	isLocal := node.pegRule == ruleLocalSymbol
	if isLocal {
		symbol = d.mapLocalSymbol(symbol)
		changed = true
	} else {
		assertNodeType(node, ruleSymbolName)
	}

	node = skipWS(node.next)
	assertNodeType(node, ruleSymbolArg)
	assertNodeType(node.up, ruleSymbolExpr)
	var b strings.Builder
	changed = d.processSymbolExpr(node.up, &b) || changed
	arg := b.String()

	if !changed {
		d.writeNode(statement)
	} else {
		d.writeCommentedNode(statement)
		fmt.Fprintf(d.output, format, symbol, arg)
	}

	if !isLocal {
		fmt.Fprintf(d.output, format, localTargetName(symbol), arg)
	}

	return statement, nil
}

func (d *delocation) processLabel(statement, label *node32) (*node32, error) {
	symbol := d.contents(label)

	switch label.pegRule {
	case ruleLocalLabel:
		d.output.WriteString(symbol + ":\n")
	case ruleLocalSymbol:
		// symbols need to be mapped so that local symbols from two
		// different .s inputs don't collide.
		d.output.WriteString(d.mapLocalSymbol(symbol) + ":\n")
	case ruleSymbolName:
		// AArch64 COFF 의 바레 'L' 로컬 라벨은 파일별 로컬 심볼로 매핑한다(.L 과 동일
		// 취급). 전역 라벨이 아니므로 localTargetName/원본 라벨을 내지 않는다.
		if d.isAarch64LocalLabel(symbol) {
			d.output.WriteString(d.mapLocalSymbol(symbol) + ":\n")
			return statement, nil
		}
		// COFF 형식에서는 중복 가능한 심볼(예: SEH 핸들러)을 파일별로 개명한다.
		mapped := symbol
		if d.format == objectFormatCOFF {
			mapped = d.mapCOFFSymbol(symbol)
		}
		// mapped 이름이 원본과 다르면 원본을 주석 처리하고 mapped 라벨을 사용.
		if mapped != symbol {
			d.writeCommentedNode(statement)
			d.output.WriteString(mapped + ":\n")
			d.output.WriteString(localTargetName(mapped) + ":\n")
		} else {
			d.output.WriteString(localTargetName(mapped) + ":\n")
			d.writeNode(statement)
		}
	default:
		return nil, fmt.Errorf("unknown label type %q", rul3s[label.pegRule])
	}

	return statement, nil
}

// instructionArgs collects all the arguments to an instruction.
func instructionArgs(node *node32) (argNodes []*node32) {
	for node = skipWS(node); node != nil; node = skipWS(node.next) {
		assertNodeType(node, ruleInstructionArg)
		argNodes = append(argNodes, node.up)
	}

	return argNodes
}

func (d *delocation) gatherOffsets(symRef *node32, offsets string) (*node32, string) {
	for symRef != nil && symRef.pegRule == ruleOffset {
		offset := d.contents(symRef)
		if offset[0] != '+' && offset[0] != '-' {
			offset = "+" + offset
		}
		offsets = offsets + offset
		symRef = symRef.next
	}
	return symRef, offsets
}

func (d *delocation) parseMemRef(memRef *node32) (symbol, offset, section string, didChange, symbolIsLocal bool, nextRef *node32) {
	if memRef.pegRule != ruleSymbolRef {
		return "", "", "", false, false, memRef
	}

	symRef := memRef.up
	nextRef = memRef.next

	// (Offset* '+')?
	symRef, offset = d.gatherOffsets(symRef, offset)

	// (LocalSymbol / SymbolName)
	symbol = d.contents(symRef)
	if symRef.pegRule == ruleLocalSymbol {
		symbolIsLocal = true
		mapped := d.mapLocalSymbol(symbol)
		if mapped != symbol {
			symbol = mapped
			didChange = true
		}
	}
	symRef = symRef.next

	// Offset*
	symRef, offset = d.gatherOffsets(symRef, offset)

	// ('@' Section / Offset*)?
	if symRef != nil {
		assertNodeType(symRef, ruleSection)
		section = d.contents(symRef)
		symRef = symRef.next

		symRef, offset = d.gatherOffsets(symRef, offset)
	}

	if symRef != nil {
		panic(fmt.Sprintf("unexpected token in SymbolRef: %q", rul3s[symRef.pegRule]))
	}

	return
}

/* Intel */

type instructionType int

const (
	instrPush instructionType = iota
	instrMove
	// instrTransformingMove is essentially a move, but it performs some
	// transformation of the data during the process.
	instrTransformingMove
	instrJump
	instrConditionalMove
	// instrCombine merges the source and destination in some fashion, for example
	// a 2-operand bitwise operation.
	instrCombine
	// instrMemoryVectorCombine is similar to instrCombine, but the source
	// register must be a memory reference and the destination register
	// must be a vector register.
	instrMemoryVectorCombine
	// instrThreeArg merges two sources into a destination in some fashion.
	instrThreeArg
	// instrCompare takes two arguments and writes outputs to the flags register.
	instrCompare
	instrOther
)

func classifyInstruction(instr string, args []*node32) instructionType {
	switch instr {
	case "push", "pushq":
		if len(args) == 1 {
			return instrPush
		}

	case "mov", "movq", "vmovq", "movsd", "vmovsd":
		if len(args) == 2 {
			return instrMove
		}

	case "cmovneq", "cmoveq":
		if len(args) == 2 {
			return instrConditionalMove
		}

	case "call", "callq", "jmp", "jo", "jno", "js", "jns", "je", "jz", "jne", "jnz", "jb", "jnae", "jc", "jnb", "jae", "jnc", "jbe", "jna", "ja", "jnbe", "jl", "jnge", "jge", "jnl", "jle", "jng", "jg", "jnle", "jp", "jpe", "jnp", "jpo":
		if len(args) == 1 {
			return instrJump
		}

	case "orq", "andq", "xorq":
		if len(args) == 2 {
			return instrCombine
		}

	case "cmpq":
		if len(args) == 2 {
			return instrCompare
		}

	case "sarxq", "shlxq", "shrxq":
		if len(args) == 3 {
			return instrThreeArg
		}

	case "vpbroadcastq":
		if len(args) == 2 {
			return instrTransformingMove
		}

	case "movlps", "movhps":
		if len(args) == 2 {
			return instrMemoryVectorCombine
		}
	}

	return instrOther
}

func push(w stringWriter) wrapperFunc {
	return func(k func()) {
		w.WriteString("\tpushq %rax\n")
		k()
		w.WriteString("\txchg %rax, (%rsp)\n")
	}
}

func compare(w stringWriter, instr, a, b string) wrapperFunc {
	return func(k func()) {
		k()
		w.WriteString(fmt.Sprintf("\t%s %s, %s\n", instr, a, b))
	}
}

func saveFlags(w stringWriter, redzoneCleared bool) wrapperFunc {
	return func(k func()) {
		if !redzoneCleared {
			w.WriteString("\tleaq -128(%rsp), %rsp\n") // Clear the red zone.
			defer w.WriteString("\tleaq 128(%rsp), %rsp\n")
		}
		w.WriteString("\tpushfq\n")
		k()
		w.WriteString("\tpopfq\n")
	}
}

func saveRegister(w stringWriter, avoidRegs []string) (wrapperFunc, string) {
	candidates := []string{"%rax", "%rbx", "%rcx", "%rdx"}

	var reg string
NextCandidate:
	for _, candidate := range candidates {
		for _, avoid := range avoidRegs {
			if candidate == avoid {
				continue NextCandidate
			}
		}

		reg = candidate
		break
	}

	if len(reg) == 0 {
		panic("too many excluded registers")
	}

	return func(k func()) {
		w.WriteString("\tleaq -128(%rsp), %rsp\n") // Clear the red zone.
		w.WriteString("\tpushq " + reg + "\n")
		k()
		w.WriteString("\tpopq " + reg + "\n")
		w.WriteString("\tleaq 128(%rsp), %rsp\n")
	}, reg
}

func moveTo(w stringWriter, target string, isAVX bool, source string) wrapperFunc {
	return func(k func()) {
		k()
		prefix := ""
		if isAVX {
			prefix = "v"
		}
		w.WriteString("\t" + prefix + "movq " + source + ", " + target + "\n")
	}
}

func finalTransform(w stringWriter, transformInstruction, reg string) wrapperFunc {
	return func(k func()) {
		k()
		w.WriteString("\t" + transformInstruction + " " + reg + ", " + reg + "\n")
	}
}

func combineOp(w stringWriter, instructionName, source, dest string) wrapperFunc {
	return func(k func()) {
		k()
		w.WriteString("\t" + instructionName + " " + source + ", " + dest + "\n")
	}
}

func threeArgCombineOp(w stringWriter, instructionName, source1, source2, dest string) wrapperFunc {
	return func(k func()) {
		k()
		w.WriteString("\t" + instructionName + " " + source1 + ", " + source2 + ", " + dest + "\n")
	}
}

func memoryVectorCombineOp(w stringWriter, instructionName, source, dest string) wrapperFunc {
	return func(k func()) {
		k()
		// These instructions can only read from memory, so push
		// tempReg and read from the stack. Note we assume the red zone
		// was previously cleared by saveRegister().
		w.WriteString("\tpushq " + source + "\n")
		w.WriteString("\t" + instructionName + " (%rsp), " + dest + "\n")
		w.WriteString("\tleaq 8(%rsp), %rsp\n")
	}
}

func isValidLEATarget(reg string) bool {
	return !strings.HasPrefix(reg, "%xmm") && !strings.HasPrefix(reg, "%ymm") && !strings.HasPrefix(reg, "%zmm")
}

func undoConditionalMove(w stringWriter, instr string) wrapperFunc {
	var invertedCondition string

	switch instr {
	case "cmoveq":
		invertedCondition = "ne"
	case "cmovneq":
		invertedCondition = "e"
	default:
		panic(fmt.Sprintf("don't know how to handle conditional move instruction %q", instr))
	}

	return func(k func()) {
		w.WriteString("\tj" + invertedCondition + " 999f\n")
		k()
		w.WriteString("999:\n")
	}
}

func (d *delocation) isRIPRelative(node *node32) bool {
	return node != nil && node.pegRule == ruleBaseIndexScale && d.contents(node) == "(%rip)"
}

func (d *delocation) handleBSS(statement *node32) (*node32, error) {
	lastStatement := statement
	for statement = statement.next; statement != nil; lastStatement, statement = statement, statement.next {
		node := skipWS(statement.up)
		if node == nil {
			d.writeNode(statement)
			continue
		}

		switch node.pegRule {
		case ruleGlobalDirective, ruleComment, ruleInstruction, ruleLocationDirective:
			d.writeNode(statement)

		case ruleDirective:
			directive := node.up
			assertNodeType(directive, ruleDirectiveName)
			directiveName := d.contents(directive)
			if directiveName == "text" || directiveName == "section" || directiveName == "data" {
				return lastStatement, nil
			}
			d.writeNode(statement)

		case ruleLabel:
			label := node.up
			d.writeNode(statement)

			if label.pegRule != ruleLocalSymbol {
				symbol := d.contents(label)
				localSymbol := localTargetName(symbol)
				d.output.WriteString(fmt.Sprintf("\n%s:\n", localSymbol))

				d.bssAccessorsNeeded[symbol] = localSymbol
			}

		case ruleLabelContainingDirective:
			var err error
			statement, err = d.processLabelContainingDirective(statement, node.up)
			if err != nil {
				return nil, err
			}

		case ruleSymbolDefiningDirective:
			var err error
			statement, err = d.processSymbolDefiningDirective(statement, node.up)
			if err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("unknown BSS statement type %q in %q", rul3s[node.pegRule], d.contents(statement))
		}
	}

	return lastStatement, nil
}

func transform(w stringWriter, inputs []inputFile) error {
	// Detect the processor and object format up front; symbol gathering below
	// needs them to recognise AArch64's bare 'L' local-label convention.
	processor := x86_64
	if len(inputs) > 0 {
		processor = detectProcessor(inputs[0])
	}
	format := objectFormatELF
	if len(inputs) > 0 {
		format = detectFormat(inputs[0])
	}
	// isLocalLabelName reports whether a label/symbol is file-local and thus
	// must not be treated as a (unique) module-global symbol.
	isLocalLabelName := func(name string) bool {
		return processor == aarch64 && format == objectFormatCOFF &&
			len(name) >= 2 && name[0] == 'L'
	}

	// symbols contains all defined symbols.
	symbols := make(map[string]struct{})
	// fileNumbers is the set of IDs seen in .file directives.
	fileNumbers := make(map[int]struct{})
	// maxObservedFileNumber contains the largest seen file number in a
	// .file directive. Zero is not a valid number.
	maxObservedFileNumber := 0
	// fileDirectivesContainMD5 is true if the compiler is outputting MD5
	// checksums in .file directives. If it does so, then this script needs
	// to match that behaviour otherwise warnings result.
	fileDirectivesContainMD5 := false

	for _, input := range inputs {
		forEachPath(input.ast.up, func(node *node32) {
			symbol := input.contents[node.begin:node.end]
			// AArch64 COFF bare 'L' labels are file-local; they are mapped
			// per-file (like ".L") and must not be registered as module-global
			// symbols (which would falsely collide across input files).
			if isLocalLabelName(symbol) {
				return
			}
			if _, ok := symbols[symbol]; ok {
				panic(fmt.Sprintf("Duplicate symbol found: %q in %q", symbol, input.path))
			}
			symbols[symbol] = struct{}{}
		}, ruleStatement, ruleLabel, ruleSymbolName)

		// Some directives also define symbols.
		forEachPath(input.ast.up, func(node *node32) {
			node = skipWS(node.next)
			if node.pegRule == ruleLocalSymbol {
				return
			}
			assertNodeType(node, ruleSymbolName)
			symbol := input.contents[node.begin:node.end]
			// Allow duplicates. A symbol may be set multiple times with .set.
			symbols[symbol] = struct{}{}
		}, ruleStatement, ruleSymbolDefiningDirective, ruleSymbolDefiningDirectiveName)

		forEachPath(input.ast.up, func(node *node32) {
			assertNodeType(node, ruleLocationDirective)
			directive := input.contents[node.begin:node.end]
			if !strings.HasPrefix(directive, ".file") {
				return
			}
			parts := strings.Fields(directive)
			if len(parts) == 2 {
				// This is a .file directive with just a
				// filename. Clang appears to generate just one
				// of these at the beginning of the output for
				// the compilation unit. Ignore it.
				return
			}
			fileNo, err := strconv.Atoi(parts[1])
			if err != nil {
				panic(fmt.Sprintf("Failed to parse file number from .file: %q", directive))
			}

			if _, ok := fileNumbers[fileNo]; ok {
				panic(fmt.Sprintf("Duplicate file number %d observed", fileNo))
			}
			fileNumbers[fileNo] = struct{}{}

			if fileNo > maxObservedFileNumber {
				maxObservedFileNumber = fileNo
			}

			for _, token := range parts[2:] {
				if token == "md5" {
					fileDirectivesContainMD5 = true
				}
			}
		}, ruleStatement, ruleLocationDirective)
	}
	// processor and format were detected at the top of transform.

	commentIndicator := "#"
	if processor == aarch64 {
		commentIndicator = "//"
	}

	// These symbols will be synthesized below as global symbols. Mark them as
	// known, so we will rewrite them to their local target name and avoid a
	// relocation.
	symbols["BORINGSSL_bcm_text_start"] = struct{}{}
	symbols["BORINGSSL_bcm_text_end"] = struct{}{}
	symbols["BORINGSSL_bcm_text_hash"] = struct{}{}

	d := &delocation{
		symbols:             symbols,
		processor:           processor,
		format:              format,
		commentIndicator:    commentIndicator,
		output:              w,
		redirectors:         make(map[string]string),
		bssAccessorsNeeded:  make(map[string]string),
		gotExternalsNeeded:  make(map[string]struct{}),
		gotOffsetsNeeded:    make(map[string]struct{}),
		gotOffOffsetsNeeded: make(map[string]struct{}),
		coffExternalPtrs:    make(map[string]struct{}),
		coffSymbolRenames:   make(map[string]string),
	}

	if d.format == objectFormatCOFF {
		return d.emitModuleCOFF(w, inputs, maxObservedFileNumber, fileDirectivesContainMD5)
	}
	return d.emitModuleELF(w, inputs, maxObservedFileNumber, fileDirectivesContainMD5)
}

// preprocess runs source through the C preprocessor.
func preprocess(cppCommand []string, path string) ([]byte, error) {
	var args []string
	args = append(args, cppCommand...)
	args = append(args, path)

	cpp := exec.Command(args[0], args[1:]...)
	cpp.Stderr = os.Stderr
	var result bytes.Buffer
	cpp.Stdout = &result

	if err := cpp.Run(); err != nil {
		return nil, err
	}

	return result.Bytes(), nil
}

func parseInputs(inputs []inputFile, cppCommand []string) error {
	for i, input := range inputs {
		var contents string

		if input.isArchive {
			arFile, err := os.Open(input.path)
			if err != nil {
				return err
			}
			defer arFile.Close()

			ar, err := ar.ParseAR(arFile)
			if err != nil {
				return err
			}

			if len(ar) != 1 {
				return fmt.Errorf("expected one file in archive, but found %d", len(ar))
			}

			for _, c := range ar {
				contents = string(c)
			}
		} else {
			var inBytes []byte
			var err error

			if len(cppCommand) > 0 {
				inBytes, err = preprocess(cppCommand, input.path)
			} else {
				inBytes, err = os.ReadFile(input.path)
			}
			if err != nil {
				return err
			}

			contents = string(inBytes)
		}

		asm := Asm{Buffer: contents, Pretty: true}
		asm.Init()
		if err := asm.Parse(); err != nil {
			return fmt.Errorf("error while parsing %q: %s", input.path, err)
		}
		ast := asm.AST()

		inputs[i].contents = contents
		inputs[i].ast = ast
	}

	return nil
}

// includePathFromHeaderFilePath returns an include directory path based on the
// path of a specific header file. It walks up the path and assumes that the
// include files are rooted in a directory called "openssl".
func includePathFromHeaderFilePath(path string) (string, error) {
	dir := path
	for {
		var file string
		dir, file = filepath.Split(dir)

		if file == "openssl" {
			return dir, nil
		}

		if len(dir) == 0 {
			break
		}
		dir = dir[:len(dir)-1]
	}

	return "", fmt.Errorf("failed to find 'openssl' path element in header file path %q", path)
}

func main() {
	// The .a file, if given, is expected to be an archive of textual
	// assembly sources. That's odd, but CMake really wants to create
	// archive files so it's the only way that we can make it work.
	arInput := flag.String("a", "", "Path to a .a file containing assembly sources")
	outFile := flag.String("o", "", "Path to output assembly")
	ccPath := flag.String("cc", "", "Path to the C compiler for preprocessing inputs")
	ccFlags := flag.String("cc-flags", "", "Flags for the C compiler when preprocessing")

	flag.Parse()

	if len(*outFile) == 0 {
		fmt.Fprintf(os.Stderr, "Must give argument to -o.\n")
		os.Exit(1)
	}

	var inputs []inputFile
	if len(*arInput) > 0 {
		inputs = append(inputs, inputFile{
			path:      *arInput,
			index:     0,
			isArchive: true,
		})
	}

	includePaths := make(map[string]struct{})

	for i, path := range flag.Args() {
		if len(path) == 0 {
			continue
		}

		// Header files are not processed but their path is remembered
		// and passed as -I arguments when invoking the preprocessor.
		if strings.HasSuffix(path, ".h") {
			dir, err := includePathFromHeaderFilePath(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err)
				os.Exit(1)
			}
			includePaths[dir] = struct{}{}
			continue
		}

		inputs = append(inputs, inputFile{
			path:  path,
			index: i + 1,
		})
	}

	var cppCommand []string
	if len(*ccPath) > 0 {
		cppCommand = append(cppCommand, *ccPath)
		cppCommand = append(cppCommand, strings.Fields(*ccFlags)...)
		// Some of ccFlags might be superfluous when running the
		// preprocessor, but we don't want the compiler complaining that
		// "argument unused during compilation".
		cppCommand = append(cppCommand, "-Wno-unused-command-line-argument")

		for includePath := range includePaths {
			cppCommand = append(cppCommand, "-I"+includePath)
		}

		// -E requests only preprocessing.
		cppCommand = append(cppCommand, "-E")
	}

	if err := parseInputs(inputs, cppCommand); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	out, err := os.OpenFile(*outFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer out.Close()

	if err := transform(out, inputs); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func forEachPath(node *node32, cb func(*node32), rules ...pegRule) {
	if node == nil {
		return
	}

	if len(rules) == 0 {
		cb(node)
		return
	}

	rule := rules[0]
	childRules := rules[1:]

	for ; node != nil; node = node.next {
		if node.pegRule != rule {
			continue
		}

		if len(childRules) == 0 {
			cb(node)
		} else {
			forEachPath(node.up, cb, childRules...)
		}
	}
}

func skipNodes(node *node32, ruleToSkip pegRule) *node32 {
	for ; node != nil && node.pegRule == ruleToSkip; node = node.next {
	}
	return node
}

func skipWS(node *node32) *node32 {
	return skipNodes(node, ruleWS)
}

func assertNodeType(node *node32, expected pegRule) {
	if rule := node.pegRule; rule != expected {
		panic(fmt.Sprintf("node was %q, but wanted %q", rul3s[rule], rul3s[expected]))
	}
}

type wrapperFunc func(func())

type wrapperStack []wrapperFunc

func (w *wrapperStack) do(baseCase func()) {
	if len(*w) == 0 {
		baseCase()
		return
	}

	wrapper := (*w)[0]
	*w = (*w)[1:]
	wrapper(func() { w.do(baseCase) })
}

// isQuotedSymbol reports whether name is a COFF/MSVC quoted symbol ("....").
func isQuotedSymbol(name string) bool {
	return len(name) >= 2 && name[0] == '"' && name[len(name)-1] == '"'
}

// decorateSymbol wraps a symbol name with a prefix and suffix. For MSVC/COFF
// quoted symbols ("?foo@@..."), the prefix/suffix are inserted *inside* the
// quotes so the result is still a single valid quoted symbol. For ordinary
// (GNU) names it is just prefix+name+suffix.
func decorateSymbol(prefix, name, suffix string) string {
	if isQuotedSymbol(name) {
		return "\"" + prefix + name[1:len(name)-1] + suffix + "\""
	}
	return prefix + name + suffix
}

// localTargetName returns the name of the local target label for a global
// symbol named name.
func localTargetName(name string) string {
	return decorateSymbol(".L", name, "_local_target")
}

// isAarch64LocalLabel reports whether name uses AArch64's bare 'L' private
// (local) label prefix. clang's assembler treats 'L'-prefixed symbols as
// file-local (temporary) on AArch64 COFF/Mach-O, unlike ELF's ".L". The
// perlasm-generated *-armv8-win.S files use this convention (e.g. "Loop",
// "LK256"), so when delocate flattens several of them into one unit these
// per-file labels would otherwise collide. We map them per-file like ".L"
// labels. (ELF AArch64 uses ".L", so this only applies to COFF.)
func (d *delocation) isAarch64LocalLabel(name string) bool {
	return d.processor == aarch64 && d.format == objectFormatCOFF &&
		len(name) >= 2 && name[0] == 'L'
}

func isSynthesized(symbol string) bool {
	return strings.HasSuffix(symbol, "_bss_get")
}

func redirectorName(symbol string) string {
	return decorateSymbol("bcm_redirector_", symbol, "")
}

// sectionType returns the type of a section. I.e. a section called “.text.foo”
// is a “.text” section.
func sectionType(section string) (string, bool) {
	if len(section) == 0 || section[0] != '.' {
		return "", false
	}

	i := strings.Index(section[1:], ".")
	if i != -1 {
		section = section[:i+1]
	}

	if strings.HasPrefix(section, ".debug_") {
		return ".debug", true
	}

	return section, true
}

// accessorName returns the name of the accessor function for a BSS symbol
// named name.
func accessorName(name string) string {
	return decorateSymbol("", name, "_bss_get")
}

func (d *delocation) mapLocalSymbol(symbol string) string {
	if d.currentInput.index == 0 {
		return symbol
	}
	return symbol + "_BCM_" + strconv.Itoa(d.currentInput.index)
}

// shouldRenameCOFFSymbol은 COFF에서 파일별로 유일한 이름으로 개명해야 하는
// 심볼인지 판단한다. perlasm이 생성하는 SEH 핸들러 같은 중복 가능한 심볼들을
// 감지한다. 예: *_handler 패턴.
func shouldRenameCOFFSymbol(symbol string) bool {
	// SEH 핸들러 심볼: se_handler, mul_handler, sqr_handler, 등
	return strings.HasSuffix(symbol, "_handler")
}

// mapCOFFSymbol은 COFF에서 필요시 심볼을 파일별로 유일한 이름으로 개명하고,
// 이미 개명된 경우 매핑된 이름을 반환한다. 같은 심볼이 여러 번 나타날 때
// 일관성 있게 개명된 이름을 반환한다.
func (d *delocation) mapCOFFSymbol(symbol string) string {
	if d.format != objectFormatCOFF || d.currentInput.index == 0 {
		return symbol
	}
	if !shouldRenameCOFFSymbol(symbol) {
		return symbol
	}

	// 이미 개명되었으면 매핑된 이름 반환.
	if renamed, ok := d.coffSymbolRenames[symbol]; ok {
		return renamed
	}

	// 새로운 개명: 파일 이름의 base를 접두사로 사용하거나, 파일 index 사용.
	// 예: se_handler (from vpaes-x86_64.pl) -> vpaes_se_handler
	// 간단하게는 파일 index를 사용할 수도 있지만, 가독성을 위해 파일 이름 기반이 좋다.
	// 현재는 파일 index만 사용하되, 미래에 파일 이름 기반으로 개선 가능.
	renamed := symbol + "_BCM_" + strconv.Itoa(d.currentInput.index)
	d.coffSymbolRenames[symbol] = renamed
	return renamed
}

func detectProcessor(input inputFile) processorType {
	for statement := input.ast.up; statement != nil; statement = statement.next {
		node := skipNodes(statement.up, ruleWS)
		if node == nil || node.pegRule != ruleInstruction {
			continue
		}

		instruction := node.up
		instructionName := input.contents[instruction.begin:instruction.end]

		switch instructionName {
		case "movq", "call", "leaq":
			return x86_64
		case "str", "bl", "ldr", "st1":
			return aarch64
		}
	}

	panic("processed entire input and didn't recognise any instructions.")
}

// detectFormat 는 입력 어셈블리의 오브젝트 파일 형식을 추정한다. COFF(윈도우)
// 어셈블리는 `.def`/`.seh_proc`/`.secrel32` 같은 형식 고유 디렉티브를 사용하므로
// 이를 발견하면 COFF 로 판정하고, 그렇지 않으면 ELF/Mach-O 로 본다.
func detectFormat(input inputFile) objectFormat {
	for statement := input.ast.up; statement != nil; statement = statement.next {
		node := skipNodes(statement.up, ruleWS)
		if node == nil || node.pegRule != ruleDirective {
			continue
		}
		directive := node.up
		if directive == nil || directive.pegRule != ruleDirectiveName {
			continue
		}
		switch input.contents[directive.begin:directive.end] {
		case "def", "seh_proc", "secrel32", "secidx", "linkonce":
			return objectFormatCOFF
		}
	}
	return objectFormatELF
}

func sortedSet(m map[string]struct{}) []string {
	ret := make([]string, 0, len(m))
	for key := range m {
		ret = append(ret, key)
	}
	sort.Strings(ret)
	return ret
}
