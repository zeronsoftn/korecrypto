// Copyright 2025 The BoringSSL Authors
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

// COFF/PE (윈도우, x86_64-w64-windows-gnu) 형식 어셈블리에 대한 delocate 처리.
// 공통 코드는 delocate.go 에, ELF/Mach-O 처리는 delocate_elf.go 에 있다.
//
// 설계 요약:
//   - 모듈의 모든 코드/읽기전용 데이터(.text$*, .rdata*)를 하나의 연속된 .text 로
//     평탄화하고, BORINGSSL_bcm_text_start ~ _end 마커로 감싼다. 해시 대상 영역
//     안에서의 참조는 모두 영역 내부 상대(PC-relative) 참조가 되도록 만든다.
//   - 모듈 내부 전역 심볼 참조는 .L<sym>_local_target 로컬 레이블로 바꿔서 COFF
//     COMDAT 병합으로 모듈 밖 사본이 선택되는 것을 막는다.
//   - 외부 호출(call/jmp)은 영역 밖(꼬리)에 두는 redirector 썽크를 통해 우회한다.
//   - 외부 주소 적재(leaq <external>(%rip))는 영역 밖 포인터(bcm_external_<sym>)에서
//     주소를 읽어오도록 movq 로 바꾼다.
//   - clang 이 만든 .refptr.<sym> 간접 참조는 대상이 모듈 내부 심볼이면 직접
//     leaq 로 바꾼다.
//   - BSS 변수는 공통 handleBSS 로 접근자(<sym>_bss_get)를 통해 영역 밖에서 접근.
//   - SEH(.seh_*), 심볼 메타(.def/.scl/.endef), 디버그(.debug_*), .ctors/.dtors,
//     .drectve, .refptr.* 섹션은 그대로 통과시킨다(해시 영역 밖).
package main

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"boringssl.googlesource.com/boringssl.git/util/fipstools/fipscommon"
)

// coffSectionCategory 는 COFF 섹션 이름을 처리 범주로 분류한다. COMDAT 접미사
// (".text$foo" 의 "$foo")는 제거하고 기준 이름으로 판단한다.
func coffSectionCategory(section string) string {
	// .refptr 보조 섹션(.rdata$.refptr.<sym>)은 절대 주소(.quad <sym>)를 담고
	// 있으므로 해시 .text 로 옮기면 안 된다. 별도 섹션으로 통과시킨다.
	if strings.Contains(section, ".refptr.") {
		return "passthrough"
	}

	base := section
	if i := strings.IndexByte(base, '$'); i >= 0 {
		base = base[:i]
	}

	switch base {
	case ".text", ".rodata", ".rdata":
		// 코드와 읽기전용 데이터는 모두 모듈 .text 로 평탄화한다.
		return "text"
	case ".bss":
		return "bss"
	case ".data":
		// FIPS 모듈에는 가변 .data 가 있어선 안 된다.
		return "data"
	default:
		// .xdata/.pdata/.ctors/.dtors/.drectve/.debug_* 등은 해시 영역 밖의
		// 별도 섹션으로 그대로 둔다.
		return "passthrough"
	}
}

func (d *delocation) processDirectiveCOFF(statement, directive *node32) (*node32, error) {
	assertNodeType(directive, ruleDirectiveName)
	directiveName := d.contents(directive)

	var args []string
	forEachPath(directive, func(arg *node32) {
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
	case "comm", "lcomm":
		if len(args) < 1 {
			return nil, errors.New("comm directive has no arguments")
		}
		d.bssAccessorsNeeded[args[0]] = args[0]
		d.writeNode(statement)

	case "data":
		return nil, errors.New(".data section found in module")

	case "def":
		// .def 지시자(COFF 심볼 정의): 첫 인자가 심볼 이름. SEH 핸들러 같은
		// 중복 가능한 심볼을 파일별로 개명한다.
		// 형식: .def <symbol>; .scl <scl>; .type 32; .endef
		if len(args) > 0 {
			original := args[0]
			renamed := d.mapCOFFSymbol(original)
			if renamed != original {
				// 원본 문자열에서 첫 번째 symbol을 개명된 것으로 치환.
				origLine := d.contents(statement)
				// ".def\t<original>;" 부분을 ".def\t<renamed>;"로 치환.
				newLine := strings.Replace(origLine, ".def\t"+original+";", ".def\t"+renamed+";", 1)
				d.writeCommentedNode(statement)
				d.output.WriteString(newLine)
				return statement, nil
			}
		}
		d.writeNode(statement)

	case "type":
		// .type 지시자: 첫 인자가 심볼 이름. SEH 핸들러 같은 중복 가능한 심볼을
		// 파일별로 개명한다.
		if len(args) > 0 {
			original := args[0]
			renamed := d.mapCOFFSymbol(original)
			if renamed != original {
				mapped := []string{renamed}
				mapped = append(mapped, args[1:]...)
				for i := range mapped {
					mapped[i] = coffQuoteSymbol(mapped[i])
				}
				d.writeCommentedNode(statement)
				d.output.WriteString("\t.type\t" + strings.Join(mapped, ",") + "\n")
				return statement, nil
			}
		}
		d.writeNode(statement)

	case "size":
		// .size 지시자: "symbol, .-symbol" 형태. symbol을 개명한다.
		if len(args) >= 1 {
			original := args[0]
			renamed := d.mapCOFFSymbol(original)
			if renamed != original {
				mapped := []string{renamed}
				// 두 번째 인자("."-symbol)도 개명된 이름으로 업데이트.
				if len(args) > 1 {
					arg2 := args[1]
					// ".-<symbol>" 형태를 ".-<renamed>" 형태로 변환.
					if strings.HasSuffix(arg2, original) && strings.Contains(arg2, original) {
						arg2 = strings.ReplaceAll(arg2, original, renamed)
					}
					mapped = append(mapped, arg2)
				}
				d.writeCommentedNode(statement)
				d.output.WriteString("\t.size\t" + strings.Join(mapped, ", ") + "\n")
				return statement, nil
			}
		}
		d.writeNode(statement)

	case "rva", "secrel32", "secidx":
		// SEH(.pdata/.xdata) 와 디버그 정보는 .rva/.secrel32/.secidx 로 .text 안의
		// 로컬 레이블(.L...)을 참조한다. delocate 는 파일별로 .L 심볼을 _BCM_n
		// 으로 개명하므로, 이런 참조의 .L 인자도 동일하게 개명해야 미정의 심볼이
		// 되지 않는다. 또한 COFF에서는 중복 가능한 전역 심볼(SEH 핸들러)도 개명한다.
		changed := false
		mapped := make([]string, len(args))
		for i, a := range args {
			if strings.HasPrefix(a, ".L") {
				m := d.mapLocalSymbol(a)
				if m != a {
					changed = true
				}
				mapped[i] = m
			} else if strings.HasPrefix(a, ".") {
				// 다른 점(.) 시작 심볼도 그대로 둔다(예: .Lenc_key_body).
				mapped[i] = coffQuoteSymbol(a)
			} else {
				// 비-.L 인자도 COFF 심볼 개명 적용.
				m := d.mapCOFFSymbol(a)
				if m != a {
					changed = true
				}
				mapped[i] = coffQuoteSymbol(m)
			}
		}
		if changed {
			d.output.WriteString("\t." + directiveName + "\t" + strings.Join(mapped, ", ") + "\n")
		} else {
			d.writeNode(statement)
		}

	case "bss":
		d.writeNode(statement)
		return d.handleBSS(statement)

	case "section":
		if len(args) == 0 {
			return nil, errors.New(".section directive has no arguments")
		}
		section := args[0]
		switch coffSectionCategory(section) {
		case "text":
			// .rodata/.rdata 와 .text$* 를 모두 .text 로 옮긴다.
			d.writeCommentedNode(statement)
			d.output.WriteString(".text\n")
			// COMDAT(`discard`) 섹션을 단일 .text 로 평탄화하면 COMDAT 선택
			// 의미가 사라져, 같은 인라인/템플릿 심볼이 다른 번역단위의 COMDAT
			// 사본과 강한 정의로 충돌한다(중복 심볼). 해당 심볼을 weak 으로
			// 만들어 링커가 하나만 고르도록 한다(원래 COMDAT 의도와 동일).
			if len(args) >= 4 && args[2] == "discard" {
				d.output.WriteString(".weak " + coffQuoteSymbol(args[3]) + "\n")
			}
		case "data":
			return nil, errors.New(".data section found in module")
		case "bss":
			d.writeNode(statement)
			return d.handleBSS(statement)
		default:
			// 통과 섹션(.xdata/.pdata/.debug/.ctors/.refptr 등)은 원본 그대로.
			d.writeNode(statement)
		}

	default:
		// .def/.scl/.endef/.seh_*/.secrel32/.linkonce/.p2align/.globl/.cfi_*/
		// .ascii/.zero/.file/.loc 등을 처리한다.
		// 특히 .def 지시자에서 중복 가능한 심볼을 개명한다.
		line := d.contents(statement)
		if strings.HasPrefix(strings.TrimSpace(line), ".def") {
			// .def 지시자: 첫 번째 심볼을 추출해서 개명 여부 확인.
			// 형식: ".def <symbol>; ..."
			parts := strings.SplitN(line, ";", 2)
			if len(parts) >= 1 {
				defPart := strings.TrimSpace(parts[0])
				// ".def <symbol>" 에서 symbol을 추출.
				fields := strings.Fields(defPart)
				if len(fields) >= 2 {
					original := fields[1]
					renamed := d.mapCOFFSymbol(original)
					if renamed != original {
						// symbol을 개명해서 출력.
						newLine := strings.Replace(line, ".def\t"+original, ".def\t"+renamed, 1)
						// ".def " 형태도 처리.
						newLine = strings.Replace(newLine, ".def "+original, ".def "+renamed, 1)
						d.writeCommentedNode(statement)
						d.output.WriteString(newLine)
						return statement, nil
					}
				}
			}
		}
		d.writeNode(statement)
	}

	return statement, nil
}

// isBranchInstruction 은 명령이 call/jmp 계열(단일 대상 분기)인지 판단한다.
func isBranchInstruction(instructionName string, argNodes []*node32) bool {
	return classifyInstruction(instructionName, argNodes) == instrJump
}

// coffQuoteSymbol 은 MSVC 맹글링 심볼처럼 식별자 문자([A-Za-z0-9_.$]) 외의 문자
// (?, @, 괄호 등)를 포함하면 따옴표로 감싼다. 디렉티브 인자 추출 과정에서 따옴표가
// 벗겨지므로(QuotedArg→QuotedText), 디렉티브를 다시 출력할 때 복원하는 데 쓴다.
func coffQuoteSymbol(s string) string {
	if isQuotedSymbol(s) {
		return s
	}
	for _, c := range s {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '_' || c == '.' || c == '$') {
			return "\"" + s + "\""
		}
	}
	return s
}

// coffExternalPtrName 은 외부 심볼 sym 의 주소를 담는 모듈 밖 포인터 심볼 이름을
// 반환하고, 해당 포인터가 필요함을 기록한다.
func (d *delocation) coffExternalPtrName(sym string) string {
	d.coffExternalPtrs[sym] = struct{}{}
	return decorateSymbol("bcm_external_", sym, "")
}

func (d *delocation) processCOFFInstruction(statement, instruction *node32) (*node32, error) {
	var prefix string
	if instruction.pegRule == ruleInstructionPrefix {
		prefix = d.contents(instruction)
		instruction = skipWS(instruction.next)
	}

	assertNodeType(instruction, ruleInstructionName)
	instructionName := d.contents(instruction)

	argNodes := instructionArgs(instruction.next)

	// 외부 데이터 값 적재: `movq <external>(%rip), %reg` 는 외부 심볼의 "값"을
	// 읽는다(예: stderr). COFF 에서는 외부 심볼의 주소를 모듈 밖 포인터
	// (bcm_external_<sym>)에서 먼저 읽어온 뒤 역참조해야 한다:
	//     movq bcm_external_<sym>(%rip), %reg   ; %reg = &sym
	//     movq (%reg), %reg                      ; %reg = sym
	// (주소를 담을 임시로 목적 레지스터를 재사용하므로 64비트 GP 레지스터 대상만
	//  지원한다.)
	if instructionName == "movq" && prefix == "" && len(argNodes) == 2 &&
		argNodes[0].pegRule == ruleMemoryRef &&
		argNodes[1].pegRule == ruleRegisterOrConstant {
		sym, off, sec, _, isLocal, memRef := d.parseMemRef(argNodes[0].up)
		dest := d.contents(argNodes[1])
		if sec == "" && off == "" && sym != "" && !isLocal &&
			d.isRIPRelative(memRef) && isValidLEATarget(dest) &&
			!strings.HasPrefix(sym, ".refptr.") && !isSynthesized(sym) {
			if _, known := d.symbols[sym]; !known {
				ptr := d.coffExternalPtrName(sym)
				d.writeCommentedNode(statement)
				fmt.Fprintf(d.output, "\tmovq\t%s(%%rip), %s\n", ptr, dest)
				fmt.Fprintf(d.output, "\tmovq\t(%s), %s\n", dest, dest)
				return statement, nil
			}
		}
	}

	var args []string
	changed := false

Args:
	for _, arg := range argNodes {
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
			if section != "" {
				return nil, fmt.Errorf("COFF reference has unexpected @%s section", section)
			}
			changed = changed || didChange

			// 심볼이 없는 순수 메모리 피연산자(예: 48(%rsp), (%rax,%rcx,8))는
			// 재배치가 없으므로 그대로 둔다.
			if symbol == "" {
				// 분류 없이 아래에서 원본 그대로 재구성.
			} else if strings.HasPrefix(symbol, ".refptr.") {
				target := strings.TrimPrefix(symbol, ".refptr.")
				if offset != "" || !d.isRIPRelative(memRef) {
					return nil, fmt.Errorf(".refptr reference in unexpected form: %q", strings.TrimSpace(d.contents(statement)))
				}
				if instructionName != "movq" {
					return nil, fmt.Errorf(".refptr used outside movq (got %q)", instructionName)
				}
				// .refptr.X 는 X 의 주소(.quad X)를 담는 clang 합성 포인터다.
				// movq .refptr.X(%rip), reg 는 reg 에 &X 를 적재한다.
				if _, known := d.symbols[target]; known {
					// 모듈 내부 심볼이면 직접 그 주소를 적재한다:
					//   movq .refptr.X(%rip), reg  ==>  leaq .LX_local_target(%rip), reg
					instructionName = "leaq"
					symbol = localTargetName(target)
				} else {
					// 외부 심볼(예: stderr)이면 모듈 밖 포인터 테이블에서 그 주소를
					// 읽어온다(leaq <external>(%rip) 와 동일한 메커니즘). 결과 reg = &X:
					//   movq .refptr.X(%rip), reg  ==>  movq bcm_external_X(%rip), reg
					symbol = d.coffExternalPtrName(target)
				}
				changed = true
			} else if symbolIsLocal {
				// parseMemRef 가 이미 매핑함.
			} else if _, known := d.symbols[symbol]; known {
				symbol = localTargetName(symbol)
				changed = true
			} else if isSynthesized(symbol) {
				// delocate 가 꼬리에 만들어내는 접근자(_bss_get). 그대로 둔다.
			} else if isBranchInstruction(instructionName, argNodes) {
				// 외부 호출/점프 → redirector 썽크로 직접 분기.
				redirector := redirectorName(symbol)
				d.redirectors[symbol] = redirector
				args = append(args, redirector)
				changed = true
				continue Args
			} else if instructionName == "leaq" {
				// 외부 심볼 주소 적재 → 모듈 밖 포인터에서 읽어온다.
				instructionName = "movq"
				symbol = d.coffExternalPtrName(symbol)
				changed = true
			} else {
				return nil, fmt.Errorf("unsupported external reference to %q in %q (COFF)", symbol, instructionName)
			}

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

		default:
			return nil, fmt.Errorf("unexpected instruction argument type %q in COFF instruction", rul3s[arg.pegRule])
		}
	}

	if changed {
		d.writeCommentedNode(statement)
		replacement := "\t" + instructionName + "\t" + strings.Join(args, ", ") + "\n"
		if prefix != "" {
			replacement = "\t" + prefix + replacement
		}
		d.output.WriteString(replacement)
	} else {
		d.writeNode(statement)
	}

	return statement, nil
}

// emitModuleCOFF 는 COFF 대상에서 delocate 된 모듈 본문을 출력한다. .text 시작/끝
// 마커, 외부 우회용 redirector, BSS 접근자, 외부 포인터, 무결성 해시 자리표시자를
// 모두 단일 .text 안(꼬리는 끝 마커 뒤)에 배치한다.
func (d *delocation) emitModuleCOFF(w stringWriter, inputs []inputFile, maxObservedFileNumber int, fileDirectivesContainMD5 bool) error {
	w.WriteString(".text\n")
	if d.processor == aarch64 {
		// aarch64 는 adrp 가 항상 재배치를 내므로(페이지 오프셋이 링크 의존), 모듈을
		// 페이지 경계로 정렬해 그 오프셋을 링크 독립 상수로 고정한다. ELF 경로와 동일.
		w.WriteString(".p2align 12\n")
	}
	w.WriteString("BORINGSSL_bcm_text_start:\n")
	w.WriteString(localTargetName("BORINGSSL_bcm_text_start") + ":\n")

	for _, input := range inputs {
		if err := d.processInput(input); err != nil {
			return err
		}
	}

	w.WriteString(".text\n")
	w.WriteString("BORINGSSL_bcm_text_end:\n")
	w.WriteString(localTargetName("BORINGSSL_bcm_text_end") + ":\n")

	// 외부 호출 redirector 썽크. COFF 에서는 ELF 메타데이터(.hidden/.type/.size/
	// .cfi_*)를 쓰지 않고 단순 레이블 + 본문만 낸다(x86_64 COFF 와 동일 방식).
	// x86_64 는 단일 jmp(__imp_ 는 IAT 간접 점프), aarch64 는 단일 b 분기다.
	for _, symbol := range sortedSet2(d.redirectors) {
		redirector := d.redirectors[symbol]
		switch d.processor {
		case aarch64:
			w.WriteString(".p2align 2\n")
			w.WriteString(redirector + ":\n")
			w.WriteString("\thint #34 // bti c\n")
			w.WriteString("\tb " + symbol + "\n")
		default:
			w.WriteString(redirector + ":\n")
			if strings.HasPrefix(symbol, "__imp_") {
				w.WriteString("\tjmp *" + symbol + "(%rip)\n")
			} else {
				w.WriteString("\tjmp " + symbol + "\n")
			}
		}
	}

	// BSS 접근자. x86_64 는 LEA 후 RET, aarch64 는 adrp/add 후 RET 이다.
	for _, name := range sortedSet2(d.bssAccessorsNeeded) {
		funcName := accessorName(name)
		target := d.bssAccessorsNeeded[name]
		switch d.processor {
		case aarch64:
			w.WriteString(".p2align 2\n")
			w.WriteString(funcName + ":\n")
			w.WriteString("\thint #34 // bti c\n")
			w.WriteString("\tadrp x0, " + target + "\n")
			w.WriteString("\tadd x0, x0, :lo12:" + target + "\n")
			w.WriteString("\tret\n")
		default:
			w.WriteString(funcName + ":\n")
			w.WriteString("\tleaq\t" + target + "(%rip), %rax\n\tret\n")
		}
	}

	// 외부 주소 포인터 테이블(x86_64/aarch64 공통). COFF 에는 GOT 가 없으므로 외부
	// 심볼 주소는 모듈 밖 .quad <sym> 포인터에서 적재한다(leaq/adrp+ldr 가 이 테이블을
	// 가리키도록 변환됨). 레이블 이름은 참조부(coffExternalPtrName)와 동일하게
	// decorateSymbol 로 만든다(MSVC 따옴표 심볼이면 따옴표 안쪽에 접두사).
	{
		for _, sym := range sortedSet(d.coffExternalPtrs) {
			w.WriteString(decorateSymbol("bcm_external_", sym, "") + ":\n")
			w.WriteString("\t.quad " + sym + "\n")
		}
	}

	// 무결성 해시 자리표시자. inject_hash 가 실제 해시로 채운다.
	w.WriteString("BORINGSSL_bcm_text_hash:\n")
	w.WriteString(localTargetName("BORINGSSL_bcm_text_hash") + ":\n")
	for _, b := range fipscommon.UninitHashValue {
		w.WriteString(".byte 0x" + strconv.FormatUint(uint64(b), 16) + "\n")
	}

	return nil
}

// sortedSet2 는 map[string]string 의 키를 정렬해 반환한다.
func sortedSet2(m map[string]string) []string {
	ret := make([]string, 0, len(m))
	for key := range m {
		ret = append(ret, key)
	}
	sort.Strings(ret)
	return ret
}
