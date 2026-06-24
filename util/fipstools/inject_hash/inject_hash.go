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

// inject_hash parses an archive containing a file object file. It finds a FIPS
// module inside that object, calculates its hash and replaces the default hash
// value in the object with the calculated value.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"boringssl.googlesource.com/boringssl.git/util/ar"
	"boringssl.googlesource.com/boringssl.git/util/fipstools/fipscommon"
)

func do(outPath, oInput, arInput, hashInput string) error {
	var objectBytes []byte
	var isStatic bool
	var perm os.FileMode

	if arInput != "" {
		isStatic = true

		if oInput != "" {
			return fmt.Errorf("-in-archive and -in-object are mutually exclusive")
		}

		fi, err := os.Stat(arInput)
		if err != nil {
			return err
		}
		perm = fi.Mode()

		arFile, err := os.Open(arInput)
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

		for _, contents := range ar {
			objectBytes = contents
		}
	} else if oInput != "" {
		fi, err := os.Stat(oInput)
		if err != nil {
			return err
		}
		perm = fi.Mode()

		if objectBytes, err = os.ReadFile(oInput); err != nil {
			return err
		}
		isStatic = strings.HasSuffix(oInput, ".o")
	} else {
		return fmt.Errorf("exactly one of -in-archive or -in-object is required")
	}

	// Hash a different object if specified.
	var err error
	hashBytes := objectBytes
	if hashInput != "" {
		hashBytes, err = os.ReadFile(hashInput)
		if err != nil {
			return err
		}
		isStatic = strings.HasSuffix(hashInput, ".o")
	}

	// 오브젝트 형식(ELF vs COFF/PE)에 따라 모듈 본문을 추출한다.
	var moduleText, moduleROData []byte
	if isELFObject(hashBytes) {
		moduleText, moduleROData, err = hashModuleELF(hashBytes, isStatic)
	} else {
		moduleText, moduleROData, err = hashModuleCOFF(hashBytes)
	}
	if err != nil {
		return err
	}

	var zeroKey [64]byte
	mac := hmac.New(sha256.New, zeroKey[:])

	if moduleROData != nil {
		var lengthBytes [8]byte
		binary.LittleEndian.PutUint64(lengthBytes[:], uint64(len(moduleText)))
		mac.Write(lengthBytes[:])
		mac.Write(moduleText)

		binary.LittleEndian.PutUint64(lengthBytes[:], uint64(len(moduleROData)))
		mac.Write(lengthBytes[:])
		mac.Write(moduleROData)
	} else {
		mac.Write(moduleText)
	}
	calculated := mac.Sum(nil)

	// Replace the default hash value in the object with the calculated
	// value and write it out.

	offset := bytes.Index(objectBytes, fipscommon.UninitHashValue[:])
	if offset < 0 {
		return errors.New("did not find uninitialised hash value in object file")
	}

	if bytes.Contains(objectBytes[offset+1:], fipscommon.UninitHashValue[:]) {
		return errors.New("found two occurrences of uninitialised hash value in object file")
	}

	if _, exists := os.LookupEnv("BORINGSSL_FIPS_SHOW_HASH"); exists {
		fmt.Printf("Module hash: %x\n", calculated)
	}
	copy(objectBytes[offset:], calculated)

	return os.WriteFile(outPath, objectBytes, perm&0777)
}

// isELFObject 는 바이트열이 ELF 오브젝트인지(매직 0x7f 'E' 'L' 'F') 판단한다.
// 그렇지 않으면 COFF/PE 로 취급한다.
func isELFObject(b []byte) bool {
	return len(b) >= 4 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F'
}

// hashModuleELF 는 ELF/Mach-O 오브젝트에서 FIPS 모듈의 .text(및 공유 빌드의
// .rodata) 본문을 추출한다.
func hashModuleELF(hashBytes []byte, isStatic bool) (moduleText, moduleROData []byte, err error) {
	object, err := elf.NewFile(bytes.NewReader(hashBytes))
	if err != nil {
		return nil, nil, errors.New("failed to parse object: " + err.Error())
	}

	// Find the .text and, optionally, .data sections.

	var textSection, rodataSection *elf.Section
	var textSectionIndex, rodataSectionIndex elf.SectionIndex
	for i, section := range object.Sections {
		switch section.Name {
		case ".text":
			textSectionIndex = elf.SectionIndex(i)
			textSection = section
		case ".rodata":
			rodataSectionIndex = elf.SectionIndex(i)
			rodataSection = section
		}
	}

	if textSection == nil {
		return nil, nil, errors.New("failed to find .text section in object")
	}

	// Find the starting and ending symbols for the module.

	var textStart, textEnd, rodataStart, rodataEnd *uint64

	// Look for symbols in either .symtab or .dynsym. Some build configurations
	// strip way .symtab.
	symbols, err := object.Symbols()
	if err == elf.ErrNoSymbols {
		symbols, err = object.DynamicSymbols()
	}
	if err != nil {
		return nil, nil, errors.New("failed to parse symbols: " + err.Error())
	}

	for _, symbol := range symbols {
		var base uint64
		switch symbol.Section {
		case textSectionIndex:
			base = textSection.Addr
		case rodataSectionIndex:
			if rodataSection == nil {
				continue
			}
			base = rodataSection.Addr
		default:
			continue
		}

		if isStatic {
			// Static objects appear to have different semantics about whether symbol
			// values are relative to their section or not.
			base = 0
		} else if symbol.Value < base {
			return nil, nil, fmt.Errorf("symbol %q at %x, which is below base of %x", symbol.Name, symbol.Value, base)
		}

		value := symbol.Value - base
		switch symbol.Name {
		case "BORINGSSL_bcm_text_start":
			if textStart != nil {
				return nil, nil, errors.New("duplicate start symbol found")
			}
			textStart = &value
		case "BORINGSSL_bcm_text_end":
			if textEnd != nil {
				return nil, nil, errors.New("duplicate end symbol found")
			}
			textEnd = &value
		case "BORINGSSL_bcm_rodata_start":
			if rodataStart != nil {
				return nil, nil, errors.New("duplicate rodata start symbol found")
			}
			rodataStart = &value
		case "BORINGSSL_bcm_rodata_end":
			if rodataEnd != nil {
				return nil, nil, errors.New("duplicate rodata end symbol found")
			}
			rodataEnd = &value
		default:
			continue
		}
	}

	if textStart == nil || textEnd == nil {
		return nil, nil, errors.New("could not find .text module boundaries in object")
	}

	if (rodataStart != nil) != (rodataEnd != nil) {
		return nil, nil, errors.New("rodata marker presence inconsistent")
	}

	if max := textSection.Size; *textStart > max || *textStart > *textEnd || *textEnd > max {
		return nil, nil, fmt.Errorf("invalid module .text boundaries: start: %x, end: %x, max: %x", *textStart, *textEnd, max)
	}

	if rodataStart != nil {
		if rodataSection == nil {
			return nil, nil, errors.New("rodata start marker inconsistent with rodata section presence")
		}
		if max := rodataSection.Size; *rodataStart > max || *rodataStart > *rodataEnd || *rodataEnd > max {
			return nil, nil, fmt.Errorf("invalid module .rodata boundaries: start: %x, end: %x, max: %x", *rodataStart, *rodataEnd, max)
		}
	}

	// Extract the module from the .text section and hash it.

	text := textSection.Open()
	if _, err := text.Seek(int64(*textStart), 0); err != nil {
		return nil, nil, errors.New("failed to seek to module start in .text: " + err.Error())
	}
	moduleText = make([]byte, *textEnd-*textStart)
	if _, err := io.ReadFull(text, moduleText); err != nil {
		return nil, nil, errors.New("failed to read .text: " + err.Error())
	}

	// Maybe extract the module's read-only data too
	if rodataStart != nil {
		rodata := rodataSection.Open()
		if _, err := rodata.Seek(int64(*rodataStart), 0); err != nil {
			return nil, nil, errors.New("failed to seek to module start in .rodata: " + err.Error())
		}
		moduleROData = make([]byte, *rodataEnd-*rodataStart)
		if _, err := io.ReadFull(rodata, moduleROData); err != nil {
			return nil, nil, errors.New("failed to read .rodata: " + err.Error())
		}
	}

	return moduleText, moduleROData, nil
}

// hashModuleCOFF 는 COFF/PE 오브젝트에서 FIPS 모듈의 .text 본문을 추출한다.
// COFF delocate 는 읽기전용 데이터를 .text 안으로 접어 넣고, 해시 대상 영역
// [BORINGSSL_bcm_text_start, BORINGSSL_bcm_text_end) 에는 재배치가 전혀 없도록
// 만들기 때문에, 정적 오브젝트에서 직접 바이트를 읽어 해시해도 런타임과 동일하다.
// 따라서 별도의 rodata 영역은 없다.
func hashModuleCOFF(hashBytes []byte) (moduleText, moduleROData []byte, err error) {
	object, err := pe.NewFile(bytes.NewReader(hashBytes))
	if err != nil {
		return nil, nil, errors.New("failed to parse COFF object: " + err.Error())
	}

	var textSection *pe.Section
	var textSectionNumber int
	for i, section := range object.Sections {
		if section.Name == ".text" {
			textSection = section
			textSectionNumber = i + 1 // COFF SectionNumber 는 1부터 시작.
		}
	}
	if textSection == nil {
		return nil, nil, errors.New("failed to find .text section in object")
	}

	var textStart, textEnd *uint64
	for _, symbol := range object.Symbols {
		if int(symbol.SectionNumber) != textSectionNumber {
			continue
		}
		// COFF 오브젝트 심볼의 Value 는 섹션 시작으로부터의 오프셋이다.
		value := uint64(symbol.Value)
		switch symbol.Name {
		case "BORINGSSL_bcm_text_start":
			if textStart != nil {
				return nil, nil, errors.New("duplicate start symbol found")
			}
			textStart = &value
		case "BORINGSSL_bcm_text_end":
			if textEnd != nil {
				return nil, nil, errors.New("duplicate end symbol found")
			}
			textEnd = &value
		}
	}

	if textStart == nil || textEnd == nil {
		return nil, nil, errors.New("could not find .text module boundaries in object")
	}

	sectionData, err := textSection.Data()
	if err != nil {
		return nil, nil, errors.New("failed to read .text section: " + err.Error())
	}

	if *textStart > *textEnd || *textEnd > uint64(len(sectionData)) {
		return nil, nil, fmt.Errorf("invalid module .text boundaries: start: %x, end: %x, max: %x", *textStart, *textEnd, len(sectionData))
	}

	moduleText = make([]byte, *textEnd-*textStart)
	copy(moduleText, sectionData[*textStart:*textEnd])
	return moduleText, nil, nil
}

func main() {
	arInput := flag.String("in-archive", "", "Path to a .a file")
	oInput := flag.String("in-object", "", "Path to a .o file")
	hashInput := flag.String("in-hash", "", "Path to an input object file to hash instead")
	outPath := flag.String("o", "", "Path to output object")

	flag.Parse()

	if err := do(*outPath, *oInput, *arInput, *hashInput); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
