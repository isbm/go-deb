package deb

import (
	"bufio"
	"strings"
)

// Basic symbol description. It is not parsed "to the ground" at the moment.
// It has only a symbol itself and the version of it.
type SymbolElement struct {
	base    string
	version string
}

// NewSymbolElement constuctor.
func NewSymbolElement() *SymbolElement {
	se := new(SymbolElement)
	return se
}

// Returns the entire symbol in one row
// This does not parses (yet?) things like:
// (arch-bits=32|arch-endian=little)32bit_le_symbol@Base etc.
func (se *SymbolElement) Base() string {
	return se.base
}

// Returns version of the symbol
func (se *SymbolElement) Version() string {
	return se.version
}

// part of the shlibdeps
type SymbolsFile struct {
	data []SymbolElement
}

func NewSymbolsFile() *SymbolsFile {
	smb := new(SymbolsFile)
	smb.data = make([]SymbolElement, 0)
	return smb
}

// Parse symbols data
func (smb *SymbolsFile) parse(data []byte) error {
	var line string
	var elm []string
	scn := bufio.NewScanner(strings.NewReader(string(data)))
	for scn.Scan() {
		line = strings.TrimSpace(scn.Text())
		if line != "" {
			elm = strings.SplitN(line, " ", 2)
			se := NewSymbolElement()
			se.base = elm[0]
			se.version = elm[1]
			smb.data = append(smb.data, *se)
		}
	}
	return nil
}

// GetSymbols returns parsed symbols file data
func (smb *SymbolsFile) GetSymbols() []SymbolElement {
	return smb.data
}
