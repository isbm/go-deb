package deb

import (
	"bufio"
	"strings"
)

// part of the shlibdeps
type SymbolsFile struct {
	data []string
}

func NewSymbolsFile() *SymbolsFile {
	smb := new(SymbolsFile)
	smb.data = make([]string, 0)
	return smb
}

// Parse symbols data
func (smb *SymbolsFile) parse(data []byte) error {
	var line string
	scn := bufio.NewScanner(strings.NewReader(string(data)))
	for scn.Scan() {
		line = strings.TrimSpace(scn.Text())
		if line != "" {
			// TODO: XXX: Parse an actual line, not just add the whole one
			smb.data = append(smb.data, line)
		}
	}
	return nil
}

// GetSymbols returns parsed symbols file data
func (smb *SymbolsFile) GetSymbols() []string {
	return smb.data
}
