package deb

import (
	"bufio"
	"strings"
)

type SharedLibrary struct {
	library      string
	version      string
	dependencies []string
}

type SharedLibsFile struct {
	libraries []SharedLibrary
}

func NewSharedLibsFile() *SharedLibsFile {
	shl := new(SharedLibsFile)
	shl.libraries = make([]SharedLibrary, 0)

	return shl
}

func (shl *SharedLibsFile) parse(data []byte) error {
	var line string
	scn := bufio.NewScanner(strings.NewReader(string(data)))
	for scn.Scan() {
		line = strings.TrimSpace(scn.Text())
		if line != "" {

		}
	}

	return nil
}

// Libraries returns shared libraries
func (shl *SharedLibsFile) Libraries() []SharedLibrary {
	return shl.libraries
}
