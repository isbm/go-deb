package deb

import (
	"bufio"
	"regexp"
	"strings"
)

type SharedLibrary struct {
	tag          string
	library      string
	version      string
	dependencies []string
}

func NewSharedLibrary() *SharedLibrary {
	shl := new(SharedLibrary)
	shl.dependencies = make([]string, 0)

	return shl
}

type SharedLibsFile struct {
	libraries []SharedLibrary
}

// Tag returns possible shared library tag. Usually it is an empty string.
func (shl *SharedLibrary) Tag() string {
	return shl.tag
}

// Name returns the name of the shared library.
func (shl *SharedLibrary) Name() string {
	return shl.library
}

// Version returns the version of the shared library.
func (shl *SharedLibrary) Version() string {
	return shl.version
}

// Dependencies returns the list of dependencies of the shared library.
func (shl *SharedLibrary) Dependencies() []string {
	return shl.dependencies
}

func NewSharedLibsFile() *SharedLibsFile {
	shl := new(SharedLibsFile)
	shl.libraries = make([]SharedLibrary, 0)

	return shl
}

func (shlf *SharedLibsFile) parse(data []byte) error {
	var line string
	scn := bufio.NewScanner(strings.NewReader(string(data)))
	for scn.Scan() {
		line = strings.TrimSpace(scn.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			shl := NewSharedLibrary()
			fe := strings.SplitN(line, " ", 2)
			if strings.HasSuffix(fe[0], ":") {
				shl.tag = fe[0]
				line = fe[1]
			}

			fe = strings.SplitN(line, " ", 3)
			shl.library, shl.version = fe[0], fe[1]
			fe = regexp.MustCompile(`[\\,\\|]`).Split(fe[2], -1)
			for _, v := range fe {
				shl.dependencies = append(shl.dependencies, strings.TrimSpace(v))
			}
			shlf.libraries = append(shlf.libraries, *shl)
		}
	}

	return nil
}

// Libraries returns shared libraries
func (shl *SharedLibsFile) Libraries() []SharedLibrary {
	return shl.libraries
}
