package deb

import (
	"fmt"
	"strings"
)

// Control file
type ControlFile struct {
	src                string
	pkg                string
	version            string
	arch               string
	maintainer         string
	installedSize      int
	depends            []string
	suggests           []string
	section            string
	priority           string
	multiArch          bool
	description        string
	originalMaintainer string
}

func NewControlFile() *ControlFile {
	cf := new(ControlFile)
	cf.depends = make([]string, 0)
	cf.suggests = make([]string, 0)
	cf.multiArch = false

	return cf
}

// Set string field by name
func (cf *ControlFile) setStringField(name string, data string) {
	switch strings.ToLower(name) {
	case "source":
		cf.src = data
	case "package":
		cf.pkg = data
	case "architecture":
		cf.arch = data
	case "maintainer":
		cf.maintainer = data
	case "section":
		cf.section = data
	case "priority":
		cf.section = data
	case "original-maintainer":
		cf.originalMaintainer = data
	default:
		fmt.Println("Field", name, "is not yet supported")
	}
}

// Source
func (cf *ControlFile) Source() string {
	return cf.src
}

//
func (cf *ControlFile) Package() string {
	return cf.pkg
}

//
func (cf *ControlFile) Version() string {
	return cf.version
}

//
func (cf *ControlFile) Architecture() string {
	return cf.arch
}

//
func (cf *ControlFile) Maintainer() string {
	return cf.maintainer
}

//
func (cf *ControlFile) InstalledSize() int {
	return cf.installedSize
}

//
func (cf *ControlFile) Section() string {
	return cf.section
}

//
func (cf *ControlFile) MultiArch() bool {
	return cf.multiArch
}

//
func (cf *ControlFile) Description() string {
	return cf.description
}

//
func (cf *ControlFile) OriginalMaintainer() string {
	return cf.originalMaintainer
}
