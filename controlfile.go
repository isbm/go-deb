package deb

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Control file
type ControlFile struct {
	src           string
	pkg           string
	version       string
	arch          string
	maintainer    string
	homepage      string
	licence       string
	oe            string
	installedSize int

	// Canonical names of control file fields that are folded fields.
	// They contain a comma separated list of package names with optional version specifications.
	breaks     []string
	conflicts  []string
	depends    []string
	enhances   []string
	predepends []string
	provides   []string
	recommends []string
	replaces   []string
	suggests   []string

	section            string
	priority           string
	multiArch          string
	description        string
	summary            string // This is not a standard field of Dpkg and it basically contains only a first line of description.
	originalMaintainer string
}

func NewControlFile() *ControlFile {
	cf := new(ControlFile)
	cf.depends = make([]string, 0)
	cf.suggests = make([]string, 0)
	cf.multiArch = ""

	return cf
}

// Check if a string is in the array
func in(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// Add to the field
func (cf *ControlFile) addToField(name string, data string) {
	switch strings.ToLower(name) {
	case "description":
		cf.description += " " + strings.TrimSpace(data)
	}
}

// Generic method to set any field
func (cf *ControlFile) setField(data ...string) error {
	if len(data) != 2 {
		return errors.New("Data must have two elements only")
	}
	name, value := strings.ToLower(strings.TrimSpace(data[0])), strings.TrimSpace(data[1])
	i, err := strconv.Atoi(value)
	if in(name, []string{"depends", "predepends", "suggests", "breaks", "enhances", "conflicts", "provides", "recommends", "replaces"}) {
		cf.setFoldedField(name, value)
	} else if err == nil {
		cf.setIntField(name, i)
	} else {
		cf.setStringField(name, value)
	}

	return nil
}

// Folded field is one-line field that is actually contains multiple values
func (cf *ControlFile) setFoldedField(name string, data string) {
	var ptr *[]string
	switch name {
	case "depends":
		ptr = &cf.depends
	case "predepends":
		ptr = &cf.predepends
	case "suggests":
		ptr = &cf.suggests
	case "breaks":
		ptr = &cf.breaks
	case "conflicts":
		ptr = &cf.conflicts
	case "enhances":
		ptr = &cf.enhances
	case "provides":
		ptr = &cf.provides
	case "recommends":
		ptr = &cf.recommends
	case "replaces":
		ptr = &cf.replaces
	default:
		ptr = nil
		fmt.Println("@@ missing folded data for:", name)
	}

	// Try to make sense of that messy pile of many ways they call "standard"
	if ptr != nil {
		var vals []string
		if strings.Contains(data, ",") || strings.Contains(data, "|") || strings.Contains(data, "(") {
			vals = regexp.MustCompile(`[\\,\\|]`).Split(data, -1)
		} else {
			vals = strings.Split(data, " ")
		}
		for _, val := range vals {
			val = strings.TrimSpace(val)
			if val != "" {
				*ptr = append(*ptr, strings.TrimSpace(val))
			}
		}
	}
}

// Set integer field
func (cf *ControlFile) setIntField(name string, data int) {
	switch name {
	case "installed-size":
		cf.installedSize = data
	}
}

// Set string field by name
func (cf *ControlFile) setStringField(name string, data string) {
	data = strings.TrimSpace(data)
	switch name {
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
		cf.priority = data
	case "original-maintainer":
		cf.originalMaintainer = data
	case "version":
		cf.version = data
	case "multi-arch":
		cf.multiArch = data
	case "description":
		if !strings.HasSuffix(data, ".") {
			data += "."
		}
		cf.summary = data // The first line is summary. The rest will be added by addToField method.
		cf.description = data
	case "homepage":
		cf.homepage = data
	case "license": // american spelling
		cf.licence = data
	case "oe":
		cf.oe = data
	default:
		fmt.Println("Field", name, "is not yet supported:")
		fmt.Println(data)
		fmt.Println("---")
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
func (cf *ControlFile) Priority() string {
	return cf.priority
}

//
func (cf *ControlFile) MultiArch() string {
	return cf.multiArch
}

//
func (cf *ControlFile) Description() string {
	return cf.description
}

// Licence of the package
func (cf *ControlFile) Licence() string {
	return cf.licence
}

//
func (cf *ControlFile) OE() string {
	return cf.oe
}

// Summary returns a first line of Description
func (cf *ControlFile) Summary() string {
	return cf.summary
}

//
func (cf *ControlFile) OriginalMaintainer() string {
	return cf.originalMaintainer
}

//
func (cf *ControlFile) Depends() []string {
	return cf.depends
}

//
func (cf *ControlFile) Suggests() []string {
	return cf.suggests
}

//
func (cf *ControlFile) Provides() []string {
	return cf.provides
}

//
func (cf *ControlFile) Recommends() []string {
	return cf.recommends
}

//
func (cf *ControlFile) Replaces() []string {
	return cf.replaces
}

//
func (cf *ControlFile) Breaks() []string {
	return cf.breaks
}

//
func (cf *ControlFile) Conflicts() []string {
	return cf.conflicts
}

//
func (cf *ControlFile) Enhances() []string {
	return cf.enhances
}

//
func (cf *ControlFile) Predepends() []string {
	return cf.predepends
}
