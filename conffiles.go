package deb

import (
	"bufio"
	"strings"
)

type CfgFilesFile struct {
	names []string
}

func NewCfgFilesFiles() *CfgFilesFile {
	cfg := new(CfgFilesFile)
	cfg.names = make([]string, 0)
	return cfg
}

func (cfg *CfgFilesFile) parse(data []byte) error {
	var line string
	scn := bufio.NewScanner(strings.NewReader(string(data)))
	for scn.Scan() {
		line = strings.TrimSpace(scn.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			cfg.names = append(cfg.names, line)
		}
	}

	return nil
}

func (cfg *CfgFilesFile) Names() []string {
	return cfg.names
}
