package deb

type CfgFilesFile struct {
	names []string
}

func NewCfgFilesFiles() *CfgFilesFile {
	cfg := new(CfgFilesFile)
	cfg.names = make([]string, 0)
	return cfg
}

func (cfg *CfgFilesFile) parse(data []byte) error {
	return nil
}

func (cfg *CfgFilesFile) Names() []string {
	return cfg.names
}
