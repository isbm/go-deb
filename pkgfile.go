package deb

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/blakesmith/ar"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

func OpenPackageFile(uri string) (*PackageFile, error) {
	var pf *PackageFile
	var err error
	if strings.Contains(uri, "://") && strings.HasPrefix(strings.ToLower(uri), "http") {
		pf, err = openPackageURL(uri)
	} else {
		pf, err = openPackagePath(uri)
	}

	return pf, err
}

func openPackagePath(path string) (*PackageFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	p, err := ReadPackageFile(f)
	if err != nil {
		return nil, err
	}
	p.setPath(path).fileSize = uint64(fi.Size())
	p.fileTime = fi.ModTime()
	return p, nil
}

// openPackageURL reads package info from a HTTP URL
func openPackageURL(path string) (*PackageFile, error) {
	resp, err := http.Get(path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	p, err := ReadPackageFile(resp.Body)
	if err != nil {
		return nil, err
	}
	p.setPath(path).fileSize = uint64(resp.ContentLength)
	if lm := resp.Header.Get("Last-Modified"); len(lm) > 0 {
		t, _ := time.Parse(time.RFC1123, lm) // ignore malformed timestamps
		p.fileTime = t
	}
	return p, nil
}

func ReadPackageFile(r io.Reader) (*PackageFile, error) {
	p := NewPackageFile()

	arFile := ar.NewReader(r)
	for {
		header, err := arFile.Next()
		if err != nil {
			if err == io.EOF {
				break
			} else {
				panic(err)
			}
		} else {
			if header.Name == "control.tar.gz" {
				var gzbuf bytes.Buffer
				var trbuf bytes.Buffer

				io.Copy(&gzbuf, arFile)
				p.unGzip(&trbuf, gzbuf.Bytes())

				tr := tar.NewReader(&trbuf)
				for {
					hdr, err := tr.Next()
					if err == io.EOF {
						break
					}
					if err != nil {
						panic(err)
					}
					if hdr.Typeflag == tar.TypeReg {
						gzbuf.Reset()
						io.Copy(&gzbuf, tr)

						switch hdr.Name[2:] {
						case "postinst":
							p.postinst = string(gzbuf.Bytes())
						case "postrm":
							p.postrm = string(gzbuf.Bytes())
						case "preinst":
							p.preinst = string(gzbuf.Bytes())
						case "prerm":
							p.prerm = string(gzbuf.Bytes())
						case "md5sums":
							p.parseMd5Sums(gzbuf.Bytes())
						case "control":
							p.parseControlFile(gzbuf.Bytes())
						case "symbols":
							p.parseSymbolsFile(gzbuf.Bytes())
						case "shlibs":
							p.parseSharedLibsFile(gzbuf.Bytes())
						case "triggers":
							p.parseTriggersFile(gzbuf.Bytes())
						default:
							fmt.Printf("\n\n### UNHANDLED YET '%s':\n==========\n\n", hdr.Name[2:])
							fmt.Println(string(gzbuf.Bytes()))
						}
					}
				}

			} else {
				fmt.Println(">> AR FILENAME:", header.Name)
			}
		}
	}

	return p, nil
}

// Checksum object computes and returns the SHA256, SHA1 and MD5 checksums
// encoded in hexadecimal) of the package file.
//
// Checksum reopens the package using the file path that was given via
// OpenPackageFile.
type Checksum struct {
	path string
}

// Constructor
func NewChecksum(path string) *Checksum {
	cs := new(Checksum)
	cs.path = path
	return cs
}

// Compute checksum for the given hash
func (cs *Checksum) compute(csType hash.Hash) (string, error) {
	if cs.path == "" {
		return "", fmt.Errorf("No path has been defined")
	}

	f, err := os.Open(cs.path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if _, err := io.Copy(csType, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(csType.Sum(nil)), nil
}

// SHA256 checksum
func (cs *Checksum) SHA256() string {
	sum, err := cs.compute(sha256.New())
	if err != nil {
		panic(err)
	}
	return sum
}

// SHA1 checksum
func (cs *Checksum) SHA1() string {
	sum, err := cs.compute(sha1.New())
	if err != nil {
		panic(err)
	}
	return sum
}

// MD5 checksum
func (cs *Checksum) MD5() string {
	sum, err := cs.compute(md5.New())
	if err != nil {
		panic(err)
	}
	return sum
}

// PackageFile object
type PackageFile struct {
	path     string
	fileSize uint64
	fileTime time.Time

	preinst  string
	prerm    string
	postinst string
	postrm   string

	checksum *Checksum
	control  *ControlFile
	symbols  *SymbolsFile
	shlibs   *SharedLibsFile
	triggers *TriggerFile

	files         []FileInfo
	fileChecksums map[string]string
}

// Constructor
func NewPackageFile() *PackageFile {
	pf := new(PackageFile)
	pf.fileChecksums = make(map[string]string)
	pf.control = NewControlFile()
	pf.symbols = NewSymbolsFile()
	pf.shlibs = NewSharedLibsFile()
	pf.triggers = NewTriggerFile()

	return pf
}

// Set path to the file
func (c *PackageFile) setPath(path string) *PackageFile {
	c.path = path
	c.checksum = NewChecksum(c.path)

	return c
}

// unGzip decompresses compressed Gzip data array
func (c *PackageFile) unGzip(writer io.Writer, data []byte) error {
	gzread, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		panic(err)
	}

	defer gzread.Close()

	data, err = ioutil.ReadAll(gzread)
	if err == nil {
		writer.Write(data)
	}

	return err
}

// Parse MD5 checksums file
func (c *PackageFile) parseMd5Sums(data []byte) {
	var sfx = regexp.MustCompile(`\s+|\t+`)
	scn := bufio.NewScanner(strings.NewReader(string(data)))
	for scn.Scan() {
		csF := strings.Split(sfx.ReplaceAllString(scn.Text(), " "), " ")
		if len(csF) == 2 && len(csF[0]) == 0x20 {
			c.fileChecksums[csF[0]] = csF[1]
		}
	}
}

// Parse Triggers
func (c *PackageFile) parseTriggersFile(data []byte) {
	c.triggers.parse(data)
}

// Parse symbols
func (c *PackageFile) parseSymbolsFile(data []byte) {
	c.symbols.parse(data)
}

// Parse shlibs
func (c *PackageFile) parseSharedLibsFile(data []byte) {
	c.shlibs.parse(data)
}

// Parse control file
func (c *PackageFile) parseControlFile(data []byte) {
	var line string
	var namedata []string
	var currentName string

	scn := bufio.NewScanner(strings.NewReader(string(data)))
	for scn.Scan() {
		// Single field values
		line = scn.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			c.control.addToField(currentName, line)
		} else {
			namedata = strings.SplitN(line, ":", 2)
			currentName = namedata[0]
			c.control.setField(namedata...)
		}
	}
}

// Path returns the path which was given to open a package file if it was opened
// with OpenPackageFile.
func (c *PackageFile) Path() string {
	return c.path
}

func (c *PackageFile) PreInstallScript() string {
	return c.preinst
}

// FileTime returns the time at which the Debian package file was last modified if
// it was opened with OpenPackageFile.
func (c *PackageFile) FileTime() time.Time {
	return c.fileTime
}

// FileSize returns the size of the package file in bytes if it was opened with
// OpenPackageFile.
func (c *PackageFile) FileSize() uint64 {
	return c.fileSize
}

func (c *PackageFile) PostInstallScript() string {
	return c.postinst
}

func (c *PackageFile) PreUninstallScript() string {
	return c.prerm
}

func (c *PackageFile) PostUninstallScript() string {
	return c.postrm
}

// GetFileChecksum returns file checksum by relative path
func (c *PackageFile) GetFileChecksum(path string) string {
	return c.fileChecksums[path]
}

// GetPackageChecksum returns checksum of the package itself
func (c *PackageFile) GetPackageChecksum() *Checksum {
	return c.checksum
}

// ControlFile returns parsed data of the package's control file
func (c *PackageFile) ControlFile() *ControlFile {
	return c.control
}

// SymbolsFile returns parsed symbols file data
func (c *PackageFile) SymbolsFile() *SymbolsFile {
	return c.symbols
}

// SharedLibsFile returns parsed shlibs file data (an alternative system to symbols)
func (c *PackageFile) SharedLibsFile() *SharedLibsFile {
	return c.shlibs
}

// TriggersFile returns parsed triggers file data.
func (c *PackageFile) TriggersFile() *TriggerFile {
	return c.triggers
}
