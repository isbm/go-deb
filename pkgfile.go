package deb

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/andrew-d/lzma"
	"github.com/blakesmith/ar"
	"github.com/xi2/xz"
)

// OpenPackageFile from URI string.
func OpenPackageFile(uri string, metaonly bool) (*PackageFile, error) {
	var pf *PackageFile
	var err error
	if strings.Contains(uri, "://") && strings.HasPrefix(strings.ToLower(uri), "http") {
		pf, err = openPackageURL(uri, metaonly)
	} else {
		pf, err = openPackagePath(uri, metaonly)
	}

	return pf, err
}

func openPackagePath(path string, metaonly bool) (*PackageFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	p, err := NewPackageFileReader(f).SetMetaonly(metaonly).Read()
	if err != nil {
		return nil, err
	}
	p.setPath(path).fileSize = uint64(fi.Size())
	p.fileTime = fi.ModTime()
	return p, nil
}

// openPackageURL reads package info from a HTTP URL
func openPackageURL(path string, metaonly bool) (*PackageFile, error) {
	resp, err := http.Get(path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	p, err := NewPackageFileReader(resp.Body).SetMetaonly(metaonly).Read()
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

// PackageFileReader object
type PackageFileReader struct {
	reader   io.Reader
	pkg      *PackageFile
	arcnt    *ar.Reader
	metaonly bool
}

// PackageFileReader constructor
func NewPackageFileReader(reader io.Reader) *PackageFileReader {
	pfr := new(PackageFileReader)
	pfr.reader = reader
	pfr.pkg = NewPackageFile()
	pfr.arcnt = ar.NewReader(pfr.reader)
	pfr.metaonly = true

	return pfr
}

func (pfr *PackageFileReader) SetMetaonly(metaonly bool) *PackageFileReader {
	pfr.metaonly = metaonly
	return pfr
}

// Error checker
func (pfr PackageFileReader) checkErr(err error) bool {
	if err != nil {
		panic(err) // Should be logging instead
	}
	return err == nil
}

// Decompress Tar data from gz or xz
func (pfr *PackageFileReader) decompressTar(header ar.Header) *tar.Reader {
	var gzbuf bytes.Buffer
	var trbuf bytes.Buffer

	_, cperr := io.Copy(&gzbuf, pfr.arcnt)
	pfr.checkErr(cperr)

	if strings.HasSuffix(header.Name, ".gz") {
		pfr.checkErr(pfr.pkg.unGzip(&trbuf, gzbuf.Bytes()))
	} else if strings.HasSuffix(header.Name, ".xz") {
		pfr.checkErr(pfr.pkg.unXz(&trbuf, gzbuf.Bytes()))
	} else if strings.HasSuffix(header.Name, ".bz2") {
		pfr.checkErr(pfr.pkg.unBzip(&trbuf, gzbuf.Bytes()))
	} else if strings.HasSuffix(header.Name, ".lzma") {
		pfr.checkErr(pfr.pkg.unLzma(&trbuf, gzbuf.Bytes()))
	}

	return tar.NewReader(&trbuf)
}

// Read _gpgbuiler file (self-signed Debian package with no role)
func (pfr *PackageFileReader) processGpgBuilderFile(header ar.Header) {
	var buff bytes.Buffer
	_, err := io.Copy(&buff, pfr.arcnt)
	pfr.checkErr(err)
	pfr.pkg.gpgbuilder = strings.TrimSpace(buff.String())
}

// Read data file, extracting the meta-data about its contents
func (pfr *PackageFileReader) processDataFile(header ar.Header) {
	if pfr.metaonly {
		return // Bail out, files were not requested
	}

	tarFile := pfr.decompressTar(header)
	for {
		hdr, err := tarFile.Next()
		if err == io.EOF {
			break
		}
		pfr.pkg.addFileContent(*hdr)
	}
}

// Read versision of the package managaer
func (pfr *PackageFileReader) processDebianBinaryFile(header ar.Header) {
	var buff bytes.Buffer
	_, err := io.Copy(&buff, pfr.arcnt)
	pfr.checkErr(err)
	pfr.pkg.debVersion = strings.TrimSpace(buff.String())
}

// Read control file, compressed with tar and gzip or xz
func (pfr *PackageFileReader) processControlFile(header ar.Header) {
	var databuf bytes.Buffer
	tarFile := pfr.decompressTar(header)
	for {
		hdr, err := tarFile.Next()
		if err == io.EOF {
			break
		}
		if pfr.checkErr(err) && hdr.Typeflag == tar.TypeReg {
			databuf.Reset()
			_, err = io.Copy(&databuf, tarFile)
			pfr.checkErr(err)

			switch hdr.Name[2:] {
			case "postinst":
				pfr.pkg.postinst = databuf.String()
			case "postrm":
				pfr.pkg.postrm = databuf.String()
			case "preinst":
				pfr.pkg.preinst = databuf.String()
			case "prerm":
				pfr.pkg.prerm = databuf.String()
			case "md5sums":
				pfr.pkg.parseMd5Sums(databuf.Bytes())
			case "control":
				pfr.pkg.parseControlFile(databuf.Bytes())
			case "symbols":
				pfr.pkg.parseSymbolsFile(databuf.Bytes())
			case "shlibs":
				pfr.pkg.parseSharedLibsFile(databuf.Bytes())
			case "triggers":
				pfr.pkg.parseTriggersFile(databuf.Bytes())
			case "conffiles":
				pfr.pkg.parseConffilesFile(databuf.Bytes())
			case "templates":
				// If it is needed
			case "config":
				// Old packaging style
			default:
				// Log unhandled content and the name here
			}
		}
	}

}

// Read Debian package data from the stream
func (pfr *PackageFileReader) Read() (*PackageFile, error) {
	for {
		header, err := pfr.arcnt.Next()
		if err != nil {
			if err == io.EOF {
				break
			} else {
				panic(err)
			}
		} else {
			// Yocto's IPK has trailing path for some weird reasons (same format tho)
			header.Name = path.Base(strings.ReplaceAll(header.Name, "/", ""))

			if strings.HasPrefix(header.Name, "control.") {
				pfr.processControlFile(*header)
			} else if strings.HasPrefix(header.Name, "data.") {
				pfr.processDataFile(*header)
			} else if header.Name == "_gpgbuilder" {
				pfr.processGpgBuilderFile(*header)
			} else if header.Name == "debian-binary" {
				pfr.processDebianBinaryFile(*header)
			}
		}
	}

	return pfr.pkg, nil
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
	path       string
	fileSize   uint64
	fileTime   time.Time
	debVersion string

	preinst  string
	prerm    string
	postinst string
	postrm   string

	checksum   *Checksum
	control    *ControlFile
	symbols    *SymbolsFile
	shlibs     *SharedLibsFile
	triggers   *TriggerFile
	conffiles  *CfgFilesFile
	gpgbuilder string

	files         []FileInfo
	fileChecksums map[string]string
}

// Constructor
func NewPackageFile() *PackageFile {
	pf := new(PackageFile)
	pf.fileChecksums = make(map[string]string)
	pf.files = make([]FileInfo, 0)
	pf.control = NewControlFile()
	pf.symbols = NewSymbolsFile()
	pf.shlibs = NewSharedLibsFile()
	pf.triggers = NewTriggerFile()
	pf.conffiles = NewCfgFilesFiles()

	return pf
}

// Set path to the file
func (c *PackageFile) setPath(path string) *PackageFile {
	c.path = path
	c.checksum = NewChecksum(c.path)

	return c
}

// unBz2 decompresses Bzip data array
func (c *PackageFile) unLzma(writer io.Writer, data []byte) error {
	lzmaread := lzma.NewReader(bytes.NewBuffer(data))
	defer lzmaread.Close()
	data, err := ioutil.ReadAll(lzmaread)
	if err == nil {
		writer.Write(data)
	}
	return err
}

// unBz2 decompresses Bzip data array
func (c *PackageFile) unBzip(writer io.Writer, data []byte) error {
	bzread := bzip2.NewReader(bytes.NewBuffer(data))
	data, err := ioutil.ReadAll(bzread)
	if err == nil {
		writer.Write(data)
	}
	return err
}

// unXz decompresses Lempel-Ziv-Markow data
func (c *PackageFile) unXz(writer io.Writer, data []byte) error {
	xzread, err := xz.NewReader(bytes.NewBuffer(data), 0)
	if err != nil {
		panic(err)
	}

	data, err = ioutil.ReadAll(xzread)
	if err == nil {
		writer.Write(data)
	}

	return err
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

// Add file content meta-data
func (c *PackageFile) addFileContent(header tar.Header) {
	info := new(FileInfo)
	info.name = header.Name
	info.mode = header.FileInfo().Mode()
	info.size = header.Size
	info.modTime = header.ModTime
	info.owner = header.Uname
	info.group = header.Gname
	info.linkname = header.Linkname

	c.files = append(c.files, *info)
}

// Parse Conffiles
func (c *PackageFile) parseConffilesFile(data []byte) {
	c.conffiles.parse(data)
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

// ConffilesFile returns parsed triggers file data.
func (c *PackageFile) ConffilesFile() *CfgFilesFile {
	return c.conffiles
}

// Return meta-content of the package
func (c *PackageFile) Files() []FileInfo {
	return c.files
}

// DpkgVersion returns the version of the format of the .deb file
func (c *PackageFile) DebVersion() string {
	return c.debVersion
}
