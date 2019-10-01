package deb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"github.com/blakesmith/ar"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

type PackageFile struct {
	path     string
	fileSize uint64
	fileTime time.Time

	preinst  string
	prerm    string
	postinst string
	postrm   string

	files []FileInfo
}

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
	p.path = path
	p.fileSize = uint64(fi.Size())
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
	p.path = path
	p.fileSize = uint64(resp.ContentLength)
	if lm := resp.Header.Get("Last-Modified"); len(lm) > 0 {
		t, _ := time.Parse(time.RFC1123, lm) // ignore malformed timestamps
		p.fileTime = t
	}
	return p, nil
}

func ReadPackageFile(r io.Reader) (*PackageFile, error) {
	p := &PackageFile{}

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
				p.ungz(&trbuf, gzbuf.Bytes())

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
						default:
							fmt.Printf("\n\n### UNHANDLED YET '%s':\n==========\n\n", hdr.Name[2:])
							fmt.Println(string(gzbuf.Bytes()))
						}
					}
				}

			} else {
				fmt.Println(">>", header.Name)
			}
		}
	}

	return p, nil
}

// ungz decompresses compressed Gzip data array
func (c *PackageFile) ungz(writer io.Writer, data []byte) error {
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

// parseControlFile function parses control file to the PackageFile structure fields
func (c *PackageFile) parseControlFile(cfdata string) error {
	return nil
}

func (c *PackageFile) PreInstallScript() string {
	return c.preinst
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
