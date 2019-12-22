# go-deb
A native implementation of the Debian specification in Go,
which is very much inspired by [go-rpm](https://github.com/cavaliercoder/go-rpm).
The `go-deb` is trying to replicate `go-rpm` as close as possible in order to provide
more or less common API. The difference between RPM and Dpkg, however, inevitable.

	$ go get github.com/isbm/go-deb


Same as go-rpm, go-deb package aims to enable cross-platform tooling for dpkg
written in Go.

Initial goals include like-for-like implementation of existing Dpkg ecosystem
features such as:

* Reading of modern and legacy Debian package file formats
* Reading, creating and updating modern and legacy Dpkg repository metadata


```go
package main

import (
	"fmt"
	"github.com/isbm/go-deb"
)

func main() {
	p, err := deb.OpenPackageFile("golang_1.12~1_amd64.deb")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Loaded package: %v - %s\n", p, p.Summary())
}
```
