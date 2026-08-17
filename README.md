#  cryptonic

Abstraction to crypto Library based on my crypto-textbook learning experiment

## Install

```
go get go-mw.de/pkg/cryptonic
```

```go
import "go-mw.de/pkg/cryptonic"
```

`go-mw.de/pkg/cryptonic` is a vanity import path. The meta tags that point the Go
toolchain at this repository are served by the
[appengine](https://github.com/go-mw-de/appengine) project, so the import path stays
stable even if the code moves to another host. The previous paths
`github.com/go-mw-de/cryptonic` and `gitlab.com/go-mw-de/cryptonic` are no longer
importable; update your imports and run `go mod tidy`.
