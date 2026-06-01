package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"

	"github.com/projectdiscovery/depx/internal/bundle/embedded"
)

func bytesForSource(source string) ([]byte, bool) {
	switch source {
	case "osv":
		if len(embedded.OSV) == 0 {
			return nil, false
		}
		return embedded.OSV, true
	case "pd":
		if len(embedded.PD) == 0 {
			return nil, false
		}
		return embedded.PD, true
	default:
		return nil, false
	}
}

func peekMeta(tarball []byte) (Meta, error) {
	var meta Meta
	gr, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return meta, err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return meta, err
		}
		if hdr.Name != metaFileName {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, 1<<20))
		if err != nil {
			return meta, err
		}
		if err := json.Unmarshal(data, &meta); err != nil {
			return meta, err
		}
		return meta, nil
	}
	return meta, fmt.Errorf("bundle missing %s", metaFileName)
}

// EmbeddedMeta returns metadata for an embedded bundle without extracting it.
func EmbeddedMeta(source string) (Meta, bool, error) {
	raw, ok := bytesForSource(source)
	if !ok {
		return Meta{}, false, nil
	}
	meta, err := peekMeta(raw)
	if err != nil {
		return Meta{}, true, err
	}
	return meta, true, nil
}
