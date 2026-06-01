package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const metaFileName = "bundle.meta.json"

// Pack writes a gzip tarball from files under cacheDir (relative paths preserved).
func Pack(cacheDir, source string, meta Meta, outPath string) error {
	if meta.Source == "" {
		meta.Source = source
	}
	if meta.SchemaVersion == 0 {
		meta.SchemaVersion = metaSchemaVersion
	}
	if meta.BuiltAt.IsZero() {
		return fmt.Errorf("bundle built_at is required")
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	metaPayload, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	if err := writeTarBytes(tw, metaFileName, metaPayload); err != nil {
		return err
	}

	walkRoot := cacheDir
	err = filepath.Walk(walkRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(walkRoot, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == metaFileName {
			return nil
		}
		if !includeCacheFile(source, rel) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return writeTarBytes(tw, rel, data)
	})
	if err != nil {
		return err
	}

	if err := tw.Close(); err != nil {
		return err
	}
	if err := gw.Close(); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	tmp := outPath + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, outPath)
}

func includeCacheFile(source, rel string) bool {
	switch {
	case strings.HasPrefix(rel, "sync/"+source+"/manifest.json"):
		return true
	case source == "osv" && rel == "mal/compiled.json":
		return true
	case source == "pd" && rel == "mal/pd_compiled.json":
		return true
	case source == "osv" && rel == "feed/index.json":
		return true
	case source == "osv" && strings.HasPrefix(rel, "vulns/") && strings.HasSuffix(rel, ".json"):
		return true
	default:
		return false
	}
}

func writeTarBytes(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0o644,
		Size:    int64(len(data)),
		ModTime: time.Now().UTC(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

// Extract unpacks a bundle tarball into cacheDir.
func Extract(cacheDir string, tarball []byte) (Meta, error) {
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
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := filepath.Clean(hdr.Name)
		if strings.Contains(name, "..") {
			return meta, fmt.Errorf("invalid tar path %q", hdr.Name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, 64<<20))
		if err != nil {
			return meta, err
		}
		if name == metaFileName {
			if err := json.Unmarshal(data, &meta); err != nil {
				return meta, err
			}
			continue
		}
		dest := filepath.Join(cacheDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return meta, err
		}
		tmp := dest + ".tmp"
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			return meta, err
		}
		if err := os.Rename(tmp, dest); err != nil {
			return meta, err
		}
	}
	if meta.Source == "" {
		return meta, fmt.Errorf("bundle missing %s", metaFileName)
	}
	return meta, nil
}
