package artifact

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/archive"
	"github.com/CompassSecurity/pipeleek/pkg/scanner"
	"github.com/CompassSecurity/pipeleek/pkg/scanner/engine"
	"github.com/h2non/filetype"
)

// ErrReleaseAssetTooLarge marks a policy skip rather than a processing failure.
var ErrReleaseAssetTooLarge = errors.New("release asset exceeds byte limit")

// ReleaseProcessOptions controls release-only processing without changing pipeline
// artifact handling. MaxBytes bounds both input size and cumulative expanded
// payloads, including intermediate nested archives and decompressed tar streams.
type ReleaseProcessOptions struct {
	MaxBytes          int64
	VerifyCredentials bool
	HitTimeout        time.Duration
	GitLabURL         string
	// ReportFinding receives the archive-relative file path and archive names
	// joined by " -> ". A standalone file has an empty archive ancestry.
	ReportFinding func(scanner.Finding, string, string)
}

type releaseProcessor struct {
	opts     ReleaseProcessOptions
	expanded int64
	detect   func([]byte, int, bool, engine.DetectionOptions) ([]scanner.Finding, error)
}

// ProcessReleaseAsset scans content in memory; it never extracts files to disk or
// executes assets. ZIP, tar, gzip, and bzip2 are supported up to ten archive layers.
// Unsupported archives and incomplete processing return errors.
func ProcessReleaseAsset(content []byte, filename string, opts ReleaseProcessOptions) error {
	if opts.MaxBytes <= 0 {
		return errors.New("release asset byte limit must be positive")
	}
	if int64(len(content)) > opts.MaxBytes {
		return ErrReleaseAssetTooLarge
	}
	if opts.ReportFinding == nil {
		return errors.New("release asset finding reporter is required")
	}
	p := releaseProcessor{opts: opts, detect: engine.DetectHitsWithOptions}
	return p.process(content, filename, nil, 0)
}

func (p *releaseProcessor) readExpanded(r io.Reader) ([]byte, error) {
	remaining := p.opts.MaxBytes - p.expanded
	// Avoid remaining+1 overflow, while still probing for an extra byte.
	content, err := io.ReadAll(io.LimitReader(r, remaining))
	p.expanded += int64(len(content))
	if err != nil {
		return nil, err
	}
	var extra [1]byte
	n, err := io.ReadFull(r, extra[:])
	if n != 0 {
		return nil, ErrReleaseAssetTooLarge
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return content, nil
}

func releaseArchiveType(content []byte, filename string) string {
	kind, _ := filetype.Match(content)
	switch kind.Extension {
	case "zip", "tar", "gz", "bz2":
		return kind.Extension
	}
	if filetype.IsArchive(content) {
		return "unsupported"
	}
	name := strings.ToLower(filename)
	for _, suffix := range []struct{ ext, kind string }{
		{".tar.gz", "gz"}, {".tgz", "gz"}, {".tar.bz2", "bz2"}, {".tbz2", "bz2"}, {".tbz", "bz2"},
		{".zip", "zip"}, {".tar", "tar"}, {".gzip", "gz"}, {".gz", "gz"}, {".bz2", "bz2"}, {".bzip2", "bz2"},
		{".7z", "unsupported"}, {".rar", "unsupported"}, {".xz", "unsupported"},
		{".zst", "unsupported"}, {".zstd", "unsupported"}, {".lz", "unsupported"},
		{".lzma", "unsupported"}, {".lz4", "unsupported"}, {".cab", "unsupported"},
		{".ar", "unsupported"}, {".deb", "unsupported"}, {".rpm", "unsupported"},
		{".txz", "unsupported"}, {".taz", "unsupported"}, {".z", "unsupported"},
		{".iso", "unsupported"}, {".dmg", "unsupported"},
	} {
		if strings.HasSuffix(name, suffix.ext) {
			return suffix.kind
		}
	}
	return ""
}

func (p *releaseProcessor) process(content []byte, filename string, ancestry []string, depth int) error {
	kind := releaseArchiveType(content, filename)
	if kind == "" {
		findings, err := p.detect(archive.ExtractPrintableStrings(content, archive.MinStringLength), 1,
			p.opts.VerifyCredentials, engine.DetectionOptions{
				Path: filename, GitLabURL: p.opts.GitLabURL, Timeout: p.opts.HitTimeout,
			})
		if err != nil {
			return fmt.Errorf("detect release asset %q: %w", filename, err)
		}
		for _, finding := range findings {
			p.opts.ReportFinding(finding, filename, strings.Join(ancestry, " -> "))
		}
		return nil
	}
	if depth >= 10 {
		return fmt.Errorf("release archive %q exceeds maximum nesting depth 10", filename)
	}
	ancestry = append(append([]string(nil), ancestry...), filename)
	switch kind {
	case "zip":
		return p.processZip(content, ancestry, depth+1)
	case "tar":
		return p.processTar(content, ancestry, depth+1)
	case "gz", "bz2":
		return p.processCompressed(content, filename, kind, ancestry, depth+1)
	default:
		return fmt.Errorf("unsupported release archive %q", filename)
	}
}

func releaseRelativePath(name string) (string, error) {
	// Backslashes may be directory separators on a producer's platform.
	name = strings.ReplaceAll(name, `\`, "/")
	clean := path.Clean(name)
	if strings.ContainsRune(name, '\x00') || strings.Contains(name, ":") ||
		path.IsAbs(name) || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("unsafe release archive member path %q", name)
	}
	return clean, nil
}

func (p *releaseProcessor) processZip(content []byte, ancestry []string, depth int) error {
	zr, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return fmt.Errorf("decode release ZIP: %w", err)
	}
	for _, member := range zr.File {
		if member.FileInfo().IsDir() && (member.Name == "./" || member.Name == ".") {
			continue
		}
		name, err := releaseRelativePath(member.Name)
		if err != nil {
			return err
		}
		if member.FileInfo().IsDir() {
			continue
		}
		if !member.Mode().IsRegular() {
			return fmt.Errorf("unsupported release ZIP member type %q", name)
		}
		if member.UncompressedSize64 > uint64(p.opts.MaxBytes-p.expanded) {
			return ErrReleaseAssetTooLarge
		}
		r, err := member.Open()
		if err != nil {
			return fmt.Errorf("open release ZIP member %q: %w", name, err)
		}
		payload, readErr := p.readExpanded(r)
		closeErr := r.Close()
		if readErr != nil {
			return fmt.Errorf("read release ZIP member %q: %w", name, readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close release ZIP member %q: %w", name, closeErr)
		}
		if err := p.process(payload, name, ancestry, depth); err != nil {
			return err
		}
	}
	return nil
}

func (p *releaseProcessor) processTar(content []byte, ancestry []string, depth int) error {
	if len(content) < 512 {
		return errors.New("decode release tar: missing archive header")
	}
	tr := tar.NewReader(bytes.NewReader(content))
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("decode release tar: %w", err)
		}
		if header.Typeflag == tar.TypeDir && (header.Name == "." || header.Name == "./") {
			continue
		}
		name, err := releaseRelativePath(header.Name)
		if err != nil {
			return err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg, tar.TypeRegA:
		default:
			return fmt.Errorf("unsupported release tar member type %q", name)
		}
		if header.Size > p.opts.MaxBytes-p.expanded {
			return ErrReleaseAssetTooLarge
		}
		payload, err := p.readExpanded(tr)
		if err != nil {
			return fmt.Errorf("read release tar member %q: %w", name, err)
		}
		if err := p.process(payload, name, ancestry, depth); err != nil {
			return err
		}
	}
}

func (p *releaseProcessor) processCompressed(content []byte, filename, kind string, ancestry []string, depth int) error {
	var r io.Reader
	if kind == "gz" {
		gz, err := gzip.NewReader(bytes.NewReader(content))
		if err != nil {
			return fmt.Errorf("decode release gzip: %w", err)
		}
		defer func() { _ = gz.Close() }()
		r = gz
	} else {
		r = bzip2.NewReader(bytes.NewReader(content))
	}
	payload, err := p.readExpanded(r)
	if err != nil {
		return fmt.Errorf("expand release %s: %w", kind, err)
	}
	innerName := strings.TrimSuffix(filename, path.Ext(filename))
	lower := strings.ToLower(filename)
	if strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".tbz2") || strings.HasSuffix(lower, ".tbz") {
		innerName += ".tar"
	}
	if releaseArchiveType(payload, innerName) == "tar" {
		// A compressed tar is one archive layer, with its original asset name.
		return p.processTar(payload, ancestry, depth)
	}
	return p.process(payload, innerName, ancestry, depth)
}
