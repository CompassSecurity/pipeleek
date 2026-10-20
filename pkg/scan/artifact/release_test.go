package artifact

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/scanner"
	"github.com/CompassSecurity/pipeleek/pkg/scanner/engine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type releaseTestFile struct {
	name    string
	content []byte
}

func releaseTestZip(t *testing.T, files ...releaseTestFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, file := range files {
		f, err := w.Create(file.name)
		require.NoError(t, err)
		_, err = f.Write(file.content)
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return buf.Bytes()
}

func releaseTestTar(t *testing.T, files ...releaseTestFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for _, file := range files {
		require.NoError(t, w.WriteHeader(&tar.Header{
			Name: file.name, Mode: 0o600, Size: int64(len(file.content)),
		}))
		_, err := w.Write(file.content)
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return buf.Bytes()
}

func releaseTestGzip(t *testing.T, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, err := w.Write(content)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

func releaseTestOptions() ReleaseProcessOptions {
	return ReleaseProcessOptions{
		MaxBytes: 1 << 20, HitTimeout: time.Minute,
		ReportFinding: func(scanner.Finding, string, string) {},
	}
}

func TestReleaseAssetMetadataAndPrintableStrings(t *testing.T) {
	text := []byte("release-secret-value")
	binary := append([]byte{0x7f, 'E', 'L', 'F', 0, 1}, text...)
	binary = append(binary, 0, 1, 2)
	inner := releaseTestGzip(t, releaseTestTar(t, releaseTestFile{"config/secret.txt", text}))
	bzip, err := base64.StdEncoding.DecodeString("QlpoOTFBWSZTWYglTdEAAAaRgAACKgQfACAAIp5BiEAMKUPmg4LYhlI8LuSKcKEhEEqbog==")
	require.NoError(t, err)
	tests := []struct {
		name, filename, wantPath, wantAncestry string
		content                                []byte
	}{
		{"plain", "notes.txt", "notes.txt", "", text},
		{"binary", "program", "program", "", binary},
		{"ZIP", "bundle.zip", "config/secret.txt", "bundle.zip",
			releaseTestZip(t, releaseTestFile{"config/secret.txt", text})},
		{"tar", "bundle.tar", "config/secret.txt", "bundle.tar",
			releaseTestTar(t, releaseTestFile{"config/secret.txt", text})},
		{"tar gzip", "bundle.tar.gz", "config/secret.txt", "bundle.tar.gz", inner},
		{"tgz", "bundle.tgz", "config/secret.txt", "bundle.tgz", inner},
		{"gzip", "notes.txt.gz", "notes.txt", "notes.txt.gz", releaseTestGzip(t, text)},
		{"bzip2", "notes.txt.bz2", "notes.txt", "notes.txt.bz2", bzip},
		{"nested ZIP tar gzip", "outer.zip", "config/secret.txt", "outer.zip -> packages/inner.tar.gz",
			releaseTestZip(t, releaseTestFile{"packages/inner.tar.gz", inner})},
		{"nested ZIP", "outer.zip", "config/secret.txt", "outer.zip -> packages/inner.zip",
			releaseTestZip(t, releaseTestFile{"packages/inner.zip",
				releaseTestZip(t, releaseTestFile{"config/secret.txt", text})})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := releaseTestOptions()
			opts.VerifyCredentials = true
			opts.GitLabURL = "https://gitlab.example.test"
			var reported int
			finding := scanner.Finding{Text: string(text)}
			opts.ReportFinding = func(actual scanner.Finding, file, ancestry string) {
				reported++
				assert.Equal(t, finding, actual)
				assert.Equal(t, tt.wantPath, file)
				assert.Equal(t, tt.wantAncestry, ancestry)
			}
			p := releaseProcessor{opts: opts, detect: func(content []byte, threads int, verify bool, options engine.DetectionOptions) ([]scanner.Finding, error) {
				assert.Contains(t, string(content), string(text))
				assert.NotContains(t, string(content), "\x00")
				assert.Equal(t, 1, threads)
				assert.True(t, verify)
				assert.Equal(t, tt.wantPath, options.Path)
				assert.Equal(t, opts.HitTimeout, options.Timeout)
				assert.Equal(t, opts.GitLabURL, options.GitLabURL)
				return []scanner.Finding{finding}, nil
			}}
			require.NoError(t, p.process(tt.content, tt.filename, nil, 0))
			assert.Equal(t, 1, reported)
		})
	}
}

func TestReleaseAssetByteLimits(t *testing.T) {
	plain := []byte("plain release text")
	opts := releaseTestOptions()
	opts.MaxBytes = int64(len(plain))
	require.NoError(t, ProcessReleaseAsset(plain, "plain.txt", opts))
	opts.MaxBytes--
	require.ErrorIs(t, ProcessReleaseAsset(plain, "plain.txt", opts), ErrReleaseAssetTooLarge)
	opts.MaxBytes = 0
	require.ErrorContains(t, ProcessReleaseAsset(nil, "plain.txt", opts), "positive")
	opts.MaxBytes = -1
	require.ErrorContains(t, ProcessReleaseAsset(nil, "plain.txt", opts), "positive")

	// Use compressible data so the expanded limit, not the input limit, is hit.
	payload := bytes.Repeat([]byte("harmless content\n"), 512)
	for _, kind := range []string{"zip", "gz"} {
		t.Run(kind, func(t *testing.T) {
			var content []byte
			if kind == "zip" {
				content = releaseTestZip(t, releaseTestFile{"one.txt", payload})
			} else {
				content = releaseTestGzip(t, payload)
			}
			opts := releaseTestOptions()
			opts.MaxBytes = int64(len(payload))
			require.NoError(t, ProcessReleaseAsset(content, "asset."+kind, opts))
			opts.MaxBytes--
			require.ErrorIs(t, ProcessReleaseAsset(content, "asset."+kind, opts), ErrReleaseAssetTooLarge)
		})
	}
	t.Run("cumulative siblings", func(t *testing.T) {
		content := releaseTestZip(t, releaseTestFile{"one.txt", payload}, releaseTestFile{"two.txt", payload})
		opts := releaseTestOptions()
		opts.MaxBytes = int64(2 * len(payload))
		require.NoError(t, ProcessReleaseAsset(content, "asset.zip", opts))
		opts.MaxBytes--
		require.ErrorIs(t, ProcessReleaseAsset(content, "asset.zip", opts), ErrReleaseAssetTooLarge)
	})
	t.Run("cumulative nested archives", func(t *testing.T) {
		inner := releaseTestZip(t, releaseTestFile{"one.txt", payload})
		content := releaseTestZip(t, releaseTestFile{"inner.zip", inner})
		opts := releaseTestOptions()
		opts.MaxBytes = int64(len(inner) + len(payload))
		require.NoError(t, ProcessReleaseAsset(content, "outer.zip", opts))
		opts.MaxBytes--
		require.ErrorIs(t, ProcessReleaseAsset(content, "outer.zip", opts), ErrReleaseAssetTooLarge)
	})
	t.Run("tar gzip includes intermediate stream", func(t *testing.T) {
		inner := releaseTestTar(t, releaseTestFile{"one.txt", payload})
		content := releaseTestGzip(t, inner)
		opts := releaseTestOptions()
		opts.MaxBytes = int64(len(inner) + len(payload))
		require.NoError(t, ProcessReleaseAsset(content, "asset.tar.gz", opts))
		opts.MaxBytes--
		require.ErrorIs(t, ProcessReleaseAsset(content, "asset.tar.gz", opts), ErrReleaseAssetTooLarge)
	})
}

func TestReleaseAssetDepth(t *testing.T) {
	content := []byte("harmless release text")
	for depth := 1; depth <= 11; depth++ {
		name := "inner.txt"
		if depth > 1 {
			name = "inner.zip"
		}
		content = releaseTestZip(t, releaseTestFile{name, content})
		err := ProcessReleaseAsset(content, "outer.zip", releaseTestOptions())
		if depth <= 10 {
			require.NoError(t, err, "depth %d", depth)
		} else {
			require.ErrorContains(t, err, "maximum nesting depth")
			require.NotErrorIs(t, err, ErrReleaseAssetTooLarge)
		}
	}
}

func TestReleaseAssetErrors(t *testing.T) {
	goodGzip := releaseTestGzip(t, []byte("release content"))
	corruptGzip := bytes.Clone(goodGzip)
	corruptGzip[len(corruptGzip)-1] ^= 0xff
	badTar := releaseTestTar(t, releaseTestFile{"file.txt", []byte("content")})
	badTar[0] ^= 0xff
	truncatedTar := releaseTestTar(t, releaseTestFile{"file.txt", bytes.Repeat([]byte("a"), 1024)})[:600]
	innerBadZip := releaseTestZip(t, releaseTestFile{"inner.zip", []byte("invalid ZIP")})
	badZip := releaseTestZip(t, releaseTestFile{"text.txt", []byte("content")})
	zr, err := zip.NewReader(bytes.NewReader(badZip), int64(len(badZip)))
	require.NoError(t, err)
	offset, err := zr.File[0].DataOffset()
	require.NoError(t, err)
	badZip[offset] ^= 0xff
	for _, tt := range []struct {
		name    string
		content []byte
	}{
		{"broken.zip", []byte("not a zip")},
		{"corrupt.zip", badZip},
		{"broken.tar", []byte("not a tar")},
		{"empty.tar", nil},
		{"badheader.tar", badTar},
		{"truncated.tar", truncatedTar},
		{"broken.gz", []byte("not a gzip")},
		{"checksum.gz", corruptGzip},
		{"truncated.gz", goodGzip[:len(goodGzip)-3]},
		{"broken.bz2", []byte("not bzip2")},
		{"unsupported.7z", []byte("unsupported archive")},
		{"unsupported.xz", []byte("unsupported archive")},
		{"unsupported.rar", []byte("unsupported archive")},
		{"unsupported-without-extension", []byte("7z\xbc\xaf\x27\x1c")},
		{"nested.zip", innerBadZip},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := ProcessReleaseAsset(tt.content, tt.name, releaseTestOptions())
			require.Error(t, err)
			require.NotErrorIs(t, err, ErrReleaseAssetTooLarge)
		})
	}
	t.Run("detection timeout", func(t *testing.T) {
		opts := releaseTestOptions()
		opts.HitTimeout = -time.Second
		require.ErrorContains(t, ProcessReleaseAsset([]byte("some content"), "notes.txt", opts), "timed out")
	})
	t.Run("detection error propagation", func(t *testing.T) {
		want := errors.New("detection failed")
		p := releaseProcessor{opts: releaseTestOptions(), detect: func([]byte, int, bool, engine.DetectionOptions) ([]scanner.Finding, error) {
			return nil, want
		}}
		require.ErrorIs(t, p.process([]byte("content"), "notes.txt", nil, 0), want)
	})
	t.Run("missing reporter", func(t *testing.T) {
		opts := releaseTestOptions()
		opts.ReportFinding = nil
		require.ErrorContains(t, ProcessReleaseAsset(nil, "empty.txt", opts), "reporter")
	})
}

func TestReleaseExpandedStreamingLimit(t *testing.T) {
	p := releaseProcessor{opts: releaseTestOptions()}
	p.opts.MaxBytes = 16
	r := bytes.NewReader(bytes.Repeat([]byte("x"), 1024))
	_, err := p.readExpanded(r)
	require.ErrorIs(t, err, ErrReleaseAssetTooLarge)
	require.Equal(t, int64(17), r.Size()-int64(r.Len()), "consume at most the budget plus one probe byte")
	require.Equal(t, int64(16), p.expanded)

	p = releaseProcessor{opts: releaseTestOptions()}
	p.opts.MaxBytes = 4
	content, err := p.readExpanded(strings.NewReader("1234"))
	require.NoError(t, err)
	require.Equal(t, "1234", string(content))
	content, err = p.readExpanded(strings.NewReader(""))
	require.NoError(t, err)
	require.Empty(t, content)
	_, err = p.readExpanded(strings.NewReader("x"))
	require.ErrorIs(t, err, ErrReleaseAssetTooLarge)

	p = releaseProcessor{opts: releaseTestOptions()}
	_, err = p.readExpanded(io.MultiReader(strings.NewReader("data"), releaseErrorReader{}))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

type releaseErrorReader struct{}

func (releaseErrorReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func TestReleaseEmptyArchivesAndDirectories(t *testing.T) {
	for _, tt := range []struct {
		name    string
		content []byte
	}{
		{"empty.zip", releaseTestZip(t)},
		{"empty.tar", releaseTestTar(t)},
		{"root.zip", releaseTestZip(t, releaseTestFile{"./", nil}, releaseTestFile{"folder/", nil})},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, ProcessReleaseAsset(tt.content, tt.name, releaseTestOptions()))
		})
	}
}

func TestReleaseAssetUnsafeMembers(t *testing.T) {
	for _, name := range []string{"../secret.txt", "/secret.txt", `C:\secret.txt`, `..\secret.txt`} {
		t.Run(fmt.Sprintf("ZIP/%s", name), func(t *testing.T) {
			content := releaseTestZip(t, releaseTestFile{name, []byte("secret")})
			require.ErrorContains(t, ProcessReleaseAsset(content, "outer.zip", releaseTestOptions()), "unsafe")
		})
		t.Run(fmt.Sprintf("tar/%s", name), func(t *testing.T) {
			content := releaseTestTar(t, releaseTestFile{name, []byte("secret")})
			require.ErrorContains(t, ProcessReleaseAsset(content, "outer.tar", releaseTestOptions()), "unsafe")
		})
	}
	t.Run("tar symlink", func(t *testing.T) {
		var buf bytes.Buffer
		w := tar.NewWriter(&buf)
		require.NoError(t, w.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}))
		require.NoError(t, w.Close())
		require.ErrorContains(t, ProcessReleaseAsset(buf.Bytes(), "outer.tar", releaseTestOptions()), "unsupported")
	})
}

func TestReleaseAssetRealEngineFinding(t *testing.T) {
	opts := releaseTestOptions()
	var found bool
	opts.ReportFinding = func(f scanner.Finding, filename, ancestry string) {
		if strings.Contains(f.Text, "glpat-zxywvutsrqponmlkjihg") {
			found = true
			assert.Equal(t, "secrets/config.txt", filename)
			assert.Equal(t, "release.zip", ancestry)
		}
	}
	content := releaseTestZip(t, releaseTestFile{"secrets/config.txt", []byte("GITLAB_TOKEN=glpat-zxywvutsrqponmlkjihg")})
	require.NoError(t, ProcessReleaseAsset(content, "release.zip", opts))
	require.True(t, found, "public processor must invoke the real detection engine and reporter")
}
