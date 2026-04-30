package scan

import (
	"bytes"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitializeOptions(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		opts, err := InitializeOptions(
			"https://gitlab.example.com",
			"token",
			"",
			"",
			"",
			false,
			false,
			4,
			true,
			[]string{"high"},
			30*time.Second,
		)

		require.NoError(t, err)
		require.NotNil(t, opts)
		assert.Equal(t, "https://gitlab.example.com", opts.GitlabURL)
		assert.Equal(t, 4, opts.MaxScanGoRoutines)
		assert.Equal(t, []string{"high"}, opts.ConfidenceFilter)
	})

	t.Run("invalid url", func(t *testing.T) {
		opts, err := InitializeOptions(
			"://not-a-url",
			"token",
			"",
			"",
			"",
			false,
			false,
			4,
			true,
			nil,
			30*time.Second,
		)

		require.Error(t, err)
		assert.Nil(t, opts)
	})

	t.Run("project and namespace exclusive", func(t *testing.T) {
		opts, err := InitializeOptions(
			"https://gitlab.example.com",
			"token",
			"group/project",
			"group",
			"",
			false,
			false,
			4,
			true,
			nil,
			30*time.Second,
		)

		require.Error(t, err)
		assert.Nil(t, opts)
	})
}

func TestRefFromRawURL(t *testing.T) {
	t.Run("extracts ref", func(t *testing.T) {
		ref := refFromRawURL("https://gitlab.com/group/project/-/snippets/123/raw/main/path/to/file.txt")
		assert.Equal(t, "main", ref)
	})

	t.Run("defaults to head", func(t *testing.T) {
		ref := refFromRawURL("https://gitlab.com/group/project/-/snippets/123")
		assert.Equal(t, "HEAD", ref)
	})
}

func TestEncodeFilePath(t *testing.T) {
	encoded := encodeFilePath("dir with spaces/file+#name.txt")
	assert.Equal(t, "dir%20with%20spaces%2Ffile+%23name.txt", encoded)
}

func TestMarkSnippetProcessed(t *testing.T) {
	scanner := &snippetsScanner{}

	scanner.markSnippetProcessed(101)
	scanner.markSnippetProcessed(102)

	assert.Equal(t, int64(102), scanner.lastSnippetID.Load())
	assert.Equal(t, int64(2), scanner.processedSnippets.Load())
}

func TestStatusFields(t *testing.T) {
	scanner := &snippetsScanner{}
	scanner.markSnippetProcessed(4242)

	var buffer bytes.Buffer
	originalLogger := log.Logger
	log.Logger = zerolog.New(&buffer)
	defer func() {
		log.Logger = originalLogger
	}()

	scanner.Status().Msg("Status")

	serialized := buffer.String()
	assert.Contains(t, serialized, "lastSnippetId")
	assert.Contains(t, serialized, "processedSnippets")
	assert.Contains(t, serialized, "4242")
	assert.Contains(t, serialized, "1")
}
