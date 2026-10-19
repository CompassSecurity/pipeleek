package rules

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
)

const ExternalRulesURL = "https://raw.githubusercontent.com/mazen160/secrets-patterns-db/master/db/rules-stable.yml"

func Download(ctx context.Context, output string, force bool) (int, error) {
	client := httpclient.GetPipeleekStandardHTTPClient()
	defer client.CloseIdleConnections()
	return download(ctx, client, ExternalRulesURL, output, force)
}

func download(ctx context.Context, client *http.Client, source, output string, force bool) (int, error) {
	if !force {
		if _, err := os.Lstat(output); err == nil {
			return 0, fmt.Errorf("%s already exists; use --force to replace it", output)
		} else if !os.IsNotExist(err) {
			return 0, fmt.Errorf("checking output: %w", err)
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return 0, fmt.Errorf("creating rules request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, fmt.Errorf("downloading rules: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("downloading rules: unexpected HTTP status %d", response.StatusCode)
	}
	// Limit external input before parsing or writing it.
	const maxSize = 16 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, maxSize+1))
	if err != nil {
		return 0, fmt.Errorf("reading downloaded rules: %w", err)
	}
	if len(data) > maxSize {
		return 0, fmt.Errorf("downloaded rules exceed %d bytes", maxSize)
	}
	patterns, err := parseRules(data, source)
	if err != nil {
		return 0, err
	}
	if len(patterns) == 0 {
		return 0, fmt.Errorf("downloaded rules contain no patterns")
	}
	temp, err := os.CreateTemp(filepath.Dir(output), ".pipeleek-rules-*")
	if err != nil {
		return 0, fmt.Errorf("creating rules temporary file: %w", err)
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return 0, fmt.Errorf("writing rules: %w", err)
	}
	if err := temp.Close(); err != nil {
		return 0, fmt.Errorf("closing rules: %w", err)
	}
	if force {
		err = os.Rename(temp.Name(), output)
	} else {
		// Publish without replacing a file created while the download was running.
		err = os.Link(temp.Name(), output)
	}
	if err != nil {
		return 0, fmt.Errorf("saving rules to %s: %w", output, err)
	}
	return len(patterns), nil
}
