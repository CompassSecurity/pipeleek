package rules

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

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
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, fmt.Errorf("reading downloaded rules: %w", err)
	}
	patterns, err := parseRules(data, source)
	if err != nil {
		return 0, err
	}
	if len(patterns) == 0 {
		return 0, fmt.Errorf("downloaded rules contain no patterns")
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	// #nosec G304 -- output is the explicit destination selected by the user through CLI/config.
	file, err := os.OpenFile(output, flags, 0600)
	if err != nil {
		return 0, fmt.Errorf("opening rules output %s: %w", output, err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return 0, fmt.Errorf("writing rules: %w", err)
	}
	if err := file.Close(); err != nil {
		return 0, fmt.Errorf("closing rules: %w", err)
	}
	return len(patterns), nil
}
