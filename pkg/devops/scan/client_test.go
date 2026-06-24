package scan

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
)

func TestAzureDevOpsNewClient_UsesPipeleekTransport(t *testing.T) {
	httpclient.SetInsecureSkipVerify(false)
	t.Cleanup(func() { httpclient.SetInsecureSkipVerify(true) })

	c := NewClient("user", "pass", "https://dev.azure.com")

	tr, ok := c.Client.Transport().(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport as client transport, got %T", c.Client.Transport())
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("expected TLSClientConfig to be set on transport")
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=false to be reflected from Pipeleek global config")
	}
}

func TestAzureDevOpsNewClient_DefaultBaseURL(t *testing.T) {
	c := NewClient("user", "pass", "")
	if c.BaseURL != "https://dev.azure.com" {
		t.Errorf("unexpected default BaseURL: %s", c.BaseURL)
	}
}

func TestAzureDevOpsNewClient_VsspsURLIsFixed(t *testing.T) {
	c := NewClient("user", "pass", "https://dev.azure.com")
	if c.VsspsURL != "https://app.vssps.visualstudio.com" {
		t.Errorf("unexpected VsspsURL: %s", c.VsspsURL)
	}
}

func TestAzureDevOpsNewClient_TLSAlwaysVerified(t *testing.T) {
	// Azure DevOps is cloud-only (dev.azure.com) and always has a valid TLS
	// certificate. The client must enforce certificate verification regardless
	// of the global --tls-verification flag.
	for _, globalSkip := range []bool{true, false} {
		t.Run(fmt.Sprintf("globalSkip=%v", globalSkip), func(t *testing.T) {
			httpclient.SetInsecureSkipVerify(globalSkip)
			t.Cleanup(func() { httpclient.SetInsecureSkipVerify(true) })

			c := NewClient("u", "p", "")
			rawTr, ok := c.Client.Transport().(*http.Transport)
			if !ok {
				t.Fatalf("expected *http.Transport, got %T", c.Client.Transport())
			}
			if rawTr.TLSClientConfig.InsecureSkipVerify {
				t.Error("InsecureSkipVerify must always be false for Azure DevOps (cloud-only service)")
			}
		})
	}
}
