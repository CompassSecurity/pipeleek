package scan

import (
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

func TestAzureDevOpsNewClient_TLSReflectsGlobalConfig(t *testing.T) {
	tests := []struct {
		name               string
		insecureSkipVerify bool
	}{
		{"skip=true", true},
		{"skip=false", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpclient.SetInsecureSkipVerify(tt.insecureSkipVerify)
			t.Cleanup(func() { httpclient.SetInsecureSkipVerify(true) })

			c := NewClient("u", "p", "")
			rawTr, ok := c.Client.Transport().(*http.Transport)
			if !ok {
				t.Fatalf("expected *http.Transport, got %T", c.Client.Transport())
			}
			got := rawTr.TLSClientConfig.InsecureSkipVerify
			if got != tt.insecureSkipVerify {
				t.Errorf("InsecureSkipVerify: want %v, got %v", tt.insecureSkipVerify, got)
			}
		})
	}
}
