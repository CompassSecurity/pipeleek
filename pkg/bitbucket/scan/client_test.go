package scan

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"testing"

	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
)

func TestNewClient_UsesPipeleekTransport(t *testing.T) {
	// Arrange: configure a distinct InsecureSkipVerify value so we can detect it.
	httpclient.SetInsecureSkipVerify(false)
	t.Cleanup(func() { httpclient.SetInsecureSkipVerify(true) })

	c := NewClient("user", "pass", "", "https://api.bitbucket.org/2.0")

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

func TestNewClient_DefaultBaseURL(t *testing.T) {
	c := NewClient("user", "pass", "", "")
	if c.BaseURL != "https://api.bitbucket.org/2.0" {
		t.Errorf("unexpected default BaseURL: %s", c.BaseURL)
	}
}

func TestNewClient_InternalBaseURLDerivedFromDefault(t *testing.T) {
	c := NewClient("user", "pass", "", "")
	if c.InternalBaseURL != "https://bitbucket.org/!api" {
		t.Errorf("unexpected InternalBaseURL: %s", c.InternalBaseURL)
	}
}

func TestNewClient_CookieJarSetWhenCookieProvided(t *testing.T) {
	c := NewClient("user", "pass", "tok123", "https://api.bitbucket.org/2.0")
	if c.Client.CookieJar() == nil {
		t.Error("expected cookie jar to be set when cookie is provided")
	}
}

func TestNewClient_NoCookieSetWhenNoCookie(t *testing.T) {
	// Resty v3 always creates a default cookie jar. When no BitBucket cookie is
	// provided, no cloud.session.token cookie should be present in the jar.
	c := NewClient("user", "pass", "", "https://api.bitbucket.org/2.0")
	jar := c.Client.CookieJar()
	if jar == nil {
		// If Resty ever stops setting a default jar this test still passes.
		return
	}
	u, _ := url.Parse("https://bitbucket.org/!api")
	for _, ck := range jar.Cookies(u) {
		if ck.Name == "cloud.session.token" {
			t.Error("cloud.session.token should not be set in jar when no cookie provided")
		}
	}
}

func TestNewClient_TLSReflectsGlobalConfig(t *testing.T) {
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

			c := NewClient("u", "p", "", "https://api.bitbucket.org/2.0")
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

// ensure the helper compiles even when tls package is not directly used in tests above
var _ = (*tls.Config)(nil)
