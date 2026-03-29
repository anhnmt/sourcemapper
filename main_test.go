package main

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/projectdiscovery/retryablehttp-go"
)

// TestOptionsStructCreation verifies we can create Options struct correctly
func TestOptionsStructCreation(t *testing.T) {
	options := retryablehttp.Options{
		RetryWaitMin: 1 * time.Second,
		RetryWaitMax: 5 * time.Second,
		Timeout:      30 * time.Second,
		RetryMax:     3,
	}

	if options.RetryMax != 3 {
		t.Errorf("Expected RetryMax=3, got %d", options.RetryMax)
	}

	if options.Timeout != 30*time.Second {
		t.Errorf("Expected Timeout=30s, got %v", options.Timeout)
	}
}

// TestNewClient verifies NewClient works with Options
func TestNewClient(t *testing.T) {
	options := retryablehttp.Options{
		RetryMax: 2,
		Timeout:  10 * time.Second,
	}

	client := retryablehttp.NewClient(options)
	if client == nil {
		t.Error("NewClient returned nil")
	}
}

// TestNewWithHTTPClient verifies NewWithHTTPClient works
func TestNewWithHTTPClient(t *testing.T) {
	// Create custom HTTP client
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			MaxIdleConns: 100,
		},
	}

	// Create Options
	options := retryablehttp.Options{
		RetryWaitMin: 1 * time.Second,
		RetryWaitMax: 5 * time.Second,
		Timeout:      30 * time.Second,
		RetryMax:     5,
	}

	// Create retryable client
	client := retryablehttp.NewWithHTTPClient(httpClient, options)
	if client == nil {
		t.Error("NewWithHTTPClient returned nil")
	}
}

// TestHTTPClientConfig verifies our config struct
func TestHTTPClientConfig(t *testing.T) {
	cfg := httpClientConfig{
		timeout:      30 * time.Second,
		retries:      5,
		insecure:     true,
		followRedirs: true,
		maxRedirs:    10,
	}

	if cfg.retries != 5 {
		t.Errorf("Expected retries=5, got %d", cfg.retries)
	}

	if !cfg.insecure {
		t.Error("Expected insecure=true")
	}
}

// TestNewHTTPClientFunction verifies our newHTTPClient function
func TestNewHTTPClientFunction(t *testing.T) {
	cfg := httpClientConfig{
		timeout:      30 * time.Second,
		retries:      3,
		insecure:     false,
		followRedirs: true,
		maxRedirs:    10,
	}

	client := newHTTPClient(cfg)
	if client == nil {
		t.Error("newHTTPClient returned nil")
	}
}
