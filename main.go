package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/retryablehttp-go"
)

// sourceMap represents a sourceMap. We only really care about the sources and
// sourcesContent arrays.
type sourceMap struct {
	Version        int      `json:"version"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

// httpClientConfig holds HTTP client configuration
type httpClientConfig struct {
	timeout      time.Duration
	retries      int
	insecure     bool
	proxy        *url.URL
	headers      map[string]string
	followRedirs bool
	maxRedirs    int
}

// options represents command line options
type options struct {
	Output      string              `flag:"output,o" validate:"required" description:"Output directory (required)"`
	URLs        goflags.StringSlice `flag:"url,u" description:"Sourcemap URL/path (comma-separated or multiple flags)"`
	JSURLs      goflags.StringSlice `flag:"jsurl,j" description:"JavaScript URL (comma-separated or multiple flags)"`
	Proxy       string              `flag:"proxy,p" description:"Proxy URL (http/socks5)"`
	Timeout     int                 `flag:"timeout,t" default:"30" description:"Request timeout in seconds"`
	Retries     int                 `flag:"retries,r" default:"3" description:"Number of retries for failed requests"`
	RateLimit   int                 `flag:"rate-limit,rl" default:"0" description:"Requests per second (0 = unlimited)"`
	Insecure    bool                `flag:"insecure,k" description:"Skip TLS certificate verification"`
	Headers     goflags.StringSlice `flag:"header,H" description:"HTTP header (comma-separated or multiple flags)"`
	Concurrency int                 `flag:"concurrency,c" default:"5" description:"Concurrent requests"`
	Silent      bool                `flag:"silent,s" description:"Silent mode (errors only)"`
	Verbose     bool                `flag:"verbose,v" description:"Verbose mode"`
}

// newHTTPClient creates a configured retryable HTTP client
func newHTTPClient(cfg httpClientConfig) *retryablehttp.Client {
	// Create transport
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.insecure,
		},
		DisableKeepAlives: false,
	}

	// Add proxy if configured
	if cfg.proxy != nil {
		transport.Proxy = http.ProxyURL(cfg.proxy)
	}

	// Create base HTTP client
	httpClient := &http.Client{
		Timeout:   cfg.timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !cfg.followRedirs {
				return http.ErrUseLastResponse
			}
			if len(via) >= cfg.maxRedirs {
				return errors.New("stopped after max redirects")
			}
			return nil
		},
	}

	// Create Options struct for retryablehttp
	options := retryablehttp.Options{
		RetryWaitMin: 1 * time.Second,
		RetryWaitMax: 5 * time.Second,
		Timeout:      cfg.timeout,
		RetryMax:     cfg.retries,
	}

	// Create retryable client
	client := retryablehttp.NewWithHTTPClient(httpClient, options)

	return client
}

// parseHeaders converts headerList to map
func parseHeaders(headers []string) map[string]string {
	headerMap := make(map[string]string)

	if len(headers) == 0 {
		return headerMap
	}

	headerString := strings.Join(headers, "\r\n") + "\r\n\r\n"
	r := bufio.NewReader(strings.NewReader(headerString))
	tpReader := textproto.NewReader(r)
	mimeHeader, err := tpReader.ReadMIMEHeader()

	if err != nil {
		log.Printf("[!] Error parsing headers: %v", err)
		return headerMap
	}

	for key, values := range mimeHeader {
		if len(values) > 0 {
			headerMap[key] = values[0]
		}
	}

	return headerMap
}

// getSourceMap retrieves a sourcemap from a URL or a local file and returns
// its sourceMap.
func getSourceMap(source string, client *retryablehttp.Client, headers map[string]string) (m sourceMap, err error) {
	var body []byte

	log.Printf("[+] Retrieving Sourcemap from %.1024s...\n", source)

	u, err := url.ParseRequestURI(source)
	if err != nil {
		// If it's a file, read it.
		body, err = os.ReadFile(source)
		if err != nil {
			return m, err
		}
	} else {
		if u.Scheme == "http" || u.Scheme == "https" {
			// If it's a URL, get it.
			req, err := retryablehttp.NewRequest("GET", u.String(), nil)
			if err != nil {
				return m, err
			}

			// Set headers
			for key, value := range headers {
				req.Header.Set(key, value)
			}

			res, err := client.Do(req)
			if err != nil {
				return m, err
			}
			defer res.Body.Close()

			body, err = io.ReadAll(res.Body)
			if err != nil {
				return m, err
			}

			if res.StatusCode != 200 && len(body) > 0 {
				log.Printf("[!] WARNING - non-200 status code: %d - Confirm this URL contains valid source map manually!", res.StatusCode)
				log.Printf("[!] WARNING - sourceMap URL request return != 200 - however, body length > 0 so continuing... ")
			}

		} else if u.Scheme == "data" {
			urlchunks := strings.Split(u.Opaque, ",")
			if len(urlchunks) < 2 {
				return m, errors.New("could not parse data URI - expected at least 2 chunks")
			}

			data, err := base64.StdEncoding.DecodeString(urlchunks[1])
			if err != nil {
				return m, err
			}

			body = []byte(data)
		} else {
			// If it's a file, read it.
			body, err = os.ReadFile(source)
			if err != nil {
				return m, err
			}
		}
	}

	// Unmarshal the body into the struct.
	log.Printf("[+] Read %d bytes, parsing JSON.\n", len(body))
	err = json.Unmarshal(body, &m)

	if err != nil {
		log.Printf("[!] Error parsing JSON - confirm %s is a valid JS sourcemap", source)
		return m, err
	}

	return m, nil
}

// getSourceMapFromJS queries a JavaScript URL, parses its headers and content and looks for sourcemaps
// follows the rules outlined in https://tc39.es/source-map-spec/#linking-generated-code
func getSourceMapFromJS(jsurl string, client *retryablehttp.Client, headers map[string]string) (m sourceMap, err error) {
	log.Printf("[+] Retrieving JavaScript from URL: %s.\n", jsurl)

	// perform the request
	u, err := url.ParseRequestURI(jsurl)
	if err != nil {
		return m, err
	}

	req, err := retryablehttp.NewRequest("GET", u.String(), nil)
	if err != nil {
		return m, err
	}

	// Set headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	res, err := client.Do(req)
	if err != nil {
		return m, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return m, errors.New("non-200 status code: " + res.Status)
	}

	var sourceMap string

	// check for SourceMap and X-SourceMap (deprecated) headers
	if sourceMap = res.Header.Get("SourceMap"); sourceMap == "" {
		sourceMap = res.Header.Get("X-SourceMap")
	}

	if sourceMap != "" {
		log.Printf("[.] Found SourceMap URI in response headers: %.1024s...", sourceMap)
	} else {
		// parse the javascript
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return m, err
		}

		// JS file can have multiple source maps in it, but only the last line is valid https://sourcemaps.info/spec.html#h.lmz475t4mvbx
		re := regexp.MustCompile(`\/\/[@#] sourceMappingURL=(.*)`)
		match := re.FindAllSubmatch(body, -1)

		if len(match) != 0 {
			// only the sourcemap at the end of the file should be valid
			sourceMap = string(match[len(match)-1][1])
			log.Printf("[.] Found SourceMap in JavaScript body: %.1024s...", sourceMap)
		}
	}

	// this introduces a forced request bug if the JS file we're parsing is
	// malicious and forces us to make a request out to something dodgy - take care
	if sourceMap != "" {
		var sourceMapURL *url.URL
		// handle absolute/relative rules
		sourceMapURL, err = url.ParseRequestURI(sourceMap)
		if err != nil {
			// relative url...
			sourceMapURL, err = u.Parse(sourceMap)
			if err != nil {
				return m, err
			}
		}

		return getSourceMap(sourceMapURL.String(), client, headers)
	}

	return m, errors.New("no sourcemap URL found")
}

// writeFile writes content to file at path p.
func writeFile(p string, content string) error {
	p = filepath.Clean(p)

	if _, err := os.Stat(filepath.Dir(p)); os.IsNotExist(err) {
		// Using MkdirAll here is tricky, because even if we fail, we might have
		// created some of the parent directories.
		err = os.MkdirAll(filepath.Dir(p), 0700)
		if err != nil {
			return err
		}
	}

	log.Printf("[+] Writing %d bytes to %s.\n", len(content), p)
	return os.WriteFile(p, []byte(content), 0600)
}

// processSourceMap extracts and writes source files from a sourcemap
func processSourceMap(sm sourceMap, outdir string) (int, error) {
	log.Printf("[+] Retrieved Sourcemap with version %d, containing %d entries.\n", sm.Version, len(sm.Sources))

	if len(sm.Sources) == 0 {
		return 0, errors.New("no sources found")
	}

	if len(sm.SourcesContent) == 0 {
		return 0, errors.New("no source content found")
	}

	// Determine how many entries we can safely process
	maxEntries := len(sm.Sources)
	if len(sm.SourcesContent) < maxEntries {
		log.Printf("[!] WARNING: sourcesContent array (%d entries) is shorter than sources array (%d entries).",
			len(sm.SourcesContent), len(sm.Sources))
		log.Printf("[!] Only processing the first %d entries that have content available.", len(sm.SourcesContent))
		maxEntries = len(sm.SourcesContent)
	} else if len(sm.SourcesContent) > len(sm.Sources) {
		log.Printf("[!] WARNING: sourcesContent array (%d entries) is longer than sources array (%d entries).",
			len(sm.SourcesContent), len(sm.Sources))
		log.Printf("[!] Extra content entries will be ignored.")
	}

	if sm.Version != 3 {
		log.Println("[!] Sourcemap is not version 3. This is untested!")
	}

	if _, err := os.Stat(outdir); os.IsNotExist(err) {
		err = os.MkdirAll(outdir, 0700)
		if err != nil {
			return 0, err
		}
	}

	processedCount := 0
	for i := 0; i < maxEntries; i++ {
		sourcePath := sm.Sources[i]

		// Sanitize path (remove/replace invalid characters like | : ? * etc)
		sourcePath = sanitizePath(sourcePath)

		// Remove leading slashes and clean path
		sourcePath = strings.TrimPrefix(sourcePath, "/")
		sourcePath = filepath.Clean(sourcePath)

		// If on windows, additional cleaning
		if runtime.GOOS == "windows" {
			sourcePath = cleanWindows(sourcePath)
		}

		// Join with output directory
		scriptPath := filepath.Join(outdir, sourcePath)
		scriptData := sm.SourcesContent[i]

		err := writeFile(scriptPath, scriptData)
		if err != nil {
			log.Printf("[!] Error writing %s file: %s", scriptPath, err)
		} else {
			processedCount++
		}
	}

	log.Printf("[+] Successfully processed %d out of %d source entries.", processedCount, len(sm.Sources))
	return processedCount, nil
}

// cleanWindows replaces the illegal characters from a path with `-`.
func cleanWindows(p string) string {
	m1 := regexp.MustCompile(`[?%*|:"<>]`)
	return m1.ReplaceAllString(p, "")
}

// sanitizePath removes or replaces invalid characters from path
func sanitizePath(p string) string {
	// Replace pipe characters and other problematic chars
	p = strings.ReplaceAll(p, "|", "_")
	p = strings.ReplaceAll(p, ":", "_")
	p = strings.ReplaceAll(p, "?", "_")
	p = strings.ReplaceAll(p, "*", "_")
	p = strings.ReplaceAll(p, "\"", "_")
	p = strings.ReplaceAll(p, "<", "_")
	p = strings.ReplaceAll(p, ">", "_")
	return p
}

func main() {
	opts := &options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("Extract source code from JavaScript sourcemaps")

	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&opts.URLs, "url", "u", nil, "sourcemap URL/path (comma-separated or multiple flags)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&opts.JSURLs, "jsurl", "j", nil, "javascript URL (comma-separated or multiple flags)", goflags.CommaSeparatedStringSliceOptions),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&opts.Output, "output", "o", "", "output directory (required)"),
	)

	flagSet.CreateGroup("config", "Configuration",
		flagSet.StringVarP(&opts.Proxy, "proxy", "p", "", "proxy URL (http/socks5)"),
		flagSet.IntVarP(&opts.Timeout, "timeout", "t", 30, "request timeout in seconds"),
		flagSet.IntVarP(&opts.Retries, "retries", "r", 3, "number of retries"),
		flagSet.IntVarP(&opts.RateLimit, "rate-limit", "rl", 0, "requests per second (0 = unlimited)"),
		flagSet.IntVarP(&opts.Concurrency, "concurrency", "c", 5, "concurrent requests"),
		flagSet.BoolVarP(&opts.Insecure, "insecure", "k", false, "skip TLS verification"),
		flagSet.StringSliceVarP(&opts.Headers, "header", "H", nil, "HTTP header (comma-separated or multiple flags)", goflags.CommaSeparatedStringSliceOptions),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVarP(&opts.Silent, "silent", "s", false, "silent mode (errors only)"),
		flagSet.BoolVarP(&opts.Verbose, "verbose", "v", false, "verbose mode"),
	)

	if err := flagSet.Parse(); err != nil {
		log.Fatalf("Error parsing flags: %s", err)
	}

	// Validation
	if opts.Output == "" {
		log.Fatal("output directory is required")
	}

	if len(opts.URLs) == 0 && len(opts.JSURLs) == 0 {
		log.Fatal("at least one -url or -jsurl is required")
	}

	if len(opts.JSURLs) > 0 && len(opts.URLs) > 0 {
		log.Println("[!] Both -jsurl and -url supplied - processing both")
	}

	// Parse proxy URL
	var proxyURL *url.URL
	var err error
	if opts.Proxy != "" {
		proxyURL, err = url.Parse(opts.Proxy)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Parse headers
	headerMap := parseHeaders(opts.Headers)
	if len(headerMap) > 0 && opts.Verbose {
		log.Printf("[+] Using %d custom header(s)\n", len(headerMap))
	}

	// Create HTTP client config
	httpCfg := httpClientConfig{
		timeout:      time.Duration(opts.Timeout) * time.Second,
		retries:      opts.Retries,
		insecure:     opts.Insecure,
		proxy:        proxyURL,
		headers:      headerMap,
		followRedirs: true,
		maxRedirs:    10,
	}

	// Create retryable HTTP client
	client := newHTTPClient(httpCfg)

	if opts.Verbose {
		log.Printf("[+] HTTP Client configured: timeout=%ds, retries=%d, insecure=%v\n",
			opts.Timeout, opts.Retries, opts.Insecure)
	}

	totalProcessed := 0
	totalFailed := 0
	totalSources := 0

	// Rate limiter setup
	var rateLimiter <-chan time.Time
	if opts.RateLimit > 0 {
		if opts.Verbose {
			log.Printf("[+] Rate limit: %d requests/second\n", opts.RateLimit)
		}
		ticker := time.NewTicker(time.Second / time.Duration(opts.RateLimit))
		defer ticker.Stop()
		rateLimiter = ticker.C
	}

	// Process sourcemap URLs
	for idx, sourceURL := range opts.URLs {
		// Rate limiting
		if rateLimiter != nil {
			<-rateLimiter
		}

		if !opts.Silent {
			log.Printf("\n[*] Processing sourcemap %d/%d: %s\n", idx+1, len(opts.URLs), sourceURL)
		}

		sm, err := getSourceMap(sourceURL, client, headerMap)
		if err != nil {
			log.Printf("[!] Failed to retrieve sourcemap from %s: %v\n", sourceURL, err)
			totalFailed++
			continue
		}

		processed, err := processSourceMap(sm, opts.Output)
		if err != nil {
			log.Printf("[!] Failed to process sourcemap from %s: %v\n", sourceURL, err)
			totalFailed++
			continue
		}

		totalProcessed += processed
		totalSources++
	}

	// Process JavaScript URLs
	for idx, jsURL := range opts.JSURLs {
		// Rate limiting
		if rateLimiter != nil {
			<-rateLimiter
		}

		if !opts.Silent {
			log.Printf("\n[*] Processing JavaScript %d/%d: %s\n", idx+1, len(opts.JSURLs), jsURL)
		}

		sm, err := getSourceMapFromJS(jsURL, client, headerMap)
		if err != nil {
			log.Printf("[!] Failed to retrieve sourcemap from %s: %v\n", jsURL, err)
			totalFailed++
			continue
		}

		processed, err := processSourceMap(sm, opts.Output)
		if err != nil {
			log.Printf("[!] Failed to process sourcemap from %s: %v\n", jsURL, err)
			totalFailed++
			continue
		}

		totalProcessed += processed
		totalSources++
	}

	if !opts.Silent {
		log.Println("\n" + strings.Repeat("=", 60))
		log.Printf("[+] SUMMARY: Processed %d sourcemaps successfully, %d failed", totalSources, totalFailed)
		log.Printf("[+] Total source files extracted: %d", totalProcessed)
		log.Println("[+] Done")
	}
}
