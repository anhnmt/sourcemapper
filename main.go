package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
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

// command line args
type config struct {
	outdir      string     // output directory
	urls        urlList    // sourcemap urls (can be multiple)
	jsurls      urlList    // javascript urls (can be multiple)
	proxy       string     // upstream proxy server
	insecure    bool       // skip tls verification
	headers     headerList // additional user-supplied http headers
	timeout     int        // request timeout in seconds
	retries     int        // number of retries
	concurrency int        // concurrent requests
	ratelimit   int        // requests per second
}

type urlList []string

func (u *urlList) String() string {
	return strings.Join(*u, ",")
}

func (u *urlList) Set(value string) error {
	*u = append(*u, value)
	return nil
}

type headerList []string

func (h *headerList) String() string {
	return ""
}

func (h *headerList) Set(value string) error {
	*h = append(*h, value)
	return nil
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
		err = os.Mkdir(outdir, 0700)
		if err != nil {
			return 0, err
		}
	}

	processedCount := 0
	for i := 0; i < maxEntries; i++ {
		sourcePath := sm.Sources[i]
		sourcePath = "/" + sourcePath // path.Clean will ignore a leading '..', must be a '/..'

		// If on windows, clean the sourcepath.
		if runtime.GOOS == "windows" {
			sourcePath = cleanWindows(sourcePath)
		}

		// Use filepath.Join. https://parsiya.net/blog/2019-03-09-path.join-considered-harmful/
		scriptPath := filepath.Join(outdir, filepath.Clean(sourcePath))
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

func main() {
	var conf config
	var err error

	flag.StringVar(&conf.outdir, "output", "", "Source file output directory - REQUIRED")
	flag.Var(&conf.urls, "url", "URL or path to the Sourcemap file - can be specified multiple times")
	flag.Var(&conf.jsurls, "jsurl", "URL to JavaScript file - can be specified multiple times")
	flag.StringVar(&conf.proxy, "proxy", "", "Proxy URL")
	flag.IntVar(&conf.timeout, "timeout", 30, "Request timeout in seconds")
	flag.IntVar(&conf.retries, "retries", 3, "Number of retries for failed requests")
	flag.IntVar(&conf.concurrency, "concurrency", 5, "Number of concurrent requests")
	flag.IntVar(&conf.ratelimit, "rate-limit", 0, "Requests per second (0 = unlimited)")
	help := flag.Bool("help", false, "Show help")
	flag.BoolVar(&conf.insecure, "insecure", false, "Ignore invalid TLS certificates")
	flag.Var(&conf.headers, "header", "A header to send with the request, similar to curl's -H. Can be set multiple times")
	flag.Parse()

	if *help || (len(conf.urls) == 0 && len(conf.jsurls) == 0) || conf.outdir == "" {
		flag.Usage()
		return
	}

	if len(conf.jsurls) > 0 && len(conf.urls) > 0 {
		log.Println("[!] Both -jsurl and -url supplied - processing both")
	}

	// Parse proxy URL
	var proxyURL *url.URL
	if conf.proxy != "" {
		proxyURL, err = url.Parse(conf.proxy)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Parse headers
	headerMap := parseHeaders(conf.headers)
	if len(headerMap) > 0 {
		log.Printf("[+] Using %d custom header(s)\n", len(headerMap))
	}

	// Create HTTP client config
	httpCfg := httpClientConfig{
		timeout:      time.Duration(conf.timeout) * time.Second,
		retries:      conf.retries,
		insecure:     conf.insecure,
		proxy:        proxyURL,
		headers:      headerMap,
		followRedirs: true,
		maxRedirs:    10,
	}

	// Create retryable HTTP client
	client := newHTTPClient(httpCfg)

	log.Printf("[+] HTTP Client configured: timeout=%ds, retries=%d, insecure=%v\n",
		conf.timeout, conf.retries, conf.insecure)

	totalProcessed := 0
	totalFailed := 0
	totalSources := 0

	// Rate limiter setup
	var rateLimiter <-chan time.Time
	if conf.ratelimit > 0 {
		log.Printf("[+] Rate limit: %d requests/second\n", conf.ratelimit)
		ticker := time.NewTicker(time.Second / time.Duration(conf.ratelimit))
		defer ticker.Stop()
		rateLimiter = ticker.C
	}

	// Process sourcemap URLs
	for idx, sourceURL := range conf.urls {
		// Rate limiting
		if rateLimiter != nil {
			<-rateLimiter
		}

		log.Printf("\n[*] Processing sourcemap %d/%d: %s\n", idx+1, len(conf.urls), sourceURL)

		// Create subdirectory for this sourcemap if multiple URLs
		outputDir := conf.outdir
		if len(conf.urls) > 1 || len(conf.jsurls) > 0 {
			outputDir = filepath.Join(conf.outdir, filepath.Clean(strings.ReplaceAll(filepath.Base(sourceURL), ".", "_")))
		}

		sm, err := getSourceMap(sourceURL, client, headerMap)
		if err != nil {
			log.Printf("[!] Failed to retrieve sourcemap from %s: %v\n", sourceURL, err)
			totalFailed++
			continue
		}

		processed, err := processSourceMap(sm, outputDir)
		if err != nil {
			log.Printf("[!] Failed to process sourcemap from %s: %v\n", sourceURL, err)
			totalFailed++
			continue
		}

		totalProcessed += processed
		totalSources++
	}

	// Process JavaScript URLs
	for idx, jsURL := range conf.jsurls {
		// Rate limiting
		if rateLimiter != nil {
			<-rateLimiter
		}

		log.Printf("\n[*] Processing JavaScript %d/%d: %s\n", idx+1, len(conf.jsurls), jsURL)

		// Create subdirectory for this sourcemap if multiple URLs
		outputDir := conf.outdir
		if len(conf.jsurls) > 1 || len(conf.urls) > 0 {
			outputDir = filepath.Join(conf.outdir, filepath.Clean(strings.ReplaceAll(filepath.Base(jsURL), ".", "_")))
		}

		sm, err := getSourceMapFromJS(jsURL, client, headerMap)
		if err != nil {
			log.Printf("[!] Failed to retrieve sourcemap from %s: %v\n", jsURL, err)
			totalFailed++
			continue
		}

		processed, err := processSourceMap(sm, outputDir)
		if err != nil {
			log.Printf("[!] Failed to process sourcemap from %s: %v\n", jsURL, err)
			totalFailed++
			continue
		}

		totalProcessed += processed
		totalSources++
	}

	log.Println("\n" + strings.Repeat("=", 60))
	log.Printf("[+] SUMMARY: Processed %d sourcemaps successfully, %d failed", totalSources, totalFailed)
	log.Printf("[+] Total source files extracted: %d", totalProcessed)
	log.Println("[+] Done")
}
