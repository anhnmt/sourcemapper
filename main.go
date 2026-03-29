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
)

// sourceMap represents a sourceMap. We only really care about the sources and
// sourcesContent arrays.
type sourceMap struct {
	Version        int      `json:"version"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

// command line args
type config struct {
	outdir   string     // output directory
	urls     urlList    // sourcemap urls (can be multiple)
	jsurls   urlList    // javascript urls (can be multiple)
	proxy    string     // upstream proxy server
	insecure bool       // skip tls verification
	headers  headerList // additional user-supplied http headers
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

// getSourceMap retrieves a sourcemap from a URL or a local file and returns
// its sourceMap.
func getSourceMap(source string, headers []string, insecureTLS bool, proxyURL url.URL) (m sourceMap, err error) {
	var body []byte
	var client http.Client

	log.Printf("[+] Retrieving Sourcemap from %.1024s...\n", source)

	u, err := url.ParseRequestURI(source)
	if err != nil {
		// If it's a file, read it.
		body, err = os.ReadFile(source)
		if err != nil {
			log.Fatalln(err)
		}
	} else {
		if u.Scheme == "http" || u.Scheme == "https" {
			// If it's a URL, get it.
			req, err := http.NewRequest("GET", u.String(), nil)
			tr := &http.Transport{}

			if err != nil {
				log.Fatalln(err)
			}

			if insecureTLS {
				tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			}

			if proxyURL != (url.URL{}) {
				tr.Proxy = http.ProxyURL(&proxyURL)
			}

			client = http.Client{
				Transport: tr,
			}

			if len(headers) > 0 {
				headerString := strings.Join(headers, "\r\n") + "\r\n\r\n" // squish all the headers together with CRLFs
				log.Printf("[+] Setting the following headers: \n%s", headerString)

				r := bufio.NewReader(strings.NewReader(headerString))
				tpReader := textproto.NewReader(r)
				mimeHeader, err := tpReader.ReadMIMEHeader()

				if err != nil {
					log.Fatalln(err)
				}

				req.Header = http.Header(mimeHeader)
			}

			res, err := client.Do(req)

			if err != nil {
				log.Fatalln(err)
			}

			body, err = io.ReadAll(res.Body)
			defer res.Body.Close()

			if res.StatusCode != 200 && len(body) > 0 {
				log.Printf("[!] WARNING - non-200 status code: %d - Confirm this URL contains valid source map manually!", res.StatusCode)
				log.Printf("[!] WARNING - sourceMap URL request return != 200 - however, body length > 0 so continuing... ")
			}

			if err != nil {
				log.Fatalln(err)
			}
		} else if u.Scheme == "data" {
			urlchunks := strings.Split(u.Opaque, ",")
			if len(urlchunks) < 2 {
				log.Fatalf("[!] Could not parse data URI - expected atleast 2 chunks but got %d\n", len(urlchunks))
			}

			data, err := base64.StdEncoding.DecodeString(urlchunks[1])
			if err != nil {
				log.Fatal("[!] Error base64 decoding", err)
			}

			body = []byte(data)
		} else {
			// If it's a file, read it.
			body, err = os.ReadFile(source)
			if err != nil {
				log.Fatalln(err)
			}
		}
	}
	// Unmarshall the body into the struct.
	log.Printf("[+] Read %d bytes, parsing JSON.\n", len(body))
	err = json.Unmarshal(body, &m)

	if err != nil {
		log.Printf("[!] Error parsing JSON - confirm %s is a valid JS sourcemap", source)
	}

	return
}

// getSourceMapFromJS queries a JavaScript URL, parses its headers and content and looks for sourcemaps
// follows the rules outlined in https://tc39.es/source-map-spec/#linking-generated-code
func getSourceMapFromJS(jsurl string, headers []string, insecureTLS bool, proxyURL url.URL) (m sourceMap, err error) {
	var client http.Client

	log.Printf("[+] Retrieving JavaScript from URL: %s.\n", jsurl)

	// perform the request
	u, err := url.ParseRequestURI(jsurl)
	if err != nil {
		log.Fatal(err)
	}

	req, err := http.NewRequest("GET", u.String(), nil)
	tr := &http.Transport{}

	if err != nil {
		log.Fatalln(err)
	}

	if insecureTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	if proxyURL != (url.URL{}) {
		tr.Proxy = http.ProxyURL(&proxyURL)
	}

	client = http.Client{
		Transport: tr,
	}

	if len(headers) > 0 {
		headerString := strings.Join(headers, "\r\n") + "\r\n\r\n" // squish all the headers together with CRLFs
		log.Printf("[+] Setting the following headers: \n%s", headerString)

		r := bufio.NewReader(strings.NewReader(headerString))
		tpReader := textproto.NewReader(r)
		mimeHeader, err := tpReader.ReadMIMEHeader()

		if err != nil {
			log.Fatalln(err)
		}

		req.Header = http.Header(mimeHeader)
	}

	res, err := client.Do(req)

	if err != nil {
		log.Fatalln(err)
	}

	if res.StatusCode != 200 {
		log.Fatalf("[!] non-200 status code: %d", res.StatusCode)
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
			log.Fatalln(err)
		}
		defer res.Body.Close()

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
				log.Fatal(err)
			}
		}

		return getSourceMap(sourceMapURL.String(), headers, insecureTLS, proxyURL)
	}

	err = errors.New("[!] No sourcemap URL found")
	return
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
	var proxyURL url.URL
	var conf config

	flag.StringVar(&conf.outdir, "output", "", "Source file output directory - REQUIRED")
	flag.Var(&conf.urls, "url", "URL or path to the Sourcemap file - can be specified multiple times")
	flag.Var(&conf.jsurls, "jsurl", "URL to JavaScript file - can be specified multiple times")
	flag.StringVar(&conf.proxy, "proxy", "", "Proxy URL")
	help := flag.Bool("help", false, "Show help")
	flag.BoolVar(&conf.insecure, "insecure", false, "Ignore invalid TLS certificates")
	flag.Var(&conf.headers, "header", "A header to send with the request, similar to curl's -H. Can be set multiple times, EG: \"./sourcemapper --header \"Cookie: session=bar\" --header \"Authorization: blerp\"")
	flag.Parse()

	if *help || (len(conf.urls) == 0 && len(conf.jsurls) == 0) || conf.outdir == "" {
		flag.Usage()
		return
	}

	if len(conf.jsurls) > 0 && len(conf.urls) > 0 {
		log.Println("[!] Both -jsurl and -url supplied - processing both")
	}

	if conf.proxy != "" {
		p, err := url.Parse(conf.proxy)
		if err != nil {
			log.Fatal(err)
		}
		proxyURL = *p
	}

	totalProcessed := 0
	totalFailed := 0
	totalSources := 0

	// Process sourcemap URLs
	for idx, sourceURL := range conf.urls {
		log.Printf("\n[*] Processing sourcemap %d/%d: %s\n", idx+1, len(conf.urls), sourceURL)

		// Create subdirectory for this sourcemap if multiple URLs
		outputDir := conf.outdir
		if len(conf.urls) > 1 || len(conf.jsurls) > 0 {
			outputDir = filepath.Join(conf.outdir, filepath.Clean(strings.ReplaceAll(filepath.Base(sourceURL), ".", "_")))
		}

		sm, err := getSourceMap(sourceURL, conf.headers, conf.insecure, proxyURL)
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
		log.Printf("\n[*] Processing JavaScript %d/%d: %s\n", idx+1, len(conf.jsurls), jsURL)

		// Create subdirectory for this sourcemap if multiple URLs
		outputDir := conf.outdir
		if len(conf.jsurls) > 1 || len(conf.urls) > 0 {
			outputDir = filepath.Join(conf.outdir, filepath.Clean(strings.ReplaceAll(filepath.Base(jsURL), ".", "_")))
		}

		sm, err := getSourceMapFromJS(jsURL, conf.headers, conf.insecure, proxyURL)
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
