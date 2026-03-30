# Sourcemapper

High-performance tool to extract original JavaScript source code from sourcemaps. Features concurrent file writing, auto-detection, batch processing, and pipeline integration.

## Features

- ✅ **Auto-detection** - Automatically detects `.map` or `.js` URLs
- ✅ **Pipeline support** - Read URLs from stdin for tool chaining
- ✅ **Batch processing** - Process multiple URLs from command line or file
- ✅ **Concurrent file writing** - Parallel extraction with worker pool
- ✅ **Auto-deduplication** - Removes duplicate URLs automatically
- ✅ **Retryable HTTP** - Auto-retry with exponential backoff
- ✅ **Rate limiting** - Control request rate
- ✅ **Proxy support** - HTTP/SOCKS5 proxy
- ✅ **Graceful error handling** - Continue on failures

## Installation

```bash
go install github.com/anhnmt/sourcemapper@latest
```

or build from source

```bash
git clone https://github.com/anhnmt/sourcemapper
cd sourcemapper
go mod tidy
go build -o sourcemapper main.go
```

## Usage

```bash
sourcemapper [flags]

INPUT:
  -u, -url string[]     URL/path (auto-detects .map or .js)
  -l, -list string      File containing URLs
  -stdin                Read URLs from stdin (for pipelines)

OUTPUT:
  -o, -output string    Output directory (required)

CONFIG:
  -p, -proxy string     Proxy URL
  -t, -timeout int      Timeout in seconds (default 30)
  -r, -retries int      Number of retries (default 3)
  -rl, -rate-limit int  Requests per second (0 = unlimited)
  -c, -concurrency int  Concurrent workers (default 5)
  -k, -insecure         Skip TLS verification (default true)
  -H, -header string[]  HTTP headers

DEBUG:
  -s, -silent           Silent mode
  -v, -verbose          Verbose mode
```

## Examples

### Basic

```bash
# Single URL
sourcemapper -o ./output -u https://example.com/app.js

# Multiple URLs (auto-detects types)
sourcemapper -o ./output -u app.js.map,bundle.js,vendor.js

# From file
sourcemapper -o ./output -l urls.txt
```

### With Options

```bash
# With authentication
sourcemapper -o ./output \
  -u https://app.example.com/bundle.js \
  -H "Cookie: session=abc123"

# Through Burp proxy
sourcemapper -o ./output \
  -u https://target.com/app.js \
  -p http://127.0.0.1:8080 \
  -k

# Rate limited
sourcemapper -o ./output \
  -u app.js,vendor.js \
  -rl 2 \
  -t 60
```

## Pipeline Integration

### Basic Pipeline

```bash
# Simple pipe
echo "https://example.com/app.js" | sourcemapper -o ./output -stdin

# From file
cat urls.txt | sourcemapper -o ./output -stdin
```

### With ProjectDiscovery Tools

```bash
# subfinder → httpx → katana → sourcemapper
subfinder -d target.com -silent | \
  httpx -silent -mc 200 | \
  katana -jc -silent | \
  grep -E '\.(js|map)$' | \
  sourcemapper -o ./recon -stdin -silent

# gau → sourcemapper
echo "target.com" | \
  gau | \
  grep '\.js' | \
  sort -u | \
  sourcemapper -o ./archived -stdin

# With auth headers
katana -u https://target.com -H "Cookie: session=xyz" -silent | \
  grep '\.js' | \
  sourcemapper -o ./output -stdin -H "Cookie: session=xyz"
```

### Full Recon Chain

```bash
# Complete recon pipeline
subfinder -d target.com -silent | \
  dnsx -silent -resp | \
  httpx -silent -mc 200 | \
  katana -jc -kf all -silent | \
  grep -E '\.(js|map)(\?|$)' | \
  sort -u | \
  sourcemapper -o ./recon-$(date +%Y%m%d) -stdin -rl 5 -silent
```

### Bug Bounty Workflow

```bash
#!/bin/bash
DOMAIN="$1"
OUTPUT="./recon-$DOMAIN"

# Extract JS sources
subfinder -d $DOMAIN -silent | \
  httpx -silent -mc 200 | \
  katana -jc -silent | \
  grep -E '\.(js|map)' | \
  sort -u | \
  sourcemapper -o $OUTPUT -stdin -rl 3 -silent

# Search for secrets
grep -r -E "api[_-]?key|secret|password|token" $OUTPUT/ > secrets.txt
echo "[+] Found $(wc -l < secrets.txt) potential secrets"
```

### Pipeline Tips

- URLs are **automatically deduplicated**
- Use `-silent` to reduce noise
- Use `-rl` to control rate
- Filter with `grep` before piping
- Combine with `sort -u` for extra deduplication

## Auto-Detection

| Pattern | Type | Action |
|---------|------|--------|
| `*.map` | Sourcemap | Direct extraction |
| `*.js` | JavaScript | Find sourcemap |
| `*.map?*` | Sourcemap | Direct extraction |
| `*.js?*` | JavaScript | Find sourcemap |

## Output

```
output/
├── webpack/_N_E/
│   ├── node_modules/next/...
│   └── webpack/runtime/...
└── src/
    ├── components/
    └── utils/
```

## Example Output

```
[+] Loaded 25 URLs from stdin
[+] Removed 8 duplicate URLs
[+] Auto-detected: 5 sourcemap URLs, 12 JavaScript URLs
[+] HTTP Client configured: timeout=30s, retries=3

[*] Processing sourcemap 1/5: https://example.com/app.js.map
[+] Retrieved Sourcemap with version 3, containing 125 entries
[+] Successfully processed 125 out of 125 source entries

============================================================
[+] SUMMARY: Processed 17 sourcemaps successfully, 0 failed
[+] Total source files extracted: 543
[+] Done
```

## URL List Format

```txt
# urls.txt - comments start with #

https://app.example.com/main.js
https://app.example.com/vendor.js.map
https://cdn.example.com/chunk.js?v=1.0
./local/app.js.map
```

## Performance

- **Concurrent workers** - Default 5, configurable with `-c`
- **Connection pooling** - 100 max idle connections
- **Auto-retry** - Exponential backoff
- **Deduplication** - Removes duplicates before processing

## Security Notes

⚠️ **Warning**: Malicious JavaScript can force requests to arbitrary URLs

**Best Practices:**
- Use `-k` only in controlled environments
- Use `-rl` to avoid rate limiting
- Use `-p` for proxy when testing production
- Check extracted code for sensitive data

## Error Handling

- Continues on failures
- Handles mismatched arrays
- Sanitizes invalid path characters
- Auto-creates directories

```
[!] WARNING: sourcesContent (16) < sources (20)
[!] Processing 16 entries with available content
[+] Successfully processed 16 out of 20 source entries
```

## Dependencies

- Go 1.21+
- [github.com/projectdiscovery/goflags](https://github.com/projectdiscovery/goflags)
- [github.com/projectdiscovery/retryablehttp-go](https://github.com/projectdiscovery/retryablehttp-go)

## Credits

- Original: [denandz/sourcemapper](https://github.com/denandz/sourcemapper)
- Enhanced: [anhnmt](https://github.com/anhnmt)

## License

Same as original sourcemapper