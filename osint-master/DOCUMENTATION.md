# `osint-master` — Complete Technical Documentation

> A multi-function **Open Source Intelligence (OSINT)** command-line tool in Go: IP geolocation + abuse lookup, username enumeration across social platforms, DNS subdomain discovery with takeover-risk analysis, plus bonus full-name people-search scraping and username generation.
> Entry point: `main.go`. Logic: `handlers/`, `help/`.

---

## 1. Project Overview

### Simple explanation

"OSINT" means finding out things about a person, company, IP address, or website using only **publicly available information** — no hacking, no passwords, just asking public services what they already know.

`osint-master` bundles five such look-ups behind one command:

| Flag | You give it… | It tells you… |
|---|---|---|
| `-i` | an IP address | which country/city/ISP it's in, its map coordinates, and whether it's been reported for abuse |
| `-u` | a username | which of GitHub / Twitter / Instagram / Reddit / LinkedIn / Medium / GitLab / Pinterest that name exists on (and, for GitHub/Reddit, a bit of profile detail) |
| `-d` | a domain (e.g. `github.com`) | which common subdomains (`api.`, `mail.`, `dev.`…) actually exist, their IPs, whether port 443 is open, and whether any look vulnerable to "subdomain takeover" |
| `-n` | a full name | tries to scrape a US phone-book site; if blocked, prints a big list of manual search links (people-search sites, social media, email guesses, Google dorks) |
| `-g` | a full name | generates dozens of likely usernames (`john.smith`, `jsmith`, `johnsmith123`…) and checks each one on the platforms |

`-o file` saves the text report to a file.

### Technical explanation

`osint-master` is a Go CLI that performs **passive reconnaissance** by calling public APIs and DNS, and by light HTML scraping. Architecture: a `flag`-based dispatcher in `main.go` selects exactly one handler in `handlers/`; each handler builds a large human-readable text report string, which `main` prints and optionally writes to a file.

| Capability | Handler | Technique / data source |
|---|---|---|
| IP lookup | `handlers.HandleIP` | `GET http://ip-api.com/json/<ip>` (geo/ISP/ASN, JSON) + `GET https://api.abuseipdb.com/api/v2/check` (abuse score, JSON, API-key header) |
| Username search | `handlers.HandleUsername` | HTTP `HEAD` to each platform's profile URL; `200`/`302` ⇒ "found"; GitHub/Reddit additionally enriched via their public JSON APIs |
| Domain enumeration | `handlers.HandleDomain` | brute-force DNS over a ~130-label wordlist (`net.LookupHost`), `net.LookupCNAME`, a TCP-connect probe to `:443`, and CNAME pattern-matching for takeover risk |
| Full-name people search | `handlers.HandleNameScraper` | scrape `usphonebook.com` with spoofed browser headers via `goquery`; on block, fall back to `getManualSearchLinks` |
| Username generation + test | `handlers.HandleGenerateAndTestUsernames` → `help.GenerateFromFullName` | permutation generator → the same `HEAD`-based platform check |
| Output | `handlers.SaveToFile` (and an unused `SaveAsPdf`) | `os.MkdirAll` + `os.WriteFile` |

**Problem it solves.** Consolidates several manual OSINT steps (open ip-api in a browser, check a username on eight sites, guess subdomains, look someone up on people-search sites) into one command with saved output — useful for footprinting during authorized security assessments, CTF recon, and OSINT training.

**Main objective.** Given one selector (IP / username / domain / name), produce a formatted intelligence report from public sources, optionally saved to disk.

**Who uses it.** Security students / junior pentesters doing the reconnaissance phase, CTF players, and OSINT learners. The README is explicit that it must only be used on targets you're authorized to investigate.

**Technologies / libraries.**
- **Language:** Go (`go 1.25.0`).
- **Standard library:** `flag`, `fmt`, `os`, `net`, `net/http`, `net/url`, `encoding/json`, `io`, `strings`, `time`, `unicode`, `path/filepath`.
- **Third-party (`go.mod`):** `github.com/PuerkitoBio/goquery` (jQuery-style HTML parsing) + its deps `github.com/andybalholm/cascadia` (CSS selectors) and `golang.org/x/net`; `github.com/jung-kurt/gofpdf` and `github.com/go-pdf/fpdf` (PDF generation — only `gofpdf` is used, in the unused `SaveAsPdf`); `github.com/joho/godotenv` (`.env` loader — declared, not visibly used in the provided source).

**Main features.**
1. IP → country/region/city/ISP/org/ASN/coordinates + Google Maps / ipinfo / VirusTotal links + AbuseIPDB abuse-report status.
2. Username presence across 8 platforms + GitHub (bio/followers/repos) and Reddit (karma) enrichment.
3. DNS subdomain brute force + resolved IPs + CNAME + a `:443` reachability check + subdomain-takeover risk classification (HIGH/MEDIUM/LOW/UNKNOWN) with per-provider notes and links to crt.sh / SecurityTrails / DNSDumpster.
4. Full-name people-search scraping with realistic-browser-header spoofing and a large manual-links fallback (people-search sites, socials, email-pattern guesses, Google dorks, PeopleDataLabs).
5. Username permutation generator (first/last/initials/separators/suffixes/prefixes/truncations, deduped, length-filtered).
6. `-o` file output.

---

## 2. Project Architecture

### 2.1 Runtime / data-flow view

```
                              user @ terminal
   ./osintmaster  -i <ip> | -u <user> | -d <domain> | -n "<name>" | -g "<name>"  [-o file]
                                    │
                                    ▼
                        ┌───────────────────────┐
                        │        main.go         │  flag.Parse • custom Usage • "exactly one option"
                        │  switch → one handler  │  print(result) • if -o: SaveToFile
                        └───────────┬───────────┘
     ┌──────────────┬──────────────┼───────────────┬──────────────────┐
     ▼              ▼              ▼               ▼                  ▼
┌─────────┐  ┌────────────┐  ┌────────────┐  ┌──────────────┐  ┌──────────────────────┐
│HandleIP │  │HandleUser  │  │HandleDomain│  │HandleName    │  │HandleGenerateAndTest │
│         │  │name        │  │            │  │Scraper       │  │Usernames             │
│ip-api   │  │HEAD /user  │  │DNS brute   │  │scrape        │  │help.GenerateFrom     │
│AbuseIPDB│  │+GitHub/    │  │+CNAME+:443 │  │usphonebook   │  │FullName → HEAD tests │
│         │  │ Reddit API │  │+takeover   │  │+goquery      │  │                      │
└────┬────┘  └─────┬──────┘  └─────┬──────┘  └──────┬───────┘  └──────────┬───────────┘
     │             │               │                │                     │
     ▼             ▼               ▼                ▼                     ▼
 net/http      net/http         net (DNS)       net/http + goquery    net/http + help/
 encoding/json encoding/json    net.Dial :443                          (permutation map)
     │             │               │                │                     │
     └─────────────┴───────────────┴────────────────┴─────────────────────┘
                                    │
                          external services / OS
   ip-api.com (HTTP) • api.abuseipdb.com (HTTPS) • api.github.com • reddit.com • usphonebook.com
   system DNS resolver • TCP/443 to each live subdomain
                                    │
                                    ▼
                     text report on stdout  (+ optional file via os.WriteFile)
```

### 2.2 Import graph

```
main ──► osint-master/handlers

handlers/handleIP.go        ──► net, net/http, io, encoding/json, strings, time, fmt
handlers/handelDomain.go    ──► net, strings, time, fmt
handlers/handleName.go      ──► net/http, net/url, strings, time, unicode, fmt,
                                github.com/PuerkitoBio/goquery
handlers/handleUsername.go  ──► net/http, encoding/json, strings, time, fmt,
                                osint-master/help
handlers/saveToFile.go      ──► os, path/filepath, fmt,
                                github.com/jung-kurt/gofpdf

help/help.go                ──► strings, fmt
```

**Observations:**
- **`main` depends only on `handlers`.** `handlers` depends on `help` (only `handleUsername.go`, for the generator).
- **No shared state, no concurrency.** Every handler runs sequentially in the calling goroutine. `HandleDomain` loops ~130 subdomains one at a time (no `sync`, no worker pool) — the slowest path by far.
- **Each handler is self-contained** and returns a single `string` (the whole report). `main` never inspects the content — it just prints and optionally saves it.
- **Two unused code paths:** `handlers.SaveAsPdf` (defined, never called) and `help.GenerateUsernameReport` / `handlers.HandleUsernameFromName` (near-duplicates of the wired-in `HandleGenerateAndTestUsernames`).
- **A committed secret:** `handleIP.go` contains a hard-coded AbuseIPDB API key (see §13).
- Package name mismatch to note: the file is `handelDomain.go` (typo) but the package is `handlers` and the exported function is `HandleDomain` — only the filename is misspelled.

### 2.3 Component-by-component

**`main.go` (`package main`)** — the dispatcher. Registers six string flags (`-n`, `-i`, `-u`, `-g`, `-d`, `-o`), installs a custom `flag.Usage`, manually intercepts `--help`/`-h` as `os.Args[1]`, then `flag.Parse()`. Counts how many of `{name, ip, username, generate, domain}` are non-empty; errors if `0` or `>1`. A `switch` calls the one matching handler, prints its returned string, and — if `-o` was given — calls `handlers.SaveToFile`.

**`handlers/handleIP.go`** — `IPInfo` struct (JSON-tagged fields for ip-api.com + AbuseIPDB). `GetIPInfo(ip)` fetches and parses the ip-api JSON, checking `status == "success"`. `CheckAbuseDB(ip)` calls AbuseIPDB with a **hard-coded key** in a `Key` header and summarizes `abuseConfidenceScore` / `totalReports` / `lastReportedAt`. `HandleIP(ip)` validates the IP (`net.ParseIP` via `isValidIP`), then assembles a multi-section text report (geographic, network, additional links, abuse status, tips).

**`handlers/handelDomain.go`** — `SubdomainInfo` struct. `getSubdomainList()` returns a ~130-entry hard-coded wordlist. `resolveSubdomain(sub)` = `net.LookupHost` (+ a stray debug `fmt.Println`). `getCNAME(sub)` = `net.LookupCNAME`. `checkSSL(sub)` = `net.DialTimeout("tcp", sub+":443", 2s)` — **connection acceptance only, no TLS handshake or cert check**. `analyzeTakeoverRisk(sub, cname, ips)` classifies HIGH (CNAME → S3/GitHub Pages/Heroku/Azure/Shopify/Medium/ReadMe.io), MEDIUM (any other external CNAME), LOW (direct A record), UNKNOWN (nothing). `HandleDomain(domain)` iterates the wordlist, resolves each `sub.domain`, and for hits gathers CNAME/SSL/risk, then formats a full report (found list, HIGH-risk section, all-active section, OSINT tips, resource links, legal note).

**`handlers/handleName.go`** — `ContactInfo` struct. `IsAllAlpha(s)`. `scrapeUSPhoneBookWithProxy(first, last, proxy)` builds a `usphonebook.com` search URL, creates an `http.Client` (optional proxy `Transport`), sets ~15 realistic browser headers, GETs, treats non-`200` as "blocked by anti-bot protection", and parses the HTML with `goquery` trying several CSS selectors for result cards / phone / address. `HandleNameScraper(fullName)` splits into first/last, validates alpha, calls the scraper with no proxy, and on failure (or zero results) falls back to `getManualSearchLinks(first, last)` — a large block of people-search URLs, social URLs, email-pattern guesses, Google dorks, a PeopleDataLabs pointer, and a legal note.

**`handlers/handleUsername.go`** — `Platform` struct + `GetPlatforms()` (8 platforms with URL templates). `ProfileInfo` (Bio/Followers/ActivityInfo/Enriched). `CheckResult`. `checkUsernameOnPlatform(username, platform, client)` — an HTTP `HEAD` with a browser UA; `Found = status == 200 || status == 302`; if found and GitHub → `enrichGitHub`, Reddit → `enrichReddit`. `enrichGitHub` GETs `api.github.com/users/<u>` (bio, followers, public_repos). `enrichReddit` GETs `reddit.com/user/<u>/about.json` (karma). `formatResult` renders one line + optional enrichment. `HandleUsername(username)` strips a leading `@`, loops the platforms, collects the "found" ones, and returns a report with a `found/total` summary. `HandleUsernameFromName` / `HandleGenerateAndTestUsernames` generate candidates via `help.GenerateFromFullName` and test the first 20 / 30.

**`handlers/saveToFile.go`** — `SaveToFile(filename, data)` = `os.MkdirAll(dir)` + `os.WriteFile(filename, []byte(data), 0644)` with printed status. `SaveAsPdf(file, content)` uses `gofpdf` to render `content` into an A4 PDF — **defined but never invoked**, and uses `os.Mkdir` (not `MkdirAll`).

**`help/help.go`** — `UsernameGenerator{FirstName, LastName}`. `GenerateAllUsernames()` builds a `map[string]bool` of permutations (first/last alone + `1`/`12`/`123`; `first+last` with `.` `_` `-` and reversed; `initial+last`; `first+initial`; `initials` + digits; truncations of `first`; a suffix cross-product `{"","1","12","123","2023","2024","_",".","-"}`; prefixes `{"the","real","im","its"}`), converts to a slice keeping only length 3–30. `GenerateFromFullName(fullName)` splits with `strings.Fields`, sets first/last, calls the generator. `GenerateUsernameReport(fullName)` formats a standalone report — **unused** (main dispatches `-g` to `HandleGenerateAndTestUsernames`).

**External services:** ip-api.com (HTTP), api.abuseipdb.com (HTTPS + key), api.github.com, www.reddit.com, www.usphonebook.com. **Databases:** none.

---

## 3. Project File Structure

```
osint-master/
├── main.go                     # CLI dispatcher (flags → one handler → print → optional save)
├── go.mod / go.sum             # module + dependencies
├── README.md                   # overview, features, usage, APIs, ethics, limitations
├── test.sh                     # interactive smoke test (build, --help, -i, -u, -d, invalid inputs)
│
├── handlers/
│   ├── handleIP.go             # -i : ip-api.com geo/ISP/ASN + AbuseIPDB abuse score
│   ├── handelDomain.go         # -d : DNS brute force + CNAME + :443 probe + takeover risk
│   ├── handleName.go           # -n : usphonebook.com scrape + manual-links fallback
│   ├── handleUsername.go       # -u / -g : HEAD-based presence check + GitHub/Reddit enrichment
│   └── saveToFile.go           # -o : SaveToFile (used) ; SaveAsPdf (unused)
│
├── help/
│   └── help.go                 # username permutation generator (used by -g via handlers)
│
├── output/putput.txt           # sample saved output
└── *.txt                       # many sample/result output files
```

### File-by-file

**`main.go`**
- **Purpose.** The only executable; routes one selector flag to one handler.
- **Imports.** `flag`, `fmt`, `os`, `osint-master/handlers`.
- **Exposes.** `func main()`.
- **Input.** `os.Args`. **Output.** the handler's report on stdout; optionally a file.

**`go.mod`**
```
module osint-master
go 1.25.0
require (
    github.com/PuerkitoBio/goquery v1.12.0 // indirect
    github.com/andybalholm/cascadia v1.3.3 // indirect
    github.com/go-pdf/fpdf v0.9.0 // indirect
    github.com/joho/godotenv v1.5.1 // indirect
    github.com/jung-kurt/gofpdf v1.16.2 // indirect
    golang.org/x/net v0.52.0 // indirect
)
```
- All marked `// indirect` (an artifact of how they were added — several are in fact used *directly*: `goquery` in `handleName.go`, `gofpdf` in `saveToFile.go`).

**`handlers/handleIP.go`**
- **Imports.** `encoding/json`, `fmt`, `io`, `net`, `net/http`, `strings`, `time`.
- **Exposes.** `IPInfo`, `GetIPInfo(ip) (*IPInfo, error)`, `CheckAbuseDB(ip) (string, error)`, `HandleIP(ip) string`, `isValidIP(ip) bool`.
- **Input.** an IP string. **Output.** a formatted report string. **Side effects.** two outbound HTTP requests.

**`handlers/handelDomain.go`**
- **Imports.** `fmt`, `net`, `strings`, `time`.
- **Exposes.** `SubdomainInfo`, `HandleDomain(domain) string` (plus unexported helpers `getSubdomainList`, `resolveSubdomain`, `getCNAME`, `checkSSL`, `analyzeTakeoverRisk`).
- **Input.** a domain string. **Output.** a report string. **Side effects.** ~130 DNS lookups, up to ~130 `LookupCNAME`, up to ~130 TCP connects to `:443`; a stray `fmt.Println` to stdout.

**`handlers/handleName.go`**
- **Imports.** `fmt`, `net/http`, `net/url`, `strings`, `time`, `unicode`, `github.com/PuerkitoBio/goquery`.
- **Exposes.** `ContactInfo`, `IsAllAlpha(s) bool`, `HandleNameScraper(fullName) string` (plus `scrapeUSPhoneBookWithProxy`, `getManualSearchLinks`).
- **Input.** a `"First Last"` string. **Output.** a report string. **Side effects.** one outbound HTTP GET to usphonebook.com.

**`handlers/handleUsername.go`**
- **Imports.** `encoding/json`, `fmt`, `net/http`, `strings`, `time`, `osint-master/help`.
- **Exposes.** `Platform`, `GetPlatforms()`, `ProfileInfo`, `CheckResult`, `HandleUsername(u) string`, `HandleUsernameFromName(name) string`, `HandleGenerateAndTestUsernames(name) string` (plus `checkUsernameOnPlatform`, `enrichGitHub`, `enrichReddit`, `formatResult`).
- **Input.** a username or a full name. **Output.** a report string. **Side effects.** one `HEAD` per platform per username, plus GitHub/Reddit `GET`s for enrichment.

**`handlers/saveToFile.go`**
- **Imports.** `fmt`, `os`, `path/filepath`, `github.com/jung-kurt/gofpdf`.
- **Exposes.** `SaveToFile(filename, data)`, `SaveAsPdf(file, content)` (unused).
- **Input.** a filename + the report string. **Output.** a file on disk; a status line.

**`help/help.go`**
- **Imports.** `fmt`, `strings`.
- **Exposes.** `UsernameGenerator`, `(*UsernameGenerator).GenerateAllUsernames()`, `GenerateFromFullName(fullName) []string`, `GenerateUsernameReport(fullName) string` (unused).
- **Input.** a full name. **Output.** a `[]string` of candidate usernames.

**`test.sh`** — builds the binary, prints `--help`, then runs `-i 8.8.8.8 -o ip.txt`, `-u torvalds -o user.txt`, `-d github.com -o domain.txt`, and three invalid inputs (`-i 999.999.999.999`, `-u ""`, `-d invalid-domain`), pausing between sections.

---

## 4. Execution Flow

### 4.1 Flow diagram

```
 start: ./osintmaster <flags>
   │
   ▼
[1] flag.Usage = <custom banner>
    register -n -i -u -g -d -o  (all flag.String, default "")
   │
   ▼
[2] if os.Args[1] in {"--help","-h"}:  flag.Usage(); return
   │
   ▼
[3] flag.Parse()
   │
   ▼
[4] if len(os.Args) == 1:  flag.Usage(); return
   │
   ▼
[5] options = count of non-empty in [name, ip, username, generate, domain]
        options == 0  → print "must provide one of -n,-i,-u,-g,-d"; return
        options  > 1  → print "use only ONE"; return
   │
   ▼
[6] switch:
      case *ip       != "":  result = HandleIP(*ip)
      case *username != "":  result = HandleUsername(*username)
      case *domain   != "":  result = HandleDomain(*domain)
      case *name     != "":  result = HandleNameScraper(*name)
      case *generate != "":  result = HandleGenerateAndTestUsernames(*generate)
   │
   ▼
[7] fmt.Println(result)
   │
   ▼
[8] if *output != "":  handlers.SaveToFile(*output, result)
   │
   ▼
 exit 0
```

### 4.2 Step-by-step narrative

1. **Custom usage installed; flags registered.** All six are `flag.String(name, "", "")` — empty default, empty help text (the help comes from the custom `flag.Usage` banner). `-o` is separate from the five "mode" flags.

2. **Manual `--help`/`-h` intercept.** Before parsing, if `os.Args[1]` is `--help` or `-h`, print the banner and return. (Note: this only catches it as the *first* argument; `flag`'s own `-help` handling would catch `-help` elsewhere.)

3. **`flag.Parse()`** populates the six `*string` pointers from the command line. Unknown flags cause `flag` to print an error and `os.Exit(2)`.

4. **No-args guard.** `len(os.Args) == 1` (just the program name) → print the banner and return.

5. **"Exactly one mode" enforcement.** Build a slice of the five mode values, count non-empty ones. `0` → error message and return; `>1` → error message and return. (`-o` alone counts as `0` modes → the "must provide one of…" error.)

6. **Dispatch.** A `switch` with no condition (`switch { case ...: }`) checks each mode in order: `ip` first, then `username`, `domain`, `name`, `generate`. Exactly one case runs (guaranteed by step 5) and assigns `result`.

7. **Print.** `fmt.Println(result)` — the entire multi-section report string.

8. **Optional save.** If `-o file` was given, `handlers.SaveToFile(file, result)` creates any parent directory (`os.MkdirAll`) and writes the report (`os.WriteFile`, mode `0644`).

### 4.3 Inside each handler

- **`HandleIP`:** `isValidIP` (`net.ParseIP`); `GetIPInfo` (HTTP GET ip-api, JSON decode, `status` check); build geo + network sections; append map/ipinfo/VirusTotal links; `CheckAbuseDB` (HTTPS GET AbuseIPDB with the key header, decode `data`, summarize); append tips. Returns the string.
- **`HandleUsername`:** trim `@`; for each of 8 platforms, `checkUsernameOnPlatform` (HTTP `HEAD`, `200`/`302` ⇒ found; GitHub/Reddit ⇒ enrich via their JSON APIs); accumulate found results and a `found/total` summary.
- **`HandleDomain`:** for each of ~130 labels, `resolveSubdomain(label+"."+domain)` (`net.LookupHost`); on a hit, `getCNAME`, `checkSSL` (`:443` connect), `analyzeTakeoverRisk`; append a per-subdomain block; every 50 iterations print a progress line; finally a summary, a HIGH-risk list, an all-active list, OSINT tips, and resource links.
- **`HandleNameScraper`:** split name; `IsAllAlpha` on both parts; `scrapeUSPhoneBookWithProxy(first, last, "")`; if it errored (esp. `403`) or returned nothing, append `getManualSearchLinks`.
- **`HandleGenerateAndTestUsernames`:** `help.GenerateFromFullName(name)` → up to 30 candidates; for each, `checkUsernameOnPlatform` on all 8 platforms; list the ones found on ≥1 platform; summary + tips.

---

## 5. Entry Point

`main.go`, run as `./osintmaster <flags>`. Go executes the package, then `main()`.

### 5.1 `main()` annotated

```go
func main() {
	// Custom help banner — printed by flag on error, and by us on --help / no args.
	flag.Usage = func() {
		fmt.Println("OSINT MASTER"); fmt.Println("============"); /* ... usage/options/examples ... */
	}

	// Six string flags; empty default; help text lives in flag.Usage above.
	name     := flag.String("n", "", "")   // full-name people search
	ip       := flag.String("i", "", "")   // IP lookup
	username := flag.String("u", "", "")   // username search
	generate := flag.String("g", "", "")   // generate + test usernames from a name
	domain   := flag.String("d", "", "")   // subdomain enumeration
	output   := flag.String("o", "", "")   // save report to this path

	// Manual --help / -h intercept (only as the first CLI token).
	if len(os.Args) > 1 && (os.Args[1] == "--help" || os.Args[1] == "-h") {
		flag.Usage(); return
	}

	flag.Parse()                      // fills the *string pointers; unknown flag → exit(2)

	if len(os.Args) == 1 {            // no arguments at all
		flag.Usage(); return
	}

	// Enforce: exactly one of the five modes.
	options := 0
	for _, c := range []string{*name, *ip, *username, *generate, *domain} {
		if c != "" { options++ }
	}
	if options == 0 { fmt.Println("Error: You must provide one of -n, -i, -u, -g, or -d"); return }
	if options  > 1 { fmt.Println("Error: Use only ONE of -n, -i, -u, -g, or -d"); return }

	// Dispatch (conditionless switch; order = ip, username, domain, name, generate).
	var result string
	switch {
	case *ip       != "": result = handlers.HandleIP(*ip)
	case *username != "": result = handlers.HandleUsername(*username)
	case *domain   != "": result = handlers.HandleDomain(*domain)
	case *name     != "": result = handlers.HandleNameScraper(*name)
	case *generate != "": result = handlers.HandleGenerateAndTestUsernames(*generate)
	}

	fmt.Println(result)              // the whole report
	if *output != "" {
		handlers.SaveToFile(*output, result)   // mkdir -p + write 0644
	}
}
```

### 5.2 Initialization / environment

- **No package initializers of note**, no config file.
- **Environment variables:** none read (despite `godotenv` being a declared dependency — the AbuseIPDB key is hard-coded instead).
- **Arguments:** the six flags; exactly one of the five modes required; `-o` optional.
- **Runtime dependencies:** outbound network (HTTP/HTTPS + DNS). If offline, handlers return error strings (or partial reports) rather than crashing.
- **Error handling at entry:** malformed flags → `flag` exits `2`. Wrong mode count / no args → a printed message and a clean `return` (exit `0`). Everything else is handled inside the handlers and surfaced as text in the report.

---

## 6. Code Deep Dive

### 6.1 `handlers.GetIPInfo`

```go
type IPInfo struct {
	Status      string  `json:"status"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	City        string  `json:"city"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"regionName"`
	AS          string  `json:"as"`
	ASN         string  `json:"asn"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Query       string  `json:"query"`
	Timezone    string  `json:"timezone"`
	Zip         string  `json:"zip"`
	AbuseConfidence int  `json:"abuseConfidenceScore,omitempty"`
	TotalReports    int  `json:"totalReports,omitempty"`
	LastReported    string `json:"lastReportedAt,omitempty"`
	UsageType       string `json:"usageType,omitempty"`
	Domain          string `json:"domain,omitempty"`
}

func GetIPInfo(ip string) (*IPInfo, error) {
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query", ip)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil { return nil, fmt.Errorf("failed to fetch IP data: %v", err) }
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil { return nil, fmt.Errorf("failed to read response: %v", err) }
	var info IPInfo
	if err := json.Unmarshal(body, &info); err != nil { return nil, fmt.Errorf("failed to parse JSON: %v", err) }
	if info.Status != "success" { return nil, fmt.Errorf("API error: %s", info.Status) }
	return &info, nil
}
```

**A. Purpose.** Fetch geolocation / ISP / ASN data for an IP from the free **ip-api.com** JSON endpoint and return it as a typed struct.

**B. Inputs.** `ip string` — already validated by `isValidIP` in `HandleIP`. Example: `"8.8.8.8"`.

**C. Internal logic — concepts: REST/JSON API, struct tags, `http.Client` timeout.**
- **`fmt.Sprintf(url, ip)`** builds `http://ip-api.com/json/8.8.8.8?fields=...`. The `fields=` query narrows the response to just the columns needed (ip-api supports a huge field set). **Plain HTTP** — the free tier has no HTTPS, so the request path (`/json/8.8.8.8`, i.e. *which IP you're investigating*) and the response travel unencrypted.
- **`&http.Client{Timeout: 10 * time.Second}`** — a per-request wall-clock cap covering DNS + connect + TLS + response body. Without it, a hung server would block the whole program forever (Go's default client has *no* timeout).
- **`client.Get(url)`** — an HTTP `GET`. `defer resp.Body.Close()` releases the connection back to the pool (mandatory in Go, or you leak sockets).
- **`io.ReadAll(resp.Body)`** — read the whole body into `[]byte`.
- **`json.Unmarshal(body, &info)`** — decode JSON into the struct using the **`json:"..."` tags** to map keys (`"regionName"` → `Region`, `"as"` → `AS`). Fields whose keys are absent stay at their zero value. Unknown JSON keys are ignored.
- **`if info.Status != "success"`** — ip-api returns `{"status":"fail","message":"reserved range"}` for private/reserved IPs or `"status":"success"` otherwise. This turns an API-level failure into a Go `error`.

> Note: `HandleIP`'s URL requests `asname` but the struct has `ASN string json:"asn"` — the response key is `asname`, not `asn`, so `info.ASN` is **always empty**; `HandleIP` only ever prints `info.AS` (the `"as"` field, e.g. `"AS15169 Google LLC"`). Minor unused field.

**D. Output.** `(*IPInfo, error)`. On success, a populated struct. Errors: network failure, read failure, JSON parse failure, or `status != "success"`. **Consumed by** `HandleIP`.

**Concrete example.**
```
GET http://ip-api.com/json/8.8.8.8?fields=...
← {"status":"success","country":"United States","countryCode":"US","regionName":"California",
   "city":"Mountain View","zip":"94043","lat":37.4223,"lon":-122.085,"timezone":"America/Los_Angeles",
   "isp":"Google LLC","org":"Google Public DNS","as":"AS15169 Google LLC","query":"8.8.8.8"}
→ IPInfo{Status:"success", Country:"United States", Region:"California", City:"Mountain View",
         Lat:37.4223, Lon:-122.085, ISP:"Google LLC", Org:"Google Public DNS", AS:"AS15169 Google LLC"}
```

---

### 6.2 `handlers.CheckAbuseDB`

```go
func CheckAbuseDB(ip string) (string, error) {
	apiKey := "716929d0ff8fedcf58069ad53bff5117660d6e50641d6df86751d6eee3936590c63a4bb2f7d3bfe2"  // <-- committed secret
	if apiKey == "" { return "API key required for abuse database (get free key from abuseipdb.com)", nil }

	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", ip)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil { return "", err }
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil { return "", err }
	defer resp.Body.Close()

	var result map[string]interface{}
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &result)

	if data, ok := result["data"].(map[string]interface{}); ok {
		confidence, _   := data["abuseConfidenceScore"].(float64)
		totalReports, _ := data["totalReports"].(float64)   // JSON numbers decode as float64
		lastReported, _ := data["lastReportedAt"].(string)
		if confidence > 0 {
			return fmt.Sprintf("IP has abuse reports (confidence: %.0f%%, total reports: %.0f, last reported: %s)",
				confidence, totalReports, lastReported), nil
		}
	}
	return "No reported abuse in last 90 days", nil
}
```

**A. Purpose.** Query **AbuseIPDB** for whether an IP has been reported for abusive activity (spam, brute force, scanning) in the last 90 days, and summarize.

**B. Inputs.** `ip string`.

**C. Internal logic — concepts: API-key auth via header, `http.NewRequest` + custom headers, dynamic JSON with `map[string]interface{}` + type assertions.**
- **`apiKey := "716929d0..."`** — a **real AbuseIPDB API key hard-coded in source** (and committed to the repo). The `if apiKey == ""` check is dead (it's never empty). This directly contradicts the README's own "Sensitive API keys should never be committed" and the presence of the `godotenv` dependency, which suggests env-var loading was intended. **This is the project's most serious issue** (see §13).
- **`http.NewRequest("GET", url, nil)`** — build a request object so custom headers can be attached (`client.Get` doesn't allow that).
- **`req.Header.Set("Key", apiKey)`** — AbuseIPDB authenticates via a `Key` header (not `Authorization`). `Accept: application/json` requests a JSON response.
- **`client.Do(req)`** — send. `defer resp.Body.Close()`.
- **`var result map[string]interface{}` + `json.Unmarshal`** — decode into a **generic map** rather than a typed struct. Every JSON value becomes `interface{}`; you recover concrete types with **type assertions** (`.(map[string]interface{})`, `.(float64)`, `.(string)`). The `, ok` / `, _` form of the assertion returns the zero value instead of panicking on a type mismatch.
- **JSON numbers are `float64`** in Go's generic decoder — hence `totalReports` is a `float64` and printed with `%.0f`.
- **No status-code check.** A `403` (bad/expired key) or `429` (rate limited) still parses (as an error JSON with no `data` key), the `if data, ok := ...` is `false`, and the function returns `"No reported abuse in last 90 days"` — a **false-negative** disguised as a clean result.

**D. Output.** `(string, error)`. Either `"IP has abuse reports (confidence: 80%, total reports: 42, last reported: 2026-08-01T...)"` or `"No reported abuse in last 90 days"`. Network errors return `("", err)`. **Consumed by** `HandleIP` (`- {abuseStatus}` line, or `- Abuse check failed: {err}`).

---

### 6.3 `handlers.HandleIP` (report assembly) + `isValidIP`

```go
func isValidIP(ip string) bool { return net.ParseIP(ip) != nil }

func HandleIP(ip string) string {
	if !isValidIP(ip) { return fmt.Sprintf("Error: '%s' is not a valid IP address\n", ip) }

	output := fmt.Sprintf("IP Address: %s\n", ip) + strings.Repeat("=", 50) + "\n\n"
	output += "[INFO] Fetching geolocation and ISP data...\n\n"

	info, err := GetIPInfo(ip)
	if err != nil { return fmt.Sprintf("Error: %v\n", err) }

	output += " GEOGRAPHIC INFORMATION:\n"
	output += fmt.Sprintf("  - Country: %s (%s)\n", info.Country, info.CountryCode)
	// ... region/city/zip/timezone (each printed only if non-empty) ...
	output += fmt.Sprintf("  - Coordinates: %.4f, %.4f\n", info.Lat, info.Lon)

	output += "\n NETWORK INFORMATION:\n"
	// ... ISP / Org (if != ISP) / AS ...

	output += "\n🔍 ADDITIONAL INFORMATION:\n"
	output += fmt.Sprintf("  - Google Maps: https://www.google.com/maps?q=%.4f,%.4f\n", info.Lat, info.Lon)
	output += fmt.Sprintf("  - IP Info: https://ipinfo.io/%s\n", ip)
	output += fmt.Sprintf("  - VirusTotal: https://www.virustotal.com/gui/ip-address/%s\n", ip)

	output += "\n  ABUSE REPORT STATUS:\n"
	abuseStatus, err := CheckAbuseDB(ip)
	if err != nil { output += fmt.Sprintf("  - Abuse check failed: %v\n", err) } else { output += fmt.Sprintf("  - %s\n", abuseStatus) }

	output += "\n" + strings.Repeat("=", 50) + "\nOSINT TIPS:\n" + /* Shodan / breach / reverse-DNS / TI tips */ ""
	return output
}
```

**A. Purpose.** Orchestrate the IP lookup and format one text report.

**B. Inputs.** `ip string` — from `main` (`*ip`).

**C. Internal logic — concept: `net.ParseIP`, string-builder-by-concatenation.**
- **`isValidIP`** delegates to **`net.ParseIP`**, which accepts both IPv4 (`1.2.3.4`) and IPv6 (`2001:db8::1`) and returns `nil` for anything malformed (`999.999.999.999`, `not-an-ip`). This replaces a hand-rolled split-and-check that's present but commented out.
- The report is built by repeated `output += ...` (Go string concatenation; for a report of this size the O(n²) copying is negligible). Conditional lines (`if info.Region != ""`) keep empty fields out.
- Three OSINT **pivot links** are generated (not fetched): a Google Maps pin, the ipinfo.io page for the IP, and the VirusTotal IP page.
- `CheckAbuseDB` is called last; its string (or an error) becomes the "ABUSE REPORT STATUS" line.

**D. Output.** the full report `string`. On invalid IP or `GetIPInfo` error, a short `Error: ...` string instead. **Consumed by** `main` (printed; saved if `-o`).

---

### 6.4 `handlers.HandleDomain` + helpers

```go
func resolveSubdomain(subdomain string) ([]string, error) {
	ips, err := net.LookupHost(subdomain)
	if err != nil { return nil, err }
	fmt.Println("ips =========> ", ips)          // <-- stray debug print
	return ips, nil
}
func getCNAME(subdomain string) string {
	cname, err := net.LookupCNAME(subdomain)
	if err != nil { return "" }
	return strings.TrimSuffix(cname, ".")
}
func checkSSL(subdomain string) (bool, string) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:443", subdomain), 2*time.Second)
	if err != nil { return false, "No SSL certificate" }
	conn.Close()
	return true, "Valid SSL certificate (basic check)"
}
func analyzeTakeoverRisk(subdomain, cname string, ips []string) (string, string) {
	if cname != "" {
		c := strings.ToLower(cname)
		if strings.Contains(c, ".s3.amazonaws.com") || strings.Contains(c, ".s3.") { return "HIGH", "CNAME points to AWS S3 bucket - potential takeover if bucket doesn't exist" }
		if strings.Contains(c, ".github.io")        { return "HIGH", "CNAME points to GitHub Pages ..." }
		if strings.Contains(c, ".herokuapp.com")    { return "HIGH", "CNAME points to Heroku ..." }
		if strings.Contains(c, ".azurewebsites.net") || strings.Contains(c, ".cloudapp.net") { return "HIGH", "CNAME points to Azure ..." }
		if strings.Contains(c, ".myshopify.com")    { return "HIGH", "CNAME points to Shopify ..." }
		if strings.Contains(c, ".medium.com")       { return "HIGH", "CNAME points to Medium ..." }
		if strings.Contains(c, ".readme.io")        { return "HIGH", "CNAME points to ReadMe.io ..." }
		return "MEDIUM", fmt.Sprintf("CNAME points to external service: %s", cname)
	}
	if len(ips) > 0 { return "LOW", "Direct IP mapping - takeover unlikely" }
	return "UNKNOWN", "No DNS records found"
}
```

**A. Purpose.** Discover which common subdomains of a domain exist, gather basic facts about each, and flag ones that *might* be vulnerable to subdomain takeover.

**B. Inputs.** `HandleDomain(domain string)` — e.g. `"github.com"`.

**C. Internal logic — concepts: DNS `A`/`AAAA` vs `CNAME`, brute-force enumeration, TCP-connect probe, subdomain takeover.**
- **`getSubdomainList()`** is a hard-coded ~130-label wordlist (`www`, `mail`, `api`, `dev`, `staging`, `vpn`, `gitlab`, `s3`, `grafana`, `v1`/`v2`…). Enumeration is only as good as this list — anything not in it is invisible (real tools also query **Certificate Transparency logs**, which the report links as a manual step: `crt.sh/?q=%.<domain>`).
- **`resolveSubdomain` → `net.LookupHost(fqdn)`** — resolves both A (IPv4) and AAAA (IPv6) records via the **system resolver**. A non-error, non-empty result ⇒ "this subdomain exists." **Wildcard DNS caveat:** if the zone has `*.github.com A 1.2.3.4`, *every* label resolves and the tool reports ~130 false positives; the code does not detect wildcards (e.g. by first resolving a random nonsense label).
- **`getCNAME` → `net.LookupCNAME`** — a **CNAME** ("canonical name") record aliases one name to another (`blog.example.com → example.github.io`). `strings.TrimSuffix(cname, ".")` drops the trailing root dot of the FQDN.
- **`checkSSL`** — **misnamed.** It does `net.DialTimeout("tcp", host:443, 2s)` — a bare **TCP connect**. If the 3-way handshake completes it returns `(true, "Valid SSL certificate (basic check)")`; otherwise `(false, "No SSL certificate")`. It performs **no TLS handshake, no certificate parsing, no expiry check** — a service could be listening on 443 with a self-signed, expired, or wrong-host cert (or non-TLS entirely) and this still says "Valid SSL certificate". `SubdomainInfo.SSLExpiry` is therefore always one of two canned strings.
- **`analyzeTakeoverRisk`** — **subdomain takeover** is when a DNS record points to a third-party service (S3 bucket, GitHub Pages repo, Heroku app…) that has since been deleted, letting an attacker re-register that resource and serve content from your subdomain. The function is a **substring match on the CNAME target**: known dangling-prone providers ⇒ `HIGH` (with a provider-specific note); any other external CNAME ⇒ `MEDIUM`; a direct A record and no CNAME ⇒ `LOW`; nothing ⇒ `UNKNOWN`. It does **not** actually fetch the subdomain to check for the tell-tale "no such bucket" / "404 There isn't a GitHub Pages site here" body — so `HIGH` here means "worth checking manually," not "confirmed takeover."
- **`HandleDomain` loop** — sequential over all ~130 labels: `resolveSubdomain`; on a hit, `getCNAME` + `checkSSL` + `analyzeTakeoverRisk`, append a formatted block, and every 50 iterations print a `[PROGRESS]` line. Then a summary, a HIGH-risk list, an all-active list (with `*`/`+`/`-` risk markers), OSINT recommendations, and resource links (SecurityTrails, crt.sh, DNSDumpster) + a legal note. **No concurrency** — with DNS timeouts and the 2 s `:443` dials, a domain with many live subdomains can take minutes.

**D. Output.** the report `string`; also a stray `ips =========>  [...]` line per hit on stdout (debug leftover). **Consumed by** `main`.

---

### 6.5 `handlers.checkUsernameOnPlatform` + enrichment

```go
func checkUsernameOnPlatform(username string, platform Platform, client *http.Client) CheckResult {
	url := fmt.Sprintf(platform.URL, username)             // e.g. "https://github.com/%s" -> ".../torvalds"
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil { return CheckResult{Platform: platform.Name, URL: url, Username: username, Found: false, Category: platform.Category} }
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil { return CheckResult{ /* Found:false */ } }
	defer resp.Body.Close()

	found := resp.StatusCode == 200 || resp.StatusCode == 302
	result := CheckResult{Platform: platform.Name, URL: url, Username: username, Found: found, Category: platform.Category}

	if found {
		switch platform.Name {
		case "GitHub": if p := enrichGitHub(username, client); p != nil { result.Profile = *p }
		case "Reddit": if p := enrichReddit(username, client); p != nil { result.Profile = *p }
		}
	}
	return result
}
```

**A. Purpose.** Decide whether `username` exists on one platform, and (for GitHub/Reddit only) pull a little profile detail.

**B. Inputs.** `username` (already `@`-stripped by `HandleUsername`), a `Platform{Name, URL, Category}`, a shared `*http.Client` (8 s timeout).

**C. Internal logic — concepts: HTTP `HEAD`, status codes, User-Agent spoofing, the unreliability of presence-by-status.**
- **`fmt.Sprintf(platform.URL, username)`** fills the `%s` in the template (`"https://twitter.com/%s"` → `"https://twitter.com/torvalds"`).
- **`http.NewRequest("HEAD", ...)`** — a `HEAD` request asks only for the response **headers and status line, no body** — cheaper than `GET` when you only need "does this URL exist?". `defer resp.Body.Close()` is still required (the body is empty but the connection must be released).
- **`req.Header.Set("User-Agent", "Mozilla/5.0 ...")`** — spoof a browser UA. Many sites 403 or serve different content to the default Go UA (`Go-http-client/1.1`).
- **`found := status == 200 || status == 302`** — the core heuristic, and its weakness:
  - Some platforms return **`200` for a non-existent user** (a "user not found" page rendered with a 200) → **false positive**.
  - Some return **`404`/`301`/`403`/`429`** for a *real* user (bot-blocking, login walls, redirects to `/login`) → **false negative**.
  - The client is created with `CheckRedirect` at its default, so a `301`/`302` to a login page may be *followed* and the final `200` counted as "found."
  - LinkedIn, Instagram, Facebook, Twitter/X are especially unreliable this way. This is exactly why **only GitHub and Reddit are enriched** — they have clean, documented public JSON APIs where "exists" is unambiguous.
- **Enrichment** (only when `found`): `enrichGitHub` GETs `https://api.github.com/users/<u>` (fields `bio`, `followers`, `public_repos`); `enrichReddit` GETs `https://www.reddit.com/user/<u>/about.json` with a specific descriptive UA (Reddit aggressively blocks generic UAs) and sums `comment_karma + link_karma`. Both return `nil` on any non-`200` (rate-limited, not found) so enrichment "fails quietly" and the base "found" line still prints.
  - **GitHub API is unauthenticated** here → 60 requests/hour limit; a `-g` run testing 30 names × (GitHub found) can blow through it and silently stop enriching.

**D. Output.** a `CheckResult{Platform, URL, Username, Found, Category, Profile}`. **Consumed by** `HandleUsername` / `HandleGenerateAndTestUsernames` (which keep the `Found` ones and call `formatResult`).

---

### 6.6 `handlers.scrapeUSPhoneBookWithProxy` + `HandleNameScraper`

```go
func scrapeUSPhoneBookWithProxy(firstName, lastName, proxyAddress string) ([]ContactInfo, error) {
	searchURL := fmt.Sprintf("https://www.usphonebook.com/search?first=%s&last=%s",
		url.QueryEscape(firstName), url.QueryEscape(lastName))
	client := &http.Client{Timeout: 15 * time.Second}
	if proxyAddress != "" {
		if proxyURL, err := url.Parse(proxyAddress); err == nil {
			client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		}
	}
	req, _ := http.NewRequest("GET", searchURL, nil)
	// ~15 headers spoofing Chrome 120 on Windows: User-Agent, Accept, Accept-Language,
	//   Accept-Encoding, Connection, Sec-Ch-Ua*, Sec-Fetch-*, Upgrade-Insecure-Requests
	resp, err := client.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	if resp.StatusCode != 200 { return nil, fmt.Errorf("HTTP error: %d (blocked by anti-bot protection)", resp.StatusCode) }

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil { return nil, err }

	var contacts []ContactInfo
	selectors := []string{".search-result", ".result-item", ".person-result", ".listing-card", "div[data-testid='result']"}
	for _, sel := range selectors {
		doc.Find(sel).Each(func(i int, s *goquery.Selection) {
			c := ContactInfo{}
			for _, ps := range []string{".phone", ".phone-num", "a[href^='tel:']", ".number", "[data-phone]"} {
				if v := s.Find(ps).Text(); v != "" { c.Phone = strings.TrimSpace(v); break }
			}
			for _, as := range []string{".address", ".street-address", ".address-line", ".location", ".adr"} {
				if v := s.Find(as).Text(); v != "" { c.Address = strings.TrimSpace(v); break }
			}
			if c.Phone != "" || c.Address != "" { contacts = append(contacts, c) }
		})
		if len(contacts) > 0 { break }
	}
	return contacts, nil
}
```

**A. Purpose.** Attempt to pull phone/address results for a person from `usphonebook.com` by scraping its search-results HTML; the caller falls back to manual links when this fails (which, per the code's own comments, is the expected case).

**B. Inputs.** `firstName`, `lastName` (already `IsAllAlpha`-validated), `proxyAddress` (the only caller passes `""`, so the proxy branch is dead in practice).

**C. Internal logic — concepts: URL query escaping, User-Agent/`Sec-*` header spoofing, HTML scraping with `goquery`, CSS selectors, anti-bot walls.**
- **`url.QueryEscape`** percent-encodes the names so `O'Brien` / spaces don't break the query string.
- **`http.Transport{Proxy: http.ProxyURL(...)}`** — would route requests through an HTTP proxy (to rotate source IPs past rate limits); unused here.
- **The ~15 spoofed headers** (`User-Agent: ...Chrome/120...`, `Sec-Ch-Ua`, `Sec-Fetch-Site: none`, `Upgrade-Insecure-Requests: 1`, …) mimic a real Chrome navigation to get past naive bot filters. `usphonebook.com` uses stronger protection (Cloudflare-style), so this typically still returns a non-`200` → `"blocked by anti-bot protection"` error.
- **`goquery.NewDocumentFromReader(resp.Body)`** parses the HTML into a jQuery-like document. **`doc.Find(selector)`** runs a **CSS selector** (via the `cascadia` engine) and returns matching nodes; `.Each` iterates them; `s.Find(...).Text()` extracts inner text.
- **Selector guessing** — the code doesn't know usphonebook's real markup, so it tries five plausible container classes and, within each, five phone selectors and five address selectors, stopping at the first that yields anything. This is inherently brittle: any markup change (or the anti-bot page) breaks it.

```go
func HandleNameScraper(fullName string) string {
	parts := strings.Fields(fullName)
	if len(parts) < 2 { return "Error: Please provide both first and last name\n" }
	firstName, lastName := parts[0], strings.Join(parts[1:], " ")
	if !IsAllAlpha(firstName) || !IsAllAlpha(lastName) { return "Error: Name should contain only letters\n" }

	output := fmt.Sprintf("First name: %s\nLast name: %s\n\n", firstName, lastName)
	output += "[INFO] Attempting to scrape USPhoneBook.com...\n[INFO] This may be blocked by anti-bot protection\n\n"

	contacts, err := scrapeUSPhoneBookWithProxy(firstName, lastName, "")
	if err != nil && strings.Contains(err.Error(), "403") {
		output += "[WARNING] Direct access blocked (403 error)\n[INFO] Trying with proxy... (You need to configure a real proxy)\n\n"
	}
	if err != nil {
		output += fmt.Sprintf("[ERROR] Scraping failed: %v\n\n", err)
		output += getManualSearchLinks(firstName, lastName)
		return output
	}
	if len(contacts) == 0 {
		output += "[INFO] No results found on USPhoneBook\n\n" + getManualSearchLinks(firstName, lastName)
	} else {
		output += fmt.Sprintf("[SUCCESS] Found %d result(s):\n\n", len(contacts))
		for i, c := range contacts { /* print Phone / Address per result */ }
	}
	return output
}
```

**D. Output.** a report `string`: either scraped `ContactInfo` rows, or (the common path) a big `getManualSearchLinks` block — people-search sites (Whitepages, AnyWho, ZabaSearch, TruePeopleSearch), socials (LinkedIn/Facebook/Twitter/Instagram/GitHub search URLs), email-pattern guesses (`first.last@gmail.com`, …), Google dorks (`site:linkedin.com/in "First Last"`), a PeopleDataLabs API pointer, and a legal/ethical note. **Consumed by** `main`.

---

### 6.7 `help.GenerateAllUsernames` / `GenerateFromFullName`

```go
type UsernameGenerator struct{ FirstName, LastName string }

func (ug *UsernameGenerator) GenerateAllUsernames() []string {
	usernames := make(map[string]bool)                 // set → dedupe
	first := strings.ToLower(strings.TrimSpace(ug.FirstName))
	last  := strings.ToLower(strings.TrimSpace(ug.LastName))
	fi, li := "", ""
	if len(first) > 0 { fi = string(first[0]) }
	if len(last)  > 0 { li = string(last[0]) }

	usernames[first] = true; usernames[first+"1"] = true; usernames[first+"12"] = true; usernames[first+"123"] = true
	if last != "" {
		usernames[last] = true; /* last+"1", last+"12" */
		usernames[first+last] = true
		usernames[first+"."+last] = true; usernames[first+"_"+last] = true; usernames[first+"-"+last] = true
		usernames[last+first] = true; usernames[last+"."+first] = true; usernames[last+"_"+first] = true
	}
	if fi != "" && last != "" { /* fi+last, fi.last, fi_last, fi-last */ }
	if first != "" && li != "" { /* first+li, first.li, first_li */ }
	if fi != "" && li != "" { usernames[fi+li] = true; /* +"1"/"12"/"123" */ }
	if len(first) >= 4 { usernames[first[:3]] = true; usernames[first[:4]] = true; /* [:5], [:6] if long enough */ }

	suffixes := []string{"", "1", "12", "123", "2023", "2024", "_", ".", "-"}
	bases := []string{first}
	if last != "" { bases = append(bases, last, first+last, fi+last) }
	for _, b := range bases { for _, s := range suffixes {
		if s == "" { usernames[b] = true } else { usernames[b+s] = true; usernames[b+"_"+s] = true; usernames[b+"."+s] = true }
	}}
	for _, p := range []string{"the", "real", "im", "its"} {
		if first != "" { usernames[p+first] = true; usernames[p+"_"+first] = true; usernames[p+"."+first] = true }
		if last  != "" { usernames[p+last] = true }
	}

	result := make([]string, 0, len(usernames))
	for u := range usernames { if len(u) >= 3 && len(u) <= 30 { result = append(result, u) } }
	return result
}

func GenerateFromFullName(fullName string) []string {
	parts := strings.Fields(fullName)
	if len(parts) == 0 { return []string{} }
	first := parts[0]
	last := ""
	if len(parts) > 1 { last = strings.Join(parts[1:], " ") }   // "Jean Michel Basquiat" → last = "Michel Basquiat"
	return (&UsernameGenerator{FirstName: first, LastName: last}).GenerateAllUsernames()
}
```

**A. Purpose.** From a full name, produce a de-duplicated list of plausible username handles to test against platforms.

**B. Inputs.** `fullName string` (`"Linus Torvalds"`); internally `FirstName` / `LastName`.

**C. Internal logic — concepts: `map` as a set for dedupe, string permutation, cross-product with suffixes/prefixes, length filtering, Go map iteration order.**
- Names are lowered and trimmed; `fi`/`li` are the first initials (guarded against empty strings).
- Permutation families: first-name + `1/12/123`; last-name variants; `first+last` with 4 separators; `last+first` reversed; `initial+last`; `first+initial`; `initials` + digits; **truncations** of the first name (`lin`, `linu`, `linus`…); a **cross-product** of `{first, last, first+last, fi+last}` × `{"", "1", "12", "123", "2023", "2024", "_", ".", "-"}` (also inserting `_`/`.` before the suffix); and **prefixes** `{the, real, im, its}`.
- All go into a `map[string]bool` so duplicates collapse (`linus1` gets added by two families).
- The final slice keeps only entries of length **3–30** (a "reasonable handle length").
- **Go map iteration is randomized**, so `GenerateAllUsernames()` returns the candidates in a **different order every run** — which means `HandleGenerateAndTestUsernames`'s "test the first 30" tests a *different 30* each time. (Neither `GenerateUsernameReport` nor the handlers sort the slice.)

**D. Output.** `[]string` of ~50–150 candidates (depends on name length). **Consumed by** `HandleGenerateAndTestUsernames` (and the unused `HandleUsernameFromName` / `GenerateUsernameReport`).

**Example.** `"Linus Torvalds"` → includes `linus`, `torvalds`, `linustorvalds`, `linus.torvalds`, `linus_torvalds`, `ltorvalds`, `l.torvalds`, `lt`, `lt123`, `lin`, `linu`, `torvalds2024`, `thelinus`, `imlinus`, …

---

### 6.8 `handlers.SaveToFile` / `SaveAsPdf`

```go
func SaveToFile(filename, data string) {
	dir := filepath.Dir(filename)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil { fmt.Println("Error creating directory:", err); return }
	}
	if err := os.WriteFile(filename, []byte(data), 0o644); err != nil { fmt.Println("Error saving file:", err); return }
	fmt.Println("Data saved in", filename)
}

func SaveAsPdf(file, content string) {           // <-- defined, never called by main
	dir := filepath.Dir(file)
	if dir != "." {
		if err := os.Mkdir(dir, 0o755); err != nil { fmt.Println("Error creating directory", err); return }  // os.Mkdir, not MkdirAll
	}
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage(); pdf.SetFont("Arial", "", 12)
	pdf.MultiCell(190, 6, content, "", "", false)
	if err := pdf.OutputFileAndClose(file); err != nil { fmt.Println("Error saving PDF file:", err); return }
	fmt.Println("PDF data successfully saved in", file)
}
```

**A. Purpose.** Persist a report. `SaveToFile` = plain text (the wired-in path). `SaveAsPdf` = A4 PDF via `gofpdf` (the README's "bonus", not connected to `main`).

**C. Internal logic.**
- **`filepath.Dir(filename)`** — the directory part (`output/ip.txt` → `output`; `ip.txt` → `.`).
- **`os.MkdirAll(dir, 0o755)`** — create the directory tree (like `mkdir -p`); no error if it already exists. `SaveAsPdf` uses **`os.Mkdir`** instead, which fails if the parent is missing *or the dir already exists* — a latent bug.
- **`os.WriteFile(filename, []byte(data), 0o644)`** — truncate-or-create + write, mode `rw-r--r--`. No path sanitization (`-o ../../x` writes there, within the user's permissions).
- **`gofpdf`** — `New("P","mm","A4","")` (portrait, millimetres, A4), `AddPage`, `SetFont("Arial",...)`, `MultiCell(width, lineHeight, text, ...)` to flow the whole report as wrapped text, `OutputFileAndClose(file)` to serialize. `gofpdf` is archived upstream; `go-pdf/fpdf` is its maintained fork (also a declared dep, unused).

**D. Output.** a file at `filename`; a status line on stdout. **Consumed by** `main` (only `SaveToFile`).

---

## 7. Code Comments — annotated key blocks

### 7.1 The dispatcher (concept first)

**Concept.** One binary, five mutually-exclusive modes. `main` validates "exactly one," then a conditionless `switch` picks the handler. Each handler is a pure `string`-returning function; `main` doesn't parse the result.

```go
// ----- exactly one mode -----
options := 0
for _, c := range []string{*name, *ip, *username, *generate, *domain} {  // -o is NOT in this list
	if c != "" { options++ }
}
if options == 0 { fmt.Println("Error: You must provide one of -n, -i, -u, -g, or -d"); return }  // e.g. only -o given
if options  > 1 { fmt.Println("Error: Use only ONE of -n, -i, -u, -g, or -d"); return }

// ----- dispatch (order fixed: ip, username, domain, name, generate) -----
var result string
switch {
case *ip       != "": result = handlers.HandleIP(*ip)                       // -i : ip-api + AbuseIPDB
case *username != "": result = handlers.HandleUsername(*username)           // -u : HEAD each platform
case *domain   != "": result = handlers.HandleDomain(*domain)              // -d : DNS brute + takeover
case *name     != "": result = handlers.HandleNameScraper(*name)          // -n : scrape + manual links
case *generate != "": result = handlers.HandleGenerateAndTestUsernames(*generate)  // -g : permute + test
}

fmt.Println(result)                          // the whole report, printed verbatim
if *output != "" { handlers.SaveToFile(*output, result) }   // mkdir -p + write 0644
```

**INPUT → PROCESSING → OUTPUT.**
```
INPUT:   ./osintmaster -i 8.8.8.8 -o output/ip.txt
PROCESS: options==1 → switch picks HandleIP("8.8.8.8") → report string
OUTPUT:  report printed to stdout ; SaveToFile writes output/ip.txt (creating output/)
```

### 7.2 IP report assembly

**Concept.** Validate → fetch (`GetIPInfo`) → format geo/network → add pivot links → fetch (`CheckAbuseDB`) → add tips. Two independent HTTP calls; either can fail without aborting the other section.

```go
func HandleIP(ip string) string {
	if !isValidIP(ip) {                                     // net.ParseIP: accepts IPv4 & IPv6, nil on garbage
		return fmt.Sprintf("Error: '%s' is not a valid IP address\n", ip)
	}
	output := fmt.Sprintf("IP Address: %s\n", ip) + strings.Repeat("=", 50) + "\n\n"

	info, err := GetIPInfo(ip)                              // HTTP GET ip-api.com (plain HTTP!) → JSON → struct
	if err != nil {
		return fmt.Sprintf("Error: %v\n", err)             // network / parse / status!="success"
	}

	output += " GEOGRAPHIC INFORMATION:\n"
	output += fmt.Sprintf("  - Country: %s (%s)\n", info.Country, info.CountryCode)
	if info.Region != "" { output += fmt.Sprintf("  - Region/State: %s\n", info.Region) }   // skip empty fields
	// ... city / zip / timezone ...
	output += fmt.Sprintf("  - Coordinates: %.4f, %.4f\n", info.Lat, info.Lon)

	output += "\n ADDITIONAL INFORMATION:\n"
	output += fmt.Sprintf("  - Google Maps: https://www.google.com/maps?q=%.4f,%.4f\n", info.Lat, info.Lon)  // pivot links, not fetched
	output += fmt.Sprintf("  - VirusTotal: https://www.virustotal.com/gui/ip-address/%s\n", ip)

	abuseStatus, err := CheckAbuseDB(ip)                    // HTTPS GET AbuseIPDB with a (hard-coded) Key header
	if err != nil { output += fmt.Sprintf("  - Abuse check failed: %v\n", err) }
	else          { output += fmt.Sprintf("  - %s\n", abuseStatus) }

	return output + /* OSINT tips block */ ""
}
```

**INPUT → PROCESSING → OUTPUT.**
```
INPUT:   "8.8.8.8"
PROCESS: ParseIP ok → GET ip-api → {US, Mountain View, Google LLC, AS15169, 37.42,-122.08}
         → GET AbuseIPDB → data.abuseConfidenceScore == 0 → "No reported abuse in last 90 days"
OUTPUT:  multi-section text: geo + network + links + "No reported abuse in last 90 days" + tips
```

### 7.3 Username presence check

**Concept.** A `HEAD` to the profile URL; `200`/`302` = "exists." Fast and API-key-free, but unreliable — hence enrichment (the trustworthy signal) is limited to GitHub and Reddit.

```go
func checkUsernameOnPlatform(username string, platform Platform, client *http.Client) CheckResult {
	url := fmt.Sprintf(platform.URL, username)             // "https://github.com/%s" → ".../torvalds"
	req, _ := http.NewRequest("HEAD", url, nil)            // HEAD: status + headers only, no body
	req.Header.Set("User-Agent", "Mozilla/5.0 ...")        // default Go UA is often blocked

	resp, err := client.Do(req)
	if err != nil { return CheckResult{Platform: platform.Name, Found: false, /* ... */} }
	defer resp.Body.Close()                                // release the connection even with no body

	found := resp.StatusCode == 200 || resp.StatusCode == 302   // heuristic — FALSE POS on soft-404, FALSE NEG on bot-blocks
	result := CheckResult{Platform: platform.Name, URL: url, Username: username, Found: found, Category: platform.Category}

	if found {                                             // only enrich platforms with a clean public API
		switch platform.Name {
		case "GitHub": if p := enrichGitHub(username, client); p != nil { result.Profile = *p }   // api.github.com/users/<u>
		case "Reddit": if p := enrichReddit(username, client); p != nil { result.Profile = *p }   // reddit.com/user/<u>/about.json
		}
	}
	return result
}
```

**INPUT → PROCESSING → OUTPUT.**
```
INPUT:   username="torvalds", platform={GitHub, "https://github.com/%s"}
PROCESS: HEAD https://github.com/torvalds → 200 → found=true
         enrichGitHub → GET api.github.com/users/torvalds → {bio:"...", followers:230000, public_repos:7}
OUTPUT:  CheckResult{Found:true, Profile:{Bio, Followers:230000, ActivityInfo:"7 public repos", Enriched:true}}
```

---

## 8. INPUT → PROCESSING → OUTPUT (per component)

```
main
  INPUT:   ./osintmaster -X value [-o file]
  PROCESS: parse flags → enforce exactly-one-mode → switch → handler → string
  OUTPUT:  report on stdout ; optional file

HandleIP
  INPUT:   ip string
  PROCESS: net.ParseIP → GET ip-api.com/json (HTTP) → JSON→IPInfo (status check)
           → GET api.abuseipdb.com (HTTPS, Key header) → summarize data.*
  OUTPUT:  geo + network + pivot links + abuse status + tips  (string)
  EXAMPLE: "8.8.8.8" → "... Country: United States (US) ... ISP: Google LLC ... ASN: AS15169 Google LLC ... No reported abuse ..."

HandleUsername
  INPUT:   username string
  PROCESS: strip '@' ; for each of 8 platforms: HEAD profile URL → 200/302 = found ;
           GitHub/Reddit → GET their JSON API for bio/followers/repos/karma
  OUTPUT:  per-platform "[FOUND] ..." lines + "Total profiles found: N/8"
  EXAMPLE: "torvalds" → "[FOUND] GitHub: https://github.com/torvalds  Bio: ...  Followers: 230000  Activity: 7 public repos" + others

HandleDomain
  INPUT:   domain string
  PROCESS: for each of ~130 labels: net.LookupHost(label.domain) ; on hit:
           net.LookupCNAME ; TCP dial :443 (2s) ; classify takeover risk by CNAME substring
  OUTPUT:  found list + HIGH-risk list + all-active list + OSINT tips + crt.sh/SecurityTrails/DNSDumpster links
  EXAMPLE: "github.com" → "✓ api.github.com  IP: ...  SSL: Valid SSL certificate (basic check)  Risk: LOW - Direct IP mapping ..."
  SIDE:    ~130 DNS queries + up to ~130 :443 connects ; a stray "ips =========>" line per hit

HandleNameScraper
  INPUT:   "First Last"
  PROCESS: split ; IsAllAlpha ; GET usphonebook.com with ~15 spoofed headers ; goquery selector-guessing ;
           on non-200 / no results → getManualSearchLinks
  OUTPUT:  scraped Phone/Address rows OR a big block of manual OSINT URLs + email guesses + dorks + legal note

HandleGenerateAndTestUsernames
  INPUT:   "First Last"
  PROCESS: help.GenerateFromFullName → ~50–150 candidates (map-order, so nondeterministic) ;
           test first 30 across 8 platforms via HEAD
  OUTPUT:  "[VALID] <name> - Found on: GitHub, ..." lines + summary + tips

SaveToFile
  INPUT:   filename, report string
  PROCESS: os.MkdirAll(dir) ; os.WriteFile(filename, data, 0644)
  OUTPUT:  a text file ; "Data saved in <file>"
```

---

## 9. Important Concepts

**TERM: OSINT / passive reconnaissance**
- *Definition.* Collecting intelligence from publicly available sources (public APIs, DNS, search engines, social profiles, public records) without interacting intrusively with the target's private systems.
- *Why it exists.* It's the legal, low-noise first phase of a security assessment (or an investigation), and it's often where most useful information already lives.
- *How it works here.* Every capability calls a *public* service (ip-api, AbuseIPDB, GitHub/Reddit public APIs, DNS, a people-search site) — no authentication bypass, no exploitation.
- *Without it.* You'd have no structured way to footprint an IP/name/domain.
- *Where.* The whole project; README "passive reconnaissance only."

**TERM: REST API / JSON / struct tags**
- *Definition.* A **REST API** exposes data over HTTP URLs, usually returning **JSON**. Go's `encoding/json` maps JSON keys ↔ struct fields via **`json:"key"` tags**; `omitempty` drops zero-value fields when *encoding*.
- *Why here.* ip-api, AbuseIPDB, GitHub, Reddit all speak JSON-over-HTTP.
- *How it works.* `json.Unmarshal(body, &v)` — matched keys fill fields, missing keys leave zero values, extra keys are ignored. For unpredictable shapes, decode into `map[string]interface{}` and use type assertions (`.(float64)`, `.(string)`).
- *Gotcha in this code.* The struct maps `"asn"` but the API sends `"asname"`, so `IPInfo.ASN` is always empty.
- *Where.* `handleIP.go` (`IPInfo`, `GetIPInfo`, `CheckAbuseDB`), `handleUsername.go` (`githubAPIResponse`, `redditAPIResponse`).

**TERM: `net/http.Client`, timeouts, `HEAD` vs `GET`, `resp.Body.Close()`**
- *Definition.* `http.Client` performs HTTP requests. `Client.Timeout` bounds the *entire* exchange. `GET` fetches headers + body; **`HEAD`** fetches headers + status line only. You must `Close()` the response body to release the connection.
- *Why here.* Timeouts stop a hung API from freezing the CLI (Go's zero-value client has *no* timeout). `HEAD` is used for the username "does this URL exist?" check to avoid downloading pages.
- *Where.* every handler builds a `&http.Client{Timeout: ...}` (10 s ip-api/AbuseIPDB, 8 s username, 5 s generate, 15 s scrape); `checkUsernameOnPlatform` uses `HEAD`; every `resp.Body.Close()` is `defer`red.

**TERM: HTTP status codes (as an existence signal)**
- *Definition.* `200 OK`, `301/302` redirect, `403 Forbidden`, `404 Not Found`, `429 Too Many Requests`.
- *How it's (mis)used here.* `found := status == 200 || status == 302`. Reliable only when a platform returns a clean `404` for missing users and `200` for real ones. Many don't: soft-404s (200 + "user not found" body) → false positives; bot walls / login redirects (403/429/301→/login) → false negatives.
- *Where.* `checkUsernameOnPlatform`; `scrapeUSPhoneBookWithProxy` (`!= 200` ⇒ "blocked by anti-bot protection").

**TERM: DNS — A/AAAA records, `CNAME`, resolvers, brute-force enumeration, wildcard DNS**
- *Definition.* **DNS** maps names to records. **A**/**AAAA** = IPv4/IPv6 address. **CNAME** = an alias pointing one name at another canonical name. A **resolver** answers queries (here, the OS resolver via `net.LookupHost`/`LookupCNAME`). **Brute-force enumeration** = try many candidate labels and see which resolve. **Wildcard DNS** = `*.domain` resolves *every* label.
- *Why here.* `-d` discovers subdomains by resolving `label.domain` for ~130 common labels; CNAMEs feed the takeover check.
- *Gotchas.* Only labels in the hard-coded list are found (real tools also mine Certificate Transparency logs — `crt.sh`); a wildcard zone yields ~130 false positives (the code doesn't probe for wildcards).
- *Where.* `handelDomain.go` (`resolveSubdomain`, `getCNAME`, `getSubdomainList`).

**TERM: Subdomain takeover**
- *Definition.* A dangling DNS record points a subdomain at a third-party resource (S3 bucket, GitHub Pages repo, Heroku app, Azure site…) that no longer exists; an attacker re-registers that resource and now controls content on your subdomain (phishing, cookie theft, bypassing SPF/DMARC-adjacent trust).
- *How it's detected here.* `analyzeTakeoverRisk` substring-matches the CNAME target against known-risky provider domains → `HIGH` + a note. It does **not** fetch the page to confirm the tell-tale "no such resource" response — so `HIGH` = "investigate," not "confirmed."
- *Where.* `handelDomain.go` (`analyzeTakeoverRisk`), surfaced in the "HIGH RISK SUBDOMAINS" report section.

**TERM: TCP connect probe vs TLS handshake / certificate validation**
- *Definition.* A **TCP connect** completes the 3-way handshake to a `host:port`. A **TLS handshake** then negotiates encryption and presents an X.509 **certificate** (issuer, validity dates, SANs) that a client validates.
- *What `checkSSL` actually does.* Only the TCP connect to `:443`. It never starts TLS, never reads a cert, never checks expiry — yet returns the string `"Valid SSL certificate (basic check)"`. This **overstates** what was verified.
- *Where.* `handelDomain.go` (`checkSSL`); `SubdomainInfo.HasSSL`/`SSLExpiry`.

**TERM: HTML scraping / `goquery` / CSS selectors / anti-bot**
- *Definition.* Extracting data from a site's HTML rather than an API. `goquery` gives a jQuery-style API over Go's HTML parser; `doc.Find("css selector")` (backed by `cascadia`) selects nodes. **Anti-bot** systems (Cloudflare, DataDome) block non-browser clients via TLS/JA3 fingerprints, header checks, JS challenges, and CAPTCHAs.
- *Why here.* `-n` tries to scrape `usphonebook.com` because it has no free API.
- *Fragility.* The code spoofs ~15 browser headers and *guesses* five container/phone/address selectors; a markup change or the anti-bot wall breaks it — so the manual-links fallback is the real product.
- *Where.* `handleName.go`.

**TERM: User-Agent spoofing**
- *Definition.* Setting the `User-Agent` header to impersonate a real browser instead of the client's default (`Go-http-client/1.1`).
- *Why here.* Many sites/APIs behave differently for non-browser UAs (403, different content, aggressive rate limits). Reddit specifically blocks generic UAs, so `enrichReddit` sends `"osint-master/1.0 (educational OSINT tool)"`.
- *Where.* `checkUsernameOnPlatform`, `enrichGitHub`, `enrichReddit`, `scrapeUSPhoneBookWithProxy`.

**TERM: API keys & secrets management**
- *Definition.* A credential that authenticates your app to a service. It must **not** be committed to source control — use environment variables, a `.env` file (gitignored), or a secrets manager.
- *In this project.* `CheckAbuseDB` **hard-codes a live AbuseIPDB key**. The repo also declares `github.com/joho/godotenv` (a `.env` loader) but never uses it. The README itself says secrets shouldn't be committed. This is the primary security defect (§13).
- *Where.* `handleIP.go` (`apiKey := "716929d0..."`).

**TERM: API rate limiting**
- *Definition.* Services cap requests per time window (ip-api: 45/min on the free HTTP endpoint; unauthenticated GitHub API: 60/hour; AbuseIPDB free: 1,000/day; Reddit: strict per-UA/IP).
- *How it bites here.* `-d` fires ~130 lookups fast; `-g` fires 8 HEADs × 30 names = 240 requests plus GitHub-API enrichment. On a `429`/`403`, `checkUsernameOnPlatform` just records "not found" and `enrichGitHub`/`enrichReddit` return `nil` — failures are silent, so results silently degrade.
- *Where.* all network handlers; README "API Rate Limits".

**TERM: Go `flag` package / conditionless `switch` / `map` as a set**
- *Definition.* `flag` parses `-name value` CLI args into typed pointers. `switch { case cond: }` (no expression) is an if/else-if chain. `map[K]bool` used purely for O(1) membership / dedupe is idiomatic Go for a "set".
- *Where.* `main.go` (flags + dispatch switch); `help.GenerateAllUsernames` (`map[string]bool` dedupe).

**TERM: `net.ParseIP`**
- *Definition.* Parses an IPv4 or IPv6 string into a `net.IP`; returns `nil` for invalid input.
- *Why here.* Robust IP validation for `-i` (replacing a hand-rolled split-check that's commented out in the file).
- *Where.* `handleIP.go` (`isValidIP`).

**TERM: `url.QueryEscape` / query strings**
- *Definition.* Percent-encodes a string so it's safe inside a URL query (` ` → `%20`, `&` → `%26`).
- *Why here.* Names/usernames go into `?first=...&last=...` and `?q=...` — escaping prevents breakage and injection into the query structure.
- *Where.* `handleName.go` (`scrapeUSPhoneBookWithProxy`, `getManualSearchLinks`).

---

## 10. Libraries and Dependencies

| Dependency | What it is | Why here | Symbols used | Used? |
|---|---|---|---|---|
| **`github.com/PuerkitoBio/goquery`** | jQuery-style HTML traversal over Go's HTML parser | Parse `usphonebook.com` search results | `goquery.NewDocumentFromReader`, `(*Document).Find`, `(*Selection).Each`, `(*Selection).Text` | **Yes** — `handleName.go` |
| **`github.com/andybalholm/cascadia`** | CSS-selector engine | Backs `goquery.Find("selector")` | (indirect, via goquery) | Yes (transitively) |
| **`golang.org/x/net`** | Extended networking (incl. `html`) | goquery's HTML tokenizer/parser | (indirect) | Yes (transitively) |
| **`github.com/jung-kurt/gofpdf`** | Pure-Go PDF generator (archived upstream) | `SaveAsPdf` renders the report as A4 PDF | `gofpdf.New`, `AddPage`, `SetFont`, `MultiCell`, `OutputFileAndClose` | **Imported, but `SaveAsPdf` is never called by `main`** |
| **`github.com/go-pdf/fpdf`** | Maintained fork of `gofpdf` | (presumably intended replacement) | none | **Declared, not imported** |
| **`github.com/joho/godotenv`** | Loads `.env` into environment variables | Presumably intended to hold the AbuseIPDB key | none | **Declared, not imported** — the key is hard-coded instead |

**Standard library:** `flag`, `fmt`, `os`, `net` (`ParseIP`, `LookupHost`, `LookupCNAME`, `DialTimeout`), `net/http` (`Client`, `NewRequest`, `Get`, `Do`, `Transport`, `ProxyURL`, `Header`), `net/url` (`QueryEscape`, `Parse`), `encoding/json` (`Unmarshal`, `NewDecoder().Decode`), `io` (`ReadAll`), `strings`, `time`, `unicode` (`IsLetter`), `path/filepath` (`Dir`).

**Why not implement it ourselves.**
- *HTML parsing/CSS selection* — a correct, spec-compliant HTML5 tokenizer + tree builder + CSS selector engine is a large, subtle body of code; `goquery`+`cascadia`+`x/net/html` provide it.
- *PDF generation* — the PDF format (objects, xref tables, font metrics, page layout) is non-trivial; `gofpdf` encapsulates it.
- Everything else (HTTP, JSON, DNS, IP parsing) is stdlib.

**What the libraries do internally (high level, not visible in this repo).** `goquery` wraps `golang.org/x/net/html.Parse` (a streaming HTML5 parser) and exposes a `Selection` over the node tree; `Find` compiles the selector string with `cascadia` into a matcher and walks the tree. `gofpdf` builds an in-memory PDF document model (pages, content streams, font resources) and serializes it to the PDF byte format on `OutputFileAndClose`. **Details beyond this are not in the provided source and are not asserted here.**

### PROJECT CODE vs LIBRARY CODE

| Project code | Library code |
|---|---|
| the flag dispatcher, the "one mode" rule, all report string assembly | `flag` parsing, `net/http` transport, `encoding/json` decoding |
| the ~130-label wordlist, the takeover CNAME rules, the risk classification | `net.LookupHost`/`LookupCNAME` (→ system resolver / `x/net/dns`) |
| the `HEAD` + `200/302` heuristic, the GitHub/Reddit enrichment mapping | GitHub/Reddit servers; `net/http` |
| the ~15 spoofed headers, the five-selector guessing loop | `goquery`/`cascadia`/`x/net/html` parsing & selection |
| the username permutation families + length filter | `strings`, Go `map` iteration |
| `SaveToFile` mkdir/write logic | `os.MkdirAll`/`os.WriteFile`; `gofpdf` for `SaveAsPdf` |

---

## 11. Operating System / Network / Database Concepts

**No database.** All state is transient; output is a flat file.

### 11.1 An HTTP API call, layer by layer (`GetIPInfo` / `CheckAbuseDB` / enrichment / scrape)
```
handler
   │  client.Get(url)  /  client.Do(req)   (http.Client, with Timeout)
   ▼
net/http Transport  →  connection pool  →  (if new) DNS resolve host  →  TCP connect  →  [TLS handshake for https://]
   ▼
kernel sockets (connect/send/recv)  →  NIC  →  … Internet …  →  ip-api.com / api.abuseipdb.com / github.com / reddit.com / usphonebook.com
   ▼
response bytes back up  →  io.ReadAll / json.Decoder  →  struct or map[string]interface{}
```
- **`http://ip-api.com`** = **no TLS** — the request line reveals *which IP you're investigating* and the response is unencrypted; anyone on-path can read both. `https://api.abuseipdb.com` and the GitHub/Reddit APIs *are* TLS-protected.
- **`Client.Timeout`** covers DNS + connect + TLS + reading the body; on expiry the request errors out and the handler returns an `Error:`/partial string.
- **Connection reuse:** `net/http` keeps idle keep-alive connections; `resp.Body.Close()` returns the connection to the pool. Not closing = a leaked connection per call.

### 11.2 DNS resolution, layer by layer (`-d`)
```
resolveSubdomain("api.github.com")
   │  net.LookupHost(fqdn)
   ▼
Go resolver → (cgo or pure-Go) → /etc/resolv.conf → send UDP/53 query to the configured resolver
   ▼
recursive resolver → root → TLD (.com) → authoritative (github.com NS) → A/AAAA answer (or NXDOMAIN)
   ▼
[]string of IPs  (err != nil / NXDOMAIN ⇒ "subdomain doesn't exist")
```
- **`net.LookupCNAME`** issues a CNAME query (or returns the canonical name from the A-record chain).
- **Caching** at the OS/resolver level means repeat runs are faster and can mask very recent DNS changes.
- **Wildcard zones** answer *every* label, so `resolveSubdomain` succeeds for nonsense labels → false-positive subdomains (undetected here).

### 11.3 The `:443` probe (`checkSSL`)
```
net.DialTimeout("tcp", "api.github.com:443", 2s)
   → DNS resolve → TCP SYN → SYN/ACK → ACK  (handshake only)
   → conn.Close()  (no TLS ClientHello is ever sent)
```
Return value reflects *only* whether something accepted a TCP connection on 443 within 2 s.

### 11.4 File output (`SaveToFile`)
```
os.MkdirAll(dir, 0755)  → mkdir() syscalls for each missing path component (no error if present)
os.WriteFile(path, data, 0644)  → open(O_WRONLY|O_CREAT|O_TRUNC) → write() → close()
```
No path normalization; the OS resolves `..`/absolute paths with the invoking user's permissions.

### 11.5 Networking primitives that appear
- **IP address** — `net.ParseIP` validates v4/v6.
- **Port** — `:443` (HTTPS), `:80` implied by `http://`.
- **Protocol** — HTTP/HTTPS over TCP; DNS over UDP/53.
- **Socket / connection** — `net.DialTimeout` returns a `net.Conn`; `http.Client` manages a pool of them.
- **Client/server** — this tool is always the client.

---

## 12. Error Handling

| What can fail | Where | Why | Detected | Result |
|---|---|---|---|---|
| Unknown / malformed flag | `flag.Parse` | typo | `flag` internal | usage to stderr → **exit 2** |
| No mode / multiple modes | `main` | user error | `options == 0` / `> 1` | printed message → clean `return` (**exit 0**) |
| Invalid IP | `HandleIP` | bad `-i` | `net.ParseIP == nil` | returns `"Error: '...' is not a valid IP address"` (printed, exit 0) |
| ip-api unreachable / timeout | `GetIPInfo` | offline, DNS fail, slow | `client.Get` err | `GetIPInfo` returns err → `HandleIP` returns `"Error: failed to fetch IP data: ..."` |
| ip-api JSON invalid | `GetIPInfo` | API change / partial body | `json.Unmarshal` err | `"Error: failed to parse JSON: ..."` |
| ip-api `status != "success"` | `GetIPInfo` | reserved/private/invalid IP per the API | explicit check | `"Error: API error: fail"` |
| AbuseIPDB network error | `CheckAbuseDB` | offline | `client.Do` err | `("", err)` → report line `"- Abuse check failed: ..."` |
| AbuseIPDB `403`/`429` (bad key / rate limit) | `CheckAbuseDB` | key expired, quota | **not checked** — no status-code check | response has no `data` key → returns `"No reported abuse in last 90 days"` — a **false negative** |
| DNS lookup fails for a subdomain | `resolveSubdomain` | subdomain doesn't exist (normal) | `net.LookupHost` err | that label skipped; loop continues |
| `LookupCNAME` fails | `getCNAME` | no CNAME (normal) | err | returns `""` (treated as "no CNAME") |
| `:443` unreachable | `checkSSL` | no TLS service (normal) | `DialTimeout` err | `(false, "No SSL certificate")` |
| Wildcard DNS | `HandleDomain` | zone has `*` record | **not detected** | ~130 false-positive "subdomains" reported |
| usphonebook non-200 | `scrapeUSPhoneBookWithProxy` | anti-bot block (expected) | `resp.StatusCode != 200` | error `"HTTP error: N (blocked by anti-bot protection)"` → `HandleNameScraper` appends `getManualSearchLinks` |
| goquery finds nothing | `scrapeUSPhoneBookWithProxy` | wrong selectors / different markup | `len(contacts) == 0` | `HandleNameScraper` appends `getManualSearchLinks` |
| Name has non-letters / one word | `HandleNameScraper` | bad `-n` | `IsAllAlpha` / `len(parts) < 2` | `"Error: Name should contain only letters"` / `"Error: Please provide both first and last name"` |
| GitHub/Reddit API `403`/`404` | `enrichGitHub`/`enrichReddit` | rate limit / not found | `resp.StatusCode != 200` | returns `nil` → base "found" line prints without enrichment (silent) |
| Username platform blocks bots | `checkUsernameOnPlatform` | `403`/`429`/login redirect | `found` becomes `false` | that platform recorded as "not found" (**false negative**) |
| Output dir uncreatable / file unwritable | `SaveToFile` | permissions, path is a file | `os.MkdirAll`/`os.WriteFile` err | prints `"Error creating directory"` / `"Error saving file"` and `return` (exit 0) |
| `SaveAsPdf` dir already exists | `SaveAsPdf` | `os.Mkdir` (not `MkdirAll`) | err | prints error and `return` — but this function is never called |
| Stray debug output | `resolveSubdomain` | leftover `fmt.Println("ips =========> ", ips)` | — | pollutes stdout mixed with the report |
| Map-order nondeterminism | `HandleGenerateAndTestUsernames` | Go randomizes `map` iteration; candidates unsorted | — | "first 30 tested" differs each run |

**Recovery mechanisms.** None beyond "return a string that says what went wrong." No retries, no backoff, no fallback API. The design philosophy is "a handler always returns *a* report string" — even a one-line error — so `main` can always print something and exit `0`. Notable consequences:
- **Exit code is `0` for essentially every outcome** (only `flag` errors give `2`). A CI/script consumer can't detect failure by exit status.
- **AbuseIPDB failures can masquerade as "clean"** because there's no status-code check — arguably the most dangerous error-handling gap (a security tool reporting "no abuse" when it actually got rate-limited).
- **Username false negatives are silent** — a blocked platform looks identical to "user doesn't exist."
- **The committed key means "it works on my machine" hides a broken design** — if the key is ever revoked, every `-i` run silently reports "No reported abuse."

---

## 13. Security Analysis

`osint-master` performs only passive recon and needs no privileges. Its risk surface is **(1) a committed secret**, **(2) cleartext transport of investigation targets**, **(3) reliability/trust of its own output**, and **(4) the legal/ethical status of the lookups**.

### 13.1 Committed API key  *(Critical)*
- **Why the operation exists.** AbuseIPDB requires a key; the author wanted `-i` to include an abuse score out of the box.
- **What could go wrong.** The key is in `handleIP.go` and committed to git history. Anyone with repo access (or anyone the repo is ever shared/published to) can: exhaust its quota (DoS the feature for the owner), attribute their own lookups to the owner's account, or — depending on the plan — access the owner's AbuseIPDB dashboard/reporting identity. Rotating it requires a code change *and* history rewrite.
- **How the project should protect itself.** Read the key from an environment variable (`os.Getenv("ABUSEIPDB_API_KEY")`) or a gitignored `.env` via the already-declared `godotenv`; keep the `if apiKey == ""` graceful-degradation path (currently dead). The README already states this rule — the code violates its own guidance.

### 13.2 Cleartext transport of the investigation target  *(Medium)*
- **Why.** ip-api's free endpoint is `http://` only.
- **What could go wrong.** The request line `GET /json/<target-ip>` and the full geolocation response are visible to any on-path observer (ISP, Wi-Fi, corporate proxy). For an analyst investigating a sensitive IP, the *fact and subject* of the investigation leak. AbuseIPDB / GitHub / Reddit calls are HTTPS, but the AbuseIPDB URL still contains `?ipAddress=<target>` — protected in transit by TLS, but present in any local proxy/SSL-inspection logs.
- **How to protect.** Use ip-api's paid HTTPS endpoint, or a different provider with free HTTPS; at minimum, run over a VPN/Tor as the README's "develop in a VM" advice gestures toward.

### 13.3 Output trust / misleading labels  *(Medium — integrity of findings)*
- **`checkSSL` returns `"Valid SSL certificate (basic check)"` after only a TCP connect** — no TLS, no cert, no expiry. An analyst reading the report could wrongly conclude a subdomain has a valid certificate. **Fix:** actually `tls.DialWithDialer` and inspect `ConnectionState().PeerCertificates` (issuer, `NotAfter`, DNS SANs), or rename the field to "port 443 reachable."
- **`analyzeTakeoverRisk` `HIGH` is a heuristic, not a finding** — it never fetches the subdomain to confirm the dangling-resource fingerprint. Presenting it as "HIGH RISK SUBDOMAINS (Check for takeover)" is acceptable *if* the reader treats it as a lead; a careless reader might report it as confirmed.
- **`AbuseIPDB` errors silently become "No reported abuse"** (§12) — a false clean.
- **Username "found" is unreliable** (soft-404 false positives, bot-block false negatives) — a report line `[FOUND] Instagram: ...` may be wrong either way. Only GitHub/Reddit (with enrichment) are trustworthy.
- **Wildcard DNS** turns `-d` into ~130 false positives with no warning.

### 13.4 Scraping & ToS  *(Low–Medium — legal/operational)*
- `scrapeUSPhoneBookWithProxy` spoofs ~15 browser headers to defeat anti-bot protection on `usphonebook.com`. That's a Terms-of-Service violation for that site and, at scale/with the (stubbed) proxy rotation, edges toward the kind of automated access that draws legal attention. The README's ethics section says "Respect API Terms of Service" — the scraper is in tension with that. In practice it's usually blocked and the tool falls back to plain links, which is fine.
- The people-search capability itself aggregates PII (phone, address) about private individuals — the README flags GDPR/CCPA and "obtain consent"; the tool cannot enforce this.

### 13.5 Minor
- **Stray `fmt.Println` in `resolveSubdomain`** — pollutes machine-readable output.
- **No `context`/cancellation** — a slow `-d` can't be cleanly interrupted mid-scan except with Ctrl-C.
- **Unauthenticated GitHub API** — 60 req/hr; a big `-g` run gets throttled and enrichment silently stops.
- **`-o` path is unsanitized** — same-user arbitrary-file overwrite (`-o ~/.bashrc`), truncating. Bounded by the user's own permissions.

### 13.6 Trust boundaries
```
[user flags]      ── flag ──► mode + value          (the user's own machine)
[remote JSON/HTML]── http/json/goquery ──► structs/strings   ◄── external, attacker-influenceable content parsed into the report
[hard-coded key]  ── header ──► api.abuseipdb.com    ◄── a secret embedded in a distributable artifact
[-o path]         ── os.WriteFile ──► filesystem     ◄── unsanitized, user-permission-bounded
```
Remote responses are *rendered into the report verbatim* (`info.ISP`, `info.Org`, scraped text, GitHub `bio`). If the report is later viewed in a context that interprets markup/escape sequences (a terminal, a web page), hostile field content could inject control sequences — low severity, but worth noting.

### 13.7 Security assumptions
1. The AbuseIPDB key remains valid and private (violated by committing it).
2. The user is authorized to investigate the given IP / name / domain / username.
3. Report consumers understand `checkSSL`, takeover `HIGH`, and username "found" are heuristics, not verified facts.
4. Running over an acceptable network (the README suggests a VM; cleartext ip-api argues for a VPN).
5. Target sites' markup / anti-bot posture is out of the tool's control (the manual-links fallback is the real deliverable for `-n`).

### 13.8 Vulnerabilities supported by the code (no invention)
- **Hard-coded, committed AbuseIPDB API key** in `handleIP.go`. *Confirmed.*
- **Plaintext HTTP to `ip-api.com`** exposing the investigated IP and the geo response on-path. *Confirmed.*
- **`CheckAbuseDB` has no HTTP status check** → `403`/`429` silently reported as "No reported abuse in last 90 days." *Confirmed.*
- **`checkSSL` reports "Valid SSL certificate" after a TCP-only probe** — misleading integrity claim. *Confirmed.*
- **No wildcard-DNS detection** in `-d` → mass false-positive subdomains. *Confirmed.*
- **`-o` writes an unsanitized path in truncate mode** → same-user arbitrary-file overwrite. *Confirmed.*
- **Stray debug `fmt.Println`** in `resolveSubdomain` corrupts structured output. *Confirmed.*
- **Nondeterministic `-g`** (unsorted map iteration) tests a different candidate subset each run. *Confirmed.*

---

## 14. Data Flow

### 14.1 IP lookup
```
"8.8.8.8"  ── main ──► HandleIP
  isValidIP → net.ParseIP("8.8.8.8") != nil → true
  GetIPInfo:
     GET http://ip-api.com/json/8.8.8.8?fields=...   (plaintext)
     ← {"status":"success","country":"United States","regionName":"California","city":"Mountain View",
        "lat":37.4223,"lon":-122.0847,"isp":"Google LLC","org":"Google Public DNS","as":"AS15169 Google LLC"}
     json.Unmarshal → IPInfo{Status:"success", Country:"United States", Region:"California", City:"Mountain View",
                             Lat:37.4223, Lon:-122.0847, ISP:"Google LLC", Org:"Google Public DNS", AS:"AS15169 Google LLC"}
  build report sections (geo, network, links)
  CheckAbuseDB:
     GET https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90   (Key: <hard-coded>)
     ← {"data":{"abuseConfidenceScore":0,"totalReports":0,"lastReportedAt":null}}
     data.abuseConfidenceScore == 0 → "No reported abuse in last 90 days"
  append abuse line + tips
  ── return string ──► main prints ; if -o: SaveToFile(path, string)
```
Shape: `"8.8.8.8"` → validated → JSON bytes → `IPInfo` struct → concatenated report sections → one big `string` → stdout / file.

### 14.2 Username search
```
"@torvalds" ── main ──► HandleUsername
  strings.TrimPrefix(username, "@") → "torvalds"
  for each Platform in GetPlatforms():
     url := fmt.Sprintf(p.URL, "torvalds")               // e.g. "https://github.com/torvalds"
     HEAD url  → status
     found := status == 200 || 302
     if found && p.Name == "GitHub":
        GET https://api.github.com/users/torvalds
        ← {"bio":"...","followers":230000,"public_repos":7}
        Profile{Bio, Followers:230000, ActivityInfo:"7 public repos", Enriched:true}
  collect CheckResult{Found:true, ...} per platform
  formatResult each → "[FOUND] GitHub: https://github.com/torvalds\n    Bio: ...\n    Followers: 230000\n    Activity: 7 public repos\n"
  append "Total profiles found: N/8"
  ── return string ──► main
```
Shape: `"@torvalds"` → `"torvalds"` → per-platform `CheckResult` structs → formatted lines → one `string`.

### 14.3 Domain enumeration
```
"github.com" ── main ──► HandleDomain
  for sub in getSubdomainList():                          // ~130 labels
     fqdn := sub + "." + "github.com"                     // "api.github.com"
     ips, err := net.LookupHost(fqdn)                     // system DNS
     if err == nil && len(ips) > 0:
        cname := net.LookupCNAME(fqdn)                    // "" if none
        hasSSL, sslText := checkSSL(fqdn)                 // TCP :443 connect only
        risk, note := analyzeTakeoverRisk(fqdn, cname, ips)  // CNAME substring match
        append SubdomainInfo{fqdn, ips, cname, hasSSL, sslText, risk, note} block to the report
  append summary + HIGH-risk list + all-active list (*/+/- markers) + tips + crt.sh/SecurityTrails/DNSDumpster links + legal note
  ── return string ──► main
```
Shape: domain → 130 candidate FQDNs → (per hit) `[]ip` + CNAME + SSL-ish bool + risk tuple → `SubdomainInfo` → report blocks → one `string`.

### 14.4 Full-name search
```
"John Smith" ── main ──► HandleNameScraper
  strings.Fields → ["John","Smith"] → first="John", last="Smith"
  IsAllAlpha("John") && IsAllAlpha("Smith") → true
  scrapeUSPhoneBookWithProxy("John","Smith",""):
     GET https://www.usphonebook.com/search?first=John&last=Smith   (~15 spoofed headers)
     ← 403  →  error "HTTP error: 403 (blocked by anti-bot protection)"
  err != nil → output += "[ERROR] Scraping failed: ..." + getManualSearchLinks("John","Smith")
     → Whitepages/AnyWho/ZabaSearch/TruePeopleSearch URLs, LinkedIn/FB/Twitter/IG/GitHub search URLs,
       john.smith@gmail.com / johnsmith@gmail.com / ... , site:linkedin.com/in "John Smith" dork, PeopleDataLabs, legal note
  ── return string ──► main
```

---

## 15. Real Execution Example

### 15.1 `-i` (IP lookup)
```
$ ./osintmaster -i 8.8.8.8 -o output/ip.txt
IP Address: 8.8.8.8
==================================================

[INFO] Fetching geolocation and ISP data...

 GEOGRAPHIC INFORMATION:
  - Country: United States (US)
  - Region/State: California
  - City: Mountain View
  - Postal Code: 94043
  - Timezone: America/Los_Angeles
  - Coordinates: 37.4223, -122.0847

 NETWORK INFORMATION:
  - ISP: Google LLC
  - Organization: Google Public DNS
  - ASN: AS15169 Google LLC

🔍 ADDITIONAL INFORMATION:
  - Google Maps: https://www.google.com/maps?q=37.4223,-122.0847
  - IP Info: https://ipinfo.io/8.8.8.8
  - VirusTotal: https://www.virustotal.com/gui/ip-address/8.8.8.8

  ABUSE REPORT STATUS:
  - No reported abuse in last 90 days

==================================================
OSINT TIPS:
  - Check if this IP appears in data breach logs
  - Use Shodan to find open ports/services (shodan.io)
  - Check reverse DNS for domain associations
  - Search IP in threat intelligence feeds
Data saved in output/ip.txt
```
Internally: `net.ParseIP` ok → `GET http://ip-api.com/json/8.8.8.8` → JSON→`IPInfo` (`status=="success"`) → sections built → `GET https://api.abuseipdb.com/...` with the hard-coded `Key` header → `data.abuseConfidenceScore == 0` → "No reported abuse…" → `SaveToFile` `mkdir -p output` + write `0644`.

### 15.2 `-u` (username)
```
$ ./osintmaster -u torvalds
Checking username: torvalds
==================================================

Searching platforms...

[FOUND] GitHub: https://github.com/torvalds
    Bio: N/A
    Followers: 231544
    Activity: 7 public repos
[FOUND] Twitter: https://twitter.com/torvalds
[FOUND] Reddit: https://reddit.com/user/torvalds
    Bio: N/A
    Activity: 1234 total karma

==================================================
Total profiles found: 3/8
```
Internally: `HEAD` to each of 8 URLs; GitHub/Twitter/Reddit return `200`/`302`; GitHub → `GET api.github.com/users/torvalds` (followers, `7 public repos`); Reddit → `GET reddit.com/user/torvalds/about.json` (karma). Instagram/LinkedIn/Medium/GitLab/Pinterest either 404 or bot-blocked → recorded "not found" (some may be false negatives).

### 15.3 `-d` (domain) — abridged
```
$ ./osintmaster -d github.com
Main Domain: github.com
======================================================================

[INFO] Enumerating subdomains...

 CHECKING SUBDOMAINS:
----------------------------------------------------------------------
ips =========>  [140.82.121.6]                 # <-- stray debug print

✓ www.github.com
    IP Addresses: 140.82.121.4
    CNAME Record: github.com
    SSL: Valid SSL certificate (basic check)
      Risk: LOW - Direct IP mapping - takeover unlikely
ips =========>  [140.82.121.6]

✓ api.github.com
    IP Addresses: 140.82.121.6
    SSL: Valid SSL certificate (basic check)
      Risk: LOW - Direct IP mapping - takeover unlikely
...
[PROGRESS] Checked 50/135 subdomains...
...
======================================================================
ENUMERATION SUMMARY:
  Total subdomains checked: 135
  Active subdomains found: 6

 HIGH RISK SUBDOMAINS (Check for takeover):
  No high-risk subdomains detected

 ALL ACTIVE SUBDOMAINS:
  1. - www.github.com
  2. - api.github.com
  ...
======================================================================
 OSINT & RECOMMENDATIONS:
  1. For HIGH risk subdomains, verify if the external service still exists
  ...
	USEFUL RESOURCES:
  - SecurityTrails: https://securitytrails.com/domain/github.com
  - crt.sh: https://crt.sh/?q=%.github.com
  - DNSDumpster: https://dnsdumpster.com/domain/github.com

 LEGAL NOTE:
  Only scan domains you own or have explicit permission to test.
```
Internally: 135 sequential `net.LookupHost`; hits also do `LookupCNAME` + a 2 s `:443` `DialTimeout`; `analyzeTakeoverRisk` sees direct A records → `LOW`. Runtime is dominated by DNS timeouts for the ~129 non-existent labels.

### 15.4 `-n` (name) — typical (blocked) path
```
$ ./osintmaster -n "John Smith"
First name: John
Last name: Smith

[INFO] Attempting to scrape USPhoneBook.com...
[INFO] This may be blocked by anti-bot protection

[ERROR] Scraping failed: HTTP error: 403 (blocked by anti-bot protection)

MANUAL OSINT SEARCH LINKS:
================================

PHONE NUMBER DIRECTORIES:
  - USPhoneBook: https://www.usphonebook.com/search?first=John&last=Smith
  - Whitepages: https://www.whitepages.com/name/John-Smith
  ...
SOCIAL MEDIA SEARCH:
  - LinkedIn: https://www.linkedin.com/search/results/people/?keywords=John+Smith
  ...
EMAIL PATTERN GUESSING:
  - john.smith@gmail.com
  - johnsmith@gmail.com
  ...
GOOGLE DORKS (Advanced Search):
  - site:linkedin.com/in "John Smith"
  ...
LEGAL AND ETHICAL NOTE:
  - Always obtain consent before gathering personal information
  ...
```

### 15.5 `-g` (generate + test) — abridged
```
$ ./osintmaster -g "Linus Torvalds"
Full Name: Linus Torvalds
Generated 118 username variations
============================================================

Testing 30 most likely username variations on social platforms...
------------------------------------------------------------

[VALID] torvalds - Found on: GitHub, Twitter, Reddit
[VALID] linus - Found on: GitHub, Reddit

============================================================

SUMMARY:
  - Total username variations generated: 118
  - Usernames tested: 30
  - Valid usernames found: 2
  ...
```
Internally: `help.GenerateFromFullName("Linus Torvalds")` → a `map`-deduped, length-3–30 slice (**order random**); the first 30 (a different 30 each run) are each `HEAD`-tested on 8 platforms.

---

## 16. Why This Design?

- **Why one binary with mode flags instead of subcommands (`osintmaster ip 8.8.8.8`)?** Fewer moving parts for a small tool; `flag` alone suffices. *Alternative:* Cobra-style subcommands (per-mode help, no "exactly one" hack). Worth it if the tool grows.
- **Why "exactly one mode," enforced by counting non-empty strings?** The five modes produce unrelated reports; combining them has no meaning. Counting is the simplest check `flag` can't express. *Downside:* `-o` alone yields the "must provide one of…" message (slightly confusing) and there's no `--all`.
- **Why do handlers return a `string` instead of a struct?** The output is a human report, not machine data; a `string` keeps `main` trivial (print, save). *Downside:* no JSON/PDF/structured output without re-plumbing (the README lists JSON export as "future"), and `SaveAsPdf` can't reuse structure.
- **Why `HEAD` + `200/302` for username presence instead of per-platform APIs?** `HEAD` is fast, needs no keys, and works uniformly across 8 sites. *Downside:* unreliable (soft-404s, bot walls). Mitigation: enrich only GitHub/Reddit, which *do* have clean APIs — so the trustworthy signal is scoped, and the rest is "best effort."
- **Why brute-force DNS with a hard-coded wordlist for subdomains?** Zero dependencies, works offline-ish (needs a resolver), predictable. *Downside:* misses everything not in the list; no CT-log mining. Mitigation: the report links `crt.sh` as the manual next step.
- **Why a TCP-connect "SSL check" instead of a real TLS handshake?** Simplicity/speed (one `DialTimeout`, no cert plumbing). *This is the wrong trade-off* — it produces a misleading "Valid SSL certificate" label. A `tls.Dial` + cert inspection is only a few more lines and would give real data (issuer, expiry, SAN mismatch).
- **Why substring-match the CNAME for takeover risk instead of fetching the page?** Fast, no extra requests, no false "connection refused" noise. *Downside:* can't distinguish "dangling (takeoverable)" from "healthy third-party host" — hence `HIGH` means "check manually."
- **Why scrape usphonebook.com at all, given it's usually blocked?** To demonstrate the scraping technique and provide *some* automated path; the manual-links block is the reliable fallback and arguably the real feature.
- **Why hard-code the AbuseIPDB key?** Almost certainly expedience ("make it work now"). *This is the clear mistake* — `godotenv` is already a dependency and the `if apiKey == ""` branch already exists for the env-var path.
- **Why sequential (no goroutines) in `HandleDomain`?** Simplicity, and politeness toward the resolver / target. *Downside:* minutes-long runs. A bounded worker pool (like `pentest-kit`'s `HostMapper`) would cut this to seconds; the README lists "parallel request optimization" as future work.
- **Why `map[string]bool` in the generator?** O(1) dedupe as families overlap (`linus1` is produced twice). *Downside:* nondeterministic iteration → `-g`'s "first 30" is unstable; sorting the slice before truncation would fix it.
- **Why `strings.Join(parts[1:], " ")` for the last name?** Handles multi-word surnames (`"Ada Lovelace King"` → last `"Lovelace King"`). *Downside:* for `-g`, the generator then treats the whole thing as one token in some families.

---

## 17. Interview / Oral Defense Questions

### Beginner

**B1. What is OSINT and what does this tool do?** — Open Source Intelligence: gathering info from public sources without intrusive access. This tool bundles IP geolocation+abuse, username enumeration, DNS subdomain discovery+takeover risk, and name-based people search behind one CLI. *(README; `main.go`.)*

**B2. What are the five modes and their flags?** — `-i` IP, `-u` username, `-d` domain, `-n` full-name search, `-g` generate+test usernames. `-o` saves output. Exactly one mode is required. *(`main.go`.)*

**B3. Which API gives the IP geolocation, and over what protocol?** — `ip-api.com` (`GET http://ip-api.com/json/<ip>`), plain **HTTP** (the free tier has no HTTPS). *(`GetIPInfo`.)*

**B4. How does `-u` decide a username "exists" on a platform?** — It sends an HTTP `HEAD` to the profile URL and treats status `200` or `302` as "found." *(`checkUsernameOnPlatform`.)*

**B5. Which two platforms get extra profile detail, and why only those?** — GitHub (bio/followers/repos) and Reddit (karma) — they have clean, documented public JSON APIs, so their "exists" and profile data are reliable. *(`enrichGitHub`, `enrichReddit`.)*

**B6. How does `-d` find subdomains?** — Brute force: for each label in a hard-coded ~130-word list, `net.LookupHost("label.domain")`; a successful resolve = the subdomain exists. *(`getSubdomainList`, `resolveSubdomain`.)*

**B7. What is subdomain takeover, in one sentence?** — When a DNS record points to a deleted third-party resource (S3 bucket, GitHub Pages repo…) that an attacker can re-register to control your subdomain. *(`analyzeTakeoverRisk`.)*

**B8. What does the tool actually do when `-n` is "blocked"?** — It falls back to `getManualSearchLinks`: a printed list of people-search sites, social-media search URLs, email-pattern guesses, and Google dorks. *(`HandleNameScraper`.)*

**B9. Where does the output go?** — Always printed to stdout; with `-o file`, also written to that file (`SaveToFile` does `mkdir -p` then `os.WriteFile` at mode `0644`). *(`main.go`, `saveToFile.go`.)*

**B10. Name one third-party library and what it's for.** — `goquery`: jQuery-style HTML parsing/CSS selection, used to scrape usphonebook.com results. *(`handleName.go`.)*

### Intermediate

**I1. Walk `HandleIP` end to end.** — `isValidIP` (`net.ParseIP`) → `GetIPInfo` (`GET http://ip-api.com/json/<ip>?fields=...`, `json.Unmarshal` into `IPInfo`, check `status=="success"`) → build geographic + network sections (skipping empty fields) → append Google Maps / ipinfo / VirusTotal pivot links → `CheckAbuseDB` (`GET https://api.abuseipdb.com/...` with a `Key` header, decode `data`, summarize `abuseConfidenceScore`) → append tips. Returns the whole string. *(`handleIP.go`.)*

**I2. Why decode AbuseIPDB into `map[string]interface{}` but ip-api into a struct?** — ip-api's shape is stable and known, so a tagged struct is cleaner. `CheckAbuseDB` only needs three fields out of a larger, less-controlled response, so a generic map + type assertions (`data["abuseConfidenceScore"].(float64)`) is quicker to write. Trade-off: no compile-time safety, and JSON numbers come back as `float64`. *(`GetIPInfo` vs `CheckAbuseDB`.)*

**I3. What's wrong with `CheckAbuseDB`'s error handling?** — It never checks `resp.StatusCode`. A `403` (bad key) or `429` (rate limited) returns an error JSON with no `data` key; the `if data, ok := ...` fails and the function returns `"No reported abuse in last 90 days"` — a false clean. *(§12; `CheckAbuseDB`.)*

**I4. Why `HEAD` and not `GET` for the username check, and what still must you do with the response?** — `HEAD` returns status + headers with no body, so it's cheaper for a pure existence check. You must still `defer resp.Body.Close()` to release the connection back to the pool. *(`checkUsernameOnPlatform`.)*

**I5. Give two reasons the `200/302` username heuristic is unreliable.** — (1) Soft-404: some platforms return `200` with a "user not found" page → false positive. (2) Bot protection / login walls return `403`/`429`/redirect-to-`/login` for real users → false negative. *(§9; `checkUsernameOnPlatform`.)*

**I6. What does `checkSSL` verify, and what does its return string claim?** — It only does a 2 s `net.DialTimeout("tcp", host:443)` — a TCP connect. On success it returns `"Valid SSL certificate (basic check)"`, which overstates it: no TLS handshake, no certificate, no expiry check. *(`checkSSL`; §13.3.)*

**I7. How does `analyzeTakeoverRisk` classify, and what does `HIGH` really mean here?** — CNAME contains a known dangling-prone provider (`.s3.`, `.github.io`, `.herokuapp.com`, `.azurewebsites.net`, `.myshopify.com`, `.medium.com`, `.readme.io`) → `HIGH`; other external CNAME → `MEDIUM`; direct A record → `LOW`; nothing → `UNKNOWN`. `HIGH` = "worth manually checking for a dangling resource," not "confirmed takeover" (it never fetches the page). *(`analyzeTakeoverRisk`.)*

**I8. Why is `-g` nondeterministic?** — `help.GenerateAllUsernames` returns candidates from a `map[string]bool`; Go randomizes map iteration order and the slice is never sorted, so `HandleGenerateAndTestUsernames`'s "first 30" is a different 30 each run. *(`GenerateAllUsernames`; §12.)*

**I9. Why do all `http.Client`s set an explicit `Timeout`?** — Go's zero-value `http.Client` has no timeout; a hung server would block the CLI forever. Each handler sets one (10 s ip-api/AbuseIPDB, 8 s username, 5 s generate, 15 s scrape). *(§9; every handler.)*

**I10. What does `url.QueryEscape` protect against in `handleName.go`?** — It percent-encodes the first/last name before putting them in `?first=...&last=...`, so spaces/apostrophes/`&` don't break the query string or let a crafted name inject extra parameters. *(`scrapeUSPhoneBookWithProxy`, `getManualSearchLinks`.)*

### Advanced

**A1. The AbuseIPDB key is hard-coded. Lay out the full impact and the correct fix.** — Impact: it's in source and git history; anyone with repo access can burn the owner's quota (DoS the feature), attribute lookups to the owner's account, and — plan-dependent — reach the owner's dashboard/reporting identity; rotation needs a code change + history rewrite. Fix: `os.Getenv("ABUSEIPDB_API_KEY")` (or gitignored `.env` via the already-declared `godotenv`), keep the `if apiKey == ""` degradation path, purge the key from history and revoke it at AbuseIPDB. The README already mandates this. *(§13.1; `CheckAbuseDB`.)*

**A2. `-d` against a domain with wildcard DNS — what happens and how would you detect it?** — Every one of the ~130 labels resolves, so the tool reports ~130 "active subdomains," almost all false. Detect it by first resolving a random nonsense label (e.g. `zzq7f9x1k.<domain>`); if *that* resolves, the zone is wildcard and per-label resolution is meaningless — either abort with a warning or switch to CT-log enumeration only. *(§9 DNS; `HandleDomain`.)*

**A3. Make `checkSSL` actually meaningful. What would you implement?** — `tls.DialWithDialer(&net.Dialer{Timeout: 3*time.Second}, "tcp", host+":443", &tls.Config{ServerName: host})`; on success inspect `conn.ConnectionState().PeerCertificates[0]`: `Issuer`, `NotBefore`/`NotAfter` (compute days-to-expiry), `DNSNames` (SAN match against `host`), and whether the chain verified (or capture the verify error for self-signed/expired). Return those instead of a canned string; on TLS failure, report *why* (handshake error vs connection refused). *(§13.3; `checkSSL`.)*

**A4. `HandleDomain` is sequential over ~130 labels with DNS timeouts and 2 s `:443` dials. Redesign it.** — A bounded worker pool: a buffered `chan struct{}` semaphore (say 30), a `sync.WaitGroup`, one goroutine per label doing `LookupHost` (+ CNAME/SSL/risk on a hit), results appended under a `sync.Mutex` (or sent on a channel and collected). Add a `context.Context` with an overall deadline so the whole scan is cancellable. This is exactly the pattern `pentest-kit`'s `HostMapper`/`DirFinder` use. Expected speedup: minutes → a few seconds. *(§16; `HandleDomain`.)*

**A5. `CheckAbuseDB` decodes into `map[string]interface{}` and asserts `.(float64)`. What are the failure modes and how would a typed struct help?** — If a field is missing, the assertion yields `0`/`""` silently (could hide "the API changed"). If AbuseIPDB ever returns an integer as a JSON string, `.(float64)` fails silently. A typed struct with `json:"abuseConfidenceScore"` fields plus a `resp.StatusCode` check would surface schema drift at decode time and let you distinguish "0% confidence" from "we never got data." *(§9 JSON; `CheckAbuseDB`.)*

**A6. The username-presence check follows redirects by default. Why is that a problem and what would you change?** — Many platforms `301`/`302` a missing (or bot-flagged) profile to `/login` or a homepage that returns `200`; the default `http.Client` follows the redirect and the final `200` is counted as "found" → false positive. Set `client.CheckRedirect = func(...) error { return http.ErrUseLastResponse }` and classify on the *first* response's status (treat `301/302` to a login path as "not found" or "unknown"). *(`checkUsernameOnPlatform`; §9.)*

**A7. What are the privacy and legal exposures of the `-n` capability, and where does the code acknowledge them?** — It aggregates PII (phone, home address) about private individuals and, via the scraper, defeats a site's anti-bot protection (ToS violation). GDPR/CCPA constrain collecting/processing personal data without a lawful basis; scraping at scale can also draw CFAA-style claims. The code acknowledges it in `getManualSearchLinks`' "LEGAL AND ETHICAL NOTE" and the README's ethics section — but nothing is *enforced*; the safeguard is procedural (only investigate with authorization/consent). *(§13.4; `handleName.go`; README.)*

**A8. `ip-api.com` is called over HTTP. Draw the exposure and give two mitigations.** — On-path observers (ISP, café Wi-Fi, corporate SSL-inspection proxy) see `GET /json/<target-ip>` and the full geo/ISP response in cleartext — leaking *that* you're investigating and *which IP*. Mitigations: (1) switch to ip-api's paid HTTPS endpoint or a provider with free HTTPS (e.g. ipwho.is, ipapi.co); (2) run the tool through a VPN/Tor (aligns with the README's "develop in a VM" isolation stance). *(§13.2; `GetIPInfo`.)*

**A9. `SaveAsPdf` uses `os.Mkdir` while `SaveToFile` uses `os.MkdirAll`, and `SaveAsPdf` is never called. Assess.** — `os.Mkdir` fails if any parent is missing *or* if the directory already exists, so `SaveAsPdf` would error on the common cases `SaveToFile` handles. Combined with it being unwired (`main` only calls `SaveToFile`) and `gofpdf` being archived upstream (the maintained `go-pdf/fpdf` is declared but unused), this is dead, half-finished code. Fix: wire a `--pdf` flag, switch to `os.MkdirAll` and `go-pdf/fpdf`, or delete it. *(`saveToFile.go`; §10.)*

**A10. Two near-duplicate username-from-name functions exist. Which is wired in, what's the difference, and what would you do?** — `main` dispatches `-g` to `HandleGenerateAndTestUsernames` (tests first 30, lists names found on ≥1 platform, prints a summary). `HandleUsernameFromName` (tests first 20, groups by username, different formatting) and `help.GenerateUsernameReport` (formats candidates *without* testing) are unused. Consolidate into one function parameterized by "how many to test" and "generate-only vs test," delete the rest. *(`handleUsername.go`, `help/help.go`; §2.)*

---

## 18. "Explain This Code to an Interviewer"

**The whole tool.**
> "It's a Go OSINT CLI with five mutually-exclusive modes selected by flags. `main` enforces exactly one of `-i`, `-u`, `-d`, `-n`, `-g`, then a conditionless switch calls one handler in the `handlers` package; each handler builds one big human-readable report string, which `main` prints and optionally writes to a file with `-o`. `-i` calls ip-api.com for geolocation/ISP/ASN and AbuseIPDB for an abuse score. `-u` sends an HTTP HEAD to eight social platforms' profile URLs and treats 200 or 302 as 'exists', then enriches GitHub and Reddit via their public JSON APIs because those are the only reliable ones. `-d` brute-forces DNS over a 130-label wordlist, grabs CNAMEs, TCP-probes port 443, and flags CNAMEs pointing at S3/GitHub Pages/Heroku/etc. as possible subdomain takeovers. `-n` tries to scrape a people-search site with spoofed browser headers via goquery and, when blocked, prints a big block of manual OSINT links. `-g` generates dozens of username permutations from a name and runs them through the same HEAD check."

**`HandleIP` / the two APIs.**
> "`isValidIP` uses `net.ParseIP`. `GetIPInfo` does a plain-HTTP GET to ip-api with a `fields=` filter, unmarshals into a tagged `IPInfo` struct, and errors out if `status != "success"`. `CheckAbuseDB` builds a request with `http.NewRequest` so it can set the `Key` header, decodes the response into a generic `map[string]interface{}`, and pulls `abuseConfidenceScore`/`totalReports`/`lastReportedAt` with type assertions. I'd flag two problems: the AbuseIPDB key is hard-coded in the source, and `CheckAbuseDB` never checks the HTTP status, so a 403 or 429 silently reports 'No reported abuse'."

**The username check.**
> "`checkUsernameOnPlatform` formats the platform's URL template with the username, sends a HEAD with a spoofed browser User-Agent, and sets `found` from status 200 or 302. It only enriches GitHub and Reddit — via `api.github.com/users/<u>` and `reddit.com/user/<u>/about.json` — because the HEAD heuristic is unreliable for the others: some sites 200 a 'not found' page, others 403 real users behind a bot wall. So the trustworthy signal is deliberately scoped to two platforms."

**The domain enumeration.**
> "For each of ~130 hard-coded labels it does `net.LookupHost('label.domain')`; a resolve means the subdomain exists. Hits also get `net.LookupCNAME`, a 2-second TCP dial to :443, and a takeover-risk classification that substring-matches the CNAME against known dangling-prone providers. Weaknesses I'd call out: it's fully sequential so it can take minutes; the 'SSL check' is only a TCP connect but the report says 'Valid SSL certificate'; and it doesn't detect wildcard DNS, which would produce ~130 false positives."

**What I'd fix first.**
> "Move the AbuseIPDB key to an env var (the `godotenv` dependency is already there); add HTTP status checks to every API call; make `checkSSL` do a real TLS handshake and read the cert; parallelize `HandleDomain` with a worker pool and a context deadline; sort the generated username slice so `-g` is deterministic; and remove the stray `fmt.Println` in `resolveSubdomain`."

---

## 19. Common Mistakes

1. **Trusting the `-u` "found/not found" verdict.** Only GitHub/Reddit (the enriched ones) are reliable; the rest have false positives (soft-404) and false negatives (bot walls).
2. **Reading "Valid SSL certificate (basic check)" as a real certificate check.** It only means "something accepted a TCP connection on port 443."
3. **Treating a `-d` `HIGH` risk as a confirmed takeover.** It's a CNAME-pattern lead; you still have to fetch the subdomain and look for the dangling-resource fingerprint.
4. **Assuming `-d` found *all* subdomains.** Only labels in the hard-coded list are tried; use `crt.sh` (linked in the report) for CT-log coverage.
5. **Running `-d` on a wildcard-DNS domain.** Every label "resolves" → a report full of phantom subdomains.
6. **Expecting `-g` to test the same usernames every run.** Map iteration is randomized and the slice isn't sorted.
7. **Relying on the exit code.** It's `0` for almost every outcome, including handled errors; only bad flags give `2`.
8. **Believing "No reported abuse" from `-i`.** If the AbuseIPDB key is revoked or rate-limited, that line appears anyway (no status check).
9. **Committing the AbuseIPDB key / shipping this repo as-is.** The key in `handleIP.go` is live and in history.
10. **Running `-i` on a sensitive target over an untrusted network.** ip-api is plain HTTP — the investigated IP leaks on-path.
11. **Piping `-d` output to another program.** The stray `ips =========>` debug lines corrupt it.
12. **Expecting `-n` to return data.** usphonebook.com almost always blocks it; the manual-links block is the real output.
13. **Assuming `SaveAsPdf` works** (via some flag). It's unwired, uses `os.Mkdir` not `MkdirAll`, and `gofpdf` is archived.
14. **`-o` with a path you care about.** No sanitization, truncate mode — `-o notes.txt` overwrites `notes.txt`.

---

## 20. Final Project Summary

### What I MUST understand
1. **The dispatcher** — `flag` → "exactly one of five modes" → conditionless `switch` → a handler that returns one report `string` → print + optional `SaveToFile`.
2. **`-i`** — ip-api.com (plain HTTP, JSON→struct, `status` check) + AbuseIPDB (HTTPS, `Key` header, generic-map decode) — and the **hard-coded key** + **missing status check**.
3. **`-u`** — HTTP `HEAD` + `200/302` heuristic across 8 platforms; enrichment (the reliable signal) limited to GitHub/Reddit via their JSON APIs.
4. **`-d`** — brute-force DNS over a ~130-label wordlist + `LookupCNAME` + a **TCP-only `:443` probe mislabeled "SSL"** + CNAME-substring **takeover-risk** classification; sequential (slow); no wildcard detection.
5. **`-n`** — spoofed-header `goquery` scrape of usphonebook.com (usually blocked) → big **manual-links fallback**.
6. **`-g`** — `help` permutation generator (`map` dedupe, length 3–30, **nondeterministic order**) → the same `HEAD` check on the first 30.
7. **The concepts** — OSINT/passive recon, REST/JSON + struct tags, `http.Client`/timeouts/`HEAD`, status-code heuristics, DNS A/CNAME/brute force/wildcard, subdomain takeover, TCP-connect vs TLS handshake, `goquery`/CSS/anti-bot, UA spoofing, API keys & secrets, rate limiting.
8. **The defects** — committed key, cleartext ip-api, no status checks (false "clean"/"not found"), misleading "Valid SSL certificate", no wildcard detection, stray debug print, unsorted `-g`, dead `SaveAsPdf`/`HandleUsernameFromName`/`GenerateUsernameReport`, unused `godotenv`/`go-pdf/fpdf`.

### Architecture in 30 seconds
> "A Go OSINT CLI, one binary, five mutually-exclusive modes: `-i` (ip-api geolocation + AbuseIPDB abuse score), `-u` (HTTP HEAD to 8 social platforms + GitHub/Reddit API enrichment), `-d` (brute-force DNS subdomains + CNAME + :443 probe + takeover-risk guess), `-n` (scrape a people-search site, fall back to manual links), `-g` (generate username permutations from a name and test them). Each handler returns a text report that `main` prints and, with `-o`, saves. No database, no concurrency, one committed API key that shouldn't be there."

### Architecture in 2 minutes
> "`main.go` registers six `flag.String`s, installs a custom usage banner, intercepts `--help`, enforces that exactly one of `-n/-i/-u/-g/-d` is set (by counting non-empty values), and a conditionless `switch` calls one handler in `handlers/`. `HandleIP` validates with `net.ParseIP`, GETs `http://ip-api.com/json/<ip>` (plain HTTP) into a JSON-tagged `IPInfo` struct, checks `status=="success"`, formats geographic and network sections plus Maps/ipinfo/VirusTotal pivot links, then `CheckAbuseDB` GETs `https://api.abuseipdb.com/api/v2/check` with a hard-coded `Key` header, decodes into `map[string]interface{}`, and summarizes `abuseConfidenceScore` — but never checks the HTTP status, so a 403/429 reports 'No reported abuse'. `HandleUsername` strips a leading `@` and, for each of 8 `Platform{Name,URL,Category}` entries, sends an HTTP `HEAD` with a spoofed browser UA and treats 200/302 as 'found'; for GitHub and Reddit (the only platforms with clean public APIs) it enriches via `api.github.com/users/<u>` and `reddit.com/user/<u>/about.json`. `HandleDomain` loops a hard-coded ~130-label wordlist, `net.LookupHost`ing `label.domain`; each hit also runs `net.LookupCNAME`, a 2-second TCP dial to `:443` (returned, misleadingly, as 'Valid SSL certificate (basic check)'), and `analyzeTakeoverRisk`, which substring-matches the CNAME target against S3/GitHub Pages/Heroku/Azure/Shopify/Medium/ReadMe.io to assign HIGH/MEDIUM/LOW/UNKNOWN; it's fully sequential (slow) and doesn't detect wildcard DNS. `HandleNameScraper` splits the name, validates letters-only, and `scrapeUSPhoneBookWithProxy` GETs usphonebook.com with ~15 spoofed Chrome headers, parsing results with `goquery` by guessing five CSS selectors — usually blocked (403), so `HandleNameScraper` appends `getManualSearchLinks` (people-search sites, social search URLs, email-pattern guesses, Google dorks, a legal note). `HandleGenerateAndTestUsernames` calls `help.GenerateFromFullName`, which builds a `map[string]bool` of permutations (first/last/initials × separators × suffixes/prefixes/truncations), filters to length 3–30, and returns a slice in random map order; the first 30 are `HEAD`-tested across the 8 platforms. `main` prints the returned string and, with `-o`, calls `SaveToFile` (`os.MkdirAll` + `os.WriteFile 0644`). Third-party deps: `goquery`(+`cascadia`+`x/net`) for scraping, `gofpdf` for an unwired `SaveAsPdf`, plus declared-but-unused `go-pdf/fpdf` and `godotenv`."

### Deep technical explanation
See §6 (each handler dissected), §9 (every concept in TERM form), §11 (HTTP/DNS/TCP layered), §12 (the full failure table and the "always exit 0 / silent false-clean" gaps), §13 (committed key, cleartext ip-api, misleading SSL label, wildcard DNS, `-o` overwrite, ToS/PII exposure). §14 traces the four data journeys; §15 shows real runs of all five modes.

### Most important functions
| Function | Role |
|---|---|
| `main.main` | Flag parse, "one mode" rule, `switch` dispatch, print, optional save |
| `handlers.GetIPInfo` | GET ip-api.com → `IPInfo` struct (status check) |
| `handlers.CheckAbuseDB` | GET AbuseIPDB (hard-coded key) → abuse summary (no status check) |
| `handlers.HandleIP` | Validate + fetch + format the IP report |
| `handlers.checkUsernameOnPlatform` | HEAD + 200/302 heuristic; GitHub/Reddit enrichment |
| `handlers.HandleUsername` | Loop 8 platforms, collect "found", format |
| `handlers.HandleDomain` | Brute-force DNS + CNAME + :443 + takeover-risk report |
| `handlers.analyzeTakeoverRisk` | CNAME-substring → HIGH/MEDIUM/LOW/UNKNOWN |
| `handlers.checkSSL` | TCP-connect to :443 (mislabeled "SSL") |
| `handlers.scrapeUSPhoneBookWithProxy` | Spoofed-header `goquery` scrape of usphonebook.com |
| `handlers.HandleNameScraper` | Scrape → fallback to `getManualSearchLinks` |
| `help.GenerateAllUsernames` / `GenerateFromFullName` | Username permutation generator (map dedupe, length filter) |
| `handlers.HandleGenerateAndTestUsernames` | Generate + `HEAD`-test the first 30 |
| `handlers.SaveToFile` | `mkdir -p` + write the report |

### Most important concepts
OSINT / passive reconnaissance · REST APIs, JSON, `encoding/json` struct tags vs `map[string]interface{}` + type assertions · `net/http.Client`, `Timeout`, `HEAD` vs `GET`, `resp.Body.Close()` · HTTP status codes as an (unreliable) existence signal · DNS A/AAAA vs CNAME, resolver, brute-force subdomain enumeration, wildcard DNS · subdomain takeover · TCP-connect probe vs TLS handshake / X.509 certificate validation · HTML scraping, `goquery`, CSS selectors, anti-bot protection · User-Agent / `Sec-*` header spoofing · API keys & secrets management (env vars / `.env` / never commit) · API rate limiting · Go `flag`, conditionless `switch`, `map` as a set, `net.ParseIP`, `url.QueryEscape`.
