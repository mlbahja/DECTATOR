# `defuse` — Complete Technical Documentation

> Windows malware mitigation / eradication CLI, written in Go.
> Packages: `main`, `config`, `proc`, `netinfo`, `persist`, `cleaner`, `verify`
> Audience: technical interview / code review / oral defense preparation.

---

## 1. Project Overview

### Simple explanation

Imagine a burglar got into your house. To be *sure* they're gone you must do four things, in the right order:

1. **Find the burglar** and every accomplice they brought.
2. **Remove them all** — kids first, then the adult who could otherwise call them back.
3. **Change the locks and remove the spare keys they hid** — the notes telling the front door to open automatically next morning.
4. **Throw out the tools they left**, then **walk the house again** to confirm nobody and nothing suspicious remains.

`defuse` does exactly this for a piece of Windows malware. You give it the malware's process name. It:

- finds the running malware process **and its child processes**,
- kills them (children first, so a "watchdog" process can't restart the parent),
- deletes the malware's **auto-start entries** from the Windows Registry and from the **Startup folders**,
- deletes the malware's **files** from disk (and the folder it lived in, if that folder is now empty),
- records any **attacker IP addresses** it can see (live network connections + IP-looking strings inside the malware file),
- and finally **re-checks** the machine and prints `CLEAN` or `INCOMPLETE`.

It also has a **`-dry-run` mode** that does all the finding and reporting but changes nothing.

### Technical explanation

`defuse` is a single-binary, single-purpose **incident-response eradication tool** for Windows, written in Go, linking `golang.org/x/sys/windows` for direct Win32 API access. It performs, in a deliberately fixed order:

| Phase | Mechanism | Win32 / OS primitive |
|---|---|---|
| Process discovery | `proc.List`, `proc.FindMatching` | `CreateToolhelp32Snapshot` + `Process32First/Next` |
| Executable path resolution | `proc.ExePath` | `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `QueryFullProcessImageName` |
| Process-tree expansion | `proc.KillOrder` | in-memory PPID graph walk (post-order DFS) |
| Termination | `proc.Kill` | `OpenProcess(PROCESS_TERMINATE)` + `TerminateProcess` |
| Live C2 discovery | `netinfo.LiveEndpoints` | `GetExtendedTcpTable` (from `iphlpapi.dll`), filtered by owning PID |
| Static C2 discovery | `netinfo.ScanFileForIPv4` | regex over the raw executable bytes |
| Registry persistence | `persist.FindRegistryPersistence` / `RemoveRegistryPersistence` | `x/sys/windows/registry` — Run / RunOnce under HKCU and HKLM |
| Startup-folder persistence | `persist.FindStartupPersistence` / `RemoveStartupPersistence` | `os.ReadDir` + `os.Remove` on the per-user and machine Startup folders |
| File cleanup | `cleaner.DeleteFile`, `cleaner.DeleteEmptyMalwareDir` | `os.Stat`, `os.Remove` (with retry), guarded by a `C:\Windows` allow-list |
| Verification | `verify.Run` | re-runs process + registry discovery, compares to zero |

**Problem it solves.** Manual malware removal is error-prone and racy. An analyst using Task Manager + `regedit` + Explorer can: kill the parent but miss a watchdog that respawns it; delete the file but leave the Run key so it re-downloads at next logon; delete the Run key while the process is still alive so the process rewrites it a millisecond later. `defuse` encodes the *correct order* and *correct completeness* into a tool, then proves the result.

**Main objective.** Given one process name, leave the machine in a state where (a) no process with that name is running, (b) no Run/RunOnce value referencing it remains, (c) its executable and dedicated folder are gone, and (d) that state is *verified*, not assumed — while never damaging the OS.

**Who uses it.** Incident responders / SOC analysts / malware-analysis students on an **isolated VM** (host-only networking, Defender disabled, clean snapshot), run from an **Administrator** prompt.

**Technologies / libraries.**
- **Language:** Go (`go 1.25.0`).
- **Only external dependency:** `golang.org/x/sys v0.47.0` (sub-packages `golang.org/x/sys/windows`, `golang.org/x/sys/windows/registry`).
- **Standard library:** `flag`, `fmt`, `os`, `path/filepath`, `strings`, `time`, `regexp`, `encoding/binary`, `unsafe`.
- **OS surface:** Win32 process/toolhelp APIs, the Windows Registry, `iphlpapi.dll`'s TCP table, NTFS, the Windows access-token / UAC elevation model.

**Main features.**
1. Normalized name matching — `maltrack`, `Mal-Track`, `MALTRACK.EXE`, `mal-track.exe` all match.
2. Full process-tree kill, deepest child first.
3. Persistence removal from four registry keys (HKCU/HKLM × Run/RunOnce) and two Startup folders.
4. Two independent attacker-IP discovery methods (live sockets + static byte scan).
5. `-dry-run` (report only) and `-verbose` (dump every value scanned).
6. Two safety guards: a `C:\Windows` deletion allow-list, and single-level-only folder deletion.
7. Post-run verification with a non-zero process exit code on incomplete cleanup.
8. Every failure logged (`[warn]` / `[fail]`), execution continues — no silent "success".

---

## 2. Project Architecture

### 2.1 Runtime / data-flow view

```
                          Administrator PowerShell
                                    │  defuse.exe -target maltrack [-dry-run] [-verbose]
                                    ▼
                          ┌───────────────────┐
                          │      main.go       │  flag parsing • elevation check • ORCHESTRATION
                          │      (package main)│  owns the fixed 9-step order
                          └───────┬───────────┘
        ┌───────────────┬─────────┼──────────┬───────────────┬──────────────┐
        ▼               ▼         ▼          ▼               ▼              ▼
   ┌─────────┐    ┌──────────┐ ┌────────┐ ┌──────────┐  ┌──────────┐  ┌──────────┐
   │ config  │    │  proc    │ │netinfo │ │ persist  │  │ cleaner  │  │  verify  │
   │ key     │◄───┤discovery │ │live TCP│ │Run/RunOnce│ │file +    │  │re-check +│
   │ paths,  │    │+ tree +  │ │table + │ │+ Startup  │ │dir delete│  │summary   │
   │ folders,│    │terminate │ │IP regex│ │find+remove│ │+ guards  │  │print     │
   │ timings │    │          │ │        │ │          │  │          │  │          │
   └─────────┘    └────┬─────┘ └───┬────┘ └────┬─────┘  └────┬─────┘  └────┬─────┘
        ▲              │           │           │  (imports proc.Normalize)  │
        │ imported by  │           │           │            │      (imports proc + persist)
        └──────────────┴───────────┴───────────┴────────────┴───────────────┘
                                    │
                                    ▼   Win32 / OS layer
   ┌───────────────────────────────────────────────────────────────────────────────┐
   │ kernel32:  CreateToolhelp32Snapshot, Process32First/Next, OpenProcess,         │
   │            TerminateProcess, QueryFullProcessImageName, CloseHandle            │
   │ iphlpapi:  GetExtendedTcpTable            registry hive: RegOpenKey,           │
   │            RegEnumValue, RegQueryValueEx, RegDeleteValue                       │
   │ NTFS:      stat / unlink / readdir / chmod (via Go os.*)                       │
   │ token:     GetTokenInformation(TokenElevation)  (UAC / elevation)             │
   └───────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                    stdout report  +  process exit code (0 clean / 1 incomplete / 2 usage)
```

### 2.2 Package-dependency view (compile-time `import` graph)

```
main ──► config
main ──► proc            proc ──► golang.org/x/sys/windows
main ──► netinfo         netinfo ──► golang.org/x/sys/windows   (+ encoding/binary, regexp, unsafe)
main ──► persist         persist ──► config
main ──► cleaner         persist ──► proc          (uses proc.Normalize)
main ──► verify          persist ──► golang.org/x/sys/windows/registry
main ──► golang.org/x/sys/windows   (checkElevation only)
                         cleaner ──► config       (WindowsDir, retry constants)
                         config  ──► golang.org/x/sys/windows/registry   (registry.Key type)
                         verify  ──► proc, persist (re-runs their discovery)
```

**Observations:**
- The graph is a **DAG** — no import cycles. `config` is a leaf; `proc` a near-leaf; `persist` on `config`+`proc`; `verify` on `proc`+`persist`; `main` on everything.
- **`proc.Normalize` is the single source of truth for "does this name match the target."** `persist` imports `proc` *only* for `Normalize`.
- **No shared mutable state, no concurrency.** Every phase runs sequentially in `main`. The `netinfo.TCPTableSource` interface exists as a *test seam*, not for concurrency.
- **Every package is Windows-only.** Building requires `GOOS=windows go build`.

### 2.3 Component-by-component

**`main` (`main.go`)** — the orchestrator. Parses three flags, checks elevation, executes the nine-step pipeline in a fixed order. Private helpers are glue only: `gatherExePaths`, `addStartupPaths`, `addPath` (path de-dup), `collectAttackerIPs`, and four "do X per hit, count successes" loops (`killProcesses`, `removeRegistryHits`, `removeStartupHits`, `deleteFiles`). Touches the OS directly only in `checkElevation`.

**`config`** — pure configuration, no behavior. Exposes `RegistryLocations()` (4 hive+path tuples), `StartupFolders()` (2 folder paths from `%APPDATA%` / `%ProgramData%`), `WindowsDir()` (`%SystemRoot%` or `C:\Windows`), and 3 timing constants (`FileDeleteAttempts=5`, `FileDeleteRetryDelay=300ms`, `KillSettleDelay=250ms`). Exists so persistence locations and timing are editable data in one place.

**`proc`** — everything about processes. `Process` struct (`PID`, `PPID`, `Name`, `ExePath`); `Normalize`, `List`, `ExePath`, `FindMatching`, `KillOrder`, `Kill`. Consumes `x/sys/windows`. Consumed by `main`, `persist` (only `Normalize`), `verify` (`FindMatching`).

**`netinfo`** — attacker-IP intelligence, two ways. `Endpoint` struct (`PID`, `IP`, `Port`); `LiveEndpoints(pids)` reads the kernel TCP table via `GetExtendedTcpTable`; `ScanFileForIPv4(path)` regex-matches dotted-quad IPv4 in a file's bytes. `TCPTableSource` interface + package var `Source` = a dependency-injection seam so `parseTCPTable` can be unit-tested against a hand-built buffer. Consumes `x/sys/windows`, `encoding/binary`, `regexp`, `unsafe`. Consumed by `main`.

**`persist`** — persistence: find *and* remove, side by side, for both mechanisms. `RegistryHit` / `StartupHit` structs; `FindRegistryPersistence` / `RemoveRegistryPersistence`; `FindStartupPersistence` / `RemoveStartupPersistence`; `DebugDump` (verbose). Helpers `matchesTarget`, `extractExePath`. Consumes `config`, `proc`, `x/sys/windows/registry`. Consumed by `main`, `verify`.

**`cleaner`** — file/dir deletion with guards. `IsProtected(path)` (under `WindowsDir()`?); `DeleteFile(path)` (refuse if protected, else `os.Remove` × 5 retries × 300 ms); `DeleteEmptyMalwareDir(exePath)` (remove the exe's *immediate* parent, only if now empty, never recursing upward). Consumes `config`. Consumed by `main`.

**`verify`** — `Summary` struct (target, dry-run flag, attacker IPs, four counters); `Run(summary)` prints the summary, and if not dry-run re-runs `proc.FindMatching` + `persist.FindRegistryPersistence`, printing `CLEAN` iff both empty and returning that bool (→ `main` exit code). Consumes `proc`, `persist`.

**External services / databases:** none. `defuse` makes no outbound connections; it only *reads* the local TCP table and local files. The C2 address is recorded, never contacted.

---

## 3. Project File Structure

```
defuse/
├── go.mod                 module name, Go version, single dependency
├── go.sum                 dependency checksums (supply-chain integrity)
├── .gitignore
├── README.md              full lab write-up + design rationale + report templates
├── main.go                package main — entry point + orchestration
├── config/config.go       package config — registry paths, folders, timings
├── proc/proc.go           package proc — process discovery / tree / kill
├── netinfo/netinfo.go     package netinfo — live TCP table + static IPv4 scan
├── persist/persist.go     package persist — Run/RunOnce + Startup, find & remove
├── cleaner/cleaner.go     package cleaner — file/dir deletion + safety guards
└── verify/verify.go       package verify — post-run re-check + summary printing
```

### `go.mod`
```
module defuse
go 1.25.0
require golang.org/x/sys v0.47.0
```
- **Purpose.** Declares the module path (`defuse` — why internal imports read `"defuse/proc"`), language version, and the one external dependency.
- **Why.** Without it the `defuse/...` import paths don't resolve and `x/sys` isn't pinned.
- **Depended on by.** The Go toolchain, every build.

### `go.sum`
Cryptographic checksums for `golang.org/x/sys`. `go build` refuses a downloaded module whose hash doesn't match — a tampered mirror can't inject modified `x/sys`. Not human-edited.

### `README.md`
Not code but load-bearing for a defense: build/run commands, the package table, the **nine-step flow with ordering rationale** ("Step 5 must come before steps 6–7"), the "found with / removed with" mechanism table, the two safety guards, lab-isolation setup, a walk-through with `«PLACEHOLDERS»`, remediation advice, templated report emails.

### `main.go` — `package main`
- **Purpose.** Entry point; the *only* place execution order is defined.
- **Imports.** `flag`, `fmt`, `os`, `path/filepath`, `strings`, `time`; `golang.org/x/sys/windows` (elevation check only); all six local packages.
- **Exposes.** `func main()`. Everything else unexported glue.
- **Input.** `os.Args`, environment (via `config`), live machine state.
- **Output.** Formatted stdout report; machine side effects; exit code `0` / `1` / `2`.

### `config/config.go` — `package config`
- **Purpose.** Central constants: *where* persistence lives, *how long* to wait around timing-sensitive ops.
- **Imports.** `os`, `path/filepath`, `time`, `golang.org/x/sys/windows/registry` (for the `registry.Key` type).
- **Exposes.** `RegistryLocation{Hive, HiveName, Path}`; `RegistryLocations()`, `StartupFolders()`, `WindowsDir()`; `FileDeleteAttempts`, `FileDeleteRetryDelay`, `KillSettleDelay`.
- **Input.** Env vars `APPDATA`, `ProgramData`, `SystemRoot`. **Output.** Path slices / a dir string / duration constants.

### `proc/proc.go` — `package proc`
- **Purpose.** All process ops: enumerate, resolve image path, build kill tree, terminate.
- **Imports.** `fmt`, `strings`, `unsafe`, `golang.org/x/sys/windows`.
- **Exposes.** `Process{PID, PPID uint32; Name, ExePath string}`; `Normalize`, `List`, `ExePath`, `FindMatching`, `KillOrder`, `Kill`.
- **Input.** Target name string; the live process table. **Output.** `[]Process`, image-path strings, errors; the side effect of `Kill`.

### `netinfo/netinfo.go` — `package netinfo`
- **Purpose.** Discover attacker IPs two independent ways.
- **Imports.** `encoding/binary`, `fmt`, `os`, `regexp`, `unsafe`, `golang.org/x/sys/windows`.
- **Exposes.** `Endpoint{PID uint32; IP string; Port uint16}`; `TCPTableSource{Read() ([]Endpoint, error)}`; `Source`; `LiveEndpoints`, `ScanFileForIPv4`.
- **Input.** A set of PIDs; a filesystem path. **Output.** `[]Endpoint` / `[]string` / error.

### `persist/persist.go` — `package persist`
- **Purpose.** Find and remove both persistence mechanisms.
- **Imports.** `fmt`, `os`, `path/filepath`, `strings`, `golang.org/x/sys/windows/registry`, `defuse/config`, `defuse/proc`.
- **Exposes.** `RegistryHit{Hive, HiveName, Path, Name, Value}` (+ method `ExePath()`), `StartupHit{Path}`; `DebugDump`, `FindRegistryPersistence`, `RemoveRegistryPersistence`, `FindStartupPersistence`, `RemoveStartupPersistence`.
- **Input.** Target name; the registry; the Startup folders. **Output.** hit slices; side effects (deleted value/file).

### `cleaner/cleaner.go` — `package cleaner`
- **Purpose.** Delete files and (one level of) directories, with guards.
- **Imports.** `fmt`, `os`, `path/filepath`, `strings`, `time`, `defuse/config`.
- **Exposes.** `IsProtected`, `DeleteFile`, `DeleteEmptyMalwareDir`.
- **Input.** A file path. **Output.** error / `(bool removedDir, error)`; side effect (unlinked file/dir).

### `verify/verify.go` — `package verify`
- **Purpose.** Prove cleanup worked; print the summary.
- **Imports.** `fmt`, `defuse/persist`, `defuse/proc`.
- **Exposes.** `Summary{Target, DryRun, AttackerIPs, ProcessesKilled, RegistryRemoved, StartupRemoved, FilesDeleted}`; `Run(Summary) bool`.
- **Input.** The populated `Summary`; the post-cleanup machine. **Output.** Printed report; `bool` (clean?).

---

## 4. Execution Flow

### 4.1 Flow diagram

```
 start
   │
   ▼
[1] flag.Parse()  ── target=="" ? ──► print usage ──► os.Exit(2)
   │ no
   ▼
[2] checkElevation()            (warn only if not elevated; never aborts)
   │
   ▼
[3] if -verbose: persist.DebugDump()      (print every Run/RunOnce value + Startup file)
   │
   ▼
[4] summary = verify.Summary{Target, DryRun}
   │
   ▼
[5] matches   = proc.FindMatching(target)          ── running procs whose Normalize(name)==Normalize(target)
    allProcs  = proc.List()                         ── full snapshot (universe for the tree)
    killOrder = proc.KillOrder(matches, allProcs)   ── matches + ALL descendants, deepest-first
   │
   ▼
[6] registryHits = persist.FindRegistryPersistence(target)   ── 4 keys scanned
    startupHits  = persist.FindStartupPersistence(target)    ── 2 folders scanned
   │
   ▼
[7] exePaths  = gatherExePaths(matches, registryHits)        ── dedup: proc images + reg-value exes
    scanPaths = addStartupPaths(exePaths, startupHits)       ── + startup file paths  (IP-scan input only)
   │
   ▼
[8] pidSet        = {p.PID for p in killOrder}
    liveEndpoints = netinfo.LiveEndpoints(pidSet)            ── kernel TCP table, filtered by owning PID
    summary.AttackerIPs = collectAttackerIPs(liveEndpoints, scanPaths)
   │
   ▼   ─────────────── DESTRUCTIVE PHASE (all skipped/logged under -dry-run) ───────────────
   ▼
[9]  summary.ProcessesKilled = killProcesses(killOrder, dryRun)     ── proc.Kill per PID
     if killed>0 && !dryRun: sleep 250ms   (KillSettleDelay — let handles close)
   ▼
[10] summary.RegistryRemoved = removeRegistryHits(registryHits, dryRun)   ── key.DeleteValue(name)
   ▼
[11] summary.StartupRemoved  = removeStartupHits(startupHits, dryRun)     ── os.Remove(file)
   ▼
[12] summary.FilesDeleted    = deleteFiles(exePaths, dryRun)             ── cleaner.DeleteFile + DeleteEmptyMalwareDir
   │
   ▼
[13] ok = verify.Run(summary)
        ├─ prints "=== Summary ===" (always)
        ├─ if dryRun: print "nothing to verify", return true
        └─ else: re-run FindMatching + FindRegistryPersistence
                 clean = (both empty) → print CLEAN / INCOMPLETE → return clean
   │
   ▼
   if !ok: os.Exit(1)      else: fall off end of main → exit 0
```

### 4.2 Step-by-step narrative

1. **Flags parsed.** `-target` (string, **required**), `-dry-run` (bool), `-verbose` (bool). Empty target → `stderr` message, `flag.Usage()`, `os.Exit(2)` (conventional "usage error", distinct from `1` = "ran but failed").

2. **Elevation check.** `checkElevation()` asks the current process token whether it is elevated. If not, prints a `[warn]` (HKLM keys and other users' processes may be untouchable) then **continues anyway** — a non-admin run still cleans HKCU + user Startup + user-owned processes.

3. **Verbose dump (optional).** `persist.DebugDump()` prints every value name/data pair in the four registry locations, then every file in both Startup folders — matched or not.

4. **Summary struct created** with the target name and dry-run flag; counters start at zero.

5. **Process discovery + tree.** `proc.FindMatching(target)` takes a fresh snapshot, normalizes every name, keeps equals, resolves full exe paths. `proc.List()` takes another snapshot (the second in the run — a minor inefficiency, not a bug) as the universe for the tree walk. `proc.KillOrder(matches, allProcs)` returns every matched process **plus every descendant**, child-before-parent. If `matches` is empty it prints "Continuing with persistence and file cleanup anyway."

6. **Persistence discovery.** `FindRegistryPersistence` scans HKCU\Run, HKCU\RunOnce, HKLM\Run, HKLM\RunOnce; a value is a hit if its *name* normalizes to the target **or** the executable basename in its *data* normalizes to the target. `FindStartupPersistence` lists both Startup folders and matches files whose normalized name equals the target.

7. **Path collection.** `gatherExePaths` builds a de-duplicated deletion list (matched-process image paths + registry-value exe paths). `addStartupPaths` produces a *second* list additionally including Startup files — used **only** as input to the IP scan, never for deletion.

8. **Attacker-IP collection.** `pidSet` = PIDs of everything about to be killed. `netinfo.LiveEndpoints(pidSet)` returns the *remote* IP/port of every connection **owned by one of those PIDs** (excluding `0.0.0.0`). `collectAttackerIPs` unions those with the IPv4-regex results over every file in `scanPaths`; order deterministic (live first, then per-file), duplicates removed.

9–12. **Destructive phase.** Each helper iterates its hit list. Under `-dry-run` each prints `[dry-run] would …` and counts it without acting. Otherwise it acts, prints `[ok]` / `[fail]`, counts only real successes. After a real kill of ≥1 process, `main` sleeps `KillSettleDelay` (250 ms) so the OS can release the file lock before step 12.

13. **Verification.** `verify.Run` always prints `=== Summary ===`. Under dry-run it stops there. Otherwise it independently re-discovers matching processes and matching registry values; `clean` is true iff both empty; it prints `Result: CLEAN` or `Result: INCOMPLETE` and returns `clean`. `main` calls `os.Exit(1)` when it returns false; otherwise exits `0`.

> **Honest gap:** verification re-checks **processes and registry only** — it does *not* re-scan the Startup folders or confirm the files are gone. `CLEAN` means "no matching process and no matching Run/RunOnce value," which is narrower than "everything in the summary was removed."

---

## 5. Entry Point

The real entry point is `func main()` in `main.go`. Go starts an executable at `package main`'s `main` after running package-level initializers — here `netinfo`'s `var ipv4Pattern = regexp.MustCompile(...)` and `var Source TCPTableSource = windowsTCPTable{}`.

### 5.1 The entry-point code, annotated

```go
func main() {
	// flag.String/Bool register a flag and return a *pointer* to where the parsed
	// value will be written. Nothing is parsed yet.
	target  := flag.String("target", "", "process name to hunt and remove (required), e.g. maltrack")
	dryRun  := flag.Bool("dry-run", false, "report what would be done without changing anything")
	verbose := flag.Bool("verbose", false, "dump every registry value and Startup file scanned, matched or not")

	flag.Parse()               // NOW os.Args is parsed; *target/*dryRun/*verbose are populated.

	if *target == "" {         // -target is mandatory.
		fmt.Fprintln(os.Stderr, "defuse: -target is required")
		flag.Usage()           // auto-generated help text from the flag definitions
		os.Exit(2)             // 2 = "command-line usage error" (convention)
	}

	checkElevation()           // prints a warning if not admin; does NOT abort

	if *verbose {
		persist.DebugDump()    // dump everything we will scan, before we scan it
	}

	// verify.Summary is the accumulator threaded through the whole run.
	summary := verify.Summary{Target: *target, DryRun: *dryRun}

	matches, err := proc.FindMatching(*target)
	if err != nil {
		fmt.Printf("[warn] list processes: %v\n", err)   // logged, not fatal
	}

	allProcs, err := proc.List()
	if err != nil {
		fmt.Printf("[warn] snapshot processes: %v\n", err)
	}

	killTargets := proc.KillOrder(matches, allProcs)     // roots + descendants, child-first

	if len(matches) == 0 {
		fmt.Printf("No running process matches %q. Continuing with persistence and file cleanup anyway.\n", *target)
	} else {
		fmt.Printf("Found %d matching process(es), %d including children.\n", len(matches), len(killTargets))
	}

	registryHits := persist.FindRegistryPersistence(*target)
	startupHits  := persist.FindStartupPersistence(*target)
	exePaths     := gatherExePaths(matches, registryHits)
	scanPaths    := addStartupPaths(exePaths, startupHits)

	pidSet := make(map[uint32]bool, len(killTargets))
	for _, p := range killTargets {
		pidSet[p.PID] = true
	}
	liveEndpoints, err := netinfo.LiveEndpoints(pidSet)
	if err != nil {
		fmt.Printf("[warn] read TCP connections: %v\n", err)
	}

	summary.AttackerIPs     = collectAttackerIPs(liveEndpoints, scanPaths)
	summary.ProcessesKilled = killProcesses(killTargets, *dryRun)
	if summary.ProcessesKilled > 0 && !*dryRun {
		time.Sleep(config.KillSettleDelay)              // 250 ms: let the OS release file handles
	}
	summary.RegistryRemoved = removeRegistryHits(registryHits, *dryRun)
	summary.StartupRemoved  = removeStartupHits(startupHits, *dryRun)
	summary.FilesDeleted    = deleteFiles(exePaths, *dryRun)

	if !verify.Run(summary) {
		os.Exit(1)                                       // 1 = ran, but cleanup incomplete
	}
	// implicit return → exit 0
}
```

### 5.2 Initialization model

- **Package initializers run before `main`.** `netinfo.ipv4Pattern` compiled once with `regexp.MustCompile` (panics on a bad pattern — acceptable for a compile-time constant). `Source` set to `windowsTCPTable{}` (zero-size struct).
- **No config file.** All "configuration" is compiled-in constants + a few environment variables read lazily by `config`.
- **Environment variables consumed:** `APPDATA`, `ProgramData` (→ Startup folders), `SystemRoot` (→ protected-path prefix; fallback `C:\Windows`).
- **Arguments:** the three flags. Unknown flags → `flag.Parse` prints an error and calls `os.Exit(2)` itself.
- **Runtime dependencies:** `kernel32.dll`, `advapi32.dll`, and `iphlpapi.dll` (loaded *lazily*; a missing DLL surfaces only when `LiveEndpoints` is called, as a returned error, not a startup crash).
- **Entry-point error handling:** only a missing `-target` aborts early (exit 2). Every other early error is `[warn]`-logged and the run continues. The only other non-zero exit is `1` from a failed verification.

---

## 6. Code Deep Dive

### 6.1 `proc.Normalize`

```go
func Normalize(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimSuffix(n, ".exe")
	var b strings.Builder
	for _, r := range n {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}
```

**A. Purpose.** Turn any of `maltrack`, `  Mal-Track.EXE `, `MAL_TRACK`, `mal.track` into one canonical token (`maltrack`) so user input, process names, registry value names, registry command lines, and Startup filenames can all be compared for equality.

**B. Inputs.** `name string` — from the `-target` flag, a `ProcessEntry32.ExeFile`, a registry value name / extracted exe basename, or a Startup `DirEntry.Name()`.

**C. Internal logic.**
1. `TrimSpace` removes leading/trailing whitespace.
2. `ToLower` — case-fold.
3. `TrimSuffix(n, ".exe")` — drop a trailing `.exe` **once** (not `TrimRight`).
4. `strings.Builder` — an append-only buffer (avoids O(n²) string concatenation). `for _, r := range n` iterates **runes** (Unicode code points).
5. Every non-`[a-z0-9]` char is dropped — hyphens, underscores, dots, spaces, parens. So `mal-track`, `mal_track`, `mal.track` all collapse to `maltrack`.
6. `b.String()` returns the token.

**D. Output.** `string` — lowercase alphanumeric-only token, possibly empty. No side effects. **Consumed by** `FindMatching`, `persist.matchesTarget`, `persist.FindStartupPersistence`.
- **Example.** `Normalize("  Mal-Track.EXE ")` → `"mal-track.exe"` → `"mal-track"` → `"maltrack"`.
- **Edge case:** non-alnum stripping means `Normalize("mal") == Normalize("m-a-l")` and `Normalize("task host") == Normalize("taskhost")` — intentional (attackers rename with separators) but widens matching.

### 6.2 `proc.List`

```go
func List() ([]Process, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("create process snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	var procs []Process
	err = windows.Process32First(snapshot, &entry)
	for err == nil {
		procs = append(procs, Process{
			PID:  entry.ProcessID,
			PPID: entry.ParentProcessID,
			Name: windows.UTF16ToString(entry.ExeFile[:]),
		})
		err = windows.Process32Next(snapshot, &entry)
	}
	return procs, nil
}
```

**A. Purpose.** Produce a full, point-in-time list of every process as plain Go structs — the search space for `FindMatching` and the universe for `KillOrder`.

**B. Inputs.** None. Implicitly the OS process table at the instant of the call.

**C. Internal logic + concepts.**
- **`CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)`** — *Toolhelp* is a Win32 API for walking system lists. A **snapshot** is a frozen kernel copy so you can iterate it stably. `TH32CS_SNAPPROCESS` = "include the process list." Returns a **HANDLE** (opaque kernel-object reference) you must return.
- **`defer windows.CloseHandle(snapshot)`** — `defer` schedules the release for when `List` returns, on every path. Forgetting it leaks a kernel handle per call.
- **`windows.ProcessEntry32`** mirrors C `PROCESSENTRY32W`. `entry.Size = unsafe.Sizeof(entry)` — the API requires the caller to write the struct's own size so the kernel knows the layout version. `unsafe.Sizeof` is compile-time size; `unsafe` is unavoidable speaking a C ABI.
- **`Process32First` / `Process32Next`** — iterator; `Next` returns a non-nil error (`ERROR_NO_MORE_FILES`) at the end, which is how `for err == nil` terminates. Mirrors the C `do { } while (Process32Next(...))` pattern.
- **`entry.ExeFile`** is a fixed `[260]uint16` — a **UTF-16** C string (Windows is natively UTF-16). `windows.UTF16ToString` converts to a Go UTF-8 `string`, stopping at the first NUL. It holds only the *base name*, never the full path — hence `ExePath`.
- Each iteration appends `Process{PID, PPID, Name}`. **`ExePath` is deliberately left empty** — resolving it requires a privileged `OpenProcess` per PID; only `FindMatching` fills it, and only for the handful that match.

**D. Output.** `([]Process, error)`. On snapshot-creation failure `(nil, wrapped error)`; otherwise `([]Process, nil)`. The terminating error from `Process32Next` is swallowed on purpose. No side effects. **Consumed by** `FindMatching`, `main` (→ `KillOrder`).

### 6.3 `proc.ExePath`

```go
func ExePath(pid uint32) (string, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", fmt.Errorf("open process %d: %w", pid, err)
	}
	defer windows.CloseHandle(handle)

	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err != nil {
		return "", fmt.Errorf("query image path for pid %d: %w", pid, err)
	}
	return windows.UTF16ToString(buf[:size]), nil
}
```

**A. Purpose.** Given a PID, return the **full on-disk path** of that process's executable — needed to delete the file.

**B. Inputs.** `pid uint32` — from a `Process` produced by `List`/`FindMatching`.

**C. Internal logic.**
- **`OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)`** — request a handle with a *specific, minimal* access right (added in Vista for exactly this "read image name/times" use case). `false` = handle not inheritable. **Fails with `ERROR_ACCESS_DENIED`** for another user's / system's process when not elevated — which is why `FindMatching` ignores the error.
- `buf := make([]uint16, windows.MAX_PATH)` — 260-wide-char output buffer. `size` passed **by pointer** as both in-param (capacity) and out-param (chars written) — a classic Win32 pattern.
- **`QueryFullProcessImageName(handle, 0, &buf[0], &size)`** — flag `0` = Win32 path format (`C:\...`) vs `1` = native NT device path. `&buf[0]` passes the address of the first element.
- `windows.UTF16ToString(buf[:size])` — slice to written length, convert.

**D. Output.** `(string, error)`. Success → full path. Failure → `("", wrapped error)`. No side effects. **Consumed by** `FindMatching` (`if path, err := ExePath(p.PID); err == nil { p.ExePath = path }` — errors silently tolerated).

### 6.4 `proc.FindMatching`

```go
func FindMatching(t string) ([]Process, error) {
	allProcess, err := List()
	if err != nil {
		return nil, err
	}
	want := Normalize(t)
	var result []Process
	for _, p := range allProcess {
		if Normalize(p.Name) != want {
			continue
		}
		if path, err := ExePath(p.PID); err == nil {
			p.ExePath = path
		}
		result = append(result, p)
	}
	return result, nil
}
```

**A. Purpose.** Return every *currently running* process whose name matches the target, with the executable path filled in where obtainable.

**B. Inputs.** `t string` — the raw `-target` value; also called by `verify.Run` for the re-check.

**C. Internal logic.**
1. `List()` — fresh full snapshot (so `FindMatching` reflects *now*, important for the post-cleanup re-check).
2. `want := Normalize(t)` — computed once.
3. Linear scan, `continue` on mismatch — O(N) over ~200 processes.
4. On a match: `ExePath(p.PID)`. **`p` is a loop-local copy** (Go `range` copies the element), so `p.ExePath = path` mutates the copy, which is then appended — the original slice is untouched.
5. If `ExePath` errors, `p.ExePath` stays `""` and the process is still included — you still want to kill it.

**D. Output.** `([]Process, error)`. Error only if the initial `List` failed. **Consumed by** `main` (→ `KillOrder`, `gatherExePaths`) and `verify.Run` (expects `len==0`).

### 6.5 `proc.KillOrder` — the process-tree walk

```go
func KillOrder(roots []Process, all []Process) []Process {
	seen := make(map[uint32]bool)
	var order []Process

	var visit func(pid uint32)
	visit = func(pid uint32) {
		for _, p := range all {
			if p.PPID == pid && !seen[p.PID] {
				seen[p.PID] = true
				visit(p.PID)              // recurse into grandchildren FIRST
				order = append(order, p)  // then record this child
			}
		}
	}

	for _, root := range roots {
		if seen[root.PID] {
			continue
		}
		seen[root.PID] = true
		visit(root.PID)
		order = append(order, root)   // root recorded LAST
	}
	return order
}
```

**A. Purpose.** Expand matched "root" processes into *the entire forest under them*, ordered so **every child comes before its parent** — a watchdog child is dead before the parent that could respawn it, and the parent is dead before you touch its Run key.

**B. Inputs.** `roots []Process` (the `matches`), `all []Process` (the full snapshot).

**C. Internal logic + concepts: recursion, closures, post-order DFS, cycle guard.**
- The process "tree" is really a **graph** defined by `PPID` (X is a child of Y if `X.PPID == Y.PID`). Windows recycles PIDs, so `PPID` can point at an unrelated newer process; the `seen` map + roots being the only entry points keeps it bounded.
- **`seen map[uint32]bool`** — a **set** of visited PIDs. `map` gives O(1) membership and prevents infinite recursion on a cycle.
- **`visit` is a recursive closure**, declared `var visit func(uint32)` first then assigned (a closure literal can't reference its own name in `:=`). It captures `all`, `seen`, `order` by reference.
- **Post-order traversal.** Inside `visit(pid)`: for each unseen direct child, mark seen, **recurse first** (`visit(p.PID)`), and only *after the recursion returns* append that child. Result: deepest descendants first, then parents.
- **Roots appended last.** After `visit(root.PID)` drains the subtree, the root itself is appended. Tree `root → child → grandchild` → `order = [grandchild, child, root]`.
- **Complexity.** O(N·M) (re-scans `all` per node). N≈200, M typically 1–5 → a few hundred comparisons. A PPID→children map would make it O(N+M).

**D. Output.** `[]Process` — every matched process and every transitive child, child-before-parent, no duplicates. Pure function. **Example.** `roots = [{PID:5012}]`, `all` has `{5044, PPID:5012}` and `{5077, PPID:5044}` → `[{5077}, {5044}, {5012}]`. **Consumed by** `main` (`pidSet` + `killProcesses`).

### 6.6 `proc.Kill`

```go
func Kill(pid uint32) error {
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return fmt.Errorf("open process %d: %w", pid, err)
	}
	defer windows.CloseHandle(handle)
	return windows.TerminateProcess(handle, 1)
}
```

**A. Purpose.** Forcibly terminate one process by PID.

**B. Inputs.** `pid uint32` — from `KillOrder`'s output.

**C. Internal logic.**
- **`OpenProcess(PROCESS_TERMINATE, false, pid)`** — request a handle with *only* the right to kill. Fails with access-denied if the target runs as another user / SYSTEM and you're not elevated (or lack `SeDebugPrivilege`).
- **`TerminateProcess(handle, 1)`** — the hard kill: the kernel stops all threads immediately, no cleanup handlers, no chance to catch it. `1` is the **exit code** the dead process reports. It does **not** kill children (why `KillOrder` enumerated them).
- `defer CloseHandle` releases the handle.

**D. Output.** `error` — `nil` on success; wrapped error if open or terminate failed (e.g. process already exited — a benign race logged as `[fail]` and skipped). **Side effect:** a process ceases to exist; open files released *shortly* after (hence `KillSettleDelay`). **Consumed by** `killProcesses`.

### 6.7 `netinfo.LiveEndpoints`

```go
type Endpoint struct {
	PID  uint32
	IP   string
	Port uint16
}
type TCPTableSource interface {
	Read() ([]Endpoint, error)
}
var Source TCPTableSource = windowsTCPTable{}

func LiveEndpoints(pids map[uint32]bool) ([]Endpoint, error) {
	all, err := Source.Read()
	if err != nil {
		return nil, err
	}
	var matched []Endpoint
	for _, e := range all {
		if pids[e.PID] && e.IP != "0.0.0.0" {
			matched = append(matched, e)
		}
	}
	return matched, nil
}
```

**A. Purpose.** Of all TCP connections, return the *remote* endpoints belonging to a process about to be killed — the malware's live C2 / exfil connections.

**B. Inputs.** `pids map[uint32]bool` — a **set** of PIDs (from `killTargets`). O(1) `pids[e.PID]` lookup in the loop.

**C. Internal logic + concept: interface-based dependency injection (test seam).**
- **`TCPTableSource` is a one-method interface** — "anything with a `Read() ([]Endpoint, error)` method satisfies it." Go interfaces are satisfied *structurally* — no `implements` keyword.
- **`var Source TCPTableSource = windowsTCPTable{}`** — the *current* implementation. Production = the real syscall. A test can set `netinfo.Source = fakeTable{...}` and feed `LiveEndpoints` a hand-built list without real sockets. **Dependency injection via a swappable package variable** — the lightest form (trade-off: global mutable state; a parameter would be "purer").
- The filter keeps `e` only if its owning PID is in the kill set **and** its remote IP isn't `0.0.0.0` (which means "not connected / listening" — a listening socket, not an attacker). `127.0.0.1` is **not** filtered (a lab C2 can legitimately be loopback).

**D. Output.** `([]Endpoint, error)` — the malware's live remote endpoints; error only if `Source.Read()` failed. **Example.** kill set `{5012, 5044}`, table row `{PID:5044, IP:"203.0.113.7", Port:443}` → `[{5044, "203.0.113.7", 443}]`. **Consumed by** `collectAttackerIPs`.

### 6.8 `netinfo.windowsTCPTable.Read` — the raw syscall

```go
var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTable = iphlpapi.NewProc("GetExtendedTcpTable")
)
const (
	afINET                = 2
	tcpTableOwnerPIDAll   = 5
	errInsufficientBuffer = 122
)
const tcpRowSize = 24

func (windowsTCPTable) Read() ([]Endpoint, error) {
	var size uint32
	ret, _, _ := procGetExtendedTCPTable.Call(
		0, uintptr(unsafe.Pointer(&size)), 0, afINET, tcpTableOwnerPIDAll, 0,
	)
	if ret != errInsufficientBuffer {
		return nil, fmt.Errorf("GetExtendedTcpTable size query failed: %d", ret)
	}
	buf := make([]byte, size)
	ret, _, _ = procGetExtendedTCPTable.Call(
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, afINET, tcpTableOwnerPIDAll, 0,
	)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable failed: %d", ret)
	}
	return parseTCPTable(buf), nil
}
```

**A. Purpose.** Ask Windows for the full IPv4 TCP connection table *with owning-PID info*, as a raw byte buffer.

**C. Internal logic + concepts: lazy DLL binding, "call twice for size", `unsafe.Pointer`/`uintptr`, address families.**
- **`windows.NewLazySystemDLL("iphlpapi.dll")` + `.NewProc("GetExtendedTcpTable")`** — resolves the DLL/function *on first use*. "System" DLL means loaded only from `System32` (anti-DLL-planting). `iphlpapi.dll` = the **IP Helper API**.
- **`GetExtendedTcpTable(pTcpTable, pdwSize, bOrder, ulAf, TableClass, Reserved)`:**
  - `0` = `NULL` table pointer (first call: "just tell me the size").
  - `&size` = in/out size in bytes.
  - `0` = `bOrder` (don't sort).
  - `afINET = 2` = **`AF_INET`** (IPv4; IPv6 would be `AF_INET6 = 23`) — IPv4-only is a limitation.
  - `tcpTableOwnerPIDAll = 5` = **`TCP_TABLE_OWNER_PID_ALL`** — every connection in every state *plus* the owning PID.
- **The two-call pattern.** First call with a null buffer returns **`ERROR_INSUFFICIENT_BUFFER` = 122**, which the code *expects* (`if ret != 122 { error }`). Second call with `make([]byte, size)` must return `0` (`NO_ERROR`).
- **`uintptr(unsafe.Pointer(&x))`** — `.Call` takes `...uintptr`. You convert `*T` → `unsafe.Pointer` → `uintptr` *in the same expression as the call* (the GC may move objects; storing the `uintptr` is a hazard — the code follows the inline rule). `&buf[0]` = the buffer's first byte.

**D. Output.** `([]Endpoint, error)` via `parseTCPTable(buf)`. No side effects. **Consumed by** `LiveEndpoints`.

### 6.9 `netinfo.parseTCPTable`, `ipFromBytes`, `portFromBytes`

```go
func parseTCPTable(buf []byte) []Endpoint {
	if len(buf) < 4 {
		return nil
	}
	numEntries := binary.LittleEndian.Uint32(buf[0:4])
	var endpoints []Endpoint
	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + i*tcpRowSize
		if int(offset+tcpRowSize) > len(buf) {
			break
		}
		row := buf[offset : offset+tcpRowSize]
		endpoints = append(endpoints, Endpoint{
			IP:   ipFromBytes(row[12:16]),
			Port: portFromBytes(row[16:20]),
			PID:  binary.LittleEndian.Uint32(row[20:24]),
		})
	}
	return endpoints
}
func ipFromBytes(b []byte) string   { return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3]) }
func portFromBytes(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }
```

**A. Purpose.** Turn the opaque `GetExtendedTcpTable` buffer into `[]Endpoint`. The buffer is a C `MIB_TCPTABLE_OWNER_PID`: a 4-byte count, then that many 24-byte `MIB_TCPROW_OWNER_PID` rows.

**C. Internal logic + concept: endianness, struct-over-bytes.**

| offset | field | meaning | encoding |
|---|---|---|---|
| 0–3 | `dwState` | connection state | little-endian DWORD — *not read* |
| 4–7 | `dwLocalAddr` | local IP | 4 octets, network order — *not read* |
| 8–11 | `dwLocalPort` | local port | network-order low 2 bytes — *not read* |
| 12–15 | `dwRemoteAddr` | **remote IP** | 4 octets, network order → `ipFromBytes` |
| 16–19 | `dwRemotePort` | **remote port** | network-order low 2 bytes → `portFromBytes` |
| 20–23 | `dwOwningPid` | **owning PID** | little-endian DWORD → `binary.LittleEndian.Uint32` |

- **`numEntries := binary.LittleEndian.Uint32(buf[0:4])`** — the row count. **Endianness** = byte order of multi-byte integers. x86/x64 is **little-endian**; `binary.LittleEndian.Uint32` reassembles `[0x02,0,0,0]` = 2.
- **`offset := 4 + i*tcpRowSize`** — skip the 4-byte header, then `i` rows of 24 bytes. `if int(offset+tcpRowSize) > len(buf) { break }` guards a truncated buffer.
- **`ipFromBytes(row[12:16])`** — `dwRemoteAddr` is stored as **4 literal address bytes in network (big-endian) order** (`93.184.216.34` → `[93,184,216,34]`), so the code just formats them in order.
- **`portFromBytes(row[16:20])`** — the port sits in the **low 16 bits** in **network byte order**: 443 → `[0x01,0xBB,0x00,0x00]` → `uint16(b[0])<<8 | uint16(b[1])` = `0x01BB` = 443.
- **`PID: binary.LittleEndian.Uint32(row[20:24])`** — a local kernel integer, native little-endian.

> **Why the same struct mixes byte order:** IP and port are copied straight from the wire (network = big-endian); the PID is a local kernel value that never touches the network (native = little-endian).

**D. Output.** `[]Endpoint{PID, IP, Port}` per row. Listening sockets have `IP == "0.0.0.0"` and are filtered by `LiveEndpoints`. **Example.** `row[12:16]=[CB 00 71 07]`, `row[16:20]=[01 BB 00 00]`, `row[20:24]=[B4 13 00 00]` → `{IP:"203.0.113.7", Port:443, PID:5044}`.

### 6.10 `netinfo.ScanFileForIPv4` + `ipv4Pattern` + `isNoise`

```go
var ipv4Pattern = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)

func ScanFileForIPv4(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	seen := make(map[string]bool)
	var ips []string
	for _, m := range ipv4Pattern.FindAll(data, -1) {
		ip := string(m)
		if !seen[ip] && !isNoise(ip) {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	return ips, nil
}
func isNoise(ip string) bool { return ip == "0.0.0.0" }
```

**A. Purpose.** The *static* attacker-IP method: read the malware executable's raw bytes and pull out anything shaped like an IPv4 address — because if the malware isn't currently beaconing, `LiveEndpoints` finds nothing but the hard-coded C2 address is usually still ASCII in the binary.

**C. Internal logic + concept: regular expressions.**
- **A regex** is a pattern compiled into a state machine. `regexp.MustCompile` compiles once at package load (panics on a bad literal). Go's `regexp` uses RE2 — linear time, no catastrophic backtracking.
- **Pattern `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`:** `\b` word boundary; `(?:...)` non-capturing group; `[0-9]{1,3}\.` 1–3 digits then a dot; `{3}` that group 3× ; `[0-9]{1,3}` final octet; `\b`.
- `os.ReadFile(path)` — slurps the **entire file** into memory (fine for KB–MB samples; wasteful for a 500 MB file).
- `ipv4Pattern.FindAll(data, -1)` — every non-overlapping match (`-1` = no limit).
- `seen` dedupes; `isNoise` filters only `0.0.0.0`. **No octet ≤ 255 check** — so `999.999.999.999` and version fragments like `1.2.3.4` are returned as "IPs." Acknowledged trade-off: better an IOC an analyst can dismiss than a missed C2.

**D. Output.** `([]string, error)` — de-duplicated dotted-quad strings; error if the file can't be read (`collectAttackerIPs` logs `[warn]` and moves on). **Example.** file contains `connect 127.0.0.1:4444` → `["127.0.0.1"]`. **Consumed by** `collectAttackerIPs`.

### 6.11 `persist.FindRegistryPersistence`, `matchesTarget`, `extractExePath`, `RemoveRegistryPersistence`

```go
func FindRegistryPersistence(target string) []RegistryHit {
	want := proc.Normalize(target)
	var hits []RegistryHit
	for _, loc := range config.RegistryLocations() {
		key, err := registry.OpenKey(loc.Hive, loc.Path, registry.READ)
		if err != nil {
			fmt.Printf("  [warn] open %s\\%s: %v\n", loc.HiveName, loc.Path, err)
			continue
		}
		names, err := key.ReadValueNames(0)
		if err != nil {
			key.Close()
			continue
		}
		for _, name := range names {
			value, _, err := key.GetStringValue(name)
			if err != nil {
				continue
			}
			if matchesTarget(name, value, want) {
				hits = append(hits, RegistryHit{
					Hive: loc.Hive, HiveName: loc.HiveName, Path: loc.Path,
					Name: name, Value: value,
				})
			}
		}
		key.Close()
	}
	return hits
}

func matchesTarget(name, value, want string) bool {
	if proc.Normalize(name) == want {
		return true
	}
	return proc.Normalize(filepath.Base(extractExePath(value))) == want
}

func extractExePath(value string) string {
	v := strings.TrimSpace(value)
	v = strings.TrimPrefix(v, `\??\`)
	v = strings.Trim(v, `"`)
	lower := strings.ToLower(v)
	if i := strings.Index(lower, ".exe"); i != -1 {
		return v[:i+4]
	}
	return v
}

func RemoveRegistryPersistence(hit RegistryHit) error {
	key, err := registry.OpenKey(hit.Hive, hit.Path, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open %s\\%s for write: %w", hit.HiveName, hit.Path, err)
	}
	defer key.Close()
	return key.DeleteValue(hit.Name)
}
```

**A. Purpose.** Detect and delete auto-run persistence in the Registry's Run/RunOnce keys. Delete **only the offending value**, never the key.

**C. Internal logic + concepts: the Windows Registry, hives, HKCU vs HKLM, `RunOnce`.**
- **The Registry** is a hierarchical key/value database: **hives** (roots) → keys → values (name → typed data).
  - **`HKEY_CURRENT_USER` (HKCU)** — per-user; writable *without* admin.
  - **`HKEY_LOCAL_MACHINE` (HKLM)** — machine-wide; writing needs **administrator**.
- **The four keys** (`config.RegistryLocations()`): `…\CurrentVersion\Run` values run **at each logon**; `…\CurrentVersion\RunOnce` run once then Windows **deletes the value**. Both under both hives.
- **`registry.OpenKey(hive, path, registry.READ)`** — `registry.READ` = `KEY_READ` (query + enumerate). HKLM without elevation can fail → `[warn]`, `continue` (partial coverage, not a crash).
- **`key.ReadValueNames(0)`** — enumerate all value names. **`key.GetStringValue(name)`** — read data as a string (Run/RunOnce values are `REG_SZ` / `REG_EXPAND_SZ`); type discarded with `_`.
- **`matchesTarget`** — two ways a value is a hit: (1) value **name** normalizes to the target (`Run\Mal-Track = ...`); (2) the **executable in the command line** normalizes to the target (`Run\Updater = "C:\...\mal-track.exe"`).
- **`extractExePath`** parses a registry command line into just the program path: trim spaces; `TrimPrefix(v, "\??\")` (the NT object-manager path prefix); `Trim(v, "\"")` (surrounding quotes); then find the first `.exe` (case-insensitive) and cut at `v[:i+4]` (discards trailing arguments). If no `.exe`, return the whole trimmed string.
  - **Limitation:** `cmd.exe /c C:\x\m.exe` → `extractExePath` returns `cmd.exe` (first `.exe`), so `Base` = `cmd.exe` won't match `maltrack` — this value is missed unless its *name* matches.
- **`RemoveRegistryPersistence`** — reopen the *same key* with `registry.SET_VALUE` (HKLM → needs admin), then **`key.DeleteValue(hit.Name)`** — deletes just that one value. The Run/RunOnce **key is never touched** (legitimate software populates it too).

**D. Output.** `FindRegistryPersistence` → `[]RegistryHit{Hive, HiveName, Path, Name, Value}`. `RemoveRegistryPersistence` → `error`. Side effect: one registry value permanently gone. **Example.** target `maltrack`; `HKCU\...\Run` has `Mal-Track = "C:\Users\a\Downloads\Fynloski\mal-track\mal-track.exe"` → hit; `hit.ExePath()` → the path → flows into `gatherExePaths` → deleted in step 12. **Consumed by** `main` and `verify.Run`.

### 6.12 `persist.FindStartupPersistence` / `RemoveStartupPersistence` / `DebugDump`

```go
func FindStartupPersistence(target string) []StartupHit {
	want := proc.Normalize(target)
	var hits []StartupHit
	for _, folder := range config.StartupFolders() {
		entries, err := os.ReadDir(folder)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if proc.Normalize(entry.Name()) == want {
				hits = append(hits, StartupHit{Path: filepath.Join(folder, entry.Name())})
			}
		}
	}
	return hits
}
func RemoveStartupPersistence(hit StartupHit) error { return os.Remove(hit.Path) }
```

**A. Purpose.** The other classic persistence: files in a **Startup folder** (Windows launches everything there at logon).

**C. Internal logic.**
- **`config.StartupFolders()`** returns `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` (**per-user**, no admin) and `%ProgramData%\...\Startup` (**all-users**, admin).
- **`os.ReadDir(folder)`** — list entries; `continue` if unreadable. Skip subdirectories; for files, `Normalize(entry.Name()) == want`.
  - **Important limitation:** `Normalize` strips all non-alphanumerics and only trims a `.exe` suffix. A **shortcut** `mal-track.lnk` → `maltracklnk` ≠ `maltrack`. This matches a Startup entry only if it's literally `mal-track.exe` or extensionless `mal-track`. Real-world Startup persistence is usually a `.lnk`, which this **misses**. `DebugDump` (verbose) at least *shows* every Startup file so an analyst can catch it manually.
- **`RemoveStartupPersistence`** = a bare `os.Remove(hit.Path)` — no `IsProtected` guard (a Startup folder is never under `C:\Windows`), and no retry loop (unlike exe-path deletions).
- **`DebugDump`** (verbose) prints every Run/RunOnce value across the 4 keys and every file in both Startup folders, matched or not — diagnostic, no side effects.

### 6.13 `cleaner.IsProtected` / `DeleteFile` / `DeleteEmptyMalwareDir`

```go
func IsProtected(path string) bool {
	windowsDir := strings.ToLower(strings.TrimRight(config.WindowsDir(), `\`)) + `\`
	return strings.HasPrefix(strings.ToLower(path), windowsDir)
}

func DeleteFile(path string) error {
	if IsProtected(path) {
		return fmt.Errorf("refusing to delete protected path %s", path)
	}
	if _, err := os.Stat(path); err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt < config.FileDeleteAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(config.FileDeleteRetryDelay)
		}
		if lastErr = os.Remove(path); lastErr == nil {
			return nil
		}
	}
	return lastErr
}

func DeleteEmptyMalwareDir(exePath string) (bool, error) {
	dir := filepath.Dir(exePath)
	if IsProtected(dir) {
		return false, fmt.Errorf("refusing to delete protected path %s", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	if len(entries) > 0 {
		return false, nil
	}
	os.Chmod(dir, 0777)
	var lastErr error
	for attempt := 0; attempt < config.FileDeleteAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(config.FileDeleteRetryDelay)
		}
		if lastErr = os.Remove(dir); lastErr == nil {
			return true, nil
		}
	}
	return false, lastErr
}
```

**A. Purpose.** Delete the malware's file(s) and, if it lived in its own folder, that folder — **without ever deleting an OS file** and **without walking up the directory tree**.

**C. Internal logic + concept: trust boundary / allow-list, `os.Remove` semantics, the "file still locked" race.**
- **`IsProtected`** — `config.WindowsDir()` = `%SystemRoot%` (or `C:\Windows`). `TrimRight(..., "\")` then `+ "\"` normalizes to exactly one trailing backslash, lowercased. `strings.HasPrefix(lower(path), "c:\windows\")` → true means "inside the Windows directory." Both functions **refuse** such paths (return an error → `main` logs `[fail]`/`[warn]` and skips). Why: a Run value like `cmd.exe /c evil.bat` could resolve to `C:\Windows\System32\cmd.exe` — deleting that bricks the OS.
  - **Weaknesses:** a *string-prefix* check — no symlink/junction resolution, doesn't cover `C:\Program Files` or non-`C:\Windows` system locations, bypassable by 8.3 short names. A guard, not a sandbox.
- **`DeleteFile` flow:** guard → `os.Stat` (must exist) → **retry loop**: up to 5 tries, 300 ms between, each `os.Remove`. The retry exists because **`TerminateProcess` returns before the kernel has released the dead process's file handles**. `os.Remove` on Windows maps to `DeleteFile` (unlink the name; data freed when the last handle closes).
- **`DeleteEmptyMalwareDir` flow:** guard the *parent dir* → `os.ReadDir(dir)` → **if it has any entries, return `(false, nil)`** ("not empty, left it alone, no error"). Only if empty does it proceed. `os.Chmod(dir, 0777)` — on Windows only clears the read-only attribute; best-effort. Then the same 5×300 ms retry loop `os.Remove(dir)`. Returns `(true, nil)` if removed.
  - **Scope is exactly one level:** removes `filepath.Dir(exePath)` and *nothing above it*.

**D. Output.** `DeleteFile` → `error`. `DeleteEmptyMalwareDir` → `(removedDir bool, err error)`. `main` switches: `err != nil` → `[warn]`; `removedDir == true` → `[ok] removed now-empty folder`; `(false, nil)` → silent.

### 6.14 `main` helper functions

- **`checkElevation`** — `windows.GetCurrentProcessToken()` returns a pseudo-handle to the current **access token** (the kernel object listing user SID, groups, privileges). `.IsElevated()` calls `GetTokenInformation(TokenElevation)`. Elevated → silent; not → `[warn]`, return anyway. **UAC** = even admins run with a *filtered* token until they explicitly elevate; HKLM writes and cross-user `OpenProcess` need the unfiltered token.
- **`gatherExePaths(matches, registryHits)`** — builds the *deletion* list from matched processes' `ExePath` and registry hits' `ExePath()`, each via `addPath`.
- **`addStartupPaths(paths, startupHits)`** — builds the *IP-scan* list: seeds `seen` from `paths`, then adds each `startupHit.Path`.
- **`addPath(paths, seen, p)`** — the de-dup primitive. `key := strings.ToLower(filepath.Clean(p))` (collapse `..`/`.`/dup separators, lowercase). If `p == ""` or `seen[key]` → unchanged; else mark and append. So `C:\x\M.EXE` and `c:\x\.\m.exe` are the same file.
- **`collectAttackerIPs(live, exePaths)`** — an inner `add(ip)` closure with its own `seen` enforces "each IP once, first occurrence wins." Adds every `live` `.IP` first, then per-path `ScanFileForIPv4` results (read error → `[warn]`, skip).
- **`killProcesses` / `removeRegistryHits` / `removeStartupHits` / `deleteFiles`** — the four "iterate hits; dry-run prints `would…` and counts; else act, print `[ok]`/`[fail]`, count only successes" loops. `deleteFiles` additionally calls `DeleteEmptyMalwareDir` after a successful file delete.

### 6.15 `verify.Run` / `printSummary`

```go
func Run(s Summary) bool {
	printSummary(s)
	if s.DryRun {
		fmt.Println("\n[dry-run] no changes were made, so nothing to verify.")
		return true
	}
	fmt.Println("\nVerifying cleanup...")
	remainingProcs, err := proc.FindMatching(s.Target)
	if err != nil {
		fmt.Printf("  [warn] could not re-check processes: %v\n", err)
	}
	remainingRegistry := persist.FindRegistryPersistence(s.Target)
	clean := len(remainingProcs) == 0 && len(remainingRegistry) == 0
	// ... prints [OK]/[FAIL] per category, then "Result: CLEAN" or "INCOMPLETE"
	return clean
}
```

**A. Purpose.** Independently re-verify the two most important invariants (no matching process, no matching Run/RunOnce value) and turn the result into the program's exit code. It doesn't trust the counters; it *re-queries the live machine*.

**C. Internal logic.**
- `printSummary(s)` always runs: target, attacker IPs, and the four `... removed: N` / `... would remove: N` lines.
- Under `-dry-run`: "nothing to verify," `return true` (exit 0).
- Otherwise: `proc.FindMatching(s.Target)` again (fresh, post-kill) and `persist.FindRegistryPersistence(s.Target)` again (post-delete). `clean = both empty`. Prints `[OK]` / `[FAIL]` per dimension, then `Result: CLEAN` / `INCOMPLETE`.

**D. Output.** `bool` → `main` does `if !verify.Run(summary) { os.Exit(1) }`.
- **Gap:** Startup folder and file deletion are *not* re-verified. A run that killed the process and removed the Run key but failed to delete a locked exe still prints `CLEAN`. The file-delete outcome is visible only in the summary counters and any `[fail]` line.

---

## 7. Code Comments (annotated load-bearing blocks)

### 7.1 The orchestration order in `main`

**Concept.** The single most important design property is the *order*: **termination happens before de-persistence**, and **persistence + file cleanup run even when no process was found**.

```go
// ---- DISCOVERY (read-only, always safe) -------------------------------------
matches, _   := proc.FindMatching(*target)            // running procs whose Normalize(name)==Normalize(target)
allProcs, _  := proc.List()                           // full snapshot: the universe for the tree walk
killTargets  := proc.KillOrder(matches, allProcs)     // matches + EVERY descendant, DEEPEST CHILD FIRST
                                                      //   → a watchdog dies before the parent that respawns it
registryHits := persist.FindRegistryPersistence(*target)  // 4 keys: HKCU/HKLM × Run/RunOnce
startupHits  := persist.FindStartupPersistence(*target)   // 2 folders: per-user + all-users Startup
exePaths  := gatherExePaths(matches, registryHits)    // dedup deletion list: proc images + reg-value exes
scanPaths := addStartupPaths(exePaths, startupHits)   // dedup IP-SCAN list (adds startup files; NOT deleted here)

// ---- INTELLIGENCE (still read-only) ---------------------------------------
pidSet := make(map[uint32]bool, len(killTargets))     // set, for O(1) "is this connection ours?" test
for _, p := range killTargets { pidSet[p.PID] = true }
liveEndpoints, _ := netinfo.LiveEndpoints(pidSet)     // kernel TCP table, remote endpoints owned by our PIDs
summary.AttackerIPs = collectAttackerIPs(liveEndpoints, scanPaths) // union(live IPs, regex IPs in each file)

// ---- DESTRUCTIVE (each step no-ops + logs under -dry-run) ------------------
summary.ProcessesKilled = killProcesses(killTargets, *dryRun)     // TerminateProcess per PID, child→parent
if summary.ProcessesKilled > 0 && !*dryRun {
	time.Sleep(config.KillSettleDelay)               // 250 ms: let the OS finish teardown + release the .exe lock
}
summary.RegistryRemoved = removeRegistryHits(registryHits, *dryRun) // key.DeleteValue(name) — value only, never the key
summary.StartupRemoved  = removeStartupHits(startupHits, *dryRun)   // os.Remove(startup file)
summary.FilesDeleted    = deleteFiles(exePaths, *dryRun)            // cleaner.DeleteFile (guarded, retried) + DeleteEmptyMalwareDir

// ---- PROOF --------------------------------------------------------------
if !verify.Run(summary) {                             // re-query machine: any matching proc OR reg value left?
	os.Exit(1)                                        // 1 = ran but not fully clean; 0 = clean; 2 = bad usage
}
```

**Important lines.** `deleteFiles(exePaths, …)` uses **`exePaths`, not `scanPaths`** — Startup files were already removed by `removeStartupHits`; `scanPaths` existed only to widen the IP scan. `time.Sleep(config.KillSettleDelay)` is the one deliberate pause. `removeRegistryHits` **after** `killProcesses` = the race-prevention guarantee.

**INPUT → PROCESSING → OUTPUT for `main`:**
```
INPUT:  -target "maltrack"  [-dry-run] [-verbose]   + live machine state
        ↓ validation: -target non-empty (else exit 2); elevation warning if not admin
        ↓ discovery: matches, tree, registry hits, startup hits, path lists
        ↓ intelligence: live C2 endpoints + static IPs → summary.AttackerIPs
        ↓ destructive (unless -dry-run): kill tree → settle → strip registry → strip startup → delete files+dir
        ↓ proof: re-query; clean iff no matching proc AND no matching reg value
OUTPUT: formatted stdout report + machine side effects + exit code 0 | 1 | 2
```

### 7.2 `KillOrder`

**Concept.** Depth-first **post-order** traversal of the PPID graph. Post-order = record a node only after its whole subtree is recorded → deepest-first ordering. A visited-set (`map`) dedupes shared children and prevents cycles.

```go
func KillOrder(roots []Process, all []Process) []Process {
	seen  := make(map[uint32]bool) // PIDs already placed into `order` (dedupe + cycle guard)
	var order []Process            // result: children strictly before their parents
	var visit func(pid uint32)     // declared first so the closure can refer to itself
	visit = func(pid uint32) {
		for _, p := range all {                  // find direct children of `pid` ...
			if p.PPID == pid && !seen[p.PID] {   // ... that we haven't handled yet
				seen[p.PID] = true
				visit(p.PID)                     // recurse: bury the whole subtree FIRST
				order = append(order, p)         // THEN record this child (post-order)
			}
		}
	}
	for _, root := range roots {
		if seen[root.PID] { continue }
		seen[root.PID] = true
		visit(root.PID)
		order = append(order, root)              // root goes LAST of its own branch
	}
	return order
}
```

**Lines that matter.** `visit(p.PID)` *before* `order = append(...)` is the whole trick. Swap them → parents first → a watchdog respawns its parent.

### 7.3 `windowsTCPTable.Read` + `parseTCPTable`

**Concept.** The **call-twice-for-size** Win32 idiom, and **mixed byte order** in one C struct.

```go
func (windowsTCPTable) Read() ([]Endpoint, error) {
	var size uint32
	// CALL 1 — pTcpTable = NULL: writes required byte count into `size`, returns ERROR_INSUFFICIENT_BUFFER (122).
	ret, _, _ := procGetExtendedTCPTable.Call(
		0,                              // pTcpTable = NULL
		uintptr(unsafe.Pointer(&size)), // pdwSize   (out: bytes needed)
		0,                              // bOrder    = false
		afINET,                         // ulAf      = AF_INET (IPv4 only)
		tcpTableOwnerPIDAll,            // TableClass= TCP_TABLE_OWNER_PID_ALL (rows carry PID)
		0,                              // Reserved
	)
	if ret != errInsufficientBuffer {   // anything other than 122 here is a real failure
		return nil, fmt.Errorf("GetExtendedTcpTable size query failed: %d", ret)
	}
	buf := make([]byte, size)           // allocate exactly what it asked for
	ret, _, _ = procGetExtendedTCPTable.Call(
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, afINET, tcpTableOwnerPIDAll, 0,
	)
	if ret != 0 { return nil, fmt.Errorf("GetExtendedTcpTable failed: %d", ret) }
	return parseTCPTable(buf), nil
}

func parseTCPTable(buf []byte) []Endpoint {
	if len(buf) < 4 { return nil }
	numEntries := binary.LittleEndian.Uint32(buf[0:4]) // header: row count, native LE integer
	var endpoints []Endpoint
	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + i*tcpRowSize                     // skip 4-byte header, then i rows of 24 bytes
		if int(offset+tcpRowSize) > len(buf) { break } // defensive: never read past the buffer
		row := buf[offset : offset+tcpRowSize]         // one MIB_TCPROW_OWNER_PID (6 DWORDs)
		endpoints = append(endpoints, Endpoint{
			IP:   ipFromBytes(row[12:16]),   // dwRemoteAddr: 4 address bytes, network order → "a.b.c.d" as-is
			Port: portFromBytes(row[16:20]), // dwRemotePort: big-endian in the low 2 bytes → (b0<<8)|b1
			PID:  binary.LittleEndian.Uint32(row[20:24]), // dwOwningPid: native LE integer
		})
	}
	return endpoints
}
```

**Lines that matter.** `if ret != errInsufficientBuffer` — the *expected* outcome of call 1 is an "error." `row[12:16]` not `row[4:8]` — the **remote** (attacker) address. `ipFromBytes` doesn't reverse bytes (address is network order); `binary.LittleEndian.Uint32` *is* used for the PID (native integer).

### 7.4 `cleaner.DeleteFile`

**Concept.** A **trust boundary** (never delete inside `C:\Windows`), and **retry-with-backoff** because a just-killed process holds its `.exe` open for a short, non-deterministic window after `TerminateProcess` returns.

```go
func DeleteFile(path string) error {
	if IsProtected(path) {                                  // trust boundary: refuse OS directory
		return fmt.Errorf("refusing to delete protected path %s", path)
	}
	if _, err := os.Stat(path); err != nil {               // nothing there? report why, don't loop
		return err
	}
	var lastErr error
	for attempt := 0; attempt < config.FileDeleteAttempts; attempt++ { // up to 5 tries
		if attempt > 0 {
			time.Sleep(config.FileDeleteRetryDelay)        // 300 ms between tries: outlast the file lock
		}
		if lastErr = os.Remove(path); lastErr == nil {     // os.Remove → Win32 DeleteFile (unlink)
			return nil
		}
	}
	return lastErr                                          // still locked / denied after 5 tries
}
```

**Lines that matter.** `IsProtected(path)` first, before `Stat` — you reject a dangerous path even if it doesn't currently exist. `attempt > 0` guard means the first try is immediate (no wasted 300 ms when unlocked).

---

## 8. INPUT → PROCESSING → OUTPUT (per component)

### `proc.FindMatching`
```
INPUT:   "maltrack"  + live process table
  ↓ List() → []Process ; want := Normalize(target) → "maltrack"
  ↓ for each proc: Normalize(Name)==want ? → ExePath(PID) (best-effort) → keep
OUTPUT:  []Process (matched, with ExePath filled where obtainable)
EXAMPLE: in "MAL-TRACK" → out [{5012,3300,"mal-track.exe","C:\...\mal-track.exe"}]
```

### `proc.KillOrder`
```
INPUT:   roots (the matches) + all (the snapshot)
  ↓ post-order DFS over PPID edges, visited-set dedupe
OUTPUT:  []Process — roots + all descendants, deepest child first
EXAMPLE: roots=[5012], all has 5044(ppid 5012), 5077(ppid 5044) → [5077, 5044, 5012]
```

### `netinfo.LiveEndpoints`
```
INPUT:   pids map[uint32]bool
  ↓ Source.Read() → GetExtendedTcpTable → parse → []Endpoint (ALL connections)
  ↓ keep e where pids[e.PID] && e.IP != "0.0.0.0"
OUTPUT:  []Endpoint (the malware's live remote endpoints)
```

### `netinfo.ScanFileForIPv4`
```
INPUT:   path (a malware exe)
  ↓ os.ReadFile → []byte ; ipv4Pattern.FindAll → matches ; dedupe; drop "0.0.0.0"
OUTPUT:  []string (dotted-quad tokens, incl. possible false positives like "1.2.3.4")
```

### `persist.FindRegistryPersistence`
```
INPUT:   target + HKCU/HKLM Run+RunOnce
  ↓ for each of 4 keys: OpenKey(READ) → ReadValueNames → GetStringValue
  ↓ matchesTarget: Normalize(name)==want OR Normalize(base(extractExePath(value)))==want
OUTPUT:  []RegistryHit{Hive,HiveName,Path,Name,Value}
```

### `cleaner.DeleteFile` / `DeleteEmptyMalwareDir`
```
INPUT:   exe path
  ↓ IsProtected? (prefix of C:\Windows\) ⇒ refuse
  ↓ DeleteFile: Stat → up to 5× os.Remove w/ 300ms backoff
  ↓ DeleteEmptyMalwareDir: parent dir; ReadDir; if empty → up to 5× os.Remove(dir)
OUTPUT:  DeleteFile → error ; DeleteEmptyMalwareDir → (removedDir bool, err error)
```

### `verify.Run`
```
INPUT:   Summary{Target, DryRun, AttackerIPs, 4 counters}
  ↓ printSummary ; if DryRun → return true
  ↓ else: FindMatching(Target) again + FindRegistryPersistence(Target) again
  ↓ clean := len(procs)==0 && len(regValues)==0
OUTPUT:  bool (→ exit 0 or 1) + "Result: CLEAN | INCOMPLETE"
```

### End-to-end worked example
```
INPUT:  defuse.exe -target maltrack     (Administrator, infected VM)
machine: process mal-track.exe PID 5012 (parent explorer.exe 3300);
         HKCU\...\Run  Mal-Track = "C:\Users\a\Downloads\Fynloski\mal-track\mal-track.exe";
         file at that path; exe bytes contain "127.0.0.1"; no live TCP connection.
PROCESSING:
  discovery → matches=[5012]; KillOrder=[5012]; registryHits=[HKCU Mal-Track]; startupHits=[]
  paths     → exePaths=["C:\Users\a\Downloads\Fynloski\mal-track\mal-track.exe"]
  intel     → LiveEndpoints({5012})=[] ; ScanFileForIPv4(exe)=["127.0.0.1"] → AttackerIPs=["127.0.0.1"]
  kill      → proc.Kill(5012) ok → sleep 250ms
  registry  → RemoveRegistryPersistence(HKCU Mal-Track) ok
  files     → DeleteFile(exe): Remove fails once → 300ms → ok ; DeleteEmptyMalwareDir: folder empty → removed
  verify    → FindMatching("maltrack")=[] ; FindRegistryPersistence("maltrack")=[] → clean=true
OUTPUT: "Result: CLEAN" ; exit code 0
```

---

## 9. Important Concepts

**TERM: Access token / privilege / UAC elevation**
- *Definition.* A Windows **access token** records the user's SID, group SIDs, and privileges. **UAC**: even admins run with a *filtered* token until explicit elevation.
- *Why it exists.* Least privilege; per-elevation user consent.
- *How it works.* The kernel checks the caller's token against each object's security descriptor. HKLM write, cross-user `OpenProcess`, and `TerminateProcess` on SYSTEM processes need the unfiltered token.
- *Why this project uses it.* `checkElevation` reads elevation state to *warn* that HKLM keys / other users' processes may be untouchable rather than silently under-clean.
- *Without it.* Non-elevated run quietly fails on HKLM and might report `CLEAN` while machine-wide persistence remains.
- *Where.* `main.checkElevation`; the failure modes surface in `persist` and `proc`.

**TERM: Toolhelp process snapshot**
- *Definition.* `CreateToolhelp32Snapshot` + `Process32First/Next` returns a frozen list of processes with PID, PPID, base image name.
- *Why.* A stable iterable view without special privilege.
- *How.* The kernel copies the process list; you iterate the copy.
- *Why here.* The simplest privilege-free way to find processes by name and get PPID.
- *Where.* `proc.List`.

**TERM: HANDLE / `CloseHandle` / `defer`**
- *Definition.* A **handle** is an opaque integer mapped to a kernel object; release each with `CloseHandle` / `key.Close()`. Go's **`defer`** runs a call when the function returns.
- *Why.* Handles are finite; `defer` guarantees cleanup on every path.
- *Where.* `proc.List`, `ExePath`, `Kill`; `persist` key operations.

**TERM: Windows Registry — hives, Run/RunOnce**
- *Definition.* Hierarchical key/value database. `…\Run` values run at every logon; `…\RunOnce` run once then self-delete.
- *Why here.* The two most common Windows persistence primitives; `defuse` reads all four (HKCU/HKLM × Run/RunOnce) and deletes matching *values*.
- *Where.* `config.RegistryLocations`, `persist`, `verify.Run`.

**TERM: Startup folder persistence**
- *Definition.* `%APPDATA%\...\Startup` (per-user) and `%ProgramData%\...\Startup` (all-users) — Windows launches their contents at logon.
- *Where.* `config.StartupFolders`, `persist.FindStartupPersistence`. **Limitation:** `Normalize` won't match `.lnk` names.

**TERM: Process tree / PPID / post-order DFS**
- *Definition.* Each process records its creator's PID (`PPID`). **DFS** explores one branch fully before backtracking; **post-order** records a node after its children.
- *Why here.* Kill children before parents so a watchdog can't respawn its parent.
- *Where.* `proc.KillOrder`.

**TERM: Go interface + dependency injection (test seam)**
- *Definition.* A Go **interface** is a method-set contract satisfied structurally. **DI** = supplying an implementation from outside.
- *How here.* `TCPTableSource` has one method `Read()`. `var Source = windowsTCPTable{}` holds the production impl; a test assigns a stub returning a hand-built `[]Endpoint`.
- *Why.* The byte-layout parsing is bug-prone and untestable welded to a syscall.
- *Trade-off.* `Source` is global mutable state; a parameter would be "purer."
- *Where.* `netinfo`.

**TERM: `syscall` via `LazyDLL` / `unsafe.Pointer` / `uintptr`**
- *Definition.* Calling an OS C function from Go. `NewLazySystemDLL` resolves a DLL on first use; `.Call(args...)` takes `uintptr` machine words.
- *How.* `uintptr(unsafe.Pointer(&x))` *inside the `.Call(...)` argument list* (a special case the GC recognizes).
- *Danger.* Wrong struct size/offset/byte order → garbage or a crash; storing the `uintptr` is a GC hazard.
- *Where.* `netinfo.windowsTCPTable.Read`; `unsafe.Sizeof(entry)` in `proc.List`.

**TERM: Endianness / network byte order**
- *Definition.* Byte order of multi-byte integers. **Little-endian** (x86/x64): least-significant byte first. **Big-endian** = "network byte order" (IP/TCP headers).
- *How here.* Remote IP/port copied from the wire → big-endian; owning PID a local integer → little-endian. `parseTCPTable` treats them differently.
- *Getting it wrong.* IPs reversed; ports swapped.
- *Where.* `netinfo.parseTCPTable`, `ipFromBytes`, `portFromBytes`.

**TERM: Regular expression (RE2)**
- *Definition.* A pattern compiled to a finite automaton; Go's `regexp` = RE2 (linear time).
- *How here.* `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b` over the file's bytes.
- *Limitation.* No octet-range check → false positives; only `0.0.0.0` filtered.
- *Where.* `netinfo.ipv4Pattern`, `ScanFileForIPv4`, `isNoise`.

**TERM: `TerminateProcess` vs graceful shutdown; `KillSettleDelay`**
- *Definition.* `TerminateProcess` is an unconditional kill — no cleanup handlers. A graceful stop (`WM_CLOSE`, `CTRL_C_EVENT`) can be ignored.
- *How.* Open file handles may linger briefly after the call returns. The 250 ms `KillSettleDelay` gives the OS time; `cleaner.DeleteFile`'s retry loop is the backstop.
- *Where.* `proc.Kill`; `main`; `cleaner.DeleteFile`.

**TERM: Trust boundary / allow-list (protected paths)**
- *Definition.* A point where lower-trust data (an attacker-written registry value) drives a dangerous action (deleting a file). A deny-rule constrains it.
- *How here.* `cleaner.IsProtected` refuses any path whose lowercased form starts with `<WindowsDir>\`.
- *Limitations.* Prefix-only; no symlink/junction resolution; doesn't cover `C:\Program Files`.
- *Where.* `cleaner.IsProtected`, `DeleteFile`, `DeleteEmptyMalwareDir`.

**TERM: Dry-run / idempotent verification**
- *Definition.* A mode that performs all discovery/reporting but no mutation. Verification re-derives state from scratch.
- *Where.* `-dry-run` flag; every destructive helper; `verify.Run`.

**TERM: Exit codes as an interface**
- *Definition.* The integer a process returns. `2` = bad usage, `1` = ran but verification failed, `0` = clean.
- *Where.* `main`: `os.Exit(2)`, `os.Exit(1)`, implicit `0`.

---

## 10. Libraries and Dependencies

### `golang.org/x/sys` (v0.47.0) — the *only* external dependency

**What it is.** A Go-team-maintained package (`golang.org/x/...` = official but outside the stdlib compatibility promise) of low-level OS primitives: raw syscalls, OS constants, thin typed wrappers, per platform.

**Why imported.** Everything `defuse` does is Windows-specific and below the stdlib's abstraction level: enumerate processes with parent PIDs, open a process for a *specific* access right, terminate it, query its image path, read/enumerate/delete registry values, check token elevation, call `GetExtendedTcpTable`.

**Sub-packages used:**
- **`golang.org/x/sys/windows`** — `CreateToolhelp32Snapshot`, `Process32First`, `Process32Next`, `ProcessEntry32`, `TH32CS_SNAPPROCESS`; `OpenProcess`, `TerminateProcess`, `QueryFullProcessImageName`, `CloseHandle`; `PROCESS_TERMINATE`, `PROCESS_QUERY_LIMITED_INFORMATION`, `MAX_PATH`; `UTF16ToString`; `NewLazySystemDLL`, `(*LazyDLL).NewProc`, `(*LazyProc).Call`; `GetCurrentProcessToken`, `(Token).IsElevated`.
- **`golang.org/x/sys/windows/registry`** — `registry.Key`, `registry.CURRENT_USER`, `registry.LOCAL_MACHINE`, `registry.OpenKey`, `registry.READ`, `registry.SET_VALUE`; `(Key).ReadValueNames`, `(Key).GetStringValue`, `(Key).DeleteValue`, `(Key).Close`.

**Why not implement it ourselves.** These are OS ABI calls — hand-writing `syscall.Syscall` stubs with the exact argument marshaling, struct layouts, and error conventions that `x/sys` already encodes and tests across Windows versions is exactly the error-prone work this package removes.

**What it does internally (high level, from what's visible).** `x/sys/windows` maps each function to a `//sys` directive that a generator turns into a `LazyDLL`/`LazyProc` lookup + `SyscallN`, converting Go types to `uintptr` and translating a zero/nonzero return into a Go `error` (`windows.Errno`). The `registry` sub-package wraps `RegOpenKeyEx`/`RegEnumValue`/`RegQueryValueEx`/`RegDeleteValue`, handling UTF-16 conversions and the "call to get size, call to get data" dance. **Detail beyond this is not in the provided source and is not asserted here.**

### PROJECT CODE vs EXTERNAL LIBRARY CODE — boundary map

| `defuse` package | Calls into `x/sys` for | Everything else is project code |
|---|---|---|
| `proc` | snapshot iteration, `OpenProcess`/`TerminateProcess`/`QueryFullProcessImageName`, `CloseHandle`, `UTF16ToString` | `Normalize`, the `for err == nil` loop, `KillOrder`'s DFS, `FindMatching`'s filter |
| `netinfo` | `NewLazySystemDLL`/`NewProc`/`Call` for `GetExtendedTcpTable` | `parseTCPTable`, `ipFromBytes`, `portFromBytes`, the two-call pattern, `ipv4Pattern`, `ScanFileForIPv4`, the `TCPTableSource` seam |
| `persist` | `registry.OpenKey`/`ReadValueNames`/`GetStringValue`/`DeleteValue`/`Close` | `matchesTarget`, `extractExePath`, the 4-location loop, hit structs |
| `cleaner` | (none — stdlib `os` only) | `IsProtected`, retry loops, single-level dir scope |
| `config` | the `registry.Key` *type* only | path lists, timing constants |
| `main` | `GetCurrentProcessToken().IsElevated()` | all orchestration + glue |
| `verify` | (none directly) | summary printing, clean/incomplete decision |

### Standard library used
`flag` (CLI parsing), `fmt` (formatted I/O + `%w` error wrapping), `os` (`Stat`, `Remove`, `ReadDir`, `ReadFile`, `Getenv`, `Exit`, `Stderr`), `path/filepath` (`Dir`, `Base`, `Clean`, `Join`), `strings`, `time` (`Sleep`, `Duration`), `regexp`, `encoding/binary` (`LittleEndian.Uint32`), `unsafe` (`Sizeof`, `Pointer`).

---

## 11. Operating System / Network / Database Concepts

No database. No outbound network of `defuse`'s own.

### 11.1 Process discovery & termination — layer by layer

```
defuse (proc)  →  x/sys/windows wrappers  →  kernel32.dll  →  ntdll.dll → syscall (ring 3 → ring 0)
  →  Windows Executive / Object Manager:
       • Toolhelp snapshot: copy the process list (EPROCESS: PID, InheritedFromUniqueProcessId = PPID, ImageFileName)
       • OpenProcess: check caller token vs target security descriptor → HANDLE with requested access mask
       • TerminateProcess: mark terminating, stop all threads, schedule teardown
  →  scheduler / memory manager reclaim threads, address space, handle table (asynchronously)
```

- **PID** — kernel-assigned, **reused** after exit.
- **PPID** — the creator's PID at creation; the parent may already be gone (a reason `KillOrder` only walks *downward* from confirmed roots).
- **Access mask** — `defuse` requests the *narrowest* per task (`PROCESS_QUERY_LIMITED_INFORMATION` to read the path, `PROCESS_TERMINATE` to kill).
- **Ring transition** — user code can't touch kernel structures; every `x/sys` call traps into ring 0.

### 11.2 Registry access — layer by layer

```
defuse (persist)  →  x/sys/windows/registry  →  advapi32.dll  →  ntdll (NtOpenKey/NtEnumerateValueKey/NtDeleteValueKey)
  →  kernel Configuration Manager  →  in-memory hive + hive files (\Windows\System32\Config\SOFTWARE for HKLM; NTUSER.DAT for HKCU)
```

- **Hive** — a tree of keys/values persisted as a file, cached in kernel memory; writes journaled (`.LOG`) for crash consistency.
- **ACLs** — HKCU\...\Run writable by the owning user; HKLM\...\Run requires `Administrators`.
- **Why delete the value, not the key:** the Run key is a shared OS integration point.

### 11.3 Filesystem — `os.Stat` / `os.Remove` / `os.ReadDir` / `os.Chmod`

```
defuse (cleaner)  →  Go os  →  syscall (Windows: GetFileAttributes, DeleteFile, FindFirstFile/Next, SetFileAttributes)
  →  ntdll → I/O Manager → NTFS driver → volume
```

- **Unlink semantics.** `os.Remove` → `DeleteFile` removes the *name*; if another handle is still open, the delete can fail with a sharing violation — the retry loop + `KillSettleDelay` cover this window.
- **Directory removal** requires the directory be empty.
- **`os.Chmod` on Windows** only affects the read-only attribute.

### 11.4 Reading the local TCP table (a kernel query, not networking)

```
defuse (netinfo)  →  GetExtendedTcpTable  →  iphlpapi.dll  →  TCP/IP stack (tcpip.sys) connection table
returns: per IPv4 TCP connection: state, local addr:port, remote addr:port, owning PID
```

- **No packets are sent.** The "attacker IP" is the **remote address** of a connection **owned by a malware PID**.
- **TCP / port / socket recap:** a connection = the 4-tuple (local IP, local port, remote IP, remote port); a **port** is a 16-bit multiplexing number; `dwOwningPid` ties a socket to its creating process — that linkage is why `defuse` can attribute a C2 connection to the malware.
- **`AF_INET`** — IPv4 only; IPv6 C2 is not covered.
- **`0.0.0.0` remote** = a listening/unconnected socket → filtered.

### 11.5 DLL loading (`LazyDLL`)

`iphlpapi.dll` is loaded on first use via `NewLazySystemDLL`, restricting the search to `System32` (mitigates DLL-planting). A missing DLL/export surfaces from `.Call` as a returned error, not a startup crash.

---

## 12. Error Handling

Doctrine: **log every failure, never crash, never report false success.**

| What can fail | Why | Detected | Next | Disposition |
|---|---|---|---|---|
| Missing `-target` | user error | `*target == ""` | `stderr` + usage + `os.Exit(2)` | the *only* hard abort |
| Not elevated | UAC-filtered token | `IsElevated() == false` | `[warn]`, continue | logged |
| `proc.List` snapshot fails | rare | non-nil error | `[warn]`, continue with partial data | logged |
| `proc.ExePath` fails | access denied / process exited | non-nil error | `ExePath` left `""`, process still killed | ignored by design |
| `proc.Kill` fails | already gone / access denied / protected | non-nil error | `[fail]`, **not counted**, next PID | logged |
| Open HKLM key fails | non-admin | non-nil error | `[warn]`, `continue` | logged; HKLM not covered this run |
| `GetStringValue` fails on a value | wrong type | non-nil error | `continue` (skip that value) | ignored |
| `RemoveRegistryPersistence` fails | can't reopen for write / `DeleteValue` errors | non-nil error | `[fail]`, not counted, continue | logged |
| `os.ReadDir` on a Startup folder fails | folder absent / env unset | non-nil error | `continue` to next folder | ignored |
| `RemoveStartupPersistence` fails | file locked / permissions | non-nil error | `[fail]`, not counted, continue | logged |
| `DeleteFile` — protected path | registry value pointed inside `C:\Windows` | `IsProtected` true | error → `[fail]`, not counted | logged (a *safety success*) |
| `DeleteFile` — file locked | killed process still holds handle | `os.Remove` non-nil ×5 | after 5×300 ms, return `lastErr` → `[fail]` | logged |
| `DeleteFile` — not found | already gone | `os.Stat` error | return it → `[fail]` | logged (arguably should be success) |
| `DeleteEmptyMalwareDir` — dir not empty | shared folder | `len(entries) > 0` | return `(false, nil)` — silent | intended |
| `DeleteEmptyMalwareDir` — remove fails | permissions / lingering handle | `os.Remove` non-nil ×5 | `(false, lastErr)` → `[warn]` | logged |
| `netinfo.LiveEndpoints` fails | `iphlpapi` missing / API error | non-nil error | `[warn]`, static IPs only | logged |
| `netinfo.ScanFileForIPv4` fails | file unreadable | non-nil error | `[warn]`, `continue` to next path | logged |
| `verify` re-check fails | rare | non-nil error | `[warn]`; `remainingProcs == nil` → **counts as clean** for that half | logged — subtle gap |

**Recovery.** The only active recovery is `cleaner`'s retry-with-fixed-delay (5 × 300 ms), backed by `main`'s one-time `KillSettleDelay`. Everything else is "log and press on," relying on `verify` + the summary + the `exit 1` to surface incompleteness.

**Error wrapping.** `fmt.Errorf("... %w", err)` preserves the underlying error for a future `errors.Is`/`errors.As` caller, though `defuse` only prints it.

**Gaps for a reviewer:**
1. A failed `verify` re-check yields `remainingProcs == nil` → treated as clean for that dimension.
2. `DeleteFile` on an already-absent file logs `[fail]` even though the goal is met.
3. `verify` never re-checks Startup folders or file existence.

---

## 13. Security Analysis

### 13.1 Privilege requirements
- **Intended:** run **elevated** so HKLM Run/RunOnce and other users' / system processes are in reach.
- **Degraded:** non-elevated still cleans HKCU + per-user Startup + user-owned processes; HKLM ops fail-and-log.
- **Privileges exercised:** `PROCESS_TERMINATE`, `PROCESS_QUERY_LIMITED_INFORMATION` on target processes; registry `SET_VALUE` on HKLM (admin); filesystem delete on user/temp paths. It does **not** enable `SeDebugPrivilege`, so terminating a protected/SYSTEM process may still fail even when elevated.

### 13.2 Trust boundaries — where untrusted data enters

| Untrusted input | Enters at | Danger | Mitigation |
|---|---|---|---|
| `-target` string | `main` flag | drives what gets killed/deleted | none technical — `-dry-run`; `Normalize` widening can over-match |
| Registry value **data** | `persist.extractExePath` → `gatherExePaths` → `cleaner.DeleteFile` | attacker chooses a path; tool deletes it | `cleaner.IsProtected` blocks `C:\Windows\...` only |
| Registry value **name** | `persist.matchesTarget` | attacker names a value to dodge/attract matching | `Normalize` equality |
| Malware **file bytes** | `netinfo.ScanFileForIPv4` (`os.ReadFile` whole file) | huge file → memory pressure; regex FP → noisy IOCs | only `0.0.0.0` filtered |
| Process names/PPIDs | `proc.List`/`KillOrder` | name spoof to dodge/attract; PPID set at creation only | `Normalize` equality; tree descends only from confirmed roots |

### 13.3 Dangerous operations

- **`TerminateProcess` on an operator-named target.** *Necessary:* can't eradicate a running RAT without stopping it. *Wrong:* wrong `-target` (or `Normalize` over-match) kills a critical process. *Protection:* `-dry-run` shows the exact PID list first; no protection against a bad target name.
- **Deleting a file whose path came from a registry value.** *Necessary:* the malware's exe is often only referenced by its Run value. *Wrong:* `Run\Updater = C:\Windows\System32\rundll32.exe evil,Start` → blocked by `IsProtected`; but `C:\Program Files\Vendor\app.exe` (if `Normalize` matches) → **would be deleted**. *Protection:* `C:\Windows` allow-list only; `-dry-run`; "cut at first `.exe`" limits argument injection.
- **`DeleteEmptyMalwareDir`.** *Necessary:* samples drop into a dedicated subfolder. *Protection:* removes **only** the exe's immediate parent, **only** if empty, **never** recursing upward.
- **`RemoveRegistryPersistence`.** *Protection:* value-level only (key untouched); matching keyed on `Normalize(target)`; `-dry-run` prints the exact `HIVE\PATH value "NAME"`.
- **Raw `GetExtendedTcpTable` via `unsafe`.** *Wrong:* struct-layout bug → misread PID or out-of-bounds. *Protection:* explicit bounds check; `TCPTableSource` seam enables unit-testing the parser.

### 13.4 Secrets, exfiltration, network posture
- **No secrets** (no API keys, no config file).
- **No outbound connections.** `defuse` never contacts the C2 address it discovers — a deliberate ethical boundary.
- **Data handling.** Attacker IPs are printed to stdout / included in the operator's report; nothing is transmitted.

### 13.5 Security assumptions
1. The operator supplies a correct, specific target and has reviewed `-dry-run` output.
2. Runs on an isolated analysis VM with a clean snapshot.
3. `C:\Windows` (`%SystemRoot%`) is the *only* directory that must be protected from deletion.
4. The malware isn't actively defending itself beyond a simple watchdog.
5. IPv4 is sufficient for C2 discovery.
6. `Normalize`'s stripping won't collide the target with a critical process name in practice.

### 13.6 Vulnerabilities supported by the code (no invention)
- **Program Files / other-profile deletion.** `IsProtected` only blocks `%SystemRoot%`. A registry value referencing `C:\Program Files\<vendor>\<name>.exe` where `Normalize(<name>) == target` would be deleted, and its now-empty folder removed.
- **`Normalize` over-matching.** `-target "task host"` matches `taskhost.exe`.
- **Regex false-positive IOCs.** No octet-range validation; version strings reported as attacker IPs.
- **`verify` treats a re-check *error* as "clean"** for that dimension (nil slice).
- **TOCTOU windows.** Between `FindMatching` and `Kill`, and between `Kill` and `DeleteFile`, the malware could spawn a child not in `KillOrder` or re-write its Run key faster than the settle delay. `verify` is the net.
- **No IPv6 C2 visibility** (`AF_INET` only).

---

## 14. Data Flow

### 14.1 The target string
```
argv "-target maltrack" → flag.Parse → *target = "maltrack"
  → Normalize("maltrack") = "maltrack"   (in FindMatching; again in persist find funcs; again in verify)
  → compared against Normalize(each process name / reg value name / extracted exe basename / startup filename)
  → stored raw in verify.Summary.Target ; re-used by verify.Run
```

### 14.2 A matched process → a deleted file
```
ProcessEntry32{ProcessID:5012, ParentProcessID:3300, ExeFile:"mal-track.exe\0..."}
  → proc.List → Process{PID:5012, PPID:3300, Name:"mal-track.exe", ExePath:""}
  → FindMatching: Normalize=="maltrack" → ExePath(5012) → Process{..., ExePath:"C:\Users\a\Downloads\Fynloski\mal-track\mal-track.exe"}
  → gatherExePaths → addPath → key "c:\users\a\downloads\fynloski\mal-track\mal-track.exe" → exePaths=[that path]
     (same path also arrives from the registry hit via extractExePath → deduped, not appended twice)
  → deleteFiles → cleaner.DeleteFile: IsProtected? no → Stat ok → Remove (locked) → 300ms → Remove ok
  → cleaner.DeleteEmptyMalwareDir: dir = "...\mal-track"; ReadDir → [] → os.Remove(dir) → (true,nil)
  → summary.FilesDeleted = 1
```
Shape journey: C struct (UTF-16) → Go `Process` (UTF-8, no path) → `Process` with path (2nd syscall) → de-duplicated `[]string` → `error` (nil) from `os.Remove` → an `int` counter → a printed line + the file gone.

### 14.3 A live TCP row → an attacker IP
```
kernel TCP/IP connection table
  → GetExtendedTcpTable (2 calls) → []byte buf
  → parseTCPTable: buf[0:4] LE → numEntries ; row[12:16]=[CB 00 71 07] → "203.0.113.7" ;
                   row[16:20]=[01 BB 00 00] → 443 ; row[20:24] LE → PID 5044
  → Endpoint{PID:5044, IP:"203.0.113.7", Port:443}
  → LiveEndpoints(pidSet={5012,5044}): pidSet[5044] && != "0.0.0.0" → kept
  → collectAttackerIPs: add("203.0.113.7") ; then ScanFileForIPv4 each path
  → summary.AttackerIPs = ["203.0.113.7", ...]
  → verify.printSummary: "Attacker IP(s):         [203.0.113.7 ...]"
```
Shape journey: kernel table → raw `[]byte` → `Endpoint` structs → filtered `[]Endpoint` → de-duplicated `[]string` → one printed line (pasted into the report email's "ATTACKER INFORMATION").

### 14.4 The `Summary` accumulator
```
main creates:   Summary{Target:"maltrack", DryRun:false}     (counters = 0)
after intel:    + AttackerIPs = [...]
after kill:     + ProcessesKilled = N
after registry: + RegistryRemoved = N
after startup:  + StartupRemoved  = N
after files:    + FilesDeleted    = N
verify.Run(summary):  printSummary ; re-query machine → clean bool ; return clean
main:  if !clean → os.Exit(1)
```
`Summary` is passed **by value** to `verify.Run`; `verify` never mutates it — it reads it and does its own fresh queries. That independence is the point.

---

## 15. Real Execution Example

### Setup (machine state)
- Process `mal-track.exe`, PID **5012**, parent `explorer.exe` (PID 3300), running as the logged-in user.
- Child `cmd.exe`, PID **5044**, parent 5012 — a crude watchdog.
- Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` → `Mal-Track` = `"C:\Users\a\Downloads\Fynloski\mal-track\mal-track.exe"`.
- File exists; its folder `...\mal-track\` contains only that exe.
- The exe's bytes contain `127.0.0.1`.
- No live TCP connection from 5012/5044 at scan time. Operator is **elevated**.

### Run 1 — `defuse.exe -target maltrack -dry-run`
```
flag.Parse → target="maltrack", dryRun=true
checkElevation → elevated → (silent)
FindMatching → PID 5012 (ExePath resolved); List → 193 procs
KillOrder(roots=[5012], all): visit(5012) → child 5044 → visit(5044) → append 5044 → append root 5012
  → killTargets = [PID 5044 (cmd.exe), PID 5012 (mal-track.exe)]
  → "Found 1 matching process(es), 2 including children."
FindRegistryPersistence → HKCU\...\Run "Mal-Track" → HIT
FindStartupPersistence → []
exePaths = ["C:\Users\a\Downloads\Fynloski\mal-track\mal-track.exe"]
LiveEndpoints({5044,5012}) → [] ; ScanFileForIPv4(exe) → ["127.0.0.1"] → AttackerIPs=["127.0.0.1"]
killProcesses(dry): "  [dry-run] would kill cmd.exe (PID 5044)" / "  ... mal-track.exe (PID 5012)"  → ProcessesKilled=2
removeRegistryHits(dry): "  [dry-run] would delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run value \"Mal-Track\""  → RegistryRemoved=1
removeStartupHits(dry) → 0
deleteFiles(dry): "  [dry-run] would delete C:\Users\a\Downloads\Fynloski\mal-track\mal-track.exe and its folder if left empty"  → FilesDeleted=1
verify.Run:
  === Summary ===
  Target:                 maltrack
  Attacker IP(s):         [127.0.0.1]
  Processes would remove: 2
  Registry values would remove: 1
  Startup files would remove: 0
  Files would remove: 1
  [dry-run] no changes were made, so nothing to verify.
exit code: 0     (machine still infected — dry run changed nothing)
```

### Run 2 — `defuse.exe -target maltrack`
```
(discovery identical)
killProcesses: proc.Kill(5044) ok → "  [ok] killed cmd.exe (PID 5044)"   (watchdog dies FIRST)
               proc.Kill(5012) ok → "  [ok] killed mal-track.exe (PID 5012)"
  → ProcessesKilled=2 ; time.Sleep(250ms)
removeRegistryHits: RemoveRegistryPersistence → OpenKey(SET_VALUE) → DeleteValue("Mal-Track") ok
  → "  [ok] deleted HKCU\Software\Microsoft\Windows\CurrentVersion\Run value \"Mal-Track\""  → RegistryRemoved=1
removeStartupHits → 0
deleteFiles: DeleteFile: IsProtected? no → Stat ok → Remove (locked) → 300ms → Remove ok
  → "  [ok] deleted C:\Users\a\Downloads\Fynloski\mal-track\mal-track.exe"
  DeleteEmptyMalwareDir: dir "...\mal-track"; ReadDir → [] → Chmod; Remove(dir) → (true,nil)
  → "  [ok] removed now-empty folder C:\Users\a\Downloads\Fynloski\mal-track"  → FilesDeleted=1
verify.Run:
  === Summary === (Processes removed: 2 / Registry values removed: 1 / Startup files removed: 0 / Files removed: 1)
  Verifying cleanup...
  FindMatching("maltrack") → []            → [OK]   no matching process remains
  FindRegistryPersistence("maltrack") → [] → [OK]   no matching registry persistence remains
  Result: CLEAN
exit code: 0
```

If the file had stayed locked past 5 retries: step 12 prints `[fail] delete ...`, `FilesDeleted` stays 0 — **but** `verify` (process + registry only) still prints `Result: CLEAN` and exits 0. The failure is visible only in the `[fail]` line and `Files removed: 0`.

---

## 16. Why This Design?

- **Why kill *before* removing persistence?** *Alternative:* remove the Run key first, then kill — a still-running process can detect the deletion or rewrite the key in the window. *Chosen:* kill the whole tree, wait `KillSettleDelay`, then de-persist. *Disadvantage:* if a kill fails, a surviving process could re-persist — but `verify` catches it and exits 1.
- **Why run persistence + file cleanup even with no matched process?** A dormant infection lives entirely in a Run key / Startup file. Discovery of processes and of persistence are independent.
- **Why a process *tree* kill, deepest-first?** `TerminateProcess` doesn't cascade; a watchdog child survives and relaunches the parent. `KillOrder`'s post-order DFS → children before parents. *Disadvantage:* O(N·M) walk (trivial at these sizes; a PPID→children map would be O(N+M)).
- **Why `map[uint32]bool` for sets?** Membership is tested inside loops (`pids[e.PID]` per TCP row; `!seen[p.PID]` per candidate child). Map = O(1); slice = O(n²) overall.
- **Why an `interface` in front of one implementation?** `parseTCPTable` (offsets, endianness, bounds) is the bug-prone part and is untestable welded to a syscall. *Disadvantage:* global mutable state.
- **Why delete the registry *value*, never the *key*?** Run/RunOnce are OS integration points that legitimate software also populates.
- **Why a hard-coded `C:\Windows` allow-list?** *Alternative:* signature checks / a policy engine — far more code and still fallible. *Chosen:* the single highest-value invariant as a cheap prefix check + `-dry-run` for everything else. *Disadvantage:* doesn't protect `C:\Program Files`, other profiles, or resolve junctions.
- **Why single-level directory deletion only?** Recursively removing empty parents would delete `Downloads`.
- **Why one package per concern?** Each concern has a distinct OS surface; clean import edges (a DAG); `verify` re-uses `proc`+`persist` discovery; `proc.Normalize` is the single matching authority.
- **Why `flag` (stdlib) not cobra/urfave?** Three flags, no subcommands; zero-dependency ethos.
- **Why exit codes 0/1/2?** So an IR runbook can branch: `2` = fix your command, `1` = machine not clean, `0` = proceed.
- **Why `%w` error wrapping if nothing inspects it?** Cheap forward-compatibility.

---

## 17. Interview / Oral Defense Questions

### Beginner

**B1. What does `defuse` do, in one sentence?** — Given a malware process name, it kills that process and its children, removes its Run/RunOnce and Startup persistence, deletes its files, records attacker IPs, and verifies the machine is clean. *(main.go orchestration; README §1.)*

**B2. Required flag and what happens without it?** — `-target`. Without it: `defuse: -target is required`, usage, exit code 2 (usage error, vs 1 = ran-but-failed). *(main.main.)*

**B3. What does `-dry-run` do?** — All discovery + reporting, no destructive action; each step prints `would …`; verification is skipped. *(dryRun branch in the four helpers; verify.Run.)*

**B4. Why the "not elevated" warning?** — Without admin it can't read/write HKLM or touch other users' processes; UAC gives even admins a filtered token until they elevate. *(main.checkElevation.)*

**B5. Which registry locations does it check?** — `Run` and `RunOnce` under both HKCU and HKLM — four keys. `Run` executes at every logon; `RunOnce` once then self-deletes. *(config.RegistryLocations.)*

**B6. The two Startup folders?** — `%APPDATA%\...\Startup` (per-user, user-writable) and `%ProgramData%\...\Startup` (all-users, admin-writable); Windows launches their contents at logon. *(config.StartupFolders.)*

**B7. What does `Normalize("Mal-Track.EXE")` return and why?** — `"maltrack"`: lowercases, trims `.exe`, strips every non-alphanumeric. So the same malware written five ways is comparable. *(proc.Normalize.)*

**B8. Why kill children before the parent?** — A watchdog child would relaunch a parent killed first. *(proc.KillOrder — post-order DFS.)*

**B9. Does `defuse` connect to the attacker's server?** — No. It only *reads* the local TCP table and the malware file's bytes; it records and reports IPs, never contacts them. *(netinfo — no outbound `net.Dial`.)*

**B10. Possible exit codes?** — `0` clean (or successful dry-run), `1` verification found a survivor, `2` usage error. *(main.)*

### Intermediate

**I1. Walk the nine-step flow and justify the ordering.** — Discovery → persistence discovery → path collection → attacker-IP intelligence → **kill tree** → settle delay → remove registry → remove Startup → delete files → verify. Kill precedes persistence removal so a running process can't rewrite its Run key mid-cleanup; persistence/file cleanup run even with zero matched processes (dormant infection). *(main.main; README §1.)*

**I2. How does `KillOrder` guarantee children-before-parents and avoid infinite loops?** — Recursive closure doing post-order DFS on the PPID graph (append a node after recursing into its children); a `map[uint32]bool` visited-set dedupes and stops PPID-reuse cycles. *(proc.KillOrder.)*

**I3. Explain the two-call pattern in `windowsTCPTable.Read`.** — First call with a NULL buffer returns `ERROR_INSUFFICIENT_BUFFER` (122) — the *expected* result — and writes the size; then allocate `make([]byte, size)` and call again expecting `0`. *(netinfo.windowsTCPTable.Read.)*

**I4. Why is the PID read little-endian but IP/port not?** — IP/port are copied from the wire (network = big-endian) and IPHLPAPI keeps them that way; the PID is a local kernel integer stored native (little-endian). *(parseTCPTable, ipFromBytes, portFromBytes.)*

**I5. How is `LiveEndpoints` testable without real connections?** — `netinfo.Source` is a package variable of interface type `TCPTableSource`; a test assigns a stub whose `Read()` returns a hand-built `[]Endpoint`. *(netinfo.)*

**I6. Why does `main` call `proc.List()` twice?** — Once inside `FindMatching` for current matches, once directly as the universe for `KillOrder`. Minor inefficiency, not a bug; the snapshot could be shared. *(main.main.)*

**I7. What does `extractExePath` do with `"\??\C:\x\m.exe" -silent`, and its blind spot?** — Trims whitespace, strips `\??\`, strips quotes, cuts at the first `.exe` → `C:\x\m.exe`. Blind spot: `cmd.exe /c C:\x\m.exe` → `cmd.exe`, so a wrapper command line is only caught if the *value name* matches. *(persist.extractExePath, matchesTarget.)*

**I8. Why `KillSettleDelay`, and the backstop?** — `TerminateProcess` returns before the OS releases the dead process's file handle, so an immediate `os.Remove` on the exe often fails; the 250 ms sleep helps and `cleaner.DeleteFile`'s 5×300 ms retry loop is the backstop. *(main; cleaner.DeleteFile.)*

**I9. The two `cleaner` safety guards and what each prevents?** — (1) `IsProtected` refuses paths under `%SystemRoot%` — prevents deleting `C:\Windows\System32\cmd.exe` via a crafted Run value. (2) `DeleteEmptyMalwareDir` removes only the exe's *immediate* parent, only if empty, never recursing — prevents deleting `Downloads`. *(cleaner.)*

**I10. What does `verify.Run` re-check, and not?** — Re-runs `proc.FindMatching` and `persist.FindRegistryPersistence`; `CLEAN` iff both empty. Does *not* re-scan Startup folders or confirm files are gone. *(verify.Run.)*

### Advanced

**A1. A race that survives the ordering, and how `verify` mitigates it.** — `KillOrder` is computed from a snapshot; between it and the kills the malware could spawn a *new* child not in the list, which re-persists after registry cleanup. `verify` re-queries the machine and returns false → `os.Exit(1)`. *(proc.KillOrder vs main timing; verify.Run.)*

**A2. `verify` treats a re-check *error* as success — show the path and the risk.** — `remainingProcs, err := proc.FindMatching(...)`; on `err != nil` it logs `[warn]` but `remainingProcs` is `nil`, so `len(...) == 0` is true and `clean` can still be true. A transient failure turns an infected result into `CLEAN` / exit 0. *(verify.Run.)*

**A3. Which deletions escape `IsProtected`, and why?** — It's a lowercased prefix test against `%SystemRoot%\` only. `C:\Program Files`, third-party driver locations outside `System32`, other user profiles, mapped drives are not protected; no junction/symlink or 8.3 short-name resolution. *(cleaner.IsProtected, DeleteFile, DeleteEmptyMalwareDir.)*

**A4. Why is `Normalize` arguably too aggressive? A concrete collision.** — Stripping all non-alnum: `Normalize("task host") == "taskhost"` and `Normalize("svc-host") == "svchost"`. A fat-fingered `-target "svc host"` would match `svchost.exe`. *(proc.Normalize.)*

**A5. The static IP scan has no octet-range check — consequences, why accepted?** — Matches `999.999.999.999` and version fragments like `1.2.3.4`; only `0.0.0.0` filtered. Accepted because missing the real hard-coded C2 (when the sample isn't beaconing) is worse than a dismissible false IOC. *(netinfo.ipv4Pattern, ScanFileForIPv4.)*

**A6. The `unsafe.Pointer`→`uintptr` rule, and the danger of violating it.** — The GC may move heap objects; a stored `uintptr` isn't tracked and can dangle after a GC. The conversion is only safe *inside the syscall Call's argument list*. `windowsTCPTable.Read` does it inline, never caching. *(netinfo.windowsTCPTable.Read.)*

**A7. `RemoveStartupPersistence` doesn't go through `cleaner` — bug or fine?** — Defensible: Startup folders are never under `%SystemRoot%`, so the guard adds nothing. Critique: it skips the retry loop (a briefly-locked Startup `.exe` fails on one attempt) and `FindStartupPersistence` won't match `.lnk` names at all (`x.lnk` → `xlnk`), missing the most common real-world Startup persistence — visible only under `-verbose`. *(persist.RemoveStartupPersistence, FindStartupPersistence, proc.Normalize.)*

**A8. Why `TerminateProcess`, and the `1` argument?** — Graceful mechanisms can be caught/ignored; a hostile process ignores them. `TerminateProcess` is unconditional. The `1` is the exit code the terminated process reports; it doesn't cascade to children. *(proc.Kill.)*

**A9. `AF_INET` only — the gap and how to close it.** — IPv4 table only; an IPv6 C2 connection is invisible. To close: a second call with `AF_INET6 = 23` against the IPv6 sibling table (`MIB_TCP6ROW_OWNER_PID`, larger rows with 16-byte addresses + scope IDs), parse that layout, merge; plus an IPv6 regex for the static scan. *(netinfo constants and Read.)*

**A10. Make `verify` trustworthy — what would you change?** — (1) Re-check Startup folders and re-`os.Stat` every path in `exePaths`; fold into `clean`. (2) On any re-check `error`, force `INCOMPLETE`. (3) Compare against the summary counters and flag mismatches. (4) Optionally re-open each registry value by name to confirm `ERROR_FILE_NOT_FOUND`. *(verify.Run, verify.Summary.)*

---

## 18. "Explain This Code to an Interviewer"

**The whole tool.**
> "`defuse` is a Windows malware-eradication CLI in Go. You give it one process name. It runs a fixed pipeline: first it discovers — snapshots the process table, finds every process whose *normalized* name matches, and expands that into the full process tree so it catches watchdog children; in parallel it scans the four Run/RunOnce registry keys and the two Startup folders for matching persistence. Then it gathers intelligence — reads the kernel's TCP connection table and keeps the remote endpoints owned by those PIDs, and regex-scans the malware's own bytes for hard-coded IPs. Only then does it act, and the order is deliberate: kill the tree deepest-child-first, wait 250 ms for handles to release, then strip the registry values, then the Startup files, then delete the executables and — if the exe lived in its own now-empty folder — that folder. Finally it re-queries the machine and prints `CLEAN` or `INCOMPLETE`, exiting non-zero on incomplete. There's a `-dry-run` that does all the discovery and none of the destruction, and two hard safety guards: it never deletes anything under `C:\Windows`, and it never walks more than one directory level up."

**`proc.KillOrder`.**
> "It takes the matched malware processes and the full snapshot and returns every process in those subtrees, ordered so a child always comes before its parent. It's a recursive closure doing a post-order depth-first walk of the parent-PID graph: for each unvisited child it recurses first and appends the child only after the recursion returns, so the deepest descendants land first. A `map[uint32]bool` visited-set dedupes shared children and makes it safe against PID-reuse cycles. The ordering is the point — kill the parent first and a watchdog child relaunches it."

**`netinfo.windowsTCPTable.Read` + `parseTCPTable`.**
> "This is the raw syscall path to `GetExtendedTcpTable` in `iphlpapi.dll`, loaded lazily. It's the classic Win32 two-call idiom: call once with a null buffer to get the size — it *returns* `ERROR_INSUFFICIENT_BUFFER`, which is the success signal here — then allocate exactly that many bytes and call again expecting zero. The buffer is a C table: a 4-byte little-endian row count, then 24-byte rows. Per row I take bytes 12–15 as the remote IPv4 address, 16–19 as the remote port, 20–23 as the owning PID. The subtlety is byte order: the address and port come off the wire so they're network byte order — I format the address bytes in place and rebuild the port as `b0<<8 | b1`; the PID is a local kernel integer so it's little-endian. It's wrapped behind a one-method interface so the parser can be unit-tested against a hand-built buffer."

**`cleaner.DeleteFile`.**
> "Delete one file, safely. First the trust boundary: if the path is under the Windows directory — a lowercased prefix check against `%SystemRoot%` — it refuses, because a registry value we parsed could point at `cmd.exe`. Then it stats the file, then tries `os.Remove` up to five times with 300-ms gaps. The retry exists because `TerminateProcess` returns before the OS has fully released the dead process's handle on its own executable, so the first delete usually loses a race; a second or third attempt wins."

**`persist.FindRegistryPersistence` + `matchesTarget`.**
> "It opens each of the four keys — Run and RunOnce under HKCU and HKLM — for read, enumerates the value names, and for each value reads its string data. A value is a hit two ways: its *name* normalizes to the target, or the executable *inside its command line* does — that second path matters because malware often uses an innocuous value name pointing at its real binary. Removal reopens the key for write and calls `DeleteValue` on just that one value — never the key itself, because Run and RunOnce are shared OS keys. Non-admin runs fail to open HKLM; that's logged as a warning and we continue with HKCU coverage."

**`verify.Run`.**
> "This is the proof step, and it's deliberately independent — it doesn't trust the counters we accumulated, it re-queries the live machine. It re-runs the process match and the registry match and declares `CLEAN` only if both are empty, returns that boolean, and `main` turns a false into exit code 1. I'd be upfront in a review that it doesn't currently re-check the Startup folders or re-stat the deleted files, so `CLEAN` is a slightly narrower claim than the summary above it."

---

## 19. Common Mistakes

1. **"It'll run on my Linux/Mac dev box."** It won't compile — `x/sys/windows` is Windows-only. `GOOS=windows GOARCH=amd64 go build`.
2. **Assuming `proc.List` fills `ExePath`.** It sets only `PID`, `PPID`, `Name`. `ExePath` is filled only by `FindMatching`, only for matched PIDs.
3. **Thinking `Normalize` just lowercases and trims `.exe`.** It also strips every non-alphanumeric character.
4. **Swapping the two lines in `KillOrder`'s `visit`.** `visit(p.PID)` must precede `order = append(order, p)` — otherwise parents die first.
5. **Expecting `GetExtendedTcpTable`'s first call to "succeed."** It returns `122` (`ERROR_INSUFFICIENT_BUFFER`) — that *is* the good path.
6. **Byte-order confusion in `parseTCPTable`.** IP/port are network (big-endian); PID is native (little-endian).
7. **Believing `CLEAN` means "everything was removed."** `verify` re-checks processes + registry only. Read the whole output.
8. **Assuming `IsProtected` protects the whole OS.** It's a prefix check against `%SystemRoot%\` only.
9. **Thinking Startup `.lnk` shortcuts are detected.** `Normalize("x.lnk")` → `xlnk` ≠ target. Only bare `.exe`/extensionless names match; `.lnk` persistence is only *shown* under `-verbose`.
10. **Removing `KillSettleDelay` "because the retry loop handles it."** It does — but every file delete then wastes a failed attempt + 300 ms.
11. **Passing a full path to `-target`.** It wants a bare process *name* (`maltrack`).
12. **Editing matching logic in multiple files.** There's one authority: `proc.Normalize`.
13. **Expecting non-zero exit on partial failure of file/Startup removal.** Only a surviving *process* or *registry value* makes `verify` return false → exit 1.
14. **Treating `AttackerIPs` as a validated blocklist.** It can contain regex false positives.

---

## 20. Final Project Summary

### What I MUST understand
1. **The fixed pipeline and why the order is fixed** — kill the process tree *before* removing persistence; run persistence + file cleanup *even with zero matched processes*.
2. **`proc.Normalize`** — the single matching authority; lowercase + trim `.exe` + strip non-alphanumerics.
3. **`proc.KillOrder`** — post-order DFS over the PPID graph → children before parents; `map` visited-set.
4. **`netinfo` two ways** — `LiveEndpoints` (kernel TCP table, filtered by owning PID) *and* `ScanFileForIPv4` (regex over the binary).
5. **The two-call Win32 size idiom** and the **mixed byte order** in `parseTCPTable`.
6. **`persist`** — Run/RunOnce under HKCU+HKLM and both Startup folders; find *and* remove side by side; delete the **value**, never the **key**.
7. **`cleaner`'s two guards** — never delete under `%SystemRoot%`; never walk more than one directory level up; plus retry-with-backoff.
8. **`verify`** — an *independent* re-query, not a trust of counters; but it only re-checks processes + registry.
9. **`TCPTableSource` interface** — a dependency-injection test seam for the byte-parsing.
10. **Exit codes** 0 / 1 / 2 as the machine-readable verdict; every failure logged, never a silent success.
11. **The honest weaknesses** — `IsProtected` is `%SystemRoot%`-only; `.lnk` Startup entries aren't matched; regex IPs can be false positives; `verify` can read a re-check error as "clean"; `proc.List` runs twice.

### Architecture in 30 seconds
> "A Go Windows CLI. One flag: the malware's process name. It discovers the matching process and its whole child tree, plus Run/RunOnce and Startup-folder persistence; collects attacker IPs from the live TCP table and from the binary's bytes; then — in this order — kills the tree child-first, strips the registry values, strips the Startup files, deletes the executables and their empty drop-folder; finally re-checks the machine and exits 0 for clean, 1 for incomplete. `-dry-run` reports without touching anything. Six packages, one per OS concern, no concurrency, one external dependency."

### Architecture in 2 minutes
> "`defuse` is an incident-response eradication tool. `main.go` is pure orchestration — parses three flags (`-target` required, `-dry-run`, `-verbose`), checks token elevation and warns if not admin, then runs a nine-step pipeline. Discovery: `proc.FindMatching` snapshots the process table with `CreateToolhelp32Snapshot`, keeps processes whose `proc.Normalize`d name equals the target, resolves each full image path; `proc.KillOrder` expands those into their complete subtrees via a post-order DFS on parent-PID so children precede parents. `persist.FindRegistryPersistence` scans Run and RunOnce under HKCU and HKLM — a value hits if its name or the executable in its command line normalizes to the target; `persist.FindStartupPersistence` scans the per-user and all-users Startup folders. Intelligence: `netinfo.LiveEndpoints` reads the kernel's owner-PID TCP table through `GetExtendedTcpTable` and keeps the remote endpoints belonging to the doomed PIDs; `netinfo.ScanFileForIPv4` regex-scans the malware bytes as a fallback. Then the destructive phase, which every step skips-and-logs under `-dry-run`: `proc.Kill` (`OpenProcess`+`TerminateProcess`) walks the kill order child-first; a 250 ms settle delay lets file handles close; `persist.RemoveRegistryPersistence` calls `DeleteValue` on just the offending value; Startup files are unlinked; `cleaner.DeleteFile` deletes each executable — refusing anything under `C:\Windows` and retrying five times for the post-kill file-lock race — and `cleaner.DeleteEmptyMalwareDir` removes the exe's immediate parent folder only if it's now empty, never recursing upward. `verify.Run` then independently re-runs the process and registry discovery and prints `CLEAN` only if both are empty, returning a boolean that becomes exit code 0 or 1. The decisions worth defending: kill-before-de-persist to win the race; persistence cleanup regardless of process presence; value-not-key registry deletion; the `%SystemRoot%` allow-list and single-level directory scope as the two hard safety rails; and a `TCPTableSource` interface so the fiddly byte-layout parsing is unit-testable."

### Deep technical explanation
See §6 (function-by-function), §11 (the OS layers each package traverses), §9 (every concept), §12 (the can-fail table and the three gaps), §13 (privilege model, trust boundaries, code-supported vulnerabilities). §14 traces the four key data journeys; §15 is a complete dual-run trace.

### Most important functions
| Function | Role |
|---|---|
| `main.main` | The nine-step orchestration; the only place the order lives |
| `proc.Normalize` | Single matching authority — canonicalizes every name compared anywhere |
| `proc.List` | `CreateToolhelp32Snapshot` iteration → `[]Process{PID,PPID,Name}` |
| `proc.FindMatching` | Filters `List` by normalized name; resolves image paths; reused by `verify` |
| `proc.KillOrder` | Post-order DFS on PPID graph → subtree, children-first |
| `proc.Kill` | `OpenProcess(PROCESS_TERMINATE)` + `TerminateProcess` |
| `netinfo.windowsTCPTable.Read` + `parseTCPTable` | Two-call `GetExtendedTcpTable`; byte-layout parse (mixed endianness) |
| `netinfo.LiveEndpoints` | Filters the TCP table to the doomed PIDs, drops `0.0.0.0` |
| `netinfo.ScanFileForIPv4` | Static fallback: regex IPv4 over the binary's bytes |
| `persist.FindRegistryPersistence` / `matchesTarget` / `extractExePath` | Detect Run/RunOnce hits by value-name or embedded exe path |
| `persist.RemoveRegistryPersistence` | `DeleteValue` — the value, never the key |
| `persist.FindStartupPersistence` / `RemoveStartupPersistence` | Startup-folder detect/unlink (no `.lnk` match) |
| `cleaner.IsProtected` | The `%SystemRoot%` deletion guard |
| `cleaner.DeleteFile` | Guarded, retried unlink (post-kill lock race) |
| `cleaner.DeleteEmptyMalwareDir` | Single-level empty-parent removal |
| `verify.Run` | Independent re-check → `CLEAN`/`INCOMPLETE` → exit 0/1 |
| `main.checkElevation` | Token elevation state → warn-only |

### Most important concepts
Access tokens / UAC elevation · Toolhelp process snapshot · Windows HANDLE + `defer` cleanup · Windows Registry (hives, HKCU vs HKLM, Run vs RunOnce) · Startup-folder persistence · process tree / PPID / post-order DFS · `map` as a set · Go interface as a dependency-injection test seam · raw syscall via `LazyDLL` / `unsafe.Pointer`→`uintptr` inline rule · the two-call "size then data" Win32 idiom · endianness / network byte order · RE2 regular expressions · `TerminateProcess` + `KillSettleDelay` · trust boundary / `%SystemRoot%` allow-list · single-level directory-deletion scope · dry-run + independent verification · process exit codes as a verdict · log-every-failure / never-false-success doctrine.
