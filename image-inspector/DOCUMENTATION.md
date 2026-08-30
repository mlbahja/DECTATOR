# `image-inspector` — Complete Technical Documentation

> A command-line **digital image forensics** tool in Python: extracts EXIF metadata (incl. GPS → decimal degrees + a Google Maps link) and performs basic **LSB steganography detection** looking for an embedded PGP public-key block.
> Entry point: `image_inspector.py`. Logic: `modules/`. Companion encoder: `Message_Hide_in_image/HideMessageinImage.py`.

---

## 1. Project Overview

### Simple explanation

Every photo file carries **hidden text about itself** that you don't see when you look at the picture: which camera took it, the exact date/time, the orientation, and — for phone photos with location on — the **GPS coordinates of where it was taken**. That block of "data about the data" is called **metadata** (specifically **EXIF** for photos).

Separately, it is possible to **hide a secret message *inside* the picture's pixels** so subtly that the image looks unchanged to the human eye. That's called **steganography**. The most common beginner technique flips the very last bit of each colour value.

`image-inspector` is a small tool that does two jobs from the terminal:

- **`-m`** — read out all the EXIF metadata (and if there's GPS, convert it to normal latitude/longitude and print a Google Maps link).
- **`-s`** — pull the last bit out of every red/green/blue value, glue those bits back into text, and check whether a hidden **PGP public key block** is sitting in there.

`-o file` saves whatever it prints to a text file.

There is also a **separate companion script** (`Message_Hide_in_image/HideMessageinImage.py`) that does the *opposite* — it hides a message inside a PNG — so you can generate a test image and then detect it.

### Technical explanation

`image-inspector` is a Python 3.10+ CLI built on **Pillow** (PIL fork) with an `argparse` front end and a `modules/` package split by concern:

| Module | Responsibility | Key Pillow API used |
|---|---|---|
| `modules/utils.py` | Validate the input path (exists, is a file, allowed extension, openable as an image) | `Image.open().verify()` |
| `modules/metadata.py` | Pull the EXIF IFD-0 tags, name them, filter binary/GPS, merge in GPS decimals | `Image.getexif()`, `PIL.ExifTags.TAGS` |
| `modules/gps.py` | Read the GPS sub-IFD (tag `34853`), convert DMS rationals → signed decimal degrees, build a Maps URL | `exif.get_ifd(34853)`, `PIL.ExifTags.GPSTAGS` |
| `modules/steganography.py` | Extract per-channel LSBs → bytes → UTF-8 text → substring-search for a PGP block | `Image.convert("RGB").getdata()` |
| `modules/output.py` | Persist a `dict` or `str` result to a text file (write or append) | plain file I/O |
| `image_inspector.py` | Arg parsing, orchestration, top-level error catch | `argparse` |

**Problem it solves.** Two everyday forensics/OSINT/CTF needs: (1) *what does this image reveal about its origin* (camera, timestamp, **where it was taken**), and (2) *is something hidden in it*. It packages the manual steps (open with an EXIF viewer; write an LSB-extraction script) behind one command with file output.

**Main objective.** Given an image path and a mode flag, print (and optionally save) either its EXIF metadata with human-readable tag names and decoded GPS, or the result of a naive LSB steganalysis for a PGP key block.

**Who uses it.** Digital-forensics / OSINT learners, CTF players (stego and metadata challenges are extremely common), and security-education contexts (the README is explicit about ethical/authorized use).

**Technologies / libraries.**
- **Language:** Python 3.10+.
- **Dependencies (`requirements.txt`):** `pillow==12.3.0` (used everywhere), `piexif==1.1.3` (**declared but never imported** — see §10).
- **Standard library:** `argparse`, `pathlib.Path`.
- **Companion script** additionally uses `Image.putdata`.

**Main features.**
1. EXIF metadata dump with tag-ID → name translation.
2. GPS extraction: DMS-rational → signed decimal degrees, hemisphere sign from `GPSLatitudeRef`/`GPSLongitudeRef`, plus a ready `https://maps.google.com/?q=lat,lon` link.
3. Basic LSB steganography detection for a `-----BEGIN PGP PUBLIC KEY BLOCK-----` … `-----END …-----` block.
4. `-o` output to a text file; when `-m -s -o` are combined, the stego result is **appended** after the metadata.
5. Input validation with typed exceptions (`FileNotFoundError`, `ValueError`, `OSError`).
6. A companion encoder to produce test images (`HideMessageinImage.py`).

---

## 2. Project Architecture

### 2.1 Runtime / data-flow view

```
                         user @ terminal
                              │  python image_inspector.py [-m] [-s] [-o FILE] <image>
                              ▼
                   ┌────────────────────────┐
                   │   image_inspector.py    │  parse_arguments() → argparse.Namespace
                   │        main()           │  orchestration + top-level try/except
                   └───────────┬────────────┘
                               │ validate_image(args.image)
                               ▼
                     ┌───────────────────┐
                     │ modules/utils.py   │  Path checks + Image.open().verify()
                     └───────────────────┘
              ┌──────────────── if args.metadata ───────────────┐
              ▼                                                  │
   ┌────────────────────┐        get_ifd(34853)        ┌────────────────────┐
   │ modules/metadata.py │ ───────────────────────────► │  modules/gps.py    │
   │ extract_metadata()  │ ◄─── {Latitude,Longitude,   │ extract_gps()      │
   │  Image.getexif()    │       Google Maps}          │ convert_to_degrees │
   │  TAGS name-map      │                              └────────────────────┘
   └─────────┬──────────┘
             │ dict {tag_name: value, ...}
             ▼
   ┌────────────────────┐   (if args.output)   ┌────────────────────┐
   │  print to stdout    │ ───────────────────► │ modules/output.py  │  save_output(dict|str, file, append)
   └────────────────────┘                       └────────────────────┘
              ┌──────────────── if args.steganography ──────────┐
              ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │ modules/steganography.py                                          │
   │ extract_lsb_bits()  Image.convert("RGB").getdata() → [r&1,g&1,b&1,…]│
   │ bits_to_bytes()     group 8, MSB-first → [0..255]                  │
   │ bytes_to_text()     bytes(...).decode("utf-8", errors="ignore")    │
   │ detect_pgp_key()    text.find(BEGIN) … text.find(END) → slice|None  │
   └───────────────────────────┬──────────────────────────────────────┘
                               ▼  (print; if args.output → save_output, append=args.metadata)

  ── separate, not imported by the CLI ──
   Message_Hide_in_image/HideMessageinImage.py :  text_to_bits() → hide_message() → Image.putdata() → save PNG
```

### 2.2 Import graph (compile-time)

```
image_inspector.py
   ├─ modules.utils         (validate_image)
   ├─ modules.metadata       (extract_metadata) ──► modules.gps (extract_gps, convert_to_degrees)
   ├─ modules.output         (save_output)
   └─ modules.steganography  (extract_lsb_bits, bits_to_bytes, bytes_to_text, detect_pgp_key)

modules.utils         ──► pathlib.Path, PIL.Image
modules.metadata      ──► PIL.Image, PIL.ExifTags.TAGS, modules.gps
modules.gps           ──► PIL.ExifTags.GPSTAGS
modules.steganography ──► PIL.Image
modules.output        ──► (stdlib only)

Message_Hide_in_image/HideMessageinImage.py ──► PIL.Image   (standalone; nothing imports it)
```

**Observations:**
- The CLI package is a small **DAG**: only `metadata → gps` is an inter-module edge; the rest are leaves off `image_inspector.py`.
- `modules/__init__.py` is **empty** — it just marks `modules/` as a package so `from modules.x import y` works.
- The encoder is **completely detached** — it is neither imported nor invoked by the CLI; it exists to *produce* test inputs.
- **No classes.** Everything is module-level functions. State is passed as arguments and return values (a `dict` for metadata, a `list[int]` for bits, a `str` for text).
- `tests/test_metadata.py` and `tests/test_steganography.py` exist but are **empty files** — there is no automated test suite; `test.sh` is a shell smoke test.

### 2.3 Component-by-component

**`image_inspector.py`** — the CLI. `parse_arguments()` builds the `argparse` parser (flags `-m/--metadata`, `-s/--steganography`, `-o/--output FILE`, positional `image`) and enforces "at least one of `-m`/`-s`". `main()` calls `validate_image`, then runs the metadata branch and/or the stego branch, printing results and optionally saving them. A single `try/except Exception` wraps the whole body and prints `Error: {e}` (so the process still exits `0`).

**`modules/utils.py`** — `validate_image(image_path)`: `Path.exists()`, `Path.is_file()`, extension ∈ `{.jpg,.jpeg,.png,.bmp,.tiff}`, then `Image.open(...).verify()` inside `try/except` (re-raised as `OSError`). Returns `True` on success, raises a typed exception otherwise. *(Contains a stray `print('ENTER to THE function -------')` as its first statement — debug cruft; see §12/§19.)*

**`modules/metadata.py`** — `extract_metadata(image_path)`: opens the image, `getexif()`; if empty returns `{}`. Calls `extract_gps(exif_data)` and, if it returns a dict, injects `Latitude`, `Longitude`, `Google Maps` into the result. Then iterates `exif_data.items()`: maps each numeric `tag_id` to a name via `PIL.ExifTags.TAGS`, **skips values that are `bytes`** and the raw `GPSInfo` entry, and stores the rest. Any failure is re-raised as `Exception(f"Error extracting metadata: {e}")`.

**`modules/gps.py`** — `extract_gps(exif_data)`: `exif_data.get_ifd(34853)` (the GPS sub-IFD, tag `0x8825`), wrapped in `try/except KeyError → None`. Names the sub-tags via `GPSTAGS`. Requires all of `GPSLatitude`, `GPSLatitudeRef`, `GPSLongitude`, `GPSLongitudeRef`; otherwise `None`. Converts lat/lon via `convert_to_degrees`, applies a negative sign for `S`/`W` hemispheres, returns `{Latitude, Longitude, "Google Maps": "https://maps.google.com/?q=lat,lon"}`. `convert_to_degrees(value)` takes a 3-element sequence (degrees, minutes, seconds) of rationals, `float()`s each (returning `None` on `ValueError`/`TypeError`), rejects `NaN` via the `x != x` idiom, and returns `deg + min/60 + sec/3600`.

**`modules/steganography.py`** — four pure functions forming a pipeline: `extract_lsb_bits(path)` → `list[int]` of 0/1 (R,G,B LSB of every pixel, image forced to RGB); `bits_to_bytes(bits)` → `list[int]` 0–255 (8 bits per byte, **MSB-first**, trailing partial group dropped); `bytes_to_text(bytes_list)` → `str` (`bytes(...).decode("utf-8", errors="ignore")`); `detect_pgp_key(text)` → the substring from `-----BEGIN PGP PUBLIC KEY BLOCK-----` through `-----END PGP PUBLIC KEY BLOCK-----`, or `None`. *(Contains stray `print("extract lbs bits -----*")` / `print("test")`.)*

**`modules/output.py`** — `save_output(data, filename, append=False)`: opens `filename` in `"a"` or `"w"` mode (UTF-8); if `data` is a `dict`, writes `key: value` lines; otherwise writes `str(data)` + newline. Prints `Data saved in {filename}`. Failures re-raised as `Exception`.

**`Message_Hide_in_image/HideMessageinImage.py`** — the encoder. `text_to_bits(text)` → an 8-bit-per-char binary string via `format(ord(c), '08b')`. `hide_message(input_image, output_image, message)` appends a `"###END###"` marker, converts to bits, opens the input as RGB, walks pixels replacing the LSB of R, G, B (in that order) with successive message bits, `putdata()`s the modified pixels, saves (as **PNG** in the `__main__` demo, because LSBs must survive losslessly). Raises `ValueError("Message is too large for this image.")` if the pixels ran out before all bits were embedded.

**External services / databases:** none. The only "external reference" produced is a `maps.google.com` URL *string* — the tool never fetches it.

---

## 3. Project File Structure

```
image-inspector/
├── image_inspector.py            # CLI entry point: argparse + orchestration
├── requirements.txt              # piexif==1.1.3 (UNUSED), pillow==12.3.0
├── README.md                     # feature list, usage, "How It Works", limitations, ethics
├── test.sh                       # bash smoke test (help / -m / -s / combined / exit code)
├── .gitignore
│
├── modules/
│   ├── __init__.py               # empty — marks the package
│   ├── utils.py                  # validate_image()
│   ├── metadata.py               # extract_metadata()  → imports modules.gps
│   ├── gps.py                    # extract_gps(), convert_to_degrees()
│   ├── steganography.py          # extract_lsb_bits / bits_to_bytes / bytes_to_text / detect_pgp_key
│   └── output.py                 # save_output()
│
├── Message_Hide_in_image/
│   └── HideMessageinImage.py     # STANDALONE encoder (produces test images) — not imported by the CLI
│
├── tests/
│   ├── test_metadata.py          # EMPTY
│   └── test_steganography.py     # EMPTY
│
├── venv/                         # local virtualenv (gitignored)
└── (many sample images)          # *.jpg / *.jpeg / *.png test inputs; metadata.txt / results.txt outputs
```

### File-by-file

**`image_inspector.py`**
- **Purpose.** The only executable; wires arguments to modules.
- **Imports.** `argparse`; `modules.utils.validate_image`; `modules.metadata.extract_metadata`; `modules.output.save_output`; from `modules.steganography`: `extract_lsb_bits, bits_to_bytes, bytes_to_text, detect_pgp_key`.
- **Exposes.** `parse_arguments()`, `main()`, the `if __name__ == "__main__": main()` guard.
- **Depends on it.** Nothing (it's the top).
- **Input.** `sys.argv`. **Output.** stdout text; optionally a file via `save_output`; process exit `0` (even on handled errors).

**`modules/__init__.py`** — empty; presence makes `modules` an importable package.

**`modules/utils.py`**
- **Purpose.** Fail fast on bad input before any parsing work.
- **Imports.** `pathlib.Path`, `PIL.Image`.
- **Exposes.** `SUPPORTED_EXTENSIONS` (a `set`), `validate_image(image_path) -> bool` (raises `FileNotFoundError` / `ValueError` / `OSError`).
- **Depended on by.** `image_inspector.py`.
- **Input.** a path string. **Output.** `True`, or an exception.

**`modules/metadata.py`**
- **Purpose.** Produce a name-keyed EXIF dictionary, with GPS decoded.
- **Imports.** `PIL.Image`, `PIL.ExifTags.TAGS`, `modules.gps.extract_gps`.
- **Exposes.** `extract_metadata(image_path) -> dict`.
- **Depended on by.** `image_inspector.py`.
- **Input.** a path. **Output.** `dict` (possibly empty); raises `Exception` on failure.

**`modules/gps.py`**
- **Purpose.** GPS sub-IFD → human coordinates + map link.
- **Imports.** `PIL.ExifTags.GPSTAGS`.
- **Exposes.** `extract_gps(exif_data) -> dict | None`, `convert_to_degrees(value) -> float | None`.
- **Depended on by.** `modules/metadata.py`.
- **Input.** a Pillow `Exif` object. **Output.** `{Latitude, Longitude, "Google Maps"}` or `None`.

**`modules/steganography.py`**
- **Purpose.** Naive LSB steganalysis for a PGP block.
- **Imports.** `PIL.Image`.
- **Exposes.** `extract_lsb_bits(image_path) -> list[int]`, `bits_to_bytes(bits) -> list[int]`, `bytes_to_text(bytes_list) -> str`, `detect_pgp_key(text) -> str | None`.
- **Depended on by.** `image_inspector.py`.
- **Input.** a path (first fn) then the previous stage's output. **Output.** bits → bytes → text → the PGP block or `None`.

**`modules/output.py`**
- **Purpose.** Persist a result.
- **Imports.** stdlib only.
- **Exposes.** `save_output(data, filename, append=False)`.
- **Depended on by.** `image_inspector.py`.
- **Input.** a `dict` or `str`, a filename, an append flag. **Output.** a text file; prints a confirmation; raises `Exception` on I/O failure.

**`Message_Hide_in_image/HideMessageinImage.py`**
- **Purpose.** Companion **encoder** to generate stego test images.
- **Imports.** `PIL.Image`.
- **Exposes.** `text_to_bits(text) -> str`, `hide_message(input_image, output_image, message)`; `__main__` demo embedding a PGP block into `../local.jpg → ../hidden.png`.
- **Depended on by.** Nothing (standalone).
- **Input.** an input image path, an output path, a message string. **Output.** a new image file with modified LSBs; prints a bit count.

**`requirements.txt`** — pins `piexif==1.1.3` and `pillow==12.3.0`. Only Pillow is actually imported.

**`test.sh`** — runs `--help`, then `-m -o metadata.txt`, `-s -o hidden_data.txt`, and `-m -s -o results.txt` against `image-example1.jpeg`, asserting the output files exist and printing the process exit code.

**`tests/*.py`** — empty placeholders; no test framework wired.

---

## 4. Execution Flow

### 4.1 Flow diagram

```
 start: python image_inspector.py [-m] [-s] [-o FILE] <image>
   │
   ▼
[1] parse_arguments()
        build argparse parser (flags + positional "image")
        args = parser.parse_args()
        if not args.metadata and not args.steganography:  parser.error(...)  → exit 2
   │
   ▼
[2] main(): try:
   │
   ▼
[3] validate_image(args.image)
        Path.exists()  else FileNotFoundError
        Path.is_file() else FileNotFoundError
        suffix in SUPPORTED_EXTENSIONS  else ValueError
        Image.open(p).verify()  else OSError("Invalid or corrupted image: ...")
   │
   ├───────────────── if args.metadata ──────────────────┐
   ▼                                                      │
[4] metadata = extract_metadata(args.image)              │
        Image.open → getexif()                            │
        if empty → return {}                              │
        gps = extract_gps(exif)                           │
           get_ifd(34853); require 4 GPS tags;            │
           convert_to_degrees(lat), (lon); sign by ref;   │
           build Google Maps URL                          │
        if gps → metadata["Latitude"/"Longitude"/"Google Maps"] = ...
        for tag_id, value in exif.items():                │
           name = TAGS.get(tag_id, tag_id)                │
           if isinstance(value, bytes): continue          │
           if name == "GPSInfo": continue                 │
           metadata[name] = value                         │
   ▼                                                      │
[5] if metadata:                                          │
        print "===== METADATA ====="; print "k: v" lines  │
        if args.output: save_output(metadata, FILE)  (mode "w")
     else:                                                │
        print "No metadata found."                        │
        if args.output: save_output("No metadata found.", FILE)
   │                                                      │
   ├───────────────── if args.steganography ─────────────┘
   ▼
[6] bits  = extract_lsb_bits(args.image)      # Image.convert("RGB").getdata() → [r&1,g&1,b&1, ...]
    bytes_= bits_to_bytes(bits)               # 8 bits → 1 byte, MSB-first
    text  = bytes_to_text(bytes_)             # bytes(...).decode("utf-8", errors="ignore")
    key   = detect_pgp_key(text)              # find BEGIN..END → slice | None
   ▼
[7] if key:
        print "===== HIDDEN PGP KEY FOUND ====="; print key
        if args.output: save_output(key, FILE, append=args.metadata)
     else:
        print "No hidden PGP key found."
        if args.output: save_output("No hidden PGP key found.", FILE, append=args.metadata)
   │
   ▼
except Exception as e:  print(f"Error: {e}")     # any raised exception lands here; exit code stays 0
```

### 4.2 Step-by-step narrative

1. **Argument parsing.** `argparse` defines two store-true flags (`-m`, `-s`), an optional `-o FILE`, and a required positional `image`. If neither `-m` nor `-s` is given, `parser.error(...)` prints usage to stderr and exits with code **2** (argparse's convention). `--help` is auto-generated and exits **0**.

2. **`main()` enters a single `try`.** Everything from here to the end is inside it; any exception is caught at the bottom.

3. **Validation** (`validate_image`). Four gates in order: the path must exist, be a regular file, have an allowed suffix (`.jpg/.jpeg/.png/.bmp/.tiff`, case-insensitive), and pass `Image.open(p).verify()`. `verify()` parses the file structure enough to detect truncation/corruption **without** fully decoding pixels; on any Pillow exception it's re-raised as `OSError("Invalid or corrupted image: …")`. *(Note: `verify()` leaves the `Image` object unusable, so downstream code must — and does — call `Image.open` again.)*

4. **Metadata branch** (`-m`). `extract_metadata` opens the image and calls `getexif()` (Pillow's modern accessor for the EXIF IFD-0 block). If there is no EXIF, it returns `{}` immediately. Otherwise it first calls `extract_gps`:
   - `exif.get_ifd(34853)` retrieves the **GPS sub-IFD** (EXIF tag `0x8825` = `GPSInfo` points to a nested tag dictionary). Missing → `None` (via the `KeyError` guard / empty dict + the required-tags check).
   - The sub-tag numeric keys are renamed via `GPSTAGS` (e.g. `2 → "GPSLatitude"`).
   - It requires `GPSLatitude`, `GPSLatitudeRef`, `GPSLongitude`, `GPSLongitudeRef`. `GPSLatitude` is three rationals **(degrees, minutes, seconds)**; `convert_to_degrees` turns that into a single float `d + m/60 + s/3600`. The `Ref` (`"N"/"S"`, `"E"/"W"`) decides the sign: `S` and `W` negate.
   - Returns `{Latitude, Longitude, "Google Maps": "https://maps.google.com/?q=lat,lon"}`; `extract_metadata` injects those three keys.

   Then it iterates the top-level EXIF items: `TAGS.get(tag_id, tag_id)` maps e.g. `271 → "Make"`, `272 → "Model"`, `306 → "DateTime"`, `274 → "Orientation"`; **`bytes` values are skipped** (binary blobs like `MakerNote` would be unreadable noise), and the raw `GPSInfo` entry is skipped (already decoded). The rest go into the dict as-is.

5. **Print / save metadata.** If the dict is non-empty: print a `===== METADATA =====` header and one `key: value` line per entry; if `-o` was given, `save_output(metadata, FILE)` writes the same lines to the file in **write** mode (`"w"`). If the dict is empty: print `No metadata found.` and, if `-o`, save that string.

6. **Steganography branch** (`-s`). The four-stage pipeline:
   - `extract_lsb_bits`: `Image.open(path).convert("RGB")` (forces 3-channel 8-bit), then for every pixel `(r,g,b)` append `r & 1`, `g & 1`, `b & 1` to a list. Result length = `3 × width × height`.
   - `bits_to_bytes`: consume the list 8 bits at a time; for each group, `value = (value << 1) | bit` (so bit[0] is the **most significant** bit); a trailing group of fewer than 8 bits is discarded (`break`).
   - `bytes_to_text`: `bytes(bytes_list).decode("utf-8", errors="ignore")` — invalid byte sequences are dropped rather than raising.
   - `detect_pgp_key`: `text.find("-----BEGIN PGP PUBLIC KEY BLOCK-----")`; if found, `text.find("-----END PGP PUBLIC KEY BLOCK-----", start)`; if found, return `text[start : end + len(END_MARKER)]`; else `None`.

7. **Print / save stego result.** If a block was found: print `===== HIDDEN PGP KEY FOUND =====` and the block; else print `No hidden PGP key found.`. If `-o` was given, `save_output(result, FILE, append=args.metadata)` — **`append` is `True` exactly when `-m` was also used**, so a combined `-m -s -o` run writes metadata first (`"w"`) then appends the stego result to the same file; a `-s -o` run overwrites (`"w"`).

8. **Error path.** Any exception raised anywhere in steps 3–7 is caught by `except Exception as e: print(f"Error: {e}")`. The program then falls off the end of `main()` and exits **0** — there is no `sys.exit(1)` on error.

---

## 5. Entry Point

The real entry point is `image_inspector.py`, executed as `python image_inspector.py …`. Python runs the module top to bottom: it imports `argparse` and the `modules.*` names, defines `parse_arguments()` and `main()`, and then hits:

```python
if __name__ == "__main__":
    main()
```

`__name__ == "__main__"` is true only when the file is run as a script (not imported), so `main()` is the effective start.

### 5.1 `parse_arguments()` — annotated

```python
def parse_arguments():
    parser = argparse.ArgumentParser(
        prog="image-inspector",
        description="Analyze image metadata and detect hidden information."
    )
    # store_true: the flag takes no value; args.metadata is True iff -m is present
    parser.add_argument("-m", "--metadata",      action="store_true", help="Extract image metadata.")
    parser.add_argument("-s", "--steganography", action="store_true", help="Detect hidden data using steganography.")
    # -o takes one value; metavar is cosmetic (shown as FILE in --help)
    parser.add_argument("-o", "--output", metavar="FILE", help="Save the output to a file.")
    # positional, required: the image path
    parser.add_argument("image", help="Path to the image file.")

    args = parser.parse_args()   # on unknown/missing args: prints usage to stderr, sys.exit(2)

    # semantic rule argparse can't express declaratively: need at least one mode
    if not args.metadata and not args.steganography:
        parser.error("At least one analysis option (-m or -s) is required.")   # → stderr + exit 2

    return args
```

- **Arguments consumed:** `-m/--metadata` (bool), `-s/--steganography` (bool), `-o/--output FILE` (str or `None`), `image` (str, required).
- **Environment variables:** none.
- **Config files:** none.
- **Dependencies at import time:** `argparse` (stdlib) and the `modules` package (which in turn imports `PIL`). If Pillow isn't installed, the *import* of `modules.utils` fails with `ModuleNotFoundError` before `main()` runs — an unhandled crash (not caught by `main`'s try).
- **Error handling at the entry point:** `argparse` handles malformed CLI usage (exit 2). The "need one mode" rule is enforced manually via `parser.error`. Everything else is deferred to `main()`'s blanket `try/except`.

### 5.2 `main()` — the orchestration body

```python
def main():
    args = parse_arguments()
    try:
        validate_image(args.image)                     # raise on bad input

        if args.metadata:
            metadata = extract_metadata(args.image)
            if metadata:
                print("===== METADATA =====")
                for key, value in metadata.items():
                    print(f"{key}: {value}")
                if args.output:
                    save_output(metadata, args.output)          # mode "w"
            else:
                message = "No metadata found."
                print(message)
                if args.output:
                    save_output(message, args.output)

        if args.steganography:
            bits       = extract_lsb_bits(args.image)
            bytes_data = bits_to_bytes(bits)
            text       = bytes_to_text(bytes_data)
            pgp_key    = detect_pgp_key(text)
            if pgp_key:
                print("\n===== HIDDEN PGP KEY FOUND =====")
                print(pgp_key)
                if args.output:
                    save_output(pgp_key, args.output, append=args.metadata)   # append iff -m too
            else:
                message = "No hidden PGP key found."
                print(message)
                if args.output:
                    save_output(message, args.output, append=args.metadata)

    except Exception as e:
        print(f"Error: {e}")        # <-- all errors funnel here; exit code stays 0
```

Both `if` blocks can run in one invocation (`-m -s`), always metadata-first. The `append=args.metadata` argument is the only coupling between the two branches.

---

## 6. Code Deep Dive

### 6.1 `utils.validate_image`

```python
SUPPORTED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".tiff"}

def validate_image(image_path):
    print('ENTER to THE function -------')        # <-- stray debug print (see notes)
    """ ...docstring-looking string that is NOT a docstring... """
    image = Path(image_path)

    if not image.exists():
        raise FileNotFoundError(f"File not found: {image_path}")
    if not image.is_file():
        raise FileNotFoundError(f"'{image_path}' is not a file.")
    if image.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"Unsupported image format '{image.suffix}'. Supported formats: {', '.join(SUPPORTED_EXTENSIONS)}")
    try:
        with Image.open(image) as img:
            img.verify()
    except Exception as e:
        raise OSError(f"Invalid or corrupted image: {e}")

    return True
```

**A. Purpose.** Reject bad input early with a *specific, typed* error, so `main`'s handler can print a meaningful message and no downstream code has to defend against "file doesn't exist" or "not an image."

**B. Inputs.** `image_path: str` — from `args.image` (the required positional). Example values: `"image-example1.jpeg"`, `"/tmp/x.png"`, `"missing.jpg"`, `"notes.txt"`, `"truncated.jpg"`.

**C. Internal logic.**
- **`Path(image_path)`** — wrap the string in a `pathlib.Path` for OS-agnostic checks.
- **`image.exists()`** — `stat()`s the path; `False` → `FileNotFoundError`.
- **`image.is_file()`** — distinguishes a regular file from a directory/socket/FIFO; a directory named `photos.jpg` would pass `exists()` but fail here. *(Raised as `FileNotFoundError`, arguably should be a different type, but it's typed and caught.)*
- **`image.suffix.lower()`** — `.suffix` is the last dotted component (`".JPEG"` → lower → `".jpeg"`). Membership test against the **`set`** `SUPPORTED_EXTENSIONS` is O(1). Not in the set → `ValueError`. **This is an extension check, not a content check** — a `.txt` renamed to `.png` passes this gate but fails the next.
- **`with Image.open(image) as img: img.verify()`** — Pillow's `open` is *lazy* (reads the header, not the pixels). **`verify()`** walks the file's structural markers (JPEG segments / PNG chunks / CRCs) to detect truncation or corruption **without decoding**. It's cheap. On any Pillow error (`UnidentifiedImageError`, `SyntaxError`, `OSError`, …) the `except` re-wraps it as `OSError("Invalid or corrupted image: …")`.
- **`return True`** on success.

> **Concept — `verify()` invalidates the object.** Per Pillow docs, after `verify()` you must not use that `Image` instance for anything else; you must `open()` again. This code obeys that: `validate_image` opens/verifies/closes in its own `with`, and `extract_metadata` / `extract_lsb_bits` each call `Image.open` afresh. A common bug is to `verify()` then `.load()` the same object.

**D. Output.** `True`, or one of `FileNotFoundError` / `ValueError` / `OSError`. Side effect: prints the stray debug line every call. **Consumed by** `main()` (only for its raise/no-raise behavior — the `True` is ignored).

**Concrete examples.**
| Input | Result |
|---|---|
| `image-example1.jpeg` (valid) | prints the debug line, returns `True` |
| `missing.jpg` | `FileNotFoundError: File not found: missing.jpg` → `main` prints `Error: File not found: missing.jpg` |
| `notes.txt` | `ValueError: Unsupported image format '.txt'. …` |
| `truncated.jpg` (half a JPEG) | `OSError: Invalid or corrupted image: …` |

---

### 6.2 `metadata.extract_metadata`

```python
from PIL import Image
from PIL.ExifTags import TAGS
from modules.gps import extract_gps

def extract_metadata(image_path):
    metadata = {}
    try:
        image = Image.open(image_path)
        exif_data = image.getexif()
        if not exif_data:
            return metadata                      # {} — "No metadata found."

        gps = extract_gps(exif_data)
        if gps:
            metadata["Latitude"]    = gps["Latitude"]
            metadata["Longitude"]   = gps["Longitude"]
            metadata["Google Maps"] = gps["Google Maps"]

        for tag_id, value in exif_data.items():
            tag_name = TAGS.get(tag_id, tag_id)
            if isinstance(value, bytes):
                continue
            if tag_name == "GPSInfo":
                continue
            metadata[tag_name] = value
        return metadata
    except Exception as e:
        raise Exception(f"Error extracting metadata: {e}")
```

**A. Purpose.** Turn Pillow's raw EXIF (numeric tag IDs → arbitrary values, plus a GPS pointer) into a **clean, name-keyed dictionary** that's printable and saveable, with the location decoded into normal coordinates.

**B. Inputs.** `image_path: str` — the validated path. Implicitly, the file's EXIF IFD-0 block (may be absent).

**C. Internal logic — concepts: EXIF, IFD, tag IDs, `TAGS` map.**
- **EXIF** ("Exchangeable Image File Format") is a metadata standard embedded in JPEG/TIFF (and, via a chunk, PNG). It's organized as **IFDs** ("Image File Directories") — tables of `(tag_id: int, value)` entries. **IFD-0** holds camera/image basics (`Make`, `Model`, `Orientation`, `DateTime`, …). Tag `0x8769` points to the **Exif sub-IFD** (exposure, ISO, lens…); tag `0x8825` (`34853`) points to the **GPS sub-IFD**.
- **`Image.getexif()`** returns a Pillow `Exif` object — a dict-like of IFD-0 entries — parsed lazily from the file. `if not exif_data:` is `True` for an empty `Exif` (a PNG straight from a screenshot tool, a stripped JPEG) → return `{}`.
- **`extract_gps(exif_data)`** (next section) — if it returns a dict, three keys (`Latitude`, `Longitude`, `Google Maps`) are copied in first, so they appear at the top of the output.
- **`for tag_id, value in exif_data.items()`** — iterate IFD-0.
  - **`TAGS.get(tag_id, tag_id)`** — `PIL.ExifTags.TAGS` is `{271: "Make", 272: "Model", 274: "Orientation", 306: "DateTime", …}`. `.get(id, id)` returns the human name, or the raw integer if the tag is unknown (so nothing is lost, just un-named).
  - **`if isinstance(value, bytes): continue`** — some EXIF values are binary blobs (`MakerNote`, sometimes `UserComment`, thumbnails). Printing them would spew mojibake and they're rarely useful here, so they're dropped.
  - **`if tag_name == "GPSInfo": continue`** — the raw `GPSInfo` value is an IFD pointer/dict, not human-readable; it's already been decoded via `extract_gps`, so skip the raw form.
  - Everything else: `metadata[tag_name] = value` (values are typically `str`, `int`, `float`/`IFDRational`, or tuples).
- **`except Exception as e: raise Exception(f"Error extracting metadata: {e}")`** — wraps *any* failure (corrupt EXIF, Pillow bug) in a generic `Exception`, which `main` catches and prints. *(Wrapping in bare `Exception` loses the original type — a minor smell.)*

**D. Output.** A `dict[str|int, Any]` (empty if no EXIF). Example:
```python
{
  "Latitude": 34.020882,
  "Longitude": -6.833333,
  "Google Maps": "https://maps.google.com/?q=34.020882,-6.833333",
  "Make": "samsung",
  "Model": "SM-A145P",
  "DateTime": "2026:07:25 10:49:00",
  "Orientation": 6,
  "XResolution": 72.0,
  "YResolution": 72.0,
  "Software": "A145PXXU...",
}
```
**Consumed by** `main()` — printed as `key: value` lines and optionally handed to `save_output`.

---

### 6.3 `gps.extract_gps` and `gps.convert_to_degrees`

```python
from PIL.ExifTags import GPSTAGS

def extract_gps(exif_data):
    try:
        gps_info = exif_data.get_ifd(34853)          # 0x8825 = GPS IFD
    except KeyError:
        return None

    gps_data = {}
    for key, value in gps_info.items():
        gps_data[GPSTAGS.get(key, key)] = value       # 2 -> "GPSLatitude", 1 -> "GPSLatitudeRef", ...

    required = ("GPSLatitude", "GPSLatitudeRef", "GPSLongitude", "GPSLongitudeRef")
    if not all(tag in gps_data for tag in required):
        return None

    latitude  = convert_to_degrees(gps_data["GPSLatitude"])
    longitude = convert_to_degrees(gps_data["GPSLongitude"])
    if latitude is None or longitude is None:
        return None

    if gps_data["GPSLatitudeRef"]  == "S":  latitude  = -latitude
    if gps_data["GPSLongitudeRef"] == "W":  longitude = -longitude

    return {
        "Latitude": latitude,
        "Longitude": longitude,
        "Google Maps": f"https://maps.google.com/?q={latitude},{longitude}",
    }

def convert_to_degrees(value):
    try:
        degrees = float(value[0]); minutes = float(value[1]); seconds = float(value[2])
    except (ValueError, TypeError):
        return None
    if degrees != degrees or minutes != minutes or seconds != seconds:   # NaN check
        return None
    return degrees + (minutes / 60) + (seconds / 3600)
```

**A. Purpose.** Convert the EXIF GPS sub-IFD's **degrees/minutes/seconds (DMS)** rationals plus hemisphere refs into a single **signed decimal-degrees** latitude and longitude, and produce a clickable Maps URL.

**B. Inputs.** `exif_data` — the Pillow `Exif` object from `getexif()`. `convert_to_degrees`'s `value` — a 3-element sequence of rationals (Pillow `IFDRational` objects, or in older data `(numerator, denominator)` tuples).

**C. Internal logic — concepts: GPS IFD, DMS, rationals, hemisphere sign, NaN.**
- **`exif_data.get_ifd(34853)`** — follows the `GPSInfo` pointer and returns the nested `{tag_id: value}` dict for the GPS IFD. In current Pillow this returns `{}` when absent (so the `except KeyError` is defensive/possibly-dead, but harmless).
- **`GPSTAGS`** maps GPS sub-tag IDs to names: `0→GPSVersionID`, `1→GPSLatitudeRef`, `2→GPSLatitude`, `3→GPSLongitudeRef`, `4→GPSLongitude`, `5→GPSAltitudeRef`, `6→GPSAltitude`, `7→GPSTimeStamp`, …
- **The `required` guard.** Without all four of lat, lat-ref, lon, lon-ref you can't produce a meaningful signed coordinate → `None` (upstream prints nothing GPS-related).
- **DMS → decimal.** EXIF stores latitude as **three rationals**: degrees, minutes, seconds (e.g. `34/1, 1/1, 15168/1000` = 34° 1′ 15.168″). Decimal degrees = `d + m/60 + s/3600`. `convert_to_degrees` does exactly that after `float()`-ing each component.
  - **`IFDRational`** supports `float()` directly (it's `numerator/denominator`). A legacy `(num, den)` **tuple** would make `float((num, den))` raise `TypeError` → caught → `None`.
  - **NaN check** — `x != x` is `True` only for IEEE-754 NaN. A corrupt `0/0` rational could surface as NaN; this rejects it rather than propagating `nan` into the URL.
- **Hemisphere sign.** Decimal-degree convention: **North/East positive, South/West negative**. `GPSLatitudeRef == "S"` → negate latitude; `GPSLongitudeRef == "W"` → negate longitude. (No negation for `"N"`/`"E"`.)
- **URL.** `f"https://maps.google.com/?q={lat},{lon}"` — the `?q=lat,lon` form drops a pin at that coordinate. **The tool only builds the string; it never requests it.**

**D. Output.** `{"Latitude": float, "Longitude": float, "Google Maps": str}` or `None`. Example: DMS `(34,1,15.168)` ref `N`, `(6,50,0.0)` ref `W` → `{"Latitude": 34.020880, "Longitude": -6.833333, "Google Maps": "https://maps.google.com/?q=34.02088,-6.833333"}`. **Consumed by** `extract_metadata` (injects the three keys).

---

### 6.4 `steganography.extract_lsb_bits`

```python
from PIL import Image

def extract_lsb_bits(image_path):
    print("extract lbs bits -----*")           # <-- stray debug print
    bits = []
    try:
        print("test")                          # <-- stray debug print
        image = Image.open(image_path)
        image = image.convert("RGB")
        for pix in image.getdata():
            r, g, b = pix
            bits.append(r & 1)
            bits.append(g & 1)
            bits.append(b & 1)
        return bits
    except Exception as e:
        raise Exception(f"Error extracting LSB bits: {e}")
```

**A. Purpose.** Extract the **least-significant bit** of every colour channel of every pixel, in scan order, as a flat list of 0/1 — the raw "LSB plane" that a hidden message would live in.

**B. Inputs.** `image_path: str` — the validated image.

**C. Internal logic — concepts: LSB, `convert("RGB")`, `getdata()`, bit masking.**
- **LSB (least-significant bit)** — in an 8-bit channel value `0..255`, the LSB contributes `±1` to the brightness of that channel for that pixel. Changing it is **visually imperceptible** — you cannot see the difference between R=200 and R=201. That's why it's the classic place to hide data: you can overwrite the entire LSB plane and the picture looks identical.
- **`Image.open(path).convert("RGB")`** — normalize to exactly 3 channels, 8 bits each. This matters: a PNG might be palettized (`"P"`), greyscale (`"L"`), or have alpha (`"RGBA"`); `convert("RGB")` gives a predictable `(r, g, b)` per pixel so the extractor's "3 bits per pixel" assumption holds. **Caveat:** for a **JPEG**, `convert("RGB")` yields the *decompressed* pixels — JPEG is lossy and does not preserve arbitrary LSBs, so LSB steganography effectively never survives in a JPEG. (The companion encoder saves **PNG** for this reason.)
- **`image.getdata()`** — an iterator over pixels in row-major (left→right, top→bottom) order, each pixel a `(r, g, b)` tuple.
- **`r & 1`** — bitwise AND with `1` isolates the LSB: even value → `0`, odd → `1`.
- Append order **R, then G, then B** per pixel — this must match the encoder's write order (it does).
- Result length = `3 × width × height`. For a 12-megapixel photo that's ~36 million ints in a Python list — **~1.1 GB+ of memory** (each small int ~28 bytes). No size guard exists (see §12/§13).

**D. Output.** `list[int]` of 0/1, length `3·W·H`. Example: a 2×1 RGB image with pixels `(200,201,202)` and `(0,1,2)` → `[0,1,0, 0,1,0]`. **Consumed by** `bits_to_bytes`.

---

### 6.5 `steganography.bits_to_bytes`

```python
def bits_to_bytes(bits):
    bytes_list = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i + 8]
        if len(byte) < 8:
            break
        value = 0
        for bit in byte:
            value = (value << 1) | bit
        bytes_list.append(value)
    return bytes_list
```

**A. Purpose.** Pack the flat bit list into bytes, so `bytes_to_text` can decode it.

**B. Inputs.** `bits: list[int]` — the LSB plane from `extract_lsb_bits`.

**C. Internal logic — concept: bit-packing, MSB-first order.**
- `range(0, len(bits), 8)` — step through the list in 8-bit windows.
- `byte = bits[i:i+8]` — a slice of ≤8 bits. `if len(byte) < 8: break` — a trailing partial group (the LSB-plane length is always a multiple of 3, rarely a multiple of 8) is **discarded**.
- **`value = (value << 1) | bit`** — build the byte **MSB-first**: the first bit of the group becomes bit 7 of the byte. Example group `[0,1,0,0,0,0,0,1]` → `0b01000001` = `65` = `'A'`.
- This ordering must match the encoder's `format(ord(c), '08b')`, which also emits MSB-first. It does. If one side used LSB-first, every byte would be bit-reversed and the text would be garbage.

**D. Output.** `list[int]` in `0..255`. Example: 16 bits `[0,1,0,0,1,0,0,0, 0,1,1,0,1,0,0,1]` → `[72, 105]` → `"Hi"`. **Consumed by** `bytes_to_text`.

---

### 6.6 `steganography.bytes_to_text`

```python
def bytes_to_text(bytes_list):
    try:
        text = bytes(bytes_list).decode("utf-8", errors="ignore")
        return text
    except Exception as e:
        raise Exception(f"Error converting bytes to text: {e}")
```

**A. Purpose.** Turn the byte list into a Python `str` so a textual marker (`-----BEGIN PGP…`) can be searched for.

**B. Inputs.** `bytes_list: list[int]` (0–255) from `bits_to_bytes`.

**C. Internal logic — concept: UTF-8 decoding, `errors="ignore"`.**
- **`bytes(bytes_list)`** — construct an immutable `bytes` object from the ints.
- **`.decode("utf-8", errors="ignore")`** — interpret those bytes as UTF-8 text. The LSB plane of a normal photo is essentially **random noise**, so most byte sequences are *not* valid UTF-8. `errors="ignore"` **drops** every invalid byte/sequence instead of raising `UnicodeDecodeError`. The net effect: the huge noisy prefix/suffix largely collapses to a shorter string of whatever ASCII/UTF-8 fragments happened to appear, and any *actually-embedded* ASCII text (like a PGP block, which is pure printable ASCII) survives intact and contiguous.
- Because a real PGP armor block is 7-bit ASCII, it round-trips through UTF-8 unchanged and stays findable.

**D. Output.** `str` (usually mostly-garbage with the hidden message embedded if present). **Consumed by** `detect_pgp_key`.

---

### 6.7 `steganography.detect_pgp_key`

```python
def detect_pgp_key(text):
    begin = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
    end   = "-----END PGP PUBLIC KEY BLOCK-----"
    start = text.find(begin)
    if start == -1:
        return None
    finish = text.find(end, start)
    if finish == -1:
        return None
    finish += len(end)
    return text[start:finish]
```

**A. Purpose.** Decide whether a **PGP public-key armor block** is present in the decoded LSB text, and if so return exactly that block.

**B. Inputs.** `text: str` — from `bytes_to_text`.

**C. Internal logic — concept: PGP ASCII armor, substring search.**
- **PGP ASCII armor** is a text envelope for binary OpenPGP data: a `-----BEGIN PGP PUBLIC KEY BLOCK-----` header line, optional headers (`Version:`), a blank line, Base64 payload, a Base64 CRC checksum line (`=xxxx`), and a `-----END PGP PUBLIC KEY BLOCK-----` footer. It's pure printable ASCII, which is why LSB-embedding + UTF-8 decode preserves it.
- **`text.find(begin)`** — index of the header, or `-1`. `-1` → `None` ("not found").
- **`text.find(end, start)`** — index of the footer, **searching only from `start` onward** (so a stray footer *before* the header doesn't confuse it). `-1` → `None`.
- **`finish += len(end)`** — extend the end index past the footer so the returned slice *includes* the full `-----END …-----` line.
- **`text[start:finish]`** — the block, header through footer inclusive. Any garbage before `start` or after `finish` (the noisy remainder of the LSB plane) is excluded.

**D. Output.** `str` (the armor block) or `None`. **Consumed by** `main()` — printed under `===== HIDDEN PGP KEY FOUND =====` and optionally saved.

> **Design note:** this is a *pattern* detector for one specific armored type. It does **not** validate the Base64, verify the CRC, parse the key, decrypt anything, or look for the `###END###` marker the companion encoder writes. It's "grep the LSB plane for a PGP header/footer pair."

---

### 6.8 `output.save_output`

```python
def save_output(data, filename, append=False):
    mode = "a" if append else "w"
    try:
        with open(filename, mode, encoding="utf-8") as file:
            if isinstance(data, dict):
                for key, value in data.items():
                    file.write(f"{key}: {value}\n")
            else:
                file.write(str(data) + "\n")
        print(f"Data saved in {filename}")
    except Exception as e:
        raise Exception(f"Error saving output: {e}")
```

**A. Purpose.** Persist a result to a text file, matching the on-screen format.

**B. Inputs.**
- `data` — a `dict` (metadata) or a `str` (the PGP block, or a "not found" / "no metadata" message).
- `filename: str` — from `args.output` (`-o`).
- `append: bool` — `False` for the metadata write; for the stego write, `append=args.metadata` (so `True` only in a combined `-m -s` run).

**C. Internal logic.**
- `mode = "a" if append else "w"` — `"w"` truncates then writes; `"a"` seeks to end and appends. This is the mechanism that lets `-m -s -o out.txt` produce one file with metadata first and the stego result after.
- `open(filename, mode, encoding="utf-8")` in a `with` block (auto-close/flush).
- `dict` → one `key: value` line per item (same shape as the stdout print). Anything else → `str(data)` + `\n`.
- Prints a confirmation. Any I/O failure (`PermissionError`, `IsADirectoryError`, bad path) is wrapped in `Exception` and bubbles to `main`.

**D. Output.** A UTF-8 text file at `filename`; a `Data saved in …` line on stdout. **No path sanitization** — `filename` is used verbatim, so `-o ../../notes.txt` writes there (constrained only by the user's own FS permissions).

**Concrete example.** `save_output({"Make":"samsung","Model":"SM-A145P"}, "metadata.txt")` →
```
metadata.txt:
Make: samsung
Model: SM-A145P
```

---

### 6.9 `HideMessageinImage.hide_message` (companion encoder)

```python
def text_to_bits(text):
    return ''.join(format(ord(char), '08b') for char in text)

def hide_message(input_image, output_image, message):
    message += "###END###"                     # end marker (the CLI decoder does NOT use it)
    bits = text_to_bits(message)

    image = Image.open(input_image).convert("RGB")
    pixels = list(image.getdata())

    bit_index = 0
    new_pixels = []
    for pixel in pixels:
        r, g, b = pixel
        rgb = [r, g, b]
        for i in range(3):
            if bit_index < len(bits):
                rgb[i] = (rgb[i] & ~1) | int(bits[bit_index])     # clear LSB, then set it to the message bit
                bit_index += 1
        new_pixels.append(tuple(rgb))

    if bit_index < len(bits):
        raise ValueError("Message is too large for this image.")

    image.putdata(new_pixels)
    image.save(output_image)
    print(f"Hidden {bit_index} bits."); print(f"Saved as {output_image}")
```

**A. Purpose.** The inverse of the detector: **embed** a message in an image's LSB plane and save it losslessly, to create test inputs.

**B. Inputs.** `input_image` (cover path), `output_image` (stego path — `.png` in the demo), `message: str` (the demo hides a full `-----BEGIN PGP PUBLIC KEY BLOCK-----` … block).

**C. Internal logic — concepts: `ord`, `format(…, '08b')`, `& ~1`, `putdata`.**
- **`text_to_bits`** — `ord(char)` is the Unicode code point; `format(n, '08b')` is its 8-bit binary string, MSB-first, zero-padded. For pure-ASCII PGP armor this is faithful; a non-ASCII char with code point > 255 would produce >8 bits and desynchronize the byte grid (not relevant for the demo).
- **`message += "###END###"`** — a sentinel so a *marker-aware* decoder could know where the payload ends. **The CLI's `detect_pgp_key` ignores it** and relies on the `-----END …-----` footer instead — so the marker is currently vestigial for this project.
- **`(rgb[i] & ~1) | int(bits[bit_index])`** — `& ~1` clears the LSB (`~1` is `…11111110`); `| bit` sets it to the message bit. So each channel's top 7 bits are untouched; only the LSB is overwritten.
- Bits are written **R, G, B** per pixel, matching the extractor's read order.
- **`if bit_index < len(bits)` AFTER the loop** — if the image ran out of pixels before all bits were embedded, this is `True` → `ValueError`. (Capacity in bits = `3·W·H`.) Placing the check after the loop is correct: `bit_index` only advances while `bit_index < len(bits)`, so a leftover means overflow.
- **`image.putdata(new_pixels)`** then **`image.save(output_image)`** — write the modified pixel array back and serialize. Saving as **PNG** (or BMP) is essential: PNG uses lossless DEFLATE, so every LSB is preserved. Saving as JPEG would re-quantize the DCT coefficients and destroy the hidden bits.

**D. Output.** A new image file whose LSB plane encodes `message + "###END###"`; a printed bit count. Running the CLI's `-s` on that PNG will decode the LSBs to text and `detect_pgp_key` will return the block.

---

## 7. Code Comments — annotated key blocks

### 7.1 The steganography pipeline (concept first)

**Concept.** Four transformations turn *pixels* into a *yes/no + the block*:
`image → LSB bits → bytes → UTF-8 text → substring match`.
Each stage is a pure function; the only image I/O is stage 1.

```python
# STAGE 1 — pixels → bit plane
def extract_lsb_bits(image_path):
    bits = []
    image = Image.open(image_path).convert("RGB")   # normalize to 8-bit R,G,B so "(r,g,b)" always unpacks
    for pix in image.getdata():                     # getdata(): pixels in row-major order
        r, g, b = pix
        bits.append(r & 1)                          # r & 1 isolates the least-significant bit (0 or 1)
        bits.append(g & 1)                          # order R,G,B MUST match the embedder's write order
        bits.append(b & 1)
    return bits                                     # length == 3 * width * height  (can be huge — no cap)

# STAGE 2 — bit plane → bytes  (MSB-first, drop trailing partial byte)
def bits_to_bytes(bits):
    out = []
    for i in range(0, len(bits), 8):
        chunk = bits[i:i+8]
        if len(chunk) < 8:                          # LSB-plane length is rarely a multiple of 8
            break                                  # discard the remainder
        v = 0
        for bit in chunk:
            v = (v << 1) | bit                     # first bit of the chunk => bit 7 of the byte (MSB-first)
        out.append(v)
    return out

# STAGE 3 — bytes → text  (lossy on purpose)
def bytes_to_text(bytes_list):
    # The LSB plane of a normal photo is ~random. errors="ignore" drops every byte
    # that isn't valid UTF-8, so noise largely vanishes while a real ASCII PGP block
    # (7-bit, always valid UTF-8) survives contiguous and searchable.
    return bytes(bytes_list).decode("utf-8", errors="ignore")

# STAGE 4 — text → the PGP armor block, or None
def detect_pgp_key(text):
    begin = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
    end   = "-----END PGP PUBLIC KEY BLOCK-----"
    start = text.find(begin)                        # -1 => header absent => not found
    if start == -1: return None
    finish = text.find(end, start)                  # search AFTER the header only
    if finish == -1: return None
    return text[start : finish + len(end)]          # include the full footer line
```

**INPUT → PROCESSING → OUTPUT.**
```
INPUT:   hidden.png  (LSBs of the first N*3 pixels encode "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----###END###")
STAGE 1: getdata() -> [0,1,1, 0,0,1, ...]                       (3 * W * H bits)
STAGE 2: -> [45, 45, 45, 45, 45, 66, 69, 71, 73, 78, ...]       (ASCII of "-----BEGIN ...")
STAGE 3: -> "\x00\x11...-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----###END###\x03..."
STAGE 4: -> "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----"
OUTPUT:  that string is printed under "===== HIDDEN PGP KEY FOUND ====="
```

### 7.2 GPS DMS → signed decimal degrees (concept first)

**Concept.** EXIF stores each coordinate as `degrees, minutes, seconds` (three fractions) plus a hemisphere letter. Maps want one signed decimal number. Formula: `decimal = degrees + minutes/60 + seconds/3600`, then negate for South/West.

```python
def convert_to_degrees(value):
    # value == (deg, min, sec) as IFDRational (num/den fractions). float() works on IFDRational.
    try:
        degrees = float(value[0]); minutes = float(value[1]); seconds = float(value[2])
    except (ValueError, TypeError):
        return None                                   # legacy (num,den) tuples => TypeError => bail
    if degrees != degrees or minutes != minutes or seconds != seconds:
        return None                                   # x != x is True only for NaN (e.g. a 0/0 rational)
    return degrees + (minutes / 60) + (seconds / 3600)

# ... in extract_gps():
latitude = convert_to_degrees(gps_data["GPSLatitude"])
if gps_data["GPSLatitudeRef"] == "S":                 # N/E are positive; S/W are negative
    latitude = -latitude
# Google Maps ?q=lat,lon drops a pin. The tool builds this STRING and never fetches it.
"Google Maps": f"https://maps.google.com/?q={latitude},{longitude}"
```

**INPUT → PROCESSING → OUTPUT.**
```
INPUT:   GPSLatitude=(34,1,15.168) GPSLatitudeRef="N" ; GPSLongitude=(6,50,0.0) GPSLongitudeRef="W"
PROCESS: 34 + 1/60 + 15.168/3600 = 34.02088 ;  6 + 50/60 + 0 = 6.833333 ;  ref "W" => -6.833333
OUTPUT:  {"Latitude": 34.02088, "Longitude": -6.833333,
          "Google Maps": "https://maps.google.com/?q=34.02088,-6.833333"}
```

### 7.3 The append coupling between the two branches

**Concept.** One combined run (`-m -s -o out.txt`) must yield **one** file with metadata then the stego verdict. The only signal used is "was `-m` also requested?".

```python
# metadata branch — always a fresh write:
if args.output:
    save_output(metadata, args.output)               # save_output(..., append=False) -> mode "w" (truncate)

# stego branch — append only if metadata already wrote to the same file this run:
if args.output:
    save_output(pgp_key, args.output, append=args.metadata)   # -m present -> "a" (append) ; -s alone -> "w"
```

**INPUT → PROCESSING → OUTPUT.**
```
INPUT:   python image_inspector.py -m -s -o out.txt photo.jpg
PROCESS: metadata branch: save_output(dict, "out.txt", append=False)  -> writes "k: v" lines, truncating
         stego branch:    save_output(msg,  "out.txt", append=True)   -> appends the verdict line
OUTPUT:  out.txt = [metadata lines] + [ "No hidden PGP key found." | the PGP block ]
```

---

## 8. INPUT → PROCESSING → OUTPUT (per component)

```
validate_image
  INPUT:   path string
  PROCESS: exists? -> is_file? -> suffix in {.jpg,.jpeg,.png,.bmp,.tiff}? -> Image.open().verify()
  OUTPUT:  True | FileNotFoundError | ValueError | OSError
  EXAMPLE: "notes.txt" -> ValueError("Unsupported image format '.txt'. ...")

extract_metadata
  INPUT:   validated path
  PROCESS: Image.getexif(); if empty -> {}; extract_gps() -> inject lat/lon/maps;
           for each IFD-0 tag: name via TAGS, skip bytes, skip GPSInfo, keep the rest
  OUTPUT:  dict {name: value}  (empty if no EXIF)
  EXAMPLE: samsung phone photo -> {"Latitude":..., "Make":"samsung", "Model":"SM-A145P", "DateTime":"2026:07:25 10:49:00", "Orientation":6, ...}

extract_gps
  INPUT:   Pillow Exif object
  PROCESS: get_ifd(34853); name via GPSTAGS; require lat/lat-ref/lon/lon-ref;
           convert_to_degrees x2; sign by hemisphere; build ?q=lat,lon URL
  OUTPUT:  {"Latitude": float, "Longitude": float, "Google Maps": str} | None

extract_lsb_bits -> bits_to_bytes -> bytes_to_text -> detect_pgp_key
  INPUT:   validated path
  PROCESS: convert("RGB") -> [r&1,g&1,b&1 per pixel] -> 8 bits/byte MSB-first -> UTF-8 decode(ignore) -> find BEGIN..END
  OUTPUT:  the PGP armor block str | None
  EXAMPLE: hidden.png -> "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----"
           image-example1.jpeg -> None  (JPEG: LSBs are decompressed noise)

save_output
  INPUT:   dict|str, filename, append
  PROCESS: open mode "a"/"w" (utf-8); dict -> "k: v\n" lines; str -> str(data)+"\n"
  OUTPUT:  a text file; "Data saved in <file>" on stdout
```

**End-to-end example (metadata + stego, combined):**
```
INPUT:  python image_inspector.py -m -s -o results.txt hidden.png
STEP 1: parse_arguments -> Namespace(metadata=True, steganography=True, output="results.txt", image="hidden.png")
STEP 2: validate_image("hidden.png") -> ".png" ok, verify() ok -> True
STEP 3: extract_metadata -> {} (a generated PNG has no EXIF)  -> prints "No metadata found." -> save_output("No metadata found.", "results.txt")  (mode "w")
STEP 4: extract_lsb_bits -> bits ; bits_to_bytes -> bytes ; bytes_to_text -> text-with-armor
STEP 5: detect_pgp_key -> "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: Test\n\nHello Mustapha\n\n-----END PGP PUBLIC KEY BLOCK-----"
STEP 6: print "===== HIDDEN PGP KEY FOUND =====" + the block ; save_output(block, "results.txt", append=True)
OUTPUT: results.txt =
        No hidden PGP key found.          <-- wait: metadata branch wrote "No metadata found." here
        -----BEGIN PGP PUBLIC KEY BLOCK-----
        Version: Test

        Hello Mustapha

        -----END PGP PUBLIC KEY BLOCK-----
        stdout: "No metadata found." , "Data saved in results.txt" x2 , "===== HIDDEN PGP KEY FOUND =====" , the block
```
*(The file's first line is `No metadata found.` — the metadata branch's message — followed by the appended PGP block.)*

---

## 9. Important Concepts

**TERM: Digital image forensics / metadata / EXIF**
- *Definition.* Metadata = "data about data." **EXIF** is the standard block of camera/image metadata embedded in JPEG/TIFF (and PNG via a chunk): make, model, timestamp, orientation, exposure, and optionally GPS.
- *Why it exists.* Cameras record shooting conditions for cataloguing, printing, and editing.
- *How it works.* Stored as **IFDs** — tables of `(numeric tag id, value)`. IFD-0 = basics; sub-IFDs (pointed to by tags `0x8769` Exif, `0x8825` GPS) hold the rest.
- *Why this project uses it.* Metadata is a primary OSINT/forensics artifact — especially the timestamp and location.
- *Without it.* No `-m` capability.
- *Example.* `Make: samsung`, `Model: SM-A145P`, `DateTime: 2026:07:25 10:49:00`.
- *Where.* `modules/metadata.py`, `PIL.ExifTags.TAGS`.

**TERM: GPS EXIF / DMS / decimal degrees / hemisphere sign**
- *Definition.* The GPS sub-IFD stores latitude/longitude as **degrees, minutes, seconds** (three rationals) plus a reference letter (`N`/`S`, `E`/`W`). "Decimal degrees" is the single-number form used by maps.
- *Why it exists.* DMS is the traditional navigational notation; EXIF inherited it.
- *How it works.* `decimal = d + m/60 + s/3600`; negate for `S`/`W`.
- *Why this project uses it.* To make the location *usable* — a raw `((34,1),(1,1),(15168,1000))` tuple isn't clickable; `34.02088, -6.833333` and a Maps URL are.
- *Without it.* The user would have to convert DMS by hand and worry about the sign.
- *Where.* `modules/gps.py` (`extract_gps`, `convert_to_degrees`, `GPSTAGS`).

**TERM: Steganography vs cryptography**
- *Definition.* **Cryptography** hides the *content* of a message (you can see there's a message, you can't read it). **Steganography** hides the *existence* of the message (it looks like an ordinary file).
- *Why it exists.* To communicate without drawing attention; to watermark; (offensively) to exfiltrate data past DLP that only inspects visible content.
- *How it works here.* LSB embedding (below).
- *Why this project uses it.* `-s` is a *detector* — steganalysis for a specific payload type.
- *Without it.* No `-s` capability.
- *Where.* `modules/steganography.py`; the companion `HideMessageinImage.py` is the embedder.

**TERM: LSB (least-significant-bit) steganography**
- *Definition.* Hiding data in the lowest bit of each colour channel value.
- *Why it exists.* The LSB changes brightness by at most 1/256 — imperceptible — so the whole LSB plane is "free space."
- *How it works.* Embed: `channel = (channel & ~1) | message_bit`. Extract: `bit = channel & 1`. 3 bits of capacity per RGB pixel ⇒ `3·W·H` bits total.
- *Why this project uses it.* It's the canonical beginner technique and the most common CTF stego.
- *Its fragility (important).* LSBs are destroyed by **lossy compression** (JPEG), resizing, colour-space conversion, format changes, and most "save as" operations. That's why the embedder writes **PNG** and why running `-s` on a `.jpeg` almost always finds nothing.
- *Detection beyond this tool.* Real steganalysis uses statistical tests (chi-square on LSB distribution, sample-pairs, RS analysis) rather than "decode all LSBs and grep."
- *Example.* R=200 (`…11001000`) hiding a `1` → 201 (`…11001001`); visually identical.
- *Where.* `extract_lsb_bits` (`r & 1`), `HideMessageinImage.hide_message` (`(x & ~1) | bit`).

**TERM: Bit / byte / MSB-first packing / bit masking**
- *Definition.* A **byte** is 8 bits. **MSB-first** ("big-endian bit order") means the first bit written is the most significant. **Masking** with `& 1` isolates the low bit; `& ~1` clears it.
- *Why it matters here.* Encoder and decoder must agree on bit order or every byte comes out reversed. Both use MSB-first (`format(n,'08b')` / `(v<<1)|bit`).
- *Where.* `bits_to_bytes`, `text_to_bits`.

**TERM: UTF-8 decoding / `errors="ignore"`**
- *Definition.* UTF-8 encodes text as 1–4 bytes per character with structural rules. `errors="ignore"` drops bytes that violate those rules instead of raising.
- *Why this project uses it.* The LSB plane of a real photo is noise; `ignore` collapses the noise while leaving any embedded 7-bit-ASCII payload intact and searchable.
- *Trade-off.* You lose the ability to detect a *binary* payload or a non-UTF-8 text payload — but the target here is an ASCII PGP armor block.
- *Where.* `bytes_to_text`.

**TERM: PGP / ASCII armor / public-key block**
- *Definition.* **PGP/OpenPGP** is public-key crypto for email/files. **ASCII armor** wraps binary OpenPGP data in a printable-text envelope: `-----BEGIN PGP PUBLIC KEY BLOCK-----`, headers, blank line, Base64 body, `=CRC`, `-----END PGP PUBLIC KEY BLOCK-----`.
- *Why this project targets it.* A public key is a plausible thing to smuggle in an image (key exchange over a covert channel), it's pure ASCII (survives the pipeline), and it has unambiguous delimiters.
- *What the tool does / doesn't do.* Finds the header/footer pair and returns the slice. Does **not** validate Base64, check the CRC, or import/parse the key.
- *Where.* `detect_pgp_key`; the encoder's demo message is exactly such a block.

**TERM: `argparse` / `store_true` / positional vs optional / `parser.error`**
- *Definition.* `argparse` builds a CLI parser from declarations. `action="store_true"` = a valueless flag defaulting to `False`. A positional arg (no dashes) is required by default. `parser.error(msg)` prints usage + `msg` to stderr and exits `2`.
- *Why this project uses it.* Standard, self-documenting (`--help` is generated), handles `-o FILE` and the required `image` cleanly.
- *The manual rule.* "at least one of `-m`/`-s`" is a cross-argument constraint `argparse` can't declare, so it's checked by hand and raised via `parser.error`.
- *Where.* `image_inspector.parse_arguments`.

**TERM: `pathlib.Path`**
- *Definition.* An object-oriented, OS-agnostic filesystem-path API.
- *Why here.* `Path(p).exists()`, `.is_file()`, `.suffix` are clearer and safer than `os.path` string-mangling.
- *Where.* `modules/utils.py`.

**TERM: Pillow lazy loading / `verify()` / `getexif()` / `convert()` / `getdata()` / `putdata()`**
- *Definition.* Pillow `Image.open` reads the header only (lazy). `verify()` checks structural integrity without decoding and **then invalidates the object**. `getexif()` returns the EXIF IFD-0. `convert("RGB")` returns a new image in that mode. `getdata()` iterates pixels; `putdata()` replaces them.
- *Why here.* `verify()` = a cheap corruption gate; `convert("RGB")` = a predictable pixel shape; the getdata/putdata pair is the read/write side of LSB work.
- *Gotcha.* After `verify()` you must re-`open()` — the code does.
- *Where.* `utils` (`verify`), `metadata` (`getexif`), `steganography` (`convert`, `getdata`), `HideMessageinImage` (`getdata`, `putdata`, `save`).

**TERM: NaN and the `x != x` test**
- *Definition.* IEEE-754 "Not a Number"; the only value for which `x != x` is `True`.
- *Why here.* A corrupt `0/0` GPS rational can decode to NaN; the check rejects it before it poisons the coordinate/URL.
- *Where.* `convert_to_degrees`.

**TERM: Decompression bomb / image-parser attack surface**
- *Definition.* A small file that decodes to an enormous bitmap (or a malformed file that triggers a parser bug), causing memory exhaustion or worse.
- *Why relevant.* `image-inspector` opens *attacker-supplied* images. `verify()` doesn't decode pixels, but `extract_metadata`/`extract_lsb_bits` do (`getexif` partially, `convert("RGB").getdata()` fully). There is **no `Image.MAX_IMAGE_PIXELS` override or size cap**, and `extract_lsb_bits` additionally builds a Python list of `3·W·H` ints.
- *Where.* `modules/metadata.py`, `modules/steganography.py` (see §13).

---

## 10. Libraries and Dependencies

### `pillow==12.3.0` (PIL fork) — the workhorse

**What it is.** The de-facto Python imaging library: open/save dozens of formats, pixel access, EXIF parsing, colour-space conversion, drawing.

**Why imported.** Everything image-related: format sniffing + integrity check (`Image.open`, `verify`), EXIF (`Image.getexif`, `PIL.ExifTags.TAGS` / `GPSTAGS`, `Exif.get_ifd`), pixel I/O (`convert`, `getdata`, `putdata`, `save`).

**Which functions/attributes are used.**
| Symbol | Used in | For |
|---|---|---|
| `Image.open(path)` | utils, metadata, steganography, encoder | lazy-open an image |
| `Image.verify()` | utils | structural corruption check (no pixel decode) |
| `Image.getexif()` | metadata | the EXIF IFD-0 dict-like |
| `Exif.get_ifd(34853)` | gps | the nested GPS sub-IFD |
| `PIL.ExifTags.TAGS` | metadata | tag id → human name (IFD-0) |
| `PIL.ExifTags.GPSTAGS` | gps | tag id → human name (GPS IFD) |
| `Image.convert("RGB")` | steganography, encoder | normalize to 8-bit R,G,B |
| `Image.getdata()` | steganography, encoder | iterate pixels in scan order |
| `Image.putdata(seq)` | encoder | replace all pixels |
| `Image.save(path)` | encoder | serialize (PNG in the demo) |

**Why not implement it ourselves.** Parsing JPEG (Huffman + DCT), PNG (zlib + filters + CRC), EXIF/TIFF IFD chains, and dozens of colour modes correctly and safely is a multi-year effort. `verify()` alone encodes a lot of format knowledge.

**What it does internally (high level, not visible in this repo).** `Image.open` sniffs magic bytes, picks a format plugin, reads the header into an `Image` object without decoding pixels. `getexif()` locates the APP1/`Exif\0\0` segment (JPEG) or `eXIf`/text chunk (PNG), parses the TIFF-structured IFD, and exposes it as a mapping; `get_ifd(tag)` follows a sub-IFD offset. `convert("RGB")` runs the pixel pipeline (decode → mode transform). **Details beyond this are not in the provided source and are not asserted here.**

### `piexif==1.1.3` — **declared but unused**

Listed in `requirements.txt` but **not imported by any module** in this project. `piexif` is a lightweight EXIF read/**write** library (Pillow's EXIF *write* support is historically weaker). It looks like it was intended for a feature (EXIF editing / stripping?) that was never built, or was replaced by `Image.getexif()`. **A reviewer should either remove it from `requirements.txt` or note the intended-but-absent feature.** Installing it is harmless.

### Standard library
`argparse` (CLI), `pathlib` (path checks). That's all.

### PROJECT CODE vs LIBRARY CODE

| Project code | Library (Pillow) code |
|---|---|
| the arg rules, the two-branch orchestration, the append coupling | `Image.open`, format plugins, `verify()` |
| `SUPPORTED_EXTENSIONS` set + the four validation gates | EXIF/TIFF IFD parsing behind `getexif()`/`get_ifd()` |
| DMS→decimal math, hemisphere sign, the Maps URL | `IFDRational` arithmetic, `TAGS`/`GPSTAGS` tables |
| the LSB read loop, MSB-first bit packing, UTF-8-ignore decode, the PGP header/footer search | `convert("RGB")` pixel pipeline, `getdata()`/`putdata()` iteration |
| `save_output` file-mode logic | Python's built-in `open`/`str` (also stdlib, not project) |

---

## 11. Operating System / Network / Database Concepts

**No network. No database.** The tool reads a local file and writes a local file. Relevant layers:

### 11.1 Reading an image, layer by layer
```
image_inspector.py
   │  Image.open(path)  /  path.exists()/.is_file()/.suffix
   ▼
Pillow  →  Python file object  →  CPython io  →  libc  →  open()/read()/fstat() syscalls
   ▼
kernel VFS  →  filesystem driver (ext4/APFS/NTFS)  →  block device
   ▼
raw bytes back up the stack  →  Pillow format plugin parses header  →  Image object
```
- `Path.suffix` is pure string work (no syscall). `exists()`/`is_file()` do a `stat()`.
- `verify()` reads and walks structural markers but **does not** allocate the full pixel buffer.
- `convert("RGB").getdata()` **does** decode every pixel — this is where a decompression bomb would bite.

### 11.2 Writing output, layer by layer
```
save_output(data, filename, mode)
   │  open(filename, "w"|"a", encoding="utf-8")   →   O_WRONLY|O_CREAT|O_TRUNC  /  O_WRONLY|O_CREAT|O_APPEND
   ▼
CPython io buffered writer  →  libc  →  write()  →  kernel VFS  →  filesystem  →  disk
```
- `"w"` ⇒ `O_TRUNC` (existing content erased); `"a"` ⇒ `O_APPEND` (writes always go to EOF). This is exactly the mechanism the `append=args.metadata` flag toggles.
- No path normalization ⇒ the OS resolves `filename` (including `..` and absolute paths) with the invoking user's permissions.

### 11.3 The one "network-shaped" artifact
`extract_gps` builds `https://maps.google.com/?q=lat,lon`. This is a **string**, printed and/or saved. The tool performs **no DNS lookup and no HTTP request**. Concepts worth knowing *if a user clicks it*: it's an HTTPS URL; `?q=` is a query parameter; `lat,lon` in that parameter tells Google Maps to centre/pin at that coordinate.

### 11.4 EXIF as a mini "database"
Not a real DB, but structurally: EXIF is a **key/value store** (tag id → value) organized into linked tables (IFDs). `getexif()` is the "read all rows of IFD-0" query; `get_ifd(34853)` is a "follow the foreign key to the GPS table" query. There is no write path in this project (that's what `piexif` would have been for).

---

## 12. Error Handling

| What can fail | Where | Why | How detected | Result |
|---|---|---|---|---|
| No mode flag | `parse_arguments` | user ran with just `image` | `not args.metadata and not args.steganography` | `parser.error` → stderr usage → **exit 2** |
| Unknown/missing CLI arg | `argparse` | typo, missing positional | argparse internal | stderr usage → **exit 2** |
| Path missing | `validate_image` | wrong path | `not Path.exists()` | `FileNotFoundError` → caught in `main` → `Error: File not found: …` → **exit 0** |
| Path is a directory | `validate_image` | user passed a folder | `not Path.is_file()` | `FileNotFoundError("… is not a file.")` → `main` → exit 0 |
| Wrong extension | `validate_image` | `.txt`, `.gif`, `.webp`, … | `suffix not in SUPPORTED_EXTENSIONS` | `ValueError` → `main` → exit 0 |
| Corrupt / truncated / not-an-image | `validate_image` | bad bytes, renamed file | `Image.verify()` raises | re-raised `OSError("Invalid or corrupted image: …")` → `main` → exit 0 |
| EXIF parse error | `extract_metadata` | malformed EXIF | Pillow raises inside the `try` | re-raised `Exception("Error extracting metadata: …")` → `main` → exit 0 |
| No EXIF present | `extract_metadata` | PNG screenshot, stripped JPEG | `if not exif_data` | returns `{}` → `main` prints `No metadata found.` (not an error) |
| GPS absent/partial | `extract_gps` | location was off | empty IFD / `required` check fails / `convert_to_degrees` None | returns `None` → no GPS keys added (silent) |
| Legacy GPS rational shape / NaN | `convert_to_degrees` | odd EXIF | `TypeError`/`ValueError` caught; `x != x` | returns `None` → GPS silently omitted |
| Image decode error in stego | `extract_lsb_bits` | corrupt pixels, exotic mode | Pillow raises inside `try` | re-raised `Exception("Error extracting LSB bits: …")` → `main` → exit 0 |
| Output file unwritable | `save_output` | `PermissionError`, path is a dir, missing parent dir | `open()` raises | re-raised `Exception("Error saving output: …")` → `main` → exit 0 |
| Pillow not installed | import time | missing dependency | `ModuleNotFoundError` at `import` | **uncaught** — traceback, non-zero exit (this is before `main`'s try) |
| Huge image (decompression bomb) | `extract_metadata` / `extract_lsb_bits` | malicious/large input | none — no size cap | `MemoryError` (may be caught by `main` as `Error: …`) or process kill by OS |

**Recovery mechanisms.** Essentially none — there is no retry, no fallback path. The design is "validate up front, then let one blanket `try/except` in `main` turn any failure into a printed `Error: {e}` line." Notably:
- **Every handled error still exits `0`.** A script/CI calling this tool cannot distinguish "found nothing" from "crashed" by exit code alone. `test.sh` prints `Exit code: $?` and will see `0` even for `Error: …`.
- **Error type is flattened.** `extract_metadata` and the stego functions re-raise as bare `Exception`, discarding the original class — `main` only ever prints the message.
- **Two functions print debug noise on every call** (`validate_image` → `ENTER to THE function -------`; `extract_lsb_bits` → `extract lbs bits -----*` and `test`) — harmless to correctness, but they pollute stdout and would corrupt a machine-readable pipeline. Left-over development scaffolding.
- **`validate_image`'s "docstring" isn't one** — the triple-quoted string sits *after* a `print(...)` statement, so it's a no-op expression, not `__doc__`.

---

## 13. Security Analysis

`image-inspector` has no auth, no network, no privileged operations. Its risk surface is **(a) parsing hostile image files** and **(b) writing to a user-controlled path**, plus **(c) the privacy sensitivity of what it extracts**.

### 13.1 Parsing untrusted images (primary attack surface)
- **Why the operation is necessary.** The whole point is to inspect files you didn't create (CTF drops, evidence, OSINT targets).
- **What could go wrong.**
  - **Decompression bomb / resource exhaustion.** A tiny file that decodes to a gigapixel image. `validate_image`'s `verify()` doesn't decode pixels, but `extract_metadata` (`getexif`) and especially `extract_lsb_bits` (`convert("RGB").getdata()` + a `3·W·H`-element Python list) do. There is **no `Image.MAX_IMAGE_PIXELS` cap and no dimension check** → `MemoryError` / swap thrash / OOM-kill. The list-building in `extract_lsb_bits` multiplies the cost (~28 bytes per int).
  - **Malformed-file parser bugs.** Pillow has had CVEs (heap overflows, infinite loops) in various format decoders. Pinning `pillow==12.3.0` is good hygiene, but it's still a large C-backed parser fed attacker bytes. `verify()` reduces but does not eliminate this (metadata/pixel decode still happens after).
- **How the project protects itself.** Extension allow-list (weak — content is what matters), and `verify()` as a structural pre-check. That's it. **No pixel/size cap, no sandbox, no timeout.**

### 13.2 Output path handling
- **Why necessary.** `-o` is a core feature.
- **What could go wrong.** `save_output` uses `args.output` **verbatim** — `-o ../../.bashrc` or `-o /etc/anything` will attempt the write (succeeding only where the invoking user already has write permission). `"w"` mode **truncates** an existing file first. So a careless `-o` can destroy an unrelated file the user owns.
- **How the project protects itself.** Not at all — no path normalization, no "must be under CWD" check, no refusal to overwrite. In practice the blast radius is "files the user can already write," so this is a foot-gun, not a privilege issue.

### 13.3 Privacy / data-sensitivity of the *findings*
- **GPS extraction is a deanonymization primitive.** `extract_gps` turns a photo into "this was taken at 34.02088, -6.83333" plus a map link — potentially someone's home. The README's Ethical Use section explicitly says: only analyze images you're authorized to. The tool doesn't (and can't) enforce that; the control is procedural.
- **The Google Maps URL** embeds the coordinates in a string that might get pasted into logs, tickets, or chat — spreading the sensitive datum further. The tool never *fetches* the URL (no data sent to Google), but the string is now in your output file.
- **No secrets, no credentials, no keys** are handled by the tool itself. The "PGP public key" it looks for is, by definition, public.

### 13.4 The companion encoder (`HideMessageinImage.py`)
- It's a **dual-use** tool: legitimately, it generates test images for the detector; the same code hides arbitrary data (including exfiltrated secrets) in an image. It's standalone and not wired into the CLI, which keeps the attack tool separate from the analysis tool. Nothing here is exploitable *against the user*; it's a capability note.

### 13.5 Trust boundaries
```
[user CLI args] ── argparse ──► args           (trusted-ish: the user's own machine)
[image file bytes] ── Pillow ──► Image/EXIF/pixels   ◄── the real trust boundary: hostile input parsed by a big C library
[args.output path] ── open() ──► filesystem     ◄── unsanitized, but bounded by the user's own permissions
```

### 13.6 Security assumptions
1. The user is authorized to inspect the image (privacy/legal).
2. Input images are not adversarially crafted to exploit Pillow or exhaust memory (no size/parser hardening).
3. `-o` targets are intentional (no overwrite protection).
4. Output (coordinates, map links, any recovered text) is handled as potentially sensitive by the user.

### 13.7 Vulnerabilities supported by the code (no invention)
- **Unbounded image dimensions** → memory-exhaustion DoS in `extract_metadata` / `extract_lsb_bits` (no `MAX_IMAGE_PIXELS`, no dimension guard, plus a `3·W·H` Python list). *Confirmed by code.*
- **Path traversal / arbitrary same-user overwrite** via `-o` (`save_output` uses the path verbatim, `"w"` truncates). *Confirmed by code.*
- **Stdout pollution** from leftover debug prints — breaks any machine-readable consumer. *Confirmed by code.*
- **Exit code `0` on all handled errors** — callers can't detect failure by exit status. *Confirmed by code.*
- **Broad `except Exception`** in `main`, `extract_metadata`, `bytes_to_text`, `extract_lsb_bits`, `save_output` — masks/renames the real error type; a Pillow security-relevant exception is reduced to a one-line print. *Confirmed by code.*

---

## 14. Data Flow

### 14.1 Metadata + GPS
```
photo.jpg (bytes)
  ── Image.open ──► lazy Image
  ── getexif() ──► Exif { 271:'samsung', 272:'SM-A145P', 274:6, 306:'2026:07:25 10:49:00', 34853:<GPS ptr>, ... }
       │
       ├─ get_ifd(34853) ──► { 1:'N', 2:(34,1,15.168), 3:'W', 4:(6,50,0.0), ... }
       │       ── GPSTAGS rename ──► { 'GPSLatitudeRef':'N', 'GPSLatitude':(34,1,15.168), 'GPSLongitudeRef':'W', 'GPSLongitude':(6,50,0.0) }
       │       ── convert_to_degrees ──► lat=34.02088, lon=6.833333
       │       ── ref 'W' ──► lon=-6.833333
       │       ── ──► { 'Latitude':34.02088, 'Longitude':-6.833333, 'Google Maps':'https://maps.google.com/?q=34.02088,-6.833333' }
       ▼
  metadata = { 'Latitude':..., 'Longitude':..., 'Google Maps':..., 'Make':'samsung', 'Model':'SM-A145P', 'DateTime':'2026:07:25 10:49:00', 'Orientation':6, ... }
  ── print "k: v" lines ──► stdout
  ── save_output(metadata, "out.txt") ──► out.txt (mode "w")
```
Shape: file bytes → `Exif` mapping (numeric keys) → GPS sub-mapping → DMS tuples → two floats → a signed-and-URL'd dict → merged name-keyed `dict` → text lines on screen / in a file.

### 14.2 Steganography
```
hidden.png (bytes)
  ── Image.open.convert("RGB").getdata() ──► [(r0,g0,b0),(r1,g1,b1), ...]   (W*H pixels)
  ── per pixel: r&1,g&1,b&1 ──► bits = [0,1,1, 0,0,1, ...]                  (3*W*H ints)
  ── bits_to_bytes (8/byte, MSB-first, drop remainder) ──► [45,45,45,45,45,66,69,71,73,78, ...]
  ── bytes(...).decode("utf-8","ignore") ──► "…noise…-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----…noise…"
  ── detect_pgp_key: find BEGIN (idx s), find END from s (idx f), slice [s : f+len(END)] ──►
     "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: Test\n\nHello Mustapha\n\n-----END PGP PUBLIC KEY BLOCK-----"
  ── print under "===== HIDDEN PGP KEY FOUND ====="  /  save_output(block, "out.txt", append=(-m was given))
```
Shape: file bytes → pixel tuples → a bit list → a byte list → one big (mostly-noise) string → a clean substring (the armor block) or `None`.

### 14.3 Where a datum changes meaning
- `274` (int) → `"Orientation"` (name) → `6` printed (still just an int; the tool doesn't interpret "6 = rotate 90° CW").
- `(34,1,15.168)` (DMS rationals) → `34.02088` (decimal) → `-6.833333` after hemisphere sign → embedded in a URL string.
- `r & 1` (a single bit of one pixel) → one of 8 bits of a byte → one character of a string → part of a matched PGP block or discarded noise.

---

## 15. Real Execution Example

### 15.1 Metadata on a phone photo
```
$ python image_inspector.py -m image-example1.jpeg
ENTER to THE function -------                 # stray debug print from validate_image
===== METADATA =====
Latitude: 34.020882
Longitude: -6.833469
Google Maps: https://maps.google.com/?q=34.020882,-6.833469
Make: samsung
Model: SM-A145P
DateTime: 2026:07:25 10:49:00
Orientation: 6
XResolution: 72.0
YResolution: 72.0
ResolutionUnit: 2
Software: A145PXXU...
YCbCrPositioning: 1
ExifOffset: 232
```
Internally: `validate_image` passes all four gates; `extract_metadata` calls `getexif()`, then `extract_gps` follows `get_ifd(34853)`, renames via `GPSTAGS`, `convert_to_degrees` does `34 + 1/60 + s/3600`, applies the `W` sign to longitude, and builds the URL; the IFD-0 loop renames the rest via `TAGS`, skipping `bytes` values and the raw `GPSInfo`.

### 15.2 Metadata + save
```
$ python image_inspector.py -m -o metadata.txt image-example1.jpeg
ENTER to THE function -------
===== METADATA =====
... (as above) ...
Data saved in metadata.txt
$ cat metadata.txt
Latitude: 34.020882
Longitude: -6.833469
Google Maps: https://maps.google.com/?q=34.020882,-6.833469
Make: samsung
Model: SM-A145P
DateTime: 2026:07:25 10:49:00
Orientation: 6
...
```
`save_output(dict, "metadata.txt")` → `append=False` → mode `"w"` → one `key: value` line per entry.

### 15.3 Steganography — negative (JPEG)
```
$ python image_inspector.py -s image-example1.jpeg
ENTER to THE function -------
extract lbs bits -----*
test
No hidden PGP key found.
```
JPEG is lossy: `convert("RGB")` yields decompressed pixels whose LSBs are effectively random. `bits_to_bytes`/`bytes_to_text` produce noise; `detect_pgp_key` finds no `-----BEGIN …` → `None`. (This is the expected result the README/`test.sh` call out.)

### 15.4 Steganography — positive (PNG made by the encoder)
```
# 1) create a stego image
$ cd Message_Hide_in_image
$ python HideMessageinImage.py
Hidden 640 bits.
Saved as ../hidden.png
$ cd ..

# 2) detect it
$ python image_inspector.py -s hidden.png
ENTER to THE function -------
extract lbs bits -----*
test

===== HIDDEN PGP KEY FOUND =====
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: Test

Hello Mustapha

-----END PGP PUBLIC KEY BLOCK-----
```
`hide_message` wrote the armor block (+ `###END###`) into the LSBs of the first ~640/3 ≈ 214 pixels of `local.jpg` and saved lossless PNG. The detector reads all LSBs, packs MSB-first, UTF-8-decodes with `ignore`, and `detect_pgp_key` slices from `-----BEGIN …` through `-----END …` (the `###END###` marker is left outside the slice and ignored).

### 15.5 Combined + save
```
$ python image_inspector.py -m -s -o results.txt hidden.png
ENTER to THE function -------
No metadata found.                      # a freshly generated PNG has no EXIF
Data saved in results.txt               # save_output("No metadata found.", "results.txt", append=False → "w")
extract lbs bits -----*
test

===== HIDDEN PGP KEY FOUND =====
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: Test

Hello Mustapha

-----END PGP PUBLIC KEY BLOCK-----
Data saved in results.txt               # save_output(block, "results.txt", append=True → "a")

$ cat results.txt
No metadata found.
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: Test

Hello Mustapha

-----END PGP PUBLIC KEY BLOCK-----
```

---

## 16. Why This Design?

- **Why split into `modules/` instead of one file?** Each concern (validation / EXIF / GPS / stego / output) has a distinct dependency and can be tested and reasoned about alone; `image_inspector.py` stays a thin orchestrator. *Alternative:* one script — fine for this size, but the split makes `metadata → gps` reuse and future extension (new detectors) clean.
- **Why functions, not classes?** There's no persistent state or polymorphism — every step is `input → output`. Classes would add ceremony (an `Analyzer` object holding a path) with no benefit. *Alternative:* a class per analysis mode with a common interface — worth it only if you expect many pluggable detectors.
- **Why `getexif()` (Pillow) instead of `piexif` or raw parsing?** `getexif()` covers the read path with tag-name maps (`TAGS`/`GPSTAGS`) and sub-IFD following (`get_ifd`) already. `piexif` shines for *writing* EXIF, which this tool doesn't do — hence it's an unused dependency.
- **Why `verify()` as the validation step (vs `.load()` / full decode)?** `verify()` is cheap and catches truncation/corruption without allocating the pixel buffer. *Downside:* it invalidates the object (must re-open), and it doesn't stop a decompression bomb (dimensions can be valid but enormous). A stronger design would also check `Image.size` against a cap and set `Image.MAX_IMAGE_PIXELS`.
- **Why `convert("RGB")` before LSB work?** To make "3 channels, 8 bits, `(r,g,b)` tuple" a guarantee regardless of the source mode (`P`, `L`, `RGBA`, `CMYK`). *Downside:* on a JPEG it silently produces decompressed noise, so `-s` on JPEGs is near-useless (arguably the tool should warn "LSB stego doesn't survive JPEG").
- **Why MSB-first bit packing?** It matches `format(ord(c), '08b')` in the companion encoder and is the more "human" reading order. The only hard requirement is that encoder and decoder agree; they do.
- **Why `errors="ignore"` on the UTF-8 decode?** The LSB plane of a real photo is noise; `ignore` discards the noise so a genuine ASCII payload stands out. *Alternative:* `errors="replace"` (keeps `�` placeholders — noisier) or scanning the raw bytes with a regex (would also catch binary-adjacent payloads). For "find a PGP armor block," ignore-decode + `str.find` is the simplest thing that works.
- **Why look only for a PGP *public key* block?** It's a realistic covert-channel payload, it's pure ASCII (survives the pipeline), and it has unambiguous `BEGIN`/`END` delimiters — so detection is a two-`find` operation with no false-positive tuning. *Limitation:* it misses every other payload type (that's in the README's "Limitations").
- **Why `-o` append only when `-m` is also present?** So a combined run yields one coherent file (metadata, then stego verdict) while a `-s`-only run doesn't accidentally append to a stale file. `append=args.metadata` is the minimal expression of that intent.
- **Why one blanket `try/except` in `main` instead of per-call handling?** Simplicity — every failure becomes `Error: {e}`. *Downsides:* exit code stays `0`, and the specific exception types raised by `validate_image` are collapsed to their message. A more robust CLI would map exception type → exit code.
- **Why keep the encoder separate and un-imported?** It's an *offensive* capability; keeping it out of the analysis tool's import graph means running `image_inspector.py` never loads embedding code, and the two concerns stay clearly labelled.

---

## 17. Interview / Oral Defense Questions

### Beginner

**B1. What two things can this tool tell you about an image?** — (1) its EXIF metadata (camera make/model, timestamp, orientation, and GPS as decimal coordinates + a Maps link); (2) whether a PGP public-key block is hidden in the pixels' least-significant bits. *(README Features; `image_inspector.main`.)*

**B2. What does `-m` vs `-s` do, and what if you pass neither?** — `-m` = metadata, `-s` = steganography detection. Neither → `parser.error("At least one analysis option (-m or -s) is required.")` → exit 2. *(`parse_arguments`.)*

**B3. What is EXIF?** — A block of camera/image metadata embedded in JPEG/TIFF (tag id → value), organized into IFDs. Read here via `Image.getexif()`. *(`modules/metadata.py`.)*

**B4. How does the tool turn EXIF GPS into a normal coordinate?** — GPS is stored as degrees/minutes/seconds; `convert_to_degrees` computes `d + m/60 + s/3600`, then `S`/`W` refs negate the value. *(`modules/gps.py`.)*

**B5. What is LSB steganography?** — Hiding data in the least-significant bit of each colour channel; the change (±1 in 256) is invisible. Extract with `channel & 1`. *(`extract_lsb_bits`.)*

**B6. Why does `-s` on a `.jpeg` almost always find nothing?** — JPEG is lossy; decompressing to RGB does not preserve arbitrary LSBs, so the hidden bits are destroyed. The companion encoder saves PNG for that reason. *(§9 LSB; `test.sh` comment.)*

**B7. What does `detect_pgp_key` actually check for?** — The literal strings `-----BEGIN PGP PUBLIC KEY BLOCK-----` and `-----END PGP PUBLIC KEY BLOCK-----`, returning the slice between (inclusive) or `None`. *(`detect_pgp_key`.)*

**B8. What does `-o file` do, and what happens if you also pass `-m`?** — Saves the output to `file`. With `-m` present, the stego result is *appended* after the metadata (`append=args.metadata`); `-s` alone overwrites. *(`save_output`, `main`.)*

**B9. What checks does `validate_image` run?** — exists → is a file → extension in `{.jpg,.jpeg,.png,.bmp,.tiff}` → `Image.open().verify()` passes. *(`modules/utils.py`.)*

**B10. Which library does the heavy lifting, and which listed dependency is unused?** — Pillow does everything; `piexif` is in `requirements.txt` but never imported. *(§10.)*

### Intermediate

**I1. Trace the four-stage steganography pipeline with types.** — `extract_lsb_bits(path) -> list[int]` (0/1, length `3·W·H`) → `bits_to_bytes(bits) -> list[int]` (0–255, MSB-first, trailing partial byte dropped) → `bytes_to_text(list) -> str` (`decode("utf-8", errors="ignore")`) → `detect_pgp_key(str) -> str | None`. *(`modules/steganography.py`.)*

**I2. Why MSB-first in `bits_to_bytes`, and what breaks if the encoder disagrees?** — `value = (value<<1)|bit` puts the first bit at position 7. The companion encoder's `format(ord(c),'08b')` is also MSB-first. If one side were LSB-first, every decoded byte would be bit-reversed and the text would be garbage — `detect_pgp_key` would find no header. *(`bits_to_bytes`, `text_to_bits`.)*

**I3. Why `errors="ignore"` on the decode, and what does it cost you?** — The LSB plane of a real photo is noise; `ignore` drops invalid UTF-8 so a real ASCII payload survives contiguous and searchable. Cost: you can't detect binary or non-UTF-8 payloads. *(`bytes_to_text`; §9.)*

**I4. `verify()` "invalidates" the Image object — where does that matter?** — After `validate_image` calls `verify()`, downstream code must `Image.open` again; `extract_metadata` and `extract_lsb_bits` each do a fresh `open`, so it's handled. A bug would be `verify()` then `.getexif()` on the same object. *(§9 Pillow; `utils` vs `metadata`/`steganography`.)*

**I5. How does a combined `-m -s -o out.txt` run produce one file?** — Metadata branch calls `save_output(dict, out, append=False)` → mode `"w"` (truncate + write). Stego branch calls `save_output(msg, out, append=args.metadata)` → `args.metadata` is `True` → mode `"a"` (append). *(`main`, `save_output`.)*

**I6. What's the `x != x` check in `convert_to_degrees` for?** — NaN detection: `x != x` is `True` only for IEEE-754 NaN. A corrupt `0/0` GPS rational could decode to NaN; the check returns `None` so the coordinate/URL isn't poisoned. *(`convert_to_degrees`.)*

**I7. Why does `extract_metadata` skip `bytes` values and `GPSInfo`?** — `bytes` values are binary blobs (`MakerNote`, thumbnails) that would print as mojibake; the raw `GPSInfo` is an IFD pointer already decoded by `extract_gps`, so its raw form is redundant. *(`extract_metadata`.)*

**I8. What exit code does the tool return when the image is missing, and why is that a problem?** — `0`. `validate_image` raises `FileNotFoundError`, `main`'s `except` prints `Error: …` and the program falls through to a normal exit. A calling script can't tell success from failure by exit status. *(§12; `main`.)*

**I9. The `###END###` marker in the encoder — does the CLI use it?** — No. `detect_pgp_key` relies on the `-----END PGP PUBLIC KEY BLOCK-----` footer and slices up to it; the `###END###` sentinel ends up outside the returned slice and is ignored. It's vestigial for this project. *(`HideMessageinImage`, `detect_pgp_key`.)*

**I10. Where would a large-image DoS actually hit, given `verify()` runs first?** — `verify()` doesn't decode pixels, so it passes a "valid but gigantic" image. The blow-up is in `extract_metadata`'s `getexif`/decode and especially `extract_lsb_bits`'s `convert("RGB").getdata()` plus the `3·W·H` int list. No `MAX_IMAGE_PIXELS` or dimension cap exists. *(§13.1.)*

### Advanced

**A1. Design a more robust steganalysis than "decode all LSBs and grep." What would you add?** — A capacity/entropy check on the LSB plane (a photo's LSBs are near-random; an embedded message region has different statistics — chi-square on the 0/1 distribution, sample-pairs / RS analysis to estimate embedding rate); look for the payload only in the low-index prefix (where sequential embedders write); support multiple markers and a length header; scan raw bytes with a regex rather than a lossy UTF-8 decode so binary payloads register. *(§9 LSB fragility/detection.)*

**A2. The extractor reads R,G,B LSBs of *every* pixel and never stops at `###END###`. What are the consequences?** — For a real hit it still works (the header/footer are found early and sliced out; trailing noise is discarded). But it wastes time/memory decoding the whole `3·W·H` plane even when the payload is 500 bytes, and it can't distinguish "message ends here" from "noise resumes" — so a payload without the exact PGP footer string would be reported as *not found* even if fully present. *(`extract_lsb_bits`, `detect_pgp_key`.)*

**A3. `save_output` writes `args.output` verbatim in `"w"` mode. Give the failure scenario and a fix.** — `python image_inspector.py -m -o ~/.bashrc photo.jpg` truncates and overwrites `~/.bashrc` with `key: value` lines (only where the user already has write perms). Fix: resolve the path, refuse paths outside a configured output dir (or outside CWD), refuse to overwrite without `--force`, and/or write to a temp file + atomic rename. *(§13.2.)*

**A4. `extract_metadata` catches everything and re-raises as bare `Exception`. What information is lost and why does it matter?** — The original exception *type* (`UnidentifiedImageError`, `OSError`, a Pillow-internal error, `MemoryError`) and traceback context. `main` then only prints `Error: Error extracting metadata: <str>`. A caller/operator can't branch on "corrupt file" vs "out of memory" vs "parser bug (possible CVE)", and automated triage of a security-relevant failure is impossible. Fix: let typed exceptions propagate, or re-raise with `raise ... from e`. *(§12; `extract_metadata`.)*

**A5. Why is `.bmp`/`.tiff` in `SUPPORTED_EXTENSIONS` but the README says only JPEG/PNG? Does it matter?** — `utils` accepts them but the pipelines assume EXIF (BMP has none → `-m` yields `{}` → "No metadata found.") and lossless pixels (BMP/TIFF are fine for `-s`; TIFF can carry EXIF). It's a mild inconsistency: `-s` on a BMP/uncompressed-TIFF would actually work well, `-m` on BMP never will. Not a bug, but the docs and the allow-list disagree. *(`utils` vs README.)*

**A6. The GPS `except KeyError` around `get_ifd(34853)` — is it doing anything?** — In current Pillow, `Exif.get_ifd(tag)` returns `{}` for an absent sub-IFD rather than raising `KeyError`, so that handler is likely **dead code**; the real "no GPS" path is `gps_info == {}` → the `required`-tags `all(...)` check fails → `None`. Harmless, but a reviewer should either remove it or note it guards an older Pillow behavior. *(`extract_gps`.)*

**A7. Two functions print debug lines on every run. Beyond untidiness, what concrete harm?** — `validate_image` prints `ENTER to THE function -------`; `extract_lsb_bits` prints `extract lbs bits -----*` and `test`. Any consumer that parses stdout (a CI check, a wrapper script, `test.sh`'s `cat`) now has non-data lines interleaved with results; piping `-m` output straight into another tool is corrupted. Also, `validate_image`'s triple-quoted string is *after* the print, so it's not even a docstring. Fix: delete the prints (or route real diagnostics to `stderr`/`logging`). *(§12; `utils`, `steganography`.)*

**A8. If you had to make `-s` meaningful on JPEGs, what are the options?** — You can't recover *LSB-plane* stego from a re-encoded JPEG. Real JPEG steganography lives in the **DCT coefficients** (JSteg, F5, OutGuess, steghide); detecting/extracting those requires reading the quantized coefficients (e.g. via a JPEG-aware library), not `convert("RGB")`. Minimum viable improvement: detect the input is JPEG and print "LSB analysis is not applicable to lossy JPEG; no result" instead of a misleading "No hidden PGP key found." *(§9 LSB fragility; `extract_lsb_bits`.)*

**A9. Trace exactly how one pixel's blue channel becomes one character.** — Say pixel 3's blue = 201 (`0b11001001`). `extract_lsb_bits` appends `201 & 1 = 1` at bit-list index 11 (pixel 3 → indices 9,10,11 for R,G,B). `bits_to_bytes` groups indices 8–15 into one byte, MSB-first: if that group is `[0,1,0,0,1,0,0,1]` → `0b01001001` = 73. `bytes_to_text` → `chr(73)` = `'I'`. If it's inside the `BEGIN…END` span, it's part of the returned block; otherwise it's noise `detect_pgp_key` excludes. *(§14.2.)*

**A10. The tool builds a `maps.google.com` URL but the README stresses ethical use. What's the privacy argument?** — `extract_gps` converts a photo into a precise real-world location and a one-click map link — a deanonymization/stalking primitive when applied to someone else's photos. The tool can't verify authorization; the safeguard is procedural (the README's "only analyze images you have permission to"). Additionally the URL string propagates the coordinate into whatever log/file/ticket the output lands in. The tool never *contacts* Google, so no data is sent — but the sensitive datum is now more widely written down. *(§13.3; README Ethical Use.)*

---

## 18. "Explain This Code to an Interviewer"

**The whole tool.**
> "It's a small Python forensics CLI on top of Pillow. `argparse` takes `-m` for metadata, `-s` for steganography, an optional `-o` output file, and a required image path — at least one of `-m`/`-s` is enforced manually. `main` validates the file (exists, is a file, allowed extension, passes Pillow's `verify()`), then runs one or both analyses. Metadata: `Image.getexif()`, translate numeric tag IDs to names via `PIL.ExifTags.TAGS`, decode the GPS sub-IFD to signed decimal degrees plus a Google Maps URL, skip binary values. Steganography: force the image to RGB, take the least-significant bit of every R, G, B value, pack those bits MSB-first into bytes, UTF-8-decode with `errors='ignore'` so the noise collapses, and string-search for a `-----BEGIN PGP PUBLIC KEY BLOCK-----` … `-----END-----` pair. `-o` saves the same output; a combined `-m -s -o` run writes metadata then appends the stego verdict. There's a separate encoder script that does the inverse — LSB-embed a message and save PNG — to generate test images."

**GPS conversion.**
> "EXIF stores latitude and longitude as three fractions — degrees, minutes, seconds — plus a hemisphere letter. `convert_to_degrees` floats each fraction, rejects NaN with the `x != x` trick, and returns `d + m/60 + s/3600`. Then `extract_gps` negates the value for a `S` or `W` reference and formats `https://maps.google.com/?q=lat,lon`. It only proceeds if all four of latitude, latitude-ref, longitude, longitude-ref are present."

**The LSB pipeline.**
> "Four pure functions. `extract_lsb_bits` opens the image, forces RGB so every pixel is a clean `(r,g,b)`, and appends `r&1, g&1, b&1` for every pixel — that's the LSB plane, `3·width·height` bits. `bits_to_bytes` walks it eight bits at a time, MSB-first, dropping a trailing partial byte. `bytes_to_text` decodes those bytes as UTF-8 with `errors='ignore'`, which throws away the random noise while leaving a real ASCII payload intact. `detect_pgp_key` finds the BEGIN marker, then the END marker after it, and returns the slice or `None`. It's deliberately the simplest possible steganalysis — it only recognizes one payload type and only survives lossless formats."

**Where I'd push back in review.**
> "Three things: leftover `print` debug statements in `validate_image` and `extract_lsb_bits` that pollute stdout; every handled error exits 0, so a caller can't detect failure; and there's no cap on image size before `convert('RGB').getdata()` builds a multi-hundred-megabyte bit list, so a decompression-bomb image is a memory-exhaustion DoS. Also `piexif` is a declared-but-unused dependency."

---

## 19. Common Mistakes

1. **Running `-s` on a JPEG and concluding "nothing is hidden."** JPEG is lossy — LSB stego doesn't survive it. Test with a PNG/BMP, or use JPEG-DCT-aware tools for real JPEG stego.
2. **`verify()` then reusing the same `Image` object.** Pillow invalidates it; you must `Image.open` again. The code does — don't "optimize" that away.
3. **Assuming the extension check validates the file.** `.txt` renamed to `.png` passes `SUPPORTED_EXTENSIONS`; only `verify()` catches it.
4. **Expecting a non-zero exit on error.** Every handled error prints `Error: …` and exits `0`. Don't gate CI on `$?`.
5. **Piping `-m` output into another program.** The stray `print` lines (`ENTER to THE function`, `extract lbs bits -----*`, `test`) are interleaved with the real output.
6. **Flipping bit order.** If you modify the encoder or decoder, keep both MSB-first, or every byte comes out bit-reversed.
7. **Feeding a huge image.** No size cap — `extract_lsb_bits` will try to build a `3·W·H` int list and may OOM.
8. **Thinking `detect_pgp_key` verifies the key.** It only matches the armor header/footer; the Base64/CRC/key itself is never checked.
9. **Editing the "docstring" in `validate_image`.** It's not a docstring (it follows a statement); `help(validate_image)` won't show it.
10. **Combining `-s -o` and expecting append.** `-s` alone overwrites (`append=args.metadata` is `False`); only `-m -s -o` appends.
11. **Believing GPS is always present.** Location must have been enabled *and* the four required tags present; otherwise `extract_gps` returns `None` and no GPS lines appear — silently.
12. **Installing/relying on `piexif`.** It's listed but never imported; don't build a feature around assuming it's wired in.
13. **Analyzing arbitrary people's photos.** GPS extraction is a real privacy/legal issue — the README's ethical note is not decoration.

---

## 20. Final Project Summary

### What I MUST understand
1. **Two independent capabilities** — EXIF metadata (`-m`) and LSB stego detection (`-s`), wired by a thin `argparse` orchestrator with one blanket `try/except`.
2. **The metadata path** — `getexif()` → `TAGS`/`GPSTAGS` name mapping → GPS sub-IFD (`get_ifd(34853)`) → DMS→signed-decimal + Maps URL → skip `bytes`/`GPSInfo`.
3. **The DMS→decimal formula** and hemisphere sign (`S`/`W` negate).
4. **The stego pipeline** — `convert("RGB")` → per-channel `& 1` → MSB-first byte packing → UTF-8 `errors="ignore"` → `find(BEGIN)…find(END)`; and that it only works on **lossless** formats.
5. **The `append=args.metadata` coupling** that makes a combined run produce one file.
6. **The companion encoder** — LSB embed with `(x & ~1) | bit`, save PNG — exists to produce test inputs and is *not* imported by the CLI.
7. **The weaknesses** — stray debug prints, exit code 0 on all errors, no image-size cap (DoS), unsanitized `-o` path, bare-`Exception` re-raises, unused `piexif`, empty test files.
8. **The concepts** — EXIF/IFD, GPS DMS, steganography vs cryptography, LSB embedding and its fragility, MSB-first bit packing, PGP ASCII armor, decompression bombs.

### Architecture in 30 seconds
> "A Python + Pillow CLI. `-m` reads EXIF (names the tags, converts GPS to decimal degrees + a Maps link); `-s` pulls the least-significant bit of every RGB channel, packs them into bytes, decodes to text, and searches for a hidden PGP public-key block. `-o` saves the output; combining `-m -s -o` writes metadata then appends the stego result. Five small single-purpose modules, no classes, no network, no database. A separate script does the reverse (LSB-embed a message into a PNG) to make test images."

### Architecture in 2 minutes
> "`image_inspector.py` parses `-m`, `-s`, `-o FILE`, and a required `image` with `argparse`, enforcing 'at least one mode' by hand. `main` calls `validate_image` — path exists, is a file, extension in a small allow-list, and `Image.open().verify()` passes (a structural check that then invalidates the object, so later code re-opens). The metadata branch calls `extract_metadata`: `Image.getexif()` for IFD-0; if empty, return `{}` ('No metadata found.'). It calls `extract_gps`, which follows the GPS sub-IFD via `get_ifd(34853)`, renames sub-tags with `GPSTAGS`, requires latitude/longitude and their refs, converts the degrees/minutes/seconds rationals to `d + m/60 + s/3600` via `convert_to_degrees` (with a NaN guard), negates for `S`/`W`, and builds `https://maps.google.com/?q=lat,lon` — those three keys are injected first. Then it walks IFD-0, mapping tag IDs to names with `PIL.ExifTags.TAGS`, skipping `bytes` values and the raw `GPSInfo`. The result dict is printed as `key: value` lines and, if `-o`, written (`save_output`, mode `w`). The steganography branch is a four-function pipeline: `extract_lsb_bits` forces the image to RGB and appends `r&1, g&1, b&1` for every pixel; `bits_to_bytes` packs eight bits per byte MSB-first, dropping a trailing partial byte; `bytes_to_text` does `bytes(...).decode('utf-8', errors='ignore')` so the near-random LSB noise collapses while a real ASCII payload survives; `detect_pgp_key` returns the substring from `-----BEGIN PGP PUBLIC KEY BLOCK-----` through `-----END …-----` or `None`. The result is printed and, if `-o`, saved with `append=args.metadata` — so a combined run yields one file with metadata then the stego verdict. Any exception anywhere is caught in `main` and printed as `Error: {e}`, and the process still exits 0. Pillow does all image work; `piexif` is a declared-but-unused dependency; the `tests/` files are empty. A standalone `HideMessageinImage.py` performs the inverse LSB embedding (clearing each channel's LSB with `& ~1` then OR-ing in the message bit) and saves PNG, used to generate stego test images."

### Deep technical explanation
See §6 (function-by-function), §9 (every concept in TERM form), §11 (the file-I/O layers; EXIF as a key/value store), §12 (the full failure table and the design's error-handling gaps), §13 (image-parser attack surface, decompression bombs, the `-o` overwrite foot-gun, privacy of GPS extraction). §14 traces the metadata and stego data journeys; §15 shows five real runs including the encoder→detector round trip.

### Most important functions
| Function | Role |
|---|---|
| `image_inspector.main` | Orchestrates validate → metadata? → stego? → print/save; single top-level error catch |
| `image_inspector.parse_arguments` | `argparse` setup + the "need one mode" rule |
| `utils.validate_image` | Four-gate input validation (exists / is file / extension / `verify()`) |
| `metadata.extract_metadata` | EXIF IFD-0 → name-keyed dict; merges GPS; skips `bytes`/`GPSInfo` |
| `gps.extract_gps` | GPS sub-IFD → signed decimal lat/lon + Maps URL |
| `gps.convert_to_degrees` | DMS rationals → decimal degrees (with NaN/type guards) |
| `steganography.extract_lsb_bits` | Pixels → per-channel LSB bit list |
| `steganography.bits_to_bytes` | Bit list → bytes (MSB-first, drop partial) |
| `steganography.bytes_to_text` | Bytes → text via UTF-8 `errors="ignore"` |
| `steganography.detect_pgp_key` | Text → the PGP armor block, or `None` |
| `output.save_output` | Persist dict/str to a file; `append` toggles `w`/`a` |
| `HideMessageinImage.hide_message` | (companion) LSB-embed a message, save PNG — makes test inputs |

### Most important concepts
Digital image forensics · EXIF / IFD / tag IDs / `TAGS` & `GPSTAGS` · GPS DMS → signed decimal degrees / hemisphere sign · steganography vs cryptography · LSB steganography (embed `(x & ~1) | bit`, extract `x & 1`) and its fragility to lossy compression / resizing · bit vs byte, MSB-first packing, bit masking (`& 1`, `& ~1`) · UTF-8 decoding with `errors="ignore"` · PGP ASCII armor (BEGIN/END public-key block) · `argparse` (`store_true`, positional vs optional, `parser.error` → exit 2) · `pathlib.Path` · Pillow lazy loading / `verify()` invalidation / `getexif` / `convert` / `getdata` / `putdata` · NaN and the `x != x` test · decompression bombs and image-parser attack surface · file open modes `w` vs `a` as the append mechanism.
