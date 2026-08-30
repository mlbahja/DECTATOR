# 🔍 Image Inspector

Image Inspector is a command-line forensic tool written in **Python** that analyzes image files to extract metadata and detect hidden information using basic steganography techniques.

The project is designed to introduce digital image forensics concepts while providing a simple and easy-to-use command-line interface.

---

# Features

## Metadata Extraction

Extracts EXIF metadata from supported image formats, including:

* Camera manufacturer
* Camera model
* Date and time
* Orientation
* GPS coordinates (when available)
* Other available EXIF tags

---

## GPS Extraction

If an image contains valid GPS information, the tool extracts and converts the coordinates into decimal degrees.

If GPS information is missing or invalid, the tool reports that no valid coordinates were found.

---

## Steganography Detection

The project performs a basic **Least Significant Bit (LSB)** analysis.

Current implementation:

* Extracts LSB bits from every RGB channel.
* Converts extracted bits into bytes.
* Decodes bytes into readable text.
* Searches for hidden PGP public key blocks.

Supported pattern:

```text
-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----
```

---

# Project Structure

```text
image-inspector/
│
├── image_inspector.py          # Main CLI application
├── requirements.txt
├── README.md
│
├── modules/
│   ├── utils.py                # Image validation
│   ├── metadata.py             # EXIF metadata extraction
│   ├── gps.py                  # GPS coordinate extraction
│   ├── steganography.py        # LSB analysis and PGP detection
│   └── output.py               # Save analysis results
│
├── tests/                      # Test images
│
└── venv/
```

---

# Requirements

* Python 3.10 or newer
* Pillow

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# Usage

## Extract metadata

```bash
python image_inspector.py -m image.jpg
```

Example output:

```text
Make: samsung
Model: SM-A145P
DateTime: 2026:07:25 10:49:00
Orientation: 6
```

---

## Save metadata to a file

```bash
python image_inspector.py -m -o metadata.txt image.jpg
```

---

## Detect hidden information

```bash
python image_inspector.py -s image.png
```

If a hidden PGP block is found:

```text
===== HIDDEN PGP KEY FOUND =====

-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----
```

Otherwise:

```text
No hidden PGP key found.
```

---

## Save steganography results

```bash
python image_inspector.py -s -o result.txt image.png
```

---

# Command-Line Options

| Option    | Description                           |
| --------- | ------------------------------------- |
| `-m`      | Extract image metadata                |
| `-s`      | Detect hidden data using LSB analysis |
| `-o FILE` | Save results to a file                |
| `image`   | Path to the image                     |

---

# Supported Formats

* JPEG
* JPG
* PNG

---

# Error Handling

The application validates:

* File existence
* Supported image format
* Invalid image files
* Missing metadata
* Missing or invalid GPS information

---

# Example

Extract metadata:

```bash
python image_inspector.py -m photo.jpg
```

Detect hidden information:

```bash
python image_inspector.py -s photo.png
```

Save the output:

```bash
python image_inspector.py -s -o output.txt hidden.png
```

---

# How It Works

## Metadata Analysis

1. Open the image.
2. Read EXIF metadata.
3. Convert EXIF tag IDs into readable names.
4. Extract GPS information if available.
5. Display or save the results.

---

## Steganography Analysis

1. Open the image.
2. Read every RGB pixel.
3. Extract the Least Significant Bit from each color channel.
4. Group bits into bytes.
5. Decode bytes into text.
6. Search for a PGP public key block.
7. Report the detection result.

---

# Limitations

Current implementation:

* Supports only basic LSB analysis.
* Detects only embedded PGP public key blocks.
* Does not recover encrypted payloads.
* Does not detect advanced steganography techniques.
* Supports only images with EXIF metadata.

---

# Future Improvements

Possible future enhancements include:

* Hidden text extraction using end markers.
* Google Maps link generation from GPS coordinates.
* Metadata comparison between images.
* Additional steganography detection methods.
* Entropy analysis.
* PNG chunk inspection.
* Image histogram analysis.
* Batch image analysis.
* JSON output support.

---

# Ethical Use

This tool is intended for:

* Digital forensics learning
* Cybersecurity education
* Capture The Flag (CTF) challenges
* Security research

Always ensure you have permission to analyze images. Do not use this software to inspect private or copyrighted material without authorization.

---

# License

This project is provided for educational purposes.
