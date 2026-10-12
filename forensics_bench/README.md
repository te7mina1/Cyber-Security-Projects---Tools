# Forensics Bench

Forensics Bench is a desktop file examination and handling workbench built with Python and Tkinter. It brings five tools into one interface: metadata inspection, controlled file damage and encryption, metadata removal and restoration, repeated file overwriting, and file-in-file steganography.

> **Use on copies of evidence.** NbCorrupt can overwrite files in place, MetaDelete can edit metadata in place, Shr3dder overwrites and can unlink files, and HideMe can replace its carrier. These operations can permanently change or destroy data. Keep an untouched evidence copy and record hashes before working.

## Features

| Tool | What it does |
| --- | --- |
| **NbExif** | Reads metadata with ExifTool, including duplicate and unknown tags, and provides profiles for all metadata, deep extraction, EXIF, GPS, IPTC, XMP, file-system information, and a quick scan. Filter results and export JSON, XML, CSV, or a selected binary metadata block. It also displays file hashes, entropy, signatures, and other technical details. |
| **NbCorrupt** | Creates a damaged output copy by default. Operations include random byte changes, header wiping, signature destruction, truncation, zero fill, pattern overwrite, and AES encryption/decryption. It also offers symlink operations. The activity log records hashes and operation results. In-place mode is destructive and requires typed confirmation. |
| **MetaDelete** | Removes all writable metadata or selected metadata groups through ExifTool. It can optionally erase bytes appended after recognized container endings and reset access/modification times. It writes a JSON metadata sidecar alongside the output, supports folder batches, restores from a sidecar, and writes manually specified tags to a copy. In-place mode edits the target. |
| **Shr3dder** | Overwrites queued files using zero, ones, random, DoE/NIST-style three-pass, Gutmann 35-pass, alternating-byte, or custom patterns. It can truncate and unlink files, verify the result, follow symlinks when explicitly enabled, and cancel a running job. |
| **HideMe** | Embeds arbitrary payloads by appending a structured stream to any carrier, or by encoding data in image pixels with LSB mode (PNG, BMP, or TGA; Pillow support is required). It can encrypt payloads with a passphrase, add a comment, scan for HideMe entries, and extract payloads. Pixel mode supports 1, 2, or 4 bits per byte. |

## Requirements

- Python 3.9 or newer
- Tkinter (often provided by the operating system's Python Tk package)
- ExifTool for NbExif and MetaDelete
- `cryptography` for AES features in NbCorrupt and HideMe
- Pillow for HideMe pixel/LSB mode

ExifTool, `cryptography`, and Pillow are optional for launching the application, but the corresponding features need them. Missing dependencies are reported by the app or when a feature is used.

On Debian or Ubuntu, install the system packages and Python dependencies with:

```bash
sudo apt install python3-tk libimage-exiftool-perl
python3 -m pip install cryptography pillow
```

If Tkinter is already installed, it does not need to be installed again. Package names and Python packaging policies vary by distribution; a virtual environment can be used for the Python packages.

## Run

From the project directory:

```bash
python3 workBench.py
```

Select an evidence file from the top-level file chooser; the selection is shared with the relevant tool pages. Each page also lets you select its own target where appropriate. Long-running operations run in the background and report progress or results in the interface.

## Typical workflows

### Inspect and export metadata

1. Select an evidence file and open **NbExif**.
2. Choose an extraction profile and select **Extract ALL metadata**.
3. Filter by tag text or metadata group if needed.
4. Export JSON, XML, CSV, or a selected binary block.

### Remove metadata while retaining a recovery record

1. Open **MetaDelete** and select a target.
2. Choose all metadata or a specific group. Optionally select appended-data removal or timestamp reset.
3. Leave in-place mode off to create a cleaned copy.
4. The original metadata is saved as a `.metadata.json` sidecar near the output. Keep the sidecar if you may need to restore the tags.

### Simulate file damage

1. Open **NbCorrupt**, choose and inspect a target, then select an operation and its parameters.
2. Keep in-place mode off to write a separate output file.
3. For encryption/decryption, enter the passphrase and retain it securely; encrypted output cannot be recovered without it.

### Embed and recover a payload

1. Open **HideMe**, choose a carrier and payload, then select append or pixel LSB mode.
2. Optionally set a passphrase and comment. Leave overwrite-in-place off to create a new carrier.
3. Use **Check container** to inspect entries, then **Extract payload** and select an output folder.

Append mode preserves the original carrier bytes and works with any file type, but the extra data increases the file size. Pixel LSB mode keeps the image dimensions and format but changes pixel values; capacity depends on image dimensions, channels, and selected bit depth. Use a passphrase if the payload needs confidentiality and integrity protection.

### Overwrite queued files

1. Open **Shr3dder**, add files or a folder, and choose an overwrite plan.
2. Review truncate, unlink, verification, and symlink-following options.
3. Confirm by typing `QUEUE` when prompted.

Overwrite behavior depends on the storage device and filesystem. SSDs, copy-on-write filesystems, snapshots, and cloud-synced storage may retain old blocks; the tool cannot guarantee physical erasure in those environments.

## Case logs and outputs

The tools show operation results in their activity panels. The application also has a session/case-log save action in the top-level controls. Exported metadata, sidecars, corrupted copies, and embedded carriers are written to the selected output locations; retain them with the case records as appropriate.

## Tests

The repository includes `test_engines.py` and `test_gui_smoke.py`. They currently import a module named `app`, but the application file in this directory is `workBench.py`. As checked in, the test scripts therefore need that module-name mismatch resolved before they can be run successfully. The GUI smoke test also requires a graphical display (it is intended to run under Xvfb in headless environments), Pillow, ExifTool, and the application dependencies.

## Implementation notes

The application is a single-file Python program. Its helper functions implement file signatures, hashing, entropy sampling, ExifTool invocation, AES container handling, HideMe container scanning, LSB bit packing, and overwrite plans. The Tkinter class builds the pages and runs longer operations in worker threads so the interface remains responsive.
