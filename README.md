# 🔐 HashVault

> **Verify file integrity. Detect changes. Protect your data.**

HashVault is a lightweight Python command-line security tool that generates and verifies **SHA-256 cryptographic hashes** for files.

## ✨ Features

- 🔑 Generate SHA-256 hashes for files
- 🛡️ Verify file integrity using an existing hash
- 🚨 Detect file modifications through hash mismatches
- ⚡ Lightweight and fast
- 🧩 Uses only Python's standard library
- 💻 Simple command-line interface
- 🚫 No external dependencies

---

## 🚀 Usage

### Generate a SHA-256 Hash

```bash
python hashvault.py generate example.txt
````

Example:

```text
SHA-256: 7c...
```

Save the generated hash if you want to verify the file later.

### Verify File Integrity

```bash
python hashvault.py verify example.txt YOUR_SHA256_HASH
```

If the file has not changed:

```text
✓ Hash verified: file integrity matches.
```

If the file has been modified:

```text
✗ Hash mismatch: file may have changed.
```

---

## 🔄 How It Works

```text
             File
              │
              ▼
       ┌──────────────┐
       │ SHA-256 Hash │
       └──────┬───────┘
              │
              ▼
       Original Hash
              │
              │
        File modified?
              │
        ┌─────┴─────┐
        │           │
       No          Yes
        │           │
        ▼           ▼
    ✓ Verified   ✗ Mismatch
```

HashVault compares the newly calculated SHA-256 hash with the original hash.

If the values match, the file contents are unchanged. If they differ, the file has changed.

---

## 🧰 Technology Stack

| Technology   | Purpose                       |
| ------------ | ----------------------------- |
| **Python**   | Application development       |
| **hashlib**  | SHA-256 cryptographic hashing |
| **pathlib**  | File and path handling        |
| **argparse** | Command-line interface        |

---

## 📁 Project Structure

```text
HashVault/
├── hashvault.py
├── README.md
└── requirements.txt
```

---

## ⚡ Installation

Clone the repository:

```bash
git clone https://github.com/pashvithareddy-debug/HashVault.git
cd HashVault
```

No third-party packages are required.

Run directly with Python:

```bash
python hashvault.py --help
```

---

## 🔐 Security Note

HashVault uses **SHA-256** to calculate file checksums.

A hash is a fingerprint of the file's contents. Even a small modification to a file will normally produce a different SHA-256 hash.

HashVault is intended for **file integrity verification** and is not a replacement for encryption, digital signatures, or secure file storage.

---

## 🔮 Future Enhancements

* [ ] Compare two files directly
* [ ] Directory-wide integrity scanning
* [ ] Checksum manifest generation
* [ ] Batch hash verification
* [ ] JSON output mode
* [ ] Colored CLI output
* [ ] Verification history
* [ ] Automated integrity monitoring

---

## 📄 License

This project is licensed under the **MIT License**.

See the [`LICENSE`](LICENSE) file for details.

---

<div align="center">

### 🔐 HashVault

**A practical cybersecurity and developer-tool project for file integrity verification.**

Built with Python.

</div>

