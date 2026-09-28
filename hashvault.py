from pathlib import Path
import hashlib
import argparse

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    parser = argparse.ArgumentParser(description="Generate and verify SHA-256 file hashes.")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="Generate a file hash")
    gen.add_argument("file")

    verify = sub.add_parser("verify", help="Verify a file against a SHA-256 hash")
    verify.add_argument("file")
    verify.add_argument("hash")

    args = parser.parse_args()
    path = Path(args.file)

    if not path.is_file():
        print(f"File not found: {path}")
        return

    actual = sha256_file(path)

    if args.command == "generate":
        print(f"SHA-256: {actual}")
    else:
        if actual.lower() == args.hash.lower():
            print("✓ Hash verified: file integrity matches.")
        else:
            print("✗ Hash mismatch: file may have changed.")

if __name__ == "__main__":
    main()
