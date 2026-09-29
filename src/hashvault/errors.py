"""Exception hierarchy. Each error carries the CLI exit code it maps to."""

EXIT_OK = 0
EXIT_MISMATCH = 1
EXIT_USAGE = 2
EXIT_FILE = 3
EXIT_MANIFEST = 4


class HashVaultError(Exception):
    exit_code = 1


class UsageError(HashVaultError):
    """Invalid arguments, algorithm, hash string or configuration."""

    exit_code = EXIT_USAGE


class FileError(HashVaultError):
    """A file or directory is missing, unreadable, or of the wrong type."""

    exit_code = EXIT_FILE


class ManifestError(HashVaultError):
    """A manifest is missing, corrupt, unsafe, or cannot be written."""

    exit_code = EXIT_MANIFEST
