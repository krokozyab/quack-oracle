# Security Policy

Do not report vulnerabilities, credentials, wallet files, packet captures, or
production connection descriptors in public issues. Contact the maintainers
privately with a minimal reproduction and affected version.

Oracle database passwords and wallet passwords must be stored in DuckDB
secrets, never in SQL fixtures, logs, connection strings, or diagnostic bundles.
Persistent DuckDB secrets may be stored unencrypted; prefer temporary secrets
or an external secret provider for production credentials.
