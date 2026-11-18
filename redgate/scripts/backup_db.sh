#!/usr/bin/env bash
# Consistent WAL-aware SQLite backup; never copy a live .db file by itself.
# Usage: backup_db.sh [--local DB_PATH] [OUTPUT.sqlite.gz]
set -euo pipefail
umask 077
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL_DB=""
if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then
  printf 'Usage: %s [--local DB_PATH] [OUTPUT.sqlite.gz]\n' "$0"
  exit 0
fi
if [[ "${1:-}" == --local ]]; then
  [[ $# -ge 2 && -n "$2" ]] || { printf 'ERROR: --local needs a database path.\n' >&2; exit 2; }
  LOCAL_DB="$2"
  shift 2
fi
[[ $# -le 1 ]] || { printf 'ERROR: Too many arguments.\n' >&2; exit 2; }
OUTPUT="${1:-$ROOT_DIR/backups/redgate-$(date -u +%Y%m%dT%H%M%SZ).sqlite.gz}"
[[ "$OUTPUT" != -* && ! -e "$OUTPUT" ]] || { printf 'ERROR: Output exists or is invalid; refusing overwrite.\n' >&2; exit 1; }
mkdir -p -- "$(dirname "$OUTPUT")"
TMP_FILE="$(mktemp "${OUTPUT}.partial.XXXXXX")"
trap 'rm -f -- "$TMP_FILE"' EXIT

# A temporary copy is made next to the DB (the writable data volume in Docker),
# checked, streamed as gzip and removed. No application import/migration occurs.
BACKUP_CODE='import gzip, pathlib, shutil, sqlite3, sys, tempfile
from urllib.parse import quote
source = pathlib.Path(sys.argv[1]).resolve(strict=True)
uri = "file:" + quote(str(source), safe="/") + "?mode=ro"
with tempfile.TemporaryDirectory(prefix=".redgate-backup-", dir=source.parent) as tmp:
    copy = pathlib.Path(tmp) / "snapshot.sqlite"
    with sqlite3.connect(uri, uri=True) as src, sqlite3.connect(copy) as dst:
        src.backup(dst, pages=128, sleep=0.01)
        if dst.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise RuntimeError("SQLite backup failed integrity verification")
    with copy.open("rb") as data, gzip.GzipFile(fileobj=sys.stdout.buffer, mode="wb", mtime=0) as output:
        shutil.copyfileobj(data, output, length=1024 * 1024)
'
if [[ -n "$LOCAL_DB" ]]; then
  "${REDGATE_PYTHON:-python3}" -c "$BACKUP_CODE" "$LOCAL_DB" > "$TMP_FILE"
else
  command -v docker >/dev/null 2>&1 || { printf 'ERROR: Docker is required (or use --local).\n' >&2; exit 1; }
  docker compose --project-directory "$ROOT_DIR" -f "$ROOT_DIR/docker-compose.yml" \
    exec -T gateway python -c "$BACKUP_CODE" /app/data/redgate.db > "$TMP_FILE"
fi
# Atomic, no-clobber publish; unlike mv -n this fails if another backup won a race.
ln -- "$TMP_FILE" "$OUTPUT"
rm -f -- "$TMP_FILE"
trap - EXIT
printf '[OK] Consistent backup saved (0600): %s\n' "$OUTPUT"
sha256sum -- "$OUTPUT"
