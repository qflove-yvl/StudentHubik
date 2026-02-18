#!/usr/bin/env bash
set -euo pipefail

DB_PATH="${1:-instance/site.db}"
BACKUP_DIR="${2:-backups}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"

mkdir -p "$BACKUP_DIR"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT_FILE="$BACKUP_DIR/site_${STAMP}.db"

if [[ ! -f "$DB_PATH" ]]; then
  echo "DB file not found: $DB_PATH" >&2
  exit 1
fi

cp "$DB_PATH" "$OUT_FILE"
find "$BACKUP_DIR" -type f -name 'site_*.db' -mtime +"$RETENTION_DAYS" -delete

echo "Backup created: $OUT_FILE"
