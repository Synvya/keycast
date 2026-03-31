#!/bin/bash
# Daily PostgreSQL backup to S3.
# Run via cron: 0 3 * * * /opt/synvya/keycast/scripts/backup-postgres.sh
set -euo pipefail

BACKUP_DIR=/opt/synvya/backups
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/keycast_$TIMESTAMP.sql.gz"

mkdir -p "$BACKUP_DIR"

echo "Starting PostgreSQL backup..."
docker exec keycast-postgres pg_dump -U postgres keycast | gzip > "$BACKUP_FILE"
echo "Backup created: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"

# Upload to S3
aws s3 cp "$BACKUP_FILE" s3://synvya-backups/keycast/
echo "Backup uploaded to s3://synvya-backups/keycast/"

# Retain 7 days locally
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +7 -delete
echo "Old local backups cleaned up (retention: 7 days)"
