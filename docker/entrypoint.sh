#!/bin/sh
# Container entrypoint. tini is PID 1 and runs this script, which always ends in exec:
#   tini -> litestream replicate -> entrypoint.sh serve -> pocketcontext serve
# or, with LITESTREAM_DISABLED=true:
#   tini -> pocketcontext serve
# SIGTERM from `docker stop` reaches Litestream, which forwards it to the server, waits for it
# to exit, and then makes a final sync. This script never prints variable values.
set -eu

APP_DIR=/app
DATA_DIR=/storage/pb_data
DB_PATH="$DATA_DIR/data.db"
LITESTREAM_CONFIG_FILE=/etc/litestream.yml
SERVER=/usr/local/bin/pocketcontext
SELF=/usr/local/bin/entrypoint.sh

log() {
	printf 'entrypoint: %s\n' "$*"
}

die() {
	printf 'entrypoint: error: %s\n' "$*" >&2
	exit 1
}

# The flags shared by `serve` and `superuser upsert`.
app_flags() {
	printf '%s\n' \
		"--dir=$DATA_DIR" \
		"--migrationsDir=$APP_DIR/pb_migrations" \
		"--hooksDir=$APP_DIR/pb_hooks" \
		"--contextConfig=$APP_DIR/pocketcontext.json"
}

serve() {
	# The server needs neither the replica credentials nor the superuser password.
	# Litestream copies its credentials into AWS_* for its own use; drop those as well.
	unset LITESTREAM_ACCESS_KEY_ID LITESTREAM_SECRET_ACCESS_KEY \
		AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY VAULTCONTEXT_SUPERUSER_PASSWORD
	# shellcheck disable=SC2046 # app_flags prints one flag per line and no value contains whitespace
	set -- serve --http=0.0.0.0:80 $(app_flags)
	if [ -z "${BASE_URL:-}" ]; then
		log "warning: BASE_URL is not set; email links point to localhost and browser origins are unrestricted. Set BASE_URL to the public application origin."
	fi
	# Only the configured application origin is allowed.
	origins=${BASE_URL:-}
	origins=${origins%/}
	if [ -n "$origins" ]; then
		set -- "$@" "--origins=$origins"
	fi
	log "starting server on port 80"
	exec "$SERVER" "$@"
}

# Validate before restore, provisioning, or the Litestream child starts the server.
if [ -n "${VAULTCONTEXT_GOOGLE_CLIENT_ID:-}" ] && [ -z "${VAULTCONTEXT_GOOGLE_CLIENT_SECRET:-}" ]; then
	die "VAULTCONTEXT_GOOGLE_CLIENT_ID requires VAULTCONTEXT_GOOGLE_CLIENT_SECRET"
elif [ -n "${VAULTCONTEXT_GOOGLE_CLIENT_SECRET:-}" ] && [ -z "${VAULTCONTEXT_GOOGLE_CLIENT_ID:-}" ]; then
	die "VAULTCONTEXT_GOOGLE_CLIENT_SECRET requires VAULTCONTEXT_GOOGLE_CLIENT_ID"
fi

if [ "${1:-}" = serve ]; then
	serve
fi

cd "$APP_DIR"
mkdir -p "$DATA_DIR"

replicate=true
if [ "${LITESTREAM_DISABLED:-}" = true ]; then
	replicate=false
	log "LITESTREAM_DISABLED=true: running without replication"
else
	missing=
	for name in LITESTREAM_BUCKET LITESTREAM_PATH LITESTREAM_ACCESS_KEY_ID LITESTREAM_SECRET_ACCESS_KEY; do
		eval "value=\${$name:-}"
		if [ -z "$value" ]; then
			missing="$missing $name"
		fi
	done
	value=
	if [ -n "$missing" ]; then
		die "missing environment variable(s):$missing. Set them, or set LITESTREAM_DISABLED to exactly 'true' to run without replication."
	fi
	: "${LITESTREAM_REGION:=}" "${LITESTREAM_ENDPOINT:=}" "${LITESTREAM_SYNC_INTERVAL:=10s}"
	export LITESTREAM_REGION LITESTREAM_ENDPOINT LITESTREAM_SYNC_INTERVAL
fi

if [ "$replicate" = true ]; then
	python3 /usr/local/bin/vaultcontext-backup.py restore || die "complete ciphertext restore failed"
	if [ -f "$DB_PATH" ]; then
		log "database exists in the volume: no restore"
	else
		log "no database in the volume: restoring from the replica when one exists"
	fi
	# Exit status 0: restored, or the database already exists, or the replica holds no backup.
	# Anything else (unreachable bucket, rejected credentials, damaged backup) stops the container,
	# so the server never starts on an empty database while a replica may exist.
	if ! litestream restore -config "$LITESTREAM_CONFIG_FILE" \
		-if-db-not-exists -if-replica-exists -integrity-check quick "$DB_PATH"; then
		die "litestream restore failed. Not starting, because starting on an empty database would replace the replica's history. Check the LITESTREAM_* variables and the bucket."
	fi
	if [ -f "$DB_PATH" ]; then
		log "database present after the restore step"
	else
		log "the replica holds no backup: the server creates a new database"
	fi
fi

python3 /usr/local/bin/vaultcontext-backup.py verify || die "ciphertext verification failed"

if [ -n "${VAULTCONTEXT_SUPERUSER_EMAIL:-}" ] && [ -n "${VAULTCONTEXT_SUPERUSER_PASSWORD:-}" ]; then
	log "upserting the superuser from VAULTCONTEXT_SUPERUSER_EMAIL"
	# shellcheck disable=SC2046 # see serve
	if ! "$SERVER" superuser upsert $(app_flags) -- "$VAULTCONTEXT_SUPERUSER_EMAIL" "$VAULTCONTEXT_SUPERUSER_PASSWORD"; then
		die "superuser upsert failed"
	fi
elif [ -n "${VAULTCONTEXT_SUPERUSER_EMAIL:-}" ]; then
	die "VAULTCONTEXT_SUPERUSER_EMAIL is set but VAULTCONTEXT_SUPERUSER_PASSWORD is missing"
elif [ -n "${VAULTCONTEXT_SUPERUSER_PASSWORD:-}" ]; then
	die "VAULTCONTEXT_SUPERUSER_PASSWORD is set but VAULTCONTEXT_SUPERUSER_EMAIL is missing"
fi

if [ "$replicate" = true ]; then
	log "starting Litestream, which starts and supervises the server"
	exec python3 /usr/local/bin/vaultcontext-backup.py supervise litestream replicate -config "$LITESTREAM_CONFIG_FILE" -exec "$SELF serve"
fi
serve
