#!/bin/sh
# Run as root inside AxonOS. Uses a dedicated PostgreSQL cluster and databases.
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin:/opt/sbin:/opt/bin
export PATH
PGDATA=${PGDATA:?Set PGDATA to a new directory on a sufficiently large writable filesystem}
PGSOCKET=${PGSOCKET:-/tmp/axonos-pg-stress-socket}
PGPORT=${PGPORT:-55432}
ROWS=${ROWS:-500000}
DATABASES=5
TABLES=100
LOG=${LOG:-/var/log/axonos-postgres-stress.log}

fail() { echo "ERROR: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail "run as root"
case "$ROWS" in ''|*[!0-9]*) fail "ROWS must be a positive integer";; esac
[ "$ROWS" -ge 1 ] && [ "$ROWS" -le 500000 ] || fail "ROWS must be 1..500000"
case "$PGPORT" in ''|*[!0-9]*) fail "PGPORT must be numeric";; esac
[ "$PGPORT" -ge 1024 ] && [ "$PGPORT" -le 65535 ] || fail "invalid PGPORT"
for path in "$PGDATA" "$PGSOCKET" "$LOG"; do
    case "$path" in
        /*) ;;
        *) fail "paths must be absolute: $path";;
    esac
    case "$path" in
        *[!a-zA-Z0-9_./-]*) fail "unsupported character in path: $path";;
    esac
done
[ "$PGDATA" != / ] && [ "$PGSOCKET" != / ] || fail "unsafe path"

postgres_ready() {
    command -v pg_config >/dev/null 2>&1 || return 1
    dir=$(pg_config --bindir) || return 1
    for binary in initdb pg_ctl psql createdb; do
        [ -x "$dir/$binary" ] || return 1
    done
}
if ! postgres_ready; then
    [ "${PG_INSTALL:-0}" = 1 ] || fail "PostgreSQL missing. Install postgresql and postgresql-client, or rerun with PG_INSTALL=1"
    command -v apt-get >/dev/null 2>&1 || fail "apt-get is unavailable"
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql postgresql-client
fi
postgres_ready || fail "PostgreSQL binaries are still unavailable after installation"
PGBIN=$(pg_config --bindir)
for binary in initdb pg_ctl psql createdb; do
    [ -x "$PGBIN/$binary" ] || fail "missing $PGBIN/$binary"
done
id postgres >/dev/null 2>&1 || fail "postgres account is missing"

echo "Workload: $DATABASES databases x $TABLES tables x $ROWS rows = $((DATABASES * TABLES * ROWS)) rows."
echo "Indexes: primary key on id and a secondary index on value, for each table."
echo "Data directory: $PGDATA. Use a persistent filesystem with substantial free space."
echo "Full workload needs many gigabytes; 4 GiB of RAM-backed storage is insufficient."

if [ -e "$PGDATA" ]; then
    [ -f "$PGDATA/.axonos-pg-stress" ] && [ -f "$PGDATA/PG_VERSION" ] ||
        fail "existing PGDATA is not a cluster created by this script; refusing to modify it"
else
    mkdir -p "$(dirname "$PGDATA")"
    mkdir "$PGDATA"
    chown postgres "$PGDATA"
    chmod 700 "$PGDATA"
    su -s /bin/sh postgres -c "'$PGBIN/initdb' -D '$PGDATA' --locale=C --encoding=UTF8 --auth-local=trust --auth-host=reject"
    touch "$PGDATA/.axonos-pg-stress"
    chown postgres "$PGDATA/.axonos-pg-stress"
fi
mkdir -p "$PGSOCKET"
chown postgres "$PGSOCKET"
chmod 700 "$PGSOCKET"
mkdir -p "$(dirname "$LOG")"
touch "$LOG"
chown postgres "$LOG"
chmod 600 "$LOG"

if ! su -s /bin/sh postgres -c "'$PGBIN/pg_ctl' -D '$PGDATA' status" >/dev/null 2>&1; then
    su -s /bin/sh postgres -c "'$PGBIN/pg_ctl' -D '$PGDATA' -l '$LOG' -o \"-k '$PGSOCKET' -p $PGPORT -c listen_addresses='' -c shared_buffers=16MB -c max_connections=20 -c dynamic_shared_memory_type=mmap -c huge_pages=off\" -w start" ||
        fail "PostgreSQL failed to start; see $LOG"
fi

run_psql() {
    su -s /bin/sh postgres -c "'$PGBIN/psql' -X -v ON_ERROR_STOP=1 -h '$PGSOCKET' -p '$PGPORT' -U postgres -d '$1'"
}
echo "Checking target databases; existing databases will not be overwritten."
existing=$(printf "%s\n" "SELECT datname FROM pg_database WHERE datname ~ '^axon_stress_[1-5]$' ORDER BY datname;" | run_psql postgres)
case "$existing" in *axon_stress_*) fail "target databases already exist; refusing to overwrite: $existing";; esac

db=1
while [ "$db" -le "$DATABASES" ]; do
    name=axon_stress_$db
    echo "Creating database $name"
    su -s /bin/sh postgres -c "'$PGBIN/createdb' -h '$PGSOCKET' -p '$PGPORT' -U postgres '$name'"
    {
        printf '%s\n' '\timing on' '\set ON_ERROR_STOP on'
        table=1
        while [ "$table" -le "$TABLES" ]; do
            name_table=bench_$table
            printf '\\echo Loading %s.%s\n' "$name" "$name_table"
            echo "CREATE TABLE $name_table (id bigint NOT NULL PRIMARY KEY, value bigint NOT NULL);"
            echo "INSERT INTO $name_table SELECT n, (n * 7919) % 1000003 FROM generate_series(1, $ROWS) AS n;"
            echo "CREATE INDEX ${name_table}_value_idx ON $name_table (value);"
            echo "ANALYZE $name_table;"
            echo "EXPLAIN (ANALYZE, BUFFERS) SELECT * FROM $name_table WHERE id = $ROWS;"
            echo "EXPLAIN (ANALYZE, BUFFERS) SELECT count(*) FROM $name_table WHERE value BETWEEN 1000 AND 2000;"
            table=$((table + 1))
        done
    } | run_psql "$name"
    db=$((db + 1))
done
echo "Completed: $DATABASES databases, $TABLES tables each, $ROWS rows per table."
echo "PostgreSQL remains running. Server log: $LOG"
echo "Stop it with: su -s /bin/sh postgres -c '$PGBIN/pg_ctl -D $PGDATA -m fast -w stop'"
