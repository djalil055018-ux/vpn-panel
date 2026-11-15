"""Prepare and verify a shadow database while retaining the installed database."""
from pathlib import Path
import hashlib
import json
import re
import subprocess

DB = ["docker", "exec", "-i", "vpn-platform-postgres", "sh", "-ec"]
PSQL = 'exec psql -X -qAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$1"'
# The stock PostgreSQL image uses /bin/sh, so positional arguments are shifted explicitly.
PG_DUMP = 'db=$1; shift; exec pg_dump -U "$POSTGRES_USER" -d "$db" "$@"'
IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,60}\Z")


def name(value):
    if not IDENTIFIER.fullmatch(value):
        raise RuntimeError("Unexpected PostgreSQL identifier")
    return '"' + value + '"'


def call_db(command, *args, data=None, stdin=None, stdout=subprocess.PIPE, timeout=120):
    return subprocess.run(DB + [command, "pauk", *args], input=data, stdin=stdin,
                          stdout=stdout, stderr=subprocess.PIPE, check=True, timeout=timeout).stdout


def psql(database, query=None, **options):
    return call_db(PSQL, database, data=query.encode() if isinstance(query, str) else query, **options)


def stock_database():
    return call_db('printf %s "$POSTGRES_DB"').decode()


def table_columns(database):
    result = psql(database, """
        SELECT json_agg(r) FROM (
          SELECT c.table_name,c.column_name,c.udt_schema,c.udt_name
          FROM information_schema.columns c
          JOIN information_schema.tables t USING (table_schema,table_name)
          WHERE c.table_schema='public' AND t.table_type='BASE TABLE'
          ORDER BY c.table_name,c.ordinal_position
        ) r;
    """)
    rows = json.loads(result)
    if not rows:
        raise RuntimeError("The application database has no schema")
    tables = {}
    for row in rows:
        tables.setdefault(row["table_name"], {})[row["column_name"]] = (row["udt_schema"], row["udt_name"])
    return tables


def check_stock(database):
    user_schemas = psql(database, """
        SELECT nspname FROM pg_namespace
        WHERE nspname NOT LIKE 'pg_%' AND nspname NOT IN ('information_schema','public');
    """).strip()
    if user_schemas:
        raise RuntimeError("The installed database has additional schemas. Upgrade left it unchanged")
    if psql(database, "SELECT extname FROM pg_extension WHERE extname NOT IN ('plpgsql','pgcrypto');").strip():
        raise RuntimeError("The installed database has additional extensions. Upgrade left it unchanged")
    if psql(database, "SELECT count(*) FROM pg_largeobject_metadata;").strip() != b"0":
        raise RuntimeError("The installed database has large objects. Upgrade left it unchanged")


def fingerprint(database, tables):
    result = {}
    for table, fields in tables.items():
        selected = ",".join(name(field) for field in fields)
        # Use a row projected onto the old columns: additional target fields must not affect ordering.
        query = (f'COPY (SELECT {selected} FROM (SELECT {selected} FROM public.{name(table)}) AS t '
                 'ORDER BY to_jsonb(t)::text COLLATE "C") TO STDOUT;')
        process = subprocess.Popen(DB + [PSQL, "pauk", database], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            process.stdin.write(query.encode())
            process.stdin.close()
            checksum = hashlib.sha256()
            lines = 0
            while chunk := process.stdout.read(262144):
                checksum.update(chunk)
                lines += chunk.count(b"\n")
            if process.wait(timeout=15):
                raise RuntimeError(f"Could not verify table {table}")
            result[table] = [lines, checksum.hexdigest()]
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    return result


def prepare(source, target, directory, backup, seed, ready_schema):
    check_stock(source)
    before = table_columns(source)
    psql("postgres", "CREATE DATABASE " + name(target) + " TEMPLATE template0;")
    psql(target, ready_schema.joinpath("pre-data.sql").read_bytes())
    after = table_columns(target)
    for table, fields in before.items():
        for field, data_type in fields.items():
            if after.get(table, {}).get(field) != data_type:
                raise RuntimeError(f"Upgrade cannot represent {table}.{field} in the new database")
    with (backup / "database.dump").open("xb") as output:
        call_db(PG_DUMP, source, "-Fc", stdout=output, timeout=900)
    with (backup / "database.dump").open("rb") as source_dump:
        call_db("exec pg_restore --list", stdin=source_dump)
    data = directory / "data-copy.sql"
    with data.open("xb") as output:
        call_db(PG_DUMP, source, "--data-only", "--no-owner", "--no-privileges", stdout=output, timeout=900)
    try:
        with data.open("rb") as content:
            psql(target, stdin=content, timeout=900)
        psql(target, ready_schema.joinpath("post-data.sql").read_bytes(), timeout=900)
        first = fingerprint(source, before)
        second = fingerprint(target, before)
        if first != second:
            changed = [table for table in first if first[table] != second[table]]
            raise RuntimeError(f"Data verification failed for {', '.join(changed)}")
        (backup / "verified-data.json").write_text(json.dumps(first, indent=2))
        if seed:
            psql(target, seed)
        return len(first), sum(entry[0] for entry in first.values())
    finally:
        data.unlink(missing_ok=True)


def switch(source, target, retained):
    # Both names change together. In-flight connections cause PostgreSQL to
    # reject the rename rather than silently discard a writer.
    psql("postgres", f"BEGIN; SET LOCAL lock_timeout='8s'; "
         f"ALTER DATABASE {name(source)} RENAME TO {name(retained)}; "
         f"ALTER DATABASE {name(target)} RENAME TO {name(source)}; COMMIT;")
