"""Compare stopped synthetic SQLite databases without exposing rows."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys

def database_digest(path):
    """Compare logical database content without exposing rows or changing the DB.

    Use stopped databases or consistent SQLite snapshots. Physical pages, WAL
    layout and freelists may differ after Litestream restores equivalent data.
    Schema, all persisted table rows, user_version and application_id are covered.
    """
    digest = hashlib.sha256()
    with sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True) as conn:
        conn.execute('PRAGMA query_only=ON')
        conn.execute('BEGIN')
        if conn.execute('PRAGMA integrity_check').fetchone() != ('ok',):
            raise RuntimeError('database integrity check failed')
        for pragma in ('user_version', 'application_id'):
            digest.update(json.dumps([pragma, conn.execute('PRAGMA ' + pragma).fetchone()[0]]).encode())
        schema = conn.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name').fetchall()
        digest.update(json.dumps(schema, ensure_ascii=True).encode())
        for kind, name, _, _ in schema:
            if kind != 'table':
                continue
            quoted = '"' + name.replace('"', '""') + '"'
            rows = []
            try:
                records = conn.execute('SELECT rowid,* FROM ' + quoted)
            except sqlite3.OperationalError:
                records = conn.execute('SELECT * FROM ' + quoted)  # WITHOUT ROWID tables
            for row in records:
                typed = [('blob', value.hex()) if isinstance(value, bytes)
                         else (type(value).__name__, value) for value in row]
                rows.append(json.dumps(typed, ensure_ascii=True, separators=(',', ':')))
            digest.update(json.dumps(name).encode())
            for row in sorted(rows):
                digest.update(row.encode())
                digest.update(b'\n')
    return digest.digest()


def verify_equivalent(source, restored):
    if database_digest(source) != database_digest(restored):
        raise RuntimeError('recovered database differs from the stopped source; migration refused')



if __name__ == "__main__":
    verify_equivalent(sys.argv[1], sys.argv[2])
    if len(sys.argv) == 5:
        # The frozen server refuses to create auxiliary.db; checkpointed SQLite
        # backup includes any source WAL without publishing source record values.
        descriptor = os.open(sys.argv[4], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        with sqlite3.connect(Path(sys.argv[3]).resolve().as_uri() + '?mode=ro', uri=True) as source:
            with sqlite3.connect(sys.argv[4]) as target:
                source.backup(target)
                assert target.execute('PRAGMA integrity_check').fetchone() == ('ok',)
        os.chmod(sys.argv[4], 0o600)
        verify_equivalent(sys.argv[3], sys.argv[4])
    print("PASS: logical schema and all table contents match")
