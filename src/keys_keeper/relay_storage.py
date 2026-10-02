"""Transactional logical-byte accounting for the relay's existing SQLite tables.

Triggers update one scope and one protocol total in the same transaction as a
record. Existing databases are counted once, under the writer lock, before the
triggers are installed. Limits never delete signed history. Physical pages,
indexes and WAL still require filesystem headroom.
"""
from __future__ import annotations


class RelayStorage:
    def __init__(self, connection, namespace: str, tables):
        # Names and columns come only from the two server schema constants.
        self.namespace = namespace
        connection.execute("""CREATE TABLE IF NOT EXISTS relay_usage (
            namespace TEXT NOT NULL, scope_id TEXT NOT NULL,
            bytes INTEGER NOT NULL CHECK(bytes >= 0),
            records INTEGER NOT NULL CHECK(records >= 0),
            PRIMARY KEY(namespace, scope_id)
        )""")
        initialized = connection.execute(
            "SELECT 1 FROM relay_usage WHERE namespace=? AND scope_id=''", (namespace,)
        ).fetchone()
        if initialized is None:
            connection.execute("INSERT INTO relay_usage VALUES(?, '', 0, 0)", (namespace,))
            for table, (scope_column, columns) in tables.items():
                size = self._size(columns)
                connection.execute(
                    f"INSERT INTO relay_usage SELECT ?, {scope_column}, SUM({size}), COUNT(*)"
                    f" FROM {table} GROUP BY {scope_column}"
                    " ON CONFLICT(namespace,scope_id) DO UPDATE SET"
                    " bytes=bytes+excluded.bytes, records=records+excluded.records",
                    (namespace,),
                )
            connection.execute("""UPDATE relay_usage SET
                bytes=(SELECT COALESCE(SUM(bytes),0) FROM relay_usage WHERE namespace=? AND scope_id!=''),
                records=(SELECT COALESCE(SUM(records),0) FROM relay_usage WHERE namespace=? AND scope_id!='')
                WHERE namespace=? AND scope_id=''""", (namespace, namespace, namespace))
        for table, (scope_column, columns) in tables.items():
            self._triggers(connection, table, scope_column, columns)

    @staticmethod
    def _size(columns, prefix=""):
        return "256 + " + " + ".join(
            f"COALESCE(length(CAST({prefix}{name} AS BLOB)),0)" for name in columns
        )

    def _triggers(self, connection, table, scope_column, columns):
        new_size, old_size = self._size(columns, "NEW."), self._size(columns, "OLD.")
        add = f"""
            INSERT INTO relay_usage VALUES('{self.namespace}', NEW.{scope_column}, {new_size}, 1)
            ON CONFLICT(namespace,scope_id) DO UPDATE SET
                bytes=bytes+excluded.bytes, records=records+1;
            UPDATE relay_usage SET bytes=bytes+({new_size}), records=records+1
                WHERE namespace='{self.namespace}' AND scope_id='';
        """
        remove = f"""
            UPDATE relay_usage SET bytes=bytes-({old_size}), records=records-1
                WHERE namespace='{self.namespace}' AND scope_id IN ('', OLD.{scope_column});
        """
        for action, body in (("INSERT", add), ("DELETE", remove), ("UPDATE", remove + add)):
            connection.execute(
                f"CREATE TRIGGER IF NOT EXISTS relay_usage_{table}_{action.lower()}"
                f" AFTER {action} ON {table} BEGIN {body} END"
            )

    def usage(self, connection, scope_id=None):
        row = connection.execute(
            "SELECT bytes,records FROM relay_usage WHERE namespace=? AND scope_id=?",
            (self.namespace, "" if scope_id is None else scope_id),
        ).fetchone()
        if row is None and scope_id is None:
            raise RuntimeError("relay storage accounting is missing")
        return (0, 0) if row is None else (row[0], row[1])

    def budget(self, connection, scope_id, limits, *, control=False):
        from keys_keeper.sync_server import SyncServerError
        for scope, byte_limit, record_limit, extra_bytes, extra_records in (
            (scope_id, limits.scope_bytes, limits.scope_records,
             limits.control_scope_bytes, limits.control_scope_records),
            (None, limits.relay_bytes, limits.relay_records,
             limits.control_relay_bytes, limits.control_relay_records),
        ):
            used_bytes, used_records = self.usage(connection, scope)
            if (used_bytes > byte_limit + (extra_bytes if control else 0)
                    or used_records > record_limit + (extra_records if control else 0)):
                raise SyncServerError(429, "storage_full", "storage full")
