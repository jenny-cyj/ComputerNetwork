import sqlite3
import time
import threading
from pathlib import Path
from typing import Optional


class DNSCache:
    """SQLite-backed cache for raw DNS response packets with thread-safe support."""

    def __init__(self, db_path: str = "dns_cache.sqlite3") -> None:
        self.db_path = Path(db_path)
        # 使用 check_same_thread=False 允许跨线程访问，用锁来保护
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.lock = threading.Lock()  # 线程锁保护数据库操作
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dns_cache (
                qname TEXT NOT NULL,
                qtype TEXT NOT NULL,
                response BLOB NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (qname, qtype)
            )
            """
        )
        self.conn.commit()

    def get(self, qname: str, qtype: str) -> Optional[bytes]:
        now = int(time.time())
        with self.lock:  # 使用锁保护数据库访问
            row = self.conn.execute(
                "SELECT response, expires_at FROM dns_cache WHERE qname = ? AND qtype = ?",
                (qname.lower().rstrip("."), qtype.upper()),
            ).fetchone()
        if row is None:
            return None

        response, expires_at = row
        if expires_at <= now:
            self.delete(qname, qtype)
            return None
        return bytes(response)

    def set(self, qname: str, qtype: str, response: bytes, ttl: int) -> None:
        now = int(time.time())
        safe_ttl = max(1, int(ttl))
        with self.lock:  # 使用锁保护数据库访问
            self.conn.execute(
                """
                INSERT INTO dns_cache(qname, qtype, response, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(qname, qtype)
                DO UPDATE SET response = excluded.response,
                              expires_at = excluded.expires_at,
                              created_at = excluded.created_at
                """,
                (
                    qname.lower().rstrip("."),
                    qtype.upper(),
                    sqlite3.Binary(response),
                    now + safe_ttl,
                    now,
                ),
            )
            self.conn.commit()

    def delete(self, qname: str, qtype: str) -> None:
        with self.lock:  # 使用锁保护数据库访问
            self.conn.execute(
                "DELETE FROM dns_cache WHERE qname = ? AND qtype = ?",
                (qname.lower().rstrip("."), qtype.upper()),
            )
            self.conn.commit()

    def close(self) -> None:
        with self.lock:
            self.conn.close()
