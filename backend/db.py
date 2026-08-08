"""SQLite 持久化层：建表、CRUD、端口分配、settings KV。
单连接 + threading.Lock（FastAPI 异步下所有调用走同步封装，由调用方 ensure 线程安全）。
字段名 camelCase ↔ snake_case 在此层映射。
"""
import json
import os
import random
import string
import sqlite3
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
DB_PATH = os.path.join(DATA_DIR, "panel.db")

_conn: Optional[sqlite3.Connection] = None
_lock = threading.Lock()


# ---------- 基础 ----------

def _rand_str(length: int) -> str:
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(length))


def new_node_id() -> str:
    return "node-" + uuid.uuid4().hex[:16]


def new_sub_id() -> str:
    return f"sub-{int(time.time() * 1000)}-{random.randint(0, 999)}"


def _conn_now() -> int:
    return int(time.time() * 1000)


def connect() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        os.makedirs(DATA_DIR, exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA foreign_keys=ON")
    return _conn


def init_db() -> None:
    with _lock:
        c = connect()
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS nodes (
              id            TEXT PRIMARY KEY,
              name          TEXT NOT NULL,
              protocol      TEXT NOT NULL,
              "group"       TEXT DEFAULT '默认分组',
              port          INTEGER NOT NULL UNIQUE,
              segment       INTEGER,
              auth_user     TEXT,
              auth_pass     TEXT,
              status        TEXT DEFAULT 'offline',
              ping          INTEGER DEFAULT 0,
              exit_ip       TEXT DEFAULT 'N/A',
              up_traffic    INTEGER DEFAULT 0,
              down_traffic  INTEGER DEFAULT 0,
              raw_config    TEXT NOT NULL DEFAULT '{}',
              sub_id        TEXT,
              stale         INTEGER DEFAULT 0,
              selected      INTEGER DEFAULT 0,
              entry_proto   TEXT DEFAULT 'mixed',
              ss_pass       TEXT,
              created_at    INTEGER,
              updated_at    INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_nodes_sub ON nodes(sub_id);
            CREATE INDEX IF NOT EXISTS idx_nodes_port ON nodes(port);

            CREATE TABLE IF NOT EXISTS relay_domains (
              id         TEXT PRIMARY KEY,
              domain     TEXT NOT NULL,
              port       INTEGER NOT NULL UNIQUE,
              auth_user  TEXT,
              auth_pass  TEXT,
              groups     TEXT NOT NULL DEFAULT '["ALL"]'
            );

            CREATE TABLE IF NOT EXISTS subscriptions (
              id            TEXT PRIMARY KEY,
              url           TEXT NOT NULL UNIQUE,
              name          TEXT,
              "group"       TEXT DEFAULT '订阅节点',
              enabled       INTEGER DEFAULT 1,
              last_refresh  INTEGER,
              node_count    INTEGER DEFAULT 0,
              last_error    TEXT,
              snapshot      TEXT,
              created_at    INTEGER
            );

            CREATE TABLE IF NOT EXISTS settings (
              key   TEXT PRIMARY KEY,
              value TEXT
            );
            """
        )
        # 老库迁移：补 entry_proto / ss_pass 列（节点对外入口协议 + ss 密码）
        cols = {r[1] for r in c.execute("PRAGMA table_info(nodes)")}
        if "entry_proto" not in cols:
            c.execute("ALTER TABLE nodes ADD COLUMN entry_proto TEXT DEFAULT 'mixed'")
        if "ss_pass" not in cols:
            c.execute("ALTER TABLE nodes ADD COLUMN ss_pass TEXT")
        c.commit()


# ---------- 行映射 ----------

def _row_to_node(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "protocol": row["protocol"],
        "group": row["group"],
        "port": row["port"],
        "segment": row["segment"],
        "authUser": row["auth_user"],
        "authPass": row["auth_pass"],
        "status": row["status"],
        "ping": row["ping"],
        "exitIp": row["exit_ip"],
        "upTraffic": row["up_traffic"],
        "downTraffic": row["down_traffic"],
        "rawConfig": json.loads(row["raw_config"] or "{}"),
        "subId": row["sub_id"],
        "stale": bool(row["stale"]),
        "selected": bool(row["selected"]),
        "entryProto": row["entry_proto"] or "mixed",
        "ssPass": row["ss_pass"],
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    }


def _node_to_params(node: Dict[str, Any]) -> tuple:
    now = _conn_now()
    return (
        node["id"],
        node.get("name", "未命名"),
        node.get("protocol", "shadowsocks"),
        node.get("group", "默认分组"),
        node["port"],
        node.get("segment"),
        node.get("authUser"),
        node.get("authPass"),
        node.get("status", "offline"),
        node.get("ping", 0),
        node.get("exitIp", "N/A"),
        node.get("upTraffic", 0),
        node.get("downTraffic", 0),
        json.dumps(node.get("rawConfig", {}), ensure_ascii=False),
        node.get("subId"),
        1 if node.get("stale") else 0,
        1 if node.get("selected") else 0,
        node.get("entryProto", "mixed"),
        node.get("ssPass"),
        node.get("createdAt", now),
        now,
    )


# ---------- 端口分配 ----------

def get_reserved_ports() -> set:
    s = get_setting("system", {})
    reserved = s.get("reservedPorts", []) if isinstance(s, dict) else []
    return set(int(p) for p in (reserved or []))


def _used_ports(c) -> set:
    used = set()
    for r in c.execute("SELECT port FROM nodes"):
        used.add(r[0])
    for r in c.execute("SELECT port FROM relay_domains"):
        used.add(r[0])
    # 直接读 settings 表（不经过 get_setting，避免在锁内二次加锁）
    row = c.execute("SELECT value FROM settings WHERE key='system'").fetchone()
    if row:
        try:
            s = json.loads(row[0])
            reserved = s.get("reservedPorts", []) if isinstance(s, dict) else []
            used |= set(int(p) for p in (reserved or []))
        except Exception:
            pass
    return used


def _next_available_port_locked(c, preferred_port: Optional[int], segment: Optional[int] = None) -> int:
    """不加锁的端口分配内核（调用方需已持有 _lock）。"""
    used = _used_ports(c)
    if preferred_port and preferred_port not in used:
        return preferred_port
    if segment == 51 or (preferred_port and str(preferred_port).startswith("51")):
        base = 51001
    else:
        base = 52001
    p = base
    while p in used:
        p += 1
    return p


def get_next_available_port(preferred_port: Optional[int], segment: Optional[int] = None) -> int:
    """51 段高质量 / 52 段普通。preferred_port 决定段；冲突自动向上跳过。"""
    with _lock:
        c = connect()
        return _next_available_port_locked(c, preferred_port, segment)


def infer_segment(name: str, protocol: str, port: Optional[int] = None) -> int:
    """质量自动判定：名称含关键词→51 段，否则 52。"""
    if port and str(port).startswith("51"):
        return 51
    if port and str(port).startswith("52"):
        return 52
    kw = ("住宅", "ISP", "原生", "家宽", "residential", "高速")
    return 51 if any(k in (name or "") for k in kw) else 52


def random_auth(port: int) -> tuple:
    """随机认证账号密码（与前端风格一致）。"""
    user = _rand_str(8)
    passwd = _rand_str(12)
    return user, passwd


# ---------- 节点 CRUD ----------

def list_nodes(q: Optional[str] = None, group: Optional[str] = None, sub_id: Optional[str] = None) -> List[Dict]:
    with _lock:
        c = connect()
        sql = "SELECT * FROM nodes"
        where = []
        params: list = []
        if group and group != "ALL":
            where.append('"group" = ?')
            params.append(group)
        if q:
            where.append("(name LIKE ? OR CAST(port AS TEXT) LIKE ?)")
            like = f"%{q}%"
            params += [like, like]
        if sub_id:
            where.append("sub_id = ?")
            params.append(sub_id)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY port ASC"
        return [_row_to_node(r) for r in c.execute(sql, params)]


def get_node(node_id: str) -> Optional[Dict]:
    with _lock:
        c = connect()
        r = c.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
        return _row_to_node(r) if r else None


def create_node(node: Dict[str, Any]) -> Dict:
    with _lock:
        c = connect()
        c.execute(
            """INSERT INTO nodes
               (id,name,protocol,"group",port,segment,auth_user,auth_pass,status,ping,
                exit_ip,up_traffic,down_traffic,raw_config,sub_id,stale,selected,entry_proto,ss_pass,created_at,updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            _node_to_params(node),
        )
        c.commit()
    return get_node(node["id"])


def create_node_batch(nodes: List[Dict[str, Any]]) -> Dict[str, Any]:
    """批量创建 + 去重（按 server:server_port）。返回 {created, skipped, duplicate, items}。"""
    created = 0
    skipped = 0
    duplicate = 0
    items: List[Dict] = []
    with _lock:
        c = connect()
        existing_servers = set()
        for r in c.execute("SELECT raw_config, id FROM nodes"):
            try:
                rc = json.loads(r["raw_config"] or "{}")
                srv = rc.get("server") or rc.get("address")
                sp = rc.get("server_port") or rc.get("port")
                if srv and sp:
                    existing_servers.add((str(srv), int(sp)))
            except Exception:
                pass
        batch_ports = set()
        for nd in nodes:
            rc = nd.get("rawConfig") or {}
            srv = rc.get("server") or rc.get("address")
            sp = rc.get("server_port") or rc.get("port")
            if srv and sp:
                key = (str(srv), int(sp))
                if key in existing_servers:
                    duplicate += 1
                    skipped += 1
                    continue
                existing_servers.add(key)
            # 端口冲突则跳过（不入库，避免 IntegrityError 中断整批）
            port = nd.get("port")
            db_used = {r[0] for r in c.execute("SELECT port FROM nodes")} | {r[0] for r in c.execute("SELECT port FROM relay_domains")}
            if not port:
                # 自动分配：从段基址起找既不在 DB 也不在批内已用端口的空闲端口
                segment = nd.get("segment")
                base = 51001 if (segment == 51 or nd.get("port") and str(nd.get("port")).startswith("51")) else 52001
                port = base
                while port in db_used or port in batch_ports:
                    port += 1
            elif port in db_used or port in batch_ports:
                skipped += 1
                continue
            batch_ports.add(port)
            nd["port"] = port
            try:
                c.execute(
                    """INSERT INTO nodes
                       (id,name,protocol,"group",port,segment,auth_user,auth_pass,status,ping,
                        exit_ip,up_traffic,down_traffic,raw_config,sub_id,stale,selected,entry_proto,ss_pass,created_at,updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    _node_to_params(nd),
                )
            except sqlite3.IntegrityError:
                skipped += 1
                continue
            items.append(_row_to_node(c.execute("SELECT * FROM nodes WHERE id = ?", (nd["id"],)).fetchone()))
            created += 1
        c.commit()
    return {"created": created, "skipped": skipped, "duplicate": duplicate, "items": items}


def update_node(node_id: str, patch: Dict[str, Any]) -> Optional[Dict]:
    with _lock:
        c = connect()
        row = c.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
        if not row:
            return None
        cur = _row_to_node(row)
        # camelCase patch → 合并
        merged = {**cur}
        for k, v in patch.items():
            if v is not None:
                merged[k] = v
        c.execute(
            """UPDATE nodes SET name=?,protocol=?,"group"=?,port=?,segment=?,auth_user=?,
               auth_pass=?,status=?,ping=?,exit_ip=?,up_traffic=?,down_traffic=?,raw_config=?,
               sub_id=?,stale=?,selected=?,entry_proto=?,ss_pass=?,updated_at=?
               WHERE id=?""",
            (
                merged["name"], merged["protocol"], merged["group"], merged["port"],
                merged["segment"], merged.get("authUser"), merged.get("authPass"),
                merged.get("status", "offline"), merged.get("ping", 0),
                merged.get("exitIp", "N/A"), merged.get("upTraffic", 0),
                merged.get("downTraffic", 0), json.dumps(merged.get("rawConfig", {}), ensure_ascii=False),
                merged.get("subId"), 1 if merged.get("stale") else 0,
                1 if merged.get("selected") else 0,
                merged.get("entryProto", "mixed"), merged.get("ssPass"),
                _conn_now(), node_id,
            ),
        )
        c.commit()
    return get_node(node_id)


def update_node_entry(node_id: str, entry_proto: str, ss_pass: Optional[str] = None) -> Optional[Dict]:
    """切换节点对外入口协议（mixed=ss|http 组合；ss=Shadowsocks 单协议）。

    切到 ss 时必须给 ss_pass（aes-256-gcm 加密密码，用户批量自定义）；无则自动生成。
    """
    with _lock:
        c = connect()
        row = c.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
        if not row:
            return None
        cur = _row_to_node(row)
        new_pass = ss_pass or cur.get("ssPass") or _gen_ss_pass()
        c.execute(
            "UPDATE nodes SET entry_proto=?, ss_pass=?, updated_at=? WHERE id=?",
            (entry_proto, new_pass, _conn_now(), node_id),
        )
        c.commit()
    return get_node(node_id)


def _gen_ss_pass() -> str:
    import secrets as _s
    return _s.token_hex(8)


def update_node_port(node_id: str, port: Optional[int]) -> Optional[Dict]:
    """更新端口；port 缺省时按当前段重分配。"""
    with _lock:
        c = connect()
        row = c.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
        if not row:
            return None
        cur = _row_to_node(row)
        used = _used_ports(c)
        # 排除自己当前端口
        if cur["port"] in used:
            used.discard(cur["port"])
        target = port
        if not target or target in used:
            seg = cur.get("segment") or infer_segment(cur["name"], cur["protocol"])
            target = _next_available_port_locked(c, port if port else None, seg)
        c.execute("UPDATE nodes SET port=?, updated_at=? WHERE id=?", (target, _conn_now(), node_id))
        c.commit()
    return get_node(node_id)


def delete_node(node_id: str) -> bool:
    with _lock:
        c = connect()
        cur = c.execute("DELETE FROM nodes WHERE id = ?", (node_id,))
        c.commit()
        return cur.rowcount > 0


def delete_node_batch(ids: List[str]) -> int:
    with _lock:
        c = connect()
        cur = c.execute("DELETE FROM nodes WHERE id IN (%s)" % ",".join("?" * len(ids)), ids)
        c.commit()
        return cur.rowcount


def add_traffic(node_id: str, up_delta: int, down_delta: int) -> None:
    """累计流量（增量）。"""
    with _lock:
        c = connect()
        c.execute(
            "UPDATE nodes SET up_traffic = up_traffic + ?, down_traffic = down_traffic + ?, updated_at = ? WHERE id = ?",
            (max(0, int(up_delta)), max(0, int(down_delta)), _conn_now(), node_id),
        )
        c.commit()


def reset_node_traffic(node_id: str) -> Optional[Dict]:
    with _lock:
        c = connect()
        c.execute("UPDATE nodes SET up_traffic=0, down_traffic=0, updated_at=? WHERE id=?", (_conn_now(), node_id))
        c.commit()
    return get_node(node_id)


def mark_nodes_stale_by_sub(sub_id: str) -> int:
    """订阅刷新失败时，把该订阅导入的已有节点标 stale（过期快照数据）。"""
    with _lock:
        c = connect()
        cur = c.execute("UPDATE nodes SET stale=1, updated_at=? WHERE sub_id=?", (_conn_now(), sub_id))
        c.commit()
        return cur.rowcount


def reset_all_traffic() -> None:
    with _lock:
        c = connect()
        c.execute("UPDATE nodes SET up_traffic=0, down_traffic=0, updated_at=?", (_conn_now(),))
        c.commit()


def update_node_probe(node_id: str, ping: int, status: str, error: Optional[str] = None) -> None:
    """探活结果落库（status/exitIp/ping 由后端覆盖，不经前端回写）。"""
    with _lock:
        c = connect()
        c.execute(
            "UPDATE nodes SET ping=?, status=?, updated_at=? WHERE id=?",
            (int(ping), status, _conn_now(), node_id),
        )
        c.commit()


# ---------- 多域名轮询 ----------

def list_relay_domains() -> List[Dict]:
    with _lock:
        c = connect()
        out = []
        for r in c.execute("SELECT * FROM relay_domains ORDER BY port"):
            out.append({
                "id": r["id"], "domain": r["domain"], "port": r["port"],
                "authUser": r["auth_user"], "authPass": r["auth_pass"],
                "groups": json.loads(r["groups"] or '["ALL"]'),
            })
        return out


def upsert_relay_domains(domains: List[Dict]) -> None:
    """整表替换（settings 里 relayDomains 全量 PUT 时同步）。"""
    with _lock:
        c = connect()
        c.execute("DELETE FROM relay_domains")
        for d in domains:
            c.execute(
                "INSERT OR REPLACE INTO relay_domains (id,domain,port,auth_user,auth_pass,groups) VALUES (?,?,?,?,?,?)",
                (d["id"], d.get("domain", ""), d.get("port"), d.get("authUser"),
                 d.get("authPass"), json.dumps(d.get("groups", ["ALL"]), ensure_ascii=False)),
            )
        c.commit()


# ---------- 订阅 ----------

def list_subs() -> List[Dict]:
    with _lock:
        c = connect()
        out = []
        for r in c.execute("SELECT * FROM subscriptions ORDER BY created_at"):
            out.append({
                "id": r["id"], "url": r["url"], "name": r["name"] or r["url"][:40],
                "group": r["group"], "enabled": bool(r["enabled"]),
                "lastRefresh": r["last_refresh"], "nodeCount": r["node_count"],
                "lastError": r["last_error"],
            })
        return out


def get_sub(sub_id: str) -> Optional[Dict]:
    with _lock:
        c = connect()
        r = c.execute("SELECT * FROM subscriptions WHERE id = ?", (sub_id,)).fetchone()
        if not r:
            return None
        return {
            "id": r["id"], "url": r["url"], "name": r["name"] or r["url"][:40],
            "group": r["group"], "enabled": bool(r["enabled"]),
            "lastRefresh": r["last_refresh"], "nodeCount": r["node_count"],
            "lastError": r["last_error"], "snapshot": r["snapshot"],
        }


def create_sub(url: str, name: Optional[str], group: Optional[str]) -> Optional[Dict]:
    with _lock:
        c = connect()
        try:
            c.execute(
                'INSERT INTO subscriptions (id,url,name,"group",enabled,created_at) VALUES (?,?,?,?,1,?)',
                (new_sub_id(), url, name or url[:40], group or "订阅节点", _conn_now()),
            )
            c.commit()
        except sqlite3.IntegrityError:
            return None
    return get_sub(c.execute("SELECT id FROM subscriptions WHERE url=?", (url,)).fetchone()["id"])


def update_sub(sub_id: str, patch: Dict[str, Any]) -> Optional[Dict]:
    with _lock:
        c = connect()
        row = c.execute("SELECT * FROM subscriptions WHERE id = ?", (sub_id,)).fetchone()
        if not row:
            return None
        allowed = {
            "name": "name", "group": '"group"', "enabled": "enabled",
            "last_refresh": "last_refresh", "node_count": "node_count",
            "last_error": "last_error", "snapshot": "snapshot",
        }
        sets = []
        params = []
        for k, v in patch.items():
            if k in allowed:
                if k == "last_error" and (v is None or v == ""):
                    sets.append("last_error = NULL")
                else:
                    if v is None:
                        continue
                    sets.append(f"{allowed[k]} = ?")
                    params.append(int(v) if k in ("enabled", "last_refresh", "node_count") else v)
        if sets:
            c.execute(f"UPDATE subscriptions SET {', '.join(sets)} WHERE id = ?", (*params, sub_id))
            c.commit()
    return get_sub(sub_id)


def delete_sub(sub_id: str) -> bool:
    with _lock:
        c = connect()
        cur = c.execute("DELETE FROM subscriptions WHERE id = ?", (sub_id,))
        c.commit()
        return cur.rowcount > 0


# ---------- settings KV ----------

def get_setting(key: str, default: Any = None) -> Any:
    with _lock:
        c = connect()
        r = c.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        if not r:
            return default
        try:
            return json.loads(r[0])
        except Exception:
            return r[0]


def set_setting(key: str, value: Any) -> None:
    with _lock:
        c = connect()
        c.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            (key, json.dumps(value, ensure_ascii=False)),
        )
        c.commit()
