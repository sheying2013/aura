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
              sub_name      TEXT,
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

            CREATE TABLE IF NOT EXISTS deleted_fingerprints (
              fingerprint TEXT PRIMARY KEY,
              created_at  INTEGER
            );
            """
        )
        # 老库迁移：补 entry_proto / ss_pass 列（节点对外入口协议 + ss 密码）
        cols = {r[1] for r in c.execute("PRAGMA table_info(nodes)")}
        if "entry_proto" not in cols:
            c.execute("ALTER TABLE nodes ADD COLUMN entry_proto TEXT DEFAULT 'mixed'")
        if "ss_pass" not in cols:
            c.execute("ALTER TABLE nodes ADD COLUMN ss_pass TEXT")
        if "sub_name" not in cols:
            c.execute("ALTER TABLE nodes ADD COLUMN sub_name TEXT")
        if "consecutive_fails" not in cols:
            c.execute("ALTER TABLE nodes ADD COLUMN consecutive_fails INTEGER DEFAULT 0")
        # IP 情报列（探活成功后落库归属地/类型/评分）
        for col, ddl in (
            ("exit_country", "TEXT"),
            ("exit_flag", "TEXT"),
            ("exit_city", "TEXT"),
            ("exit_type", "TEXT"),
            ("exit_score", "INTEGER"),
            ("exit_risk", "INTEGER"),
        ):
            if col not in cols:
                c.execute(f"ALTER TABLE nodes ADD COLUMN {col} {ddl}")
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
        "subName": row["sub_name"] if "sub_name" in row.keys() else None,
        "stale": bool(row["stale"]),
        "selected": bool(row["selected"]),
        "entryProto": row["entry_proto"] or "mixed",
        "ssPass": row["ss_pass"],
        "consecutiveFails": row["consecutive_fails"] if "consecutive_fails" in row.keys() else 0,
        "exitCountry": row["exit_country"] if "exit_country" in row.keys() else None,
        "exitFlag": row["exit_flag"] if "exit_flag" in row.keys() else None,
        "exitCity": row["exit_city"] if "exit_city" in row.keys() else None,
        "exitType": row["exit_type"] if "exit_type" in row.keys() else None,
        "exitScore": row["exit_score"] if "exit_score" in row.keys() else None,
        "exitRisk": row["exit_risk"] if "exit_risk" in row.keys() else None,
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
        node.get("subName"),
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


def _next_available_port_locked(c, preferred_port: Optional[int], segment: Optional[int] = None) -> Optional[int]:
    """不加锁的端口分配内核（调用方需已持有 _lock）。默认从 52001 起分配。

    P2-2：端口池 52001-65535 全占满时返回 None（不再 p+=1 越过 65535 产生非法端口）。
    """
    used = _used_ports(c)
    if preferred_port and preferred_port not in used:
        return preferred_port
    base = 52001
    p = base
    while p in used:
        p += 1
        if p > 65535:
            return None  # 端口池耗尽
    return p


def get_next_available_port(preferred_port: Optional[int], segment: Optional[int] = None) -> int:
    """端口分配：preferred_port 生效则用之，否则从 52001 起；冲突自动向上跳过。"""
    with _lock:
        c = connect()
        return _next_available_port_locked(c, preferred_port, segment)


def random_auth(port: int) -> tuple:
    """随机认证账号密码（与前端风格一致）。"""
    user = _rand_str(8)
    passwd = _rand_str(12)
    return user, passwd


def rename_group(old_name: str, new_name: str) -> Dict[str, Any]:
    """分组重命名：批量更新节点分组 + relay_domains 的 groups 引用。

    返回 {updated, relayUpdated}——updated=节点数，relayUpdated=引用更新的域名数。
    """
    if not old_name or not new_name or old_name == new_name:
        return {"updated": 0, "relayUpdated": 0}
    with _lock:
        c = connect()
        cur = c.execute('UPDATE nodes SET "group"=?, updated_at=? WHERE "group"=?',
                        (new_name, _conn_now(), old_name))
        updated = cur.rowcount
        relay_updated = 0
        for r in c.execute("SELECT id, groups FROM relay_domains"):
            try:
                groups = json.loads(r["groups"] or '["ALL"]')
            except Exception:
                continue
            if old_name in groups and "ALL" not in groups:
                groups = [new_name if g == old_name else g for g in groups]
                c.execute("UPDATE relay_domains SET groups=? WHERE id=?", (json.dumps(groups), r["id"]))
                relay_updated += 1
        # settings.relayDomains 同步更新（否则前端下次保存设置会用旧分组名回退）
        if relay_updated:
            srow = c.execute("SELECT value FROM settings WHERE key='system'").fetchone()
            if srow:
                try:
                    s = json.loads(srow["value"] or "{}")
                except Exception:
                    s = {}
                changed = False
                for rd in s.get("relayDomains", []) or []:
                    gs = rd.get("groups") or ["ALL"]
                    if old_name in gs and "ALL" not in gs:
                        rd["groups"] = [new_name if g == old_name else g for g in gs]
                        changed = True
                if changed:
                    c.execute("UPDATE settings SET value=? WHERE key='system'",
                              (json.dumps(s, ensure_ascii=False),))
        c.commit()
        return {"updated": updated, "relayUpdated": relay_updated}


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
                exit_ip,up_traffic,down_traffic,raw_config,sub_id,sub_name,stale,selected,entry_proto,ss_pass,created_at,updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            _node_to_params(node),
        )
        c.commit()
    return get_node(node["id"])


def create_node_batch(nodes: List[Dict[str, Any]], update_existing_sub: bool = False) -> Dict[str, Any]:
    """批量创建 + 去重（按 server:server_port）。返回 {created, skipped, duplicate, items}。

    update_existing_sub=True（订阅刷新）：同 subId 且 server:port 已存在的节点
    直接 UPDATE（机场换密码/uuid 后新参数生效，P1-3），不回跳；不同 subId /
    无 subId 的节点仍走去重跳过，防止误改他组/手动导入节点。
    """
    created = 0
    skipped = 0
    duplicate = 0
    items: List[Dict] = []
    with _lock:
        c = connect()
        # 一次性预载：现有节点 server 指纹 + 已删指纹 + 已用端口（避免每节点循环全表扫描 O(N²)）
        existing_servers = set()
        existing_by_key: Dict[tuple, Dict] = {}  # (sub_id, srv, sp) → 节点行（订阅刷新更新用）
        for r in c.execute("SELECT raw_config, id, sub_id FROM nodes"):
            try:
                rc = json.loads(r["raw_config"] or "{}")
                srv = rc.get("server") or rc.get("address")
                sp = rc.get("server_port") or rc.get("port")
                if srv and sp:
                    existing_servers.add((str(srv), int(sp)))
                    if r["sub_id"]:
                        existing_by_key[(r["sub_id"], str(srv), int(sp))] = {
                            "id": r["id"], "sub_id": r["sub_id"]}
            except Exception:
                pass
        # 已删除节点指纹（sub_id|server|port）：订阅刷新不重复导入
        deleted_fps = {r["fingerprint"] for r in c.execute("SELECT fingerprint FROM deleted_fingerprints")}
        # 已用端口只查一次（含 relay_domains），循环内只增批内集合
        db_used = {r[0] for r in c.execute("SELECT port FROM nodes")} | {r[0] for r in c.execute("SELECT port FROM relay_domains")}
        # 保留端口段（settings.system.reservedPorts）也计入占用——与 get_next_available_port 主路径一致，
        # 否则批内自动分配会占用用户预留的端口
        _rp_row = c.execute("SELECT value FROM settings WHERE key='system'").fetchone()
        if _rp_row:
            try:
                _s = json.loads(_rp_row[0] or "{}")
                for p in (_s.get("reservedPorts", []) or []):
                    try:
                        db_used.add(int(p))
                    except (TypeError, ValueError):
                        pass
            except Exception:
                pass
        batch_ports = set()
        for nd in nodes:
            # 每个节点必须带 id（前端 batch payload / 订阅导入都不传，由后端生成）
            if not nd.get("id"):
                nd["id"] = new_node_id()
            rc = nd.get("rawConfig") or {}
            srv = rc.get("server") or rc.get("address")
            sp = rc.get("server_port") or rc.get("port")
            if srv and sp:
                key = (str(srv), int(sp))
                # 订阅刷新：同 subId 已存在 → 原地 UPDATE（机场换参数后新配置生效），不重复导入
                if update_existing_sub and nd.get("subId"):
                    ex = existing_by_key.get((nd["subId"], str(srv), int(sp)))
                    if ex:
                        upd = dict(nd)
                        upd["id"] = ex["id"]
                        # 取该节点当前端口（更新不动端口，避免端口漂移）
                        prow = c.execute("SELECT port FROM nodes WHERE id=?", (ex["id"],)).fetchone()
                        upd["port"] = prow["port"] if prow else 0
                        c.execute(
                            """UPDATE nodes SET name=?,protocol=?,"group"=?,segment=?,auth_user=?,
                               auth_pass=?,status=?,ping=?,exit_ip=?,raw_config=?,sub_name=?,
                               entry_proto=?,ss_pass=?,stale=?,updated_at=? WHERE id=?""",
                            (upd.get("name", "未命名"), upd.get("protocol", "shadowsocks"),
                             upd.get("group", "默认分组"), upd.get("segment"),
                             upd.get("authUser"), upd.get("authPass"),
                             upd.get("status", "offline"), upd.get("ping", 0),
                             upd.get("exitIp", "N/A"),
                             json.dumps(upd.get("rawConfig", {}), ensure_ascii=False),
                             upd.get("subName"), upd.get("entryProto", "mixed"),
                             upd.get("ssPass"), 1 if upd.get("stale") else 0,
                             _conn_now(), ex["id"]),
                        )
                        duplicate += 1  # 语义：已存在被更新（前端显示"重复（已存在）"数量不变）
                        continue
                # 刷新路径：不同 subId 同 server 允许导入（各自订阅独立，不互相挤占）；
                # 非刷新路径（手动导入/订阅首次导入）保持全局 server:port 去重
                if not update_existing_sub and key in existing_servers:
                    duplicate += 1
                    skipped += 1
                    continue
                # 已删除节点指纹：订阅刷新时不重复导入（仅跳过，不占 duplicate 计数）。
                # 注意：先检查指纹再 add existing_servers——已删节点不占位，同 host 不同订阅仍可导入
                if nd.get("subId") and f"{nd['subId']}|{srv}|{sp}" in deleted_fps:
                    skipped += 1
                    continue
                existing_servers.add(key)
            # 端口冲突则跳过（不入库，避免 IntegrityError 中断整批）
            port = nd.get("port")
            if not port:
                # 自动分配：从 52001 起找既不在 DB 也不在批内已用端口的空闲端口
                base = 52001
                port = base
                while port in db_used or port in batch_ports:
                    port += 1
            elif port in db_used or port in batch_ports:
                skipped += 1
                continue
            batch_ports.add(port)
            db_used.add(port)
            nd["port"] = port
            try:
                c.execute(
                    """INSERT INTO nodes
                       (id,name,protocol,"group",port,segment,auth_user,auth_pass,status,ping,
                        exit_ip,up_traffic,down_traffic,raw_config,sub_id,sub_name,stale,selected,entry_proto,ss_pass,created_at,updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    _node_to_params(nd),
                )
            except sqlite3.IntegrityError:
                skipped += 1
                continue
            # 不再逐条回查（200 节点 = 200 次全字段 SELECT），输入字段齐全直接用
            items.append(nd)
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
            merged[k] = v
        # P2-1：编辑弹窗改端口到已占用值 → 不再 IntegrityError 500，
        # 冲突时自动重分配空闲端口（与 update_node_port 语义一致）
        if "port" in patch and patch.get("port"):
            used = _used_ports(c)
            if cur["port"] in used:
                used.discard(cur["port"])
            if patch["port"] in used:
                newp = _next_available_port_locked(c, None)
                if newp is not None:
                    merged["port"] = newp
        c.execute(
            """UPDATE nodes SET name=?,protocol=?,"group"=?,port=?,segment=?,auth_user=?,
               auth_pass=?,status=?,ping=?,exit_ip=?,up_traffic=?,down_traffic=?,raw_config=?,
               sub_id=?,sub_name=?,stale=?,selected=?,entry_proto=?,ss_pass=?,consecutive_fails=?,
               exit_country=?,exit_flag=?,exit_city=?,exit_type=?,exit_score=?,exit_risk=?,updated_at=?
               WHERE id=?""",
            (
                merged["name"], merged["protocol"], merged["group"], merged["port"],
                merged["segment"], merged.get("authUser"), merged.get("authPass"),
                merged.get("status", "offline"), merged.get("ping", 0),
                merged.get("exitIp", "N/A"), merged.get("upTraffic", 0),
                merged.get("downTraffic", 0), json.dumps(merged.get("rawConfig", {}), ensure_ascii=False),
                merged.get("subId"), merged.get("subName"),
                1 if merged.get("stale") else 0,
                1 if merged.get("selected") else 0,
                merged.get("entryProto", "mixed"), merged.get("ssPass"),
                merged.get("consecutiveFails", 0),
                merged.get("exitCountry"), merged.get("exitFlag"), merged.get("exitCity"),
                merged.get("exitType"), merged.get("exitScore"), merged.get("exitRisk"),
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
            target = _next_available_port_locked(c, port if port else None)
        c.execute("UPDATE nodes SET port=?, updated_at=? WHERE id=?", (target, _conn_now(), node_id))
        c.commit()
    return get_node(node_id)


def delete_node(node_id: str) -> bool:
    with _lock:
        c = connect()
        node = c.execute("SELECT raw_config, sub_id FROM nodes WHERE id = ?", (node_id,)).fetchone()
        cur = c.execute("DELETE FROM nodes WHERE id = ?", (node_id,))
        if cur.rowcount > 0 and node:
            _record_deleted(c, node)
        c.commit()
        return cur.rowcount > 0


def delete_node_batch(ids: List[str]) -> int:
    with _lock:
        c = connect()
        marks = []
        for nid in ids:
            node = c.execute("SELECT raw_config, sub_id FROM nodes WHERE id = ?", (nid,)).fetchone()
            if node:
                marks.append(node)
        cur = c.execute("DELETE FROM nodes WHERE id IN (%s)" % ",".join("?" * len(ids)), ids)
        for node in marks:
            _record_deleted(c, node)
        c.commit()
        return cur.rowcount


def _record_deleted(c: sqlite3.Connection, node_row) -> None:
    """记录已删除节点指纹（sub_id + server:port），订阅刷新不再重复导入。"""
    rc = json.loads(node_row["raw_config"] or "{}")
    srv = rc.get("server") or rc.get("address")
    sp = rc.get("server_port") or rc.get("port")
    sub_id = node_row["sub_id"]
    if not srv or not sp or not sub_id:
        return
    fp = f"{sub_id}|{srv}|{sp}"
    c.execute("INSERT OR IGNORE INTO deleted_fingerprints (fingerprint, created_at) VALUES (?, ?)",
              (fp, _conn_now()))


def deleted_fingerprints(sub_id: Optional[str] = None) -> set:
    """订阅指纹集合（sub_id 过滤可选）。"""
    with _lock:
        c = connect()
        if sub_id:
            rows = c.execute("SELECT fingerprint FROM deleted_fingerprints WHERE fingerprint LIKE ?",
                             (f"{sub_id}|%",)).fetchall()
        else:
            rows = c.execute("SELECT fingerprint FROM deleted_fingerprints").fetchall()
        return {r["fingerprint"] for r in rows}


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


def unmark_nodes_stale_by_sub(sub_id: str) -> int:
    """订阅刷新成功后清 stale：订阅恢复正常时，历史失败标记的橙色警示应消除。"""
    with _lock:
        c = connect()
        cur = c.execute("UPDATE nodes SET stale=0, updated_at=? WHERE sub_id=? AND stale=1", (_conn_now(), sub_id))
        c.commit()
        return cur.rowcount


def reset_all_traffic() -> None:
    with _lock:
        c = connect()
        c.execute("UPDATE nodes SET up_traffic=0, down_traffic=0, updated_at=?", (_conn_now(),))
        c.commit()


def update_node_probe(node_id: str, ping: int, status: str, error: Optional[str] = None) -> Optional[int]:
    """探活结果落库（status/exitIp/ping 由后端覆盖，不经前端回写）。

    失败计数：status=online 清零；其他状态（offline/error/disabled）累加。
    返回累计失败次数（供调度器判断自动停用/删除），成功返回 0。
    """
    with _lock:
        c = connect()
        if status == "online":
            c.execute(
                "UPDATE nodes SET ping=?, status=?, consecutive_fails=0, updated_at=? WHERE id=?",
                (int(ping), status, _conn_now(), node_id),
            )
            c.commit()
            return 0
        c.execute(
            "UPDATE nodes SET ping=?, status=?, consecutive_fails=consecutive_fails+1, updated_at=? WHERE id=?",
            (int(ping), status, _conn_now(), node_id),
        )
        c.commit()
        row = c.execute("SELECT consecutive_fails FROM nodes WHERE id=?", (node_id,)).fetchone()
        return row["consecutive_fails"] if row else 0


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
    """整表替换（settings 里 relayDomains 全量 PUT 时同步）。

    P2-3：port UNIQUE 约束下 INSERT OR REPLACE 会静默删旧行（同名/同端口新域名
    覆盖旧域名，且可能破坏其他关联）。改为：先按 id 删对应行，再 INSERT——同 id
    更新、不同 id 同端口冲突时抛 IntegrityError（由调用方捕获提示，不静默删行）。
    """
    with _lock:
        c = connect()
        ids = [d["id"] for d in domains if d.get("id")]
        if ids:
            c.executemany("DELETE FROM relay_domains WHERE id = ?", [(i,) for i in ids])
        for d in domains:
            try:
                c.execute(
                    "INSERT INTO relay_domains (id,domain,port,auth_user,auth_pass,groups) VALUES (?,?,?,?,?,?)",
                    (d["id"], d.get("domain", ""), d.get("port"), d.get("authUser"),
                     d.get("authPass"), json.dumps(d.get("groups", ["ALL"]), ensure_ascii=False)),
                )
            except sqlite3.IntegrityError:
                continue  # 端口冲突：跳过新行，保留旧行（不静默删）
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
                # stale：上次刷新失败且无 last-good 快照 → 失效；有快照 → 降级
                "stale": bool(r["last_error"] and not r["snapshot"]),
                "degraded": bool(r["last_error"] and r["snapshot"]),
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
    sub_id = new_sub_id()
    with _lock:
        c = connect()
        try:
            c.execute(
                'INSERT INTO subscriptions (id,url,name,"group",enabled,created_at) VALUES (?,?,?,?,1,?)',
                (sub_id, url, name or url[:40], group or "订阅节点", _conn_now()),
            )
            c.commit()
        except sqlite3.IntegrityError:
            return None
    return get_sub(sub_id)


def update_sub(sub_id: str, patch: Dict[str, Any]) -> Optional[Dict]:
    with _lock:
        c = connect()
        row = c.execute("SELECT * FROM subscriptions WHERE id = ?", (sub_id,)).fetchone()
        if not row:
            return None
        allowed = {
            "name": "name", "group": '"group"', "enabled": "enabled",
            "url": "url", "last_refresh": "last_refresh", "node_count": "node_count",
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
