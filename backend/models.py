"""Pydantic v2 传输模型。
字段名直接用 camelCase（与前端 nodeState/systemSettings 一致），
DB 层负责 camelCase ↔ snake_case 映射，避免 alias 转换坑。
"""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------- 节点 ----------

class NodeCreate(BaseModel):
    name: str
    protocol: str
    group: Optional[str] = None
    port: Optional[int] = None
    segment: Optional[int] = None
    authUser: Optional[str] = None
    authPass: Optional[str] = None
    rawConfig: Optional[Dict[str, Any]] = None
    subId: Optional[str] = None
    subName: Optional[str] = None  # 订阅名（订阅导入节点，列表显示来源）
    status: Optional[str] = None
    ping: Optional[int] = None
    exitIp: Optional[str] = None
    upTraffic: Optional[int] = None
    downTraffic: Optional[int] = None
    entryProto: Optional[str] = "mixed"  # mixed(ss+http) | ss
    ssPass: Optional[str] = None


class Node(NodeCreate):
    id: str
    stale: bool = False
    selected: bool = False
    createdAt: Optional[int] = None
    updatedAt: Optional[int] = None


class EntryConvertRequest(BaseModel):
    """批量转换节点对外入口协议。entryProto: mixed | ss。"""
    ids: List[str] = []
    entryProto: str = "ss"          # 目标入口协议
    ssPass: Optional[str] = None    # 转 ss 时的统一加密密码（空则每个节点随机生成）
    method: str = "aes-256-gcm"     # 固定加密方式


class EntryConvertResponse(BaseModel):
    ok: bool = True
    converted: int = 0
    failed: int = 0
    errors: List[Dict[str, str]] = []
    items: List[Node] = []


class NodeBatchRequest(BaseModel):
    nodes: List[NodeCreate]


class NodeBatchResponse(BaseModel):
    created: int = 0
    skipped: int = 0
    duplicate: int = 0
    items: List[Node] = []


class NodeListResponse(BaseModel):
    items: List[Node] = []
    total: int = 0


class NodePatch(BaseModel):
    """节点可 patch 字段（可选，缺省不变）。"""
    name: Optional[str] = None
    group: Optional[str] = None
    port: Optional[int] = None
    segment: Optional[int] = None
    authUser: Optional[str] = None
    authPass: Optional[str] = None
    rawConfig: Optional[Dict[str, Any]] = None
    subId: Optional[str] = None
    status: Optional[str] = None
    ping: Optional[int] = None
    exitIp: Optional[str] = None
    upTraffic: Optional[int] = None
    downTraffic: Optional[int] = None
    stale: Optional[bool] = None
    entryProto: Optional[str] = None
    ssPass: Optional[str] = None
    selected: Optional[bool] = None
    consecutiveFails: Optional[int] = None


class PortUpdateRequest(BaseModel):
    port: Optional[int] = None


class PingRequest(BaseModel):
    ids: Optional[List[str]] = None
    all: bool = True
    includeDisabled: bool = False


class PingResultItem(BaseModel):
    id: str
    tag: str
    ping: int = 0
    status: str = "offline"
    error: Optional[str] = None


class DeleteBatchRequest(BaseModel):
    ids: List[str]


class DeleteBatchResponse(BaseModel):
    deleted: int = 0


# ---------- 多域名轮询 ----------

class RelayDomain(BaseModel):
    id: str
    domain: str
    port: int
    authUser: Optional[str] = None
    authPass: Optional[str] = None
    groups: List[str] = Field(default_factory=lambda: ["ALL"])


# ---------- 订阅 ----------

class SubCreate(BaseModel):
    url: str
    name: Optional[str] = None
    group: Optional[str] = None
    enabled: bool = True


class Subscription(BaseModel):
    id: str
    url: str
    name: str
    group: str = "订阅节点"
    enabled: bool = True
    lastRefresh: Optional[int] = None
    nodeCount: int = 0
    lastError: Optional[str] = None


class SubToggleRequest(BaseModel):
    enabled: bool


class SubFetchRequest(BaseModel):
    url: str


class SubFetchResponse(BaseModel):
    ok: bool
    status: Optional[int] = None
    content: Optional[str] = None
    error: Optional[str] = None


class SubParseRequest(BaseModel):
    content: str


class SubParseNode(BaseModel):
    name: str
    protocol: str
    rawConfig: Dict[str, Any]


class SubParseResponse(BaseModel):
    nodes: List[SubParseNode] = []


class SubRefreshRequest(BaseModel):
    ids: Optional[List[str]] = None
    all: bool = True


class SubRefreshResult(BaseModel):
    id: str
    ok: bool
    count: int = 0
    stale: bool = False
    imported: int = 0
    error: Optional[str] = None


class SubRefreshResponse(BaseModel):
    results: List[SubRefreshResult] = []


# ---------- 配置 ----------

class ConfigStatus(BaseModel):
    running: bool = False
    pid: Optional[int] = None
    uptime: Optional[float] = None
    version: Optional[str] = None
    clashApiOk: bool = False
    controller: Optional[str] = None


class ConfigApplyResponse(BaseModel):
    ok: bool
    message: str
    running: bool = False
    clashApiOk: bool = False
    errors: List[Dict[str, str]] = []


# ---------- 统计 ----------

class GlobalStats(BaseModel):
    upRate: float = 0.0
    downRate: float = 0.0
    upTotal: int = 0
    downTotal: int = 0


class NodeStats(BaseModel):
    id: str
    port: Optional[int] = None
    upTraffic: int = 0
    downTraffic: int = 0
    upRate: float = 0.0
    downRate: float = 0.0
    status: str = "offline"
    ping: int = 0


class RelayStats(BaseModel):
    id: str
    port: int
    upRate: float = 0.0
    downRate: float = 0.0


class StatsResponse(BaseModel):
    global_: GlobalStats = Field(default_factory=GlobalStats, alias="global")
    nodes: List[NodeStats] = []
    relayDomains: List[RelayStats] = []

    model_config = {"populate_by_name": True}
