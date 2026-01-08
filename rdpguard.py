# RDPGuard - RDP 爆破检测与自动封禁工具
# 作者: ChaosJulien
#
# ⚠️ 免责声明: 本工具可能修改系统防火墙规则，存在误封风险。
#    请在测试环境充分验证后再用于生产。作者不承担任何使用后果。
#
# License: MIT

"""
RDPGuard - RDP 爆破检测与自动封禁工具
- 读取火绒 log.db 的“快照副本”（避免数据库被占用导致读取失败）
- 提取 RDP 爆破（fname=rlogin, detail.detail.detection=RDP）
- 将事件/统计/封禁记录持久化到 state.db
- 自动通过 Windows 防火墙封禁
  * 永久封禁：使用“一个聚合规则”合并大量 IP（性能更好；过大自动拆分 -1/-2/...）
  * 临时封禁：按 IP 单独规则（到期自动解封）
- 生成 report.html（若安装 matplotlib 可额外生成图表）
- 采集 Windows 防火墙 DROP 日志（pfirewall.log），用于验证封禁后仍在尝试的攻击源
- 自主轮询：默认每 5 分钟执行一轮（可配置）

必须使用【管理员】运行。
"""

import os
import re
import sys
import time
import json
import shutil
import sqlite3
import subprocess
from pathlib import Path
from datetime import datetime

# =========================
# 配置（按需修改）
# =========================

# 火绒数据库路径（与你环境一致）
HUORONG_DIR = Path(r"C:\ProgramData\Huorong\Sysdiag")
LOG_DB = HUORONG_DIR / "log.db"
LOG_DB_WAL = HUORONG_DIR / "log.db-wal"
LOG_DB_SHM = HUORONG_DIR / "log.db-shm"
HUORONG_TABLE = "HrLogV3_60"  # 火绒日志表名（你的环境是这个）

# RDPGuard 工作目录
BASE = Path(r"C:\ProgramData\RDPGuard")
STATE_DB = BASE / "state.db"
LOG_FILE = BASE / "rdpguard.log"
REPORT_HTML = BASE / "report.html"
CHART_TOP = BASE / "top_ips.png"
CHART_DAILY = BASE / "daily_hits.png"
SNAP_DIR = BASE / "snapshots"

# 快照保留策略：只保留最近 N 个快照（避免无限增长）
SNAPSHOT_KEEP_MAX = 50  # 每 5 分钟跑一次，保留 50~100 很够用

# 防火墙规则命名
RULE_PREFIX_TEMP = "RDPGuard"  # 临时封禁（单 IP 规则）：DisplayName="RDPGuard <ip>"
RULE_POOL_NAME = "RDPGuard-Blocked-IP-Pool"  # 永久封禁（聚合规则）：DisplayName=该名字（必要时拆分 -1/-2/...）

# 事件保留：state.db 中 events/drops 只保留最近 N 天（用于窗口统计/报表）
EVENT_RETENTION_DAYS = 30

# 封禁策略（火绒检测事件窗口）
THRESH_10M = 5
BAN_10M_HOURS = 24

THRESH_1D = 20
BAN_1D_DAYS = 7

THRESH_TOTAL = 100  # 达到累计次数则永久封禁

# 轮询执行（自主运行）
POLL_SECONDS = 300  # 5分钟
LOCK_FILE = BASE / "rdpguard.lock"

# Windows 防火墙 DROP 日志（用于验证封禁后仍在尝试的攻击）
ENABLE_FW_DROP_LOG = True
FW_LOG = Path(r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log")
FW_LOG_MAX_KB = 16384  # 16MB
RDP_PORT = 3389  # 你的 RDP 端口（默认 3389；如果你改了端口，这里要同步）

# IP 提取正则
RE_IP = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)

# =========================
# 工具函数
# =========================

def now_ts() -> int:
    """当前 Unix 时间戳（秒）"""
    return int(time.time())

def ts_to_local_str(ts: int) -> str:
    """时间戳转本地时间字符串"""
    return datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")

def ensure_dirs():
    """确保工作目录存在"""
    BASE.mkdir(parents=True, exist_ok=True)
    SNAP_DIR.mkdir(parents=True, exist_ok=True)

def append_log(msg: str):
    """写日志到文件 + 控制台输出"""
    ensure_dirs()
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n"
    try:
        with open(LOG_FILE, "a", encoding="utf-8", errors="ignore") as f:
            f.write(line)
    except Exception:
        pass
    print(msg)

def is_admin() -> bool:
    """判断是否管理员权限（net session 需要管理员）"""
    p = subprocess.run(
        ["powershell", "-NoProfile", "-Command", "net session"],
        capture_output=True, text=True
    )
    return p.returncode == 0

def run_ps(cmd: str) -> subprocess.CompletedProcess:
    """运行 PowerShell 命令"""
    return subprocess.run(
        ["powershell", "-NoProfile", "-Command", cmd],
        capture_output=True, text=True
    )

def cleanup_snapshots_keep_last_n():
    """
    快照清理：只保留最近 SNAPSHOT_KEEP_MAX 个快照目录。
    仅删除目录名符合 YYYYMMDD_HHMMSS 的目录，避免误删其他文件夹。
    """
    if not SNAP_DIR.exists():
        return

    items = []
    for p in SNAP_DIR.iterdir():
        if not p.is_dir():
            continue
        try:
            dt = datetime.strptime(p.name, "%Y%m%d_%H%M%S")
            ts = int(dt.timestamp())
            items.append((ts, p))
        except Exception:
            continue

    items.sort(key=lambda x: x[0], reverse=True)

    for _, p in items[SNAPSHOT_KEEP_MAX:]:
        try:
            shutil.rmtree(p, ignore_errors=True)
            append_log(f"SNAP_CLEAN 已删除旧快照：{p.name}")
        except Exception as e:
            append_log(f"SNAP_CLEAN 删除失败：{p.name}，错误：{e}")

def acquire_lock():
    """简单锁文件：防止你手误启动两份导致重复跑"""
    ensure_dirs()
    if LOCK_FILE.exists():
        raise RuntimeError(f"检测到锁文件，可能已有实例在运行：{LOCK_FILE}")
    LOCK_FILE.write_text(str(os.getpid()), encoding="utf-8", errors="ignore")

def release_lock():
    """释放锁文件"""
    try:
        if LOCK_FILE.exists():
            LOCK_FILE.unlink()
    except Exception:
        pass

# =========================
# 数据库：state.db
# =========================

def ensure_state_db():
    """初始化 state.db 结构"""
    ensure_dirs()
    conn = sqlite3.connect(str(STATE_DB))
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS meta(
      k TEXT PRIMARY KEY,
      v TEXT NOT NULL
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS events(
      ts INTEGER NOT NULL,
      ip TEXT NOT NULL
    )""")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_ip_ts ON events(ip, ts)")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS stats(
      ip TEXT PRIMARY KEY,
      first_seen INTEGER,
      last_seen INTEGER,
      hits_total INTEGER DEFAULT 0
    )""")

    # bans 表：记录临时/永久封禁
    # expires_at 为 NULL 表示永久封禁
    # kind: 'temp' 或 'perm'
    cur.execute("""
    CREATE TABLE IF NOT EXISTS bans(
      ip TEXT PRIMARY KEY,
      rule_name TEXT NOT NULL,
      kind TEXT NOT NULL,
      banned_at INTEGER NOT NULL,
      expires_at INTEGER,
      reason TEXT NOT NULL
    )""")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_bans_kind ON bans(kind)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_bans_expires ON bans(expires_at)")

    # drops 表：记录防火墙 DROP 事件（用于验证封禁后是否仍在尝试）
    cur.execute("""
    CREATE TABLE IF NOT EXISTS drops(
      ts INTEGER NOT NULL,
      ip TEXT NOT NULL
    )""")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_drops_ts ON drops(ts)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_drops_ip_ts ON drops(ip, ts)")

    conn.commit()
    conn.close()

def get_meta(k: str, default: str = "0") -> str:
    """读取 meta 键值"""
    conn = sqlite3.connect(str(STATE_DB))
    cur = conn.cursor()
    cur.execute("SELECT v FROM meta WHERE k=?", (k,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else default

def set_meta(k: str, v: str):
    """写入 meta 键值"""
    conn = sqlite3.connect(str(STATE_DB))
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
        (k, str(v))
    )
    conn.commit()
    conn.close()

def update_state_with_events(events):
    """
    events: list[(ts:int, ip:str)]
    - 写入 events
    - 更新 stats（首次/最后出现/累计次数）
    - 清理超出 EVENT_RETENTION_DAYS 的旧 events
    """
    if not events:
        return

    conn = sqlite3.connect(str(STATE_DB))
    cur = conn.cursor()

    cur.executemany("INSERT INTO events(ts, ip) VALUES(?,?)", events)

    for ts, ip in events:
        cur.execute("SELECT first_seen, last_seen, hits_total FROM stats WHERE ip=?", (ip,))
        row = cur.fetchone()
        if not row:
            cur.execute(
                "INSERT INTO stats(ip, first_seen, last_seen, hits_total) VALUES(?,?,?,?)",
                (ip, ts, ts, 1)
            )
        else:
            first_seen, last_seen, hits_total = row
            if first_seen is None:
                first_seen = ts
            if last_seen is None or ts > last_seen:
                last_seen = ts
            hits_total = (hits_total or 0) + 1
            cur.execute(
                "UPDATE stats SET first_seen=?, last_seen=?, hits_total=? WHERE ip=?",
                (first_seen, last_seen, hits_total, ip)
            )

    keep_from = now_ts() - EVENT_RETENTION_DAYS * 86400
    cur.execute("DELETE FROM events WHERE ts < ?", (keep_from,))

    conn.commit()
    conn.close()

# =========================
# 火绒快照读取
# =========================

def mirror_huorong_db() -> Path:
    """
    将火绒 log.db（以及 wal/shm）复制到快照目录，避免被占用/锁导致读取失败。
    并在复制前执行“只保留最近 N 个快照”的清理策略。
    返回快照中的 log.db 路径。
    """
    if not LOG_DB.exists():
        raise FileNotFoundError(str(LOG_DB))

    ensure_dirs()
    cleanup_snapshots_keep_last_n()

    snap = SNAP_DIR / time.strftime("%Y%m%d_%H%M%S")
    snap.mkdir(parents=True, exist_ok=True)

    shutil.copy2(LOG_DB, snap / "log.db")
    if LOG_DB_WAL.exists():
        shutil.copy2(LOG_DB_WAL, snap / "log.db-wal")
    if LOG_DB_SHM.exists():
        shutil.copy2(LOG_DB_SHM, snap / "log.db-shm")

    return snap / "log.db"

def parse_ips_from_detail(detail: str):
    """
    从火绒 detail 字段解析攻击者 IP，返回 set[str]。
    优先：json.loads（火绒常见是 JSON 字符串）
    兜底：正则扫描（仅当检测字段像 RDP 时才扫描，降低误报）
    """
    ips = set()
    if not detail:
        return ips
    s = str(detail).strip()

    try:
        obj = json.loads(s)
        d = obj.get("detail", {})
        if d.get("detection") != "RDP":
            return set()

        ra = d.get("raddr")
        if isinstance(ra, str) and ra:
            ips.add(ra)

        rdata = d.get("rdata", {})
        arr = rdata.get("raddr")
        if isinstance(arr, list):
            for x in arr:
                if isinstance(x, str) and x:
                    ips.add(x)
        return ips
    except Exception:
        pass

    if ("detection" not in s) or ("RDP" not in s):
        return set()
    if '"detection":"RDP"' not in s and "'detection':'RDP'" not in s and "detection\":\"RDP" not in s:
        return set()

    for ip in RE_IP.findall(s):
        ips.add(ip)
    return ips

def read_new_events_from_snapshot(snapshot_db: Path, last_ts: int):
    """
    增量读取：只取 ts > last_ts 且 fname='rlogin' 的记录
    返回 (events, max_ts_seen)
    """
    conn = sqlite3.connect(str(snapshot_db))
    cur = conn.cursor()

    sql = f"""
    SELECT ts, detail
    FROM {HUORONG_TABLE}
    WHERE fname='rlogin'
      AND ts > ?
      AND detail LIKE '%detection%'
    ORDER BY ts ASC
    """
    cur.execute(sql, (last_ts,))
    rows = cur.fetchall()
    conn.close()

    out = []
    max_ts = last_ts

    for ts, detail in rows:
        if ts is None or detail is None:
            continue
        ips = parse_ips_from_detail(str(detail))
        if not ips:
            continue
        for ip in ips:
            out.append((int(ts), ip))
        if int(ts) > max_ts:
            max_ts = int(ts)

    return out, max_ts

# =========================
# 防火墙操作
# =========================

def fw_rule_exists(display_name: str) -> bool:
    """判断防火墙规则是否存在"""
    p = run_ps(f"Get-NetFirewallRule -DisplayName '{display_name}' -ErrorAction SilentlyContinue | Select -First 1")
    return bool(p.stdout.strip())

def fw_remove_rule(display_name: str) -> bool:
    """删除防火墙规则"""
    p = run_ps(f"Get-NetFirewallRule -DisplayName '{display_name}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule")
    return p.returncode == 0

def fw_create_block_rule_single_ip(ip: str, display_name: str) -> bool:
    """创建单 IP 入站拦截规则"""
    cmd = (
        f"New-NetFirewallRule -DisplayName '{display_name}' "
        f"-Direction Inbound -Action Block -RemoteAddress {ip} -Profile Any"
    )
    p = run_ps(cmd)
    return p.returncode == 0

def fw_upsert_permanent_pool_rule(ips):
    """
    创建/更新“永久封禁聚合规则”（一个规则合并很多 IP）：
      DisplayName: RULE_POOL_NAME
      RemoteAddress: ip1,ip2,...

    注意：防火墙存在长度/数量限制；若失败则自动拆分为多个规则：RULE_POOL_NAME-1/-2/...
    """
    ips = sorted(set(ips))
    if not ips:
        return True

    remote = ",".join(ips)

    # 尝试单规则
    if not fw_rule_exists(RULE_POOL_NAME):
        cmd = (
            f"New-NetFirewallRule -DisplayName '{RULE_POOL_NAME}' "
            f"-Direction Inbound -Action Block -RemoteAddress {remote} -Profile Any"
        )
        p = run_ps(cmd)
        if p.returncode == 0:
            return True
    else:
        cmd = f"Set-NetFirewallRule -DisplayName '{RULE_POOL_NAME}' -RemoteAddress {remote}"
        p = run_ps(cmd)
        if p.returncode == 0:
            return True

    # 单规则失败：拆分（先移除主规则，避免混乱）
    if fw_rule_exists(RULE_POOL_NAME):
        fw_remove_rule(RULE_POOL_NAME)

    chunk_size = 500  # 保守一点，避免 PowerShell 参数过长
    ok_all = True
    for i in range(0, len(ips), chunk_size):
        chunk = ips[i:i + chunk_size]
        name = f"{RULE_POOL_NAME}-{(i // chunk_size) + 1}"
        remote_chunk = ",".join(chunk)

        if fw_rule_exists(name):
            p = run_ps(f"Set-NetFirewallRule -DisplayName '{name}' -RemoteAddress {remote_chunk}")
        else:
            p = run_ps(
                f"New-NetFirewallRule -DisplayName '{name}' -Direction Inbound -Action Block "
                f"-RemoteAddress {remote_chunk} -Profile Any"
            )
        if p.returncode != 0:
            ok_all = False

    return ok_all

# =========================
# 防火墙 DROP 日志（pfirewall.log）
# =========================

def ensure_firewall_drop_logging():
    """确保 Windows 防火墙开启丢弃日志（管理员运行）"""
    if not ENABLE_FW_DROP_LOG:
        return

    cmd = (
        "Set-NetFirewallProfile -Profile Domain,Public,Private "
        f"-LogBlocked True -LogAllowed False "
        f"-LogFileName '{str(FW_LOG)}' "
        f"-LogMaxSizeKilobytes {FW_LOG_MAX_KB}"
    )
    p = run_ps(cmd)
    if p.returncode == 0:
        append_log("已确保开启防火墙 DROP 日志")
    else:
        err = (p.stderr or "").strip()
        append_log(f"警告：开启防火墙 DROP 日志失败：{err if err else '未知错误'}")

def parse_firewall_drop_log_and_store():
    """
    增量解析 pfirewall.log，提取被 DROP 的 RDP 连接（dst-port=RDP_PORT）
    将 (ts, src_ip) 写入 drops 表。
    """
    if not ENABLE_FW_DROP_LOG:
        return

    if not FW_LOG.exists():
        append_log(f"未找到防火墙日志：{FW_LOG}")
        return

    last_pos = int(get_meta("fwlog_pos", "0"))

    try:
        size = FW_LOG.stat().st_size
    except Exception:
        return

    # 文件被清空/轮转：从头读
    if size < last_pos:
        last_pos = 0

    new_rows = []
    new_pos = last_pos

    try:
        with open(FW_LOG, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(last_pos)

            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # 常见格式（Windows 防火墙日志默认字段）：
                # date time action protocol src-ip dst-ip src-port dst-port ...
                parts = line.split()
                if len(parts) < 8:
                    continue

                date_s, time_s, action, proto = parts[0], parts[1], parts[2], parts[3]
                if action.upper() != "DROP":
                    continue
                if proto.upper() != "TCP":
                    continue

                src_ip = parts[4]
                dst_port = parts[7]

                if str(dst_port) != str(RDP_PORT):
                    continue
                if not RE_IP.fullmatch(src_ip):
                    continue

                try:
                    dt = datetime.strptime(f"{date_s} {time_s}", "%Y-%m-%d %H:%M:%S")
                    ts = int(dt.timestamp())
                except Exception:
                    continue

                new_rows.append((ts, src_ip))

            new_pos = f.tell()
    except Exception as e:
        append_log(f"DROP_LOG 读取失败：{e}")
        return

    if new_rows:
        conn = sqlite3.connect(str(STATE_DB))
        cur = conn.cursor()
        cur.executemany("INSERT INTO drops(ts, ip) VALUES(?,?)", new_rows)

        keep_from = now_ts() - EVENT_RETENTION_DAYS * 86400
        cur.execute("DELETE FROM drops WHERE ts < ?", (keep_from,))

        conn.commit()
        conn.close()

        append_log(f"DROP_LOG 已导入 {len(new_rows)} 条（RDP_PORT={RDP_PORT}）")

    set_meta("fwlog_pos", str(new_pos))

# =========================
# 封禁决策引擎
# =========================

def decide_and_apply_bans():
    """
    - 自动解封已到期的临时封禁规则
    - 统计窗口命中次数（近 10 分钟、近 24 小时）
    - 永久封禁：stats.hits_total >= THRESH_TOTAL
      -> 更新聚合规则，并在 bans(kind='perm') 记录
    - 临时封禁：未永久封禁的 IP，满足窗口阈值
      -> 创建单 IP 防火墙规则，记录 bans(kind='temp')
    """
    now = now_ts()
    t10 = now - 10 * 60
    t1d = now - 24 * 3600

    conn = sqlite3.connect(str(STATE_DB))
    cur = conn.cursor()

    # 1) 解封到期的临时封禁
    cur.execute("""
      SELECT ip, rule_name FROM bans
      WHERE kind='temp' AND expires_at IS NOT NULL AND expires_at <= ?
    """, (now,))
    expired = cur.fetchall()
    for ip, rule_name in expired:
        fw_remove_rule(rule_name)
        append_log(f"解封 {ip}（临时封禁到期）")
        cur.execute("DELETE FROM bans WHERE ip=?", (ip,))

    # 2) 统计近 24h 的窗口命中（同时得出近 10m 和近 1d）
    cur.execute("""
      SELECT ip,
             SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END) AS hits_10m,
             SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END) AS hits_1d
      FROM events
      WHERE ts >= ?
      GROUP BY ip
    """, (t10, t1d, t1d))
    window = {ip: (h10 or 0, h1d or 0) for ip, h10, h1d in cur.fetchall()}

    # 3) 累计命中
    cur.execute("SELECT ip, hits_total FROM stats")
    totals = {ip: (hits_total or 0) for ip, hits_total in cur.fetchall()}

    # 4) 已封禁映射
    cur.execute("SELECT ip, kind FROM bans")
    banned_map = {ip: kind for ip, kind in cur.fetchall()}

    # 5) 永久封禁集合（累计达到阈值）
    perm_ips = [ip for ip, total in totals.items() if total >= THRESH_TOTAL]
    if perm_ips:
        ok = fw_upsert_permanent_pool_rule(perm_ips)
        if ok:
            for ip in perm_ips:
                if banned_map.get(ip) == "perm":
                    continue
                # 永久封禁不创建 per-ip 规则，rule_name 记录聚合规则名
                cur.execute("""
                  INSERT OR REPLACE INTO bans(ip, rule_name, kind, banned_at, expires_at, reason)
                  VALUES (?,?,?,?,?,?)
                """, (ip, RULE_POOL_NAME, "perm", now, None, f"累计>={THRESH_TOTAL}"))
            append_log(f"已更新永久封禁聚合规则，永久封禁 IP 数：{len(perm_ips)}")
        else:
            append_log("错误：更新永久封禁聚合规则失败（可能是防火墙限制/权限问题）")

    # 6) 临时封禁（只对非永久封禁、且未封禁的 IP 生效）
    new_temp = []
    for ip, total in totals.items():
        if total >= THRESH_TOTAL:
            continue
        if ip in banned_map:
            continue

        h10, h1d = window.get(ip, (0, 0))
        reason = None
        expires_at = None

        if h1d >= THRESH_1D:
            reason = f"近24小时>={THRESH_1D}"
            expires_at = now + BAN_1D_DAYS * 86400
        elif h10 >= THRESH_10M:
            reason = f"近10分钟>={THRESH_10M}"
            expires_at = now + BAN_10M_HOURS * 3600

        if reason:
            rule_name = f"{RULE_PREFIX_TEMP} {ip}"
            new_temp.append((ip, rule_name, now, expires_at, reason))

    # 批量应用临时封禁：限制一次最多处理数量，避免运行时间过长
    max_apply = 200
    applied = 0
    for ip, rule_name, banned_at, expires_at, reason in new_temp:
        if applied >= max_apply:
            break

        if not fw_rule_exists(rule_name):
            ok = fw_create_block_rule_single_ip(ip, rule_name)
            if not ok:
                append_log(f"临时封禁失败 {ip}（原因：{reason}）")
                continue

        cur.execute("""
          INSERT OR REPLACE INTO bans(ip, rule_name, kind, banned_at, expires_at, reason)
          VALUES (?,?,?,?,?,?)
        """, (ip, rule_name, "temp", banned_at, expires_at, reason))

        append_log(f"临时封禁 {ip}（{reason}），到期：{ts_to_local_str(expires_at)}")
        applied += 1

    conn.commit()
    conn.close()

# =========================
# 报表生成（含态势卡片 + 可选图表）
# =========================

def generate_report():
    """生成 report.html（可选生成图表 top_ips.png / daily_hits.png）"""
    now = now_ts()
    t24 = now - 24 * 3600
    t1h = now - 3600

    conn = sqlite3.connect(str(STATE_DB))
    cur = conn.cursor()

    # ========= 态势卡片指标 =========

    # 近24小时命中
    cur.execute("SELECT COUNT(*) FROM events WHERE ts >= ?", (t24,))
    hits_24h = int(cur.fetchone()[0] or 0)

    # 近24小时攻击IP去重
    cur.execute("SELECT COUNT(DISTINCT ip) FROM events WHERE ts >= ?", (t24,))
    uniq_ips_24h = int(cur.fetchone()[0] or 0)

    # 近1小时活跃攻击源（去重）
    cur.execute("SELECT COUNT(DISTINCT ip) FROM events WHERE ts >= ?", (t1h,))
    active_ips_1h = int(cur.fetchone()[0] or 0)

    # 近24小时新增攻击源（按 stats.first_seen 计算）
    cur.execute("SELECT COUNT(*) FROM stats WHERE first_seen IS NOT NULL AND first_seen >= ?", (t24,))
    new_ips_24h = int(cur.fetchone()[0] or 0)

    # 当前有效临时封禁
    cur.execute("""
      SELECT COUNT(*) FROM bans
      WHERE kind='temp' AND expires_at IS NOT NULL AND expires_at > ?
    """, (now,))
    temp_bans_active = int(cur.fetchone()[0] or 0)

    # 永久封禁总数（数据库记录）
    cur.execute("SELECT COUNT(*) FROM bans WHERE kind='perm'")
    perm_bans_total = int(cur.fetchone()[0] or 0)

    # DROP 近24小时次数
    cur.execute("SELECT COUNT(*) FROM drops WHERE ts >= ?", (t24,))
    drops_24h = int(cur.fetchone()[0] or 0)

    # DROP 近24小时去重 IP 数
    cur.execute("SELECT COUNT(DISTINCT ip) FROM drops WHERE ts >= ?", (t24,))
    drops_ips_24h = int(cur.fetchone()[0] or 0)

    # ========= 明细表：封禁记录（最近 200 条） =========
    cur.execute("""
      SELECT ip, kind, reason, banned_at, expires_at
      FROM bans
      ORDER BY banned_at DESC
      LIMIT 200
    """)
    bans = cur.fetchall()

    # ========= 时间序列：每日命中（近 EVENT_RETENTION_DAYS 天） =========
    from_ts = now - EVENT_RETENTION_DAYS * 86400
    cur.execute("""
      SELECT date(datetime(ts,'unixepoch','localtime')) AS day, COUNT(*) AS hits
      FROM events
      WHERE ts >= ?
      GROUP BY day
      ORDER BY day ASC
    """, (from_ts,))
    daily = cur.fetchall()

    # ========= Top 20（累计命中，仍保留，后续你想删可以一键删掉这块） =========
    cur.execute("""
      SELECT ip, hits_total, first_seen, last_seen
      FROM stats
      ORDER BY hits_total DESC
      LIMIT 20
    """)
    top = cur.fetchall()

    conn.close()

    # ========= 可选图表（有 matplotlib 才画） =========
    plt = None
    try:
        import matplotlib.pyplot as plt  # type: ignore
    except Exception:
        plt = None

    use_cn = True  # 默认尝试中文；若找不到中文字体会切换为英文

    if plt:
        # 解决中文字体缺失：自动选择可用中文字体；否则退回英文
        try:
            from matplotlib import rcParams
            from matplotlib import font_manager

            def pick_cjk_font():
                candidates = [
                    "Microsoft YaHei",
                    "SimHei",
                    "Microsoft JhengHei",
                    "PingFang SC",
                    "Noto Sans CJK SC",
                    "Source Han Sans SC",
                    "WenQuanYi Micro Hei",
                ]
                available = {f.name for f in font_manager.fontManager.ttflist}
                for name in candidates:
                    if name in available:
                        return name
                return None

            cjk = pick_cjk_font()
            if cjk:
                rcParams["font.family"] = cjk
                rcParams["axes.unicode_minus"] = False
                use_cn = True
            else:
                use_cn = False
        except Exception:
            use_cn = False

        # Top IP 横向柱状图（累计）
        try:
            ips = [r[0] for r in top][::-1]
            hits = [r[1] for r in top][::-1]
            plt.figure(figsize=(10, 6))
            plt.barh(ips, hits)
            plt.xlabel("累计命中次数（hits_total）" if use_cn else "Total hits (hits_total)")
            plt.tight_layout()
            plt.savefig(str(CHART_TOP), dpi=160)
            plt.close()
        except Exception:
            pass

        # 每日趋势折线
        try:
            days = [r[0] for r in daily]
            dh = [r[1] for r in daily]
            plt.figure(figsize=(10, 4))
            plt.plot(days, dh, marker="o")
            plt.xticks(rotation=30, ha="right")
            plt.ylabel("命中次数（hits）" if use_cn else "Hits")
            plt.tight_layout()
            plt.savefig(str(CHART_DAILY), dpi=160)
            plt.close()
        except Exception:
            pass

    def fmt_ts(x):
        if x is None:
            return "-"
        return ts_to_local_str(int(x))

    ban_rows = "\n".join(
        f"<tr><td>{ip}</td><td>{kind}</td><td>{reason}</td><td>{fmt_ts(bat)}</td><td>{fmt_ts(exp)}</td></tr>"
        for ip, kind, reason, bat, exp in bans
    )

    # ========= HTML：态势卡片 =========
    html = f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>RDPGuard Report</title>
<style>
:root {{
  --bg:#0b0f14; --fg:#e6edf3; --muted:rgba(230,237,243,.75);
  --card:#111826; --border:#223049;
}}
body{{font-family:Segoe UI,Arial,sans-serif;margin:20px;background:var(--bg);color:var(--fg)}}
h1,h2,h3{{margin:.4em 0}}
.small{{opacity:.85;font-size:13px;color:var(--muted)}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:16px;margin:12px 0}}
.grid{{display:grid;grid-template-columns:repeat(3, minmax(0, 1fr));gap:12px}}
.kpi{{background:#0d1420;border:1px solid var(--border);border-radius:12px;padding:14px}}
.kpi .label{{font-size:13px;color:var(--muted)}}
.kpi .value{{font-size:28px;font-weight:700;margin-top:6px}}
.kpi .hint{{font-size:12px;color:var(--muted);margin-top:6px}}
table{{width:100%;border-collapse:collapse}}
th,td{{border-bottom:1px solid var(--border);padding:8px;text-align:left;font-size:14px}}
img{{max-width:100%;border-radius:10px;border:1px solid var(--border);background:var(--bg)}}
.code{{font-family:Consolas,monospace}}
@media (max-width: 900px) {{
  .grid{{grid-template-columns:1fr}}
}}
</style>
</head>
<body>
<h1>RDPGuard 面板</h1>
<div class="small">更新时间：{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>

<div class="card">
  <h2>态势概览（近 24 小时 / 近 1 小时）</h2>
  <div class="grid">
    <div class="kpi">
      <div class="label">近 24 小时命中</div>
      <div class="value">{hits_24h}</div>
      <div class="hint">来源：火绒 RDP 检测 events</div>
    </div>
    <div class="kpi">
      <div class="label">近 24 小时攻击 IP 数（去重）</div>
      <div class="value">{uniq_ips_24h}</div>
      <div class="hint">同一 IP 多次命中只算 1</div>
    </div>
    <div class="kpi">
      <div class="label">活跃攻击源（近 1 小时去重）</div>
      <div class="value">{active_ips_1h}</div>
      <div class="hint">衡量“此刻”攻击强度</div>
    </div>

    <div class="kpi">
      <div class="label">新增攻击源（近 24h 首次出现）</div>
      <div class="value">{new_ips_24h}</div>
      <div class="hint">按 stats.first_seen 统计</div>
    </div>
    <div class="kpi">
      <div class="label">当前有效封禁（临时）</div>
      <div class="value">{temp_bans_active}</div>
      <div class="hint">expires_at > now 的 temp</div>
    </div>
    <div class="kpi">
      <div class="label">永久封禁总数（记录）</div>
      <div class="value">{perm_bans_total}</div>
      <div class="hint">聚合规则：<span class="code">{RULE_POOL_NAME}</span></div>
    </div>
  </div>
</div>

<div class="card">
  <h2>封禁后验证（防火墙 DROP 日志）</h2>
  <div class="grid">
    <div class="kpi">
      <div class="label">近 24 小时 DROP 次数（RDP 端口 {RDP_PORT}）</div>
      <div class="value">{drops_24h}</div>
      <div class="hint">来源：{FW_LOG}</div>
    </div>
    <div class="kpi">
      <div class="label">近 24 小时仍在尝试的 IP（去重）</div>
      <div class="value">{drops_ips_24h}</div>
      <div class="hint">用于判断封禁后是否继续扫描</div>
    </div>
    <div class="kpi">
      <div class="label">快照保留</div>
      <div class="value">{SNAPSHOT_KEEP_MAX}</div>
      <div class="hint">只保留最近 N 个快照目录</div>
    </div>
  </div>
</div>

<div class="card">
  <h2>每日命中趋势（近 {EVENT_RETENTION_DAYS} 天）</h2>
  {"<img src='daily_hits.png' alt='daily'/>" if CHART_DAILY.exists() else "<div class='small'>未生成图表（可能未安装 matplotlib）</div>"}
</div>

<div class="card">
  <h2>当前封禁（数据库记录，最近 200 条）</h2>
  <table>
    <thead><tr><th>IP</th><th>kind</th><th>reason</th><th>banned_at</th><th>expires_at</th></tr></thead>
    <tbody>{ban_rows}</tbody>
  </table>
</div>

<div class="small">日志文件：{LOG_FILE}</div>
</body>
</html>
"""
    REPORT_HTML.write_text(html, encoding="utf-8", errors="ignore")

# =========================
# 单轮执行 / 轮询主循环
# =========================

def run_once():
    """执行一轮：快照 -> 导入 -> 封禁 -> DROP 导入 -> 报表"""
    ensure_state_db()

    last_ts = int(get_meta("last_ts", "0"))

    try:
        snap_db = mirror_huorong_db()
    except Exception as e:
        append_log(f"错误：复制火绒数据库失败：{e}")
        return

    events, max_ts = read_new_events_from_snapshot(snap_db, last_ts)

    if events:
        update_state_with_events(events)
        set_meta("last_ts", str(max_ts))
        append_log(f"已导入 {len(events)} 条新事件，最大 ts={max_ts}")
    else:
        append_log("本轮未导入新事件（0）")

    decide_and_apply_bans()

    # 采集 DROP：先确保开启，再增量导入
    try:
        ensure_firewall_drop_logging()
        parse_firewall_drop_log_and_store()
    except Exception as e:
        append_log(f"DROP_LOG 处理异常：{e}")

    generate_report()
    append_log(f"已生成报表：{REPORT_HTML}")

def main():
    if not is_admin():
        print("请用【管理员】运行：需要创建/删除 Windows 防火墙规则。")
        sys.exit(1)

    # 轮询模式：一直跑
    acquire_lock()
    try:
        append_log(f"启动轮询：每 {POLL_SECONDS} 秒执行一次")
        while True:
            start = time.time()
            try:
                run_once()
            except Exception as e:
                append_log(f"ERROR: 本轮执行失败：{e}")

            elapsed = time.time() - start
            sleep_s = max(5, POLL_SECONDS - int(elapsed))
            append_log(f"等待下一轮：{sleep_s}s")
            time.sleep(sleep_s)
    finally:
        release_lock()

if __name__ == "__main__":
    main()
