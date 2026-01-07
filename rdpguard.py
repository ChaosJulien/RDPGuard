# RDPGuard - RDP 爆破检测与自动封禁工具
# 作者: ChaosJulien
# 
# ⚠️ 免责声明: 本工具可能修改系统防火墙规则，存在误封风险。
#    请在测试环境充分验证后再用于生产。作者不承担任何使用后果。
# 
# License: MIT

"""
RDPGuard (rewritten)
- Read Huorong log.db snapshots
- Extract RDP brute-force (fname=rlogin, detection=RDP)
- Persist events/stats/bans in state.db
- Auto block via Windows Firewall
  * Permanent bans: ONE aggregated rule (fast)
  * Temporary bans: per-IP rules (auto unban when expired)
- Generate report.html (+ optional charts if matplotlib installed)

Run as Administrator.
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
# Config (edit if needed)
# =========================

# Huorong DB (confirmed in your environment)
HUORONG_DIR = Path(r"C:\ProgramData\Huorong\Sysdiag")
LOG_DB = HUORONG_DIR / "log.db"
LOG_DB_WAL = HUORONG_DIR / "log.db-wal"
LOG_DB_SHM = HUORONG_DIR / "log.db-shm"
HUORONG_TABLE = "HrLogV3_60"  # your table

# RDPGuard working dir
BASE = Path(r"C:\ProgramData\RDPGuard")
STATE_DB = BASE / "state.db"
LOG_FILE = BASE / "rdpguard.log"
REPORT_HTML = BASE / "report.html"
CHART_TOP = BASE / "top_ips.png"
CHART_DAILY = BASE / "daily_hits.png"
SNAP_DIR = BASE / "snapshots"

# Firewall naming
RULE_PREFIX_TEMP = "RDPGuard"  # per-IP temporary rules: "RDPGuard <ip>"
RULE_POOL_NAME = "RDPGuard-Blocked-IP-Pool"  # aggregated permanent ban rule

# Retention
EVENT_RETENTION_DAYS = 30  # keep events in state.db for last N days

# Ban policy
THRESH_10M = 5
BAN_10M_HOURS = 24

THRESH_1D = 20
BAN_1D_DAYS = 7

THRESH_TOTAL = 100  # permanent ban threshold

# Parsing helpers
RE_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")

# =========================
# Utilities
# =========================

def now_ts() -> int:
    return int(time.time())

def ts_to_local_str(ts: int) -> str:
    return datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")

def ensure_dirs():
    BASE.mkdir(parents=True, exist_ok=True)
    SNAP_DIR.mkdir(parents=True, exist_ok=True)

def append_log(msg: str):
    ensure_dirs()
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n"
    try:
        with open(LOG_FILE, "a", encoding="utf-8", errors="ignore") as f:
            f.write(line)
    except Exception:
        pass
    print(msg)

def is_admin() -> bool:
    # net session requires admin
    p = subprocess.run(["powershell", "-NoProfile", "-Command", "net session"],
                       capture_output=True, text=True)
    return p.returncode == 0

def run_ps(cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True)

# =========================
# DB: state.db
# =========================

def ensure_state_db():
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

    # bans table records both temp and permanent
    # expires_at NULL means permanent
    # kind: 'temp' or 'perm'
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

    conn.commit()
    conn.close()

def get_meta(k: str, default: str = "0") -> str:
    conn = sqlite3.connect(str(STATE_DB))
    cur = conn.cursor()
    cur.execute("SELECT v FROM meta WHERE k=?", (k,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else default

def set_meta(k: str, v: str):
    conn = sqlite3.connect(str(STATE_DB))
    cur = conn.cursor()
    cur.execute("INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))
    conn.commit()
    conn.close()

def update_state_with_events(events):
    """
    events: list[(ts:int, ip:str)]
    - insert events
    - update stats
    - cleanup old events beyond retention
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

    # cleanup
    keep_from = now_ts() - EVENT_RETENTION_DAYS * 86400
    cur.execute("DELETE FROM events WHERE ts < ?", (keep_from,))

    conn.commit()
    conn.close()

# =========================
# Huorong snapshot read
# =========================

def mirror_huorong_db() -> Path:
    """
    Copy log.db (+ wal/shm if exists) to snapshot folder to avoid lock/disk I/O error.
    Returns snapshot log.db path.
    """
    if not LOG_DB.exists():
        raise FileNotFoundError(str(LOG_DB))

    ensure_dirs()
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
    Return set[str] of attacker IPs.
    Preferred: json.loads on detail (Huorong stores JSON with double quotes)
    Fallback: regex scan if it looks like detection=RDP.
    """
    ips = set()
    if not detail:
        return ips
    s = str(detail).strip()

    # JSON path (most common in your samples)
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

    # Fallback (rare)
    if ("detection" not in s) or ("RDP" not in s):
        return set()
    # reduce false positives
    if '"detection":"RDP"' not in s and "'detection':'RDP'" not in s and "detection\":\"RDP" not in s:
        return set()

    for ip in RE_IP.findall(s):
        ips.add(ip)
    return ips

def read_new_events_from_snapshot(snapshot_db: Path, last_ts: int):
    """
    Incremental ingest: ts > last_ts, fname='rlogin'
    Return (events, max_ts_seen)
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
# Firewall operations
# =========================

def fw_rule_exists(display_name: str) -> bool:
    p = run_ps(f"Get-NetFirewallRule -DisplayName '{display_name}' -ErrorAction SilentlyContinue | Select -First 1")
    return bool(p.stdout.strip())

def fw_remove_rule(display_name: str) -> bool:
    p = run_ps(f"Get-NetFirewallRule -DisplayName '{display_name}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule")
    return p.returncode == 0

def fw_create_block_rule_single_ip(ip: str, display_name: str) -> bool:
    # Block inbound from remote IP
    cmd = (
        f"New-NetFirewallRule -DisplayName '{display_name}' "
        f"-Direction Inbound -Action Block -RemoteAddress {ip} -Profile Any"
    )
    p = run_ps(cmd)
    return p.returncode == 0

def fw_upsert_permanent_pool_rule(ips):
    """
    Create or update ONE aggregated rule:
      DisplayName: RDPGuard-Blocked-IP-Pool
      RemoteAddress: ip1,ip2,...
    This is the key optimization.
    """
    # Firewall limits exist; for very large lists you may need multiple pool rules.
    # In practice, this still handles hundreds/thousands well; if it fails we split.
    ips = sorted(set(ips))
    if not ips:
        return True

    # try one rule
    remote = ",".join(ips)
    if not fw_rule_exists(RULE_POOL_NAME):
        cmd = (
            f"New-NetFirewallRule -DisplayName '{RULE_POOL_NAME}' "
            f"-Direction Inbound -Action Block -RemoteAddress {remote} -Profile Any"
        )
        p = run_ps(cmd)
        if p.returncode == 0:
            return True
    else:
        # update existing rule
        cmd = f"Set-NetFirewallRule -DisplayName '{RULE_POOL_NAME}' -RemoteAddress {remote}"
        p = run_ps(cmd)
        if p.returncode == 0:
            return True

    # fallback: split into chunks if one rule is too big
    # We create multiple rules: RDPGuard-Blocked-IP-Pool-1, -2, ...
    # First remove original pool if exists to avoid confusion.
    if fw_rule_exists(RULE_POOL_NAME):
        fw_remove_rule(RULE_POOL_NAME)

    chunk_size = 500  # conservative
    ok_all = True
    for i in range(0, len(ips), chunk_size):
        chunk = ips[i:i+chunk_size]
        name = f"{RULE_POOL_NAME}-{(i//chunk_size)+1}"
        remote = ",".join(chunk)
        if fw_rule_exists(name):
            p = run_ps(f"Set-NetFirewallRule -DisplayName '{name}' -RemoteAddress {remote}")
        else:
            p = run_ps(
                f"New-NetFirewallRule -DisplayName '{name}' -Direction Inbound -Action Block "
                f"-RemoteAddress {remote} -Profile Any"
            )
        if p.returncode != 0:
            ok_all = False
    return ok_all

# =========================
# Ban decision engine
# =========================

def decide_and_apply_bans():
    """
    - Unban expired temp rules
    - Compute windows counts (10m/1d) from events
    - Permanent bans based on stats.hits_total >= THRESH_TOTAL
      -> aggregated firewall pool rule(s), record in bans(kind='perm')
    - Temporary bans based on windows thresholds for IPs not permanently banned
      -> per-IP firewall rules, record in bans(kind='temp')
    """
    now = now_ts()
    t10 = now - 10 * 60
    t1d = now - 24 * 3600

    conn = sqlite3.connect(str(STATE_DB))
    cur = conn.cursor()

    # 1) Unban expired temp bans
    cur.execute("""
      SELECT ip, rule_name FROM bans
      WHERE kind='temp' AND expires_at IS NOT NULL AND expires_at <= ?
    """, (now,))
    expired = cur.fetchall()
    for ip, rule_name in expired:
        fw_remove_rule(rule_name)
        append_log(f"UNBAN {ip} (expired)")
        cur.execute("DELETE FROM bans WHERE ip=?", (ip,))

    # 2) Compute window hits for last 24h (10m / 1d)
    cur.execute("""
      SELECT ip,
             SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END) AS hits_10m,
             SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END) AS hits_1d
      FROM events
      WHERE ts >= ?
      GROUP BY ip
    """, (t10, t1d, t1d))
    window = {ip: (h10 or 0, h1d or 0) for ip, h10, h1d in cur.fetchall()}

    # 3) Total hits
    cur.execute("SELECT ip, hits_total FROM stats")
    totals = {ip: (hits_total or 0) for ip, hits_total in cur.fetchall()}

    # 4) Current bans
    cur.execute("SELECT ip, kind FROM bans")
    banned_map = {ip: kind for ip, kind in cur.fetchall()}

    # ---- Permanent ban set ----
    perm_ips = [ip for ip, total in totals.items() if total >= THRESH_TOTAL]
    # Apply aggregated firewall rule(s)
    if perm_ips:
        ok = fw_upsert_permanent_pool_rule(perm_ips)
        if ok:
            # record them in bans(kind='perm')
            for ip in perm_ips:
                if banned_map.get(ip) == "perm":
                    continue
                # for permanent bans we do not create per-ip rule; rule_name stores pool name
                cur.execute("""
                  INSERT OR REPLACE INTO bans(ip, rule_name, kind, banned_at, expires_at, reason)
                  VALUES (?,?,?,?,?,?)
                """, (ip, RULE_POOL_NAME, "perm", now, None, f"total>={THRESH_TOTAL}"))
            append_log(f"PERM_POOL updated, perm_ips={len(perm_ips)}")
        else:
            append_log("ERROR: failed to update permanent pool rule(s)")

    # ---- Temporary bans (only for not permanently banned) ----
    new_temp = []
    for ip, total in totals.items():
        if total >= THRESH_TOTAL:
            continue  # perm already
        if ip in banned_map:
            continue  # already banned (temp)

        h10, h1d = window.get(ip, (0, 0))
        reason = None
        expires_at = None

        if h1d >= THRESH_1D:
            reason = f"1d>={THRESH_1D}"
            expires_at = now + BAN_1D_DAYS * 86400
        elif h10 >= THRESH_10M:
            reason = f"10m>={THRESH_10M}"
            expires_at = now + BAN_10M_HOURS * 3600

        if reason:
            rule_name = f"{RULE_PREFIX_TEMP} {ip}"
            new_temp.append((ip, rule_name, now, expires_at, reason))

    # Apply temp bans per IP (limited batch to avoid long runs)
    # You can increase this if you want.
    max_apply = 200
    applied = 0
    for ip, rule_name, banned_at, expires_at, reason in new_temp:
        if applied >= max_apply:
            break
        if not fw_rule_exists(rule_name):
            ok = fw_create_block_rule_single_ip(ip, rule_name)
            if not ok:
                append_log(f"TEMP BAN FAIL {ip} ({reason})")
                continue

        cur.execute("""
          INSERT OR REPLACE INTO bans(ip, rule_name, kind, banned_at, expires_at, reason)
          VALUES (?,?,?,?,?,?)
        """, (ip, rule_name, "temp", banned_at, expires_at, reason))

        if expires_at:
            append_log(f"TEMP BAN {ip} ({reason}) until {ts_to_local_str(expires_at)}")
        else:
            append_log(f"TEMP BAN {ip} ({reason})")
        applied += 1

    conn.commit()
    conn.close()

# =========================
# Report
# =========================

def generate_report():
    conn = sqlite3.connect(str(STATE_DB))
    cur = conn.cursor()

    # top 20
    cur.execute("""
      SELECT ip, hits_total, first_seen, last_seen
      FROM stats
      ORDER BY hits_total DESC
      LIMIT 20
    """)
    top = cur.fetchall()

    # bans (recent 200)
    cur.execute("""
      SELECT ip, kind, reason, banned_at, expires_at
      FROM bans
      ORDER BY banned_at DESC
      LIMIT 200
    """)
    bans = cur.fetchall()

    # daily hits (retention window)
    now = now_ts()
    from_ts = now - EVENT_RETENTION_DAYS * 86400
    cur.execute("""
      SELECT date(datetime(ts,'unixepoch','localtime')) AS day, COUNT(*) AS hits
      FROM events
      WHERE ts >= ?
      GROUP BY day
      ORDER BY day ASC
    """, (from_ts,))
    daily = cur.fetchall()

    conn.close()

    # optional charts
    plt = None
    try:
        import matplotlib.pyplot as plt  # type: ignore
    except Exception:
        plt = None

    if plt:
        # Top IP barh
        ips = [r[0] for r in top][::-1]
        hits = [r[1] for r in top][::-1]
        plt.figure(figsize=(10, 6))
        plt.barh(ips, hits)
        plt.xlabel("hits_total")
        plt.tight_layout()
        plt.savefig(str(CHART_TOP), dpi=160)
        plt.close()

        # Daily line
        days = [r[0] for r in daily]
        dh = [r[1] for r in daily]
        plt.figure(figsize=(10, 4))
        plt.plot(days, dh, marker="o")
        plt.xticks(rotation=30, ha="right")
        plt.ylabel("hits")
        plt.tight_layout()
        plt.savefig(str(CHART_DAILY), dpi=160)
        plt.close()

    def fmt_ts(x):
        if x is None:
            return "-"
        return ts_to_local_str(int(x))

    top_rows = "\n".join(
        f"<tr><td>{ip}</td><td>{hits}</td><td>{fmt_ts(fs)}</td><td>{fmt_ts(ls)}</td></tr>"
        for ip, hits, fs, ls in top
    )

    ban_rows = "\n".join(
        f"<tr><td>{ip}</td><td>{kind}</td><td>{reason}</td><td>{fmt_ts(bat)}</td><td>{fmt_ts(exp)}</td></tr>"
        for ip, kind, reason, bat, exp in bans
    )

    html = f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>RDPGuard Report</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:20px;background:#0b0f14;color:#e6edf3}}
h1,h2{{margin:0.4em 0}}
.card{{background:#111826;border:1px solid #223049;border-radius:12px;padding:16px;margin:12px 0}}
table{{width:100%;border-collapse:collapse}}
th,td{{border-bottom:1px solid #223049;padding:8px;text-align:left;font-size:14px}}
.small{{opacity:.8;font-size:13px}}
img{{max-width:100%;border-radius:10px;border:1px solid #223049;background:#0b0f14}}
.code{{font-family:Consolas,monospace}}
</style>
</head>
<body>
<h1>RDPGuard 面板</h1>
<div class="small">更新时间：{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>

<div class="card">
  <h2>永久封禁聚合规则</h2>
  <div class="small">规则名：<span class="code">{RULE_POOL_NAME}</span>（如过大将自动拆分为 -1/-2/...）</div>
</div>

<div class="card">
  <h2>Top IP（累计命中）</h2>
  {"<img src='top_ips.png' alt='top'/>" if CHART_TOP.exists() else "<div class='small'>未生成图表（可能未安装 matplotlib）</div>"}
  <table>
    <thead><tr><th>IP</th><th>hits_total</th><th>first_seen</th><th>last_seen</th></tr></thead>
    <tbody>{top_rows}</tbody>
  </table>
</div>

<div class="card">
  <h2>每日命中（近 {EVENT_RETENTION_DAYS} 天）</h2>
  {"<img src='daily_hits.png' alt='daily'/>" if CHART_DAILY.exists() else "<div class='small'>未生成图表（可能未安装 matplotlib）</div>"}
</div>

<div class="card">
  <h2>当前封禁（数据库记录）</h2>
  <table>
    <thead><tr><th>IP</th><th>kind</th><th>reason</th><th>banned_at</th><th>expires_at</th></tr></thead>
    <tbody>{ban_rows}</tbody>
  </table>
</div>

<div class="small">日志：{LOG_FILE}</div>
</body>
</html>
"""
    REPORT_HTML.write_text(html, encoding="utf-8", errors="ignore")

# =========================
# Main
# =========================

def main():
    if not is_admin():
        print("请用【管理员】运行：需要创建/删除 Windows 防火墙规则。")
        sys.exit(1)

    ensure_state_db()

    # Incremental cursor
    last_ts = int(get_meta("last_ts", "0"))

    # Mirror Huorong DB
    try:
        snap_db = mirror_huorong_db()
    except Exception as e:
        append_log(f"ERROR: mirror huorong db failed: {e}")
        return

    # Ingest new events
    events, max_ts = read_new_events_from_snapshot(snap_db, last_ts)

    if events:
        update_state_with_events(events)
        set_meta("last_ts", str(max_ts))
        append_log(f"INGEST {len(events)} new events, ts <= {max_ts}")
    else:
        append_log("INGEST 0 new events")

    # Apply bans
    decide_and_apply_bans()

    # Report
    generate_report()
    append_log(f"REPORT {REPORT_HTML}")

if __name__ == "__main__":
    main()
