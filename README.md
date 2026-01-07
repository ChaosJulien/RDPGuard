# RDPGuard

Windows RDP 爆破检测 · 自动封禁（Windows 防火墙）· 攻击取证 · 云/IDC 归属打标 & 批量举报辅助工具

<!-- PROJECT SHIELDS -->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
<br />

<p align="center">
  <a href="https://github.com/ChaosJulien/RDPGuard">
  </a>

  <h3 align="center">RDPGuard</h3>
  <p align="center">
    从火绒日志提取 RDP 攻击 → 统计留痕 → 自动下发 Windows 防火墙封禁 → 输出报告 → 结合 IP-Data 将攻击 IP 按云厂商/IDC 打标并导出举报材料
    <br />
    <a href="https://github.com/ChaosJulien/RDPGuard"><strong>探索本项目文档 »</strong></a>
    <br />
    <br />
    <a href="https://github.com/ChaosJulien/RDPGuard">查看代码</a>
    ·
    <a href="https://github.com/ChaosJulien/RDPGuard/issues">报告 Bug</a>
    ·
    <a href="https://github.com/ChaosJulien/RDPGuard/issues">提出新特性</a>
  </p>
</p>

> 本项目面向防御与取证：不主动扫描、不反制，仅处理本机安全日志与本机防火墙策略。  
> 适用：公网 Windows 主机、暴露 RDP/3389 的环境、需要长期留痕与合规举报的场景。

---

## 目录（更新后）
- [上手指南](#上手指南)
  - [开发前的配置要求](#开发前的配置要求)
  - [安装步骤](#安装步骤)
  - [快速运行](#快速运行)
- [功能概览](#功能概览)
- [工作原理](#工作原理)
- [文件目录说明](#文件目录说明)
- [配置说明](#配置说明)
- [部署与自启动](#部署与自启动)
- [取证与查询](#取证与查询)
- [云/IDC 归属打标（IP-Data）](#云idc-归属打标ip-data)
- [常见问题](#常见问题)
- [贡献者](#贡献者)
  - [如何参与开源项目](#如何参与开源项目)
- [作者](#作者)
- [安全与法律声明](#安全与法律声明)
- [鸣谢](#鸣谢)
- [版本控制（可选）](#版本控制)

---

## 上手指南

### 开发前的配置要求

1. Windows 10 / Windows Server（建议 Server）
2. 已安装 **火绒安全**（用于生成拦截/检测日志）
3. Python 3.9+（建议 3.11/3.12）
4. 需要 **管理员权限**（创建/更新/删除 Windows 防火墙规则）
5. 可选：matplotlib（用于生成图表，不装也能运行）

> 注意：火绒日志库文件可能会被占用，RDPGuard 会采用 “snapshot 快照复制” 方式读取，以规避 `disk I/O error`。

---

### 安装步骤

1. Clone 仓库

```bash
git clone https://github.com/ChaosJulien/RDPGuard.git
cd RDPGuard
```

2. 安装依赖

```bash
pip install -r requirements.txt
```

3. 以管理员方式运行 PowerShell / CMD，然后执行

```bash
python rdpguard.py
```

---

### 快速运行

运行后会生成：

* 运行日志：`C:\ProgramData\RDPGuard\rdpguard.log`
* 状态库：`C:\ProgramData\RDPGuard\state.db`
* 报告面板：`C:\ProgramData\RDPGuard\report.html`
* 快照目录：`C:\ProgramData\RDPGuard\snapshots\YYYYMMDD_HHMMSS\`

---

## 功能概览

* ✅ 从火绒数据库（`log.db`）解析 RDP 爆破事件（`fname=rlogin & detection=RDP`）
* ✅ 增量采集（`last_ts` 游标）
* ✅ 事件持久化（SQLite `state.db`）
* ✅ 统计维度：IP 首次/最近出现时间、累计命中次数、时间窗口命中（10m/1d/total）
* ✅ 自动下发 Windows 防火墙封禁规则（Block Inbound）

  * 永久封禁：**聚合规则（推荐）**，避免“一 IP 一条规则”导致执行极慢
  * 临时封禁：单 IP 单规则，便于到期解封与审计
* ✅ 可视化报告（HTML + 可选图表）
* ✅ 结合 IP-Data：把攻击 IP **按国内云/IDC 厂商归属打标**，导出 CSV，用于批量举报

---

## 工作原理

1. **读取源**
   火绒日志库通常位于：`C:\ProgramData\Huorong\Sysdiag\log.db`

2. **快照镜像**
   复制 `log.db`（以及 `-wal/-shm`）到快照目录，避免读取时被锁导致 I/O 错误

3. **事件抽取**
   从表（如 `HrLogV3_60`）读取 `fname='rlogin'` 且 `detail` 中 `detection=RDP` 的记录
   从 `detail` JSON 中提取 `raddr` 与 `rdata.raddr[]`

4. **持久化 & 统计**
   写入 `state.db`：

   * `events(ts, ip)`：事件流水（用于窗口统计、报表）
   * `stats(ip, first_seen, last_seen, hits_total)`：累计统计
   * `bans(ip, kind, reason, expires_at, ...)`：封禁记录（临时/永久）

5. **封禁策略**（可配置）

   * 10 分钟命中 ≥ N → 临时封禁
   * 24 小时命中 ≥ M → 中期封禁
   * 累计命中 ≥ K → 永久封禁（聚合规则）

6. **输出报告**
   生成 `report.html`（+可选图表）

---

## 文件目录说明

建议仓库结构如下（示例）：

```text
RDPGuard/
├── rdpguard.py
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
└── tools/
    ├── export_last30d.py          #（可选）导出近30天攻击IP
    └── tag_cloud_idc.py           #（可选）CIDR 归属打标脚本
```

运行时生成的数据位于：

```text
C:\ProgramData\RDPGuard\
├── state.db
├── rdpguard.log
├── report.html
├── top_ips.png           # 可选
├── daily_hits.png         # 可选
└── snapshots\
    └── 20260107_225131\
        ├── log.db
        ├── log.db-wal     # 可选
        └── log.db-shm     # 可选
```

---

## 配置说明

在 `rdpguard.py` 顶部可配置：

* 火绒日志路径（Huorong Sysdiag）
* `HUORONG_TABLE`（默认 `HrLogV3_60`）
* 事件保留天数（默认 30 天）
* 封禁阈值/时长（10m/1d/total）
* 防火墙规则命名（聚合规则名、临时规则前缀）

建议：

* 永久封禁使用聚合规则，减少规则数量，提高执行速度与系统稳定性
* 临时封禁用于短期高频爆破（便于自动解封）

---

## 部署与自启动

### 方式 1：任务计划程序（推荐）

1. 打开「任务计划程序」
2. 创建任务（不是“基本任务”）
3. 常规：

   * ✅ 使用最高权限运行（必须）
4. 触发器：

   * 每 5 分钟 / 每 10 分钟运行一次（按你的压力调整）
5. 操作：

   * 程序/脚本：`python`
   * 参数：`C:\path\to\rdpguard.py`
   * 起始于：脚本所在目录

---

## 取证与查询

### 1）查询某个 IP 是否攻击过（以 state.db 为准）

```sql
SELECT
  ip,
  COUNT(*) AS hits,
  datetime(MIN(ts), 'unixepoch', 'localtime') AS first_seen,
  datetime(MAX(ts), 'unixepoch', 'localtime') AS last_seen
FROM events
WHERE ip = '43.157.168.79'
GROUP BY ip;
```

### 2）导出近 30 天攻击 IP（示例）

```sql
SELECT
  ip,
  COUNT(*) AS hits_30d,
  datetime(MIN(ts), 'unixepoch', 'localtime') AS first_seen,
  datetime(MAX(ts), 'unixepoch', 'localtime') AS last_seen
FROM events
WHERE ts >= strftime('%s','now') - 30*86400
GROUP BY ip
ORDER BY hits_30d DESC;
```

> 说明：如果你要“严格近 30 天且完整”，也可以直接对火绒快照库查询（更权威但更慢）。

---

## 云/IDC 归属打标（IP-Data）

为了把攻击 IP **按云厂商/IDC 归属**批量分类并导出举报材料，本项目建议使用 **IP-Data** 维护的云/IDC CIDR 列表。

### IP-Data 能解决什么问题？

* 判断一个攻击 IP 是否来自云/IDC（更可能是肉鸡/云主机）
* 按厂商分组（阿里云 / 腾讯云 / 华为云 / 京东云 / UCloud / 金山云…）
* 导出 CSV → 批量提交安全举报工单（更高效率）

### 推荐目录结构（与你当前放置方式兼容）

```text
example/
├─ last30d_attack_ips.csv
└─ provider/
   ├─ aliyun-cidr-ipv4.txt
   ├─ tencent-cidr-ipv4.txt
   ├─ huawei-cidr-ipv4.txt
   ├─ jdcloud-cidr-ipv4.txt
   ├─ ucloud-cidr-ipv4.txt
   ├─ ksyun-cidr-ipv4.txt
   ├─ baidu-cidr-ipv4.txt
   ├─ all-cidr-ipv4.txt
   └─ ...（可选：aws/azure/gcp/oracle/...）
```

### 建议输出（举报最省事）

* `last30d_tagged.csv`：总表（含 provider 标签）
* `reports/aliyun.csv`、`reports/tencent.csv`…：按厂商拆分的举报清单

你可以直接把 `reports/aliyun.csv` 当作阿里云工单附件，把 `reports/tencent.csv` 当作腾讯云工单附件。

---

## 常见问题

### Q1：为什么直接读取火绒 log.db 会报 `disk I/O error`？

A：火绒可能占用数据库并写入 WAL。RDPGuard 通过快照复制读取，避免锁与 I/O 冲突。

### Q2：为什么封禁很慢，BAN 一秒一个？

A：如果“一 IP 一条规则”，系统会很慢。推荐使用“永久封禁聚合规则”（一个规则承载多个 IP），速度会快很多。

---

## 贡献者

欢迎贡献！你可以通过 Fork 的方式参与：

### 如何参与开源项目

1. Fork 本项目
2. 新建分支开发你的功能/修复 (`git checkout -b feature/xxxx`)
3. 提交更改 (`git commit -m 'Add xxxx'`)
4. 推送到你的 Fork (`git push origin feature/xxxx`)
5. 在 GitHub 发起 Pull Request

> 如果你提交的是安全相关增强（例如规则聚合、解析兼容、性能优化、报告增强），我会优先合并。

---

## 作者

**ChaosJulien**（在读大学生）
联系邮箱：**[chaosjulien@qq.com](mailto:chaosjulien@qq.com)**

如果你在使用中遇到：

* 规则生成异常
* 火绒日志解析兼容问题
* 云/IDC 归属打标需求
* 想要适配其他安全产品日志

欢迎通过 Issue 或邮件联系我。

---

## 安全与法律声明

### 🔒 安全声明
- 本工具**仅读取本地火绒日志**，**仅修改本机 Windows 防火墙规则**。
- **不会**外连任何服务器（除可选手动举报外）。
- **不会**扫描、探测、反制任何远程主机。
- 所有数据（日志、数据库、报告）均存储于 `C:\ProgramData\RDPGuard\`，默认对普通用户不可见。

### ⚠️ 免责声明
本工具（RDPGuard）按“**现状**”（AS IS）提供，作者 **ChaosJulien** 不对其适用性、可靠性、安全性或任何其他方面作出明示或暗示的保证。
- 使用本工具可能**修改您的 Windows 防火墙规则**，存在**误封合法 IP** 的风险，请务必在测试环境中验证后再部署到生产环境。
- 封禁策略基于火绒日志解析，若火绒日志格式变更，可能导致**解析失败或漏报**。
- 作者**不对因使用本工具造成的任何直接或间接损失**（包括但不限于服务中断、数据丢失、业务影响）承担责任。
- 请勿将本工具用于非法目的。使用者须自行确保其行为符合所在国家/地区的法律法规。
> **使用即表示您已理解并接受上述风险。**

### 版权说明
本项目采用 **MIT License** 开源授权。  
完整许可证内容请参阅：[LICENSE](https://github.com/ChaosJulien/RDPGuard/blob/main/LICENSE)

---

## 鸣谢

* [Shields.io](https://shields.io)
* [Choose an Open Source License](https://choosealicense.com)
* Windows Firewall / PowerShell Cmdlets 文档
* [IP 段数据集：IP-Data（云/IDC CIDR 列表维护项目）](https://github.com/axpwx/IP-Data)

---

<!-- links -->

[contributors-shield]: https://img.shields.io/github/contributors/ChaosJulien/RDPGuard.svg?style=flat-square
[contributors-url]: https://github.com/ChaosJulien/RDPGuard/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/ChaosJulien/RDPGuard.svg?style=flat-square
[forks-url]: https://github.com/ChaosJulien/RDPGuard/network/members
[stars-shield]: https://img.shields.io/github/stars/ChaosJulien/RDPGuard.svg?style=flat-square
[stars-url]: https://github.com/ChaosJulien/RDPGuard/stargazers
[issues-shield]: https://img.shields.io/github/issues/ChaosJulien/RDPGuard.svg?style=flat-square
[issues-url]: https://github.com/ChaosJulien/RDPGuard/issues
[license-shield]: https://img.shields.io/github/license/ChaosJulien/RDPGuard.svg?style=flat-square
[license-url]: https://github.com/ChaosJulien/RDPGuard/blob/main/LICENSE