# Banner 指纹识别系统 — 需求拆解与实施计划（plan.md）

> 版本：v1.0　日期：2026-10-14
> 状态：需求已澄清（4 项关键决策已确认），待评审后进入开发
> 本文档只做需求拆解、架构设计与计划，不包含实现代码。

---

## 0. 项目一句话定义

用 Golang 开发一套 **Banner 指纹识别系统**：接收一批网络扫描原始数据（`ip`、`port`、`banner`），离线解析出 `protocol` / `product` / `version` / `os_hint` / `confidence`，以 **client + server** 架构交付，**Docker Compose 一键启动**。

已确认的 4 项范围决策（来自需求澄清 QA）：

| # | 决策点 | 结论 |
|---|--------|------|
| D1 | Banner 获取方式 | **纯离线解析**：只解析传入的 banner，不向任何目标发起网络连接 |
| D2 | client 形态 | **CLI 客户端 + server REST API**（无 Web UI） |
| D3 | 协议覆盖范围 | **核心协议 + 常见扩展，约 18 种**（见 §2.2） |
| D4 | 结果存储 | **无状态**：内存处理、直接返回，不落库、不做历史查询 |

---

## 1. 需求拆解

### 1.1 功能需求（FR）

| 编号 | 需求 | 说明 | 优先级 |
|------|------|------|--------|
| FR-1 | 批量数据接收 | server 提供 HTTP API，接收一批 `{ip, port, banner}` 记录；client 从文件/stdin 读取并提交 | P0 |
| FR-2 | 多输入格式 | 支持 JSON 数组、JSONL、CSV 三种输入；banner 支持纯文本、转义文本、Base64、Hex 自动/显式解码 | P0 |
| FR-3 | 协议识别 | 基于 banner 内容特征为主、端口先验为辅，判定 `protocol` | P0 |
| FR-4 | 产品识别 | 在协议确定后识别软件产品（如 OpenSSH、nginx、Apache、MySQL、Redis、ProFTPD、Jetty） | P0 |
| FR-5 | 版本提取 | 尽可能提取精确版本号字符串（如 `8.9p1`、`1.24.0`、`2.4.57`、`8.0.32`、`1.3.7`、`9.4.51`） | P0 |
| FR-6 | OS 提示 | 从 banner 中提取操作系统线索（如 SSH 软件串里的 `Ubuntu-3ubuntu0.4` → `Ubuntu`），无则为空串 | P0 |
| FR-7 | 置信度输出 | 每条记录输出 `confidence`（0.00–1.00，两位小数），按证据分层评分 | P0 |
| FR-8 | 纠错兜底 | 无法识别的记录不报错、不中断整批：`protocol` 尽力给出（端口推断或 `unknown`），product/version/os_hint 输出空串，低置信度 | P0 |
| FR-9 | 顺序与一致性 | 输出顺序与输入顺序严格一致；字段名、类型、缺失值表示与验收示例完全一致 | P0 |
| FR-10 | 侦察接口 | 提供 `/healthz`、`/readyz`、以及返回支持协议清单/规则数量的元信息接口（便于验收与调试） | P1 |
| FR-11 | 外置规则覆盖 | 内置规则编译进二进制；支持挂载外置规则文件覆盖/扩展（不改代码即可加规则） | P2 |

### 1.2 输出规格（验收对齐）

| 字段 | 类型 | 缺失时 | 说明 |
|------|------|--------|------|
| `ip` | string | 不可缺失 | 原样回显（支持 IPv4/IPv6） |
| `port` | int | 不可缺失 | 1–65535 |
| `protocol` | string | `"unknown"` | 协议名，大写风格：`SSH` / `HTTP` / `MySQL` / `Redis` / `FTP` … |
| `product` | string | `""` | 软件官方命名风格：`OpenSSH` / `nginx` / `Apache` / `MySQL` / `Redis` / `ProFTPD` / `Jetty` |
| `version` | string | `""` | 精确版本串，原样保留（含 `p1`、`Ubuntu-3ubuntu0.4` 前段等处理见规则说明） |
| `os_hint` | string | `""` | `Ubuntu` / `Debian` / `CentOS` / `Windows` / `FreeBSD` 等 |
| `confidence` | float | 不可缺失 | 0.00–1.00，两位小数 |

**两个必须写入实现的验收口径（源自示例）：**
1. 示例中 **443 端口记录的 `protocol` 是 `HTTP` 而非 `HTTPS`** —— 因此 TLS 上的 HTTP 统一输出 `HTTP`，不做 HTTPS 区分（版本/OS 仍从明文 HTTP 响应头提取）。
2. 缺失值用 **空字符串**（如 Redis 的 `"version":""`、nginx 的 `"os_hint":""`），**不是 `null`**。

### 1.3 识别深度要求（验收基线）

题目要求"识别深度至少达到示例所示"，即：

- 示例覆盖的 7 类协议（SSH / HTTP×3 / MySQL / Redis / FTP）**必须**给出 `protocol` + `product`；
- banner 中携带版本信息的（除 Redis 示例外）**必须**给出 `version`；
- SSH **必须**给出 `os_hint`；
- `confidence` 数值以示例为**校准锚点**，允许 ±0.05 偏差（示例锚点：0.95 / 0.9 / 0.9 / 0.9 / 0.7 / 0.9 / 0.85）。Redis 示例 product 有值而 version 为空、confidence 仅 0.7，说明"产品确认但版本缺失"应显著降分。

### 1.4 非功能需求（NFR）

| 编号 | 需求 | 目标值（默认假设，见 §10） |
|------|------|---------------------------|
| NFR-1 | 性能 | 单批 10 万条端到端 ≤ 10s（P95），单条识别 < 1ms 量级 |
| NFR-2 | 并发 | server 可并发处理多批请求；client 支持分片并发提交（默认 4 并发） |
| NFR-3 | 鲁棒性 | 畸形/截断/二进制/非 UTF-8 banner 不 panic、不 500，按 FR-8 降级 |
| NFR-4 | 零外联（安全） | 引擎与 server 不含任何对外网络拨号能力（无 `net.Dial` 到目标）；这是 D1 的硬约束，需可审计 |
| NFR-5 | 输入防护 | 请求体大小上限（默认 32MB）、单条 banner 上限（默认 64KB）、记录数上限（默认 20 万），可配置 |
| NFR-6 | 资源占用 | 镜像 < 50MB（alpine/distroless 静态二进制）；空闲内存 < 50MB；启动 < 2s |
| NFR-7 | 可观测性 | 结构化日志（JSON）、请求 ID 透传、访问日志；日志级别可配 |
| NFR-8 | 可测试性 | 引擎为无 IO 纯函数；每协议 ≥ 3 条 golden 语料（正/变体/负）；核心包单测覆盖 ≥ 80% |
| NFR-9 | 交付 | `docker compose` 一键启动 server；`docker compose run` 一键跑 CLI 示例；README 首屏即演示命令 |
| NFR-10 | 可移植 | linux/amd64 + arm64 镜像；CGO 关闭、静态编译 |

### 1.5 非目标（明确不做）

- ❌ 主动扫描 / 主动连接目标补采 banner（D1）
- ❌ Web UI、报表、图表（D2）
- ❌ 数据库、历史查询、统计接口（D4）
- ❌ 端口存活探测、漏洞检测、弱口令检测、爆破
- ❌ 认证/多租户（验收场景为内网单实例；若需要 API Token 见 §10-6）

---

## 2. 识别能力设计

### 2.1 协议支持清单（D3：约 18 种）

| 类别 | 协议 |
|------|------|
| 文本 Banner | SSH、FTP、SMTP、POP3、IMAP、Telnet、Redis |
| HTTP 家族 | HTTP（含 443 TLS 上的明文 HTTP 响应；按示例口径输出 `HTTP`）、Elasticsearch（HTTP + 特征头）、Docker API（HTTP + 特征头） |
| 二进制握手 | MySQL、PostgreSQL、MongoDB、SMB、VNC、RDP |
| 内存/中间件 | Memcached |
| 可选扩展（P2） | AMQP/RabbitMQ、LDAP |

端口先验表（辅助信号，非决定性）：21→FTP、22→SSH、23→Telnet、25/465/587→SMTP、80/8000/8080/8888→HTTP、443/8443→HTTP、110→POP3、143→IMAP、3306→MySQL、5432→PostgreSQL、6379→Redis、11211→Memcached、27017→MongoDB、9200→Elasticsearch、445→SMB、3389→RDP、5900→VNC、2375/2376→Docker API。

### 2.2 识别流水线（5 层）

```
banner 原始载荷
  → [1] 解码层    转义/Base64/Hex/原生字节 → 规范化字节流 + 可见文本
  → [2] 协议判定  内容签名匹配(主) + 端口先验(辅) → 候选协议与得分
  → [3] 产品识别  命中协议的产品规则集（有序、首命中）→ product
  → [4] 版本/OS   规则捕获组 + 专项解析（SSH 软件串、Server 头等）→ version, os_hint
  → [5] 置信度    证据分层加权合成 → confidence
  → 输出记录（字段规格见 §1.2）
```

关键设计点：

- **内容优先于端口**：2222 上的 SSH 必须识别为 SSH；8080 上的非 HTTP 内容不得强行判 HTTP。端口仅在内容无信号时作候选与降级依据。
- **候选筛选加速**：先按首字节/端口把候选协议缩小到 1–3 个，再做完整规则匹配，保证 NFR-1。
- **每协议独立规则集**：规则文件按协议分文件（见 §4 结构），便于扩展与回归。
- **纯函数引擎**：`decode → probe → extract → score` 全程无 IO、无全局可变状态，方便单测与未来水平扩展。

### 2.3 规则模型（声明式）

每条规则包含：`协议 → 匹配方式（前缀/包含/正则/二进制偏移）→ 提取字段（product/version/os 的捕获组）→ 基础置信度权重 → 优先级`。
匹配按优先级有序、**首命中即定产品**，避免多规则互相覆盖；正则使用 Go 原生 RE2（无灾难性回溯风险）。
内置规则以 Go 数据结构编译进二进制，外置覆盖规则使用 YAML（唯一第三方依赖 `gopkg.in/yaml.v3`，见 §4.3）。

### 2.4 置信度模型（校准到示例锚点）

采用**证据分层加权**，分档如下（最终以示例 7 条为回归锚点，±0.05）：

| 证据层级 | 典型场景 | 置信度区间 | 示例锚点 |
|----------|----------|-----------|----------|
| 协议签名 + 产品签名 + 版本提取 + 端口一致 | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4` | 0.90–0.99 | SSH=0.95 |
| 协议签名 + 产品签名 + 版本提取 | nginx/Apache/MySQL/ProFTPD 版本可解析 | 0.85–0.95 | 0.90、Jetty=0.85 |
| 产品确认但版本缺失 | Redis 返回 `-NOAUTH`/`+PONG` 类响应 | 0.65–0.80 | Redis=0.70 |
| 仅协议签名（产品未知） | 仅 `HTTP/1.1 200 OK` 无 Server 头 | 0.60–0.75 | — |
| 仅端口推断 | 22 端口但 banner 为空 | 0.30–0.50 | — |
| 无任何信号 | 空 banner + 非常见端口 | 0.00（`protocol=unknown`） | — |

---

## 3. 接口契约

### 3.1 Server REST API

| 方法 | 路径 | 用途 |
|------|------|------|
| POST | `/api/v1/identify` | 批量识别（核心接口） |
| GET | `/healthz` | 存活探针（Compose healthcheck 用） |
| GET | `/readyz` | 就绪探针（规则加载完成后为就绪） |
| GET | `/api/v1/meta` | 版本、支持的协议清单、规则数量 |

**请求体（JSON，契约示例）**

```json
{
  "records": [
    {"ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"},
    {"ip": "1.2.3.5", "port": 80,  "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n..."},
    {"ip": "1.2.3.6", "port": 3306, "banner_base64": "3gAAAAo...", "encoding": "base64"}
  ],
  "options": {"include_evidence": false}
}
```

- `banner`：文本（可含转义字符）；二进制 payload 用 `banner_base64`；`encoding` 可为 `auto|text|base64|hex`（默认 auto）。
- `include_evidence: true` 时额外返回命中规则名等调试信息（默认关闭，保证验收输出纯净）。

**响应体（信封格式，`?output=array` 时直接返回裸数组）**

```json
{
  "results": [
    {"ip": "1.2.3.4", "port": 22, "protocol": "SSH", "product": "OpenSSH", "version": "8.9p1", "os_hint": "Ubuntu", "confidence": 0.95}
  ],
  "stats": {"total": 3, "identified": 2, "unknown": 0, "elapsed_ms": 12}
}
```

**错误模型**：`400`（参数错误，`errors[]` 定位到第 i 条记录）/ `413`（超限）/ `415`（不支持的编码）/ `500`（内部错误）。单条记录识别失败**不算**请求错误（FR-8）。

### 3.2 CLI（`bfp-cli`）

```
bfp-cli identify [flags]
  --server string        server 地址（env BFP_SERVER，默认 http://localhost:8080）
  --input  path|-        输入文件或 stdin（默认 -）
  --output path|-        输出文件或 stdout（默认 -）
  --in-format  auto|json|jsonl|csv     默认 auto（按扩展名+内容嗅探）
  --out-format array|json|jsonl|csv    默认 array（**裸数组，与验收示例完全同构**）
  --banner-encoding auto|text|base64|hex
  --batch-size N         默认 1000（分片提交）
  --concurrency N        默认 4
  --timeout duration     默认 30s
  --retry N              默认 2（仅网络错误/5xx 重试，指数退避）
  --fail-fast            首条失败即退出
  --quiet

bfp-cli ping        # 连通性检查（供 Compose healthcheck / 调试）
bfp-cli version
```

- **退出码约定**：`0` 全部成功；`1` 部分记录失败（未 fail-fast）；`2` 用法/参数错误；`3` server 不可达。
- CSV 输入规格：表头 `ip,port,banner`（表头可省略），banner 含逗号需加引号；输出 CSV 同构。
- 非 UTF-8 banner：CLI 自动转 Base64 提交，保证二进制安全。

### 3.3 数据一致性规约

- `results` 与输入记录 **1:1、同序**；
- `port` 为整数、`confidence` 为两位小数浮点；
- 缺失值一律空字符串（§1.2），不使用 `null`。

---

## 4. 项目基础结构（规范）

### 4.1 目录结构

```
.
├── cmd/
│   ├── bfp-server/main.go        # server 入口（仅装配：config → api → engine）
│   └── bfp-cli/main.go           # CLI 入口（仅装配：config → client）
├── internal/
│   ├── config/                   # 配置装载（flag + env：BFP_*），默认值集中管理
│   ├── api/                      # HTTP 层：router、handler、middleware（限流/限额/日志/请求ID）、DTO
│   ├── engine/                   # 识别引擎（纯函数、零 IO、可单测，不依赖 net/http）
│   │   ├── decode/               #   载荷解码（转义/Base64/Hex/字节规范化）
│   │   ├── probe/                #   协议候选判定（签名匹配 + 端口先验）
│   │   ├── rule/                 #   规则模型、编译、优先级调度
│   │   ├── extract/              #   product / version / os_hint 提取器
│   │   └── score/                #   置信度合成（§2.4 模型）
│   ├── rules/                    # 内置规则数据（按协议一文件：ssh.go、http.go、mysql.go…）
│   ├── model/                    # 领域模型：ScanRecord、FingerprintResult、JSON 序列化契约
│   ├── client/                   # CLI 逻辑：输入解析、分片并发、重试、输出渲染
│   └── version/                  # 版本与构建信息（ldflags 注入）
├── rules/                        # 外置规则（YAML，可选挂载覆盖，FR-11）
├── testdata/
│   ├── ssh/  http/  mysql/  redis/  ftp/  ...   # 每协议 golden 语料：input + expected.json
│   └── acceptance/               # 验收对拍样例（含题目示例同类数据）
├── deploy/
│   ├── docker-compose.yml
│   ├── server.Dockerfile
│   └── cli.Dockerfile
├── scripts/
│   ├── acceptance.sh             # 验收对拍：起服务 → 跑样例 → 与期望 JSON diff
│   └── gen-samples.sh            # 生成随机/边界样例数据
├── docs/
│   ├── api.md                    # API 契约（与 §3 同步）
│   └── rules.md                  # 规则编写指南（外置规则格式）
├── Makefile                      # build / test / lint / docker / demo / acceptance
├── go.mod  go.sum
├── README.md                     # 首屏：一键启动 + 验收命令 + 字段说明
└── plan.md                       # 本文档
```

### 4.2 命名与依赖规约

- **模块名**：`hsxa-banner-fingerprint`（可替换为实际仓库路径）；二进制名 `bfp-server` / `bfp-cli`。
- **依赖方向**（单向，不得回指）：`cmd → api | client → engine → model`；`engine` 禁止 import `net/http`、`config`、`client`。
- **Go 版本**：`go 1.26`（与本地 go1.26.5 及镜像 `golang:1.26-alpine` 对齐）。
- **第三方依赖最小化**：HTTP 路由用标准库 `net/http`（Go 1.22+ 增强路由）；JSON 用标准库；YAML 仅 `gopkg.in/yaml.v3` 一处（外置规则）；**不引入 Web 框架、不引入 ORM**。
- **代码质量门禁**：`gofmt` / `go vet` / `golangci-lint`（默认规则集）；核心包单测覆盖 ≥ 80%；提交前 `make check`。
- **错误处理规约**：错误包装用 `fmt.Errorf("...: %w", err)`；引擎层不使用 `panic`；所有导出 API 有 doc comment。

### 4.3 规则文件组织

- 内置规则：`internal/rules/<protocol>.go`，每文件导出一个规则集，注册到统一 registry；启动时编译正则（一次性）并构建端口索引。
- 外置规则：`rules/*.yaml`，字段为 `protocol / match(pattern, type) / product / version_group / os_group / weight / priority`；启动时加载，同名规则按"外置覆盖内置"合并；加载失败时 **fail-fast 拒绝启动**（避免带着坏规则上线），`/readyz` 在加载完成前返回 503。

---

## 5. 交付与部署

### 5.1 镜像策略

| 项 | server.Dockerfile | cli.Dockerfile |
|----|-------------------|----------------|
| 构建阶段 | `golang:1.26-alpine`，`CGO_ENABLED=0`，`-trimpath -ldflags "-s -w -X version..."` | 同左 |
| 运行阶段 | `alpine:3.20`，非 root 用户，只读根文件系统可选 | 同左（或复用 distroless/static） |
| 健康检查 | `bfp-server -health-check`（二进制自带子命令，避免装 wget/curl） | — |
| 目标体积 | < 50MB，多架构构建（amd64/arm64） | 同左 |

### 5.2 docker-compose.yml 服务定义

| 服务 | 说明 |
|------|------|
| `server` | 暴露 `8080:8080`；`healthcheck` 调 `/healthz`；`restart: unless-stopped`；env：`BFP_LISTEN_ADDR`、`BFP_LOG_LEVEL`、`BFP_MAX_BODY`、`BFP_RULES_DIR`（可挂载 `./rules`） |
| `cli` | `depends_on: server(condition: service_healthy)`；挂载 `./data:/data:ro`；`profiles: [cli]`（默认 `up` 不启动，避免一次性容器干扰）；one-shot 执行后退出 |

### 5.3 一键启动与验收流程（写入 README 首屏）

```bash
# 1) 一键启动服务
docker compose up -d
# 2) 一条命令跑通识别（输出与验收示例同构的 JSON 数组）
docker compose run --rm cli --input /data/sample.json
# 3) 或直接 curl
curl -s -X POST localhost:8080/api/v1/identify?output=array -d @data/sample.json
# 4) 一键验收对拍
make acceptance        # 等价 scripts/acceptance.sh：起服务→跑样例→与期望 JSON diff→退出码
```

---

## 6. 测试与验收

### 6.1 测试策略

| 层级 | 内容 | 工具 |
|------|------|------|
| 单元测试 | decode 各编码、每协议规则、置信度合成、CLI 输入解析 | `go test`，table-driven |
| Golden 测试 | `testdata/<proto>/` 每协议 ≥ 3 例（标准/变体/负例）：输入 banner → `expected.json` 全字段断言 | `go test` + 文件对拍 |
| API 测试 | handler 级：正常批、混合批、畸形 JSON、超限、超长 banner、错误定位 | `httptest` |
| 端到端 | Compose 起全套 → CLI 提交 → 返回断言；`/healthz` 探活 | `scripts/acceptance.sh` |
| 鲁棒性 | 随机字节 fuzz decode 层不 panic；空 banner/截断/超长用例 | `go test -fuzz`（短时） |
| 性能 | 10 万条合成数据基准，输出 P95 耗时 | `go test -bench` + acceptance 脚本计时 |
| 安全审计 | 断言 `engine` 包无网络调用（依赖方向检查 + 代码审查清单） | lint 规则/评审 checklist |

### 6.2 验收标准（对拍清单）

针对验收数据（同类示例）：

1. **字段级精确匹配**：`protocol` / `product` / `version` 与示例口径一致（如 443 输出 `HTTP`+`Apache`+`2.4.57`；SSH 输出 `os_hint=Ubuntu`）。
2. **空缺表示一致**：无版本/无 OS 输出 `""`，非 `null`。
3. **类型一致**：`port` int、`confidence` float（两位小数）。
4. **顺序一致**：输出与输入 1:1 同序。
5. **CLI 端到端可用**：README 中 3 条命令全部可复制执行成功。
6. **鲁棒性**：畸形/空/二进制 banner 返回降级结果且 HTTP 200，无 500、无 panic。
7. **零外联**：纯离线约束成立（代码审计 + 部署环境无外网仍全功能）。
8. **性能**：10 万条 ≤ 目标阈值（默认 10s，待 §10-3 确认）。

---

## 7. 里程碑与任务分解（WBS）

| 阶段 | 内容 | 产出（DoD） | 预估 |
|------|------|------------|------|
| M0 骨架与契约冻结 | 目录结构落地、`go.mod`、Makefile、API 契约（§3）定稿、示例语料准备（7 类 + 变体） | 空跑 CI 通过；契约文档评审通过 | 0.5 人日 |
| M1 引擎核心 | model、decode、probe/rule 框架、score 框架；**SSH + HTTP 全链路打通**（含 os_hint） | 示例中 SSH/nginx/Apache/Jetty 4 条 golden 通过 | 2 人日 |
| M2 规则库扩展 | FTP/MySQL/Redis/SMTP/POP3/IMAP/Telnet/PostgreSQL/MongoDB/Memcached/ES/SMB/RDP/VNC/Docker API 规则；置信度校准到示例锚点 | 示例 7 条全部通过；每协议 golden 语料绿 | 2 人日 |
| M3 server | REST API、middleware（限额/日志/请求 ID）、健康检查、meta 接口、配置装载 | API 测试全绿；`/healthz` 可用 | 1 人日 |
| M4 client | 三种输入格式解析、编码嗅探、分片并发、重试、输出渲染（裸数组/jsonl/csv）、退出码 | CLI 单测全绿；端到端手工验证 | 1 人日 |
| M5 交付与文档 | 两个 Dockerfile、compose、README、docs/api.md、docs/rules.md、acceptance.sh | `docker compose up -d` + `docker compose run --rm cli` 首次即成功 | 1 人日 |
| M6 硬化与验收 | 性能基准、fuzz、错误路径、验收对拍固化、镜像瘦身与多架构构建 | §6.2 八项验收清单全部勾选 | 1.5 人日 |

**合计约 9 人日**（单人串行）。关键路径：M1 → M2 → M5（M3/M4 可与 M2 部分并行）。

---

## 8. 风险与缓解

| 编号 | 风险 | 影响 | 缓解 |
|------|------|------|------|
| R1 | Banner 变体极多（不同扫描器格式、截断、含控制字符） | 漏识别/误识别 | 解码层统一规范化；规则宽松化 + 每协议语料回归；首命中优先级防冲突 |
| R2 | **443/HTTPS 的 banner 若仅为原始 TLS 字节流**，纯离线无法还原 `Apache/2.4.57`（TLS 加密不可解） | 该类记录只能给 `protocol=HTTP` + 低置信度 | 默认假设验收 banner 含明文 HTTP 响应头；降级能力：解析 TLS 记录（识别 443→HTTP、提取证书 CN/ALPN 作 product 线索）。**需确认（§10-2）** |
| R3 | 端口与内容信号冲突（非标端口服务） | 误判 | "内容优先、端口兜底"策略 + 冲突用例回归测试 |
| R4 | 二进制 banner 经 JSON 传输损坏 | 识别失败 | API 支持 `banner_base64`；CLI 自动探测非 UTF-8 并转码 |
| R5 | 大 batch 性能不达标 | 验收超时 | 候选协议索引 + 规则预编译 + client 分片并发 + 基准测试守护 |
| R6 | 规则误报（如任意 HTTP 文本被识别为特定产品） | 精度下降 | 产品识别必须命中产品专属特征；置信度分层；负例语料 |
| R7 | 容器基础镜像/工具链版本漂移 | 构建失败 | 固定镜像 tag（`golang:1.26-alpine`、`alpine:3.20`）；`go.mod` 固化版本；CI 锁 |

---

## 9. 建议的实现顺序（下一步动作）

1. 按 M0 落地目录骨架与 `go.mod`（仅骨架，无业务代码）；
2. 冻结 §3 接口契约与 §1.2 字段规格（评审一次）；
3. 准备 golden 语料：以题目示例 + 各协议真实 banner 变体构建 `testdata/`；
4. 按 M1 → M2 顺序实现引擎（先 SSH/HTTP 打通全链路，再横向加协议）；
5. M3/M4 并行接 API 与 CLI；
6. M5 交付 Compose；M6 跑 `make acceptance` 固化验收。

---

## 10. 待确认事项（含默认假设，不阻塞开发）

| # | 问题 | 默认假设（已按此设计） |
|---|------|----------------------|
| 1 | 验收数据的具体格式与规模（JSON 数组？JSONL？banner 编码？单条最大长度？总条数？） | JSON 数组；banner 为文本（可能含转义）；单条 ≤ 64KB；单批 ≤ 10 万条 |
| 2 | 443 端口记录的 banner 是否包含明文 HTTP 响应头（而非仅 TLS 握手字节）？ | **假设包含明文**（否则 Apache 版本无法离线还原，见 R2） |
| 3 | 是否有硬性性能指标（吞吐/耗时）？ | 单批 10 万条 ≤ 10s（P95） |
| 4 | `os_hint` 是否有枚举/大小写规范要求？ | 常见发行版英文名，首字母大写（`Ubuntu`/`Debian`/`CentOS`/`Windows`/`FreeBSD`） |
| 5 | 是否需要 `/metrics`（Prometheus）与中文 README？ | `/metrics` 暂列为 P2 可选项；README 默认中文 + 英文要点 |
| 6 | server 是否需要简单鉴权（API Token）？ | 默认无鉴权（内网单实例）；如需要 1 小时内可加 static token 中间件 |
| 7 | 验收"一键启动"的准确命令与端口期望？ | `docker compose up -d` 后 server 监听 `8080`；见 §5.3 |
| 8 | 是否需要 CI 配置（GitHub Actions / GitLab CI）？ | 暂不包含，`make check` 作为本地门禁 |
