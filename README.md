# Banner 指纹识别系统（hsxa-banner-fingerprint）

离线解析网络扫描原始数据（`ip` / `port` / `banner`），输出 `protocol` / `product` / `version` / `os_hint` / `confidence`。
交付形态：**CLI 客户端（bfp-cli）+ REST API 服务（bfp-server）**，Docker Compose 一键启动。

**纯离线**：只解析传入的 banner，绝不向任何目标 `ip:port` 发起网络连接，也不提供"主动补采"开关。

---

## 一键启动与验收（复制即可执行）

```bash
# 1) 一键启动服务（监听 8080）
docker compose up -d

# 2) 一条命令跑通识别，输出与验收示例同构的 JSON 数组
docker compose run --rm cli --input /data/sample.json

# 3) 或直接 curl
curl -s -X POST localhost:8080/api/v1/identify?output=array -d @data/sample.json
```

`docker compose run` 的 `cli` 服务默认执行 `identify`，因此 `--input` 可以直接跟在服务名后。
本地不装 Docker 时，用 `make build` 后执行 `make demo`（起本地 server 并跑 CLI 示例）或 `make acceptance`（完整验收对拍）。

## 验收对拍

```bash
make acceptance        # 等价于 bash scripts/acceptance.sh
```

脚本会构建二进制、启动临时服务，然后逐项检查：字段级匹配、`null` 禁止、类型、输入顺序 1:1、CLI/curl 端到端、畸形 banner 降级仍 200、零外联审计、10 万条吞吐。全部通过时打印 `acceptance PASSED`。

## 输出规格（冻结契约）

| 字段 | 类型 | 缺失时 | 说明 |
|------|------|--------|------|
| `ip` | string | 不可缺失 | 原样回显，支持 IPv4/IPv6 |
| `port` | int | 不可缺失 | 1–65535 |
| `protocol` | string | `"unknown"` | 大写风格：`SSH` / `HTTP` / `MySQL` / `Redis` / `FTP` … |
| `product` | string | `""` | `OpenSSH` / `nginx` / `Apache` / `MySQL` / `Redis` / `ProFTPD` / `Jetty` … |
| `version` | string | `""` | 精确版本串，如 `8.9p1`、`1.24.0`、`2.4.57` |
| `os_hint` | string | `""` | `Ubuntu` / `Debian` / `CentOS` / `Windows` / `FreeBSD` … |
| `confidence` | float | 不可缺失 | 0.00–1.00，两位小数 |

两条容易踩坑的验收口径：

1. **443 端口 TLS 上的 HTTP，`protocol` 输出 `HTTP`，不输出 `HTTPS`**；若 banner 只有 TLS 握手字节、没有明文响应头，则给出 `HTTP` + 低置信度（0.40）且不臆造 product/version。
2. **缺失值一律空字符串，绝不输出 `null`**。

示例（`curl` 的响应）：

```json
[{"ip":"10.10.1.11","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95}]
```

## 识别能力

支持约 18 种协议（详见 [docs/rules.md](docs/rules.md)）：SSH、FTP、SMTP、POP3、IMAP、Telnet、Redis、HTTP、Elasticsearch、Docker API、MySQL、PostgreSQL、MongoDB、SMB、VNC、RDP、Memcached，可选扩展 AMQP、LDAP。

判定策略：**内容特征为主、端口先验为辅**。2222 端口上的 SSH 仍输出 `SSH`；8080 端口上的非 HTTP 内容不会被强判为 HTTP；内容无任何信号时才用端口表兜底（置信度 0.35）。

### 置信度模型（对齐验收锚点）

| 证据层级 | 计算 | 典型结果 |
|----------|------|----------|
| 协议签名 0.60 + 产品 0.15 + 版本 0.15 + OS 0.05 | 全证据 | SSH 0.95 |
| 协议签名 0.60 + 产品 0.15/0.10 + 版本 0.15 | 版本可解析 | nginx/Apache/MySQL/ProFTPD 0.90，Jetty 0.85 |
| 协议签名 0.60 + 产品 0.10 | 产品确认但版本缺失 | Redis 0.70 |
| 协议签名 0.60 | 仅协议 | 0.60 |
| 端口先验 0.35 | 仅端口推断 | 0.35 |
| 无信号 | — | `unknown` / 0.00 |

验收锚点（0.95 / 0.90 / 0.90 / 0.90 / 0.70 / 0.90 / 0.85）由 `internal/engine/score` 的权重**精确复现**，允许 ±0.05。

## 常用命令

```bash
make build        # 构建 bin/bfp-server、bin/bfp-cli
make test         # 全部单测 + golden 语料
make cover        # 核心包覆盖率
make check        # gofmt + go vet + go test（本地门禁）
make acceptance   # 端到端验收对拍
make demo         # 本地起服务并跑 CLI 示例
make docker       # 构建两个镜像
```

### CLI 用法

```bash
bfp-cli identify --input data/sample.json                    # 默认裸 JSON 数组
bfp-cli identify --input scan.jsonl --in-format jsonl --out-format csv
cat scan.csv | bfp-cli identify --in-format csv --batch-size 5000 --concurrency 8
bfp-cli ping --server http://localhost:8080
```

退出码：`0` 全部成功；`1` 部分批次失败；`2` 用法/输入错误；`3` server 不可达。

### Server 接口

| 方法 | 路径 | 用途 |
|------|------|------|
| POST | `/api/v1/identify` | 批量识别；`?output=array` 返回裸数组，默认返回带 `stats` 的信封 |
| GET | `/healthz` | 存活探针 |
| GET | `/readyz` | 就绪探针（规则加载完成后 200，之前 503） |
| GET | `/api/v1/meta` | 版本、协议清单、规则数量 |

完整契约见 [docs/api.md](docs/api.md)。配置项：`BFP_LISTEN_ADDR`、`BFP_LOG_LEVEL`、`BFP_MAX_BODY`、`BFP_MAX_RECORDS`、`BFP_MAX_BANNER_BYTES`、`BFP_RULES_DIR`。

## 项目结构

```
cmd/bfp-server, cmd/bfp-cli    二进制入口（仅装配）
internal/engine/               识别引擎：纯函数、零 IO、不 import net/http
  decode/ probe/ rule/ extract/ score/
internal/rules/                内置规则（按协议一文件）+ 外置 YAML 覆盖加载
internal/api/                  HTTP 层：路由、中间件、限额、健康检查
internal/client/               CLI 逻辑：输入解析、分片并发、重试、输出渲染
internal/model/                领域模型与 JSON 契约
testdata/                      每协议 golden 语料 + acceptance 验收数据
scripts/                       acceptance.sh、gen-samples.sh、bfptool 辅助工具
deploy/                        Dockerfile 与 compose（根目录 compose 为规范文件）
```

依赖：仅标准库 + `gopkg.in/yaml.v3`（外置规则）。无 Web 框架、无数据库、无 ORM。

## 测试与质量

```bash
go test ./...                       # 单测 + golden（含 7 条验收锚点）
go test -bench=. ./internal/engine/ # 吞吐基准
go test -fuzz=FuzzDecodeText ./internal/engine/decode/ -fuzztime=30s
```

核心包（engine/decode/rule/probe/score/extract/rules/model）行覆盖 ≥ 80%，见 `make cover`。

## 已知边界

- banner 仅含 TLS 握手字节时无法离线还原 HTTP 产品与版本（TLS 加密不可解），只给 `protocol=HTTP` + 0.40。
- 裸 `-ERR`/`220` 一类通用应答在非标准端口上存在协议歧义（POP3/Redis、FTP/SMTP），此时由端口先验裁决，无先验时按协议名排序取首个。
- 外置规则中正则无法匹配 ≥ 0x80 的裸字节（Go 正则按 rune 匹配），二进制特征请使用 `match_type: binary|contains`；启动时会拒绝这类规则。
