# 规则编写指南

规则分两类：**内置规则**（Go 数据结构，编译进二进制）与**外置规则**（YAML，启动时覆盖/扩展内置规则）。

## 1. 内置规则组织

| 文件 | 协议 | 端口先验 |
|------|------|----------|
| `internal/rules/ssh.go` | SSH | 22, 2222 |
| `internal/rules/ftp.go` | FTP | 21 |
| `internal/rules/smtp.go` | SMTP | 25, 465, 587 |
| `internal/rules/pop3.go` | POP3 | 110, 995 |
| `internal/rules/imap.go` | IMAP | 143, 993 |
| `internal/rules/telnet.go` | Telnet | 23, 2323 |
| `internal/rules/redis.go` | Redis | 6379 |
| `internal/rules/http.go` | HTTP | 80, 443, 8000, 8080, 8443, 8888 |
| `internal/rules/elasticsearch.go` | Elasticsearch | 9200, 9300 |
| `internal/rules/dockerapi.go` | Docker API | 2375, 2376 |
| `internal/rules/mysql.go` | MySQL / MariaDB | 3306 |
| `internal/rules/postgresql.go` | PostgreSQL | 5432 |
| `internal/rules/mongodb.go` | MongoDB | 27017 |
| `internal/rules/smb.go` | SMB | 445, 139 |
| `internal/rules/vnc.go` | VNC | 5900, 5901 |
| `internal/rules/rdp.go` | RDP | 3389 |
| `internal/rules/memcached.go` | Memcached | 11211 |

每个文件导出一个 `*rule.Set`：签名规则（`ProtoRules`）、产品规则（`ProductRules`）、端口先验（`Ports`）、以及二进制握手专用的 `Extract` 函数。新增协议只需新建一个文件并加入 `internal/rules/rules.go` 的 `allSets()`。

## 2. 规则模型

```
Rule{
  Name          规则名（同一组内唯一，外置覆盖按此名匹配）
  Kind          protocol | product（由所在列表推断）
  MatchType     prefix | contains | regex | binary
  Pattern       字面量文本、Go RE2 正则、或含 \xHH 的字节模式
  Offset        仅 binary：匹配起始偏移
  Product       命中时输出的规范产品名
  VersionGroup  1-based 正则捕获组 → version
  VersionTemplate  非捕获写法，支持 $1..$9
  OSGroup       1-based 正则捕获组 → os_hint
  OSHint        命中时的固定 os_hint
  Weight        置信度贡献（协议 ~0.60，产品 0.15 强 / 0.10 弱）
  Priority      同组内排序，大者先匹配
}
```

匹配顺序：同一协议内按 `Priority` 降序、**首命中即定**；产品规则优先于 `Extract` 函数（声明式规则表达不了时才写代码）。

> ⚠️ **正则不能匹配 ≥ 0x80 的裸字节**。Go 正则按 rune 匹配，`\xd0` 会被解释为 U+00D0 的 UTF-8 编码而非字节 `0xD0`，因此对二进制握手永远匹配不上。二进制特征请使用 `match_type: binary`（可带 `offset`）或 `contains`，它们的 `\xHH` 会先解码为裸字节再比较。`rule.Compile` 会主动拒绝这类正则并在启动时报错（`internal/engine/rule/rule.go: checkByteEscapes`）。

## 3. 外置规则（覆盖/扩展）

`BFP_RULES_DIR`（compose 中挂载 `./rules:/rules:ro`）下的每个 `*.yaml` 在启动时合并进内置规则：

- **同名规则覆盖**：文件里 `name` 与内置规则相同的规则会替换它；
- **新名字追加**：新增规则参与匹配，可用于给已有协议加产品；
- **新协议新增**：`protocol` 不在内置清单里时，整组作为新协议注册。

加载失败（YAML 语法、缺 `protocol`、正则不合法）时进程 **拒绝启动**，`/readyz` 保持 503，避免带着坏规则对外服务。

示例（见 `rules/example.yaml`，启用后 HTTP 识别 Caddy）：

```yaml
protocol: HTTP

product_rules:
  - name: http-server-caddy
    match_type: regex
    pattern: '(?i)server:\s*Caddy'
    product: Caddy
    weight: 0.10
    priority: 205
```

新增协议：

```yaml
protocol: MyProto
ports: [12345]
protocol_rules:
  - name: myproto-signature
    match_type: binary
    pattern: "\x01MYPROTO"
    weight: 0.60
    priority: 100
product_rules:
  - name: myproto-product
    match_type: regex
    pattern: 'MyProto/([\d.]+)'
    product: MyProto
    version_group: 1
    weight: 0.15
    priority: 100
```

## 4. 置信度权重

权重常量集中在 `internal/engine/score/score.go`：

| 常量 | 值 | 用途 |
|------|----|------|
| `WeightProtoSignature` | 0.60 | 唯一协议签名 |
| `WeightProtoDistinctive` | 0.65 | 协议+产品双重特征（Elasticsearch、Docker API 头），需压过通用 HTTP |
| `WeightProtoWeak` | 0.55 | 歧义签名（裸 `220`、行内 `HTTP/1.1`） |
| `WeightProtoTLSOnly` | 0.40 | 仅 TLS 记录（按端口判为 HTTP，无明文可提取） |
| `WeightProtoPortOnly` | 0.35 | 仅端口先验 |
| `WeightProductStrong` | 0.15 | 产品 + 版本证据 |
| `WeightProductWeak` | 0.10 | 产品确认但无版本（Redis `-NOAUTH`） |
| `WeightVersion` | 0.15 | 提取到版本 |
| `WeightOS` | 0.05 | 提取到 OS 提示 |

产品规则没有版本证据时应使用 `WeightProductWeak`，这是"产品确认但版本缺失"显著低于其他锚点的原因。

## 5. 语料与回归

- 每协议 ≥ 3 条 golden 语料：`testdata/<proto>/input.json` + `expected.json`（标准/变体/负例，负例含"内容优先于端口"的冲突用例）。
- 验收锚点：`testdata/acceptance/`，由 `internal/rules/golden_test.go` 的 `TestAcceptanceAnchors` 与 `scripts/acceptance.sh` 双重回归。
- 新增或修改规则后至少运行：

```bash
go test ./...              # golden 语料 + 单测
make acceptance            # 端到端对拍
```

对拍失败必须修实现，不允许放宽期望值（置信度容差固定 ±0.05）。

## 6. 已知歧义

| 场景 | 行为 |
|------|------|
| 裸 `-ERR`（POP3 / Redis 都可能） | 两条规则同为 0.60，由端口先验裁决（110 → POP3，6379 → Redis）；端口无先验时按协议名排序取首个 |
| 裸 `220`（FTP / SMTP 都可能） | 带产品关键词的规则（0.60）优先；否则通用规则 0.55，由端口先验裁决 |
| 仅 TLS 字节 | 端口先验为 HTTP（443/8443）时输出 `HTTP` + 0.40，不猜测产品；其它端口仅用端口先验 |
| 端口与内容冲突 | 内容优先：2222 上的 SSH 输出 `SSH`；8080 上的非 HTTP 内容不判 HTTP |
