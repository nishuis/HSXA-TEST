# API 契约（bfp-server）

Base URL 默认 `http://localhost:8080`。所有响应均为 `application/json; charset=utf-8`，每行末尾带一个换行。

## POST /api/v1/identify

批量识别。查询参数 `output` 支持 `array`（直接返回结果数组，与验收示例同构）与默认信封格式。

### 请求体

```json
{
  "records": [
    {"ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"},
    {"ip": "1.2.3.5", "port": 80, "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n"},
    {"ip": "1.2.3.6", "port": 3306, "banner_base64": "3gAAAAo...", "encoding": "base64"}
  ],
  "options": {"include_evidence": false}
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `records[].ip` | string | 必填，非空 |
| `records[].port` | int | 必填，1–65535 |
| `records[].banner` | string | 文本 banner，支持 `\r\n`、`\xHH` 等转义 |
| `records[].banner_base64` | string | 二进制 banner，存在时优先于 `banner` |
| `records[].encoding` | string | `auto`（默认）\| `text` \| `base64` \| `hex` |
| `options.include_evidence` | bool | 为 `true` 时每条结果追加 `evidence`（命中的规则名等），默认关闭 |

`encoding=auto` 会嗅探 Hex → Base64 → 转义文本，且只在解码结果确实像协议载荷或二进制时才采用，避免误伤文本 banner。

### 响应体（默认信封）

```json
{
  "results": [
    {"ip": "1.2.3.4", "port": 22, "protocol": "SSH", "product": "OpenSSH", "version": "8.9p1", "os_hint": "Ubuntu", "confidence": 0.95}
  ],
  "stats": {"total": 3, "identified": 2, "unknown": 0, "elapsed_ms": 12}
}
```

`?output=array` 时响应体为裸数组：

```json
[{"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95}]
```

### 字段契约

| 字段 | 类型 | 缺失时 |
|------|------|--------|
| `ip` | string | 原样回显 |
| `port` | int | 原样回显 |
| `protocol` | string | `"unknown"` |
| `product` | string | `""` |
| `version` | string | `""` |
| `os_hint` | string | `""` |
| `confidence` | float | 0.00–1.00，两位小数 |

`results` 与输入 `records` **严格 1:1 且同序**：任何一条记录识别失败都不会影响其它记录，也不会改变数组长度或顺序。

### 错误模型

| 状态码 | 场景 | 响应 |
|--------|------|------|
| 400 | 请求体不是合法 JSON、`ip` 为空、`port` 越界 | `{"errors":[{"index":2,"field":"port","message":"..."}]}` |
| 413 | 请求体超过 `BFP_MAX_BODY`、记录数超过 `BFP_MAX_RECORDS`、单条 banner 超过 `BFP_MAX_BANNER_BYTES` | 同上 |
| 415 | `encoding` 不在允许集合内 | 同上 |
| 405 | 方法与路径不匹配（响应带 `Allow` 头） | 同上 |
| 500 | 内部错误（含被兜住的 panic） | `{"errors":[{"index":-1,"message":"internal error"}]}` |

`index` 为出问题记录的下标，`-1` 表示请求级问题。**单条记录识别失败不算请求错误**：banner 为空/畸形/二进制时，该条返回降级结果（`protocol` 按端口先验或 `unknown`，product/version/os_hint 为空串，低置信度），HTTP 状态仍为 200。

## GET /healthz

```json
{"status":"ok"}
```

始终 200，用于容器 healthcheck（`bfp-server -health-check` 即调用它）。

## GET /readyz

规则加载完成前 `503 {"status":"loading"}`，之后 `200 {"status":"ready"}`。外置规则加载失败时进程直接拒绝启动（fail-fast），因此不会出现"带着坏规则对外服务"的状态。

## GET /api/v1/meta

```json
{
  "version": "0.1.0",
  "protocols": ["SSH", "FTP", "SMTP", "POP3", "IMAP", "Telnet", "Redis", "HTTP", "Elasticsearch", "Docker API", "MySQL", "PostgreSQL", "MongoDB", "SMB", "VNC", "RDP", "Memcached"],
  "rule_count": 76,
  "uptime_seconds": 42
}
```

## 中间件与限额

- 请求 ID：读取 `X-Request-Id`，缺省时生成 8 字节随机值并回写同名响应头；访问日志为 JSON 结构化输出，含方法、路径、状态码、字节数、耗时。
- 请求体上限：默认 32 MiB（`BFP_MAX_BODY`）。
- 记录数上限：默认 200000（`BFP_MAX_RECORDS`）。
- 单条 banner 上限：默认 64 KiB（`BFP_MAX_BANNER_BYTES`），超出即截断并标记（服务端），或在 API 校验阶段直接 413（请求侧）。
- panic 兜底：任何未预期 panic 都会转为 500 JSON，连接不会中断。
